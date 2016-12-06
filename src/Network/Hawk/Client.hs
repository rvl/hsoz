{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards           #-}
{-# LANGUAGE DeriveDataTypeable #-}

-- | Functions for making Hawk-authenticated request headers and
-- verifying responses from the server.
--
-- The easiest way to make authenticated requests is to use 'withHawk'
-- with functions from the "Network.HTTP.Simple" module (from the
-- @http-conduit@ package).

module Network.Hawk.Client
       ( -- * Higher-level API
         withHawk
       -- ** Types
       , ServerAuthorizationCheck(..)
       , HawkException(..)
       , Credentials(..)
       -- * Protocol functions
       , sign
       , authenticate
       , header
       , headerOz
       , getBewit
       -- ** Types
       , Header(..)
       , Authorization
       , module Network.Hawk.Types
       ) where

import           Control.Monad.IO.Class    (MonadIO, liftIO)
import           Crypto.Hash
import           Crypto.Random
import qualified Data.ByteArray            as BA (unpack)
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Base64    as B64
import qualified Data.ByteString.Char8     as S8
import qualified Data.ByteString.Lazy      as BL
import           Data.Byteable             (constEqBytes)
import           Data.CaseInsensitive      (CI (..))
import qualified Data.Map                  as M
import           Data.Maybe                (catMaybes, fromMaybe)
import           Data.Text                 (Text)
import qualified Data.Text                 as T
import           Data.Text.Encoding        (encodeUtf8)
import           Data.Time.Clock           (NominalDiffTime)
import           Data.Time.Clock.POSIX
import           Network.HTTP.Types.Header (HeaderName, hContentType, hWWWAuthenticate, hAuthorization, ResponseHeaders)
import           Network.HTTP.Types.Method (Method)
import           Network.HTTP.Types.Status (Status, statusCode)
import           Network.HTTP.Types.URI    (extractPath)
import           Network.HTTP.Client       (Response, responseHeaders)
import           Network.HTTP.Client       (Request, requestHeaders, requestBody, getUri, method, secure)
import           Network.HTTP.Client       (HttpException(..))
import           URI.ByteString            (authorityHost, authorityPort,
                                            hostBS, laxURIParserOptions,
                                            parseURI, portNumber, uriAuthority)
import           Data.Typeable             (Typeable)
import           Control.Exception         (Exception, throwIO)
import           Control.Monad.Catch       as E (MonadThrow(..), MonadCatch(..), handle)
import           Control.Monad             (join)

import           Network.Hawk.Common
import           Network.Hawk.Types
import           Network.Hawk.Util
import           Network.Iron.Util
import           Network.Hawk.Client.Types
import           Network.Hawk.Client.HeaderParser

-- | Generates the Hawk authentication header for a request.
header :: Text -- ^ The request URL
       -> Method -- ^ The request method
       -> Credentials -- ^ Credentials used to generate the header
       -> Maybe PayloadInfo -- ^ Optional request payload
       -> NominalDiffTime -- ^ Time offset to sync with server time
       -> Maybe ExtData -- ^ Application-specific @ext@ data
       -> IO Header
header url method creds payload skew ext =
  headerBase url method creds payload skew ext Nothing Nothing

-- | Generates the Hawk authentication header for an Oz request. Oz
-- requires another attribute -- the application id. It also has an
-- optional delegated-by attribute, which is the application id of the
-- application the credentials were directly issued to.
headerOz :: Text -- ^ The request URL
         -> Method -- ^ The request method
         -> Credentials -- ^ Credentials used to generate the header
         -> Maybe PayloadInfo -- ^ Optional request payload
         -> NominalDiffTime -- ^ Time offset to sync with server time
         -> Maybe ExtData -- ^ Application-specific @ext@ data
         -> Text -- ^ Oz application identifier
         -> Maybe Text -- ^ Oz delegated application
         -> IO Header
headerOz url method creds payload skew ext app dlg =
  headerBase url method creds payload skew ext (Just app) dlg

headerBase :: Text -> Method -> Credentials -> Maybe PayloadInfo -> NominalDiffTime
           -> Maybe ExtData -> Maybe Text -> Maybe Text -> IO Header
headerBase url method creds payload skew ext app dlg = do
  now <- getPOSIXTime
  nonce <- genNonce
  return $ header' url method creds payload skew ext app dlg now nonce

header' :: Text -> Method -> Credentials -> Maybe PayloadInfo -> NominalDiffTime
        -> Maybe ExtData -> Maybe Text -> Maybe Text
        -> POSIXTime -> ByteString -> Header
header' url method creds payload skew ext app dlg ts nonce = Header auth arts
  where
    auth = clientHawkAuth arts
    arts = clientHeaderArtifacts ts' nonce method (encodeUtf8 url)
           hash ext app dlg (ccId creds) mac
    hash = calculatePayloadHash (ccAlgorithm creds) <$> payload
    mac  = clientMac HawkHeader creds arts
    ts'  = ts + skew

clientHeaderArtifacts :: POSIXTime -> ByteString -> Method -> ByteString
                      -> Maybe ByteString -> Maybe ByteString
                      -> Maybe Text -> Maybe Text
                      -> ClientId -> ByteString
                      -> HeaderArtifacts
clientHeaderArtifacts now nonce method url hash ext app dlg cid mac =
  HeaderArtifacts method host port resource cid now nonce mac hash ext app dlg
  where
    (SplitURL host port resource) = fromMaybe relUrl $ splitUrl url
    relUrl = SplitURL "" Nothing url

clientHawkAuth :: HeaderArtifacts -> ByteString
clientHawkAuth arts@HeaderArtifacts{..} = hawkHeaderString (hawkHeaderItems items)
  where
    items = [ ("id",    Just . encodeUtf8 $ haId)
            , ("ts",    Just . S8.pack . show . round $ haTimestamp)
            , ("nonce", Just haNonce)
            , ("hash",  haHash)
            , ("ext",   haExt)
            , ("mac",   Just haMac)
            , ("app",   encodeUtf8 <$> haApp)
            , ("dlg",   encodeUtf8 <$> haDlg)
            ]

clientMac :: HawkType -> Credentials -> HeaderArtifacts -> ByteString
clientMac h Credentials{..} arts = calculateMac ccAlgorithm ccKey arts h

hawkHeaderItems :: [(ByteString, Maybe ByteString)] -> [(ByteString, ByteString)]
hawkHeaderItems = catMaybes . map pull
  where
    pull (k, Just v)  = Just (k, v)
    pull (k, Nothing) = Nothing

splitUrl :: ByteString -> Maybe SplitURL
splitUrl url = SplitURL <$> host <*> pure port <*> path
  where
    p = either (const Nothing) uriAuthority (parseURI laxURIParserOptions url)
    host = fmap (hostBS . authorityHost) p
    port :: Maybe Int
    port = fmap portNumber $ p >>= authorityPort
    path = fmap (const (extractPath url)) p

genNonce :: IO ByteString
genNonce = takeRandom 10 <$> getSystemDRG
  where takeRandom n g = fst $ withRandomBytes g n (b64url :: ByteString -> ByteString)

-- | Whether the client wants to check the received
-- @Server-Authorization@ header depends on the application.
data ServerAuthorizationCheck = ServerAuthorizationNotRequired
                              | ServerAuthorizationRequired
                              deriving Show

-- | Validates the server response from a signed request. If the
-- payload body is provided, its hash will be checked.
authenticate :: Response body -- ^ Response from server.
             -> Credentials -- ^ Credentials used for signing the request.
             -> HeaderArtifacts -- ^ The result of 'sign'.
             -> Maybe BL.ByteString -- ^ Optional payload body from response.
             -> ServerAuthorizationCheck -- ^ Whether a valid @Server-Authorization@ header is required.
             -> IO (Either String ()) -- ^ Error message if authentication failed.
authenticate r creds artifacts payload saCheck = do
  now <- getPOSIXTime
  return $ authenticate' r creds artifacts payload saCheck now

authenticate' :: Response body -> Credentials -> HeaderArtifacts
              -> Maybe BL.ByteString -> ServerAuthorizationCheck
              -> POSIXTime -> Either String ()
authenticate' r creds artifacts payload saCheck now = do
  let w = responseHeader hWWWAuthenticate r
  ts <- mapM (checkWwwAuthenticateHeader creds) w
  let sa = responseHeader hServerAuthorization r
  sarh <- checkServerAuthorizationHeader creds artifacts saCheck now sa
  let ct = fromMaybe "" $ responseHeader hContentType r
  let payload' = PayloadInfo ct <$> payload
  case sarh of
    Just sarh' -> checkPayloadHash (ccAlgorithm creds) (sarhHash sarh') payload'
    Nothing -> Right ()

-- fixme: lens version from wreq is better
responseHeader :: HeaderName -> Response body -> Maybe ByteString
responseHeader h = lookup h . responseHeaders

-- | The protocol relies on a clock sync between the client and
-- server. To accomplish this, the server informs the client of its
-- current time when an invalid timestamp is received.
--
-- If an attacker is able to manipulate this information and cause the
-- client to use an incorrect time, it would be able to cause the
-- client to generate authenticated requests using time in the
-- future. Such requests will fail when sent by the client, and will
-- not likely leave a trace on the server (given the common
-- implementation of nonce, if at all enforced). The attacker will
-- then be able to replay the request at the correct time without
-- detection.
--
-- The client must only use the time information provided by the
-- server if:
--
-- * it was delivered over a TLS connection and the server identity
--   has been verified, or
-- * the `tsm` MAC digest calculated using the same client credentials
--   over the timestamp has been verified.
checkWwwAuthenticateHeader :: Credentials -> ByteString -> Either String POSIXTime
checkWwwAuthenticateHeader creds w = do
  WwwAuthenticateHeader{..} <- parseWwwAuthenticateHeader w
  let tsm = calculateTsMac (ccAlgorithm creds) wahTs
  if wahTsm `constEqBytes` tsm
    then Right wahTs
    else Left "Invalid server timestamp hash"

checkServerAuthorizationHeader :: Credentials -> HeaderArtifacts
                               -> ServerAuthorizationCheck -> POSIXTime
                               -> Maybe ByteString
                               -> Either String (Maybe ServerAuthorizationReplyHeader)
checkServerAuthorizationHeader _ _ ServerAuthorizationNotRequired _ Nothing = Right Nothing
checkServerAuthorizationHeader _ _ ServerAuthorizationRequired _ Nothing = Left "Missing Server-Authorization header"
checkServerAuthorizationHeader creds arts _ now (Just sa) = do
  sarh <- parseServerAuthorizationReplyHeader sa
  let mac = clientMac HawkResponse creds arts
  if sarhMac sarh `constEqBytes` mac
    then Right (Just sarh)
    else Left "Bad response mac"

----------------------------------------------------------------------------

-- | Generate a bewit value for a given URI. If the URI can't be
-- parsed, @Nothing@ will be returned.
--
-- See "Network.Hawk.URI" for more information about bewits.
getBewit :: Credentials -- ^ Credentials used to generate the bewit.
         -> NominalDiffTime -- ^ Time-to-live (TTL) value.
         -> Maybe ExtData -- ^ Optional application-specific data.
         -> NominalDiffTime -- ^ Time offset to sync with server time.
         -> ByteString -- ^ URI.
         -> IO (Maybe ByteString) -- ^ Base-64 encoded bewit value.
-- fixme: javascript version supports deconstructed parsed uri objects
-- fixme: not much point having two time interval arguments? Maybe just have a single expiry time argument.
getBewit creds ttl ext offset uri = do
  exp <- fmap (+ (ttl + offset)) getPOSIXTime
  return $ encodeBewit creds <$> bewitArtifacts uri exp ext

bewitArtifacts :: ByteString -> POSIXTime -> Maybe ExtData -> Maybe HeaderArtifacts
bewitArtifacts uri exp ext = make <$> splitUrl uri
  where make (SplitURL host port resource) =
          HeaderArtifacts "GET" host port resource "" exp "" "" Nothing ext Nothing Nothing

encodeBewit :: Credentials -> HeaderArtifacts -> ByteString
encodeBewit creds arts = bewitString (ccId creds) (haTimestamp arts) mac (haExt arts)
  where mac = clientMac HawkBewit creds arts

-- | Constructs a bewit: @id\exp\mac\ext@
bewitString :: ClientId -> POSIXTime -> ByteString -> Maybe ExtData -> ByteString
bewitString cid exp mac ext = b64url (S8.intercalate "\\" parts)
  where parts = [ encodeUtf8 cid, S8.pack . show . round $ exp
                , mac, fromMaybe "" ext ]

----------------------------------------------------------------------------

-- | Modifies a 'Wai.Request' to include the @Authorization@ header
-- necessary for Hawk.
sign :: MonadIO m => Credentials -- ^ Credentials for signing
     -> Maybe ExtData -- ^ Optional application-specific data.
     -> Maybe PayloadInfo -- ^ Optional payload to hash
     -> NominalDiffTime -- ^ Time offset to sync with server time
     -> Request -- ^ The request to sign
     -> m (HeaderArtifacts, Request)
sign creds ext payload skew req = do
  let uri = T.pack . show . getUri $ req
  hdr <- liftIO $ header uri (method req) creds payload skew ext
  return $ (hdrArtifacts hdr, addAuth hdr req)

addAuth :: Header -> Request -> Request
addAuth hdr req = req { requestHeaders = (auth:requestHeaders req) }
  where auth = (hAuthorization, hdrField hdr)

-- | Client exceptions specific to Hawk.
data HawkException = HawkServerAuthorizationException String
  -- ^ The returned @Server-Authorization@ header did not validate.
  deriving (Show, Typeable)
instance Exception HawkException

-- | Signs and executes a request, then checks the server's
-- response. Handles retrying of requests if the server and client
-- clocks are out of sync.
--
-- A 'HawkException' will be thrown if the server's response fails to
-- authenticate.
withHawk :: (MonadIO m, MonadCatch m) =>
            Credentials       -- ^ Credentials for signing the request.
         -> Maybe ExtData     -- ^ Optional application-specific data.
         -> Maybe PayloadInfo -- ^ Optional payload to sign.
         -> ServerAuthorizationCheck -- ^ Whether to verify the server's response.
         -> (Request -> m (Response body)) -- ^ The action to run with the request.
         -> Request           -- ^ The request to sign.
         -> m (Response body) -- ^ The result of the action.
withHawk creds ext payload ck http req = withHawkBase creds ext payload ck http req

withHawkPayload :: (MonadIO m, MonadCatch m) =>
                   Credentials -> Maybe ExtData -> PayloadInfo
                -> ServerAuthorizationCheck
                -> (Request -> m (Response body)) -> Request -> m (Response body)
withHawkPayload creds ext payload ck http req = withHawkBase creds ext (Just payload) ck http req

-- | Makes a Hawk signed request. If the server responds saying "Stale
-- timestamp", then retry using an adjusted timestamp.
withHawkBase :: (MonadIO m, MonadThrow m, MonadCatch m) =>
                Credentials -> Maybe ExtData -> Maybe PayloadInfo
             -> ServerAuthorizationCheck
             -> (Request -> m (Response body)) -> Request -> m (Response body)
withHawkBase creds ext payload ck http req = do
  let handle = makeExpiryHandler creds req
  r <- handle $ doSignedRequest 0 creds ext payload ck http req
  case r of
    Right res -> return res
    Left ts -> do
      now <- liftIO getPOSIXTime
      doSignedRequest (now - ts) creds ext payload ck http req


makeExpiryHandler :: MonadCatch m => Credentials -> Request
                  -> m a -> m (Either NominalDiffTime a)
makeExpiryHandler creds req = E.handle handler . fmap Right
  where
    handler e@(StatusCodeException s h _) =
      case wasStale req creds h s of
        Just ts -> return $ Left ts
        Nothing -> throwM e

-- | Signs a request, runs it, then authenticates the response.
doSignedRequest :: (MonadIO m, MonadThrow m) =>
                    NominalDiffTime
                -> Credentials -> Maybe ExtData -> Maybe PayloadInfo
                -> ServerAuthorizationCheck
                -> (Request -> m (Response body)) -> Request
                -> m (Response body)
doSignedRequest skew creds ext payload ck http req = do
  (arts, req') <- sign creds ext payload skew req
  resp <- http req'
  auth <- authResponse creds arts ck resp
  case auth of
    Left e -> throwM $ HawkServerAuthorizationException e
    Right _ -> return resp

-- | Authenticates the server's response if required.
authResponse :: MonadIO m => Credentials -> HeaderArtifacts
             -> ServerAuthorizationCheck
             -> Response body -> m (Either String ())
authResponse creds arts ck resp = do
  let body = Nothing -- Just $ getResponseBody r
  case ck of
    ServerAuthorizationRequired ->
      liftIO $ authenticate resp creds arts body ck
    ServerAuthorizationNotRequired -> return (Right ())

wasStale :: Request -> Credentials -> ResponseHeaders -> Status -> Maybe NominalDiffTime
wasStale req creds hdrs s
  | secure req && statusCode s == 401 = hawkTs creds hdrs
  | otherwise                         = Nothing

-- | Gets the WWW-Authenticate header value and returns the server
-- timestamp, if the response contains an authenticated timestamp.
hawkTs :: Credentials -> ResponseHeaders -> Maybe POSIXTime
hawkTs creds = join . fmap parseTs . wwwAuthenticate
  where
    wwwAuthenticate = lookup hWWWAuthenticate
    parseTs = rightJust . checkWwwAuthenticateHeader creds
