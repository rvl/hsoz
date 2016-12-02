{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards           #-}
{-# LANGUAGE DeriveDataTypeable #-}

-- | Functions for making Hawk-authenticated request headers and
-- verifying responses from the server.

module Network.Hawk.Client
       ( header
       , headerOz
       , getBewit
       , authenticate
       , sign, signWithPayload
       , sign', signWithPayload'
       , withHawk
       , withHawkPayload
       , ServerAuthorizationCheck(..)
       , Credentials(..)
       , Header(..)
       , Authorization
       , HeaderArtifacts
       , module Network.Hawk.Types
       , HawkException(..)
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
import           Network.HTTP.Types.Status (statusCode)
import           Network.HTTP.Types.URI    (extractPath)
import           Network.HTTP.Client       (Response, responseHeaders)
import           Network.HTTP.Client       (Request, requestHeaders, requestBody, getUri, method, secure)
import           Network.HTTP.Client       (HttpException(..))
import           URI.ByteString            (authorityHost, authorityPort,
                                            hostBS, laxURIParserOptions,
                                            parseURI, portNumber, uriAuthority)
import           Data.Typeable             (Typeable)
import           Control.Exception         (Exception, throwIO)
import           Control.Monad.Catch       as E (MonadThrow(..), MonadCatch(..))
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
       -> Maybe ExtData -- ^ @ext@ data
       -> IO Header
header url method creds payload ext = headerBase url method creds payload ext Nothing Nothing

-- | Generates the Hawk authentication header for an Oz request. Oz
-- requires another attribute -- the application id. It also has an
-- optional delegated-by attribute, which is the application id of the
-- application the credentials were directly issued to.
headerOz :: Text -> Method -> Credentials -> Maybe PayloadInfo -> Maybe ExtData
         -> Text -> Maybe Text -> IO Header
headerOz url method creds payload ext app dlg = headerBase url method creds payload ext (Just app) dlg

headerBase :: Text -> Method -> Credentials -> Maybe PayloadInfo -> Maybe ExtData
           -> Maybe Text -> Maybe Text -> IO Header
headerBase url method creds payload ext app dlg = do
  now <- getPOSIXTime
  nonce <- genNonce
  let hash = calculatePayloadHash (ccAlgorithm creds) <$> payload
      mac  = clientMac HawkHeader creds arts
      arts = clientHeaderArtifacts now nonce method (encodeUtf8 url) hash ext app dlg (ccId creds) mac
      auth = clientHawkAuth arts
  return $ Header auth arts

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
clientMac h Credentials{..} HeaderArtifacts{..} =
  calculateMac ccAlgorithm ccKey
      haTimestamp haNonce haMethod haResource haHost haPort h

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
genNonce = takeRandom <$> getSystemDRG
  where takeRandom g = fst $ withRandomBytes g 10 B64.encode

-- | Whether the client wants to check the received
-- @Server-Authorization@ header depends on the application.
data ServerAuthorizationCheck = ServerAuthorizationNotRequired
                              | ServerAuthorizationRequired
                              deriving Show

-- | Validates the server response.
authenticate :: Response body -> Credentials -> HeaderArtifacts
             -> Maybe BL.ByteString -> ServerAuthorizationCheck
             -> IO (Either String ())
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

-- | Generate a bewit value for a given URI.
getBewit :: Credentials -> NominalDiffTime -> Maybe ExtData -> NominalDiffTime
         -> ByteString -> IO (Maybe ByteString)
-- fixme: javascript version supports deconstructed parsed uri objects
-- fixme: not much point having two time interval arguments?
getBewit creds ttl ext offset uri = do
  exp <- fmap (+ (ttl + offset)) getPOSIXTime
  return $ bewit exp <$> splitUrl uri
  where
    bewit exp = encode . clientMac HawkBewit creds . make
      where
        make (SplitURL host port resource) =
          HeaderArtifacts "GET" host port resource "" exp "" "" Nothing ext Nothing Nothing
        encode = b64url . S8.intercalate "\\" . parts
        parts mac = [ encodeUtf8 . ccId $ creds
                    , S8.pack . show . round $ exp
                    , mac, fromMaybe "" ext ]

----------------------------------------------------------------------------

sign :: MonadIO m => Credentials -> Maybe ExtData
     -> Request -> m Request
sign creds ext req = snd <$> signRequest creds ext Nothing req

sign' :: MonadIO m => Credentials -> Maybe ExtData
     -> Request -> m (HeaderArtifacts, Request)
sign' creds ext req = signRequest creds ext Nothing req

signWithPayload :: MonadIO m => Credentials -> Maybe ExtData -> PayloadInfo
                -> Request -> m Request
signWithPayload creds ext payload req = snd <$> signWithPayload' creds ext payload req

signWithPayload' :: MonadIO m => Credentials -> Maybe ExtData -> PayloadInfo
                 -> Request -> m (HeaderArtifacts, Request)
signWithPayload' creds ext payload req = signRequest creds ext (Just payload) req

signRequest :: MonadIO m => Credentials -> Maybe ExtData -> Maybe PayloadInfo
            -> Request -> m (HeaderArtifacts, Request)
signRequest creds ext payload req = do
  let uri = T.pack . show . getUri $ req
  hdr <- liftIO $ header uri (method req) creds payload ext
  return $ (hdrArtifacts hdr, addAuth hdr req)

addAuth :: Header -> Request -> Request
addAuth hdr req = req { requestHeaders = (auth:requestHeaders req) }
  where auth = (hAuthorization, hdrField hdr)

data HawkException = HawkServerAuthorizationException String
                   | HawkStaleTimestampException
  deriving (Show, Typeable)
instance Exception HawkException

withHawk :: (MonadIO m, MonadThrow m, MonadCatch m) =>
            Credentials -> Maybe ExtData -> ServerAuthorizationCheck
         -> (Request -> m (Response body)) -> Request -> m (Response body)
withHawk creds ext ck http req = do
  (arts, req') <- sign' creds ext req
  doSignedRequest creds arts ck http req'

withHawkPayload :: (MonadIO m, MonadThrow m, MonadCatch m) =>
                   Credentials -> Maybe ExtData -> PayloadInfo
                -> ServerAuthorizationCheck
                -> (Request -> m (Response body)) -> Request -> m (Response body)
withHawkPayload creds ext payload ck http req = do
  (arts, req') <- signWithPayload' creds ext payload req
  doSignedRequest creds arts ck http req'

doSignedRequest :: (MonadIO m, MonadThrow m, MonadCatch m) =>
                   Credentials -> HeaderArtifacts -> ServerAuthorizationCheck
                -> (Request -> m (Response body)) -> Request -> m (Response body)
doSignedRequest creds arts ck http req = do
  r <- http req
  let body = Nothing -- Just $ getResponseBody r
  case ck of
    ServerAuthorizationRequired -> do
      res <- liftIO $ authenticate r creds arts body ck
      case res of
        Left e -> throwM $ HawkServerAuthorizationException e
        Right () -> return r
    ServerAuthorizationNotRequired -> return r

hawkTs :: Credentials -> ResponseHeaders -> Maybe POSIXTime
hawkTs creds = join . fmap parseTs . wwwAuthenticate
  where
    wwwAuthenticate = lookup hWWWAuthenticate
    parseTs = rightJust . checkWwwAuthenticateHeader creds
