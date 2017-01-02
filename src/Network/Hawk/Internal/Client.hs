{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards           #-}
{-# LANGUAGE DeriveDataTypeable #-}

-- | Note that this is essentially the "kitchen sink" export module,
-- including many functions intended only to be used internally by
-- this package. No API stability is guaranteed for this module. If
-- you see functions here which you believe should be promoted to a
-- stable API, please contact the author.

module Network.Hawk.Internal.Client where

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
                                            parseURI, portNumber, uriAuthority,
                                            uriScheme, schemeBS)
import           Data.Typeable             (Typeable)
import           Control.Exception         (Exception, throwIO)
import           Control.Monad.Catch       as E (MonadThrow(..), MonadCatch(..), handle)
import           Control.Monad             (join, void)

import           Network.Hawk.Internal
import           Network.Hawk.Internal.Types
import           Network.Hawk.Util
import           Network.Iron.Util
import           Network.Hawk.Internal.Client.Types
import           Network.Hawk.Internal.Client.HeaderParser

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
headerBase url method creds payload skew ext app dlg =
  headerBase' url method creds payload skew ext app dlg <$> getPOSIXTime <*> genNonce

headerBase' :: Text -> Method -> Credentials
            -> Maybe PayloadInfo -> NominalDiffTime
            -> Maybe ExtData -> Maybe Text -> Maybe Text
            -> POSIXTime -> ByteString -> Header
headerBase' url method creds payload skew ext app dlg ts nonce = let
  arts = header' HawkHeader url method creds payload skew ext app dlg ts nonce
  in Header (clientHawkAuth arts) arts

-- | Generates an authorization object for a Hawk signed message.
message :: Credentials     -- ^ Credentials for encryption.
        -> ByteString      -- ^ Destination host.
        -> Maybe Int       -- ^ Destination port.
        -> BL.ByteString   -- ^ The message.
        -> NominalDiffTime -- ^ Time offset to sync with server time.
        -> IO MessageAuth
message creds host port msg skew =
  message' creds host port msg skew <$> getPOSIXTime <*> genNonce

-- | Generates an authorization object for a Hawk signed message. This
-- variation allows the user to provide the message timestamp and
-- nonce string.
message' :: Credentials     -- ^ Credentials for encryption.
         -> ByteString      -- ^ Destination host.
         -> Maybe Int       -- ^ Destination port.
         -> BL.ByteString   -- ^ The message.
         -> NominalDiffTime -- ^ Time offset to sync with server time.
         -> POSIXTime       -- ^ Message timestamp.
         -> ByteString      -- ^ Random nonce string.
         -> MessageAuth
message' creds host port msg skew ts nonce = artsMsg creds arts
  where
    arts = HeaderArtifacts "" host port "" (ccId creds) ts' nonce "" (Just hash) Nothing Nothing Nothing
    hash = calculatePayloadHash (ccAlgorithm creds) payload
    payload = PayloadInfo "" msg
    ts' = ts + skew

-- | Signs a message stored in the given artifacts bundle.
artsMsg :: Credentials -> HeaderArtifacts -> MessageAuth
artsMsg creds arts@HeaderArtifacts{..} = MessageAuth haId haTimestamp haNonce hash mac
  where
    mac = clientMac creds HawkMessage arts
    hash = fromMaybe "" haHash

header' :: HawkType -> Text -> Method -> Credentials
        -> Maybe PayloadInfo -> NominalDiffTime
        -> Maybe ExtData -> Maybe Text -> Maybe Text
        -> POSIXTime -> ByteString -> HeaderArtifacts
header' ty url method creds payload skew ext app dlg ts nonce = arts
  where
    arts = headerArtifacts ts' nonce method (encodeUtf8 url)
      hash ext app dlg (ccId creds) mac
    hash = calculatePayloadHash (ccAlgorithm creds) <$> payload
    mac  = clientMac creds ty arts
    ts'  = ts + skew

-- | Constructs artifacts bundle from header params.
headerArtifacts :: POSIXTime -> ByteString -> Method -> ByteString
                -> Maybe ByteString -> Maybe ByteString
                -> Maybe Text -> Maybe Text
                -> ClientId -> ByteString
                -> HeaderArtifacts
headerArtifacts now nonce method url hash ext app dlg cid mac =
  HeaderArtifacts method host (Just port') resource cid now nonce mac hash ext app dlg
  where
    s@(SplitURL _ host port resource) = fromMaybe relUrl $ splitUrl url
    relUrl = SplitURL HTTP "" Nothing url
    port' = urlPort' s

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

clientMac :: Credentials -> HawkType -> HeaderArtifacts -> ByteString
clientMac Credentials{..} = calculateMac ccAlgorithm ccKey

hawkHeaderItems :: [(ByteString, Maybe ByteString)] -> [(ByteString, ByteString)]
hawkHeaderItems = catMaybes . map pull
  where
    pull (k, Just v)  = Just (k, v)
    pull (k, Nothing) = Nothing

splitUrl :: ByteString -> Maybe SplitURL
splitUrl url = SplitURL s <$> host <*> pure port <*> path
  where
    p = either (const Nothing) Just (parseURI laxURIParserOptions url)
    a = p >>= uriAuthority
    https = fmap (schemeBS . uriScheme) p == Just "https"
    s = if https then HTTPS else HTTP
    host = fmap (hostBS . authorityHost) a
    port :: Maybe Int
    port = fmap portNumber (a >>= authorityPort)
    path = fmap (const (extractPath url)) a

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
             -> IO (Either String (Maybe ServerAuthorizationHeader)) -- ^ Error message if authentication failed.
authenticate r creds artifacts payload saCheck = do
  now <- getPOSIXTime
  return $ authenticate' r creds artifacts payload saCheck now

authenticate' :: Response body -> Credentials -> HeaderArtifacts
              -> Maybe BL.ByteString -> ServerAuthorizationCheck
              -> POSIXTime -> Either String (Maybe ServerAuthorizationHeader)
authenticate' r creds arts payload saCheck now = do
  let w = responseHeader hWWWAuthenticate r
  ts <- mapM (checkWwwAuthenticateHeader creds) w
  let sa = responseHeader hServerAuthorization r
  msah <- checkServerAuthorizationHeader creds arts saCheck now sa
  let ct = fromMaybe "" $ responseHeader hContentType r
  let payload' = PayloadInfo ct <$> payload
  case msah of
    Just sah -> checkPayloadHash (ccAlgorithm creds) (sahHash sah) payload'
    Nothing -> return ()
  return msah

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
checkWwwAuthenticateHeader :: Credentials -> ByteString -> Either String (Maybe POSIXTime)
checkWwwAuthenticateHeader creds w = parseWwwAuthenticateHeader w >>= check
  where
    check h | tsm `tsmEq` (wahTsm h) = Right (wahTs h)
            | otherwise = Left "Invalid server timestamp hash"
      where tsm = calculateTsMac (ccAlgorithm creds) <$> wahTs h

    tsmEq :: Maybe ByteString -> Maybe ByteString -> Bool
    tsmEq (Just a) (Just b) = a `constEqBytes` b
    tsmEq (Just _) Nothing  = False
    tsmEq _        _        = True

checkServerAuthorizationHeader :: Credentials -> HeaderArtifacts
                               -> ServerAuthorizationCheck -> POSIXTime
                               -> Maybe ByteString
                               -> Either String (Maybe ServerAuthorizationHeader)
checkServerAuthorizationHeader _ _ ServerAuthorizationNotRequired _ Nothing = Right Nothing
checkServerAuthorizationHeader _ _ ServerAuthorizationRequired _ Nothing = Left "Missing Server-Authorization header"
checkServerAuthorizationHeader creds arts _ now (Just sa) =
  parseServerAuthorizationHeader sa >>= check
  where check sah | sahMac sah `constEqBytes` mac = Right (Just sah)
                  | otherwise = Left "Bad response mac"
          where
            arts' = responseArtifacts sah arts
            mac = clientMac creds HawkResponse arts'

-- | Updates the artifacts which were used for client authentication
-- with values from there server's response.
responseArtifacts :: ServerAuthorizationHeader -> HeaderArtifacts -> HeaderArtifacts
responseArtifacts ServerAuthorizationHeader{..} arts = arts { haMac  = sahMac
                                                            , haExt  = sahExt
                                                            , haHash = sahHash
                                                            }

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
  where make (SplitURL s host port resource) =
          HeaderArtifacts "GET" host port resource "" exp "" "" Nothing ext Nothing Nothing

encodeBewit :: Credentials -> HeaderArtifacts -> ByteString
encodeBewit creds arts = bewitString (ccId creds) (haTimestamp arts) mac (haExt arts)
  where mac = clientMac creds HawkBewit arts

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
             -> Response body -> m (Either String (Maybe ServerAuthorizationHeader))
authResponse creds arts ck resp = do
  let body = Nothing -- Just $ getResponseBody r
  case ck of
    ServerAuthorizationRequired ->
      liftIO $ authenticate resp creds arts body ck
    ServerAuthorizationNotRequired -> return (Right Nothing)

wasStale :: Request -> Credentials -> ResponseHeaders -> Status -> Maybe NominalDiffTime
wasStale req creds hdrs s
  | secure req && statusCode s == 401 = hawkTs creds hdrs
  | otherwise                         = Nothing

-- | Gets the WWW-Authenticate header value and returns the server
-- timestamp, if the response contains an authenticated timestamp.
hawkTs :: Credentials -> ResponseHeaders -> Maybe POSIXTime
hawkTs creds = join . join . fmap parseTs . wwwAuthenticate
  where
    wwwAuthenticate = lookup hWWWAuthenticate
    parseTs = rightJust . checkWwwAuthenticateHeader creds
