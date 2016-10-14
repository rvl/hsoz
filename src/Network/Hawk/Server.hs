{-# LANGUAGE RecordWildCards #-}

-- | These are functions for checking authenticated requests and
-- sending authenticated responses.

module Network.Hawk.Server
       ( authenticateRequest
       , authenticate
       , HawkReq(..)
       , header
       , defaultAuthReqOpts
       , defaultAuthOpts
       , AuthReqOpts(..)
       , AuthOpts(..)
       , AuthResult
       , AuthResult'(..)
       , AuthFail(..)
       , AuthSuccess(..)
       , CredentialsFunc
       , module Network.Hawk.Types
       ) where

import           Control.Applicative       ((<|>))
import           Control.Monad             (join)
import           Control.Monad.IO.Class    (MonadIO, liftIO)
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Char8     as S8
import qualified Data.ByteString.Lazy      as BL
import           Data.CaseInsensitive      (CI (..))
import           Data.Maybe                (catMaybes, fromMaybe)
import           Data.Monoid               ((<>))
import           Data.Text                 (Text)
import           Data.Text.Encoding        (decodeUtf8)
import           Data.Time.Clock           (NominalDiffTime)
import           Data.Time.Clock.POSIX
import           Network.HTTP.Types.Header (Header, hAuthorization,
                                            hContentType)
import           Network.HTTP.Types.Method (Method, methodGet, methodPost)
import           Network.Wai               (Request, rawPathInfo,
                                            rawQueryString, remoteHost,
                                            requestHeaderHost, requestHeaders,
                                            requestMethod)

import           Network.Hawk.Common
import           Network.Hawk.Types
import           Network.Hawk.Util
import           Network.Iron.Util         (fixedTimeEq)

-- | Bundle of parameters for 'authenticateRequest'. Provides
-- information about what the public URL of the server would be. If
-- the application is served from a HTTP reverse proxy, then the
-- @Host@ header might have a different name, or the @hostname:port@
-- might need to be overridden.
data AuthReqOpts = AuthReqOpts
  { saHostHeaderName :: Maybe (CI ByteString) -- ^ Alternate name for @Host@ header
  , saHost           :: Maybe ByteString -- ^ Overrides the URL host
  , saPort           :: Maybe ByteString -- ^ Overrides the URL port
  , saOpts           :: AuthOpts  -- ^ Parameters for 'authenticate'
  }

-- | Bundle of parameters for 'authenticate'.
data AuthOpts = AuthOpts
  { saCheckNonce          :: NonceFunc
  , saTimestampSkew       :: NominalDiffTime
  , saIronLocaltimeOffset :: NominalDiffTime -- fixme: check this is still needed
  }

-- | Default parameters for 'authenticateRequest'. These are:
--
--
defaultAuthReqOpts = AuthReqOpts Nothing Nothing Nothing defaultAuthOpts

defaultAuthOpts = AuthOpts (\x t n -> True) 60 0

-- | A user-supplied callback to get credentials from a client
-- identifier.
type CredentialsFunc m = ClientId -> m (Either String ServerCredentials)

-- | Checks the @Authorization@ header of a 'Network.Wai.Request' and
-- (optionally) a payload. The header will be parsed and verified with
-- the credentials supplied.
authenticateRequest :: MonadIO m => AuthReqOpts -> CredentialsFunc m
                             -> Request -> Maybe BL.ByteString -> m AuthResult
authenticateRequest opts cred req body = do
  let hreq = hawkReq opts req body
  if BS.null (hrqAuthorization hreq)
    then return $ Left (AuthFailBadRequest "Missing Authorization header" Nothing)
    else authenticate (saOpts opts) cred hreq

-- | A package of values containing the attributes of a HTTP request
-- which are relevant to Hawk authentication.
data HawkReq = HawkReq
  { hrqMethod        :: Method
  , hrqUrl           :: ByteString
  , hrqHost          :: ByteString
  , hrqPort          :: Maybe Int
  , hrqAuthorization :: ByteString
  , hrqPayload       :: Maybe PayloadInfo
  } deriving Show

hawkReq :: AuthReqOpts -> Request -> Maybe BL.ByteString -> HawkReq
hawkReq AuthReqOpts{..} req body = HawkReq { hrqMethod = requestMethod req
                           , hrqUrl = rawPathInfo req <> rawQueryString req -- fixme: path /= url
                           , hrqHost = fromMaybe "" (saHost <|> host)
                           , hrqPort = port
                           , hrqAuthorization = fromMaybe "" $ lookup hAuthorization $ requestHeaders req
                           , hrqPayload = PayloadInfo ct <$> body -- if provided, the payload hash will be checked
                           }
  where
    hostHdr = maybe (requestHeaderHost req) (flip lookup (requestHeaders req)) saHostHeaderName
    (host, port) = case parseHostnamePort <$> hostHdr of
      Nothing             -> (Nothing, Nothing)
      (Just ("", p))      -> (Nothing, p)
      (Just (h, Just p))  -> (Just h, Just p)
      (Just (h, Nothing)) -> (Just h, Nothing)
    ct = fromMaybe "" $ lookup hContentType $ requestHeaders req


-- | Checks the @Authorization@ header of a generic request. The
-- header will be parsed and verified with the credentials
-- supplied. If a payload is provided, it will be verified.
authenticate :: MonadIO m => AuthOpts -> CredentialsFunc m -> HawkReq -> m AuthResult
-- fixme: payload hash is included in result. Need a function which
-- can be used to verify payload later if it's not immediately
-- available.
authenticate opts getCreds req@HawkReq{..} = do
  now <- liftIO getPOSIXTime
  case parseServerAuthorizationHeader hrqAuthorization of
    Right sah@AuthorizationHeader{..} -> do
      creds <- getCreds sahId
      return $ case creds of
        Right creds' -> serverAuthenticate' now opts creds' req sah
        Left e -> Left (AuthFailUnauthorized e Nothing (Just (serverAuthArtifacts req sah)))
    Left err -> return $ Left err

serverAuthenticate' :: POSIXTime -> AuthOpts -> ServerCredentials
                    -> HawkReq -> AuthorizationHeader -> AuthResult
serverAuthenticate' now opts creds hrq@HawkReq{..} sah@AuthorizationHeader{..} = do
  -- fixme: check !credentials => empty credentials
  -- fixme: check !credentials.key || !credentials.algorithm => invalid credentials
  -- fixme: check credentials.algorithm? => unknown algorithm
  let arts = serverAuthArtifacts hrq sah
  let doCheck = authResult creds arts
  let mac = serverMac creds arts HawkHeader
  if mac `fixedTimeEq` sahMac then do
    doCheck $ checkPayloadHash (scAlgorithm creds) sahHash hrqPayload
    doCheck $ checkNonce (saCheckNonce opts) (scKey creds) sahNonce sahTs
    doCheck $ checkExpiration now (saTimestampSkew opts) sahTs
    doCheck $ Right ()
    else Left (AuthFailUnauthorized "Bad mac" (Just creds) (Just arts))

-- | Maps auth status into the more detailed success/failure type
authResult :: ServerCredentials -> ServerAuthArtifacts -> Either String a -> Either AuthFail AuthSuccess
authResult c a (Right _) = Right (AuthSuccess c a)
authResult c a (Left e)  = Left (AuthFailUnauthorized e (Just c) (Just a))

serverAuthArtifacts :: HawkReq -> AuthorizationHeader -> ServerAuthArtifacts
serverAuthArtifacts HawkReq{..} AuthorizationHeader{..} =
  ServerAuthArtifacts hrqMethod hrqHost hrqPort hrqUrl
    sahId sahTs sahNonce sahMac sahHash sahExt (fmap decodeUtf8 sahApp) sahDlg


-- | Generates a suitable @Server-Authorization@ header to send back
-- to the client. Credentials and artifacts would be provided by a
-- previous call to 'authenticateRequest' (or 'authenticate').
--
-- If a payload is supplied, its hash will be included in the header.
header :: ServerCredentials -> ServerAuthArtifacts -> Maybe PayloadInfo -> Header
header creds arts payload = (hServerAuthorization, hawkHeaderString (catMaybes parts))
  where
    parts :: [Maybe (ByteString, ByteString)]
    parts = [ Just ("mac", mac)
            , fmap ((,) "hash") hash
            , fmap ((,) "ext") ext]
    hash = calculatePayloadHash (scAlgorithm creds) <$> payload
    ext = escapeHeaderAttribute <$> (shaExt arts)
    mac = serverMac creds arts HawkResponse

serverMac :: ServerCredentials -> ServerAuthArtifacts -> HawkType -> ByteString
serverMac ServerCredentials{..} ServerAuthArtifacts{..} =
  calculateMac scAlgorithm scKey
    shaTimestamp shaNonce shaMethod shaResource shaHost shaPort

-- | User-supplied nonce validation function.
type NonceFunc = Key -> POSIXTime -> Nonce -> Bool
type Nonce = ByteString

checkNonce :: NonceFunc -> Key -> Nonce -> POSIXTime -> Either String ()
checkNonce nonceFunc key nonce ts = if nonceFunc key ts nonce then Right ()
                                    else Left "Invalid nonce"

checkExpiration :: POSIXTime -> NominalDiffTime -> POSIXTime -> Either String ()
checkExpiration now skew ts = if abs (ts - now) <= skew then Right ()
                              else Left "Expired seal"

----------------------------------------------------------------------------
-- Authorization header parsing

-- | Represents the `Authorization` header which the client
-- sends to the server.
data AuthorizationHeader = AuthorizationHeader
  { sahId    :: Text
  , sahTs    :: POSIXTime
  , sahNonce :: ByteString
  , sahMac   :: ByteString
  , sahHash  :: Maybe ByteString -- ^ optional payload hash
  , sahExt   :: Maybe ByteString -- ^ optional extra data to verify
  , sahApp   :: Maybe ByteString -- ^ optional oz application id
  , sahDlg   :: Maybe ByteString -- ^ optional oz delegate
  } deriving Show

parseServerAuthorizationHeader :: ByteString -> AuthResult' AuthorizationHeader
parseServerAuthorizationHeader = parseHeaderServer allKeys serverAuthHeader

allKeys = ["id", "ts", "nonce", "hash", "ext", "mac", "app", "dlg"]

parseHeaderServer :: [ByteString] -> (AuthAttrs -> Either String hdr) -> ByteString -> AuthResult' hdr
parseHeaderServer keys hdr = parseResult . parseHeader keys hdr
  where
    -- Map parse failures to the detailed error statuses
    parseResult :: Either String (AuthScheme, hdr) -> AuthResult' hdr
    parseResult (Right ("Hawk", h)) = Right h
    parseResult (Right _)           = Left (AuthFailUnauthorized "Hawk" Nothing Nothing)
    parseResult (Left e)            = Left (AuthFailBadRequest e Nothing)

serverAuthHeader :: AuthAttrs -> Either String AuthorizationHeader
serverAuthHeader m = do
  id <- decodeUtf8 <$> authAttr m "id"
  ts <- join (readTs <$> authAttr m "ts")
  nonce <- authAttr m "nonce"
  mac <- authAttr m "mac"
  return $ AuthorizationHeader id ts nonce mac
    (authAttrMaybe m "hash") (authAttrMaybe m "ext")
    (authAttrMaybe m "app") (authAttrMaybe m "dlg")

----------------------------------------------------------------------------
