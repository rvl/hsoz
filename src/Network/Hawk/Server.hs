{-# LANGUAGE RecordWildCards #-}

module Network.Hawk.Server
       ( authenticate
       , authenticateRequest
       , header
       , defaultAuthReqOpts
       , defaultAuthOpts
       , AuthReqOpts(..)
       , AuthResult
       , AuthResult'(..)
       , AuthFail(..)
       , AuthSuccess(..)
       , CredentialsFunc
       , module Network.Hawk.Types
       ) where

import Data.Text (Text)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as S8
import Data.Text.Encoding (decodeUtf8)
import Data.CaseInsensitive (CI(..))
import Data.Time.Clock.POSIX
import Data.Time.Clock (NominalDiffTime)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Network.Wai (Request, requestHeaderHost, requestHeaders, remoteHost, requestMethod, rawPathInfo, rawQueryString)
import Network.HTTP.Types.Method (Method, methodGet, methodPost)
import Network.HTTP.Types.Header (hAuthorization, hContentType, Header)
import Data.Monoid ((<>))
import Data.Maybe (catMaybes, fromMaybe)
import Control.Applicative ((<|>))
import Control.Monad (join)

import Network.Iron.Util (fixedTimeEq)
import Network.Hawk.Common
import Network.Hawk.Types
import Network.Hawk.Util

data AuthReqOpts = AuthReqOpts
                   { saHostHeaderName :: Maybe (CI ByteString)
                   , saHost :: Maybe ByteString
                   , saPort :: Maybe ByteString
                   , saOpts :: AuthOpts
                   }

data AuthOpts = AuthOpts
                { saCheckNonce :: NonceFunc
                , saTimestampSkew :: NominalDiffTime
                , ironLocaltimeOffset :: NominalDiffTime -- seconds
                }

defaultAuthReqOpts = AuthReqOpts Nothing Nothing Nothing defaultAuthOpts

defaultAuthOpts = AuthOpts (\x t n -> True) 60 0

type CredentialsFunc m = ClientId -> m (Either String ServerCredentials)

-- Used by header: shaHash shaExt shaTimestamp shaNonce shaMethod shaResource

-- | Is like the node Http.ServerRequest variation of authenticate in
-- server.js
authenticateRequest :: MonadIO m => AuthReqOpts -> CredentialsFunc m
                             -> Request -> Maybe BL.ByteString -> m AuthResult
authenticateRequest opts cred req body = do
  let hreq = hawkReq opts req body
  if BS.null (hrqAuthorization hreq)
    then return $ Left (AuthFailBadRequest "Missing Authorization header" Nothing)
    else authenticate (saOpts opts) cred hreq

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
      Nothing -> (Nothing, Nothing)
      (Just ("", p)) -> (Nothing, p)
      (Just (h, Just p)) -> (Just h, Just p)
      (Just (h, Nothing)) -> (Just h, Nothing)
    ct = fromMaybe "" $ lookup hContentType $ requestHeaders req


{-
  fixme: make a variant of server authenticate without payload. the
  payload hash is returned in result so that it can be verified later.
-}
authenticate :: MonadIO m => AuthOpts -> CredentialsFunc m -> HawkReq -> m AuthResult
authenticate opts getCreds req@HawkReq{..} = do
  now <- liftIO getPOSIXTime
  liftIO $ putStrLn $ "now is " ++ show now
  case parseServerAuthorizationHeader hrqAuthorization of
    Right sah@AuthorizationHeader{..} -> do
      liftIO $ putStrLn ("a " ++ show sahId)
      creds <- getCreds sahId
      liftIO $ (putStrLn $ "got creds " ++ show creds)
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
  let doCheck = authResult1 creds arts
  let mac = calculateMac (scKey creds) (scAlgorithm creds) HawkHeader sahTs sahNonce hrqMethod hrqUrl hrqHost hrqPort
  if mac `fixedTimeEq` sahMac then do
    doCheck $ checkPayloadHash (scAlgorithm creds) sahHash hrqPayload
    doCheck $ checkNonce (saCheckNonce opts) (scKey creds) sahNonce sahTs
    doCheck $ checkExpiration now (saTimestampSkew opts) sahTs
    doCheck $ Right ()
    else Left (AuthFailUnauthorized "Bad mac" (Just creds) (Just arts))

authResult1 :: ServerCredentials -> ServerAuthArtifacts -> Either String a -> Either AuthFail AuthSuccess
authResult1 c a (Right _) = Right (AuthSuccess c a)
authResult1 c a (Left e) = Left (AuthFailUnauthorized e (Just c) (Just a))

serverAuthArtifacts :: HawkReq -> AuthorizationHeader -> ServerAuthArtifacts
serverAuthArtifacts HawkReq{..} AuthorizationHeader{..} =
  ServerAuthArtifacts hrqMethod hrqHost hrqPort hrqUrl
    sahId sahTs sahNonce sahMac sahHash sahExt (fmap decodeUtf8 sahApp) sahDlg


-- | Generates a suitable @Server-Authorization@ header to send back to the
-- client. Credentials and Artifacts would be provided by
-- authenticate.
-- The payload is ...
-- TODO: server.js also seems to allow options.hash and options.ext
header :: ServerCredentials -> ServerAuthArtifacts -> Maybe PayloadInfo -> Header
header creds ServerAuthArtifacts{..} payload =
  (hServerAuthorization, hawkHeaderString (catMaybes parts))
  where
    parts :: [Maybe (ByteString, ByteString)]
    parts = [ Just ("mac", mac)
            , fmap ((,) "hash") hash
            , fmap ((,) "ext") ext]
    hash = calculatePayloadHash (scAlgorithm creds) <$> payload
    ext = escapeHeaderAttribute <$> shaExt
    mac = calculateMac (scKey creds) (scAlgorithm creds) HawkResponse
            shaTimestamp shaNonce shaMethod shaResource shaHost shaPort


-- | nonce validation function. The function signature is function(key, nonce, ts, callback)
-- where 'callback' must be called using the signature function(err).
-- args: key ts nonce -> valid
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
  , sahHash  :: Maybe ByteString -- optional payload hash
  , sahExt   :: Maybe ByteString -- optional extra data to verify
  , sahApp   :: Maybe ByteString -- optional oz application id
  , sahDlg   :: Maybe ByteString -- optional oz delegate
  } deriving Show

parseServerAuthorizationHeader :: ByteString -> AuthResult' AuthorizationHeader
parseServerAuthorizationHeader = parseHeaderServer allKeys serverAuthHeader

allKeys = ["id", "ts", "nonce", "hash", "ext", "mac", "app", "dlg"]

parseHeaderServer :: [ByteString] -> (AuthAttrs -> Either String hdr) -> ByteString -> AuthResult' hdr
parseHeaderServer keys hdr = authResult2 . parseHeader keys hdr

authResult2 :: Either String (AuthScheme, hdr) -> AuthResult' hdr
authResult2 (Right ("Hawk", h)) = Right h
authResult2 (Right _)           = Left (AuthFailUnauthorized "Hawk" Nothing Nothing)
authResult2 (Left e)            = Left (AuthFailBadRequest e Nothing)


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
