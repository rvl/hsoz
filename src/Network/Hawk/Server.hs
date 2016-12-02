{-# LANGUAGE RecordWildCards #-}

-- | These are functions for checking authenticated requests and
-- sending authenticated responses.

module Network.Hawk.Server
       ( authenticateRequest
       , authenticate
       , authenticateBewit
       , authenticatePayload
       , HawkReq(..)
       , header
       , AuthReqOpts(..)
       , AuthOpts(..)
       , def
       , module Network.Hawk.Server.Types
       ) where

import           Control.Applicative       ((<|>))
import           Control.Monad             (join)
import           Control.Monad.IO.Class    (MonadIO, liftIO)
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Char8     as S8
import qualified Data.ByteString.Lazy      as BL
import           Data.Byteable             (constEqBytes)
import           Data.CaseInsensitive      (CI (..))
import           Data.Maybe                (catMaybes, fromMaybe)
import           Data.Monoid               ((<>))
import           Data.Text                 (Text)
import qualified Data.Text                 as T
import           Data.Text.Encoding        (decodeUtf8, decodeUtf8')
import           Control.Error.Safe        (rightMay)
import           Data.Default              (Default(..))
import           Data.Time.Clock           (NominalDiffTime)
import           Data.Time.Clock.POSIX
import           Network.HTTP.Types.Header (Header, hAuthorization,
                                            hContentType, hWWWAuthenticate)
import           Network.HTTP.Types.Method (Method, methodGet, methodPost)
import           Network.HTTP.Types.Status (Status, ok200, badRequest400, unauthorized401)
import           Network.HTTP.Types.URI    (renderQuery)
import           Network.Wai               (Request, rawPathInfo,
                                            rawQueryString, queryString,
                                            remoteHost, requestMethod,
                                            requestHeaderHost, requestHeaders)

import           Network.Hawk.Common
import           Network.Hawk.Server.Types
import           Network.Hawk.Util
import           Network.Iron.Util         (b64urldec, justRight, mapLeft)

-- | Bundle of parameters for 'authenticateRequest'. Provides
-- information about what the public URL of the server would be. If
-- the application is served from a HTTP reverse proxy, then the
-- @Host@ header might have a different name, or the @hostname:port@
-- might need to be overridden.
data AuthReqOpts = AuthReqOpts
  { saHostHeaderName :: Maybe (CI ByteString) -- ^ Alternate name for @Host@ header
  , saHost           :: Maybe ByteString -- ^ Overrides the URL host
  , saPort           :: Maybe ByteString -- ^ Overrides the URL port
  , saBewitParam     :: ByteString -- ^ Query parameter for bewit authentication
  , saOpts           :: AuthOpts  -- ^ Parameters for 'authenticate'
  }

-- | Bundle of parameters for 'authenticate'.
data AuthOpts = AuthOpts
  { saCheckNonce          :: NonceFunc
  , saTimestampSkew       :: NominalDiffTime
  , saIronLocaltimeOffset :: NominalDiffTime -- fixme: check this is still needed
  }

instance Default AuthReqOpts where
  def = AuthReqOpts Nothing Nothing Nothing "bewit" def

instance Default AuthOpts where
  def = AuthOpts (\x t n -> True) 60 0

-- | Checks the @Authorization@ header of a 'Network.Wai.Request' and
-- (optionally) a payload. The header will be parsed and verified with
-- the credentials supplied.
--
-- If the request payload is provided, it will be verified. If a
-- payload is not supplied, it can be verified later with
-- 'authenticatePayload'.
authenticateRequest :: MonadIO m => AuthReqOpts -> CredentialsFunc m t
                    -> Request -> Maybe BL.ByteString -> m (AuthResult t)
authenticateRequest opts creds req body = do
  let hreq = hawkReq opts req body
  if BS.null (hrqAuthorization hreq)
    then return $ Left (AuthFailBadRequest "Missing Authorization header" Nothing)
    else authenticate (saOpts opts) creds hreq

authenticateBewit' opts (creds, t) req bewit
  | mac `constEqBytes` (bewitMac bewit) = Right (AuthSuccess creds arts t)
  | otherwise = Left (AuthFailUnauthorized "Bad mac" (Just creds) (Just arts))
  where
    arts = bewitArtifacts req bewit
    mac = serverMac creds arts HawkBewit

bewitArtifacts :: HawkReq -> Bewit -> HeaderArtifacts
bewitArtifacts HawkReq{..} Bewit{..} =
  HeaderArtifacts hrqMethod hrqHost hrqPort hrqBewitlessUrl
    "" bewitExp "" "" Nothing (Just bewitExt) Nothing Nothing

-- | Checks the @Authorization@ header of a request according to the
-- "bewit" scheme. See "Network.Hawk.URI" for a description of that
-- scheme.
authenticateBewit :: MonadIO m => AuthReqOpts -> CredentialsFunc m t
                  -> Request -> m (AuthResult t)
authenticateBewit opts getCreds req = do
  now <- liftIO getPOSIXTime
  case checkBewit hrq now of
    Right bewit -> do
      mcreds <- mapLeft unauthorized <$> getCreds (bewitId bewit)
      return $ case mcreds of
        Right creds -> authenticateBewit' opts creds hrq bewit
        Left e -> undefined
    Left e -> return (Left e)

  where
    hrq = hawkReq opts req Nothing
    checkBewit :: HawkReq -> POSIXTime -> Either AuthFail Bewit
    checkBewit HawkReq{..} now = do
      encBewit <- checkEmpty hrqBewit
      checkMethod hrqMethod
      checkHeader hrqAuthorization
      bewit <- mapLeft unauthorized $ decodeBewit encBewit
      checkAttrs bewit
      checkExpiry bewit now
      return bewit

    -- need a bewit in the query string
    checkEmpty (Just "") = Left (unauthorized "Empty bewit")
    checkEmpty Nothing   = Left (unauthorized "")
    checkEmpty (Just b)  = Right b
    -- bewit is not intended for PUT, POST, DELETE, etc
    checkMethod m = if m == "GET" || m == "HEAD" then Right ()
                    else Left (unauthorized "Invalid method")
    -- client should use either holder-of-key or bewit, not both
    checkHeader h = if BS.null h then Right ()
                    else Left (badRequest "Multiple authentications")
    -- disallow empty attributes
    checkAttrs (Bewit i _ m _) = if T.null i || BS.null m
                                 then Left (badRequest "Missing bewit attributes")
                                 else Right ()
    checkExpiry b now = if now < bewitExp b then Right ()
                        else Left (AuthFailUnauthorized ("Access expired " ++ show (bewitExp b)) Nothing Nothing) -- fixme: include hrqBewit
    unauthorized e = AuthFailUnauthorized e Nothing Nothing
    badRequest e = AuthFailBadRequest e Nothing


hawkReq :: AuthReqOpts -> Request -> Maybe BL.ByteString -> HawkReq
hawkReq AuthReqOpts{..} req body = HawkReq
  { hrqMethod = requestMethod req
  , hrqUrl = baseUrl <> rawQueryString req
  , hrqHost = justString (saHost <|> host)
  , hrqPort = port
  , hrqAuthorization = justString $ lookup hAuthorization $ requestHeaders req
  , hrqPayload = PayloadInfo ct <$> body -- if provided, the payload hash will be checked
  , hrqBewit = fmap justString <$> lookup saBewitParam $ queryString req
  , hrqBewitlessUrl = baseUrl <> bewitQueryString
  }
  where
    baseUrl = rawPathInfo req  -- fixme: path /= url
    hostHdr = maybe (requestHeaderHost req) (flip lookup (requestHeaders req)) saHostHeaderName
    (host, port) = case parseHostnamePort <$> hostHdr of
      Nothing             -> (Nothing, Nothing)
      (Just ("", p))      -> (Nothing, p)
      (Just (h, Just p))  -> (Just h, Just p)
      (Just (h, Nothing)) -> (Just h, Nothing)
    ct = justString $ lookup hContentType $ requestHeaders req
    justString = fromMaybe ""
    bewitQueryString = renderQuery True $ removeBewit (queryString req)
    removeBewit = filter ((/= saBewitParam) . fst)

-- | Checks the @Authorization@ header of a generic request. The
-- header will be parsed and verified with the credentials
-- supplied.
--
-- If a payload is provided, it will be verified. If the payload is
-- not supplied, it can be verified later with 'authenticatePayload'.
authenticate :: MonadIO m => AuthOpts -> CredentialsFunc m t -> HawkReq -> m (AuthResult t)
authenticate opts getCreds req@HawkReq{..} = do
  now <- liftIO getPOSIXTime
  case parseServerAuthorizationHeader hrqAuthorization of
    Right sah@AuthorizationHeader{..} -> do
      creds <- getCreds sahId
      return $ case creds of
        Right creds' -> authenticate' now opts creds' req sah
        Left e -> Left (AuthFailUnauthorized e Nothing (Just (headerArtifacts req sah)))
    Left err -> return $ Left err

authenticate' :: POSIXTime -> AuthOpts -> (Credentials, t)
              -> HawkReq -> AuthorizationHeader -> AuthResult t
authenticate' now opts (creds, t) hrq@HawkReq{..} sah@AuthorizationHeader{..} = do
  let arts = headerArtifacts hrq sah
      doCheck = authResult creds arts t
      doCheckExp = authResultExp now creds arts t
      mac = serverMac creds arts HawkHeader
  if mac `constEqBytes` sahMac then do
    doCheck $ checkPayloadHash (scAlgorithm creds) sahHash hrqPayload
    doCheck $ checkNonce (saCheckNonce opts) (scKey creds) sahNonce sahTs
    doCheckExp $ checkExpiration now (saTimestampSkew opts) sahTs
    doCheck $ Right ()
    else Left (AuthFailUnauthorized "Bad mac" (Just creds) (Just arts))

-- | Maps auth status into the more detailed success/failure type
authResult :: Credentials -> HeaderArtifacts -> t
           -> Either String a -> Either AuthFail (AuthSuccess t)
authResult c a t (Right _) = Right (AuthSuccess c a t)
authResult c a _ (Left e)  = Left (AuthFailUnauthorized e (Just c) (Just a))

-- fixme: refactor with authResult and doCheck
authResultExp :: POSIXTime -> Credentials -> HeaderArtifacts -> t
           -> Either String a -> Either AuthFail (AuthSuccess t)
authResultExp _ c a t (Right _) = Right (AuthSuccess c a t)
authResultExp now c a _ (Left e)  = Left (AuthFailStaleTimeStamp e now c a)

-- | Constructs artifacts bundle out of the request.
headerArtifacts :: HawkReq -> AuthorizationHeader -> HeaderArtifacts
headerArtifacts HawkReq{..} AuthorizationHeader{..} =
  HeaderArtifacts hrqMethod hrqHost hrqPort hrqUrl
    sahId sahTs sahNonce sahMac sahHash sahExt sahApp sahDlg

-- | Verifies the payload hash as a separate step after other things
-- have been check. This is useful when the request body is streamed
-- for example.
authenticatePayload :: AuthSuccess t -> PayloadInfo -> Either String ()
authenticatePayload (AuthSuccess c a _) p =
  checkPayloadHash (scAlgorithm c) (shaHash a) (Just p)


-- | Generates a suitable @Server-Authorization@ header to send back
-- to the client. Credentials and artifacts would be provided by a
-- previous call to 'authenticateRequest' (or 'authenticate').
--
-- If a payload is supplied, its hash will be included in the header.
header :: AuthResult t -> Maybe PayloadInfo -> (Status, Header)
header (Right a) p = (ok200, (hServerAuthorization, headerSuccess a p))
header (Left e) _ = (status e, (hWWWAuthenticate, headerFail e))
  where
    status (AuthFailBadRequest _ _)       = badRequest400
    status (AuthFailUnauthorized _ _ _)   = unauthorized401
    status (AuthFailStaleTimeStamp _ _ _ _) = unauthorized401

headerSuccess :: AuthSuccess t -> Maybe PayloadInfo -> ByteString
headerSuccess (AuthSuccess creds arts _) payload = hawkHeaderString (catMaybes parts)
  where
    parts :: [Maybe (ByteString, ByteString)]
    parts = [ Just ("mac", mac)
            , fmap ((,) "hash") hash
            , fmap ((,) "ext") ext]
    hash = calculatePayloadHash (scAlgorithm creds) <$> payload
    ext = escapeHeaderAttribute <$> (shaExt arts)
    mac = serverMac creds arts HawkResponse

serverMac :: Credentials -> HeaderArtifacts -> HawkType -> ByteString
serverMac Credentials{..} HeaderArtifacts{..} =
  calculateMac scAlgorithm scKey
    shaTimestamp shaNonce shaMethod shaResource shaHost shaPort

headerFail :: AuthFail -> ByteString
headerFail (AuthFailBadRequest e _) = hawkHeaderError e []
headerFail (AuthFailUnauthorized e _ _) = hawkHeaderError e []
headerFail (AuthFailStaleTimeStamp e now creds artifacts) = timestampMessage e now creds

hawkHeaderError :: String -> [(ByteString, ByteString)] -> ByteString
hawkHeaderError e ps = hawkHeaderString (("error", S8.pack e):ps)

timestampMessage :: String -> POSIXTime -> Credentials -> ByteString
timestampMessage e now creds = hawkHeaderError e parts
  where
    parts = [ ("ts", (S8.pack . show . floor) now)
            , ("tsm", calculateTsMac (scAlgorithm creds) now)
            ]

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
  , sahExt   :: Maybe ExtData    -- ^ optional extra data to verify
  , sahApp   :: Maybe Text       -- ^ optional oz application id
  , sahDlg   :: Maybe Text       -- ^ optional oz delegate
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
    (decodeUtf8 <$> authAttrMaybe m "app")
    (decodeUtf8 <$> authAttrMaybe m "dlg")

----------------------------------------------------------------------------
-- Bewit parsing

data Bewit = Bewit
             { bewitId  :: Text
             , bewitExp :: POSIXTime
             , bewitMac :: ByteString
             , bewitExt :: ByteString
             } deriving Show

-- | Parses an bewit query string value in the format
-- @id\exp\mac\ext@. The delimiter @'\'@ is used as because it is a
-- reserved header attribute character.
decodeBewit :: ByteString -> Either String Bewit
decodeBewit s = decode s >>= fourParts >>= bewit
  where
    decode = fmap (S8.split '\\') . fixMsg . b64urldec
    fourParts [a, b, c, d] = Right (a, b, c, d)
    fourParts _            = Left "Invalid bewit structure"
    bewit = justRight "Invalid bewit structure" . bewit'
    bewit' (id, exp, mac, ext) = Bewit <$> decodeId id
                                 <*> readTsMaybe exp
                                 <*> pure mac <*> pure ext
    fixMsg = mapLeft (const "Invalid bewit encoding")
    decodeId = rightMay . decodeUtf8'

----------------------------------------------------------------------------
