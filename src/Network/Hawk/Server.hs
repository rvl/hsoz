{-# LANGUAGE RecordWildCards #-}

-- | These are functions for checking authenticated requests and
-- sending authenticated responses.
--
-- For an easy way to add Hawk authentication to a "Network.Wai"
-- 'Network.Wai.Application', use the "Network.Hawk.Middleware"
-- module.

module Network.Hawk.Server
       ( -- * Authenticating "Network.Wai" requests
         authenticateRequest
       , authenticatePayload
       , authenticateBewitRequest
       , AuthReqOpts(..)
       -- ** Generic variants
       , authenticate
       , authenticateBewit
       , authenticateMessage
       , HawkReq(..)
       -- ** Options for authentication
       , AuthOpts(..)
       , Credentials(..)
       , CredentialsFunc
       , NonceFunc
       , Nonce
       , def
       -- ** Authentication result
       , AuthResult
       , AuthResult'(..)
       , AuthSuccess(..)
       , AuthFail(..)
       , authValue
       , authFailMessage
       -- * Authenticated reponses
       , header
       , module Network.Hawk.Types
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
import           Data.Maybe                (fromMaybe)
import           Data.Monoid               ((<>))
import           Data.Text                 (Text)
import qualified Data.Text                 as T
import           Data.Text.Encoding        (decodeUtf8, decodeUtf8')
import           Control.Error.Safe        (rightMay)
import           Data.Default              (Default(..))
import           Data.Time.Clock           (NominalDiffTime)
import           Data.Time.Clock.POSIX
import           Network.HTTP.Types.Header (Header, hAuthorization, hContentType)
import           Network.HTTP.Types.Method (Method, methodGet, methodPost)
import           Network.HTTP.Types.URI    (renderQuery)
import           Network.Wai               (Request, rawPathInfo,
                                            rawQueryString, queryString,
                                            remoteHost, requestMethod,
                                            requestHeaderHost, requestHeaders)

import           Network.Hawk.Types
import           Network.Hawk.Internal
import           Network.Hawk.Internal.Server
import           Network.Hawk.Internal.Server.Types
import           Network.Hawk.Internal.Server.Header
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
  , saBewitParam     :: ByteString
    -- ^ Query parameter for bewit authentication. Defaults to @"bewit"@.
  , saOpts           :: AuthOpts  -- ^ Parameters for 'authenticate'
  }

-- | Bundle of parameters for 'authenticate'.
data AuthOpts = AuthOpts
  { saCheckNonce          :: NonceFunc
    -- ^ Nonce validation function. Defaults to a function which
    -- always returns @True@.
  , saTimestampSkew       :: NominalDiffTime
    -- ^ Number of seconds of permitted clock skew for incoming
    -- timestamps. Defaults to 60 seconds.  Provides a +/- skew which
    -- means actual allowed window is double the number of seconds.
  , saLocaltimeOffset :: NominalDiffTime
    -- ^ Offsets the local time. Defaults to 0.
  }

instance Default AuthReqOpts where
  def = AuthReqOpts Nothing Nothing Nothing "bewit" def

instance Default AuthOpts where
  def = AuthOpts (\x t n -> return True) 60 0

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

authenticateBewit' (creds, t) req bewit
  | mac `constEqBytes` (bewitMac bewit) = Right (AuthSuccess creds arts t)
  | otherwise = Left (AuthFailUnauthorized "Bad mac" (Just creds) (Just arts))
  where
    arts = bewitArtifacts req bewit
    mac = serverMac creds arts HawkBewit

bewitArtifacts :: HawkReq -> Bewit -> HeaderArtifacts
bewitArtifacts HawkReq{..} Bewit{..} =
  HeaderArtifacts hrqMethod hrqHost hrqPort hrqBewitlessUrl
    "" bewitExp "" "" Nothing (Just bewitExt) Nothing Nothing

-- | Checks the @Authorization@ header of a 'Wai.Request' according to
-- the "bewit" scheme. See "Network.Hawk.URI" for a description of
-- that scheme.
authenticateBewitRequest :: MonadIO m => AuthReqOpts -> CredentialsFunc m t
                         -> Request -> m (AuthResult t)
authenticateBewitRequest opts creds req =
  authenticateBewit (saOpts opts) creds (hawkReq opts req Nothing)

-- | Checks the @Authorization@ header of a request ('HawkReq')
-- according to the "bewit" scheme.
authenticateBewit :: MonadIO m => AuthOpts -> CredentialsFunc m t
                  -> HawkReq -> m (AuthResult t)
authenticateBewit opts getCreds hrq@HawkReq{..} = do
  now <- getServerTime opts
  case checkBewit hrq now of
    Right bewit -> do
      mcreds <- mapLeft unauthorized <$> getCreds (bewitId bewit)
      return $ case mcreds of
        Right creds -> authenticateBewit' creds hrq bewit
        Left e -> undefined
    Left e -> return (Left e)

  where
    checkBewit :: HawkReq -> POSIXTime -> Either AuthFail Bewit
    checkBewit HawkReq{..} now = do
      checkMethod hrqMethod
      checkLength hrqUrl
      encBewit <- checkEmpty hrqBewit
      checkHeader hrqAuthorization
      bewit <- mapLeft unauthorized $ decodeBewit encBewit
      checkAttrs bewit
      checkExpiry bewit now
      return bewit

    -- javascript impl limits query string length to avoid a DoS
    -- attack on string matching
    checkLength url | BS.length url <= urlMaxLength = Right ()
                    | otherwise = Left (badRequest "Resource path exceeds max length")
    urlMaxLength = 4096

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

-- | Current time, with the server time offset applied.
getServerTime :: MonadIO m => AuthOpts -> m POSIXTime
getServerTime AuthOpts{..} = (+ saLocaltimeOffset) <$> liftIO getPOSIXTime

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
  case parseServerAuthorizationHeader hrqAuthorization of
    Right sah -> let arts = headerArtifacts req sah
                 in authenticateBase HawkHeader opts getCreds arts hrqPayload sah
    Left err -> return $ Left err

authenticateMessage :: MonadIO m => AuthOpts -> CredentialsFunc m t
                    -> ByteString -> Maybe Int -> BL.ByteString
                    -> Message -> m (AuthResult t)
authenticateMessage opts getCreds host port msg auth =
  authenticateBase HawkMessage opts getCreds arts payload sah
  where
    arts = msgArts host port auth
    payload = Just (PayloadInfo "" msg)
    sah = msgAuth auth

-- fixme: correspondence between Message and AuthorizationHeader
msgAuth :: Message -> AuthorizationHeader
msgAuth Message{..} = AuthorizationHeader
                      { sahId = msgId
                      , sahTs = msgTimestamp
                      , sahNonce = msgNonce
                      , sahMac = msgMac
                      , sahHash = Just msgHash
                      , sahExt = Nothing
                      , sahApp = Nothing
                      , sahDlg = Nothing
                      }

msgArts :: ByteString -> Maybe Int -> Message -> HeaderArtifacts
msgArts host port Message{..} = HeaderArtifacts
                                { haMethod = "GET"
                                , haHost = host
                                , haPort = port
                                , haResource = ""
                                , haId = ""
                                , haTimestamp = msgTimestamp
                                , haNonce = msgNonce
                                , haMac = ""
                                , haHash = Just msgHash
                                , haExt = Nothing
                                , haApp = Nothing
                                , haDlg = Nothing
                      }

authenticateBase :: MonadIO m => HawkType -> AuthOpts -> CredentialsFunc m t
                 -> HeaderArtifacts -> Maybe PayloadInfo
                 -> AuthorizationHeader -> m (AuthResult t)
authenticateBase ty opts getCreds arts payload sah@AuthorizationHeader{..} = do
  now <- getServerTime opts
  creds <- getCreds sahId
  case creds of
    Right creds' -> do
      nonce <- liftIO $ saCheckNonce opts (scKey (fst creds')) sahTs sahNonce
      return $ authenticate' ty now opts creds' nonce arts payload sah
    Left e -> return $ Left (AuthFailUnauthorized e Nothing (Just arts))

authenticate' :: HawkType -> POSIXTime -> AuthOpts -> (Credentials, t) -> Bool
              -> HeaderArtifacts -> Maybe PayloadInfo -> AuthorizationHeader
              -> AuthResult t
authenticate' ty now opts (creds, t) nonce arts payload sah@AuthorizationHeader{..} = do
  let doCheck = authResult creds arts t
      doCheckExp = authResultExp now creds arts t
      mac = serverMac creds arts ty
  if mac `constEqBytes` sahMac then do
    doCheck $ checkPayloadHash (scAlgorithm creds) sahHash payload
    doCheck $ checkNonce nonce
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
  checkPayloadHash (scAlgorithm c) (haHash a) (Just p)


checkNonce :: Bool -> Either String ()
checkNonce True  = Right ()
checkNonce False = Left "Invalid nonce"

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
