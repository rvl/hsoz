{-# LANGUAGE DeriveGeneric             #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards           #-}

-- | Functions for making Hawk-authenticated request headers and
-- verifying responses from the server.

module Network.Hawk.Client
       ( header
       , headerOz
       , getBewit
       , authenticate
       , ServerAuthorizationCheck(..)
       , Credentials(..)
       , Header(..)
       , Authorization
       , HeaderArtifacts
       , module Network.Hawk.Types
       ) where

import           Control.Monad             (join)
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
import           GHC.Generics
import           Network.HTTP.Types.Header (hContentType, hWWWAuthenticate, HeaderName)
import           Network.HTTP.Types.Method (Method)
import           Network.HTTP.Types.URI    (extractPath)
import           Network.HTTP.Client       (Response, responseHeaders)
import           Network.Socket            (PortNumber, SockAddr (..))
import           URI.ByteString            (authorityHost, authorityPort,
                                            hostBS, laxURIParserOptions,
                                            parseURI, portNumber, uriAuthority)

import           Network.Hawk.Common
import           Network.Hawk.Types
import           Network.Hawk.Util
import           Network.Iron.Util

-- | ID and key used for encrypting Hawk @Authorization@ header.
data Credentials = Credentials
  { ccId        :: ClientId
  , ccKey       :: Key
  , ccAlgorithm :: HawkAlgo
  } deriving (Show, Generic)

-- | Struct for attributes which will be encoded in the Hawk
-- @Authorization@ header. The term "artifacts" comes from the
-- original Javascript implementation of Hawk.
data HeaderArtifacts = HeaderArtifacts
  { chaTimestamp :: POSIXTime
  , chaNonce     :: ByteString
  , chaMethod    :: Method
  , chaHost      :: ByteString
  , chaPort      :: Maybe Int
  , chaResource  :: ByteString
  , chaHash      :: Maybe ByteString
  , chaExt       :: Maybe ByteString -- fixme: this should be json value
  , chaApp       :: Maybe Text -- ^ app id, for oz
  , chaDlg       :: Maybe Text -- ^ delegated-by app id, for oz
  } deriving Show

-- | The result of Hawk header generation.
data Header = Header
  { hdrField     :: Authorization  -- ^ Value of @Authorization@ header.
  , hdrArtifacts :: HeaderArtifacts  -- ^ Not sure if this is needed by users.
  } deriving (Show, Generic)

-- | Generates the Hawk authentication header for a request.
header :: Text -> Method -> Credentials -> Maybe PayloadInfo -> Maybe Text -> IO Header
header url method creds payload ext = headerBase url method creds payload ext Nothing Nothing

-- | Generates the Hawk authentication header for an Oz request. Oz
-- requires another attribute -- the application id. It also has an
-- optional delegated-by attribute, which is the application id of the
-- application the credentials were directly issued to.
headerOz :: Text -> Method -> Credentials -> Maybe PayloadInfo -> Maybe Text
         -> Text -> Maybe Text -> IO Header
headerOz url method creds payload ext app dlg = headerBase url method creds payload ext (Just app) dlg

headerBase :: Text -> Method -> Credentials -> Maybe PayloadInfo -> Maybe Text
           -> Maybe Text -> Maybe Text -> IO Header
headerBase url method creds payload ext app dlg = do
  now <- getPOSIXTime
  nonce <- genNonce
  let hash = calculatePayloadHash (ccAlgorithm creds) <$> payload
  let art = clientHeaderArtifacts now nonce method (encodeUtf8 url) hash (encodeUtf8 <$> ext) app dlg
  let auth = clientHawkAuth creds art
  return $ Header auth art

clientHeaderArtifacts :: POSIXTime -> ByteString -> Method -> ByteString
                      -> Maybe ByteString -> Maybe ByteString
                      -> Maybe Text -> Maybe Text
                      -> HeaderArtifacts
clientHeaderArtifacts now nonce method url hash ext app dlg = case splitUrl url of
  Just (SplitURL host port resource) ->
    HeaderArtifacts now nonce method host port resource hash ext app dlg
  Nothing ->
    HeaderArtifacts now nonce method "" Nothing url hash ext app dlg

clientHawkAuth :: Credentials -> HeaderArtifacts -> ByteString
clientHawkAuth creds arts@HeaderArtifacts{..} = hawkHeaderString (hawkHeaderItems items)
  where
    items = [ ("id", (Just . encodeUtf8 . ccId) creds)
            , ("ts", (Just . S8.pack . show . round) chaTimestamp)
            , ("nonce", Just chaNonce)
            , ("hash", chaHash)
            , ("ext", chaExt)
            , ("mac", Just $ clientMac HawkHeader creds arts)
            , ("app", encodeUtf8 <$> chaApp)
            , ("dlg", encodeUtf8 <$> chaDlg)
            ]

clientMac :: HawkType -> Credentials -> HeaderArtifacts -> ByteString
clientMac h Credentials{..} HeaderArtifacts{..} =
  calculateMac ccAlgorithm ccKey
      chaTimestamp chaNonce chaMethod chaResource chaHost chaPort h

hawkHeaderItems :: [(ByteString, Maybe ByteString)] -> [(ByteString, ByteString)]
hawkHeaderItems = catMaybes . map pull
  where
    pull (k, Just v)  = Just (k, v)
    pull (k, Nothing) = Nothing

data SplitURL = SplitURL
  { urlHost :: ByteString
  , urlPort :: Maybe Int
  , urlPath :: ByteString
  } deriving (Show, Generic)

splitUrl :: ByteString -> Maybe SplitURL
splitUrl url = SplitURL <$> host <*> pure port <*> path
  where
    p = either (const Nothing) uriAuthority (parseURI laxURIParserOptions url)
    host = fmap (hostBS . authorityHost) p
    port :: Maybe Int
    port = fmap portNumber $ p >>= authorityPort
    path = fmap (const (extractPath url)) p

genNonce :: IO ByteString
genNonce = do
  g <- getSystemDRG
  return $ fst $ withRandomBytes g 10 B64.encode

-- | Whether the client wants to check the received
-- @Server-Authorization@ header depends on the application.
data ServerAuthorizationCheck = ServerAuthorizationNotRequired
                              | ServerAuthorizationRequired
                              deriving Show

-- | Validates the server response.
authenticate :: Response BL.ByteString -> Credentials -> HeaderArtifacts
                      -> Maybe BL.ByteString -> ServerAuthorizationCheck
                      -> IO (Either String ())
authenticate r creds artifacts payload saCheck = do
  now <- getPOSIXTime
  return $ clientAuthenticate' r creds artifacts payload saCheck now

clientAuthenticate' :: Response BL.ByteString -> Credentials -> HeaderArtifacts
                       -> Maybe BL.ByteString -> ServerAuthorizationCheck
                       -> POSIXTime -> Either String ()
clientAuthenticate' r creds artifacts payload saCheck now = do
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
--
-- fixme: implement checks for both of the above conditions
checkWwwAuthenticateHeader :: Credentials -> ByteString -> Either String POSIXTime
checkWwwAuthenticateHeader creds w = do
  WwwAuthenticateHeader{..} <- parseWwwAuthenticateHeader w
  let tsm = calculateTsMac wahTs creds
  if wahTsm `constEqBytes` tsm
    then Right wahTs
    else Left "Invalid server timestamp hash"

calculateTsMac :: POSIXTime -> Credentials -> ByteString
calculateTsMac = undefined  -- fixme: achtung minen

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

-- | Represents the `WWW-Authenticate` header which the server uses to
-- respond when the client isn't authenticated.
data WwwAuthenticateHeader = WwwAuthenticateHeader
                             { wahTs    :: POSIXTime  -- ^ server's timestamp
                             , wahTsm   :: ByteString -- ^ timestamp mac
                             , wahError :: ByteString
                             } deriving Show

-- | Represents the `Server-Authorization` header which the server
-- sends back to the client.
data ServerAuthorizationReplyHeader = ServerAuthorizationReplyHeader
                                      { sarhMac  :: ByteString
                                      , sarhHash :: Maybe ByteString -- ^ optional payload hash
                                      , sarhExt  :: Maybe ByteString
                                      } deriving Show

parseWwwAuthenticateHeader :: ByteString -> Either String WwwAuthenticateHeader
parseWwwAuthenticateHeader = fmap snd . parseHeader wwwKeys wwwAuthHeader

parseServerAuthorizationReplyHeader :: ByteString -> Either String ServerAuthorizationReplyHeader
parseServerAuthorizationReplyHeader = fmap snd . parseHeader serverKeys serverAuthReplyHeader

wwwKeys = ["tsm", "ts", "error"]
serverKeys = ["mac", "ext", "hash"]

wwwAuthHeader :: AuthAttrs -> Either String WwwAuthenticateHeader
wwwAuthHeader m = do
  credTs <- join (readTs <$> authAttr m "ts")
  credTsm <- authAttr m "tsm"
  credError <- authAttr m "error"
  return $ WwwAuthenticateHeader credTs credTsm credError

serverAuthReplyHeader :: AuthAttrs -> Either String ServerAuthorizationReplyHeader
serverAuthReplyHeader m = do
  mac <- authAttr m "mac"
  let hash = authAttrMaybe m "hash"
  let ext = authAttrMaybe m "ext"
  return $ ServerAuthorizationReplyHeader mac hash ext

-- | Generate a bewit value for a given URI.
getBewit :: Credentials -> NominalDiffTime -> Maybe ByteString -> NominalDiffTime
         -> ByteString -> IO (Maybe ByteString)
-- fixme: ext is a json value i think
-- fixme: javascript version supports deconstructed parsed uri objects
-- fixme: not much point having two time interval arguments?
getBewit creds ttl ext offset uri = do
  exp <- fmap (+ (ttl + offset)) getPOSIXTime
  return $ bewit exp <$> splitUrl uri
  where
    bewit exp = encode . clientMac HawkBewit creds . make
      where
        make (SplitURL host port resource) =
          HeaderArtifacts exp "" "GET" host port resource Nothing ext Nothing Nothing
        encode = b64url . S8.intercalate "\\" . parts
        parts mac = [ encodeUtf8 . ccId $ creds
                    , S8.pack . show . round $ exp
                    , mac, fromMaybe "" ext ]
