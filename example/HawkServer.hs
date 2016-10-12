module HawkServer where

import Network.Wai
import Network.Wai.Handler.Warp
import Network.HTTP.Types.Status
import Network.HTTP.Types.Header
import Data.Text (Text)
import qualified Data.Text as T
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as S8
import qualified Data.Map as M
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import Data.Monoid
import Data.Monoid
import Control.Monad.IO.Class (liftIO)

import Network.Hawk
import qualified Network.Hawk.Server as Hawk
import Common

serverMain :: IO ()
serverMain = run 8000 app

auth :: ClientId -> IO (Either String ServerCredentials)
auth id = return $ Right $ ServerCredentials sharedKey (HawkAlgo SHA256) "Steve" Nothing Nothing

app :: Application
app req respond = do
  let opts = Hawk.defaultAuthReqOpts
  payload <- lazyRequestBody req
  res <- Hawk.authenticateRequest opts auth req (Just payload)
  respond $ case res of
    Right (Hawk.AuthSuccess creds artifacts) -> do
      let ext = decodeUtf8 <$> shaExt artifacts
      let payload = textPayload $ "Hello " <> scUser creds <> maybe "" (" " <>) ext
      let autho = Hawk.header creds artifacts (Just payload)
      responseLBS status200 [payloadCt payload, autho] (payloadData payload)
    Left (Hawk.AuthFailBadRequest e _) -> responseLBS badRequest400 [] (lazyString e)
    Left (Hawk.AuthFailUnauthorized _ _ _) -> responseLBS unauthorized401 [plain] "Shoosh!"
    Left (Hawk.AuthFailStaleTimeStamp e creds artifacts) -> do
      let autho = Hawk.header creds artifacts Nothing
      responseLBS unauthorized401 [plain, autho] (lazyString e)

lazyString :: String -> BL.ByteString
lazyString = BL.fromStrict . S8.pack

textPayload :: Text -> PayloadInfo
textPayload = PayloadInfo (snd plain) . BL.fromStrict . encodeUtf8

payloadCt :: PayloadInfo -> Header
payloadCt (PayloadInfo ct _) = (hContentType, ct)

plain :: Header
plain = (hContentType, "text/plain")
