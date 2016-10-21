module HawkServer where

import           Control.Monad.IO.Class    (liftIO)
import           Data.ByteString           (ByteString)
import qualified Data.ByteString.Char8     as S8
import qualified Data.ByteString.Lazy      as BL
import qualified Data.Map                  as M
import           Data.Monoid
import           Data.Monoid
import           Data.Text                 (Text)
import qualified Data.Text                 as T
import           Data.Text.Encoding        (decodeUtf8, encodeUtf8)
import           Network.HTTP.Types.Header
import           Network.HTTP.Types.Status
import           Network.Wai
import           Network.Wai.Handler.Warp

import           Common
import           Network.Hawk.Server.Types
import qualified Network.Hawk.Server       as Hawk

serverMain :: IO ()
serverMain = run 8000 app

auth :: ClientId -> IO (Either String (Credentials, Text))
auth id = return $ Right (Credentials sharedKey (HawkAlgo SHA256), "Steve")

app :: Application
app req respond = do
  let opts = Hawk.defaultAuthReqOpts
  payload <- lazyRequestBody req
  res <- Hawk.authenticateRequest opts auth req (Just payload)
  respond $ case res of
    Right (Hawk.AuthSuccess creds artifacts user) -> do
      let ext = decodeUtf8 <$> shaExt artifacts
      let payload = textPayload $ "Hello " <> user <> maybe "" (" " <>) ext
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
