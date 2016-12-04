module HawkServer where

import           Control.Monad.IO.Class    (liftIO)
import           Data.ByteString           (ByteString)
import qualified Data.ByteString.Char8     as S8
import qualified Data.ByteString.Lazy      as BL
import qualified Data.ByteString.Lazy.Char8 as L8
import           Data.Default
import qualified Data.Map                  as M
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
import qualified Network.Hawk.Server.Nonce as Hawk

serverMain :: IO ()
serverMain = do
  opts <- Hawk.nonceOptsReq 60
  run 8000 (app opts)

auth :: ClientId -> IO (Either String (Credentials, Text))
auth id = return $ Right (Credentials sharedKey (HawkAlgo SHA256), "Steve")

app :: Hawk.AuthReqOpts -> Application
app opts req respond = do
  payload <- lazyRequestBody req
  res <- Hawk.authenticateRequest opts auth req (Just payload)
  respond $ case res of
    Right (Hawk.AuthSuccess creds artifacts user) -> let
      ext = decodeUtf8 <$> haExt artifacts
      payload = textPayload $ "Hello " <> user <> maybe "" (" " <>) ext
      (ok, autho) = Hawk.header res (Just payload)
      in responseLBS ok [payloadCt payload, autho] (payloadData payload)
    Left f -> let
      (status, hdr) = Hawk.header res Nothing
      msg = case f of
        AuthFailBadRequest e _         -> e
        AuthFailUnauthorized e _ _     -> "Shoosh!"
        AuthFailStaleTimeStamp e _ _ _ -> e
      in responseLBS status [plain, hdr] (L8.pack msg)

textPayload :: Text -> PayloadInfo
textPayload = PayloadInfo (snd plain) . BL.fromStrict . encodeUtf8

payloadCt :: PayloadInfo -> Header
payloadCt (PayloadInfo ct _) = (hContentType, ct)

plain :: Header
plain = (hContentType, "text/plain")
