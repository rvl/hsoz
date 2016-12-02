module HawkClient where

import           Control.Exception         as E
import           Control.Lens
import           Control.Monad             (void)
import           Data.ByteString           (ByteString)
import qualified Data.ByteString.Lazy.Char8 as L8
import qualified Data.ByteString.Lazy      as BL
import           Data.Either               (isRight)
import qualified Data.Map                  as M
import qualified Data.Text                 as T
import           Data.Text.Encoding        (decodeUtf8, encodeUtf8)
import           Network.HTTP.Client       (HttpException (..))
import           Network.HTTP.Types.Header (hAuthorization)
import           Network.HTTP.Types.Status (statusCode)
import           Network.HTTP.Simple

import           Common
import           Network.Hawk
import qualified Network.Hawk.Client       as Hawk

uri = "http://localhost:8000/resource/1?b=1&a=2"
creds = Hawk.Credentials "dh37fgj492je" sharedKey (HawkAlgo SHA256)
ext = Just "some-app-data"
payload = PayloadInfo "" ""

clientMain :: IO ()
clientMain = do
  (arts, req) <- Hawk.signWithPayload' creds ext payload uri
  r <- httpLBS req

  res <- Hawk.authenticate r creds arts
         (Just $ getResponseBody r)
         Hawk.ServerAuthorizationRequired

  printResponse (isRight res) r

printResponse :: Bool -> Response BL.ByteString -> IO ()
printResponse valid r = putStrLn $ (show $ getResponseStatusCode r) ++ ": "
                        ++ L8.unpack (getResponseBody r)
                        ++ (if valid then " (valid)" else " (invalid)")

clientMainSimple :: IO ()
clientMainSimple = ((withHawk httpLBS) uri >>= printResponse True) `E.catches` handlers
  where
    withHawk = Hawk.withHawkPayload creds ext payload Hawk.ServerAuthorizationRequired
    handlers = [E.Handler handleHTTP, E.Handler handleHawk]
    handleHTTP e@(StatusCodeException s _ _)
      | statusCode s == 401 = putStrLn "Unauthorized"
      | otherwise           = throwIO e
    handleHawk (Hawk.HawkServerAuthorizationException e)
      = putStrLn "Invalid server response"
