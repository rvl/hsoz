module HawkClient where

import           Control.Exception         as E
import           Control.Lens
import           Control.Monad             (void)
import           Data.ByteString           (ByteString)
import qualified Data.ByteString.Char8     as S8
import qualified Data.ByteString.Lazy.Char8 as L8
import qualified Data.ByteString.Lazy      as BL
import           Data.Either               (isRight)
import qualified Data.Map                  as M
import qualified Data.Text                 as T
import           Data.Text.Encoding        (decodeUtf8, encodeUtf8)
import           Network.HTTP.Client       (HttpException (..))
import           Network.HTTP.Types.Header (ResponseHeaders, hAuthorization, hWWWAuthenticate)
import           Network.HTTP.Types.Status (Status(..))
import           Network.HTTP.Simple
import           Data.Monoid               ((<>))

import           Common
import           Network.Hawk
import qualified Network.Hawk.Client       as Hawk

uri = "http://localhost:8000/resource/1?b=1&a=2"
creds = Hawk.Credentials "dh37fgj492je" sharedKey (HawkAlgo SHA256)
ext = Just "some-app-data"
payload = PayloadInfo "" ""

clientMainSimple :: IO ()
clientMainSimple = do
  (arts, req) <- Hawk.sign creds ext (Just payload) 0 uri
  r <- httpLBS req

  res <- Hawk.authenticate r creds arts
         (Just $ getResponseBody r)
         Hawk.ServerAuthorizationRequired

  printResponse (isRight res) r

printResponse :: Bool -> Response BL.ByteString -> IO ()
printResponse valid r = putStrLn $ (show $ getResponseStatusCode r) ++ ": "
                        ++ L8.unpack (getResponseBody r)
                        ++ (if valid then " (valid)" else " (invalid)")

clientMain :: IO ()
clientMain = (withHawk httpLBS uri >>= printResponse True) `E.catches` handlers
  where
    withHawk = Hawk.withHawk creds ext (Just payload) Hawk.ServerAuthorizationRequired
    handlers = [E.Handler handleHTTP, E.Handler handleHawk]
    handleHTTP e@(StatusCodeException s hdrs _)
      | statusCode s == 401 = S8.putStrLn $ errMessage s hdrs
      | otherwise           = throwIO e
    handleHawk (Hawk.HawkServerAuthorizationException e)
      = putStrLn $ "Invalid server response: " ++ e

errMessage :: Status -> ResponseHeaders -> ByteString
errMessage s hdrs = statusMessage s <> maybe "" (": " <>) authHdr
  where authHdr = lookup hWWWAuthenticate hdrs
