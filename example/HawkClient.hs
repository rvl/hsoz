module HawkClient where

import           Control.Exception         as E
import           Control.Lens
import           Control.Monad             (void)
import           Data.ByteString           (ByteString)
import qualified Data.ByteString.Char8     as S8
import qualified Data.ByteString.Lazy      as BL
import           Data.Either               (isRight)
import qualified Data.Map                  as M
import qualified Data.Text                 as T
import           Data.Text.Encoding        (decodeUtf8, encodeUtf8)
import           Network.HTTP.Client       (HttpException (..))
import           Network.HTTP.Types.Header (hAuthorization)
import           Network.Wreq

import           Common
import           Network.Hawk
import qualified Network.Hawk.Client       as Hawk

clientMain :: IO ()
clientMain = void $ clientAuth creds uri -- `E.catch` handler
  where
    uri = "http://localhost:8000/resource/1?b=1&a=2"
    creds = Hawk.Credentials "dh37fgj492je" sharedKey (HawkAlgo SHA256)
    handler e@(StatusCodeException s _ _)
      | s ^. statusCode == 401 = putStrLn "Unauthorized"
      | otherwise              = throwIO e

clientAuth :: Hawk.Credentials -> T.Text -> IO Bool
clientAuth creds uri = do
  hdr <- Hawk.header uri "GET" creds Nothing (Just "some-app-data")
  let opts = defaults & header hAuthorization .~ [Hawk.hdrField hdr]
  r <- getWith opts (T.unpack uri)
  let body = r ^. responseBody -- & BL.toStrict & decodeUtf8
  res <- Hawk.authenticate r creds (Hawk.hdrArtifacts hdr) (Just body) Hawk.ServerAuthorizationRequired
  putStrLn $ (show $ r ^. responseStatus . statusCode) ++ ": "
    ++ (S8.unpack $ BL.toStrict body)
    ++ (if isRight res then " (valid)" else " (invalid)")
  return $ isRight res
