module BewitClient where

import           Control.Exception          as E
import           Control.Lens
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Char8      as S8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Network.HTTP.Client        (HttpException (..))
import           Network.HTTP.Simple
import           Data.Monoid

import           Common
import           Network.Hawk
import qualified Network.Hawk.Client        as Hawk

clientMain :: IO ()
clientMain = do
  let uri = "http://localhost:8000/resource/1?b=1&a=2"
      creds = Hawk.Credentials "dh37fgj492je" sharedKey (HawkAlgo SHA256)

  res <- Hawk.getBewit creds 60 Nothing 0 uri
  case res of
    Just bewit -> do
      let uri' = S8.unpack $ uri <> "&bewit=" <> bewit
      r <- httpLBS (parseRequest_ uri')
      print $ getResponseStatusCode r
      L8.putStrLn $ ": " <> getResponseBody r
    Nothing -> putStrLn "Couldn't generate bewit"
