module OzServer where

import           Common
import qualified Data.ByteString.Char8    as S8
import qualified Data.ByteString.Lazy     as BL
import           Data.CaseInsensitive     (original)
import           Data.List                (find)
import           Data.Monoid              ((<>))
import           Data.Text                (Text)
import           Network.HTTP.Types       (hAuthorization)
import           Network.Oz.Application
import           Network.Oz.Types
import           Network.Wai
import           Network.Wai.Handler.Warp

-- fixme: temp
import           Data.Aeson               (Value (..), encode, object, (.=))
import qualified Data.Text                as T
import qualified Network.Hawk.Client      as Hawk

serverMain :: IO ()
serverMain = do
  let opts = defaultOzServerOpts { ozSecret = sharedKey, ozLoadApp = loadApp }
  app <- ozApp opts

  putStrLn "Try this:"
  printCurl (head apps) "http://localhost:8000/oz/app" Nothing

  run 8000 app

-- | Example apps registry
apps = [OzApp "app123" Nothing False sharedKey (Hawk.HawkAlgo Hawk.SHA256)]

-- | Example lookup of an app by id
loadApp :: OzLoadApp
loadApp aid = return $ case find ((== aid) . ozAppId) apps of
                         Just app -> Right app
                         Nothing -> Left ("ozAppId " ++ show aid ++ " not found")

-- | Shows a curl command line with Hawk Authorization header which
-- can be used to access Oz.
printCurl :: OzApp -> Text -> Maybe Value -> IO ()
printCurl (OzApp aid _ _ key algo) url mdata = do
  auth <- Hawk.headerOz url "POST" creds Nothing Nothing aid Nothing
  let authHeader = S8.unpack . fmtHeader . mkHeader $ auth
  putStrLn $ "curl -i -X POST " <> dataArg <> "-H 'Content-Type: application/json' -H '" <> authHeader <> "' " <> T.unpack url
  where
    dataArg = maybe "" (\d -> "--data '" <> S8.unpack d <> "'") (fmap (BL.toStrict . encode) mdata)
    creds = Hawk.Credentials aid key algo
    fmtHeader (h, v) = original h <> ": " <> v
    mkHeader = (,) hAuthorization . Hawk.hdrField
