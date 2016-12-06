module BewitServer where

import           Data.Text                 (Text)
import           Data.Default              (def)
import           Network.HTTP.Types.Status (status200)
import           Network.Wai
import           Network.Wai.Handler.Warp

import           Common
import qualified Network.Hawk.Server       as Hawk
import           Network.Hawk.Types
import           Network.Hawk.Middleware   (bewitAuth)

serverMain :: IO ()
serverMain = run 8000 (middleware app)

auth :: ClientId -> IO (Either String (Hawk.Credentials, Text))
auth _ = return $ Right (Hawk.Credentials sharedKey (HawkAlgo SHA256), "Steve")

middleware :: Middleware
middleware = bewitAuth def auth

app :: Application
app req respond = respond $ responseLBS status200 [] "hello"
