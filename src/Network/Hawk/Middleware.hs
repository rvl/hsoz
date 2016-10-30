module Network.Hawk.Middleware
  ( hawkAuth
  , bewitAuth
  ) where

import Data.Text (Text)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy.Char8 as L8
import Network.Wai
import           Network.HTTP.Types        (badRequest400, unauthorized401)
import           Network.HTTP.Types.Header (Header, hContentType, hWWWAuthenticate)

import qualified Data.Vault.Lazy as V

import qualified Network.Hawk.Server as Hawk

data VerifyPayload = DontVerifyPayload | VerifyPayload
  deriving (Show, Eq)

hawkAuth :: Hawk.AuthReqOpts -> VerifyPayload -> Hawk.CredentialsFunc IO t -> Middleware
hawkAuth opts vp c = genHawkAuth $ \req -> do
  payload <- case vp of
               DontVerifyPayload -> pure Nothing
               VerifyPayload -> Just <$> lazyRequestBody req
  Hawk.authenticateRequest opts c req payload

bewitAuth :: Hawk.AuthReqOpts -> Hawk.CredentialsFunc IO t -> Middleware
bewitAuth opts creds = genHawkAuth $ Hawk.authenticateBewit opts creds

genHawkAuth :: (Request -> IO (Hawk.AuthResult t)) -> Application -> Application
genHawkAuth auth app req respond = do
  k <- V.newKey
  res <- auth req
  case res of
    Right s -> do
      let vault' = V.insert k s (vault req)
          req' = req { vault = vault' }
      app req' respond
    Left f -> respond $ case f of
      Hawk.AuthFailBadRequest e _ ->
        responseLBS badRequest400 [plain, wwwAuthHawk] (L8.pack e)
      Hawk.AuthFailUnauthorized e _ _ ->
        responseLBS unauthorized401 [plain, wwwAuthHawk] (L8.pack e)
      Hawk.AuthFailStaleTimeStamp e creds artifacts ->
        let autho = Hawk.header creds artifacts Nothing
        in responseLBS unauthorized401 [plain, autho] (L8.pack e)

plain, wwwAuthHawk :: Header
plain = (hContentType, "text/plain")
wwwAuthHawk = (hWWWAuthenticate, "Hawk")

hawkAuth' :: Hawk.AuthReqOpts -> VerifyPayload -> Hawk.CredentialsFunc IO t -> Middleware
hawkAuth' opts vp c app req respond = do
  k <- V.newKey
  payload <- case vp of
               DontVerifyPayload -> pure Nothing
               VerifyPayload -> Just <$> lazyRequestBody req
  res <- Hawk.authenticateRequest opts c req payload
  case res of
    Right s -> do
      let vault' = V.insert k s (vault req)
          req' = req { vault = vault' }
      app req' respond
    Left f -> respond $ case f of
      Hawk.AuthFailBadRequest e _ ->
        responseLBS badRequest400 [plain, wwwAuthHawk] (L8.pack e)
      Hawk.AuthFailUnauthorized e _ _ ->
        responseLBS unauthorized401 [plain, wwwAuthHawk] (L8.pack e)
      Hawk.AuthFailStaleTimeStamp e creds artifacts ->
        let autho = Hawk.header creds artifacts Nothing
        in responseLBS unauthorized401 [plain, autho] (L8.pack e)

bewitAuth' :: Hawk.AuthReqOpts -> Hawk.CredentialsFunc IO t -> Application -> Application
bewitAuth' opts creds app req respond = do
  k <- V.newKey
  res <- Hawk.authenticateBewit opts creds req
  case res of
    Right s -> do
      let vault' = V.insert k s (vault req)
          req' = req { vault = vault' }
      app req' respond
    Left f -> respond $ case f of
      Hawk.AuthFailBadRequest e _ ->
        responseLBS badRequest400 [plain, wwwAuthHawk] (L8.pack e)
      Hawk.AuthFailUnauthorized e _ _ ->
        responseLBS unauthorized401 [plain, wwwAuthHawk] (L8.pack e)
      Hawk.AuthFailStaleTimeStamp e creds artifacts ->
        let autho = Hawk.header creds artifacts Nothing
        in responseLBS unauthorized401 [plain, autho] (L8.pack e)
