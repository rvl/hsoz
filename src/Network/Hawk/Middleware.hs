-- | Middlewares which can be used to add Hawk authentication to a
-- "Network.Wai" 'Network.Wai.Application'.
--
-- The authentication result is stored in a 'Data.Vault.Lazy.Vault'.
--
-- Note that 'Network.Wai.ifRequest' can be used to conditionally
-- apply these middlewares.

module Network.Hawk.Middleware
  ( hawkAuth
  , bewitAuth
  , VerifyPayload(..)
  ) where

import Data.Text (Text)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy.Char8 as L8
import Network.Wai
import           Network.HTTP.Types        (badRequest400, unauthorized401)
import           Network.HTTP.Types.Header (Header, hContentType, hWWWAuthenticate)

import qualified Data.Vault.Lazy as V

import qualified Network.Hawk.Server as Hawk
import qualified Network.Hawk.Server.Types as Hawk

-- | Whether the middleware should verify the payload hash by reading
-- the entire request body. 'Network.Hawk.Server.authenticatePayload'
-- can be used to verify the payload at a later stage.
data VerifyPayload = DontVerifyPayload -- ^ Ignore payload hash.
                   | VerifyPayload -- ^ Read request body and check payload hash.
  deriving (Show, Eq)

-- | Authenticates requests with Hawk according to the provided
-- options and credentials.
hawkAuth :: Hawk.AuthReqOpts -> VerifyPayload -> Hawk.CredentialsFunc IO t -> Middleware
hawkAuth opts vp c = genHawkAuth $ \req -> do
  payload <- case vp of
               DontVerifyPayload -> pure Nothing
               VerifyPayload -> Just <$> lazyRequestBody req
  Hawk.authenticateRequest opts c req payload

-- | Authenticates @GET@ requests with the Hawk bewit scheme,
-- according to the provided options and credentials.
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
      -- fixme: insert Server-Authorization header
      app req' respond
    Left f -> respond $ failResponse f

failResponse :: Hawk.AuthFail -> Response
failResponse f = responseLBS status [(hContentType, plain), hdr] msg
  where
    (status, hdr) = Hawk.header (Left f) (Just payload)
    msg = L8.pack (Hawk.authFailMessage f)
    plain = "text/plain"
    payload = Hawk.PayloadInfo plain msg
