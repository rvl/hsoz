{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- | Consider this module to be internal, and don't import directly.

module Network.Hawk.Internal.Server.Types where

import Data.ByteString           (ByteString)
import Data.Text                 (Text)
import Data.Time.Clock.POSIX     (POSIXTime)
import Network.HTTP.Types.Method (Method)
import GHC.Generics
import Data.Default
import Network.Hawk.Types

-- | The end result of authentication.
type AuthResult t = AuthResult' (AuthSuccess t)
-- | An intermediate result of authentication.
type AuthResult' r = Either AuthFail r

-- | Authentication can fail in multiple ways. This type includes the
-- information necessary to generate a suitable response for the
-- client. In the case of a stale timestamp, the client may try
-- another authenticated request.
data AuthFail = AuthFailBadRequest String (Maybe HeaderArtifacts)
              | AuthFailUnauthorized String (Maybe Credentials) (Maybe HeaderArtifacts)
              | AuthFailStaleTimeStamp String POSIXTime Credentials HeaderArtifacts
              deriving (Show, Eq)

-- | Successful authentication produces a set of credentials and
-- "artifacts". Also included in the result is the result of
-- 'CredentialsFunc'.
data AuthSuccess t = AuthSuccess Credentials HeaderArtifacts t

instance Show t => Show (AuthSuccess t) where
  show (AuthSuccess c a t) = "AuthSuccess " ++ show t

instance Eq t => Eq (AuthSuccess t) where
  AuthSuccess c a t == AuthSuccess d b u = c == d && a == b && t == u

-- | The result of an 'AuthSuccess'.
authValue :: AuthSuccess t -> t
authValue (AuthSuccess _ _ t) = t

-- | The error message from an 'AuthFail'.
authFailMessage :: AuthFail -> String
authFailMessage (AuthFailBadRequest e _) = e
authFailMessage (AuthFailUnauthorized e _ _) = e
authFailMessage (AuthFailStaleTimeStamp e _ _ _) = e

----------------------------------------------------------------------------

-- | A package of values containing the attributes of a HTTP request
-- which are relevant to Hawk authentication.
data HawkReq = HawkReq
  { hrqMethod        :: Method
  , hrqUrl           :: ByteString
  , hrqHost          :: ByteString
  , hrqPort          :: Maybe Int
  , hrqAuthorization :: ByteString
  , hrqPayload       :: Maybe PayloadInfo
  , hrqBewit         :: Maybe ByteString
  , hrqBewitlessUrl  :: ByteString
  } deriving Show

instance Default HawkReq where
  def = HawkReq "GET" "/" "localhost" Nothing "" Nothing Nothing ""

-- | The set of data the server requires for key-based hash
-- verification of artifacts.
data Credentials = Credentials
  { scKey       :: Key -- ^ Key
  , scAlgorithm :: HawkAlgo -- ^ HMAC
  } deriving (Show, Eq, Generic)

-- | A user-supplied callback to get credentials from a client
-- identifier.
type CredentialsFunc m t = ClientId -> m (Either String (Credentials, t))

-- | User-supplied nonce validation function. It should return 'True'
-- if the nonce is valid.
--
-- Checking nonces can prevent request replay attacks. If the same key
-- and nonce have already been seen, then the request can be denied.
type NonceFunc = Key -> POSIXTime -> Nonce -> IO Bool

-- | The nonce should be a short sequence of random ASCII characters.
type Nonce = ByteString
