{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Network.Hawk.Server.Types
  ( AuthResult
  , AuthResult'(..)
  , AuthFail(..)
  , AuthSuccess(..)
  , Credentials(..)
  , HeaderArtifacts(..)
  , CredentialsFunc
  , module Network.Hawk.Types
  ) where

import           Data.ByteString           (ByteString)
import           Data.Text                 (Text)
import           Data.Time.Clock.POSIX     (POSIXTime)
import           Network.HTTP.Types.Method (Method)
import           GHC.Generics

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
              | AuthFailStaleTimeStamp String Credentials HeaderArtifacts
              deriving Show

-- | Successful authentication produces a set of credentials and
-- "artifacts". Also included in the result is the result of
-- 'CredentialsFunc'.
data AuthSuccess t = AuthSuccess Credentials HeaderArtifacts t

----------------------------------------------------------------------------

-- | The set of data the server requires for key-based hash
-- verification of artifacts.
data Credentials = Credentials
  { scKey       :: Key -- ^ Key
  , scAlgorithm :: HawkAlgo -- ^ HMAC
  } deriving (Show, Generic)

-- | HeaderArtifacts are the attributes which are included in the
-- verification. The terminology (and spelling) come from the original
-- Javascript implementation of Hawk.
data HeaderArtifacts = HeaderArtifacts
  { shaMethod    :: Method
  , shaHost      :: ByteString
  , shaPort      :: Maybe Int
  , shaResource  :: ByteString
  --, shaHeader  :: ServerAuthorizationHeader
  , shaId        :: ClientId
  , shaTimestamp :: POSIXTime
  , shaNonce     :: ByteString
  , shaMac       :: ByteString
  , shaHash      :: Maybe ByteString
  , shaExt       :: Maybe ByteString
  , shaApp       :: Maybe Text
  , shaDlg       :: Maybe ByteString
  } deriving Show

-- | A user-supplied callback to get credentials from a client
-- identifier.
type CredentialsFunc m t = ClientId -> m (Either String (Credentials, t))
