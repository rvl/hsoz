{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Network.Hawk.Server.Types
  ( AuthResult
  , AuthResult'(..)
  , AuthFail(..)
  , AuthSuccess(..)
  , ServerCredentials(..)
  , ServerAuthArtifacts(..)
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
data AuthFail = AuthFailBadRequest String (Maybe ServerAuthArtifacts)
              | AuthFailUnauthorized String (Maybe ServerCredentials) (Maybe ServerAuthArtifacts)
              | AuthFailStaleTimeStamp String ServerCredentials ServerAuthArtifacts
              deriving Show

-- | The result of a successful authentication is a set of credentials
-- and "artifacts".
data AuthSuccess t = AuthSuccess ServerCredentials t ServerAuthArtifacts

----------------------------------------------------------------------------

-- | The set of data the server requires for key-based hash
-- verification of artifacts.
data ServerCredentials = ServerCredentials
  { scKey       :: Key -- ^ Key
  , scAlgorithm :: HawkAlgo -- ^ HMAC
  -- fixme: remove these:
  -- , scUser      :: Text
  -- , scApp       :: Maybe Text  -- fixme: maybe not Maybe
  -- , scDlg       :: Maybe ByteString
  } deriving (Show, Generic)

-- | Artifacts are the attributes which are included in the
-- verification. The terminology (and spelling) come from the original
-- Javascript implementation of Hawk.
data ServerAuthArtifacts = ServerAuthArtifacts
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
type CredentialsFunc m t = ClientId -> m (Either String (ServerCredentials, t))
