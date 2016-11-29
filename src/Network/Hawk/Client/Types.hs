{-# LANGUAGE DeriveGeneric             #-}

-- | Consider this module to be internal, and don't import directly.

module Network.Hawk.Client.Types where

import           Data.Text (Text)
import           Data.ByteString (ByteString)
import           Data.Time.Clock.POSIX (POSIXTime)
import           GHC.Generics
import           Network.HTTP.Types.Method (Method)

import           Network.Hawk.Common
import           Network.Hawk.Types

-- | ID and key used for encrypting Hawk @Authorization@ header.
data Credentials = Credentials
  { ccId        :: ClientId
  , ccKey       :: Key
  , ccAlgorithm :: HawkAlgo
  } deriving (Show, Generic)

-- | Struct for attributes which will be encoded in the Hawk
-- @Authorization@ header. The term "artifacts" comes from the
-- original Javascript implementation of Hawk.
data HeaderArtifacts = HeaderArtifacts
  { chaTimestamp :: POSIXTime
  , chaNonce     :: ByteString
  , chaMethod    :: Method
  , chaHost      :: ByteString
  , chaPort      :: Maybe Int
  , chaResource  :: ByteString
  , chaHash      :: Maybe ByteString
  , chaExt       :: Maybe ByteString -- fixme: this should be json value
  , chaApp       :: Maybe Text -- ^ app id, for oz
  , chaDlg       :: Maybe Text -- ^ delegated-by app id, for oz
  } deriving Show

-- | The result of Hawk header generation.
data Header = Header
  { hdrField     :: Authorization  -- ^ Value of @Authorization@ header.
  , hdrArtifacts :: HeaderArtifacts  -- ^ Not sure if this is needed by users.
  } deriving (Show, Generic)


data SplitURL = SplitURL
  { urlHost :: ByteString
  , urlPort :: Maybe Int
  , urlPath :: ByteString
  } deriving (Show, Generic)
