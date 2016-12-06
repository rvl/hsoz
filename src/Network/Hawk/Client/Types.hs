{-# LANGUAGE DeriveGeneric #-}

-- | Consider this module to be internal, and don't import directly.

module Network.Hawk.Client.Types where

import           Data.Text (Text)
import           Data.ByteString (ByteString)
import           Data.Time.Clock.POSIX (POSIXTime)
import           GHC.Generics
import           Network.HTTP.Types.Method (Method)

import           Network.Hawk.Internal (Authorization)
import           Network.Hawk.Types

-- | ID and key used for encrypting Hawk @Authorization@ header.
data Credentials = Credentials
  { ccId        :: ClientId
  , ccKey       :: Key
  , ccAlgorithm :: HawkAlgo
  } deriving (Show, Generic)

-- | The result of Hawk header generation.
data Header = Header
  { hdrField     :: Authorization  -- ^ Value of @Authorization@ header.
  , hdrArtifacts :: HeaderArtifacts  -- ^ The parameters used to generate the header.
  } deriving (Show, Generic)

data SplitURL = SplitURL
  { urlHost :: ByteString
  , urlPort :: Maybe Int
  , urlPath :: ByteString
  } deriving (Show, Generic)
