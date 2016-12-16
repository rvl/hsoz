{-# LANGUAGE RecordWildCards #-}

module Network.Hawk.Internal.Server where

import Data.ByteString (ByteString)

import Network.Hawk.Types
import Network.Hawk.Internal.Server.Types
import Network.Hawk.Internal

serverMac :: Credentials -> HawkType -> HeaderArtifacts -> ByteString
serverMac Credentials{..} = calculateMac scAlgorithm scKey
