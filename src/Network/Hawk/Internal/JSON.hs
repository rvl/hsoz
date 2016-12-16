{-# LANGUAGE RecordWildCards           #-}
module Network.Hawk.Internal.JSON where

import qualified Data.ByteString.Char8 as S8
import Data.Aeson
import Data.Aeson.Types (typeMismatch)
import Network.Hawk.Types (MessageAuth(..))

instance ToJSON MessageAuth where
  toJSON MessageAuth{..} = object
                           [ "id"    .= msgId
                           , "ts"    .= msgTimestamp
                           , "nonce" .= S8.unpack msgNonce
                           , "hash"  .= S8.unpack msgHash
                           , "mac"   .= S8.unpack msgMac
                           ]

instance FromJSON MessageAuth where
  parseJSON (Object v) = MessageAuth
                         <$> v .: "id"
                         <*> v .: "ts"
                         <*> v .:* "nonce"
                         <*> v .:* "hash"
                         <*> v .:* "mac"
    where v .:* k = S8.pack <$> (v .: k)
  parseJSON invalid = typeMismatch "MessageAuth" invalid
