{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE ExistentialQuantification  #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Network.Hawk.Algo
  ( HawkAlgo(..)
  , HawkAlgoCls(..)
  , Key(..)
  , SHA1(SHA1)
  , SHA256(SHA256)
  , readHawkAlgo
  ) where

import           Crypto.Hash             (Digest (..), hash)
import           Crypto.Hash.Algorithms  (SHA1 (..), SHA256 (..))
import           Crypto.MAC.HMAC         (HMAC, hmac, hmacGetDigest)
import           Data.ByteArray          (ByteArrayAccess)
import qualified Data.ByteArray.Encoding as B (Base (..), convertToBase)
import           Data.ByteString         (ByteString)
import           Data.Char               (toLower)
import           Data.String             (IsString)
import           GHC.Generics
import           Network.Iron.Util       (b64)

-- fixme: decide whether this should be text or bytestring or
-- SecureMem, and whether it should be put into Iron.
-- | A user-supplied password or generated key.
newtype Key = Key ByteString deriving (Show, Generic, ByteArrayAccess, IsString)

-- | The class of HMAC algorithms supported by the Hawk
-- protocol. Users of the 'Network.Hawk' module probably won't
-- directly need this.
class HawkAlgoCls a where
  -- | Calculates the hash of a message. The result is encoded in
  -- Base64.
  hawkHash :: a -> ByteString -> ByteString
  -- | Calculates the hash-based MAC of a message. The result is
  -- encoded in Base64.
  hawkMac :: a -> Key -> ByteString -> ByteString

-- | A wrapper data type representing one of the supported HMAC
-- algorithms. Use @HawkAlgo SHA1@ or @HawkAlgo SHA256@.
data HawkAlgo = forall alg . (HawkAlgoCls alg, Show alg) => HawkAlgo alg

instance HawkAlgoCls HawkAlgo where
  hawkHash (HawkAlgo alg) = hawkHash alg
  hawkMac (HawkAlgo alg) = hawkMac alg

instance Show HawkAlgo where
  show (HawkAlgo a) = map toLower (show a)

instance HawkAlgoCls SHA1 where
  hawkHash _ bs = b64 (hash bs :: Digest SHA1)
  hawkMac _ k bs = b64 $ hmacGetDigest (hmac k bs :: HMAC SHA1)

instance HawkAlgoCls SHA256 where
  hawkHash _ bs = b64 (hash bs :: Digest SHA256)
  hawkMac _ k bs = b64 $ hmacGetDigest (hmac k bs :: HMAC SHA256)

-- | Inverse of 'show', for parsing @"algorithm"@ fields in JSON
-- structures.
readHawkAlgo :: String -> Maybe HawkAlgo
readHawkAlgo a = case map toLower a of
                   "sha1"   -> Just (HawkAlgo SHA1)
                   "sha256" -> Just (HawkAlgo SHA256)
                   _        -> Nothing
