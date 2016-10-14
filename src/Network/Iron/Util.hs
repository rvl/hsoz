module Network.Iron.Util
  ( b64
  , urlSafeBase64
  , fixedTimeEq
  ) where

import           Crypto.Hash
import           Data.ByteArray          (ByteArrayAccess)
import qualified Data.ByteArray.Encoding as B (Base (..), convertToBase)
import           Data.ByteString         (ByteString)
import qualified Data.ByteString         as BS (pack, unpack)
import qualified Data.ByteString.Char8   as S8

-- | Shorthand for encode in Base64.
b64 :: ByteArrayAccess a => a -> ByteString
b64 = B.convertToBase B.Base64

-- | Fixes up a Base64 encoded string so that it's more convenient to
-- include in URLs. The padding @=@ signs are removed, and the
-- characters @+@ and @/@ are replaced with @-@ and @_@.
urlSafeBase64 :: ByteString -> ByteString
urlSafeBase64 = S8.filter (/= '=') . S8.map (tr '+' '-' . tr '/' '_')
  where
    tr a b c = if c == a then b else c

-- | Compare bytestrings in such a way that unequal bytestrings take
-- the same time to compare as equal bytestrings (assuming they have
-- the same length).
fixedTimeEq :: ByteString -> ByteString -> Bool
-- fixme: actually test the timing
-- fixme: also use securemem ffi version
fixedTimeEq a b = foldr (&&) True $ zipWith (==) (BS.unpack a) (BS.unpack b)
