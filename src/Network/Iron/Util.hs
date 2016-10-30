-- | Miscellaneous shortcut functions, mostly for internal use.

module Network.Iron.Util
  ( b64
  , b64dec
  , b64url
  , b64urldec
  , urlSafeBase64
  , unUrlSafeBase64
  , parseExpMsec
  ) where

import           Crypto.Hash
import           Data.ByteArray          (ByteArrayAccess)
import qualified Data.ByteArray.Encoding as B (Base (..), convertToBase, convertFromBase)
import           Data.ByteString         (ByteString)
import qualified Data.ByteString         as BS (pack, unpack)
import qualified Data.ByteString.Char8   as S8
import           Data.Monoid             ((<>))
import           Data.Time.Clock         (NominalDiffTime)
import           Text.Read               (readMaybe)

-- | Shorthand for encode in Base64.
b64 :: ByteArrayAccess a => a -> ByteString
b64 = B.convertToBase B.Base64

b64url :: ByteArrayAccess a => a -> ByteString
b64url = urlSafeBase64 . b64

b64dec :: ByteArrayAccess a => a -> Either String ByteString
b64dec = B.convertFromBase B.Base64

b64urldec :: ByteString -> Either String ByteString
b64urldec = b64dec . unUrlSafeBase64

-- | Fixes up a Base64 encoded string so that it's more convenient to
-- include in URLs. The padding @=@ signs are removed, and the
-- characters @+@ and @/@ are replaced with @-@ and @_@.
urlSafeBase64 :: ByteString -> ByteString
urlSafeBase64 = S8.filter (/= '=') . S8.map (tr '+' '-' . tr '/' '_')
  where
    tr a b c = if c == a then b else c

-- | The inverse of 'urlSafeBase64'.
unUrlSafeBase64 :: ByteString -> ByteString
unUrlSafeBase64 = pad . S8.map (tr '-' '+' . tr '_' '/')
  where
    tr a b c = if c == a then b else c
    pad s = s <> S8.replicate (S8.length s `mod` 4) '='

-- | Reads a positive integer time value in milliseconds. This is for
-- parsing ttls or expiry times written as milliseconds since the unix
-- epoch.
parseExpMsec :: ByteString -> Maybe NominalDiffTime
parseExpMsec = (>>= fromMsec . guard) . readMaybe . S8.unpack
  where
    fromMsec = fmap ((/ 1000) . fromInteger)
    -- ttls must be positive
    guard n | n > 0 = Just n
            | otherwise = Nothing
