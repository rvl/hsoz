-- | Miscellaneous shortcut functions, mostly for internal use.

module Network.Iron.Util (
  -- * Base64
    b64
  , b64dec
  , b64url
  , b64urldec
  -- * Time parsing
  , parseExpMsec
  -- * Error handling
  , justRight
  , rightJust
  ) where

import           Data.ByteArray          (ByteArrayAccess)
import qualified Data.ByteArray.Encoding as B (Base (..), convertToBase, convertFromBase)
import           Data.ByteString         (ByteString)
import qualified Data.ByteString.Char8   as S8
import           Data.Monoid             ((<>))
import           Data.Time.Clock         (NominalDiffTime)
import           Text.Read               (readMaybe)

-- | Shorthand for encode in Base64.
b64 :: ByteArrayAccess a => a -> ByteString
b64 = B.convertToBase B.Base64

b64url :: ByteArrayAccess a => a -> ByteString
b64url = B.convertToBase B.Base64URLUnpadded

b64dec :: ByteArrayAccess a => a -> Either String ByteString
b64dec = B.convertFromBase B.Base64

b64urldec :: ByteString -> Either String ByteString
b64urldec = B.convertFromBase B.Base64URLUnpadded

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


-- | Converts 'Either' to 'Maybe'.
rightJust :: Either e a -> Maybe a
rightJust (Right a) = Just a
rightJust _ = Nothing

-- | Converts 'Maybe' to 'Either'.
justRight :: e -> Maybe a -> Either e a
justRight _ (Just a) = Right a
justRight e Nothing = Left e
