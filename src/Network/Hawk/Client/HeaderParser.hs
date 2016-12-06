-- | Internal module.

module Network.Hawk.Client.HeaderParser
  ( parseWwwAuthenticateHeader
  , parseServerAuthorizationReplyHeader
  , WwwAuthenticateHeader(..)
  , ServerAuthorizationReplyHeader(..)
  ) where

import Data.ByteString (ByteString)
import Data.Time.Clock.POSIX     (POSIXTime)
import Network.Hawk.Client.Types
import Control.Monad (join)

import Network.Hawk.Util

-- | Represents the @WWW-Authenticate@ header which the server uses to
-- respond when the client isn't authenticated.
data WwwAuthenticateHeader = WwwAuthenticateHeader
                             { wahTs    :: POSIXTime  -- ^ server's timestamp
                             , wahTsm   :: ByteString -- ^ timestamp mac
                             , wahError :: ByteString
                             } deriving Show

-- | Represents the @Server-Authorization@ header which the server
-- sends back to the client.
data ServerAuthorizationReplyHeader = ServerAuthorizationReplyHeader
                                      { sarhMac  :: ByteString
                                      , sarhHash :: Maybe ByteString -- ^ optional payload hash
                                      , sarhExt  :: Maybe ByteString
                                      } deriving Show

parseWwwAuthenticateHeader :: ByteString -> Either String WwwAuthenticateHeader
parseWwwAuthenticateHeader = fmap snd . parseHeader wwwKeys wwwAuthHeader

parseServerAuthorizationReplyHeader :: ByteString -> Either String ServerAuthorizationReplyHeader
parseServerAuthorizationReplyHeader = fmap snd . parseHeader serverKeys serverAuthReplyHeader

wwwKeys = ["tsm", "ts", "error"]
serverKeys = ["mac", "ext", "hash"]

wwwAuthHeader :: AuthAttrs -> Either String WwwAuthenticateHeader
wwwAuthHeader m = do
  credTs <- join (readTs <$> authAttr m "ts")
  credTsm <- authAttr m "tsm"
  credError <- authAttr m "error"
  return $ WwwAuthenticateHeader credTs credTsm credError

serverAuthReplyHeader :: AuthAttrs -> Either String ServerAuthorizationReplyHeader
serverAuthReplyHeader m = do
  mac <- authAttr m "mac"
  let hash = authAttrMaybe m "hash"
  let ext = authAttrMaybe m "ext"
  return $ ServerAuthorizationReplyHeader mac hash ext
