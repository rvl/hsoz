-- | Internal module.

module Network.Hawk.Internal.Client.HeaderParser
  ( parseWwwAuthenticateHeader
  , parseServerAuthorizationHeader
  , WwwAuthenticateHeader(..)
  , ServerAuthorizationHeader(..)
  ) where

import Data.ByteString (ByteString)
import Data.Time.Clock.POSIX     (POSIXTime)
import Network.Hawk.Types
import Control.Monad (join)

import Network.Hawk.Util

parseWwwAuthenticateHeader :: ByteString -> Either String WwwAuthenticateHeader
parseWwwAuthenticateHeader = fmap snd . parseHeader wwwKeys wwwAuthHeader

parseServerAuthorizationHeader :: ByteString -> Either String ServerAuthorizationHeader
parseServerAuthorizationHeader = fmap snd . parseHeader serverKeys serverAuthReplyHeader

wwwKeys = ["error", "tsm", "ts"]
serverKeys = ["mac", "ext", "hash"]

wwwAuthHeader :: AuthAttrs -> Either String WwwAuthenticateHeader
wwwAuthHeader m = do
  err <- authAttr m "error"
  case authAttrMaybe m "ts" of
    Just ts' -> do
      ts <- readTs ts'
      tsm <- authAttr m "tsm"
      return $ WwwAuthenticateHeader err (Just ts) (Just tsm)
    Nothing -> return $ WwwAuthenticateHeader err Nothing Nothing

serverAuthReplyHeader :: AuthAttrs -> Either String ServerAuthorizationHeader
serverAuthReplyHeader m = do
  mac <- authAttr m "mac"
  let hash = authAttrMaybe m "hash"
  let ext = authAttrMaybe m "ext"
  return $ ServerAuthorizationHeader mac hash ext
