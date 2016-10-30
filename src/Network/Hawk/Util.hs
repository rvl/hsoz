module Network.Hawk.Util
       ( parseHostnamePort
       , parseHeader
       , AuthAttrs
       , AuthScheme
       , authAttr
       , authAttrMaybe
       , readTs
       , readTsMaybe
       ) where

import           Control.Applicative              ((<|>))
import           Data.Attoparsec.ByteString.Char8
import           Data.ByteString                  (ByteString)
import qualified Data.ByteString.Char8            as S8
import           Data.CaseInsensitive             (CI)
import qualified Data.CaseInsensitive             as CI
import qualified Data.Map                         as M
import           Data.Monoid                      ((<>))
import           Data.Text                        (Text)
import           Data.Text.Encoding               (decodeUtf8)
import           Data.Time.Clock.POSIX

import           Network.Hawk.Common
import           Network.Hawk.Types

parseHeader :: [ByteString] -> (AuthAttrs -> Either String hdr) -> ByteString -> Either String (AuthScheme, hdr)
parseHeader keys hdr = parseOnly (hawkAuthParser keys hdr)

type AuthAttrs = M.Map ByteString ByteString
type AuthScheme = CI ByteString

hawkAuthParser :: [ByteString] -> (AuthAttrs -> Either String hdr) -> Parser (AuthScheme, hdr)
hawkAuthParser keys parseHdrs = do
  s <- scheme
  m <- authParser keys
  endOfInput
  case parseHdrs m of
    Right h -> return (s, h)
    Left a  -> fail a

authAttrMaybe :: AuthAttrs -> ByteString -> Maybe ByteString
authAttrMaybe m a = M.lookup a m

authAttr :: AuthAttrs -> ByteString -> Either String ByteString
authAttr m a = case authAttrMaybe m a of
  Just v  -> Right v
  Nothing -> Left $ S8.unpack ("Missing \"" <> a <> "\" attribute")

authParser :: [ByteString] -> Parser AuthAttrs
authParser keys = M.fromList <$> attrs (parseKeys keys)

scheme :: Parser AuthScheme
scheme = (CI.mk <$> stringCI "Hawk") <* skipSpace

attrs :: Parser ByteString -> Parser [(ByteString, ByteString)]
attrs key = (attr key <* skipSpace) `sepBy` (char8 ',' >> skipSpace)

attr :: Parser ByteString -> Parser (ByteString, ByteString)
attr key = (,) <$> key <*> (char8 '=' *> val)

parseKeys :: [ByteString] -> Parser ByteString
parseKeys = choice . map string

val :: Parser ByteString
val = q *> takeTill ((==) '"') <* q
      where q = char8 '"'

readTs :: ByteString -> Either String POSIXTime
readTs = toEither "Invalid timestamp" . readTsMaybe
  where
    toEither _ (Just a) = Right a
    toEither e Nothing  = Left e

-- | Hawk timestamps/bewit expirations are in seconds since the epoch,
-- unlike iron ttls and expiry.
readTsMaybe :: ByteString -> Maybe POSIXTime
readTsMaybe = fmap fromInteger . (>>= check) . S8.readInteger
  where
    -- there should be no left-overs from integer parse
    check (i, rest) = if S8.null rest then Just i else Nothing

parseHostnamePort :: ByteString -> (ByteString, Maybe Int)
parseHostnamePort hp = case parseOnly hostnamePort hp of
  Right r -> r
  Left _  -> ("", Nothing)

-- fixme: not sure whether to allow junk text after port

hostnamePort :: Parser (ByteString, Maybe Int)
hostnamePort = (,) <$> hostname <*> port

hostname :: Parser ByteString
hostname = takeTill ((==) ':')

port :: Parser (Maybe Int)
port = (Just <$> (char8 ':' *> decimal <* endOfInput)) <|> pure Nothing
