{-# LANGUAGE ExistentialQuantification #-}

module Network.Hawk.Common
       ( calculateMac
       , escapeHeaderAttribute
       , hawkHeaderString
       , calculateTsMac
       , calculatePayloadHash
       , checkPayloadHash
       , checkPayloadHashMaybe
       , hServerAuthorization
       , HawkType(..)
       , Authorization
       ) where

import           Crypto.Hash.Algorithms    (HashAlgorithm, SHA1 (..),
                                            SHA256 (..))
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import           Data.ByteString.Builder   (byteString, charUtf8,
                                            toLazyByteString)
import qualified Data.ByteString.Char8     as S8
import qualified Data.ByteString.Lazy      as BL
import           Data.Byteable             (constEqBytes)
import           Data.Char                 (toLower, toUpper)
import           Data.List                 (intercalate)
import           Data.Monoid               ((<>))
import           Data.Time.Clock.POSIX
import           Network.HTTP.Types.Header (HeaderName)
import           Network.HTTP.Types.Method (Method)

import           Network.Hawk.Types

data HawkType = HawkHeader | HawkBewit | HawkResponse
              deriving (Show, Eq)

-- | The value of an @Authorization@ header.
type Authorization = ByteString

-- | Generates a @hawk.1.@ string with the given attributes,
-- calculates its HMAC, and returns the Base64 encoded hash.
calculateMac :: HawkAlgoCls a => a -> Key
             -> POSIXTime -> ByteString -> Method
             -> ByteString -> ByteString -> Maybe Int
             -> HawkType -> ByteString
calculateMac a key ts nonce method path host port hawkType = hawkMac a key str
  where
    str = hawk1String hawkType ts nonce method path host port

-- This would be the same as Hoek.escapeHeaderAttribute, which
-- replaces double quotes and backslashes so that the string can be
-- put in a HTTP header. I'm not sure if it's needed if WAI already
-- quotes header values.
escapeHeaderAttribute :: ByteString -> ByteString
escapeHeaderAttribute = id

checkPayload :: HawkAlgoCls a => Maybe ByteString -> a -> ContentType -> BL.ByteString -> Either String ()
checkPayload (Just hash) algo ct payload = if good then Right () else Left "Bad payload hash"
  where
    good = hash `constEqBytes` (calculatePayloadHash algo payloadInfo)
    payloadInfo = PayloadInfo ct payload
checkPayload Nothing algo ct payload = Left "Missing required payload hash"

checkPayloadHashMaybe :: HawkAlgoCls a => a -> Maybe ByteString -> Maybe PayloadInfo -> Maybe Bool
checkPayloadHashMaybe _    _           Nothing        = Just True
checkPayloadHashMaybe _    Nothing     (Just _)       = Nothing
checkPayloadHashMaybe algo (Just hash) (Just payload) = Just (hash == calculatePayloadHash algo payload)

checkPayloadHash :: HawkAlgoCls a => a -> Maybe ByteString -> Maybe PayloadInfo -> Either String ()
checkPayloadHash algo hash payload = case checkPayloadHashMaybe algo hash payload of
  Nothing    -> Left "Missing response hash attribute"
  Just False -> Left "Bad response payload mac"
  Just True  -> Right ()

hawk1String :: HawkType -> POSIXTime -> ByteString -> Method -> ByteString -> ByteString -> Maybe Int -> ByteString
-- corresponds to generateNormalizedString in crypto.js
-- fixme: ext and payload hash
hawk1String t ts nonce method resource host port = newlines $
  [ "hawk.1." <> hawkType t
  , S8.pack . show . round $ ts
  , nonce
  , S8.map toUpper method
  , resource
  , S8.map toLower host
  , maybe "" (S8.pack . show) port
  , payloadHash
  ] ++ ext
  where
      ext = []
      payloadHash = ""

hawk1Payload :: PayloadInfo -> ByteString
hawk1Payload (PayloadInfo contentType body) = newlines [ "hawk.1.payload"
                                                       , contentType
                                                       , BL.toStrict body ]

newlines :: [ByteString] -> ByteString
newlines lines = BS.intercalate (S8.singleton '\n') (lines ++ [""])

hawkType :: HawkType -> ByteString
hawkType HawkHeader   = "header"
hawkType HawkBewit    = "bewit"
hawkType HawkResponse = "response"

hawk1Header = hawk1String HawkHeader

-- Generates an @Authorization@ header string of the form:
-- Hawk id="app123", ts="1476130687", nonce="+olvVyT7i8dqkA==",
--   mac="xG9KhUQXjCSWbqNbRI41tI19+fG0upsuDoVbNpt8+K0=", app="app123"
hawkHeaderString :: [(ByteString, ByteString)] -> ByteString
hawkHeaderString items = BL.toStrict $ toLazyByteString bld
  where
    bld = byteString "Hawk " <> mconcat (intercalate comma $ foldMap q items)
    comma = [byteString ", "]
    q (k, v) = [[byteString k, byteString "=\"", byteString v, byteString "\""]]

calculatePayloadHash :: HawkAlgoCls a => a -> PayloadInfo -> ByteString
-- fixme: maybe convert payload to strict further up the chain, or
-- feed chunks to the hasher
calculatePayloadHash algo payload = hawkHash algo (hawk1Payload payload)

calculateTsMac :: HawkAlgoCls a => a -> POSIXTime -> ByteString
calculateTsMac algo ts = hawkHash algo (hawk1Ts ts)

hawk1Ts :: POSIXTime -> ByteString
hawk1Ts ts = newlines ["hawk.1.ts", nowSecs ts]
  where nowSecs = S8.pack . show . floor

-- | The name of the authorization header which the server provides to
-- the client.
hServerAuthorization :: HeaderName
hServerAuthorization = "Server-Authorization"
