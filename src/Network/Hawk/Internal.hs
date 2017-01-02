{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ExistentialQuantification #-}

-- | These functions are intended only to be used internally by this
-- package. No API stability is guaranteed for this module. If you see
-- functions here which you believe should be promoted to a stable
-- API, please contact the author.

module Network.Hawk.Internal
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
import           Data.Text.Encoding        (encodeUtf8)
import           Data.Byteable             (constEqBytes)
import           Data.Char                 (toLower, toUpper)
import           Data.List                 (intercalate)
import           Data.Monoid               ((<>))
import           Data.Maybe                (fromMaybe)
import           Data.Time.Clock.POSIX
import           Network.HTTP.Types.Header (HeaderName)
import           Network.HTTP.Types.Method (Method)

import           Network.Hawk.Algo
import           Network.Hawk.Internal.Types

data HawkType = HawkHeader
              | HawkMessage
              | HawkBewit
              | HawkResponse
              | HawkPayload
              | HawkTs
              deriving (Show, Eq)

-- | The value of an @Authorization@ header.
type Authorization = ByteString

-- | Generates a @hawk.1.@ string with the given attributes,
-- calculates its HMAC, and returns the Base64 encoded hash.
calculateMac :: HawkAlgoCls a => a -> Key -> HawkType -> HeaderArtifacts -> ByteString
calculateMac a key ty arts = hawkMac a key $ hawk1String ty arts

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

hawk1String :: HawkType -> HeaderArtifacts -> ByteString
-- corresponds to generateNormalizedString in crypto.js
hawk1String t HeaderArtifacts{..} = newlines $
  [ hawk1Header t
  , S8.pack . show . round $ haTimestamp
  , haNonce
  , S8.map toUpper haMethod
  , haResource
  , S8.map toLower haHost
  , maybe "" (S8.pack . show) haPort
  , fromMaybe "" haHash
  , maybe "" escapeExt haExt
  ] ++ map encodeUtf8 (oz haApp haDlg)
  where
    oz Nothing _ = []
    oz (Just a) (Just d) = [a, d]
    oz (Just a) Nothing = [a]

hawk1Payload :: PayloadInfo -> ByteString
hawk1Payload (PayloadInfo contentType body) = newlines [ hawk1Header HawkPayload
                                                       , contentType
                                                       , BL.toStrict body ]

hawk1Ts :: POSIXTime -> ByteString
hawk1Ts ts = newlines [hawk1Header HawkTs, nowSecs ts]
  where nowSecs = S8.pack . show . floor

hawk1Header :: HawkType -> ByteString
hawk1Header t = "hawk.1." <> hawkType t

hawkType :: HawkType -> ByteString
hawkType HawkHeader   = "header"
hawkType HawkMessage  = "message"
hawkType HawkBewit    = "bewit"
hawkType HawkResponse = "response"
hawkType HawkPayload  = "payload"
hawkType HawkTs       = "ts"

newlines :: [ByteString] -> ByteString
newlines lines = BS.intercalate (S8.singleton '\n') (lines ++ [""])

escapeExt :: ExtData -> ExtData
escapeExt = sub '\n' "\\n" . sub '\\' "\\\\"
  where
    sub s r = BS.intercalate r . S8.split s

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

-- | The name of the authorization header which the server provides to
-- the client.
hServerAuthorization :: HeaderName
hServerAuthorization = "Server-Authorization"
