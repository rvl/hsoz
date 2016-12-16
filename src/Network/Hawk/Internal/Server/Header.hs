module Network.Hawk.Internal.Server.Header
  ( header
  , headerSuccess
  , headerFail
  , timestampMessage
  ) where

import           Data.ByteString           (ByteString)
import qualified Data.ByteString.Char8     as S8
import           Data.Time.Clock.POSIX
import           Data.Maybe                (catMaybes)

import Network.HTTP.Types.Status (Status, ok200, badRequest400, unauthorized401)
import Network.HTTP.Types.Header (Header, hWWWAuthenticate)

import Network.Hawk.Types
import Network.Hawk.Internal.Server
import Network.Hawk.Internal.Server.Types
import Network.Hawk.Internal

-- | Generates a suitable @Server-Authorization@ header to send back
-- to the client. Credentials and artifacts would be provided by a
-- previous call to 'authenticateRequest' (or 'authenticate').
--
-- If a payload is supplied, its hash will be included in the header.
header :: AuthResult t -> Maybe PayloadInfo -> (Status, Header)
header (Right a) p = (ok200, (hServerAuthorization, headerSuccess a p))
header (Left e) _ = (status e, (hWWWAuthenticate, headerFail e))
  where
    status (AuthFailBadRequest _ _)       = badRequest400
    status (AuthFailUnauthorized _ _ _)   = unauthorized401
    status (AuthFailStaleTimeStamp _ _ _ _) = unauthorized401

headerSuccess :: AuthSuccess t -> Maybe PayloadInfo -> ByteString
headerSuccess (AuthSuccess creds arts _) payload = hawkHeaderString (catMaybes parts)
  where
    parts :: [Maybe (ByteString, ByteString)]
    parts = [ Just ("mac", mac)
            , fmap ((,) "hash") hash
            , fmap ((,) "ext") ext]
    hash = calculatePayloadHash (scAlgorithm creds) <$> payload
    ext = escapeHeaderAttribute <$> haExt arts
    mac = serverMac creds HawkResponse (arts { haHash = hash })

headerFail :: AuthFail -> ByteString
headerFail (AuthFailBadRequest e _) = hawkHeaderError e []
headerFail (AuthFailUnauthorized e _ _) = hawkHeaderError e []
headerFail (AuthFailStaleTimeStamp e now creds artifacts) = timestampMessage e now creds

hawkHeaderError :: String -> [(ByteString, ByteString)] -> ByteString
hawkHeaderError e ps = hawkHeaderString (("error", S8.pack e):ps)

timestampMessage :: String -> POSIXTime -> Credentials -> ByteString
timestampMessage e now creds = hawkHeaderError e parts
  where
    parts = [ ("ts", (S8.pack . show . floor) now)
            , ("tsm", calculateTsMac (scAlgorithm creds) now)
            ]
