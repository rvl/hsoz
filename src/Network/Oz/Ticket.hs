{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections       #-}

module Network.Oz.Ticket
  ( issueTicket
  , parseTicket
  ) where

import           Control.Monad          (liftM, void)
import           Control.Monad.IO.Class (MonadIO (..), liftIO)
import           Crypto.Random
import           Data.Aeson             (Object (..), Value (..), object,
                                         toJSON)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base64 as B64
import           Data.List              (isInfixOf, nub)
import           Data.Maybe             (catMaybes, fromMaybe)
import           Data.Text              (Text)
import qualified Data.Text              as T
import           Data.Text.Encoding     (decodeUtf8)
import           Data.Time.Clock.POSIX  (POSIXTime, getPOSIXTime)

import           Network.Hawk.Types
import qualified Network.Iron           as Iron
import           Network.Oz.JSON
import           Network.Oz.Types

issueTicket :: MonadIO m => OzApp -> ServerCredentials -> Maybe OzGrant -> Key -> TicketOpts -> m (Maybe OzSealedTicket)
issueTicket app creds mgrant password opts = do
  scope <- leftFail $ checkPassword password >> checkGrant app mgrant
  now <- liftIO getPOSIXTime
  let exp = getExpiry (ticketOptsTicketTtl opts) mgrant now
  let ticket = OzTicket { ozTicketExp = exp
                        , ozTicketApp = ozAppId app
                        , ozTicketUser = ozGrantUser <$> mgrant
                        , ozTicketScope = fromMaybe [] scope
                        , ozTicketGrant = ozGrantId <$> mgrant
                        , ozTicketDelegate = ticketOptsDelegate opts
                        , ozTicketDlg = Nothing  -- fixme: check?
                        }
  liftIO $ generateTicket opts password ticket

  where
    checkPassword (Key p) | BS.null p = Left "Invalid encryption password"
                          | otherwise = Right ()
    checkGrant _ Nothing = Right Nothing
    checkGrant OzApp{..} (Just OzGrant{..}) = checkScopes ozAppScope ozGrantScope -- fixme: what else to check?

    checkScopes :: Maybe OzScope -> Maybe OzScope -> Either String (Maybe OzScope)
    checkScopes (Just app) Nothing = Just <$> checkScope app
    checkScopes (Just app) (Just grant) | isInfixOf grant app = Just <$> checkScope grant
                                        | otherwise = Left "Grant scope is not a subset of the application scope"
    checkScopes Nothing Nothing = Right Nothing

    checkScope :: OzScope -> Either String OzScope
    checkScope scope | any T.null scope = Left "scope includes empty string value"
                     | length (nub scope) /= length scope = Left "scope includes duplicated item"
                     | otherwise = Right scope

    getExpiry ttl mgrant now = maybe id (min . ozGrantExp) mgrant (now + ttl)

leftFail :: Monad m => Either String a -> m a
leftFail (Left e)  = fail e
leftFail (Right a) = return a

randomKey :: TicketOpts -> IO ByteString
randomKey TicketOpts{..} = do
  -- fixme: check that this is seeded properly
  drg <- getSystemDRG
  return (fst $ withRandomBytes drg ticketOptsKeyBytes base64)

base64 :: ByteString -> ByteString
base64 = Iron.urlSafeBase64 . B64.encode

generateTicket :: TicketOpts -> Key -> OzTicket -> IO (Maybe OzSealedTicket)
generateTicket opts@TicketOpts{..} (Key p) t = do
  key <- randomKey opts
  let Object ext = toJSON ticketOptsExt
  let sealed = OzSealedTicket t (Key key) ticketOptsHmacAlgorithm ext ""
  mid <- Iron.sealWith ticketOptsIron (Iron.Password p) sealed
  return (finishSeal ticketOptsExt sealed <$> mid)

-- | Removes the private ext part and adds the ticket ID.
finishSeal :: OzExt -> OzSealedTicket -> ByteString -> OzSealedTicket
finishSeal ext ticket ticketId = ticket { ozTicketId = decodeUtf8 ticketId
                                        , ozTicketExt = ozExtPublic ext
                                        }

-- | Decodes a Hawk "app" string into an Oz Ticket.
parseTicket :: TicketOpts -> Key -> ByteString -> IO (Either String OzSealedTicket)
parseTicket TicketOpts{..} (Key p) = Iron.unsealWith ticketOptsIron (Iron.Password p)
