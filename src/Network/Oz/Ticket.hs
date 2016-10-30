{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections       #-}

-- | This module is best imported qualified.
-- Unless you are writing your own Oz endpoints, all you
-- will need for a normal application server is 'rsvp'.

module Network.Oz.Ticket
  ( rsvp
  , issue
  , reissue
  , parse
  ) where

import           Control.Monad          (liftM, void, when)
import           Control.Monad.IO.Class (MonadIO (..), liftIO)
import           Control.Applicative    ((<|>))
import           Data.Monoid            ((<>))
import           Crypto.Random
import           Data.Aeson             (Object (..), Value (..), object,
                                         toJSON)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base64 as B64
import           Data.List              (isInfixOf, nub)
import           Data.Maybe             (catMaybes, fromMaybe, isJust)
import           Data.Text              (Text)
import qualified Data.Text              as T
import           Data.Text.Encoding     (decodeUtf8)
import           Data.Time.Clock.POSIX  (POSIXTime, getPOSIXTime)

import           Network.Hawk.Server.Types
import qualified Network.Iron           as Iron
import           Network.Oz.JSON
import           Network.Oz.Types

-- | When the user authorizes the application access request, the
-- server issues an /rsvp/ which is an encoded string containing the
-- application identifier, the grant identifier, and an expiration.
--
-- This function generates the /rsvp/ string.
rsvp :: MonadIO m => OzAppId -> Maybe OzGrantId -> Key -> TicketOpts -> m (Maybe ByteString)
rsvp app grant (Key p) TicketOpts{..} = liftIO $ do
  now <- getPOSIXTime
  Iron.sealWith ticketOptsIron (Iron.password p) (envelope now)
  where
    envelope now = OzTicket
                   { ozTicketExp = now + ticketOptsRsvpTtl
                   , ozTicketApp = app
                   , ozTicketGrant = grant
                   , ozTicketUser = Nothing
                   , ozTicketScope = []
                   , ozTicketDelegate = False
                   , ozTicketDlg = Nothing
                   }

-- | Issues a new application or user ticket.
issue :: MonadIO m => Key -> OzApp -> Maybe OzGrant -> TicketOpts -> m (Either String OzSealedTicket)
issue p app mgrant opts = case checkGrant app mgrant of
                            Right scope -> issueTicket p mgrant
                                           (fromMaybe [] scope)
                                           (ozAppId app)
                                           Nothing True opts
                            Left e -> return (Left e)
  where
    checkGrant _ Nothing = Right Nothing
    checkGrant OzApp{..} (Just OzGrant{..}) = checkGrantScope ozAppScope ozGrantScope -- fixme: what else to check?

-- | Generates a ticket without any checking
issueTicket :: MonadIO m => Key -> Maybe OzGrant -> OzScope -> OzAppId
            -> Maybe OzAppId -> Bool -> TicketOpts
            -> m (Either String OzSealedTicket)
issueTicket p mgrant scope app dlg delegate opts = do
  exp <- getExpiry opts mgrant
  let ticket = OzTicket { ozTicketExp = exp
                        , ozTicketApp = app
                        , ozTicketScope = scope
                        , ozTicketGrant = ozGrantId <$> mgrant
                        , ozTicketUser = ozGrantUser <$> mgrant
                        , ozTicketDlg = dlg
                        , ozTicketDelegate = ticketOptsDelegate opts && delegate
                        }
  res <- liftIO $ generateTicket opts p ticket
  return $ maybe (Left "Could not issue ticket") Right res


-- | Reissues an application or user ticket.
reissue :: MonadIO m => Key -> OzApp -> Maybe OzGrant
        -> TicketOpts -> Maybe OzScope -> Maybe OzAppId
        -> OzSealedTicket -> m (Either String OzSealedTicket)
reissue p app mgrant opts@TicketOpts{..} mscope issueTo t = case checks of
    Right () -> issueTicket p mgrant
      (fromMaybe ozTicketScope mscope)
      (fromMaybe ozTicketApp issueTo)
      (issueTo <|> ozTicketDlg)
      ozTicketDelegate
      opts'
    Left e -> return (Left e)
  where
    checks :: Either String ()
    checks = do
      void $ checkParentScope (Just ozTicketScope) mscope
      when (ticketOptsDelegate && not ozTicketDelegate)
        $ Left "Cannot override ticket delegate restriction"
      when (isJust issueTo) $ do
        when (isJust ozTicketDlg) $ Left "Cannot re-delegate" -- fixme: http bad request
        when (not ozTicketDelegate) $ Left "Ticket does not allow delegation"
      when (ozTicketGrant /= fmap ozGrantId mgrant) $
        Left "Parent ticket grant does not match options.grant"

    OzTicket{..} = ozTicket t

    opts' = if ticketOptsExt == mempty && not (null (ozTicketExt t))
      then opts { ticketOptsExt = OzExt (ozTicketExt t) mempty }
      else opts


getExpiry :: MonadIO m => TicketOpts -> Maybe OzGrant -> m POSIXTime
getExpiry opts mgrant = do
  now <- liftIO getPOSIXTime
  return $ calc (ticketOptsTicketTtl opts) mgrant now
  where
    calc ttl mgrant now = maybe id (min . ozGrantExp) mgrant (now + ttl)

-- | Probably not a worthy function
checkPassword :: Key -> Either String ()
checkPassword (Key p) | BS.null p = Left "Invalid encryption password"
                      | otherwise = Right ()

-- | Validate a grant scope in comparison to an app scope.
checkGrantScope :: Maybe OzScope -> Maybe OzScope -> Either String (Maybe OzScope)
checkGrantScope app grant = mapLeft (const msg) (checkScopes app grant)
  where msg = "Grant scope is not a subset of the application scope"

checkParentScope :: Maybe OzScope -> Maybe OzScope -> Either String (Maybe OzScope)
checkParentScope parent scope = mapLeft (const msg) (checkScopes parent scope)
  where msg = "New scope is not a subset of the parent ticket scope"

checkScopes :: Maybe OzScope -> Maybe OzScope -> Either String (Maybe OzScope)
checkScopes Nothing    Nothing       = Right Nothing
checkScopes Nothing    (Just _)      = Left ""
checkScopes (Just big) Nothing       = Just <$> checkScope big
checkScopes (Just big) (Just little) | isInfixOf little big = Just <$> checkScope little
                                     | otherwise = Left "not a subset"

-- | Validate scope array strings.
checkScope :: OzScope -> Either String OzScope
checkScope scope | any T.null scope = Left "scope includes empty string value"
                 | length (nub scope) /= length scope = Left "scope includes duplicated item"
                 | otherwise = Right scope

mapLeft :: (a -> c) -> Either a b -> Either c b
mapLeft f (Left a) = Left (f a)
mapLeft _ (Right b) = Right b

randomKey :: TicketOpts -> IO ByteString
randomKey TicketOpts{..} = do
  -- fixme: check that this is seeded properly
  drg <- getSystemDRG
  return (fst $ withRandomBytes drg ticketOptsKeyBytes base64)

base64 :: ByteString -> ByteString
base64 = Iron.urlSafeBase64 . B64.encode

-- | Adds the cryptographic properties to a ticket and prepares it for
-- sending.
generateTicket :: TicketOpts -> Key -> OzTicket -> IO (Maybe OzSealedTicket)
generateTicket opts@TicketOpts{..} (Key p) t = do
  key <- randomKey opts
  let Object ext = toJSON ticketOptsExt
  let sealed = OzSealedTicket t (Key key) ticketOptsHmacAlgorithm ext ""
  mid <- Iron.sealWith ticketOptsIron (Iron.password p) sealed
  return (finishSeal ticketOptsExt sealed <$> mid)

-- | Removes the private ext part and adds the ticket ID.
finishSeal :: OzExt -> OzSealedTicket -> ByteString -> OzSealedTicket
finishSeal ext ticket ticketId = ticket { ozTicketId = decodeUtf8 ticketId
                                        , ozTicketExt = ozExtPublic ext
                                        }

-- | Decodes a Hawk "app" string into an Oz Ticket.
parse :: TicketOpts -> Key -> ByteString -> IO (Either String OzSealedTicket)
parse TicketOpts{..} (Key p) = Iron.unsealWith ticketOptsIron lookup
  where lookup = Iron.onePassword p
