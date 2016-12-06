{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Functions for implementing an Oz server.

module Network.Oz.Server
  ( authenticate
  , authenticateExpired
  , authenticate'
  , CheckExpiration(..)
  ) where

import           Control.Monad          (when)
import           Control.Monad.IO.Class (MonadIO (..))
import           Data.ByteString        (ByteString)
import           Data.Maybe             (fromMaybe)
import           Data.Text              (Text)
import           Data.Text.Encoding     (encodeUtf8, decodeUtf8)
import           Data.Time.Clock.POSIX  (getPOSIXTime)
import           Network.Wai

import           Network.Hawk.Server    (AuthFail (..), AuthResult, AuthResult' (..),
                                         AuthSuccess (..),
                                         Credentials(..))
import qualified Network.Hawk.Server    as Hawk
import           Network.Hawk.Types
import qualified Network.Oz.Ticket      as Ticket
import           Network.Oz.Types

data CheckExpiration = CheckExpiration | AllowExpired deriving Show

-- | Authenticates a 'Network.Wai.Request' using Hawk
-- 'Network.Hawk.Server.authenticateRequest'. The Oz ticket is
-- decrypted and decoded from the Hawk attributes.
authenticate :: forall m. MonadIO m => Key -> TicketOpts -> Hawk.AuthReqOpts -> Request
             -> m (AuthResult OzSealedTicket)
authenticate = authenticate' CheckExpiration

-- | Same as 'authenticate' but expired Oz tickets are permitted.
authenticateExpired :: forall m. MonadIO m => Key -> TicketOpts -> Hawk.AuthReqOpts -> Request
                    -> m (AuthResult OzSealedTicket)
authenticateExpired = authenticate' AllowExpired

-- | 'authenticate' and 'authenticateExpired' are written in terms of
-- this function.
authenticate' :: forall m. MonadIO m => CheckExpiration -> Key -> TicketOpts -> Hawk.AuthReqOpts -> Request
                 -> m (AuthResult OzSealedTicket)
authenticate' ce p opts hawkOpts req =
  check <$> Hawk.authenticateRequest hawkOpts creds req Nothing
  where
    check :: AuthResult OzSealedTicket -> AuthResult OzSealedTicket
    check r = r >>= check'
      where
        check' r@(AuthSuccess c a@HeaderArtifacts{..} t@OzSealedTicket{..})
          | ozTicketApp ozTicket /= fromMaybe "" haApp =
            Left $ AuthFailUnauthorized "Mismatching application id" (Just c) (Just a)
          | ozTicketDlg ozTicket /= haDlg && ozTicketDlg ozTicket /= Nothing =
            Left $ AuthFailUnauthorized "Mismatching delegated application id" (Just c) (Just a)
          | otherwise = Right r

    creds :: OzAppId -> m (Either String (Hawk.Credentials, OzSealedTicket))
    creds cid = liftIO $ fmap ticketCreds <$> ticket (encodeUtf8 cid)

    ticket :: ByteString -> IO (Either String OzSealedTicket)
    -- fixme: maybe use case instead of either
    ticket t = Ticket.parse opts p t >>= either (return . Left) checkExpiry

    checkExpiry sealed = case ce of
      CheckExpiration -> do
        now <- getPOSIXTime
        return $ if ozTicketExp (ozTicket sealed) <= now
          then Left "Expired ticket"
          else Right sealed
      AllowExpired -> return $ Right sealed

ticketCreds :: OzSealedTicket -> (Hawk.Credentials, OzSealedTicket)
ticketCreds t@OzSealedTicket{..} = (c, t)
  where c = Hawk.Credentials ozTicketKey ozTicketAlgorithm
