{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Functions for implementing an Oz server.

module Network.Oz.Server
  ( authenticateRequest
  --, authenticate
  ) where

import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Data.ByteString (ByteString)
import Control.Monad.IO.Class (MonadIO(..))
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.Wai
import Data.Maybe (fromMaybe)

import Network.Oz.Types
import qualified Network.Hawk.Server as Hawk
import Network.Hawk.Server (AuthResult, AuthSuccess(..), AuthFail(..), scApp, shaApp, scDlg, shaDlg)
import Network.Hawk.Types
import Network.Oz.Ticket

-- | Authenticates a 'Network.Wai.Request' using Hawk
-- 'Network.Hawk.Server.authenticateRequest'. The Oz ticket is
-- decrypted and decoded from the Hawk attributes.
authenticateRequest :: forall m. MonadIO m => Key -> TicketOpts -> Hawk.AuthReqOpts -> Request -> m AuthResult
-- goes to Network.Hawk.Server.authenticateRequest
authenticateRequest p opts hawkOpts req = check <$> Hawk.authenticateRequest hawkOpts creds req Nothing
  where
    check :: AuthResult -> AuthResult
    check r@(Right (AuthSuccess c@ServerCredentials{..} a@ServerAuthArtifacts{..}))
      | scApp /= shaApp =
          Left $ AuthFailUnauthorized "Mismatching application id" (Just c) (Just a)
      | scDlg /= shaDlg && scDlg /= Nothing =
          Left $ AuthFailUnauthorized "Mismatching delegated application id" (Just c) (Just a)
      | otherwise = Left $ AuthFailBadRequest "hello there" Nothing

    creds :: OzAppId -> m (Either String Hawk.ServerCredentials)
    creds cid = do
      t <- liftIO $ ticket (encodeUtf8 cid)
      return (fmap ticketCreds t)

    ticket :: ByteString -> IO (Either String OzSealedTicket)
    ticket t = do
      res <- parseTicket opts p t
      case res of
        Right sealed -> do
          now <- getPOSIXTime
          return $ if ozTicketExp (ozTicket sealed) <= now
            then Left "Expired ticket"
            else Right sealed
        Left e -> return $ Left e

ticketCreds :: OzSealedTicket -> Hawk.ServerCredentials
ticketCreds OzSealedTicket{..} = Hawk.ServerCredentials
  { scKey = ozTicketKey
  , scAlgorithm = ozTicketAlgorithm
  , scUser = fromMaybe "" (ozTicketUser ozTicket)
  , scApp = Just (ozTicketApp ozTicket)
  , scDlg = fmap encodeUtf8 (ozTicketDlg ozTicket)
  }

authenticate :: MonadIO m => Text -> Key -> TicketOpts -> Hawk.AuthReqOpts
             -> m (Either String (ServerCredentials, ServerAuthArtifacts))
authenticate = fail "unimplemented"
