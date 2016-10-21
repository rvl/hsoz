{-# LANGUAGE RecordWildCards #-}

-- | Provides a "Network.Wai" 'Network.Wai.Application' for managing
-- Oz tickets.
--
-- The Oz ticket endpoints can be run with Warp or embedded within
-- another application.

module Network.Oz.Application
  ( ozApp
  , OzServerOpts(..)
  , OzLoadApp
  , OzLoadGrant
  , defaultOzServerOpts
  ) where

import           Control.Monad             (liftM, void, when)
import           Control.Monad.IO.Class    (MonadIO (..), liftIO)
import           Control.Applicative       ((<|>))
import           Data.Aeson.Types          (ToJSON)
import           Data.ByteString           (ByteString)
import           Data.Maybe                (fromMaybe, isJust)
import           Data.Monoid               ((<>))
import           Data.Proxy
import           Data.Text                 (Text)
import qualified Data.Text                 as T
import           Data.Text.Encoding        (decodeUtf8, encodeUtf8)
import qualified Data.Text.Lazy            as TL
import           Network.HTTP.Types        (status400, status401)
import           Network.Wai
import           Web.Scotty
import           Data.Time.Clock.POSIX     (getPOSIXTime)

import           Network.Hawk.Server       (AuthSuccess (..), Key (..), HeaderArtifacts (..))
import qualified Network.Hawk.Server       as Hawk
import qualified Network.Oz.Boom           as Boom
import           Network.Oz.Internal.Types
import           Network.Oz.JSON
import           Network.Oz.Server
import qualified Network.Oz.Ticket         as Ticket
import           Network.Oz.Types

data OzServerOpts = OzServerOpts
  { ozSecret     :: Key -- ^ The password for encrypting Oz tickets
  , ozLoadApp    :: OzLoadApp -- ^ Callback to look up registered apps
  , ozLoadGrant  :: OzLoadGrant -- ^ Callback to look up grants
  , ozTicketOpts :: TicketOpts -- ^ Ticket generation options
  , ozHawk       :: Hawk.AuthReqOpts -- ^ Configuration of Hawk for this server
  , ozEndpoints  :: Endpoints -- ^ URL route configuration of API endpoints
  }

-- | An empty Oz endpoint configuration. The password should be set to
-- something secret.
defaultOzServerOpts :: Key -> OzServerOpts
defaultOzServerOpts p = OzServerOpts p defaultLoadApp defaultLoadGrant
  defaultTicketOpts Hawk.defaultAuthReqOpts defaultEndpoints

defaultLoadApp :: OzLoadApp
defaultLoadApp _ = return $ Left "ozLoadApp not set"

defaultLoadGrant :: OzLoadGrant
defaultLoadGrant _ = return $ Left "ozLoadGrant not set"

-- | Starts the 'Network.Wai.Application'.
ozApp :: OzServerOpts -> IO Application
ozApp OzServerOpts{..} = scottyApp $ do
  defaultHandler Boom.errHandler
  let post' r = post . literal . T.unpack . r $ ozEndpoints
  post' endpointApp     $ app >>= ejson
  post' endpointReissue $ jsonData >>= reissue >>= json
  post' endpointRsvp    $ jsonData >>= rsvp >>= json
  where
    app :: ActionM (Either String OzSealedTicket)
    app = do
      (creds, arts) <- hawkAuthAction
      appCfg <- loadAppAction (shaApp arts)
      Ticket.issue ozSecret appCfg Nothing ozTicketOpts

    -- fixme: flatten staircases
    reissue :: ReissueRequest -> ActionM OzSealedTicket
    reissue (ReissueRequest mid mscope) = do
      res <- request >>= authenticateExpired ozSecret ozTicketOpts ozHawk
      case res of
        Right (AuthSuccess c a t) -> do
          let appId = ozTicketApp (ozTicket t)
          appCfg <- liftIO $ ozLoadApp appId
          case appCfg of
            Right app -> do
              when (isJust mid && not (ozAppDelegate app)) $
                Boom.forbidden "Application has no delegation rights"
              case ozTicketGrant (ozTicket t) of
                Nothing -> reissueAction c app Nothing Nothing mid mscope t
                Just gid -> do
                  mgrant <- liftIO $ ozLoadGrant gid
                  case mgrant of
                    Right (grant, mext) -> do
                      now <- liftIO $ getPOSIXTime
                      when (((ozGrantApp grant /= ozTicketApp (ozTicket t)) &&
                             (Just (ozGrantApp grant) /= ozTicketDlg (ozTicket t))) ||
                             (ozGrantExp grant <= now)) $ Boom.unauthorized "Invalid grant"
                      reissueAction c app (Just grant) mext mid mscope t
                    Left e -> Boom.forbidden e
            Left e -> Boom.unauthorized (e <|> "Invalid application")
        Left e -> hawkAuthFail e

    reissueAction :: Hawk.Credentials -> OzApp -> Maybe OzGrant -> Maybe OzExt
                   -> Maybe OzAppId -> Maybe OzScope -> OzSealedTicket -> ActionM OzSealedTicket
    reissueAction creds a mgrant mext mid mscope t = do
      res <- Ticket.reissue ozSecret a mgrant (opts mext) mscope mid t
      either Boom.forbidden return res
      where
        opts (Just ext) = ozTicketOpts { ticketOptsExt = ext }
        opts Nothing = ozTicketOpts

    -- Authenticates an application request and if valid, exchanges
    -- the provided rsvp with a ticket.
    rsvp :: RsvpRequest -> ActionM OzSealedTicket
    rsvp (RsvpRequest r) = do
      res <- request >>= authenticate ozSecret ozTicketOpts ozHawk
      case res of
        Right (AuthSuccess c a t) -> do
          when (ozTicketUser (ozTicket t) == Nothing) $
            Boom.unauthorized "User ticket cannot be used on an application endpoint"
          mt <- liftIO $ Ticket.parse ozTicketOpts ozSecret (encodeUtf8 r)
          case mt of
            Right envelope -> do
              when (ozTicketApp (ozTicket envelope) /= (ozTicketApp (ozTicket t))) $
                Boom.forbidden "Mismatiching ticket and rsvp apps"
              now <- liftIO $ getPOSIXTime
              when (ozTicketExp (ozTicket envelope) <= now) $
                Boom.forbidden "Expired rsvp"
              case ozTicketGrant (ozTicket envelope) of
                Just gid -> do
                  mgrant <- liftIO $ ozLoadGrant gid
                  case mgrant of
                    Right (grant, mext) -> do
                      when ((ozGrantApp grant /= ozTicketApp (ozTicket envelope)) ||
                            (ozGrantExp grant <= now)) $ Boom.forbidden "Invalid grant"
                      appCfg <- liftIO $ ozLoadApp (ozTicketApp (ozTicket envelope))
                      case appCfg of
                        Right app -> do
                          let opts' = case mext of
                                        Just ext -> ozTicketOpts { ticketOptsExt = ext }
                                        Nothing -> ozTicketOpts
                          res <- Ticket.issue ozSecret app (Just grant) opts'
                          either Boom.forbidden return res
                        Left e -> Boom.forbidden (e <|> "Invalid application")
                    Left e -> Boom.forbidden e -- probably forbidden
                Nothing -> Boom.forbidden "Missing grant id"
            Left e -> Boom.forbidden e
        Left f -> hawkAuthFail f

    -- Scotty action to check the Authorization header
    hawkAuthAction :: ActionM (Hawk.Credentials, Hawk.HeaderArtifacts)
    hawkAuthAction = do
      req <- request
      -- payload <- fmap Just body  -- fixme: check if it's compatible with jsonData
      let payload = Nothing
      let creds = liftIO . liftM (fmap appCreds) . ozLoadApp
      res <- Hawk.authenticateRequest ozHawk creds req payload
      case res of
        Right (AuthSuccess c a _) -> return (c, a)
        Left f                  -> hawkAuthFail f

    -- respond to failed hawk authentication
    hawkAuthFail :: Hawk.AuthFail -> ActionM a
    hawkAuthFail (Hawk.AuthFailBadRequest e _)       = Boom.badRequest e
    hawkAuthFail (Hawk.AuthFailUnauthorized e _ _)   = Boom.unauthorized e
    -- fixme: need to send back server's time so client can apply offset
    hawkAuthFail (Hawk.AuthFailStaleTimeStamp e c a) = Boom.unauthorized e

    loadAppAction appId = do
      appCfg <- liftIO $ loadApp appId
      case appCfg of
        Right app -> return app
        Left e    -> Boom.unauthorized e

    loadApp Nothing      = return $ Left "Invalid application object"
    loadApp (Just appId) = ozLoadApp appId

    ejson :: (Show a, ToJSON a) => Either String a -> ActionM ()
    ejson (Right a) = do
      liftIO $ print a
      json a
    ejson (Left e) = Boom.internal e

appCreds :: OzApp -> (Hawk.Credentials, ())
appCreds OzApp{..} = (Hawk.Credentials ozAppKey ozAppAlgorithm, ())
