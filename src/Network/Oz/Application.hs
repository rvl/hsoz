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

import           Control.Monad             (liftM, void)
import           Control.Monad.IO.Class    (MonadIO (..), liftIO)
import           Data.Aeson.Types          (ToJSON)
import           Data.ByteString           (ByteString)
import           Data.Maybe                (fromMaybe)
import           Data.Monoid               ((<>))
import           Data.Proxy
import           Data.Text                 (Text)
import qualified Data.Text                 as T
import           Data.Text.Encoding        (decodeUtf8)
import qualified Data.Text.Lazy            as TL
import           Network.HTTP.Types        (status400, status401)
import           Network.Wai
import           Web.Scotty

import           Network.Hawk.Server       (AuthSuccess (..))
import qualified Network.Hawk.Server       as Hawk
import           Network.Hawk.Types
import qualified Network.Oz.Boom           as Boom
import           Network.Oz.Internal.Types
import           Network.Oz.JSON
import           Network.Oz.Server
import           Network.Oz.Ticket
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
defaultOzServerOpts :: OzServerOpts
defaultOzServerOpts = OzServerOpts "secret" defaultLoadApp defaultLoadGrant
  defaultTicketOpts Hawk.defaultAuthReqOpts defaultEndpoints

defaultLoadApp :: OzLoadApp
defaultLoadApp _ = return $ Left "ozLoadApp not set"

defaultLoadGrant :: OzLoadGrant
defaultLoadGrant _ = return $ Left "ozLoadGrant not set"

-- | Starts the 'Network.Wai.Application'.
ozApp :: OzServerOpts -> IO Application
ozApp OzServerOpts{..} = scottyApp $ do
  -- middleware $ hawkAuthMiddleware opts
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
      res <- liftIO $ issueTicket appCfg creds Nothing ozSecret ozTicketOpts
      return $ maybe (Left "Could not issue ticket") Right res

    reissue :: ReissueRequest -> ActionM OzTicket
    reissue (ReissueRequest mid mscope) = do
      (creds, arts) <- hawkAuthAction
      appCfg <- loadAppAction (shaApp arts)
      return undefined

    -- Authenticates an application request and if valid, exchanges
    -- the provided rsvp with a ticket.
    rsvp :: RsvpRequest -> ActionM OzTicket
    rsvp (RsvpRequest r) = undefined

    -- Scotty action to check the Authorization header
    hawkAuthAction :: ActionM (ServerCredentials, ServerAuthArtifacts)
    hawkAuthAction = do
      req <- request
      -- payload <- fmap Just body  -- fixme: check if it's compatible with jsonData
      let payload = Nothing
      let creds = liftIO . liftM (fmap appCreds) . ozLoadApp
      res <- Hawk.authenticateRequest ozHawk creds req payload
      case res of
        Right (AuthSuccess c a) -> return (c, a)
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

appCreds :: OzApp -> Hawk.ServerCredentials
appCreds OzApp{..} = Hawk.ServerCredentials
  { scKey = ozAppKey
  , scAlgorithm = ozAppAlgorithm
  , scUser = ""  -- fixme: ???
  , scApp = Just ozAppId
  , scDlg = Nothing  -- fixme: ???
  }

{-

hawkAuthMiddleware :: OzServerOpts -> Middleware
hawkAuthMiddleware opts app req respond = do
  res <- authenticateRequest opts' creds req Nothing
  case res of
    Right (AuthSuccess creds arts) -> app req respond
    Left _ -> respond err
  where
    opts' = undefined
    err = reponseLBS status401 [] "Hawk auth failed"
-}

{-
endpoints.app(req, payload, options, callback)

Authenticates an application request and if valid, issues an application ticket where:

req - the node HTTP server request object.
payload - this argument is ignored and is defined only to keep the endpoint method signature consistent with the other endpoints.
options - protocol configuration options where:
encryptionPassword - required.
loadAppFunc - required.
ticket - optional ticket options used for parsing and issuance.
hawk - optional Hawk configuration object. Defaults to the Hawk defaults.
callback - the method used to return the request result with signature function(err, ticket) where:
err - an error condition.
ticket - a ticket response object.
-}



{-
endpoints.reissue(req, payload, options, callback)

Reissue an existing ticket (the ticket used to authenticate the request) where:

req - the node HTTP server request object.
payload - The HTTP request payload fully parsed into an object with the following optional keys:
issueTo - a different application identifier than the one of the current application. Used to delegate access between applications. Defaults to the current application.
scope - an array of scope strings which must be a subset of the ticket's granted scope. Defaults to the original ticket scope.
options - protocol configuration options where:
encryptionPassword - required.
loadAppFunc - required.
loadGrantFunc - required.
ticket - optional ticket options used for parsing and issuance.
hawk - optional Hawk configuration object. Defaults to the Hawk defaults.
callback - the method used to return the request result with signature function(err, ticket) where:
err - an error condition.
ticket - a ticket response object.
-}

{-
endpoints.rsvp(req, payload, options, callback)

Authenticates an application request and if valid, exchanges the provided rsvp with a ticket where:

req - the node HTTP server request object.
payload - The HTTP request payload fully parsed into an object with the following keys:
rsvp - the required rsvp string provided to the user to bring back to the application after granting authorization.
options - protocol configuration options where:
encryptionPassword - required.
loadAppFunc - required.
loadGrantFunc - required.
ticket - optional ticket options used for parsing and issuance.
hawk - optional Hawk configuration object. Defaults to the Hawk defaults.
callback - the method used to return the request result with signature function(err, ticket) where:
err - an error condition.
ticket - a ticket response object.

-}
