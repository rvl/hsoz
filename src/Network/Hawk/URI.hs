-- | == Single URI Authorization
--
-- There are cases in which limited and short-term access to a
-- protected resource is granted to a third party which does not have
-- access to the shared credentials. For example, displaying a
-- protected image on a web page accessed by anyone. __Hawk__ provides
-- limited support for such URIs in the form of a /bewit/ — a URI
-- query parameter appended to the request URI which contains the
-- necessary credentials to authenticate the request.
--
-- Because of the significant security risks involved in issuing such
-- access, bewit usage is purposely limited only to GET requests and
-- for a finite period of time. Both the client and server can issue
-- bewit credentials, however, the server should not use the same
-- credentials as the client to maintain clear traceability as to who
-- issued which credentials.
--
-- In order to simplify implementation, bewit credentials do not
-- support single-use policy and can be replayed multiple times within
-- the granted access timeframe.
--
-- This module collects the URI authorization functions in a single
-- module, to mirror the @Hawk.uri@ module of the javascript
-- implementation.

module Network.Hawk.URI
  ( authenticate
  , middleware
  , getBewit
  ) where

import           Control.Monad.IO.Class    (MonadIO)
import           Network.Wai               (Request)

import Network.Hawk.Types
import Network.Hawk.Server (authenticateBewitRequest, authenticateBewit, CredentialsFunc, AuthReqOpts, AuthOpts, AuthResult, HawkReq)
import Network.Hawk.Middleware (bewitAuth)
import Network.Hawk.Client (getBewit)

-- | See 'Network.Hawk.Server.authenticateBewitRequest'.
authenticateRequest :: MonadIO m => AuthReqOpts -> CredentialsFunc m t
             -> Request -> m (AuthResult t)
authenticateRequest = authenticateBewitRequest

-- | See 'Network.Hawk.Server.authenticateBewit'.
authenticate :: MonadIO m => AuthOpts -> CredentialsFunc m t
             -> HawkReq -> m (AuthResult t)
authenticate = authenticateBewit

-- | See 'Network.Hawk.Middleware.bewitAuth'.
middleware = bewitAuth
