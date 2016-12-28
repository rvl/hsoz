-- | Functions for making Hawk-authenticated request headers and
-- verifying responses from the server.
--
-- The easiest way to make authenticated requests is to use 'withHawk'
-- with functions from the "Network.HTTP.Simple" module (from the
-- @http-conduit@ package).

module Network.Hawk.Client
       ( -- * Higher-level API
         withHawk
       -- ** Types
       , ServerAuthorizationCheck(..)
       , HawkException(..)
       , Credentials(..)
       -- * Protocol functions
       , sign
       , authenticate
       , header
       , headerOz
       , getBewit
       , message
       -- ** Types
       , Header(..)
       , Authorization
       , module Network.Hawk.Types
       ) where

import Network.Hawk.Internal.Client
import Network.Hawk.Internal.Client.Types
import Network.Hawk.Types
import Network.Hawk.Internal
