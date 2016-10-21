-- | <<images/oz.png>>
--
-- Oz is a web authorization protocol based on industry best
-- practices. Oz combines the "Network.Hawk" authentication protocol
-- with the "Network.Iron" encryption protocol to provide a simple to
-- use and secure solution for granting and authenticating third-party
-- access to an API on behalf of a user or an application.
--
-- For making Oz-authenticated requests, import the
-- "Network.Oz.Client" module, which provides wrappers around
-- "Network.Wreq".
--
-- When implementing an Oz-authenticated application, import
-- "Network.Oz.Application" and use 'Network.Oz.Application.ozApp' to
-- provide a WAI 'Network.Wai.Application' and plug it into your
-- application. The endpoints will handle issuing tickets.
--
-- 'Network.Oz.Server.authenticate' checks tickets provided with
-- 'Network.Wai.Request's.
--
-- == How it works
--
-- 1. The application uses its previously issued Hawk credentials to
--    authenticate with the server and request an application
--    ticket. If valid, the server issues an application ticket. (see
--    'Network.Oz.Application.app' endpoint)
-- 2. The application directs the user to grant it authorization by
--    providing the user with its application identifier. The user
--    authenticates with the server, reviews the authorization grant
--    and its scope, and if approved the server returns an rsvp. (see
--    'Network.Oz.Ticket.rsvp' function)
-- 3. The user returns to the application with the rsvp which the
--    application uses to request a new user-specific ticket. If
--    valid, the server returns a new ticket. (see
--    'Network.Oz.Application.rsvp' endpoint)
-- 4. The application uses the user-ticket to access the user's
--    protected resources. (see 'Network.Oz.Server.authenticate'
--    function)
--

module Network.Oz
  ( module Network.Oz.Types
  ) where

import           Network.Oz.Types
