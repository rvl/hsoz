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
-- 'Network.Oz.Server.authenticateRequest' checks tickets.

module Network.Oz
  ( module Network.Oz.Types
  ) where

import Network.Oz.Types
