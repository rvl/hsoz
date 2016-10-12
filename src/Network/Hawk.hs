-- |
-- <<images/hawk-logo.png>>
--
-- __Hawk__ is a HTTP authentication scheme using a hash-based message
-- authentication code (HMAC) algorithm to provide partial HTTP
-- request cryptographic verification.
--
-- The message verification covers HTTP method, request URI, host, and
-- optionally the request payload of both requests and responses.
--
-- Similar to the HTTP [Digest access authentication
-- schemes](http://www.ietf.org/rfc/rfc2617.txt), /Hawk/ uses a set of
-- client credentials which include an identifier (e.g. username) and
-- key (e.g. password).
--
-- Likewise, just as with the Digest scheme, the key is never included
-- in authenticated requests. Instead, it is used to calculate a
-- request MAC value which is included in its place.
--
-- Unlike Digest, this scheme is not intended to protect the key
-- itself (the password in Digest) because the client and server must
-- both have access to the key material in the clear.
--
-- The /Hawk/ scheme requires the establishment of a shared symmetric
-- key between the client and the server, which is beyond the scope of
-- this module. Typically, the shared credentials are established via
-- an initial TLS-protected phase or derived from some other shared
-- confidential information available to both the client and the
-- server.
--
-- More information about /Hawk's/ design can be found at its web
-- site: https://github.com/hueniverse/hawk
--
-- == Usage
--
-- To use /Hawk/, depending on your application, use a qualified
-- import of either "Network.Hawk.Server" or "Network.Hawk.Client".
--
-- These modules respectively contain functions to generate
-- @Server-Authorization@/@Authorization@ headers, as well as
-- functions to authenticate requests/responses from the
-- client/server.
--
-- Additionally, there is a small example server and client in the
-- <https://github.com/rvl/hsoz project git repository>.

module Network.Hawk
       ( module Network.Hawk.Types
       ) where

import Network.Hawk.Client
import Network.Hawk.Server
import Network.Hawk.Types
