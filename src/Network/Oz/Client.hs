{-# LANGUAGE RecordWildCards #-}

-- | Functions for making Oz-authenticated requests.
--
-- This module is under construction.

module Network.Oz.Client
  ( header
  , withSession
  , reissue
  , Endpoints(..)
  , defaultEndpoints
  ) where

import           Data.ByteString           (ByteString)
import           Data.Text                 (Text)
import           Data.Time.Clock.POSIX     (POSIXTime, getPOSIXTime)

-- import Network.HTTP.Types.URI (URI)
import           Network.HTTP.Client       (Request, defaultManagerSettings,
                                            managerModifyRequest,
                                            managerRetryableException)
import           Network.HTTP.Types.Header (Header, hWWWAuthenticate)
import           Network.HTTP.Types.Method (Method)

import           Control.Exception         (SomeException)
import           Data.IORef                (newIORef, readIORef, writeIORef)

-- import Network.Wai (Request, requestHeaderHost, requestHeaders, remoteHost, requestMethod, rawPathInfo, rawQueryString)

import           Network.Wreq.Session      (Session)
import qualified Network.Wreq.Session      as S

import qualified Network.Hawk.Client       as Hawk
import           Network.Oz.Types

-- |A convenience utility to generate the application Hawk request
-- authorization header for making authenticated Oz requests.
header :: Text -> Method -> OzSealedTicket -> IO Hawk.Header
-- fixme: support hawk header options
header uri method t@OzSealedTicket{..} = Hawk.header uri method creds Nothing Nothing
  where
    creds = ticketCreds t
    -- fixme: app and dlg need to get passed to header

ticketCreds :: OzSealedTicket -> Hawk.Credentials
ticketCreds OzSealedTicket{..} = Hawk.Credentials ozTicketId ozTicketKey ozTicketAlgorithm

-- | Work in progress.
withSession :: Endpoints -> Text -> Hawk.Credentials -> (Session -> IO a) -> IO a
withSession ep uri creds act = do
  ref <- newIORef (Nothing :: Maybe OzTicket)
  S.withSessionControl Nothing settings act
  where
    settings = defaultManagerSettings
               { managerModifyRequest = addAuth
               , managerRetryableException = shouldRetry }
    addAuth :: Request -> IO Request
    -- fixme: check ticket ref
    addAuth = return
    shouldRetry :: SomeException -> Bool
    -- fixme: catch unauthorized and retry with auth
    shouldRetry = managerRetryableException defaultManagerSettings

-- | Re-issues (refreshes) a ticket.
reissue :: Endpoints -> Hawk.Credentials -> OzTicket -> IO (Either String OzTicket)
reissue ep creds OzTicket{..} = undefined -- fixme: implement

-- | Re-issues a ticket if it has expired.
-- fixme: maybe need slightly earlier reissue
reissueMaybe :: Endpoints -> Hawk.Credentials -> OzTicket -> IO (Either String OzTicket)
reissueMaybe ep creds t = do
  now <- getPOSIXTime
  if now >= ozTicketExp t
    then reissue ep creds t
    else return (Right t)

{- connection.request(path, ticket, options, callback)

Requests a protected resource where:

path - the resource path (e.g. '/resource').
ticket - the application or user ticket. If the ticket is expired, it will automatically attempt to refresh it.
options - optional configuration object where:
method - the HTTP method (e.g. 'GET'). Defaults to 'GET'.
payload - the request payload object or string. Defaults to no payload.
callback - the callback method using the signature function(err, result, code, ticket) where:
err - an error condition.
result - the requested resource (parsed to object if JSON).
code - the HTTP response code.
ticket - the ticket used to make the request (may be different from the ticket provided when the ticket was expired and refreshed).

-> sessionRequest
  probably not needed because withSession should handle ticket


connection.app(path, options, callback)

Requests a protected resource using a shared application ticket where:

path - the resource path (e.g. '/resource').
options - optional configuration object where:
method - the HTTP method (e.g. 'GET'). Defaults to 'GET'.
payload - the request payload object or string. Defaults to no payload.
callback - the callback method using the signature function(err, result, code, ticket) where:
err - an error condition.
result - the requested resource (parsed to object if JSON).
code - the HTTP response code.
ticket - the ticket used to make the request (may be different from the ticket provided when the ticket was expired and refreshed).
Once an application ticket is obtained internally using the provided hawk credentials in the constructor, it will be reused by called to connection.app(). If it expires, it will automatically refresh and stored for future usage.

-> sessionRequestApp
   not sure if needed

-}
