{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Network.Hawk.Internal.Types where

import           Control.Applicative
import           Data.ByteString           (ByteString)
import qualified Data.ByteString.Lazy      as BL
import           Data.Text                 (Text)
import           Data.Time.Clock.POSIX     (POSIXTime)
import           Network.HTTP.Types.Method (Method)

import           Network.Hawk.Algo

-- | Identifies a particular client so that their credentials can be
-- looked up.
type ClientId = Text

-- | Extension data included in verification hash. This can be
-- anything or nothing, depending on what the application needs.
type ExtData = ByteString

-- | Struct for attributes which will be encoded in the Hawk
-- @Authorization@ header and included in the verification. The
-- terminology (and spelling) come from the original Javascript
-- implementation of Hawk.
data HeaderArtifacts = HeaderArtifacts
  { haMethod    :: Method           -- ^ Signed request method.
  -- fixme: replace host/port/resource with SplitURL
  , haHost      :: ByteString       -- ^ Request host.
  , haPort      :: Maybe Int        -- ^ Request port.
  , haResource  :: ByteString       -- ^ Request path and query params.
  , haId        :: ClientId         -- ^ Client identifier.
  , haTimestamp :: POSIXTime        -- ^ Time of request.
  , haNonce     :: ByteString       -- ^ Nonce value.
  , haMac       :: ByteString       -- ^ Entire header hash.
  , haHash      :: Maybe ByteString -- ^ Payload hash.
  , haExt       :: Maybe ExtData    -- ^ Optional application-specific data.
  , haApp       :: Maybe Text       -- ^ Oz application, Iron-encoded.
  , haDlg       :: Maybe Text       -- ^ Oz delegated-by application.
  } deriving (Show, Eq)

----------------------------------------------------------------------------

-- | Value of @Content-Type@ HTTP headers.
type ContentType = ByteString -- fixme: CI ByteString

-- | Payload data and content type bundled up for convenience.
data PayloadInfo = PayloadInfo
                   { payloadContentType :: ContentType
                   , payloadData        :: BL.ByteString
                   } deriving Show

----------------------------------------------------------------------------

-- | Authorization attributes for a Hawk message. This is generated by
-- 'Network.Hawk.Client.message' and verified by
-- 'Network.Hawk.Server.authenticateMessage'.
data MessageAuth = MessageAuth
                   { msgId        :: ClientId   -- ^ User identifier.
                   , msgTimestamp :: POSIXTime  -- ^ Message time.
                   , msgNonce     :: ByteString -- ^ Nonce string.
                   , msgHash      :: ByteString -- ^ Message hash.
                   , msgMac :: ByteString -- ^ Hash of all message parameters.
                   } deriving (Show, Eq)

----------------------------------------------------------------------------

-- | Represents the @WWW-Authenticate@ header which the server uses to
-- respond when the client isn't authenticated.
data WwwAuthenticateHeader = WwwAuthenticateHeader
  { wahError :: ByteString       -- ^ Error message
  , wahTs    :: Maybe POSIXTime  -- ^ Server's timestamp
  , wahTsm   :: Maybe ByteString -- ^ Timestamp mac
  } deriving (Show, Eq)

-- | Represents the @Server-Authorization@ header which the server
-- sends back to the client.
data ServerAuthorizationHeader = ServerAuthorizationHeader
  { sahMac  :: ByteString       -- ^ Hash of all response parameters.
  , sahHash :: Maybe ByteString -- ^ Optional payload hash.
  , sahExt  :: Maybe ExtData    -- ^ Optional application-specific data.
  } deriving (Show, Eq)