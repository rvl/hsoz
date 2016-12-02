{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Network.Hawk.Types
       ( ClientId
       , ExtData
       , HeaderArtifacts(..)
       , Key(..)
       , ContentType
       , PayloadInfo(..)
       , module Network.Hawk.Algo
       ) where

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
  { haMethod    :: Method           -- ^ Signed request method
  , haHost      :: ByteString       -- ^ Request host
  , haPort      :: Maybe Int        -- ^ Request port
  , haResource  :: ByteString       -- ^ Request path and query params
  , haId        :: ClientId         -- ^ Client identifier
  , haTimestamp :: POSIXTime
  , haNonce     :: ByteString       -- ^ Nonce data
  , haMac       :: ByteString       -- ^ Entire header hash
  , haHash      :: Maybe ByteString -- ^ Payload hash
  , haExt       :: Maybe ExtData    -- ^ Optional application data
  , haApp       :: Maybe Text       -- ^ Oz application, Iron-encoded
  , haDlg       :: Maybe Text       -- ^ Oz delegated-by application
  } deriving (Show, Eq)

----------------------------------------------------------------------------

-- | Value of @Content-Type@ HTTP headers.
type ContentType = ByteString -- fixme: CI ByteString

-- | Payload data and content type bundled up for convenience.
data PayloadInfo = PayloadInfo
                   { payloadContentType :: ContentType
                   , payloadData        :: BL.ByteString
                   } deriving Show
