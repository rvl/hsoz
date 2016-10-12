{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Network.Hawk.Types
       ( ClientId
       , Key(..)
       , ServerCredentials(..)
       , ServerAuthArtifacts(..)
       , ContentType
       , PayloadInfo(..)
       , module Network.Hawk.Algo
       ) where

import Data.Text (Text)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import GHC.Generics
import Network.HTTP.Types.Method (Method)
import Data.Time.Clock.POSIX (POSIXTime)
import Control.Applicative

import Network.Hawk.Algo

-- | Identifies a particular client so that their credentials can be
-- looked up.
type ClientId = Text

----------------------------------------------------------------------------

data ServerCredentials = ServerCredentials
  { scKey       :: Key
  , scAlgorithm :: HawkAlgo
  , scUser      :: Text
  , scApp       :: Maybe Text  -- fixme: maybe not Maybe
  , scDlg       :: Maybe ByteString
  } deriving (Show, Generic)

data ServerAuthArtifacts = ServerAuthArtifacts
  { shaMethod    :: Method
  , shaHost      :: ByteString
  , shaPort      :: Maybe Int
  , shaResource  :: ByteString
  --, shaHeader  :: ServerAuthorizationHeader
  , shaId        :: ClientId
  , shaTimestamp :: POSIXTime
  , shaNonce     :: ByteString
  , shaMac       :: ByteString
  , shaHash      :: Maybe ByteString
  , shaExt       :: Maybe ByteString
  , shaApp       :: Maybe Text
  , shaDlg       :: Maybe ByteString
  } deriving Show

----------------------------------------------------------------------------

-- | Value of @Content-Type@ HTTP header.
type ContentType = ByteString -- fixme: CI ByteString

-- | Payload data and content type bundled up for convenience.
data PayloadInfo = PayloadInfo
                   { payloadContentType :: ContentType
                   , payloadData :: BL.ByteString
                   } deriving Show
