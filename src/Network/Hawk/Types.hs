{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Network.Hawk.Types
       ( ClientId
       , ExtData
       , Key(..)
       , ContentType
       , PayloadInfo(..)
       , module Network.Hawk.Algo
       ) where

import           Control.Applicative
import           Data.ByteString           (ByteString)
import qualified Data.ByteString.Lazy      as BL
import           Data.Text                 (Text)

import           Network.Hawk.Algo

-- | Identifies a particular client so that their credentials can be
-- looked up.
type ClientId = Text

-- | Extension data included in verification hash. This can be
-- anything or nothing, depending on what the application needs.
type ExtData = ByteString

----------------------------------------------------------------------------

-- | Value of @Content-Type@ HTTP headers.
type ContentType = ByteString -- fixme: CI ByteString

-- | Payload data and content type bundled up for convenience.
data PayloadInfo = PayloadInfo
                   { payloadContentType :: ContentType
                   , payloadData        :: BL.ByteString
                   } deriving Show
