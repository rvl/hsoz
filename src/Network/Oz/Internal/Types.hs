module Network.Oz.Internal.Types
  ( ReissueRequest(..)
  , RsvpRequest(..)
  ) where

import           Data.Text        (Text)

-- fixme: needs to be the other way around
import           Network.Oz.Types (OzAppId, OzScope)

-- | Payload for oz app reissue endpoint.
-- 'OzAppId' A different application identifier than the one
-- of the current application. Used to delegate
-- access between applications. Defaults to the
-- current application.
-- 'OzScope' An array of scope strings which must be a
-- subset of the ticket's granted scope. Defaults to
-- the original ticket scope.
data ReissueRequest = ReissueRequest (Maybe OzAppId) (Maybe OzScope)

-- | Payload for oz app rsvp endpoint.
-- Single field is the required rsvp string provided to the user to
-- bring back to the application after granting authorization
data RsvpRequest = RsvpRequest Text
