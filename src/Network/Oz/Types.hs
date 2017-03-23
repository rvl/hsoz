{-# LANGUAGE DeriveGeneric #-}

module Network.Oz.Types
  ( OzTicket(..)
  , OzSealedTicket(..)
  , OzApp(..)
  , OzGrant(..)
  , OzExt(..)
  , TicketOpts(..)
  , defaultTicketOpts

  , OzAppId
  , OzUserId
  , OzGrantId
  , OzPermission
  , OzScope
  , OzTicketId

  , OzLoadApp
  , OzLoadGrant

  , Endpoints(..)
  , defaultEndpoints
  ) where

import           Crypto.Hash.Algorithms (SHA256 (..))
import           Data.Aeson             (Object)
import           Data.ByteString        (ByteString)
import           Data.Text              (Text)
import           Data.Time.Clock        (NominalDiffTime)
import           Data.Time.Clock.POSIX  (POSIXTime)
import           GHC.Generics
import           Data.Default           (Default(..))

import           Network.Hawk           (HawkAlgo)
import           Network.Hawk.Types
import qualified Network.Iron           as Iron

-- | Identifies an Oz Application
type OzAppId = Text
-- | Identifies a user
type OzUserId = Text
-- | Identifies an Oz grant
type OzGrantId = Text
-- | Tag representing permissions of application
type OzPermission = Text
-- | Set of permissions for application
type OzScope = [OzPermission]
-- | Oz ticket identifier, which is also a 'Network.Iron' encrypted
-- version of the ticket.
type OzTicketId = Text

-- | An object describing an application.
data OzApp = OzApp
  { ozAppId        :: OzAppId  -- ^ The application identifier

  -- | An array with the default application scope.
  , ozAppScope     :: Maybe OzScope
  -- | If true, the application is allowed to delegate a
  -- ticket to another application. Defaults to false.
  , ozAppDelegate  :: Bool
  -- | The shared secret used to authenticate.
  , ozAppKey       :: Key
  -- | The HMAC algorithm used to authenticate.
  , ozAppAlgorithm :: HawkAlgo
  } deriving (Show, Generic)

-- | A grant is the authorization given to an application by a user to
-- access the user's protected resources. Grants can be persisted in a
-- database (usually to support revocation) or can be self describing
-- (using an encoded identifier).
data OzGrant = OzGrant
  { ozGrantId    :: OzGrantId  -- ^ The grant identifier

  -- | The application identifier.
  , ozGrantApp   :: OzAppId
  -- | The user identifier.
  , ozGrantUser  :: OzUserId
  -- | Grant expiration time
  , ozGrantExp   :: POSIXTime
  -- | An array with the scope granted by the user to the application.
  , ozGrantScope :: Maybe OzScope
  } deriving (Show, Generic)

-- | An object used to include custom server data in the ticket and
-- response. The public part is included in the Oz reponse under
-- ticket.ext. The private part is only available within the encoded
-- ticket.
data OzExt = OzExt
             { ozExtPublic  :: Object -- ^ Public ext; included in response
             , ozExtPrivate :: Object -- ^ Private ext; only in encoded ticket.
             } deriving (Show, Eq, Generic)

instance Monoid OzExt where
  mempty = OzExt mempty mempty
  mappend (OzExt a b) (OzExt c d) = OzExt (mappend a c) (mappend b d)

-- | A sealed ticket is the result of 'Network.Oz.Ticket.issue'. It is
-- JSON-encoded and given to the app.
--
-- Unlike most Hawk credential identifiers, the Oz ticket identifier
-- is an encoded Iron string which when decoded contains an 'OzTicket'
data OzSealedTicket = OzSealedTicket
  { ozTicket          :: OzTicket
  , ozTicketKey       :: Key -- ^ A shared secret used to authenticate.
  , ozTicketAlgorithm :: HawkAlgo -- ^ The HMAC algorithm used to authenticate (e.g. HMAC-SHA256).
  , ozTicketExt       :: Object -- ^ Custom server public data attached to the ticket.
  , ozTicketId        :: OzTicketId  -- ^ The ticket identifier used for making authenticated Hawk requests.
  } deriving (Show, Generic)

-- | An object describing a ticket and its public properties.  An Oz
-- ticket is a set of Hawk credentials used by the application to
-- access protected resources. Just like any other Hawk credentials.
data OzTicket = OzTicket {
  -- | Ticket expiration time.
    ozTicketExp      :: POSIXTime
  -- | The application id the ticket was issued to.
  , ozTicketApp      :: OzAppId

  -- | The user id if the ticket represents access to
  -- user resources. If no user id is included, the
  -- ticket allows the application access to the
  -- application own resources only.
  , ozTicketUser     :: Maybe OzUserId
  -- | The ticket scope. Defaults to @[]@ if no scope is
  -- specified.
  , ozTicketScope    :: OzScope
  -- | If user is set, includes the grant identifier
  -- referencing the authorization granted by the user
  -- to the application. Can be a unique identifier or
  -- string encoding the grant information as long as
  -- the server is able to parse the information later.
  , ozTicketGrant    :: Maybe OzGrantId
  -- | If false, the ticket cannot be delegated
  -- regardless of the application permissions. Defaults
  -- to true which means use the application permissions
  -- to delegate.
  , ozTicketDelegate :: Bool
  -- | If the ticket is the result of access delegation,
  -- the application id of the delegating application.
  , ozTicketDlg      :: Maybe OzAppId
  } deriving (Show, Generic)


-- | Ticket generation options. The default values are:
--
--     * One hour ticket lifetime.
--     * One minute RSVP lifetime.
--     * Use the application permissions to delegate.
--     * 'Network.Iron.defaults' Iron configuration.
--     * 32 byte Hawk key length.
--     * 'Crypto.Hash.Algorithms.SHA256' message authentication.
--     * No ext data.

data TicketOpts = TicketOpts
  { ticketOptsTicketTtl     :: NominalDiffTime -- ^ Ticket lifetime
  , ticketOptsRsvpTtl       :: NominalDiffTime -- ^ RSVP lifetime

  -- | If false, the ticket cannot be delegated
  -- regardless of the application
  -- permissions.
  , ticketOptsDelegate      :: Bool
  -- | Overrides the default Iron configuration.
  , ticketOptsIron          :: Iron.Options
  -- | The Hawk key length in bytes.
  , ticketOptsKeyBytes      :: Int
  -- | The Hawk HMAC algorithm.
  , ticketOptsHmacAlgorithm :: HawkAlgo
  -- | Custom server data to be included in the ticket.
  , ticketOptsExt           :: OzExt
  }

defaultTicketOpts :: TicketOpts
defaultTicketOpts = TicketOpts 3600 60 True iron 32 (HawkAlgo SHA256) mempty
  where iron = Iron.options Iron.AES256CBC Iron.SHA256 256 100000

instance Default TicketOpts where
  def = defaultTicketOpts

-- | User-supplied function to look up an Oz app definition by its
-- identifier.
type OzLoadApp = OzAppId -> IO (Either String OzApp)

-- | User-supplied function to look up an Oz grant by its identifier.
type OzLoadGrant = OzGrantId -> IO (Either String (OzGrant, Maybe OzExt))

-- | Describes the URL configuration of the Oz server.
data Endpoints = Endpoints
  { endpointApp     :: Text
  , endpointReissue :: Text
  , endpointRsvp    :: Text
  } deriving Show

-- | A normal set of endpoint URL paths.
defaultEndpoints :: Endpoints
defaultEndpoints = Endpoints "/oz/app" "/oz/reissue" "/oz/rsvp"
