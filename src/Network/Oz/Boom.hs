-- | Emulation of HapiJS Boom responses.

module Network.Oz.Boom
  ( badRequest
  , unauthorized
  , forbidden
  , internal
  , errHandler
  ) where

import Data.Text.Lazy (Text, pack, toStrict)
import qualified Data.Text.Lazy as TL
import Data.Text.Encoding (decodeUtf8)
import Web.Scotty.Trans
import Data.Aeson (object, Value(..), (.=))
import Network.HTTP.Types.Status (Status(..), status400, status401, status403, status500, mkStatus)
import Control.Monad.IO.Class (liftIO, MonadIO(..))
import Data.Monoid ((<>))
import Text.Read (readMaybe)
import Data.Maybe (fromMaybe)

-- fixme: can't figure out scotty custom error types, so am doing lame
-- conversion of status codes to strings.

{-
import Control.Monad.Error

instance Error Boom where
  strMsg = Boom status500

data Boom = Boom Status String
  deriving (Show, Eq)

instance ScottyError Boom where
  stringError = Boom status500
  showError = TL.pack . show
-}

type Boom = Text

badRequest :: Monad m => String -> ActionT Boom m a
badRequest e = boom status400 e

unauthorized :: Monad m => String -> ActionT Boom m a
unauthorized e = boom status401 e

forbidden :: Monad m => String -> ActionT Boom m a
forbidden e = boom status403 e

internal :: Monad m => String -> ActionT Boom m a
internal e = boom status500 e

boom :: Monad m => Status -> String -> ActionT Boom m a
boom code e = do
  status code
  let e' = pack e
  json $ boomObject code e'
  raise $ pack (show (statusCode code)) <> " " <> e'
  -- raise (Boom code e)

boomObject :: Status -> Text -> Value
boomObject code msg = object
  [ "statusCode" .= statusCode code
  , "error" .= decodeUtf8 (statusMessage code)
  , "message" .= msg
  ]

{-
errHandlerBoom :: Monad m => Boom -> ActionT Boom m ()
errHandlerBoom (Boom code msg) = status code
-}

errHandler :: MonadIO m => Text -> ActionT Text m ()
errHandler e = do
  liftIO $ putStrLn $ "*** errHandler " ++ show e
  let (code, msg) = TL.break (== ' ') e
  status $ maybe status500 toEnum (readMaybe (TL.unpack code))
