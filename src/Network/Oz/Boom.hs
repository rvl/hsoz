-- | Emulation of HapiJS Boom responses.

module Network.Oz.Boom
  ( badRequest
  , unauthorized
  , forbidden
  , internal
  , errHandler
  ) where

import           Control.Monad.IO.Class    (MonadIO (..), liftIO)
import           Data.Aeson                (Value (..), object, (.=))
import           Data.Maybe                (fromMaybe)
import           Data.Monoid               ((<>))
import           Data.Text.Encoding        (decodeUtf8)
import           Data.Text.Lazy            (Text, pack, toStrict)
import qualified Data.Text.Lazy            as TL
import           Network.HTTP.Types.Status (Status (..), mkStatus, status400,
                                            status401, status403, status500)
import           Text.Read                 (readMaybe)
import           Web.Scotty.Trans

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
