{-# LANGUAGE RecordWildCards #-}

module OzServer where

import           Common
import qualified Data.ByteString.Char8    as S8
import qualified Data.ByteString.Lazy     as BL
import           Data.Text.Lazy.Encoding  (encodeUtf8, decodeUtf8)
import qualified Data.Text.Encoding       as ES8 (encodeUtf8, decodeUtf8)
import           Data.CaseInsensitive     (original)
import           Data.List                (find)
import           Data.Monoid              ((<>))
import           Data.Text.Lazy           (Text)
import qualified Data.Text.Lazy           as TL
import           Network.HTTP.Types       (hAuthorization)
import           Network.Wai
import           Control.Monad.IO.Class   (liftIO)
import           Web.Scotty
import           Lucid

import           Network.Oz.Application
import           Network.Oz.Types
import           Network.Oz.Ticket        (rsvp)
import qualified Network.Iron             as Iron

-- fixme: temp
import           Data.Aeson               (Value (..), encode, object, (.=))
import qualified Data.Text                as T
import qualified Network.Hawk.Client      as Hawk

serverMain :: IO ()
serverMain = do
  let opts = (defaultOzServerOpts sharedKey) { ozLoadApp = loadApp }

  let exampleApp = head apps

  scotty 8000 $ do
    middleware $ ifRequest needAuth (ozAuth opts)
    get "/" $ do
      let appUrl = "http://localhost:8000/oz/app" -- fixme: build url from request Host header
      curl <- liftIO $ printCurl exampleApp appUrl Nothing
      lucid $ do
        h1_ "Oz Auth Example"
        p_ "To get an app ticket, try this:"
        pre_ $ toHtml curl

    get "/authorize" $ do
      sealed <- param "ticket"
      res <- liftIO $ openTicket sealed
      lucid $ do
        h1_ "Log in and review grants"
        case res of
          Right t -> do
            p_ $ "Ticket is " <> toHtml (show t)
            case ozTicketGrant t of
              Just grant -> p_ $ "Grant is " <> toHtml grant
              Nothing -> p_ "No grant in ticket"
            if (not . null . ozTicketScope $ t)
              then do
                p_ $ "Requested scope is:"
                ul_ $ mapM_ (li_ . toHtml) (ozTicketScope t)
              else p_ $ "Requested scope is empty"
          Left e -> do
            p_ $ "Couldn't open the ticket: "
            p_ $ toHtml e
        form_ [ method_ "get", action_ "/" ] $ do
          input_ [ type_ "submit", name_ "cancel", value_ "Cancel" ]
        form_ [ method_ "post" ] $ do
          input_ [ type_ "hidden", name_ "ticket", value_ $ ES8.decodeUtf8 sealed ]
          input_ [ type_ "submit", name_ "submit", value_ "Continue" ]


    post "/authorize" $ do
      sealed <- param "ticket"
      res <- liftIO $ openTicket sealed
      -- fixme: unsealed the ticket, now sealing it again ... something's wrong
      -- need to change it to an rsvp
      r <- case res of
             Right t@OzTicket{..} -> do
               r' <- liftIO $ rsvp ozTicketApp ozTicketGrant sharedKey defaultTicketOpts
               return $ Right (t, r')
             Left e -> return $ Left e

      lucid $ do
        h1_ "Getting rsvp"
        case r of
          Right (t, mrsvp) -> do
            p_ $ "Ticket is " <> toHtml (show t)
            p_ $ "Your rsvp is" <> (toHtml $ show mrsvp)
            case mrsvp of
              Just r -> do
                let url = "/oz/rsvp?ticket=" <> ES8.decodeUtf8 r
                a_ [ href_ url ] "Exchange rsvp for user-specific ticket"
              Nothing -> p_ "failure"
          Left e -> do
            p_ $ "Couldn't open the ticket: "
            p_ $ toHtml e

    -- post "/access" $ do
    --   sealed <- param "ticket"
    --   res <- liftIO $ openTicket sealed
    --   r <- case res of
    --     Right t@OzTicket{..} -> do
    --       r' <- liftIO $ rsvp ozTicketApp ozTicketGrant sharedKey defaultTicketOpts
    --            return $ Right (t, r')
    --          Left e -> return $ Left e

    --   lucid $ do
    --     h1_ "Getting user-ticket"

    get "/protected" $ do
      text $ "this requires a user-ticket"

    -- embed the Oz ticket endpoints
    ozAppScotty opts

lucid :: Html a -> ActionM ()
lucid = html . renderText . page
  where page h = doctypehtml_ $ do
          head_ $ title_ "Oz Auth Example"
          body_ h

needAuth :: Request -> Bool
needAuth req = case reverse (pathInfo req) of
                 ("protected":_) -> True
                 otherwise -> False

openTicket :: S8.ByteString -> IO (Either String OzTicket)
openTicket = Iron.unseal opts (password sharedKey)
  where
    opts = ticketOptsIron defaultTicketOpts
    password (Hawk.Key p) = Iron.onePassword p

-- | Example apps registry
apps = [OzApp "app123" Nothing False sharedKey (Hawk.HawkAlgo Hawk.SHA256)]

-- | Example lookup of an app by id
loadApp :: OzLoadApp
loadApp aid = return $ case find ((== aid) . ozAppId) apps of
                         Just app -> Right app
                         Nothing -> Left ("ozAppId " ++ show aid ++ " not found")

-- | Shows a curl command line with Hawk Authorization header which
-- can be used to access Oz.
printCurl :: OzApp -> Text -> Maybe Value -> IO Text
printCurl (OzApp aid _ _ key algo) url mdata = do
  auth <- Hawk.headerOz (TL.toStrict url) "POST" creds Nothing 0 Nothing aid Nothing
  let authHeader = decodeUtf8 . BL.fromStrict . fmtHeader . mkHeader $ auth
  return $ "curl -i -X POST " <> dataArg <> "-H 'Content-Type: application/json' -H '" <> authHeader <> "' " <> url
  where
    dataArg = maybe "" (\d -> "--data '" <> decodeUtf8 d <> "'") (fmap encode mdata)
    creds = Hawk.Credentials aid key algo
    fmtHeader (h, v) = original h <> ": " <> v
    mkHeader = (,) hAuthorization . Hawk.hdrField
