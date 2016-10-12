{-# LANGUAGE TupleSections #-}
{-# LANGUAGE RecordWildCards #-}
module Network.Oz.JSON where

import Data.Aeson
import Data.Aeson.Types
import qualified Data.Aeson.Types as JSON
import Data.Text (Text)
import qualified Data.Text as T (pack, unpack, null)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Char (toLower)
import Data.Time.Clock.POSIX (POSIXTime)
import Data.Scientific (toRealFloat)
import Data.Maybe (catMaybes)

import Network.Oz.Types
import Network.Oz.Internal.Types
import Network.Hawk.Types

fieldModifier :: String -> String
fieldModifier = drop 1 . dropWhile (/= '_') . dropWhile (== '_') . camelTo2 '_'

opts = defaultOptions { JSON.fieldLabelModifier = fieldModifier }

instance ToJSON OzSealedTicket where
  toJSON OzSealedTicket{..} = object $ ticketObj ozTicket ++ mid ++
                              [ "key" .= fromKey ozTicketKey
                              , "algorithm" .= ozTicketAlgorithm
                              ] ++ ext
    where
      fromKey (Key k) = decodeUtf8 k
      mid = if T.null ozTicketId then [] else [("id", String ozTicketId)]
      ext = if ozTicketExt == mempty then [] else ["ext" .= ozTicketExt]

instance ToJSON OzTicket where
  toJSON ticket = object $ ticketObj ticket

ticketObj :: OzTicket -> [Pair]
ticketObj OzTicket{..} = catMaybes
                         [ Just ("exp", toMsec ozTicketExp)
                         , Just ("app", String ozTicketApp)
                         , Just ("scope", toJSON ozTicketScope)
                         , may "grant" ozTicketGrant
                         , may "user" ozTicketUser
                         , may "dlg" ozTicketDlg
                         , Just ("delegate", Bool ozTicketDelegate)
                         ]
  where
    toMsec = Number . fromIntegral . round . (* 1000)
    may k = fmap ((k,) . String)

instance FromJSON OzSealedTicket where
  parseJSON (Object v) = OzSealedTicket
                         <$> parseJSON (Object v)
                         <*> v .: "key"
                         <*> v .: "algorithim"
                         <*> v .: "ext"
                         <*> pure ""
  parseJSON invalid = typeMismatch "Ticket" invalid

instance FromJSON OzTicket where
  parseJSON (Object v) = OzTicket
                         <$> fmap fromMsec (v .: "exp")
                         <*> v .: "app"
                         <*> v .: "user"
                         <*> v .: "scope"
                         <*> v .: "grant"
                         <*> v .: "delegate"
                         <*> v .: "dlg"
    where
      fromMsec = realToFrac . toRealFloat . (/ 1000)

  parseJSON invalid = typeMismatch "Ticket" invalid

instance ToJSON HawkAlgo where
  toJSON = String . T.pack . show

instance FromJSON HawkAlgo where
  parseJSON (String s) = case readHawkAlgo (T.unpack s) of
                           Just a -> return a
                           Nothing -> fail "Unknown algorithm"

instance ToJSON OzExt where
  toJSON = genericToJSON opts

instance FromJSON OzExt where
  parseJSON = genericParseJSON opts

instance FromJSON Key where
  parseJSON (String v) = return $ Key (encodeUtf8 v)
  parseJSON invalid = typeMismatch "Key" invalid

instance FromJSON ReissueRequest where
  parseJSON (Object v) = ReissueRequest <$>
                           v .:? "issueTo" <*>
                           v .:? "scope"

instance FromJSON RsvpRequest where
  parseJSON (Object v) = RsvpRequest <$> v .: "rsvp"
