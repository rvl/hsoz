import Options.Applicative
import Data.Monoid ((<>))
import Data.Bifunctor (bimap)
import Control.Monad (join, unless)
import Data.Time.Clock (NominalDiffTime)
import Text.Read (readEither)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy.Char8 as L8
import qualified Data.ByteString.Char8 as S8
import System.IO
import Data.Aeson
import Data.Text (Text)
import qualified Data.Text.Lazy as TL
import Data.Text.Lazy.Encoding (decodeUtf8With, encodeUtf8, decodeUtf8')
import Data.Text.Encoding.Error (lenientDecode)

import Network.Iron

main :: IO ()
main = join . execParser $
  info (helper <*> parser)
  (  fullDesc
  <> header "Iron Utility"
  <> progDesc "Seals/unseals Iron messages."
  )
  where
    parser :: Parser (IO ())
    parser =
      iron
        <$> (Right <$> ( strOption
              (  long "password"
                <> short 'p'
                <> metavar "STRING"
                <> help "Encryption password"
              )) <|>
              (Left <$> ( strOption
                (  long "password-file"
                   <> metavar "FILENAME"
                   <> help "File containing encryption password"
                )
              ))
            )
        <*> ( optional
              ( flag' Seal
                ( long "seal"
                  <> short 's'
                  <> help "Seal (encrypt) input" )
              <|>
              flag' Unseal
                ( long "unseal"
                  <> short 'u'
                  <> help "Unseal (decrypt) input" )
              )
            )
        <*> flag StringFormat JSONFormat
            ( long "json"
              <> short 'j'
              <> help "Encode/decode input/output as JSON values"
            )
        <*> option ttl
            ( long "ttl"
            <> metavar "NUMBER"
            <> help "Ticket lifetime in seconds (default: 0 -- infinite)"
            <> value 0
            )
        <*> option auto
            (long "cipher"
            <> metavar "TYPE"
            <> help "Encryption algorithm: AES128CTR or AES256CBC (default)"
            <> value AES256CBC
            )
      <*> option auto
            ( long "salt-bits"
            <> metavar "INTEGER"
            <> help "Number of salt bits for key generation."
            <> value 256
            )
      <*> option auto
            ( long "iterations"
            <> metavar "INTEGER"
            <> help "Number of iterations of key derivation function."
            <> value 100000
            )

ttl :: ReadM NominalDiffTime
ttl = eitherReader (fmap fromInteger . readEither)

data Action = Seal | Unseal
data Format = JSONFormat | StringFormat

iron :: Either String String -> Maybe Action -> Format -> NominalDiffTime
     -> IronCipher -> Int -> Int -> IO ()
iron p a j ttl c s i = do
  p' <- password <$> readPassword p
  let opts = (options c SHA256 s i) { ironTTL = ttl }
  L8.hGetContents stdin >>= mapM_ (processLine opts p' a j) . L8.lines

readPassword :: Either FilePath String -> IO ByteString
readPassword (Left f) = withFile f ReadMode S8.hGetLine
-- fixme: error handling, checking if password is valid
readPassword (Right p) = return (S8.pack p)

processLine :: Options -> Password -> Maybe Action -> Format -> L8.ByteString -> IO ()
processLine opts p a j l = doLine opts p a j l >>= uncurry L8.hPutStrLn . output

output :: Either String ByteString -> (Handle, L8.ByteString)
output (Left e)  = (stderr, L8.pack e)
output (Right s) = (stdout, L8.fromStrict s)

doLine :: Options -> Password -> Maybe Action -> Format -> L8.ByteString -> IO (Either String ByteString)
doLine o p (Just Unseal) j s = lineUnseal o p j s
doLine o p (Just Seal) j s   = lineSeal o p j s
doLine o p Nothing j s | L8.isPrefixOf "Fe26.2" s = lineUnseal o p j s
                       | otherwise                = lineSeal o p j s

lineUnseal :: Options -> Password -> Format -> L8.ByteString -> IO (Either String ByteString)
lineUnseal o p j s = doUnseal o p s >>= return . join . fmap (fmap L8.toStrict . unconv j)

lineSeal :: Options -> Password -> Format -> L8.ByteString -> IO (Either String ByteString)
lineSeal o p j s = case conv j s of
                     Right v -> doSeal o p v
                     Left e -> return (Left e)

unconv :: Format -> Value -> Either String L8.ByteString
unconv JSONFormat  v           = Right . encode $ v
unconv StringFormat (String s) = Right . encodeUtf8 . TL.fromStrict $ s
unconv StringFormat _          = Left "Value is not a plain JSON string"

conv :: Format -> L8.ByteString -> Either String Value
conv JSONFormat   = eitherDecode'
conv StringFormat = bimap show (String . TL.toStrict) . decodeUtf8'

doSeal :: ToJSON a => Options -> Password -> a -> IO (Either String ByteString)
doSeal o p a = justRight "Failed to seal" <$> seal o p a

doUnseal :: FromJSON a => Options -> Password -> L8.ByteString -> IO (Either String a)
doUnseal o p s = unseal o (const (Just p)) (L8.toStrict s)

-- | Converts 'Maybe' to 'Either'.
justRight :: e -> Maybe a -> Either e a
justRight _ (Just a) = Right a
justRight e Nothing = Left e
