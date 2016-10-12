{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NamedFieldPuns #-}

-- | <<images/iron-logo.png>>
--
-- /Iron/ is a cryptographic utility for sealing a JSON object using
-- symmetric key encryption with message integrity verification. Or in
-- other words, it lets you encrypt an object, send it around (in
-- cookies, authentication credentials, etc.), then receive it back
-- and decrypt it. The algorithm ensures that the message was not
-- tampered with, and also provides a simple mechanism for password
-- rotation.
--
-- For more information about the sealing/unsealing process, as well
-- as security considerations, see the
-- <https://github.com/hueniverse/iron Iron Website>.
--
-- == Usage
-- To seal an object:
--
-- >>> import Data.Aeson
-- >>> import qualified Network.Iron as Iron
-- >>> let Just obj = decode "{\"a\":1,\"d\":{\"e\":\"f\"},\"b\":2,\"c\":[3,4,5]}" :: Maybe Object
-- >>> let password = Iron.Password "some_not_random_password"
-- >>> s <- Iron.seal password obj
-- >>> print s
-- "Fe26.2**a92316548adafcacff14f05c26f1a03aba037d01051027635f0fc27be8b758ee
-- *UJDElYgEo8JoSL1eF9kZgQ==*h1Qdx2+98HAbx1bp/+qQNnkS+0M5DIpgNfoXEPM3w2hx8NI
-- PIkYpWI0MVs4Vs2b7**caf5f1b71b2d2722973768802e3ecaaae63374968009e584bfc65f
-- eaed51ca4e*zYMPeS7ogfLXgKujSZ4q-au0aWtlp2gJoIhwZJefXW0"
--
-- The resulting "sealed" object is a string which can be sent via
-- cookies, URI query parameter, or a HTTP header attribute.
--
-- To unseal the string:
--
-- >>> Iron.unseal password s :: IO (Either String Object)
-- Right (Object (fromList [("a",Number 1.0),
-- ("d",Object (fromList [("e",String "f")])),
-- ("b",Number 2.0),
-- ("c",Array [Number 3.0,Number 4.0,Number 5.0])]))

module Network.Iron
  ( seal
  , sealWith
  , unseal
  , unsealWith
  , defaults
  , Options(..)
  , EncryptionOpts(..)
  , IntegrityOpts(..)
  , IronCipher(..)
  , IronMAC(..)
  , SHA256(SHA256)
  , IronSalt(..)
  , Password(..)
  , Passwords(..)
  , urlSafeBase64
  ) where

import Data.Aeson
import qualified Data.Aeson as JSON (encode, eitherDecode')
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as S8
import Data.Text (Text)
import Text.Read (readMaybe)
import Data.Time.Clock.POSIX
import Data.Time.Clock (NominalDiffTime)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import Crypto.Random
import Crypto.MAC.HMAC (hmac, initialize, updates, finalize, Context, HMAC, hmacGetDigest)
import Crypto.Hash.Algorithms (SHA256(..))
import Crypto.Cipher.AES (AES128, AES256(..))
import Crypto.Cipher.Types
import Crypto.Data.Padding
import Crypto.Hash.Algorithms (SHA1(..))
import Crypto.Error (CryptoFailable(..), maybeCryptoError)
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import Numeric (showHex)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import qualified Data.Map as M
import Data.Maybe (fromJust)
import Control.Monad (when, liftM)
import Data.Monoid ((<>))
import Network.Iron.Util

{-
unimplemented:
 - looking up password by id

todo:
 - maybe remove ieSalt/iiSalt and ieIV from opts? these values
   pregenerated by the user might not be necessary
-}

data Options = Options
  { ironEncryption :: EncryptionOpts -- ^ Encryption options
  , ironIntegrity :: IntegrityOpts  -- ^ Message integrity verification options
  , ironTTL :: NominalDiffTime -- ^ Message lifetime in seconds
  , ironTimestampSkew :: NominalDiffTime -- ^ Clock difference allowance in seconds
  , ironLocaltimeOffset :: NominalDiffTime -- ^ Clock offset in seconds
  } deriving Show

-- | Encryption algorithms supported by Iron.
data IronCipher = AES128CTR | AES256CBC  deriving Show

class IsIronCipher a where
  ivSize :: a -> Int
  keySize :: a -> Int
  ironEncrypt :: a -> ByteString -> ByteString -> ByteString -> Maybe ByteString
  ironDecrypt :: a -> ByteString -> ByteString -> ByteString -> Maybe ByteString

class IsIronMAC a where
  macKeySize :: a -> Int
  ironMac :: a -> ByteString -> ByteString -> ByteString

-- | Integrity checking algorithm supported by Iron. At present, there
-- is only one. Use @IronMAC SHA256@.
data IronMAC = forall alg . (IsIronMAC alg, Show alg) => IronMAC alg

instance Show IronMAC where
  show (IronMAC alg) = show alg

instance IsIronMAC IronMAC where
  macKeySize (IronMAC alg) = macKeySize alg
  ironMac (IronMAC alg) = ironMac alg

-- | Specifies the salt for password-based key generation.
data IronSalt = IronSalt ByteString -- ^ Supply pre-generated salt
              | IronGenSalt Int -- ^ Generate salt of given size, in bits
  deriving Show

-- | Options controlling encryption of Iron messages.
data EncryptionOpts = EncryptionOpts
  { ieSalt :: IronSalt -- ^ Salt for password-based key generation
  , ieAlgorithm :: IronCipher -- ^ Encryption algorithm
  , ieIterations :: Int -- ^ Number of iterations for password-based key generation
  , ieIV :: Maybe ByteString -- ^ Pre-generated initial value block
  } deriving Show

-- | Options controlling cryptographic verification of Iron messages.
data IntegrityOpts = IntegrityOpts
  { iiSalt :: IronSalt -- ^ Salt for MAC key generation
  , iiAlgorithm :: IronMAC -- ^ Hash-based MAC algorithm
  , iiIterations :: Int -- ^ Number of iterations for MAC key generation
  } deriving Show

defaultsEncrypt :: IronCipher -> EncryptionOpts
defaultsEncrypt algo = EncryptionOpts
                       { ieSalt = IronGenSalt 256
                       , ieAlgorithm = algo
                       , ieIterations = 1
                       , ieIV = Nothing }

defaultsIntegrity :: IronMAC -> IntegrityOpts
defaultsIntegrity algo = IntegrityOpts
                         { iiSalt = IronGenSalt 256
                         , iiAlgorithm = algo
                         , iiIterations = 1 }

-- | Default Iron options. Used by 'seal' and 'unseal'. The options are:
--
-- * Encryption: AES256 CBC
-- * Integrity HMAC: SHA256
-- * Infinite message lifetime
-- * Timestamp skew: 60 seconds either way
-- * Local time offset: 0
defaults :: Options
defaults = Options
  { ironEncryption = defaultsEncrypt AES256CBC
  , ironIntegrity = defaultsIntegrity (IronMAC SHA256)
  , ironTTL = 0
  , ironTimestampSkew = 60
  , ironLocaltimeOffset = 0
  }

-- | Password for sealing Iron messages.
data Password = Password ByteString  -- ^ Normal password
              | PasswordId ByteString Passwords -- ^ Look up password by ID

-- | A store of passwords. This doesn't work yet.
data Passwords = OnePassword ByteString
               | Passwords ByteString ByteString

passwordId :: Password -> ByteString
passwordId (Password _) = ""
passwordId (PasswordId id _) = id

encPassword, intPassword :: Password -> ByteString
encPassword (Password p) = p
encPassword (PasswordId _ (OnePassword p)) = p
encPassword (PasswordId _ (Passwords p _)) = p
intPassword (Password p) = p
intPassword (PasswordId _ (OnePassword p)) = p
intPassword (PasswordId _ (Passwords _ p)) = p

-- | Encodes and encrypts a 'Data.Aeson.Value' using the given
-- password.
seal :: ToJSON a => Password -> a -> IO ByteString
seal password = liftM fromJust <$> sealWith defaults password

-- | Encodes and encrypts a 'Data.Aeson.Value' using the given
-- password and 'Options'. Encryption may fail if the supplied
-- options are wrong.
sealWith :: ToJSON a => Options -> Password -> a -> IO (Maybe ByteString)
sealWith opts p v = do
  s <- getSealStuff opts
  return $ seal' opts s p v

-- | Variables necessary for sealing whose values come from the
-- IO world.
data SealStuff = SealStuff
  { ssNow :: POSIXTime
  , ssEncSalt :: ByteString
  , ssIv :: ByteString
  , ssIntSalt :: ByteString
  } deriving (Show)

-- | Gets the time, generate random numbers.
getSealStuff :: Options -> IO SealStuff
getSealStuff opts@Options{..} = do
  now <- getPOSIXTime
  drg1 <- getSystemDRG
  let (encSalt, drg2) = genSaltMaybe (ieSalt ironEncryption) drg1
  let (intSalt, drg3) = genSaltMaybe (iiSalt ironIntegrity) drg2
  let (iv, _) = genIVMaybe (ieAlgorithm ironEncryption) (ieIV ironEncryption) drg3
  return $ SealStuff (now + ironLocaltimeOffset) encSalt iv intSalt


-- | Effects-pure part of sealing process.
--
-- The seal process follows these general steps:
--   generate encryption salt saltE
--   derive an encryption key keyE using saltE and a password
--   generate an integrity salt saltI
--   derive an integrity (HMAC) key keyI using saltI
--   generate a random initialization vector iv
--   encrypt the serialized object string using keyE and iv
--   mac the encrypted object along with saltE and iv
--   concatenate saltE, saltI, iv, and the encrypted object into a URI-friendly string
seal' :: forall a. ToJSON a => Options -> SealStuff -> Password -> a -> Maybe ByteString
seal' opts SealStuff{..} sec = fmap (strCookie . mac . strEncCookie) . encrypt
  where
    encrypt :: a -> Maybe EncCookie
    encrypt obj = EncCookie (passwordId sec) ssEncSalt ssIv expiration <$> ctext
      where
        EncryptionOpts{..} = ironEncryption opts
        encKey = generateKey ieIterations size (encPassword sec) ssEncSalt
        ctext = ironEncrypt ieAlgorithm encKey ssIv json
        json = BL.toStrict $ JSON.encode obj
        expiration = expTime opts ssNow
        size = keySize ieAlgorithm

    mac :: ByteString -> Cookie
    mac str = Cookie str ssIntSalt macDigest
      where
        IntegrityOpts{..} = ironIntegrity opts
        macKey = generateKey iiIterations size (intPassword sec) ssIntSalt
        macDigest = macWithKey iiAlgorithm macKey str
        size = macKeySize iiAlgorithm


data EncCookie = EncCookie
  { ckPasswordId :: ByteString
  , ckEncSalt :: ByteString
  , ckIv :: ByteString
  , ckExpiration :: Maybe NominalDiffTime
  , ckText :: ByteString
  } deriving Show

data Cookie = Cookie
  { ckEnc :: ByteString
  , ckIntSalt :: ByteString
  , ckIntDigest :: ByteString
  } deriving Show

strEncCookie :: EncCookie -> ByteString
strEncCookie (EncCookie pid s iv e t) = cat [macPrefix, pid, s, b64 iv, b64 t, expStr e]

strCookie :: Cookie -> ByteString
strCookie (Cookie a b c) = cat [a, b, c]

parseCookie :: ByteString -> Either String (EncCookie, Cookie)
parseCookie ck = do
  when (length parts /= 8) $ Left "Incorrect number of sealed components"
  when (pfx /= macPrefix) $ Left "Wrong mac prefix"
  eck <- EncCookie <$> pure a <*> pure b <*> B64.decode c <*> parseExp e <*> B64.decode d
  return (eck, Cookie enc f g)
  where
    parts = uncat ck
    (pfx:a:b:c:d:e:f:g:[]) = parts
    enc = cat $ take 6 parts
    parseExp :: ByteString -> Either String (Maybe NominalDiffTime)
    parseExp "" = Right Nothing
    parseExp n = maybe (Left "Invalid expiration") (Right . toExp) (readMaybe $ S8.unpack n)
    toExp :: Integer -> Maybe NominalDiffTime
    toExp n | n > 0 = Just (fromInteger n)
            | otherwise = Nothing

cat :: [ByteString] -> ByteString
cat = BS.intercalate (S8.singleton '*')

uncat :: ByteString -> [ByteString]
uncat = S8.split '*'

expStr :: Maybe NominalDiffTime -> ByteString
expStr = maybe "" (S8.pack . show . round)

expTime :: Options -> POSIXTime -> Maybe NominalDiffTime
expTime Options{ironTTL} now | ironTTL > 0 = Just ((now + ironTTL) * 1000)
                              | otherwise = Nothing

instance IsIronMAC SHA256 where
  macKeySize _ = 32
  ironMac _ key text = b64 $ hmacGetDigest (hmac key text :: HMAC SHA256)

-- | Calculates the MAC of a message. The result is encoded in the
-- URL-friendly variant of Base64.
macWithKey :: IronMAC -> ByteString -> ByteString -> ByteString
macWithKey algo key text = urlSafeBase64 (ironMac algo key text)

generateKey :: Int -> Int -> ByteString -> ByteString -> ByteString
generateKey iterations size = PBKDF2.generate prf params
  where
    prf = PBKDF2.prfHMAC SHA1
    params = PBKDF2.Parameters iterations size

passwordValid :: EncryptionOpts -> ByteString -> Bool
passwordValid EncryptionOpts{..} sec = keySize ieAlgorithm < BS.length sec

-- | Prepares the variables necessary to use cryptonite block cipher
-- functions.
aesSetup :: BlockCipher c => ByteString -> ByteString -> Maybe (c, IV c, Format)
aesSetup key iv = (,,) <$> ctx <*> iv' <*> p
  where
    ctx = maybeCryptoError (cipherInit key)
    iv' = makeIV iv
    p = fmap (PKCS7 . blockSize) ctx

instance IsIronCipher IronCipher where
  -- IV is the size of one block
  ivSize AES128CTR = blockSize (undefined :: AES128)
  ivSize AES256CBC = blockSize (undefined :: AES256)

  -- Iron's chosen key size -- should fall within the range of
  -- cryptonite cipherKeySize
  keySize AES128CTR = 16
  keySize AES256CBC = 32

  -- Encrypt with AES block counter mode
  ironEncrypt AES128CTR key iv text = do
    (ctx :: AES128, iv', p) <- aesSetup key iv
    return $ ctrCombine ctx iv' (pad p text)

  -- Encrypt with AES block chaining mode
  ironEncrypt AES256CBC key iv text = do
    (ctx :: AES256, iv', p) <- aesSetup key iv
    let text' = pad p text
    return $ cbcEncrypt ctx iv' text'

  -- Decrypt with AES block counter mode
  ironDecrypt AES128CTR key iv ctext = do
    (ctx :: AES128, iv', p) <- aesSetup key iv
    unpad p (ctrCombine ctx iv' ctext)

  -- Decrypt with AES block chaining mode
  ironDecrypt AES256CBC key iv ctext = do
    (ctx :: AES256, iv', p) <- aesSetup key iv
    let text' = cbcDecrypt ctx iv' ctext
    unpad p text'

-- | Decrypts an Iron-encoded message 'Data.Aeson.Value' with the
-- given password.
unseal :: FromJSON a => Password -> ByteString -> IO (Either String a)
unseal password = unsealWith defaults password

-- | Decrypts an Iron-encoded message 'Data.Aeson.Value' with the
-- given password and 'Options'.
unsealWith :: FromJSON a => Options -> Password -> ByteString -> IO (Either String a)
unsealWith opts p t = do
  now <- getPOSIXTime
  return $ unseal' opts now p t

-- | Effects-pure part of unsealing process.
unseal' :: FromJSON a => Options -> POSIXTime -> Password -> ByteString -> Either String a
unseal' opts now sec cookie = do
  (eck, ck) <- parseCookie cookie
  _ <- checkExpiration now (ironTimestampSkew opts) eck
  password <- getPassword opts (ckPasswordId eck) sec
  ok <- verify ck
  case decrypt eck of
    Just ctext -> JSON.eitherDecode' (BL.fromStrict ctext)
    Nothing -> Left "Iron decryption failed"
  where
    decrypt :: EncCookie -> Maybe ByteString
    decrypt EncCookie{..} = text
      where
        EncryptionOpts{..} = ironEncryption opts
        encKey = generateKey ieIterations size (encPassword sec) ckEncSalt
        text = ironDecrypt ieAlgorithm encKey ckIv ckText -- fixme: handle fail
        size = keySize ieAlgorithm

    verify :: Cookie -> Either String ()
    verify Cookie{..} = if fixedTimeEq ckIntDigest macDigest
                           then Right ()
                           else Left "Bad hmac value"
      where
        IntegrityOpts{..} = ironIntegrity opts
        macKey = generateKey iiIterations size (intPassword sec) ckIntSalt
        macDigest = macWithKey iiAlgorithm macKey ckEnc
        size = macKeySize iiAlgorithm

    checkExpiration :: NominalDiffTime -> NominalDiffTime -> EncCookie -> Either String ()
    checkExpiration now skew EncCookie{ckExpiration} = if isExpired now skew ckExpiration
                                                          then Left "Expired seal"
                                                          else Right ()

    getPassword :: Options -> ByteString -> Password -> Either String Password
    -- id lookup not implemented yet
    getPassword opts pid password = Right password

isExpired :: POSIXTime -> NominalDiffTime -> Maybe POSIXTime -> Bool
isExpired _ _ Nothing = False
isExpired now skew (Just exp) = exp <= (now - skew)

genSalt :: DRG gen => Int -> gen -> (ByteString, gen)
genSalt saltBits gen = withRandomBytes gen (saltBits `quot` 8) B16.encode

genIV :: DRG gen => Int -> gen -> (ByteString, gen)
genIV size gen = withRandomBytes gen size id

genSaltMaybe :: DRG gen => IronSalt -> gen -> (ByteString, gen)
genSaltMaybe (IronSalt salt) = \gen -> (salt, gen)
genSaltMaybe (IronGenSalt len) = genSalt len

genIVMaybe :: DRG gen => IronCipher -> Maybe ByteString -> gen -> (ByteString, gen)
genIVMaybe _ (Just iv) = \gen -> (iv, gen)
genIVMaybe algo Nothing = genIV (ivSize algo)

macPrefix, macFormatVersion :: ByteString
macPrefix = "Fe26." <> macFormatVersion
macFormatVersion = "2"
