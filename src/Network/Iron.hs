{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE NamedFieldPuns            #-}
{-# LANGUAGE RecordWildCards           #-}
{-# LANGUAGE ScopedTypeVariables       #-}

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
-- >>> import Data.ByteString (ByteString)
-- >>> import Data.Aeson
-- >>> import qualified Network.Iron as Iron
-- >>> let opts = Iron.options Iron.AES256CBC Iron.SHA256 256 66666
-- >>> let Just obj = decode "{\"a\":1,\"d\":{\"e\":\"f\"},\"b\":2,\"c\":[3,4,5]}" :: Maybe Object
-- >>> let secret = "some_not_random_password" :: ByteString
-- >>> Just s <- Iron.seal opts (Iron.password secret) obj
-- >>> print s
-- "Fe26.2**3976da2bc627b3551c1ebfe40376bb791efb17f4425facc648038fdaaa2f67b2
-- *voiPExJrXAxmTWyQr7-Hvw*r_Ok7NOgy9sD2fS61t_u9z8qoszwBRze3NnA6PFmjnd06sLh0
-- 9HRDlLorNYQJeEP**f6e22615db961e5ddc2ed47d956700b2ee63f0ab6f7ae6d3471989e5
-- 4928e653*RsQNtNp4u5L-0fmZHSpPL7nbjBkqyKEyBcbOCbpEcpY"
--
-- The resulting "sealed" object is a string which can be sent via
-- cookies, URI query parameter, or a HTTP header attribute.
--
-- To unseal the string:
--
-- >>> Iron.unseal opts (onePassword secret) s :: IO (Either String Object)
-- Right (Object (fromList [("a",Number 1.0),
-- ("d",Object (fromList [("e",String "f")])),
-- ("b",Number 2.0),
-- ("c",Array [Number 3.0,Number 4.0,Number 5.0])]))

module Network.Iron
  ( seal
  , unseal
  , options
  , password
  , passwords
  , passwordWithId
  , passwordsWithId
  , Password
  , PasswordId
  , LookupPassword
  , onePassword
  , Options(..)
  , EncryptionOpts(..)
  , IntegrityOpts(..)
  , IronCipher(..)
  , IronHMAC(..)
  , Salt(..)
  ) where

import           Control.Monad          (liftM, when)
import           Crypto.Cipher.AES      (AES128, AES256 (..))
import           Crypto.Cipher.Types
import           Crypto.Data.Padding
import           Crypto.Error           (CryptoFailable (..), maybeCryptoError)
import qualified Crypto.Hash.Algorithms as C (SHA256 (..))
import           Crypto.Hash.Algorithms (HashAlgorithm(..), SHA1 (..))
import qualified Crypto.KDF.PBKDF2      as PBKDF2
import           Crypto.MAC.HMAC        (Context, HMAC, finalize, hmac,
                                         hmacGetDigest, initialize, updates)
import           Crypto.Random
import           Data.Aeson
import qualified Data.Aeson             as JSON (eitherDecode', encode)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Char8  as S8
import qualified Data.ByteString.Lazy   as BL
import qualified Data.ByteArray         as BA
import           Data.ByteArray         (ScrubbedBytes, ByteArrayAccess)
import qualified Data.Map               as M
import           Data.Maybe             (fromJust)
import           Data.Monoid            ((<>))
import           Data.Text              (Text)
import           Data.Text.Encoding     (decodeUtf8, encodeUtf8)
import           Data.Char              (isAscii, isAlphaNum)
import           Data.Time.Clock        (NominalDiffTime)
import           Data.Time.Clock.POSIX
import           Network.Iron.Util
import           Numeric                (showHex)

-- | Iron options used by 'sealWith' and 'unsealWith'.
data Options = Options
  { ironEncryption      :: EncryptionOpts  -- ^ Encryption options
  , ironIntegrity       :: IntegrityOpts   -- ^ Message integrity verification options
  , ironTTL             :: NominalDiffTime -- ^ Message lifetime in seconds
  , ironTimestampSkew   :: NominalDiffTime -- ^ Clock difference allowance in seconds
  , ironLocaltimeOffset :: NominalDiffTime -- ^ Clock offset in seconds
  } deriving Show

-- | Encryption algorithms supported by Iron.
data IronCipher = AES128CTR | AES256CBC  deriving (Show, Read, Eq, Enum)
data IronHMAC = SHA256 deriving (Show, Read, Eq, Enum)

class IsIronCipher a where
  ivSize :: a -> Int
  keySize :: a -> Int
  ironEncrypt :: a -> ByteString -> ByteString -> ByteString -> Maybe ByteString
  ironDecrypt :: a -> ByteString -> ByteString -> ByteString -> Maybe ByteString

class IsIronMAC a where
  macKeySize :: a -> Int
  ironMac :: a -> ByteString -> ByteString -> ByteString

instance IsIronMAC IronHMAC where
  macKeySize SHA256 = 32
  ironMac SHA256 key text = b64url $ hmacGetDigest (hmac key text :: HMAC C.SHA256)

-- | Specifies the salt for password-based key generation.
data Salt = Salt ByteString -- ^ Supply pre-generated salt
          | GenSalt Int     -- ^ Generate salt of given size, in bits
  deriving Show

{-
todo:
 - maybe remove ieSalt/iiSalt and ieIV from opts? these values
   pre-generated by the user might only be necessary for unit tests.
-}

-- | Options controlling encryption of Iron messages.
data EncryptionOpts = EncryptionOpts
  { ieSalt       :: Salt -- ^ Salt for password-based key generation
  , ieAlgorithm  :: IronCipher -- ^ Encryption algorithm
  , ieIterations :: Int -- ^ Number of iterations for password-based key generation
  , ieIV         :: Maybe ByteString -- ^ Pre-generated initial value block
  } deriving Show

-- | Options controlling cryptographic verification of Iron messages.
data IntegrityOpts = IntegrityOpts
  { iiSalt       :: Salt -- ^ Salt for MAC key generation
  , iiAlgorithm  :: IronHMAC -- ^ Hash-based MAC algorithm
  , iiIterations :: Int -- ^ Number of iterations for MAC key generation
  } deriving Show

encryptOptions :: IronCipher -- ^ Cipher algorithm
               -> Int -- ^ Number of salt bits for key generation
               -> Int -- ^ Number of iterations of key derivation function
               -> EncryptionOpts
encryptOptions a s n = EncryptionOpts
                       { ieSalt = GenSalt s
                       , ieAlgorithm = a
                       , ieIterations = n
                       , ieIV = Nothing }

integrityOptions :: IronHMAC -- ^ Cryptographic hash algorithm
                 -> Int -- ^ Number of salt bits for key generation
                 -> Int -- ^ Number of iterations of key derivation function
                 -> IntegrityOpts
integrityOptions a s n = IntegrityOpts
                         { iiSalt = GenSalt s
                         , iiAlgorithm = a
                         , iiIterations = n }

-- | A set of basic options. You need to choose a cipher and
-- parameters for key generation.
--
-- There are also some default options chosen, which are:
-- * Infinite message lifetime
-- * Timestamp skew: 60 seconds either way
-- * Local time offset: 0
options :: IronCipher -- ^ Encryption algorithm.
        -> IronHMAC    -- ^ Integrity check algorithm (use @SHA256@).
        -> Int        -- ^ Number of salt bits for key generation.
        -> Int        -- ^ Number of iterations of key derivation function.
        -> Options
options e i s n = Options
  { ironEncryption = encryptOptions e s n
  , ironIntegrity = integrityOptions i s n
  , ironTTL = 0
  , ironTimestampSkew = 60
  , ironLocaltimeOffset = 0
  }

-- | Identifies the password to use when unsealing the message.
type PasswordId = ByteString

-- | Represents the password(s) used to seal and unseal Iron
-- messages. To construct a 'Password', use one of 'password',
-- 'passwords', 'passwordWithId', 'passwordsWithId'.
data Password = MkPassword
  { passwordId :: PasswordId
  , encKey     :: KeyPass -- ^ Encryption key/password
  , intKey     :: KeyPass -- ^ Integrity key/password
  } deriving (Show, Eq)

-- | Represents a key used for the cipher or message authentication
-- code, or a password from which a key will be generated.
data KeyPass = Key ScrubbedBytes      -- ^ Pre-generated key
             | Password ScrubbedBytes -- ^ Key derived from password
             deriving (Show, Eq)
             -- note: ScrubbedBytes Show doesn't actually show any content

-- | Constructs a 'Password'.
password :: ByteArrayAccess a => a -> Password
password p = passwords p p

-- | Constructs a 'Password', with different encryption and integrity
-- verification passwords.
passwords :: ByteArrayAccess a => a -> a -> Password
passwords e i = password' mempty e i

-- | Constructs a 'Password'. The given identifier will be included as
-- the second component of the the sealed @Fe26@ string. The
-- identifier must only include alphanumeric characters and the
-- underscore, otherwise nothing will be returned.
passwordWithId :: ByteArrayAccess a => PasswordId -> a -> Maybe Password
passwordWithId k p = passwordsWithId k p p

-- | Constructs a 'Password', with different encryption and integrity
-- verification passwords. The given identifier will be included as
-- the second component of the the sealed @Fe26@ string. The
-- identifier must only include alphanumeric characters and the
-- underscore, otherwise nothing will be returned.
passwordsWithId :: ByteArrayAccess a => PasswordId -> a -> a -> Maybe Password
passwordsWithId k e i | validId k = Just $ password' k e i
                      | otherwise = Nothing

validId :: PasswordId -> Bool
validId k = not (S8.null k) && S8.all inRange k
  where inRange c = isAscii c && isAlphaNum c || c == '_'

passwordValid :: ByteArrayAccess a => EncryptionOpts -> a -> Bool
passwordValid EncryptionOpts{..} sec = keySize ieAlgorithm <= BA.length sec

password' :: ByteArrayAccess a => PasswordId -> a -> a -> Password
password' k e i = MkPassword k (passwd e) (passwd i)
  where passwd = Password . BA.convert

-- | User-supplied function to get the password corresponding to the
-- identifier from the sealed message.
type LookupPassword = PasswordId -> Maybe Password

-- | The simple case of LookupPassword, where there is the same
-- password for encryption and verification of all messages.
onePassword :: ByteArrayAccess a => a -> LookupPassword
onePassword = const . Just . password

-- | Encodes and encrypts a 'Data.Aeson.Value' using the given
-- password and 'Options'. Encryption may fail if the supplied
-- options are wrong.
seal :: ToJSON a => Options -> Password -> a -> IO (Maybe ByteString)
seal opts p v = do
  s <- getSealStuff opts
  return $ seal' opts s p v

-- | Variables necessary for sealing whose values come from the
-- IO world.
data SealStuff = SealStuff
  { ssNow     :: POSIXTime
  , ssEncSalt :: ByteString
  , ssIv      :: ByteString
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
seal' opts SealStuff{..} sec a = encrypt a >>= fmap strCookie . mac . strEncCookie
  where
    encrypt :: a -> Maybe EncCookie
    encrypt obj = do
      key <- rightJust $ generateKey ieIterations size ssEncSalt (encKey sec)
      ctext <- ironEncrypt ieAlgorithm key ssIv json
      return $ EncCookie (passwordId sec) ssEncSalt ssIv expiration ctext
      where
        EncryptionOpts{..} = ironEncryption opts
        json = BL.toStrict $ JSON.encode obj
        expiration = expTime opts ssNow
        size = keySize ieAlgorithm

    mac :: ByteString -> Maybe Cookie
    mac str = Cookie str ssIntSalt <$> rightJust digest
      where
        digest = hmacWithPassword intOpts key ssIntSalt str
        intOpts = ironIntegrity opts
        key = intKey sec

data EncCookie = EncCookie
  { ckPasswordId :: PasswordId
  , ckEncSalt    :: ByteString
  , ckIv         :: ByteString
  , ckExpiration :: Maybe NominalDiffTime
  , ckText       :: ByteString
  } deriving Show

data Cookie = Cookie
  { ckEnc       :: ByteString
  , ckIntSalt   :: ByteString
  , ckIntDigest :: ByteString
  } deriving Show

strEncCookie :: EncCookie -> ByteString
strEncCookie (EncCookie pid s iv e t) = cat [macPrefix, pid, s, b64url iv, b64url t, expStr e]

strCookie :: Cookie -> ByteString
strCookie (Cookie a b c) = cat [a, b, c]

parseCookie :: ByteString -> Either String (EncCookie, Cookie)
parseCookie ck = do
  when (length parts /= 8) $ Left "Incorrect number of sealed components"
  when (pfx /= macPrefix) $ Left "Wrong mac prefix"
  eck <- EncCookie <$> pure a <*> pure b <*> b64' c <*> exp e <*> b64' d
  return (eck, Cookie enc f g)
  where
    parts = uncat ck
    (pfx:a:b:c:d:e:f:g:[]) = parts
    enc = cat $ take 6 parts
    exp :: ByteString -> Either String (Maybe NominalDiffTime)
    exp "" = Right Nothing
    exp n = maybe (Left "Invalid expiration") (Right . Just) $ parseExpMsec n
    b64' = b64urldec

cat :: [ByteString] -> ByteString
cat = BS.intercalate (S8.singleton '*')

uncat :: ByteString -> [ByteString]
uncat = S8.split '*'

expStr :: Maybe NominalDiffTime -> ByteString
expStr = maybe "" (S8.pack . show . round)

expTime :: Options -> POSIXTime -> Maybe NominalDiffTime
expTime Options{ironTTL} now | ironTTL > 0 = Just ((now + ironTTL) * 1000)
                              | otherwise = Nothing

-- | Calculates the MAC of a message. The result is encoded in the
-- URL-friendly variant of Base64.
macWithKey :: IronHMAC -> ByteString -> ByteString -> ByteString
macWithKey algo key text = ironMac algo key text

generateKey :: Int -> Int -> ByteString -> KeyPass -> Either String ByteString
generateKey _ s _ (Key k) | BA.length k >= s = Right (BA.convert k)
                          | otherwise = Left "Key buffer (password) too small"
generateKey n s l (Password p) | BS.null l = Left "Missing salt"
                               | otherwise = Right (generateKey' n s l p)

generateKey' :: BA.ByteArrayAccess p => Int -> Int -> ByteString -> p -> ByteString
generateKey' iterations size salt p = PBKDF2.generate prf params p salt
  where
    prf = PBKDF2.prfHMAC SHA1
    params = PBKDF2.Parameters iterations size

-- | Calculates integrity hash.
hmacWithPassword :: IntegrityOpts -> KeyPass -> ByteString -> ByteString
                 -> Either String ByteString
hmacWithPassword IntegrityOpts{..} key salt text = do
  key' <- generateKey iiIterations (macKeySize iiAlgorithm) salt key
  Right $ macWithKey iiAlgorithm key' text

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
-- given password and 'Options'.
unseal :: FromJSON a => Options -> LookupPassword -> ByteString -> IO (Either String a)
unseal opts p t = do
  now <- getPOSIXTime
  return $ unseal' opts now p t

-- | Effects-pure part of unsealing process.
unseal' :: FromJSON a => Options -> POSIXTime -> LookupPassword -> ByteString -> Either String a
unseal' opts now p cookie = do
  (eck, ck) <- parseCookie cookie
  _ <- checkExpiration now (ironTimestampSkew opts) eck
  MkPassword _ enc int <- getPassword opts (ckPasswordId eck) p
  ok <- verify ck int
  decrypt eck enc >>= JSON.eitherDecode' . BL.fromStrict
  where
    decrypt :: EncCookie -> KeyPass -> Either String ByteString
    decrypt EncCookie{..} sec = do
      let EncryptionOpts{..} = ironEncryption opts
          size = keySize ieAlgorithm
      key <- generateKey ieIterations size ckEncSalt sec
      case ironDecrypt ieAlgorithm key ckIv ckText of
        Just ctext -> Right ctext
        Nothing -> Left "Iron decryption failed"

    verify :: Cookie -> KeyPass -> Either String ()
    verify Cookie{..} sec = do
      digest <- hmacWithPassword (ironIntegrity opts) sec ckIntSalt ckEnc
      if BA.constEq ckIntDigest digest
        then Right ()
        else Left "Bad hmac value"

    checkExpiration :: NominalDiffTime -> NominalDiffTime -> EncCookie -> Either String ()
    checkExpiration now skew EncCookie{ckExpiration} = if isExpired now skew ckExpiration
                                                          then Left "Expired seal"
                                                          else Right ()

    getPassword :: Options -> PasswordId -> LookupPassword -> Either String Password
    getPassword opts pid lookup = case lookup pid of
                                    Just p -> Right p
                                    Nothing -> Left $ "Cannot find password: " <> S8.unpack pid

isExpired :: POSIXTime -> NominalDiffTime -> Maybe POSIXTime -> Bool
isExpired _ _ Nothing         = False
isExpired now skew (Just exp) = exp <= (now - skew)

genSalt :: DRG gen => Int -> gen -> (ByteString, gen)
genSalt saltBits gen = withRandomBytes gen (saltBits `quot` 8) b16

genIV :: DRG gen => Int -> gen -> (ByteString, gen)
genIV size gen = withRandomBytes gen size id

genSaltMaybe :: DRG gen => Salt -> gen -> (ByteString, gen)
genSaltMaybe (Salt salt)   = \gen -> (salt, gen)
genSaltMaybe (GenSalt len) = genSalt len

genIVMaybe :: DRG gen => IronCipher -> Maybe ByteString -> gen -> (ByteString, gen)
genIVMaybe _ (Just iv)  = \gen -> (iv, gen)
genIVMaybe algo Nothing = genIV (ivSize algo)

macPrefix, macFormatVersion :: ByteString
macPrefix = "Fe26." <> macFormatVersion
macFormatVersion = "2"
