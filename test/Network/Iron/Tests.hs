{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}
{-# LANGUAGE Rank2Types #-}

module Network.Iron.Tests (tests) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as S8
import Data.Maybe (fromJust)
import Data.Either (isLeft)
import Data.Aeson
import Data.Time.Clock (NominalDiffTime)
import Data.Default (def)

import Test.QuickCheck
import Test.QuickCheck.Monadic
import qualified Test.QuickCheck         as QC
import qualified Test.QuickCheck.Monadic as QC
import           Test.Tasty              (TestTree, testGroup)
import           Test.Tasty.HUnit        (testCase)
import           Test.Tasty.QuickCheck   (testProperty)
import           Test.HUnit              (Assertion, (@?=))

import Network.Iron

tests :: TestTree
tests = testGroup "Network.Iron"
    [ testProperty "seal . unseal == id -- many different options"
      (prop_test :: Test1 Object -> Property)
    , testProperty "seal . unseal == id -- default options" prop_test1
    , testProperty "seal . unseal == id -- expiration" prop_test2
    , testProperty "seal . unseal == id -- expiration and many different options"
      (prop_test3 :: Test1 Object -> Property)
    , testProperty "unseal fails when password not found"
      (prop_test4 :: Test1 Object -> Property)

    , testGroup "Seal"
      [ testCase "returns an error when password.id is invalid" testSeal01
      -- , testCase "returns an error when password is missing" testSeal02  -- fixme: enable
      ]
    , testGroup "Unseal"
      [ testCase "unseals a ticket" testUnseal01
      , testCase "returns an error when number of sealed components is wrong" testUnseal02
      , testCase "returns an error when mac prefix is wrong" testUnseal03
      , testCase "returns an error when integrity check fails" testUnseal04
      , testCase "returns an error when decryption fails" testUnseal05
      , testCase "returns an error when iv base64 decoding fails" testUnseal06
      , testCase "returns an error when decrypted object is invalid" testUnseal07
      , testCase "returns an error when expired" testUnseal08
      , testCase "returns an error when expiration NaN" testUnseal09
      ]
    ]

obj :: Object
obj = fromJust $ decode "{\"a\":1,\"d\":{\"e\":\"f\"},\"b\":2,\"c\":[3,4,5]}"

testPassword :: ByteString
testPassword = "some_not_random_password_that_is_also_long_enough"

defaultPassword :: Password
defaultPassword = makeOnePassword testPassword

makeOnePassword :: ByteString -> Password
makeOnePassword = fromJust . passwordWithId "default"

lookupPassword :: LookupPassword
lookupPassword = onePassword testPassword

instance Arbitrary NominalDiffTime where
  arbitrary = do
    n <- choose (0, 3600 * 24) :: Gen Double
    return $ realToFrac n

instance Arbitrary Object where
  arbitrary = pure obj

instance Arbitrary Password where
  arbitrary = do
    p1 <- arbitrary :: Gen ByteString
    p2 <- arbitrary
    pid <- arbitraryPasswordId
    n <- choose (1, 4) :: Gen Int
    -- fixme: add pre-generated keys of 128/256 bit lengths
    return $ case n of
      1 -> password p1
      2 -> passwords p1 p2
      3 -> fromJust $ passwordWithId pid p1
      4 -> fromJust $ passwordsWithId pid p1 p2

onePassword' :: Password -> LookupPassword
onePassword' = const . Just

arbitraryPasswordId :: Gen PasswordId
arbitraryPasswordId = do
  cs <- listOf1 (elements $ ['a'..'z'] ++ ['0'..'9'] ++ ['A'..'Z'] ++ ['_'])
  return $ S8.pack cs

instance Arbitrary ByteString where
    arbitrary = fmap S8.pack arbitrary

instance Arbitrary Options where
  arbitrary = Options <$> arbitrary <*> arbitrary <*> ttl <*> skew <*> offset
    where
      ttl = oneof [arbitrary, pure 0]
      skew = pure 0
      offset = pure 0

instance Arbitrary EncryptionOpts where
  arbitrary = EncryptionOpts <$> arbitrary <*> arbitrary <*> choose (1, 3) <*> pure Nothing

instance Arbitrary IntegrityOpts where
  arbitrary = IntegrityOpts <$> arbitrary <*> arbitrary <*> choose (1, 3)

instance Arbitrary IronSalt where
  -- arbitrary = oneof [IronSalt <$> arbitrary, pure $ IronGenSalt 256]
  arbitrary = pure (IronGenSalt 256)

instance Arbitrary IronCipher where
  arbitrary = oneof (map pure [AES128CTR, AES256CBC])

instance Arbitrary IronMAC where
  arbitrary = pure (IronMAC SHA256)

data Test1 a = Test1
  { test1Obj :: a
  , test1Opts :: Options
  , test1Password :: Password
  } deriving Show

instance Arbitrary a => Arbitrary (Test1 a) where
  arbitrary = Test1 <$> arbitrary <*> arbitrary <*> arbitrary

prop_test :: (ToJSON a, FromJSON a, Eq a) => Test1 a -> Property
prop_test Test1{..} = monadicIO $ do
  obj' <- run $ do
    s <- seal test1Password test1Obj
    Right m <- unseal (onePassword' test1Password) s
    return m
  assert (obj' == obj)

-- turns object into a ticket than parses the ticket successfully
prop_test1 :: Object -> Property
prop_test1 o = monadicIO $ do
  obj' <- run $ do
    s <- seal defaultPassword o
    unseal lookupPassword s
  assert (obj' == Right obj)

-- unseal and sealed object with expiration
prop_test2 :: NominalDiffTime -> Property
prop_test2 ttl = monadicIO $ do
  let opts = def { ironTTL = ttl }
  obj' <- run $ do
    Just s <- sealWith opts defaultPassword obj
    unseal lookupPassword s
  assert (obj' == Right obj)

-- unseal and sealed object with expiration and time offset
prop_test3 :: (ToJSON a, FromJSON a, Eq a) => Test1 a -> Property
prop_test3 Test1{..} = monadicIO $ do
  let testTTL = max 1 (ironTTL test1Opts)
      opts = test1Opts
             { ironLocaltimeOffset = negate (testTTL + 100)
             , ironTTL = testTTL }
  mobj' <- run $ do
    Just s <- sealWith opts test1Password test1Obj
    unseal (onePassword' test1Password) s
  assert (testTTL == 0 || isErr mobj')
  assert (testTTL /= 0 || mobj' == Right test1Obj)

isErr :: Either String a -> Bool
isErr = isLeft

-- fixme: following tests need iron api to accept pre-generated keys
-- [ ] turns object into a ticket than parses the ticket successfully (password buffer)
-- [ ] fails to turns object into a ticket (password buffer too short)

-- [X] turns object into a ticket than parses the ticket successfully (password object)
-- [X] handles separate password buffers (password object)
-- [?] handles a common password buffer (password object)

-- fails to parse a sealed object when password not found
prop_test4 :: ToJSON a => Test1 a -> Property
prop_test4 Test1{..} = monadicIO $ do
  mobj' <- run $ do
    Just s <- sealWith test1Opts defaultPassword test1Obj
    unseal (const Nothing) s :: IO (Either String Object)
  assert (mobj' == Left "Cannot find password: default")

-- ## generateKey

-- many cases are impossible because of the construction of types.

-- [/] returns an error when password is missing
-- [/] returns an error when password is too short
-- [/] returns an error when options are missing
-- [/] returns an error when an unknown algorithm is specified

-- fixme: add options error handling to getSealStuff
-- [ ] returns an error when no salt or salt bits are provided
-- [ ] returns an error when invalid salt bits are provided
-- fixme: can haskell DRG fail?
-- [ ] returns an error when Cryptiles.randomBits fails
-- fixme: PBKDF2.generate is a pure function, is it total?
-- [ ] returns an error when Crypto.pbkdf2 fails

-- ## encrypt
-- [/] returns an error when password is missing -- impossible by construction
-- ## decrypt
-- [/] returns an error when password is missing

-- ## hmacWithPassword
-- [/] returns an error when password is missing
-- [~] produces the same mac when used with buffer password

-- ## seal
-- [/] returns an error when password is missing
-- [/] returns an error when integrity options are missing

-- returns an error when password.id is invalid
testSeal01 :: Assertion
testSeal01 = passwordWithId "asd$" ("asd" :: ByteString) @?= Nothing

testSeal02 :: Assertion
-- returns an error when password is missing
testSeal02 = Just (password ("" :: ByteString)) @?= Nothing


-- ## unseal

ticket01, ticket02, ticket03, ticket04 :: ByteString
ticket01 = "Fe26.2**0cdd607945dd1dffb7da0b0bf5f1a7daa6218cbae14cac51dcbd91fb077aeb5b*aOZLCKLhCt0D5IU1qLTtYw*g0ilNDlQ3TsdFUqJCqAm9iL7Wa60H7eYcHL_5oP136TOJREkS3BzheDC1dlxz5oJ**05b8943049af490e913bbc3a2485bee2aaf7b823f4c41d0ff0b7c168371a3772*R8yscVdTBRMdsoVbdDiFmUL8zb-c3PQLGJn4Y8C-AqI"
ticket02 = "x*Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU"
ticket03 = "Fe27.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU"
ticket04 = "Fe26.2**b3ad22402ccc60fa4d527f7d1c9ff2e37e9b2e5723e9e2ffba39a489e9849609*QKCeXLs6Rp7f4LL56V7hBg*OvZEoAq_nGOpA1zae-fAtl7VNCNdhZhCqo-hWFCBeWuTTpSupJ7LxQqzSQBRAcgw**72018a21d3fac5c1608a0f9e461de0fcf17b2befe97855978c17a793faa01db1*Qj53DFE3GZd5yigt-mVl9lnp0VUoSjh5a5jgDmod1EZ"

-- unseals a ticket
testUnseal01 :: Assertion
testUnseal01 = do
  r <- unseal lookupPassword ticket01
  r @?= Right obj

-- | Asserts that unsealing a ticket fails with the given message
unsealFail :: ByteString -> String -> Assertion
unsealFail ticket msg = do
  r <- unseal lookupPassword ticket :: IO (Either String Object)
  r @?= Left msg

-- returns an error when number of sealed components is wrong
testUnseal02 :: Assertion
testUnseal02 = unsealFail ticket02 "Incorrect number of sealed components"

-- [/] returns an error when password is missing

-- returns an error when mac prefix is wrong
testUnseal03 :: Assertion
testUnseal03 = unsealFail ticket03 "Wrong mac prefix"

-- returns an error when integrity check fails
testUnseal04 :: Assertion
testUnseal04 = unsealFail ticket04 "Bad hmac value"

-- returns an error when decryption fails
testUnseal05 :: Assertion
testUnseal05 = unsealFail ticket "base64: input: invalid encoding at offset: 64"
  where ticket = "Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M??**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*n04AwdA-1wOnGusZJVjoZC9sbAPfBRCnd4iVyX2yM2Y"

-- returns an error when iv base64 decoding fails
testUnseal06 :: Assertion
testUnseal06 = unsealFail ticket "base64: input: invalid encoding at offset: 22"
  where ticket = "Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw??*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*iF6pSFeSD8iYRlYIfD6VRwADFjFR3fX6hM_kIjN3_ew"

-- returns an error when decrypted object is invalid
testUnseal07 :: Assertion
testUnseal07 = unsealFail ticket "Error in $: Failed reading: satisfy"
  where ticket = "Fe26.2**2e7f52699752d2e9325097a1ddbb6e39b22f21a9e354989a681e004445cec66b*aRq0dy_f-_jWIisjiugZKw*byjIKZvNBwaCd2epZ9CIdw**19f2010b44cd3736b3acaf81181a453830778ebdc9c418f91dfd1812eb761730*5_b7lBEkLLQJ6awNQ75Q3QHbPP89kCPfdYqP43Eylss"

-- returns an error when expired
testUnseal08 = unsealFail ticket "Expired seal"
  where ticket = "Fe26.2**a38dc7a7bf2f8ff650b103d8c669d76ad219527fbfff3d98e3b30bbecbe9bd3b*nTsatb7AQE1t0uMXDx-2aw*uIO5bRFTwEBlPC1Nd_hfSkZfqxkxuY1EO2Be_jJPNQCqFNumRBjQAl8WIKBW1beF*1380495854060*e4fe33b6dc4c7ef5ad7907f015deb7b03723b03a54764aceeb2ab1235cc8dce3*yE0dHH22wy4N9z_djofZNhja9l7rDLuq6H24HBswSp0"

-- returns an error when expiration NaN
testUnseal09 = unsealFail ticket "Invalid expiration"
  where ticket = "Fe26.2**a38dc7a7bf2f8ff650b103d8c669d76ad219527fbfff3d98e3b30bbecbe9bd3b*nTsatb7AQE1t0uMXDx-2aw*uIO5bRFTwEBlPC1Nd_hfSkZfqxkxuY1EO2Be_jJPNQCqFNumRBjQAl8WIKBW1beF*a*e4fe33b6dc4c7ef5ad7907f015deb7b03723b03a54764aceeb2ab1235cc8dce3*yTXLwJ3XDHC0gRNR3J5xxIvkHovPZEa5auw6voFT6b8"
