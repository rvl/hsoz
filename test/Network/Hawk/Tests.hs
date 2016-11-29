module Network.Hawk.Tests (tests) where

import Data.Either (isRight)
import Data.Default

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)
import Test.HUnit (Assertion, (@?=), (@?))

import Network.Hawk
import Network.Hawk.Server.Types (HawkReq(..), AuthSuccess(..))
import qualified Network.Hawk.Client as Client
import qualified Network.Hawk.Server as Server

tests :: TestTree
tests = testGroup "Network.Hawk"
        [ testCase "generates a header then successfully parses it" test01
        , testCase "generates a header then successfully parse it (WAI request)" test02
        , testCase "generates a header then successfully parse it (absolute request uri)" test03
        ]

makeCreds :: Client.ClientId -> (Client.Credentials, Server.CredentialsFunc IO String)
makeCreds i = (cc, \i -> return sc)
  where
    cc = Client.Credentials i key algo
    sc = Right (Server.Credentials key algo, user)
    key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
    algo = if i == "1" then HawkAlgo SHA1 else HawkAlgo SHA256
    user = "steve"

test01 :: Assertion
test01 = do
  let (creds, credsFunc) = makeCreds "123456"
      ext = Just "some-app-data"
  hdr <- Client.header "http://example.com:8080/resource/4?filter=a" "GET" creds Nothing ext
  let hrq = def
            { hrqUrl = "/resource/4?filter=a"
            , hrqHost = "example.com"
            , hrqPort = Just 8080
            , hrqAuthorization = Client.hdrField hdr
            }
  res <- Server.authenticate def credsFunc hrq
  isRight res @?= True
  let Right (Server.AuthSuccess creds' arts user) = res
  user @?= "steve"
  Server.shaExt arts @?= Just "some-app-data"

-- generates a header then successfully parse it (WAI request)
-- fixme: need to setup 'Network.WAI.Request'
test02 :: Assertion
test02 = return ()

-- generates a header then successfully parse it (absolute request uri)
test03 :: Assertion
test03 = do
  let (creds, credsFunc) = makeCreds "123456"
      ext = Just "some-app-data"
      payload = PayloadInfo "text/plain;x=y" "some not so random text"
  hdr <- Client.header "http://example.com:8080/resource/4?filter=a" "POST" creds (Just payload) ext
  let hrq = def
            { hrqMethod = "POST"
            , hrqUrl = "/resource/4?filter=a" -- fixme: not absolute
            , hrqHost = "example.com"
            , hrqPort = Just 8080
            , hrqAuthorization = Client.hdrField hdr
            , hrqPayload = Nothing
            }
  res <- Server.authenticate def credsFunc hrq
  isRight res @? "Expected auth success, got: " ++ show res
  let Right s@(Server.AuthSuccess creds' arts user) = res
  user @?= "steve"
  Server.shaExt arts @?= Just "some-app-data"
  Server.authenticatePayload s payload @?= Right ()
