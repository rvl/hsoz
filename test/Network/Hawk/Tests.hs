{-# LANGUAGE RecordWildCards #-}

module Network.Hawk.Tests (tests) where

import Data.Either (isRight)
import Data.Maybe (isJust)
import Data.Default
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import Network.Wai (Request(..), defaultRequest)
import Network.HTTP.Client (Response(..))
import Network.HTTP.Client.Internal (Response(..))
import Network.HTTP.Types (Method, RequestHeaders)
import Network.HTTP.Types.Status (ok200)
import Data.Text.Encoding (decodeUtf8)
import Data.Time.Clock.POSIX     (POSIXTime, getPOSIXTime)

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)
import Test.HUnit (Assertion, (@?=), (@?))
import Test.Tasty.QuickCheck (testProperty)
import Test.QuickCheck

import Network.Hawk
import Network.Hawk.Server.Types (HawkReq(..), AuthSuccess(..))
import qualified Network.Hawk.Client as Client
import qualified Network.Hawk.Server as Server
import qualified Network.Hawk.Types (HeaderArtifacts(..))
import qualified Network.Hawk.Server.Nonce as Server

tests :: TestTree
tests = testGroup "Network.Hawk"
        [ testGroup "Client+Server"
          [ test01
          , test02
          , test03
          , test04
          --, testCase "generates a header then successfully parse it (no server header options)" boring
          --, testCase "generates a header then successfully parse it (with hash)" duplicate
          , test05
          , test06
          , test07
          , test08
          --, testCase "generates a header then fail authentication due to bad hash" duplicate
          , test09
          ]
        , testGroup "header" [ testHeader01 ]
        , testGroup "Server"
          [ testGroup "authenticate()"
            [ testServerAuth01
            , testServerAuth02
            , testServerAuth05
            , testServerAuth06
            , testServerAuth07
            , testServerAuth08
            ]
          ]
        ]

makeCreds :: Client.ClientId -> (Client.Credentials, Server.CredentialsFunc IO String, String)
makeCreds i = (cc, \i -> return sc, user)
  where
    cc = Client.Credentials i key algo
    sc = Right (Server.Credentials key algo, user)
    key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
    algo = if i == "1" then HawkAlgo SHA1 else HawkAlgo SHA256
    user = "steve"

test01 = testCase "generates a header then successfully parses it" $ do
  let (creds, credsFunc, user) = makeCreds "123456"
      ext = Just "some-app-data"
  hdr <- Client.header "http://example.com:8080/resource/4?filter=a" "GET" creds Nothing 0 ext
  let hrq = def
            { hrqUrl = "/resource/4?filter=a"
            , hrqHost = "example.com"
            , hrqPort = Just 8080
            , hrqAuthorization = Client.hdrField hdr
            }
  r <- Server.authenticate def credsFunc hrq
  isRight r @?= True
  let Right (Server.AuthSuccess creds' arts user) = r
  user @?= "steve"
  Server.haExt arts @?= Just "some-app-data"

test02 = testCase "generates a header then successfully parses it (WAI request)" $ do
  -- Generate client header
  let (creds, credsFunc, user) = makeCreds "123456"
      ext = Just "some-app-data"
      payload = PayloadInfo "text/plain;x=y" "some not so random text"
  hdr <- Client.header "http://example.com:8080/resource/4?filter=a" "POST" creds (Just payload) 0 ext

  -- Server verifies client request
  let req = mockRequest "POST" "/resource/4" "?filter=a" "example.com:8080" payload [("authorization", Client.hdrField hdr)]

  r <- Server.authenticateRequest def credsFunc req (Just (payloadData payload))
  isRight r @? "Expected auth success, got: " ++ show r
  let Right s@(Server.AuthSuccess creds2 arts user) = r
  user @?= "steve"
  Server.haExt arts @?= Just "some-app-data"
  Server.authenticatePayload s payload @?= Right ()

  -- Client verifies server response
  let payload2 = PayloadInfo "text/plain" "Some reply"
      (_, hdr2) = Server.header r (Just payload2)
      res = mockResponse payload2 [hdr2]
      creds2' = clientCreds "" creds2
      arts' = arts
  r2 <- Client.authenticate res creds2' arts' (Just (payloadData payload2)) Client.ServerAuthorizationRequired
  r2 @?= Right ()

clientCreds :: ClientId -> Server.Credentials -> Client.Credentials
clientCreds i (Server.Credentials k a) = Client.Credentials i k a

mockRequest :: Method -> ByteString -> ByteString -> ByteString -> PayloadInfo -> RequestHeaders -> Request
mockRequest method path qs host (PayloadInfo ct _) hdrs = defaultRequest
  { requestMethod = method
  , rawPathInfo = path
  , rawQueryString = qs
  , requestHeaderHost = Just host
  , requestHeaders = [("host", host), ("content-type", ct)] ++ hdrs
  }

mockResponse :: PayloadInfo -> RequestHeaders -> Response BL.ByteString
mockResponse (PayloadInfo ct d) hdrs = Response
        { responseStatus = ok200
        , responseHeaders = hdrs ++ [("content-type", ct)]
        , responseBody = d
        , responseVersion = undefined
        , responseCookieJar = undefined
        , responseClose' = undefined
        }

test03 = testCase "generates a header then successfully parses it (absolute request uri)" $ do
  let (creds, credsFunc, user) = makeCreds "123456"
      ext = Just "some-app-data"
      payload = PayloadInfo "text/plain;x=y" "some not so random text"
  hdr <- Client.header "http://example.com:8080/resource/4?filter=a" "POST" creds (Just payload) 0 ext
  let hrq = def
            { hrqMethod = "POST"
            , hrqUrl = "/resource/4?filter=a" -- fixme: not absolute
            , hrqHost = "example.com"
            , hrqPort = Just 8080
            , hrqAuthorization = Client.hdrField hdr
            , hrqPayload = Nothing
            }
  r <- Server.authenticate def credsFunc hrq
  isRight r @? "Expected auth success, got: " ++ show r
  let Right s@(Server.AuthSuccess creds2 arts user) = r
  user @?= "steve"
  Server.haExt arts @?= Just "some-app-data"
  Server.authenticatePayload s payload @?= Right ()

  let payload2 = PayloadInfo "text/plain" "some reply"
      fixmeExt2 = "response-specific"
      (_, hdr) = Server.header r (Just payload2)
      res = mockResponse payload2 [hdr]
      creds2' = clientCreds "" creds2
      arts' = arts

  r2 <- Client.authenticate res creds2' arts' (Just (payloadData payload2)) Client.ServerAuthorizationRequired
  r2 @?= Right ()


test04 = testCase "generates a header then fails to parse it (missing server header hash)" $ do
  let (creds, credsFunc, user) = makeCreds "123456"
      ext = Just "some-app-data"
      payload = PayloadInfo "text/plain;x=y" "some not so random text"
  hdr <- Client.header "http://example.com:8080/resource/4?filter=a" "POST" creds (Just payload) 0 ext
  let hrq = def
            { hrqMethod = "POST"
            , hrqUrl = "/resource/4?filter=a" -- fixme: not absolute
            , hrqHost = "example.com"
            , hrqPort = Just 8080
            , hrqAuthorization = Client.hdrField hdr
            , hrqPayload = Nothing
            }
  r <- Server.authenticate def credsFunc hrq
  isRight r @? "Expected auth success, got: " ++ show r
  let Right s@(Server.AuthSuccess creds2 arts user) = r
  user @?= "steve"
  Server.haExt arts @?= Just "some-app-data"
  Server.authenticatePayload s payload @?= Right ()

  let payload2 = PayloadInfo "text/plain" "some reply"
      fixmeExt2 = "response-specific"
      (_, hdr) = Server.header r Nothing
      res = mockResponse payload2 [hdr]
      creds2' = clientCreds "" creds2
      arts' = arts

  r2 <- Client.authenticate res creds2' arts' (Just (payloadData payload2)) Client.ServerAuthorizationRequired
  r2 @?= Left "Missing response hash attribute"

test05 = testCase "generates a header then successfully parse it then validate payload" $ do
  let (creds, credsFunc, user) = makeCreds "123456"
      ext = Just "some-app-data"
      -- fixme: js impl seems to have a default content-type
      payload = PayloadInfo "text/plain" "hola!"
      payload2 = PayloadInfo "text/html" "hola!"
      payload3 = PayloadInfo "text/plain" "hello!"
  hdr <- Client.header "http://example.com:8080/resource/4?filter=a" "GET" creds (Just payload) 0 ext
  let hrq = def
            { hrqUrl = "/resource/4?filter=a"
            , hrqHost = "example.com"
            , hrqPort = Just 8080
            , hrqAuthorization = Client.hdrField hdr
            }

  -- authenticate request
  r <- Server.authenticate def credsFunc hrq
  isRight r @?= True
  let Right s@(Server.AuthSuccess creds' arts user) = r
  user @?= "steve"
  Server.haExt arts @?= Just "some-app-data"

  -- authenticate payload
  Server.authenticatePayload s payload @?= Right ()
  Server.authenticatePayload s payload2 @?= Left "Bad response payload mac"
  Server.authenticatePayload s payload3 @?= Left "Bad response payload mac"

test06 = testCase "generates a header then successfully parses and validates payload" $ do
  let (creds, credsFunc, user) = makeCreds "123456"
      ext = Just "some-app-data"
      -- js impl has empty string as default content-type
      payload = PayloadInfo "" "hola!"
      payload2 = PayloadInfo "text/plain" "hola!"
      payload3 = PayloadInfo "" "hello!"
  hdr <- Client.header "http://example.com:8080/resource/4?filter=a" "GET" creds (Just payload) 0 ext
  let hrq = def
            { hrqUrl = "/resource/4?filter=a"
            , hrqHost = "example.com"
            , hrqPort = Just 8080
            , hrqAuthorization = Client.hdrField hdr
            , hrqPayload = Just payload
            }
      hrq2 = hrq { hrqPayload = Just payload2 }
      hrq3 = hrq { hrqPayload = Just payload3 }

  -- authenticate request
  r <- Server.authenticate def credsFunc hrq
  isRight r @?= True
  let Right s@(Server.AuthSuccess creds' arts user) = r
  user @?= "steve"
  Server.haExt arts @?= Just "some-app-data"

  r2 <- Server.authenticate def credsFunc hrq2
  r2 @?= Left (Server.AuthFailUnauthorized "Bad response payload mac" (Just creds') (Just arts))

  r3 <- Server.authenticate def credsFunc hrq3
  r3 @?= Left (Server.AuthFailUnauthorized "Bad response payload mac" (Just creds') (Just arts))

test07 = testCase "generates a header then successfully parse it (app)" $ do
  let (creds, credsFunc, user) = makeCreds "123456"
      ext = Just "some-app-data"
      app = "asd23ased"
  hdr <- Client.headerOz "http://example.com:8080/resource/4?filter=a" "GET"
    creds Nothing 0 ext app Nothing
  let hrq = def
            { hrqUrl = "/resource/4?filter=a"
            , hrqHost = "example.com"
            , hrqPort = Just 8080
            , hrqAuthorization = Client.hdrField hdr
            }

  -- authenticate request
  r <- Server.authenticate def credsFunc hrq
  isRight r @?= True
  let Right s@(Server.AuthSuccess creds' arts user) = r
  user @?= user
  Server.haExt arts @?= Just "some-app-data"
  Server.haApp arts @?= Just app
  Server.haDlg arts @?= Nothing

test08 = testCase "generates a header then successfully parse it (app, dlg)" $ do
  let (creds, credsFunc, user) = makeCreds "123456"
      ext = Just "some-app-data"
      app = "asd23ased"
      dlg = "23434szr3q4d"
  hdr <- Client.headerOz "http://example.com:8080/resource/4?filter=a" "GET"
    creds Nothing 0 ext app (Just dlg)
  let hrq = def
            { hrqUrl = "/resource/4?filter=a"
            , hrqHost = "example.com"
            , hrqPort = Just 8080
            , hrqAuthorization = Client.hdrField hdr
            }

  -- authenticate request
  r <- Server.authenticate def credsFunc hrq
  isRight r @?= True
  let Right s@(Server.AuthSuccess creds' arts user) = r
  user @?= user
  Server.haExt arts @?= Just "some-app-data"
  Server.haApp arts @?= Just app
  Server.haDlg arts @?= Just "23434szr3q4d"

test09 = testCase "generates a header for one resource then fail to authenticate another" $ do
  let (creds, credsFunc, user) = makeCreds "123456"
      ext = Just "some-app-data"
  hdr <- Client.header "http://example.com:8080/resource/4?filter=a" "GET" creds Nothing 0 ext
  let hrq = def
            { hrqUrl = "/something/else"
            , hrqHost = "example.com"
            , hrqPort = Just 8080
            , hrqAuthorization = Client.hdrField hdr
            }

  -- authenticate request
  r <- Server.authenticate def credsFunc hrq
  let Left f@(Server.AuthFailUnauthorized e creds arts) = r
  e @?= "Bad mac"
  isJust creds @?= True
  --arts @?= Nothing

missing, boring :: Assertion
missing = return ()
boring = return ()

testHeader01 = testCase "returns a valid authorization header (sha1)" $ do
  return ()

testUrl01 = "/resource/4?filter=a"
testUrl02 = "/resource/1?b=1&a=2"

testReq01 = def { hrqUrl = testUrl01
                , hrqHost = "example.com"
                , hrqPort = Just 8080
                , hrqAuthorization = ""
                }
testReq02 = def { hrqUrl = testUrl02
                , hrqHost = "example.com"
                , hrqPort = Just 8000
                , hrqAuthorization = ""
                }

testAuth auth ts hrq = do
  now <- getPOSIXTime
  opts <- testNonceOpts ts now
  testAuth' auth ts hrq now opts

testNonceOpts ts now = Server.nonceOpts (now - ts + 60)

testAuth' auth ts hrq now opts = do
  let opts' = opts { Server.saLocaltimeOffset = ts - now }
      hrq' = hrq { hrqAuthorization = auth }
  Server.authenticate opts' testCredsFunc hrq'

testCredsFunc i = f i
  where (_, f, _) = makeCreds i

checkAuthSuccess (Left f) = show f @?= "some success"
checkAuthSuccess (Right (AuthSuccess c a t)) = t @?= "steve"

checkAuthFail (Left f) msg = Server.authFailMessage f @?= msg
checkAuthFail (Right _) _ = "success" @?= "failure"


-- authenticate
testServerAuth01 = testCase "parses a valid authentication header (sha1)" $ do
  res <- testAuth "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\"" 1353788437 testReq01
  checkAuthSuccess res

testServerAuth02 = testCase "parses a valid authentication header (sha256)" $ do
  res <- testAuth "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\"" 1353832234 testReq02
  checkAuthSuccess res

-- These two are really just testing the hawkReq function.
-- testServerAuth03 = testCase "parses a valid authentication header (host override)"
-- testServerAuth04 = testCase "parses a valid authentication header (host port override)"

testServerAuth05 = testCase "parses a valid authentication header (POST with payload)" $ do
  let hrq = testReq01 { hrqMethod = "POST" }
  res <- testAuth "Hawk id=\"123456\", ts=\"1357926341\", nonce=\"1AwuJD\", hash=\"qAiXIVv+yjDATneWxZP2YCTa9aHRgQdnH9b3Wc+o3dg=\", ext=\"some-app-data\", mac=\"UeYcj5UoTVaAWXNvJfLVia7kU3VabxCqrccXP8sUGC4=\"" 1357926341 hrq
  checkAuthSuccess res


testServerAuth06 = testCase "errors on missing hash" $ do
  let hrq = testReq02 { hrqPayload = Just (PayloadInfo "" "body") }
  res <- testAuth "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\"" 1353832234 hrq
  -- js impl says "Missing required payload hash"
  checkAuthFail res "Missing response hash attribute"

testServerAuth07 = testCase "errors on a stale timestamp" $ do
  now <- getPOSIXTime
  res <- testAuth' "Hawk id=\"123456\", ts=\"1362337299\", nonce=\"UzmxSs\", ext=\"some-app-data\", mac=\"wnNUxchvvryMH2RxckTdZ/gY3ijzvccx4keVvELC61w=\"" now testReq01 now def
  checkAuthFail res "Expired seal" -- js impl says "Stale timestamp"

{-
-- fixme: allow testing of internal modules
testWWWAuthenticate = testProperty "timeStampMessage . parseWwwAuthenticateHeader == id"
  prop_parseWWWAuthenticate

prop_parseWWWAuthenticate :: (POSIXTime, String) -> Property
prop_parseWWWAuthenticate (ts, error) = (check <$> wh) == Right True
  where
    check Client.WwwAuthenticateHeader{..} = wahTs == ts &&
                                             wahError error &&
                                             wahTsm /= "" &&
                                             cc = Right ts
    creds = testCredsFunc "asdf"
    h = Server.timeStampMessage error ts creds
    wh = Client.parseWwwAuthenticateHeader h
    cc = Client.checkWwwAuthenticateHeader creds h
-}

testServerAuth08 = testCase "errors on a replay" $ do
  let auth = "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=\", ext=\"hello\""
      ts = 1353788437
  now <- getPOSIXTime
  opts <- testNonceOpts ts now
  res1 <- testAuth' auth ts testReq01 now opts
  checkAuthSuccess res1
  res2 <- testAuth' auth ts testReq01 now opts
  checkAuthFail res2 "Invalid nonce"

{-
testServerAuth09 = testCase "does not error on nonce collision if keys differ"
testServerAuth10 = testCase "errors on an invalid authentication header: wrong scheme"
testServerAuth11 = testCase "errors on an invalid authentication header: no scheme"
testServerAuth12 = testCase "errors on an missing authorization header"
testServerAuth13 = testCase "errors on an missing host header"
testServerAuth14 = testCase "errors on an missing authorization attribute (id)"
testServerAuth15 = testCase "errors on an missing authorization attribute (ts)"
testServerAuth16 = testCase "errors on an missing authorization attribute (nonce)"
testServerAuth17 = testCase "errors on an missing authorization attribute (mac)"
testServerAuth18 = testCase "errors on an unknown authorization attribute"
testServerAuth19 = testCase "errors on an bad authorization header format"
testServerAuth20 = testCase "errors on an bad authorization attribute value"
testServerAuth21 = testCase "errors on an empty authorization attribute value"
testServerAuth22 = testCase "errors on duplicated authorization attribute key"
testServerAuth23 = testCase "errors on an invalid authorization header format"
testServerAuth24 = testCase "errors on an bad host header (missing host)"
testServerAuth25 = testCase "errors on an bad host header (pad port)"
testServerAuth26 = testCase "errors on credentialsFunc error"
testServerAuth27 = testCase "errors on credentialsFunc error (with credentials)"
testServerAuth28 = testCase "errors on missing credentials"
testServerAuth29 = testCase "errors on invalid credentials (id)"
testServerAuth30 = testCase "errors on invalid credentials (key)"
testServerAuth31 = testCase "errors on unknown credentials algorithm"
testServerAuth32 = testCase "errors on unknown bad mac"

-- header()
testServerHeader01 = testCase "generates header"
testServerHeader02 = testCase "generates header (empty payload)"
testServerHeader03 = testCase "generates header (pre calculated hash)"
testServerHeader04 = testCase "generates header (null ext)"
testServerHeader05 = testCase "errors on missing artifacts"
testServerHeader06 = testCase "errors on invalid artifacts"
testServerHeader07 = testCase "errors on missing credentials"
testServerHeader08 = testCase "errors on invalid credentials (key)"
testServerHeader09 = testCase "errors on invalid algorithm"

-- authenticateBewit()

testServerBewit01 = testCase "errors on uri too long"
-}

{-
-- message
testServerMessage01 = testCase "errors on invalid authorization (ts)"
testServerMessage01 = testCase "errors on invalid authorization (nonce)"
testServerMessage01 = testCase "errors on invalid authorization (hash)"
testServerMessage01 = testCase "errors with credentials"
testServerMessage01 = testCase "errors on nonce collision"
testServerMessage01 = testCase "should generate an authorization then successfully parse it"
testServerMessage01 = testCase "should fail authorization on mismatching host"
testServerMessage01 = testCase "should fail authorization on stale timestamp"
testServerMessage01 = testCase "overrides timestampSkewSec"
testServerMessage01 = testCase "should fail authorization on invalid authorization"
testServerMessage01 = testCase "should fail authorization on bad hash"
testServerMessage01 = testCase "should fail authorization on nonce error"
testServerMessage01 = testCase "should fail authorization on credentials error"
testServerMessage01 = testCase "should fail authorization on missing credentials"
testServerMessage01 = testCase "should fail authorization on invalid credentials"
testServerMessage01 = testCase "should fail authorization on invalid credentials algorithm"
testServerMessage01 = testCase "should fail on missing host"
testServerMessage01 = testCase "should fail on missing credentials"
testServerMessage01 = testCase "should fail on invalid algorithm"
-}
