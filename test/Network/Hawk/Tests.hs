{-# LANGUAGE RecordWildCards #-}

module Network.Hawk.Tests (tests) where

import Data.Either (isRight)
import Data.Maybe (isJust)
import Data.Default
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import Network.Wai (Request(..), defaultRequest)
import Network.HTTP.Client (Response(..))
import Network.HTTP.Client.Internal (Response(..))
import Network.HTTP.Types (Method, RequestHeaders)
import Network.HTTP.Types.Status (ok200)
import Data.Text.Encoding (decodeUtf8)
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import Data.Time.Clock (NominalDiffTime)

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)
import Test.HUnit (Assertion, (@?=), (@?))
import Test.Tasty.QuickCheck (testProperty)
import Test.QuickCheck
import Test.QuickCheck.Monadic

import Network.Hawk
import Network.Hawk.Internal.Server.Types (HawkReq(..), AuthSuccess(..))
import Network.Hawk.Internal.Server.Header (timestampMessage)
import Network.Hawk.Internal (calculatePayloadHash)
import qualified Network.Hawk.Client as Client
import qualified Network.Hawk.Client.HeaderParser as Client
import qualified Network.Hawk.Server as Server
import qualified Network.Hawk.Types as Hawk (HeaderArtifacts(..))
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
          , testWWWAuthenticate
          ]
        , testGroup "Server"
          [ testGroup "authenticate"
            [ testServerAuth01
            , testServerAuth02
            , testServerAuth05
            , testServerAuth06
            , testServerAuth07
            , testServerAuth08
            , testServerAuth09
            , testServerAuth10
            , testServerAuth11
            , testServerAuth12
            , testServerAuth13
            , testServerAuth14
            , testServerAuth15
            , testServerAuth16
            , testServerAuth17
            , testServerAuth18
            , testServerAuth19
            -- , testServerAuth20
            -- , testServerAuth21
            -- , testServerAuth22
            -- , testServerAuth23
            , testServerAuth26
            -- , testServerAuth30
            , testServerAuth32
            ]
          , testGroup "header"
            [ testServerHeader01
            , testServerHeader02
            , testServerHeader04
            , testServerHeader08
            ]
          , testGroup "authenticateBewit"
            [ testServerBewit01
            ]
          , testGroup "message"
            [ testMessages
            , testServerMessage04
            , testServerMessage05
            ]
          ]
        , testGroup "Client"
          [ testGroup "header"
            [ testClientHeader01
            , testClientHeader02
            , testClientHeader03
            , testClientHeader05
            , testClientHeader06
            --, testClientHeader07
            --, testClientHeader09
            ]
          , testGroup "authenticate" []
          , testGroup "message" []
          ]
        ]

makeCreds :: Client.ClientId -> (Client.Credentials, Server.CredentialsFunc IO String, String)
makeCreds i = (cc, \i -> return sc, user)
  where
    sc@(Right (Server.Credentials key algo, user)) = testCreds i
    cc = Client.Credentials i key algo

testCredsFunc = return . testCreds
testCreds "456"          = credsBob
testCreds "doesnotexist" = Left "Unknown user"
testCreds "999"          = credsFred
testCreds "1"            = credsSteve' (HawkAlgo SHA1)
testCreds _              = credsSteve' (HawkAlgo SHA256)

credsSteve = credsSteve' (HawkAlgo SHA256)
credsSteve' algo = Right (Server.Credentials key algo, "steve")
  where key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
credsBob = Right (Server.Credentials altKey (HawkAlgo SHA256), "bob")
  where altKey = "xrunpaw3489ruxnpa98w4rxnwerxhqb98rpaxn39848"
credsFred = Right (Server.Credentials "hi" (HawkAlgo SHA256), "fred")



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
  Hawk.haExt arts @?= Just "some-app-data"

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
  Hawk.haExt arts @?= Just "some-app-data"
  Server.authenticatePayload s payload @?= Right ()

  -- Client verifies server response
  let payload2 = PayloadInfo "text/plain" "Some reply"
      (_, hdr2) = Server.header r (Just payload2)
      res = mockResponse payload2 [hdr2]
      creds2' = clientCreds "" creds2
      arts' = arts { haHash = Just $ calculatePayloadHash (Client.ccAlgorithm creds) payload2 }
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
  let Right s@(Server.AuthSuccess creds2 arts user') = r
  user' @?= "steve"
  Hawk.haExt arts @?= Just "some-app-data"
  Server.authenticatePayload s payload @?= Right ()

  let payload2 = PayloadInfo "text/plain" "some reply"
      fixmeExt2 = "response-specific"
      (_, hdr) = Server.header r (Just payload2)
      res = mockResponse payload2 [hdr]
      creds2' = clientCreds "" creds2
      arts' = arts { haHash = Just $ calculatePayloadHash (Client.ccAlgorithm creds) payload2 }

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
  let Right s@(Server.AuthSuccess creds2 arts user') = r
  user' @?= "steve"
  Hawk.haExt arts @?= Just "some-app-data"
  Server.authenticatePayload s payload @?= Right ()

  let payload2 = PayloadInfo "text/plain" "some reply"
      fixmeExt2 = "response-specific"
      (_, hdr) = Server.header r Nothing
      res = mockResponse payload2 [hdr]
      creds2' = clientCreds "" creds2
      arts2 = arts { haHash = Nothing }

  r2 <- Client.authenticate res creds2' arts2 (Just (payloadData payload2)) Client.ServerAuthorizationRequired
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
  Hawk.haExt arts @?= Just "some-app-data"

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
  Hawk.haExt arts @?= Just "some-app-data"

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
  Hawk.haExt arts @?= Just "some-app-data"
  Hawk.haApp arts @?= Just app
  Hawk.haDlg arts @?= Nothing

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
  Hawk.haExt arts @?= Just "some-app-data"
  Hawk.haApp arts @?= Just app
  Hawk.haDlg arts @?= Just "23434szr3q4d"

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

testReq1 = def { hrqUrl = "/resource/1?b=1&a=2"
               , hrqHost = "example.com"
               , hrqPort = Just 8000
               , hrqAuthorization = ""
               }

testReq4 = def { hrqUrl = "/resource/4?filter=a"
               , hrqHost = "example.com"
               , hrqPort = Just 8080
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

checkAuthSuccess = checkAuthSuccessUser "steve"
checkAuthSuccessUser _    (Left f) = show f @?= "some success"
checkAuthSuccessUser user (Right (AuthSuccess c a t)) = t @?= user

checkAuthFail msg (Left f)  = Server.authFailMessage f @?= msg
checkAuthFail _   (Right _) = "success" @?= "failure"


-- authenticate
testServerAuth01 = testCase "parses a valid authentication header (sha1)" $ do
  res <- testAuth "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\"" 1353788437 testReq4
  checkAuthSuccess res

testServerAuth02 = testCase "parses a valid authentication header (sha256)" $ do
  res <- testAuth "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\"" 1353832234 testReq1
  checkAuthSuccess res

-- These two are really just testing the hawkReq function.
-- testServerAuth03 = testCase "parses a valid authentication header (host override)"
-- testServerAuth04 = testCase "parses a valid authentication header (host port override)"

testServerAuth05 = testCase "parses a valid authentication header (POST with payload)" $ do
  let hrq = testReq4 { hrqMethod = "POST" }
  res <- testAuth "Hawk id=\"123456\", ts=\"1357926341\", nonce=\"1AwuJD\", hash=\"qAiXIVv+yjDATneWxZP2YCTa9aHRgQdnH9b3Wc+o3dg=\", ext=\"some-app-data\", mac=\"UeYcj5UoTVaAWXNvJfLVia7kU3VabxCqrccXP8sUGC4=\"" 1357926341 hrq
  checkAuthSuccess res


testServerAuth06 = testCase "errors on missing hash" $ do
  let hrq = testReq1 { hrqPayload = Just (PayloadInfo "" "body") }
  res <- testAuth "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\"" 1353832234 hrq
  -- js impl says "Missing required payload hash"
  checkAuthFail "Missing response hash attribute" res

testServerAuth07 = testCase "errors on a stale timestamp" $ do
  now <- getPOSIXTime
  res <- testAuth' "Hawk id=\"123456\", ts=\"1362337299\", nonce=\"UzmxSs\", ext=\"some-app-data\", mac=\"wnNUxchvvryMH2RxckTdZ/gY3ijzvccx4keVvELC61w=\"" now testReq4 now def
  checkAuthFail "Expired seal" res -- js impl says "Stale timestamp"

testWWWAuthenticate = testProperty "timeStampMessage . parseWwwAuthenticateHeader == id"
  prop_parseWWWAuthenticate

instance Arbitrary NominalDiffTime where
  arbitrary = do
    n <- choose (-3600 * 24, 3600 * 24) :: Gen Double
    return $ 1481062437 + realToFrac n

prop_parseWWWAuthenticate :: (POSIXTime, String) -> Property
prop_parseWWWAuthenticate (ts, error) = isNice error ==>
                                        either (const $ property False) check wh
  where
    check Client.WwwAuthenticateHeader{..} = floor wahTs == floor ts .&&.
                                             wahError == (S8.pack error) .&&.
                                             wahTsm /= ""
    algo = HawkAlgo SHA256
    key = "key"
    cc = Client.Credentials "1" key algo
    sc = Server.Credentials key algo
    h = timestampMessage error ts sc
    wh = Client.parseWwwAuthenticateHeader h
    --ck = Client.checkWwwAuthenticateHeader cc h
    -- fixme: need to handle quote characters?
    isNice s = notElem '"' s && notElem '\\' s

testServerAuth08 = testCase "errors on a replay" $ do
  let auth = "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=\", ext=\"hello\""
      ts = 1353788437
  now <- getPOSIXTime
  opts <- testNonceOpts ts now
  res1 <- testAuth' auth ts testReq4 now opts
  checkAuthSuccess res1
  res2 <- testAuth' auth ts testReq4 now opts
  checkAuthFail "Invalid nonce" res2

testServerAuth09 = testCase "does not error on nonce collision if keys differ" $ do
  let auth1 = "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=\", ext=\"hello\""
      auth2 = "Hawk id=\"456\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"LXfmTnRzrLd9TD7yfH+4se46Bx6AHyhpM94hLCiNia4=\", ext=\"hello\""
      ts = 1353788437
  now <- getPOSIXTime
  opts <- testNonceOpts ts now
  res1 <- testAuth' auth1 ts testReq4 now opts
  checkAuthSuccess res1
  res2 <- testAuth' auth2 ts testReq4 now opts
  checkAuthSuccessUser "bob" res2

testServerAuth10 = testCase "errors on an invalid authentication header: wrong scheme" $ do
  res <- testAuth "Basic asdasdasdasd" 1353788437 testReq4
  checkAuthFail "string" res -- fixme: not a good error message

testServerAuth11 = testCase "errors on an invalid authentication header: no scheme" $ do
  res <- testAuth "!@#" 1353788437 testReq4
  checkAuthFail "string" res -- fixme: "Invalid header syntax"

testServerAuth12 = testCase "errors on an missing authorization header" $ do
  res <- testAuth "" 1353788437 testReq4
  checkAuthFail "not enough input" res -- fixme: need better error message

-- fixme
testServerAuth13 = testCase "errors on an missing host header" (return ())

missingAttrTest attr auth = testAuth auth 1353788437 testReq4 >>= checkAuthFail msg
  -- js impl is just "Missing attributes"
  where msg = "Failed reading: Missing \"" ++ attr ++ "\" attribute"

testServerAuth14 = testCase "errors on an missing authorization attribute (id)" $
                   missingAttrTest "id" "Hawk ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""

testServerAuth15 = testCase "errors on an missing authorization attribute (ts)" $
                   missingAttrTest "ts" "Hawk id=\"123\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""

testServerAuth16 = testCase "errors on an missing authorization attribute (nonce)" $
                   missingAttrTest "nonce" "Hawk id=\"123\", ts=\"1353788437\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""
testServerAuth17 = testCase "errors on an missing authorization attribute (mac)" $
                   missingAttrTest "mac" "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", ext=\"hello\""

testServerAuth18 = testCase "errors on an unknown authorization attribute" $ do
  let msg = "endOfInput" -- fixme: "Unknown attribute: x"
      auth = "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", x=\"3\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""
  testAuth auth 1353788437 testReq4 >>= checkAuthFail msg

testServerAuth19 = testCase "errors on an bad authorization header format" $ do
  let msg = "endOfInput" -- fixme: "Bad header format"
      auth = "Hawk id=\"123\\\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""
  res <- testAuth auth 1353788437 testReq4
  checkAuthFail msg res

testServerAuth20 = testCase "errors on an bad authorization attribute value" $ do
  res <- testAuth "Hawk id=\"\t\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\"" 1353788437 testReq4
  checkAuthFail "Bad attribute value: id" res

testServerAuth21 = testCase "errors on an empty authorization attribute value" $ do
  res <- testAuth "Hawk id=\"\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\"" 1353788437 testReq4
  checkAuthFail "Bad attribute value: id" res

testServerAuth22 = testCase "errors on duplicated authorization attribute key" $ do
  res <- testAuth "Hawk id=\"123\", id=\"456\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\"" 1353788437 testReq4
  checkAuthFail "Duplicate attribute: id" res

testServerAuth23 = testCase "errors on an invalid authorization header format" $ do
  res <- testAuth "Hawk" 1353788437 testReq4
  checkAuthFail "Invalid header syntax" res

-- fixme: i don't think these are needed because HawkReq has types
-- testServerAuth24 = testCase "errors on an bad host header (missing host)" (fail "n/a for wai?")
-- testServerAuth25 = testCase "errors on an bad host header (bad port)" (fail "n/a for wai?")

testServerAuth26 = testCase "errors on credentialsFunc error" $ do
  res <- testAuth "Hawk id=\"doesnotexist\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"doesn't matter\", ext=\"hello\"" 1353788437 testReq4
  checkAuthFail "Unknown user" res

-- not sure why this use case is needed
-- testServerAuth27 = testCase "errors on credentialsFunc error (with credentials)" (fail "n/a")

-- following errors can't happen in this implementation
-- testServerAuth28 = testCase "errors on missing credentials"
-- testServerAuth29 = testCase "errors on invalid credentials (id)"
-- testServerAuth30 = testCase "errors on invalid credentials (key)"
-- testServerAuth31 = testCase "errors on unknown credentials algorithm"

testServerAuth30 = testCase "errors on invalid credentials (key too short)" $ do
  res <- testAuth "Hawk id=\"999\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"doesn't matter\", ext=\"hello\"" 1353788437 testReq4
  checkAuthFail "Invalid credentials" res

testServerAuth32 = testCase "errors on unknown bad mac" $ do
  res <- testAuth "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcU4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\"" 1353788437 testReq4
  checkAuthFail "Bad mac" res


-- header()
testServerHeader01 = testCase "generates header" $ do
  let Right (creds, user) = credsSteve
  let arts = HeaderArtifacts
             { haMethod = "POST"
             , haHost = "example.com"
             , haPort = Just 8080
             , haResource = hrqUrl testReq4
             , haTimestamp = 1398546787
             , haNonce = "xUwusx"
             , haHash = Just "nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk="
             -- note js tests override artifacts ext with a param to header()
             , haExt = Just "response-specific"
             , haMac = "dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA="
             , haId = "123456"
             , haApp = Nothing
             , haDlg = Nothing
             }
      res = Right (AuthSuccess creds arts ())
      (_, (_, hdr)) = Server.header res (Just $ PayloadInfo "text/plain" "some reply")
  hdr @?= "Hawk mac=\"n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE=\", hash=\"f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=\", ext=\"response-specific\""

testServerHeader02 = testCase "generates header (empty payload)" $ do
  let Right (creds, user) = credsSteve
  let arts = HeaderArtifacts
             { haMethod = "POST"
             , haHost = "example.com"
             , haPort = Just 8080
             , haResource = hrqUrl testReq4
             , haTimestamp = 1398546787
             , haNonce = "xUwusx"
             , haHash = Just "nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk="
             -- note js tests override artifacts ext with a param to header()
             , haExt = Just "response-specific"
             , haMac = "dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA="
             , haId = "123456"
             , haApp = Nothing
             , haDlg = Nothing
             }
      res = Right (AuthSuccess creds arts ())
      (_, (_, hdr)) = Server.header res (Just $ PayloadInfo "text/plain" "")
  hdr @?= "Hawk mac=\"i8/kUBDx0QF+PpCtW860kkV/fa9dbwEoe/FpGUXowf0=\", hash=\"q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA=\", ext=\"response-specific\""

{-
-- fixme: need to change PayloadInfo to support this use case
testServerHeader03 = testCase "generates header (pre calculated hash)" $ do
  let hash = calculatePayloadHash creds (PayloadInfo "text/plain" "some reply")
  -- hash becomes PayloadHash "nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk="
  return ()
-}

testServerHeader04 = testCase "generates header (null ext)" $ do
  let Right (creds, user) = credsSteve
  let arts = HeaderArtifacts
             { haMethod = "POST"
             , haHost = "example.com"
             , haPort = Just 8080
             , haResource = hrqUrl testReq4
             , haTimestamp = 1398546787
             , haNonce = "xUwusx"
             , haHash = Just "nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk="
             , haExt = Nothing
             , haMac = "dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA="
             , haId = "123456"
             , haApp = Nothing
             , haDlg = Nothing
             }
      res = Right (AuthSuccess creds arts ())
      (_, (_, hdr)) = Server.header res (Just $ PayloadInfo "text/plain" "some reply")
  hdr @?= "Hawk mac=\"6PrybJTJs20jsgBw5eilXpcytD8kUbaIKNYXL+6g0ns=\", hash=\"f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=\""

-- not relevant due to types
--testServerHeader05 = testCase "errors on missing artifacts"
--testServerHeader06 = testCase "errors on invalid artifacts"
--testServerHeader07 = testCase "errors on missing credentials"
--testServerHeader09 = testCase "errors on invalid algorithm"

testServerHeader08 = testCase "errors on invalid credentials (key)" $ do
  let Right (creds, user) = credsFred
  let arts = HeaderArtifacts
             { haMethod = "POST"
             , haHost = "example.com"
             , haPort = Just 8080
             , haResource = hrqUrl testReq4
             , haTimestamp = 1398546787
             , haNonce = "xUwusx"
             , haHash = Just "nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk="
             , haExt = Just "response-specific"
             , haMac = "dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA="
             , haId = "123456"
             , haApp = Nothing
             , haDlg = Nothing
             }
      res = Right (AuthSuccess creds arts ())
      (_, (_, hdr)) = Server.header res (Just $ PayloadInfo "text/plain" "some reply")
  -- fixme: header should return empty string or something because key
  -- is too short
  hdr @?= "Hawk mac=\"f877uh9HCdCTF/Y3hIxG0XdUAsWQDqfkPekzLasFlNY=\", hash=\"f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=\", ext=\"response-specific\""


-- authenticateBewit()
testServerBewit01 = testCase "errors on uri too long" $ do
  let req = testReq4
            { hrqUrl = S8.pack ('/':take 5000 (repeat 'x'))
            , hrqAuthorization = "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""
            }
  res <- Server.authenticateBewit def testCredsFunc req
  case res of
    Right _ -> "success" @?= "failure"
    Left (Server.AuthFailBadRequest e _) -> e @?= "Resource path exceeds max length"
    Left e -> show e @?= "AuthFailBadRequest _ _"

-- message
testMessages = testProperty "Client.message . Server.authenticateMessage == Right"
  prop_messageSame

prop_messageSame :: String -> Property
prop_messageSame msg = monadicIO $ do
  res <- run $ do
    tm <- setupTestMessage
    testMessage (tm { tmMsg = BL.fromStrict (S8.pack msg) })
  assert (isRight res)

data TestMessage = TestMessage
                   { tmServerCreds :: Server.Credentials
                   , tmClientCreds :: Client.Credentials
                   , tmCredsFunc :: Server.CredentialsFunc IO String
                   , tmHost :: ByteString
                   , tmPort :: Maybe Int
                   , tmSkew :: NominalDiffTime
                   , tmOpts :: Server.AuthOpts
                   , tmMsg :: BL.ByteString
                   }

setupTestMessage :: IO TestMessage
setupTestMessage = do
  let cf = testCredsFunc
  Right (sc, user) <- cf "123456"
  let cc = clientCreds "" sc
  opts <- Server.nonceOpts 60
  return $ TestMessage sc cc testCredsFunc "example.com" (Just 8080) 0 opts ""

testMessage TestMessage{..} = do
  auth <- Client.message tmClientCreds tmHost tmPort tmMsg tmSkew
  Server.authenticateMessage tmOpts tmCredsFunc tmHost tmPort tmMsg auth

-- because of types, these test cases are impossible
--testServerMessage01 = testCase "errors on invalid authorization (ts)"
--testServerMessage02 = testCase "errors on invalid authorization (nonce)"
--testServerMessage03 = testCase "errors on invalid authorization (hash)"

testServerMessage04 = testCase "errors with credentials" $ do
  tm <- setupTestMessage
  res <- testMessage (tm { tmCredsFunc = \i -> return (Left "something") })
  case res of
    Right _ -> "success" @?= "failure"
    Left (Server.AuthFailUnauthorized e _ _) -> e @?= "something"
    Left e -> show e @?= "AuthFailUnauthorized _ _ _"

testServerMessage05 = testCase "errors on nonce collision" $ do
  tm@TestMessage{..} <- setupTestMessage
  auth <- Client.message tmClientCreds tmHost tmPort tmMsg tmSkew
  res <- Server.authenticateMessage tmOpts tmCredsFunc tmHost tmPort tmMsg auth
  Server.authValue <$> res @?= Right "steve"
  res2 <- Server.authenticateMessage tmOpts tmCredsFunc tmHost tmPort tmMsg auth
  isRight res2 @?= False
  let Left e = res2
  Server.authFailMessage e @?= "Invalid nonce"

testServerMessage06 = testCase "should generate an authorization then successfully parse it"
testServerMessage07 = testCase "should fail authorization on mismatching host"
testServerMessage08 = testCase "should fail authorization on stale timestamp"
testServerMessage09 = testCase "overrides timestampSkewSec"
testServerMessage10 = testCase "should fail authorization on invalid authorization"
testServerMessage11 = testCase "should fail authorization on bad hash"
testServerMessage12 = testCase "should fail authorization on nonce error"
testServerMessage13 = testCase "should fail authorization on credentials error"
testServerMessage14 = testCase "should fail authorization on missing credentials"
testServerMessage15 = testCase "should fail authorization on invalid credentials"
testServerMessage16 = testCase "should fail authorization on invalid credentials algorithm"
testServerMessage17 = testCase "should fail on missing host"
testServerMessage18 = testCase "should fail on missing credentials"
testServerMessage19 = testCase "should fail on invalid algorithm"


testClientUrl1 = "http://example.net/somewhere/over/the/rainbow"
testClientUrl2 = "https://example.net/somewhere/over/the/rainbow"
testClientCreds1 = Client.Credentials "123456" "2983d45yun89q" (HawkAlgo SHA1)
testClientCreds2 = Client.Credentials "123456" "2983d45yun89q" (HawkAlgo SHA256)
testPayload1 = PayloadInfo "" "something to write about"
testPayload2 = PayloadInfo "text/plain" "something to write about"
testPayload3 = PayloadInfo "text/plain" ""

testClientExt = "Bazinga!"

data TestClient = TestClient
                  { tcUrl :: Text
                  , tcMethod :: ByteString
                  , tcCreds :: Client.Credentials
                  , tcPayload :: Maybe PayloadInfo
                  , tcSkew :: NominalDiffTime
                  , tcExt :: Maybe ExtData
                  , tcTimestamp :: POSIXTime
                  , tcNonce :: ByteString
                  }

instance Default TestClient where
  def = TestClient testClientUrl2 "POST" testClientCreds2 (Just testPayload2) 0 (Just testClientExt) 1353809207 "Ygvqdz"

testClientHeader TestClient{..} = Client.hdrField $ Client.headerBase' tcUrl tcMethod tcCreds tcPayload tcSkew tcExt Nothing Nothing tcTimestamp tcNonce

testClientHeader01 = testCase "returns a valid authorization header (sha1)" $ do
  let hdr = testClientHeader (def { tcUrl = testClientUrl1, tcCreds = testClientCreds1, tcPayload = Just testPayload1 })
  hdr @?= "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"bsvY3IfUllw6V5rvk4tStEvpBhE=\", ext=\"Bazinga!\", mac=\"qbf1ZPG/r/e06F4ht+T77LXi5vw=\""

testClientHeader02 = testCase "returns a valid authorization header (sha256)" $ do
  let hdr = testClientHeader def
  hdr @?= "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=\", ext=\"Bazinga!\", mac=\"q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8=\""

testClientHeader03 = testCase "returns a valid authorization header (no ext)" $ do
  let hdr = testClientHeader (def { tcExt = Nothing })
  hdr @?= "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=\", mac=\"HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=\""

-- don't need this test because of types
-- testClientHeader04 = testCase "returns a valid authorization header (null ext)"

testClientHeader05 = testCase "returns a valid authorization header (empty payload)" $ do
  let hdr = testClientHeader (def { tcPayload = Just testPayload3, tcExt = Nothing })
  hdr @?= "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA=\", mac=\"U5k16YEzn3UnBHKeBzsDXn067Gu3R4YaY6xOt9PYRZM=\""

testClientHeader06 = testCase "returns a valid authorization header (pre hashed payload)" $ do
  let hash = calculatePayloadHash (HawkAlgo SHA256) testPayload2
      -- fixme: use precalculated hash
      hdr = testClientHeader (def { tcPayload = Just testPayload2, tcExt = Nothing })
  hdr @?= "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=\", mac=\"HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=\""

testClientHeader07 = testCase "errors on missing uri" $ do
  let hdr = testClientHeader (def { tcUrl = "" })
  hdr @?= ""

-- js impl tests supply a number instead of string url
-- testClientHeader08 = testCase "errors on invalid uri"

testClientHeader09 = testCase "errors on missing method" $ do
  let hdr = testClientHeader (def { tcMethod = "" })
  hdr @?= ""

-- js impl tests supply a number instead of string
--testClientHeader10 = testCase "errors on invalid method"

-- not needed because of types
-- testClientHeader11 = testCase "errors on missing options"
-- testClientHeader12 = testCase "errors on invalid credentials (id)"
-- testClientHeader13 = testCase "errors on missing credentials"
-- testClientHeader14 = testCase "errors on invalid credentials"
-- testClientHeader15 = testCase "errors on invalid algorithm"

testClientAuth01 = testCase "returns false on invalid header"
testClientAuth02 = testCase "returns false on invalid header (callback)"
testClientAuth03 = testCase "returns false on invalid mac"
testClientAuth04 = testCase "returns true on ignoring hash"
testClientAuth05 = testCase "validates response payload"
testClientAuth06 = testCase "validates response payload (callback)"
testClientAuth07 = testCase "errors on invalid response payload"
testClientAuth08 = testCase "fails on invalid WWW-Authenticate header format"
testClientAuth09 = testCase "fails on invalid WWW-Authenticate header format"
testClientAuth10 = testCase "skips tsm validation when missing ts"


testClientMessage01 = testCase "generates authorization"
testClientMessage02 = testCase "errors on invalid host"
testClientMessage03 = testCase "errors on invalid port"
testClientMessage04 = testCase "errors on missing host"
testClientMessage05 = testCase "errors on null message"
testClientMessage06 = testCase "errors on missing message"
testClientMessage07 = testCase "errors on invalid message"
testClientMessage08 = testCase "errors on missing options"
testClientMessage09 = testCase "errors on invalid credentials (id)"
testClientMessage10 = testCase "errors on invalid credentials (key)"
