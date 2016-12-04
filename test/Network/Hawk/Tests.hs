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

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)
import Test.HUnit (Assertion, (@?=), (@?))

import Network.Hawk
import Network.Hawk.Server.Types (HawkReq(..), AuthSuccess(..))
import qualified Network.Hawk.Client as Client
import qualified Network.Hawk.Server as Server
import qualified Network.Hawk.Types (HeaderArtifacts(..))

tests :: TestTree
tests = testGroup "Network.Hawk"
        [ testGroup "Server"
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
