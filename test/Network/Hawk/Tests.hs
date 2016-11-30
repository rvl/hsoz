{-# LANGUAGE RecordWildCards #-}

module Network.Hawk.Tests (tests) where

import Data.Either (isRight)
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
import qualified Network.Hawk.Client.Types as Client (HeaderArtifacts(..))
import qualified Network.Hawk.Server.Types as Server (HeaderArtifacts(..))

tests :: TestTree
tests = testGroup "Network.Hawk"
        [ testCase "generates a header then successfully parses it" test01
        , testCase "generates a header then successfully parses it (WAI request)" test02
        , testCase "generates a header then successfully parses it (absolute request uri)" test03
        , testCase "generates a header then fails to parse it (missing server header hash)" test04
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
  r <- Server.authenticate def credsFunc hrq
  isRight r @?= True
  let Right (Server.AuthSuccess creds' arts user) = r
  user @?= "steve"
  Server.shaExt arts @?= Just "some-app-data"

-- generates a header then successfully parse it (WAI request)
test02 :: Assertion
test02 = do
  -- Generate client header
  let (creds, credsFunc) = makeCreds "123456"
      ext = Just "some-app-data"
      payload = PayloadInfo "text/plain;x=y" "some not so random text"
  hdr <- Client.header "http://example.com:8080/resource/4?filter=a" "POST" creds (Just payload) ext

  -- Server verifies client request
  let req = mockRequest "POST" "/resource/4" "?filter=a" "example.com:8080" payload [("authorization", Client.hdrField hdr)]

  r <- Server.authenticateRequest def credsFunc req (Just (payloadData payload))
  isRight r @? "Expected auth success, got: " ++ show r
  let Right s@(Server.AuthSuccess creds2 arts user) = r
  user @?= "steve"
  Server.shaExt arts @?= Just "some-app-data"
  Server.authenticatePayload s payload @?= Right ()

  -- Client verifies server response
  let payload2 = PayloadInfo "text/plain" "Some reply"
      hdr2 = Server.header creds2 arts (Just payload2)
      res = mockResponse payload2 [hdr2]
      creds2' = clientCreds "" creds2
      arts' = clientHeaderArtifacts arts
  r2 <- Client.authenticate res creds2' arts' (Just (payloadData payload2)) Client.ServerAuthorizationRequired
  r2 @?= Right ()

clientCreds :: ClientId -> Server.Credentials -> Client.Credentials
clientCreds i (Server.Credentials k a) = Client.Credentials i k a

-- fixme: there's possibly a case for merging these two types
-- server artifacts have header mac and client id
-- dlg is text/bytestring
clientHeaderArtifacts :: Server.HeaderArtifacts -> Client.HeaderArtifacts
clientHeaderArtifacts Server.HeaderArtifacts{..} = Client.HeaderArtifacts
  { chaTimestamp = shaTimestamp
  , chaNonce     = shaNonce
  , chaMethod    = shaMethod
  , chaHost      = shaHost
  , chaPort      = shaPort
  , chaResource  = shaResource
  , chaHash      = shaHash
  , chaExt       = shaExt
  , chaApp       = shaApp
  , chaDlg       = decodeUtf8 <$> shaDlg
  -- , shaId        :: ClientId
  -- , shaMac       :: ByteString
  }

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
  r <- Server.authenticate def credsFunc hrq
  isRight r @? "Expected auth success, got: " ++ show r
  let Right s@(Server.AuthSuccess creds2 arts user) = r
  user @?= "steve"
  Server.shaExt arts @?= Just "some-app-data"
  Server.authenticatePayload s payload @?= Right ()

  let payload2 = PayloadInfo "text/plain" "some reply"
      fixmeExt2 = "response-specific"
      hdr = Server.header creds2 arts (Just payload2)
      res = mockResponse payload2 [hdr]
      creds2' = clientCreds "" creds2
      arts' = clientHeaderArtifacts arts

  r2 <- Client.authenticate res creds2' arts' (Just (payloadData payload2)) Client.ServerAuthorizationRequired
  r2 @?= Right ()


-- generates a header then fails to parse it (missing server header hash)
test04 :: Assertion
test04 = do
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
  r <- Server.authenticate def credsFunc hrq
  isRight r @? "Expected auth success, got: " ++ show r
  let Right s@(Server.AuthSuccess creds2 arts user) = r
  user @?= "steve"
  Server.shaExt arts @?= Just "some-app-data"
  Server.authenticatePayload s payload @?= Right ()

  let payload2 = PayloadInfo "text/plain" "some reply"
      fixmeExt2 = "response-specific"
      hdr = Server.header creds2 arts Nothing
      res = mockResponse payload2 [hdr]
      creds2' = clientCreds "" creds2
      arts' = clientHeaderArtifacts arts

  r2 <- Client.authenticate res creds2' arts' (Just (payloadData payload2)) Client.ServerAuthorizationRequired
  r2 @?= Left "Missing response hash attribute"
