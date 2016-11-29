module Main where

import           Test.Tasty (defaultMain, testGroup)

import qualified Network.Iron.Tests
import qualified Network.Hawk.Tests
import qualified Network.Oz.Tests

main :: IO ()
main = defaultMain $ testGroup "Tests"
    [ Network.Iron.Tests.tests
    , Network.Hawk.Tests.tests
    , Network.Oz.Tests.tests
    ]
