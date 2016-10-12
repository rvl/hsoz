module Main where

import System.Environment (getArgs, getProgName)

import qualified HawkServer as Hawk
import qualified HawkClient as Hawk
import qualified OzServer as Oz
import qualified OzClient as Oz

main :: IO ()
main = do
  prog <- getProgName
  args <- getArgs
  case dispatch prog of
    Just act -> act
    Nothing -> case args of
      (arg:_) -> case dispatch arg of
        Just act -> act
        Nothing -> usage prog
      _ -> usage prog

dispatch :: String -> Maybe (IO ())
dispatch "hawk-server" = Just Hawk.serverMain
dispatch "hawk-client" = Just Hawk.clientMain
dispatch "oz-server" = Just Oz.serverMain
dispatch "oz-client" = Just Oz.clientMain
dispatch _ = Nothing

usage :: String -> IO ()
usage prog = putStrLn $ "Usage: " ++ prog ++ " [ hawk-server | hawk-client | oz-server | oz-client ]"
