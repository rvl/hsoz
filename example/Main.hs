module Main where

import Data.List (intercalate)
import System.Environment (getArgs, getProgName)

import qualified HawkClient         as Hawk
import qualified HawkServer         as Hawk
import qualified BewitClient        as Bewit
import qualified BewitServer        as Bewit
import qualified OzClient           as Oz
import qualified OzServer           as Oz

main :: IO ()
main = do
  prog <- getProgName
  args <- getArgs
  case dispatch prog of
    Just act -> act
    Nothing -> case args of
      (arg:_) -> case dispatch arg of
        Just act -> act
        Nothing  -> usage prog
      _ -> usage prog

dispatch :: String -> Maybe (IO ())
dispatch "hawk-server"  = Just Hawk.serverMain
dispatch "hawk-client"  = Just Hawk.clientMain
dispatch "bewit-server" = Just Bewit.serverMain
dispatch "bewit-client" = Just Bewit.clientMain
dispatch "oz-server"    = Just Oz.serverMain
dispatch "oz-client"    = Just Oz.clientMain
dispatch _              = Nothing

usage :: String -> IO ()
usage prog = putStrLn $ "Usage: " ++ prog ++ " [ " ++ progs ++ " ]"
  where
    progs = intercalate " | " [ p ++ "-" ++ c | p <- ps, c <- cs]
    ps = ["hawk", "bewit", "oz"]
    cs = ["client", "server"]
