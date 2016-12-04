-- | /Nonces/ prevent replaying of requests. This module provides a
-- nonce validation function which stores previous requests while they
-- are fresh.

module Network.Hawk.Server.Nonce
  ( nonceOpts
  , nonceOptsReq
  ) where

import Data.IORef
import Data.Sequence (Seq, (|>))
import qualified Data.Sequence as Q
import Data.HashSet (HashSet)
import qualified Data.HashSet as S
import Data.Time.Clock.POSIX
import Data.Time.Clock (NominalDiffTime)
import Data.Hashable (Hashable)
import Data.Foldable (toList)

import Network.Hawk.Server (AuthOpts(..), AuthReqOpts(..), Key, def)
import Network.Hawk.Server.Types (Nonce, NonceFunc)

-- | Creates an 'Hawk.AuthOpts' with a nonce validation function which
-- remembers previous nonces for as long as they are valid. The @skew@
-- parameter determines how long a signed request is valid for.
nonceOpts :: NominalDiffTime -> IO AuthOpts
nonceOpts skew = do
  ref <- newIORef (Q.empty, S.empty)
  let nf = makeNonceFunc skew ref
  return $ AuthOpts nf skew 0

-- | Creates an 'Hawk.AuthReqOpts' with a nonce validation function
-- which remembers previous nonces for as long as they are valid. The
-- @skew@ parameter determines how long a signed request is valid for.
nonceOptsReq :: NominalDiffTime -> IO AuthReqOpts
nonceOptsReq skew = do
  opts <- nonceOpts skew
  return $ def { saOpts = opts }

instance Hashable Key

-- Maintain both a queue and set. Queue provides fast expiry of stale
-- nonces and the hash set provides a fast test for nonce existence.
type Store = (Seq (Key, Nonce, POSIXTime), HashSet (Key, Nonce))

makeNonceFunc :: NominalDiffTime -> IORef Store -> NonceFunc
makeNonceFunc skew ref = \k t n -> do
  now <- getPOSIXTime
  atomicModifyIORef' ref (update now (abs skew) k n t)

update :: POSIXTime -> NominalDiffTime -> Key -> Nonce -> POSIXTime -> Store -> (Store, Bool)
update now skew k n t (q, s) = ((q'', s''), fresh)
  where
    fresh = (not $ S.member (k, n) s) && t + skew >= now - skew
    q' | fresh     = q |> (k, n, now + skew)
       | otherwise = q
    s' | fresh     = S.insert (k, n) s
       | otherwise = s
    (dead, q'') = Q.breakl (\(_, _, t) -> t >= now) q'
    s'' = S.difference s' (S.fromList [(k, n) | (k, n, t) <- toList dead])
