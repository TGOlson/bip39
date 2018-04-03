module Main ( main ) where

import qualified Test.Hspec       as Hspec

import qualified Crypto.BIP39Spec

main :: IO ()
main = mapM_ Hspec.hspec specs

specs :: [Hspec.Spec]
specs =
  [ Crypto.BIP39Spec.spec
  ]
