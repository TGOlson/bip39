module Main ( main ) where

import Data.List
import Data.Monoid
import Options.Generic
import System.Random

import Crypto.BIP39.Entropy.Random
import Crypto.BIP39.Mnemonic

newtype Command = Command Int
  deriving (Generic, Show)

instance ParseRecord Command

main :: IO ()
main = do
    gen <- newStdGen

    getRecord "BIP39" >>= \case
        Command 128 -> printMnemonic $ mnemonic (genEntropy128 gen)
        Command 160 -> printMnemonic $ mnemonic (genEntropy160 gen)
        Command 192 -> printMnemonic $ mnemonic (genEntropy192 gen)
        Command 224 -> printMnemonic $ mnemonic (genEntropy224 gen)
        Command 256 -> printMnemonic $ mnemonic (genEntropy256 gen)
        Command x   -> error $ "Invalid strength " <> show x
  where
    printMnemonic = putStrLn . intercalate "\n" . fmap show . toWords
