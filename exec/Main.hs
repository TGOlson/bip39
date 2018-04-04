module Main ( main ) where

import Data.List
import Data.Monoid
import Options.Generic
import System.Random

import Crypto.BIP39.Entropy
import Crypto.BIP39.Mnemonic

newtype Command = Command Int
  deriving (Generic, Show)

instance ParseRecord Command

main :: IO ()
main = do
    gen <- newStdGen

    getRecord "BIP39" >>= \case
        Command 128 -> printMnemonic $ mnemonic (generateEntropy gen Strength128)
        Command 160 -> printMnemonic $ mnemonic (generateEntropy gen Strength160)
        Command 192 -> printMnemonic $ mnemonic (generateEntropy gen Strength192)
        Command 224 -> printMnemonic $ mnemonic (generateEntropy gen Strength224)
        Command 256 -> printMnemonic $ mnemonic (generateEntropy gen Strength256)
        Command x   -> error $ "Invalid strength " <> show x
  where
    printMnemonic = putStrLn . intercalate "\n" . fmap show . toWords
