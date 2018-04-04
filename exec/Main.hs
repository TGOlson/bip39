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
    (Command numBits) <- getRecord "BIP39"
    gen <- newStdGen

    case fromBitCount numBits of
        Just str -> do
            putStrLn $ "Generating mnemonic with " <> show (bitCount str) <> " bits of entropy. Using seed " <> show gen

            let mnemonic = toMnemonic (generateEntropy gen str)
                wordStrings = fmap show (toWords mnemonic)
                formattedWords = "  " <> intercalate "\n  " wordStrings

            putStrLn formattedWords
        Nothing  -> error $ "Invalid strength " <> show numBits
