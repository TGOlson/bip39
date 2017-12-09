module Main ( main ) where

import qualified Data.ByteString as B
import           Data.List
import           Data.Maybe
import           Options.Generic

import           Crypto.BIP39

data Command = Command { read :: Bool, file :: Maybe String }
  deriving (Generic, Show)

instance ParseRecord Command

main :: IO ()
main = getRecord "BIP39" >>= \case
    Command False Nothing     -> generateEntropyStdGen S256 >>= (printMnemonic . entropyToMnemonic)
    Command False (Just path) -> generateEntropyStdGen S256 >>= (B.writeFile path . bytes)
    Command True  (Just path) -> B.readFile path >>= (printMnemonic . entropyToMnemonic . toEntropy)
    Command True Nothing      -> error "Path required to read seed"
  where
    printMnemonic = putStrLn . intercalate "\n"
    toEntropy = fromMaybe (error "Invalid bytes") . fromBytes
