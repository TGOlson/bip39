module Crypto.BIP39Spec ( spec ) where

import           Test.Hspec

import qualified Data.ByteString       as B
import           Data.Maybe
import           Data.Monoid
import           Numeric

import qualified Crypto.BIP39.Entropy  as Entropy
import           Crypto.BIP39.Mnemonic
import           TestData

spec :: Spec
spec = describe "Crypto.BIP39Spec" $ do
    it "should create the expected mnemonic for all test cases" $
        allTestCases $ \(TestCase entropyHex expectedWordList _) ->
            let entropy = hexToEntropy entropyHex
            in toWords (toMnemonic entropy) == expectedWordList

    it "should round trip serialize for all test cases" $
        allTestCases $ \(TestCase entropyHex _ _) ->
            let entropy = hexToEntropy entropyHex
            in toEntropy (toMnemonic entropy) == entropy

allTestCases :: (TestCase -> Bool) -> Bool
allTestCases = flip all testCases

hexToEntropy :: String -> Entropy.Entropy
hexToEntropy = fromMaybe (error "unexpected error building entropy in test") . Entropy.entropy . hexToBytes

hexToBytes :: String -> B.ByteString
hexToBytes hexStr = B.pack bytes
  where
    hexToByte = fst . head . Numeric.readHex
    bytes = hexToByte <$> groups
    numGroups = length hexStr `div` 2
    groups = foldl (\acc i -> acc <> pure (slice2 (i * 2) hexStr)) mempty [0 .. numGroups - 1]
    slice2 offset = take 2 . drop offset
