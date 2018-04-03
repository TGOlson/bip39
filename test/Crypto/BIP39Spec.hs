module Crypto.BIP39Spec ( spec ) where

import Test.Hspec

import Data.Monoid
import Data.Word
import Numeric

import Crypto.BIP39.Entropy
import Crypto.BIP39.Mnemonic
import TestData

spec :: Spec
spec = describe "Crypto.BIP39Spec" $
    it "should create the expected mnemonic and seed for all test cases" $
        flip all testCases $ \(TestCase entropyHex expectedWordList _expectedSeed) ->
            case length entropyHex of
                32 -> let [bs1, bs2, bs3, bs4] = splitHex entropyHex
                          entropy = entropy128 bs1 bs2 bs3 bs4
                      in toWords (mnemonic entropy) == expectedWordList
                40 -> let [bs1, bs2, bs3, bs4, bs5] = splitHex entropyHex
                          entropy = entropy160 bs1 bs2 bs3 bs4 bs5
                      in toWords (mnemonic entropy) == expectedWordList
                48 -> let [bs1, bs2, bs3, bs4, bs5, bs6] = splitHex entropyHex
                          entropy = entropy192 bs1 bs2 bs3 bs4 bs5 bs6
                      in toWords (mnemonic entropy) == expectedWordList
                56 -> let [bs1, bs2, bs3, bs4, bs5, bs6, bs7] = splitHex entropyHex
                          entropy = entropy224 bs1 bs2 bs3 bs4 bs5 bs6 bs7
                      in toWords (mnemonic entropy) == expectedWordList
                64 -> let [bs1, bs2, bs3, bs4, bs5, bs6, bs7, bs8] = splitHex entropyHex
                          entropy = entropy256 bs1 bs2 bs3 bs4 bs5 bs6 bs7 bs8
                      in toWords (mnemonic entropy) == expectedWordList
                _   -> error $ "unexpected test case hex " <> entropyHex

hexToWord32 :: String -> Word32
hexToWord32 = fst . head . Numeric.readHex

splitHex :: String -> [Word32]
splitHex str = hexToWord32 <$> groups
  where
    numGroups = length str `div` 8
    groups = foldl (\acc i -> acc <> pure (slice8 (i * 8) str)) mempty [0 .. numGroups - 1]
    slice8 offset = take 8 . drop offset
