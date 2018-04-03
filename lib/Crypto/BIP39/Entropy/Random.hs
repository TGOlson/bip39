module Crypto.BIP39.Entropy.Random
    ( genEntropy128
    , genEntropy160
    , genEntropy192
    , genEntropy224
    , genEntropy256
    ) where

import System.Random

import Crypto.BIP39.Entropy
import Crypto.BIP39.Strength


genEntropy128 :: RandomGen g => g -> Entropy Strength128
genEntropy128 gen = entropy128 bs1 bs2 bs3 bs4
  where
    [bs1, bs2, bs3, bs4] = take 4 (randoms gen)

genEntropy160 :: RandomGen g => g -> Entropy Strength160
genEntropy160 gen = entropy160 bs1 bs2 bs3 bs4 bs5
  where
    [bs1, bs2, bs3, bs4, bs5] = take 5 (randoms gen)

genEntropy192 :: RandomGen g => g -> Entropy Strength192
genEntropy192 gen = entropy192 bs1 bs2 bs3 bs4 bs5 bs6
  where
    [bs1, bs2, bs3, bs4, bs5, bs6] = take 6 (randoms gen)

genEntropy224 :: RandomGen g => g -> Entropy Strength224
genEntropy224 gen = entropy224 bs1 bs2 bs3 bs4 bs5 bs6 bs7
  where
    [bs1, bs2, bs3, bs4, bs5, bs6, bs7] = take 7 (randoms gen)

genEntropy256 :: RandomGen g => g -> Entropy Strength256
genEntropy256 gen = entropy256 bs1 bs2 bs3 bs4 bs5 bs6 bs7 bs8
  where
    [bs1, bs2, bs3, bs4, bs5, bs6, bs7, bs8] = take 8 (randoms gen)
