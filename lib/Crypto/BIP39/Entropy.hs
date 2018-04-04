module Crypto.BIP39.Entropy
    ( Entropy
    , bytes
    , strength
    , entropy
    , generateEntropyStdGen
    , generateEntropy
    , Strength(..)
    , bitCount
    , fromBitCount
    ) where

import qualified Data.ByteString as B
import           Data.Maybe
import           System.Random

data Entropy = Entropy { _bytes :: B.ByteString, _strength :: Strength }
  deriving (Eq, Show)

bytes :: Entropy -> B.ByteString
bytes = _bytes

strength :: Entropy -> Strength
strength = _strength

entropy :: B.ByteString -> Maybe Entropy
entropy bs = Entropy bs <$> fromBitCount numBits
  where
    numBits = B.length bs * 8

generateEntropyStdGen :: Strength -> IO Entropy
generateEntropyStdGen str = generateEntropy <$> newStdGen <*> return str

generateEntropy :: RandomGen g => g -> Strength -> Entropy
generateEntropy gen str = fromMaybe (error "unexpected error generating entropy") $ entropy bs
 where
   bs = B.pack $ take (bitCount str `div` 8) (randoms gen)

data Strength
    = Strength128
    | Strength160
    | Strength192
    | Strength224
    | Strength256
  deriving (Eq, Show)

bitCount :: Strength -> Int
bitCount = \case Strength128 -> 128
                 Strength160 -> 160
                 Strength192 -> 192
                 Strength224 -> 224
                 Strength256 -> 256

fromBitCount :: Int -> Maybe Strength
fromBitCount = \case
    128 -> Just Strength128
    160 -> Just Strength160
    192 -> Just Strength192
    224 -> Just Strength224
    256 -> Just Strength256
    _   -> Nothing
