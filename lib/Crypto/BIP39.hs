module Crypto.BIP39
    ( Strength(..)
    , Entropy
    , generateEntropy
    , entropyToMnemonic
    , mnemonicToEntropy
    ) where

import           Control.Monad         (void)
import qualified Crypto.Hash.SHA256    as SHA256
import           Data.Binary
import           Data.Binary.Bits.Get
import           Data.Binary.Bits.Put
import           Data.Binary.Get       (runGet)
import           Data.Binary.Put       (runPut)
import qualified Data.ByteString       as B
import qualified Data.ByteString.Lazy  as L8
import           Data.Monoid
import qualified Data.Set              as Set
import           System.Random

import qualified Crypto.BIP39.WordList as WordList

newtype Entropy = Entropy { _bytes :: B.ByteString }
  deriving (Eq, Show)

data Strength = S128 | S160 | S192 | S224 | S256

bitCount :: Strength -> Int
bitCount = \case S128 -> 128
                 S160 -> 160
                 S192 -> 192
                 S224 -> 224
                 S256 -> 256


-- CS = ENT / 32
-- MS = (ENT + CS) / 11
--
-- |  ENT  | CS | ENT+CS |  MS  |
-- +-------+----+--------+------+
-- |  128  |  4 |   132  |  12  |
-- |  160  |  5 |   165  |  15  |
-- |  192  |  6 |   198  |  18  |
-- |  224  |  7 |   231  |  21  |
-- |  256  |  8 |   264  |  24  |


-- API -------------------------------------------------------------------------------------------------------

generateEntropy :: RandomGen g => Strength -> g -> Entropy
generateEntropy strength gen = Entropy (bytes <> calcChecksum bytes)
  where
    bytes = randomBytes (bitCount strength `div` 8) gen

entropyToMnemonic :: Entropy -> [String]
entropyToMnemonic = fmap (`Set.elemAt` WordList.english) . entropyToIndices

mnemonicToEntropy :: [String] -> Entropy
mnemonicToEntropy = indicesToBytes . seedToIndices


-- TODO:
-- verifyChecksum :: Entropy -> Bool


-- Utils -----------------------------------------------------------------------------------------------------

randomBytes :: RandomGen g => Int -> g -> B.ByteString
randomBytes x = B.pack . take x . randoms


calcChecksum :: B.ByteString -> B.ByteString
calcChecksum bytes = B.take x $ SHA256.hash bytes
  where
    -- TODO: need to take x bits
    -- this only works because it just happens to be a full byte
    x = B.length bytes `div` 32


entropyToIndices :: Entropy -> [Int]
entropyToIndices (Entropy bytes) = runGet (runBitGet bitGet) (L8.fromStrict bytes)
  where
    x = (B.length bytes * 8) `div` 11
    bitGet = block $ sequenceA $ replicate x getInt11
    getInt11 = fromIntegral <$> word16be 11


seedToIndices :: [String] -> [Int]
seedToIndices ws = (`Set.findIndex` WordList.english) <$> ws


indicesToBytes :: [Int] -> Entropy
indicesToBytes ixs = Entropy $ L8.toStrict $ runPut (runBitPut bitPut)
  where
    ws :: [Word16]
    ws = fromIntegral <$> ixs

    bitPut :: BitPut ()
    bitPut = void $ sequence $ putWord16be 11 <$> ws
