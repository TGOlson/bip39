module Crypto.BIP39
    ( Strength(..)
    , Entropy
    , bytes
    , fromBytes
    , generateEntropy
    , generateEntropyStdGen
    , entropyToMnemonic
    , mnemonicToEntropy
    , verifyChecksum
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

-- TODO: phantom type Entropy 'Strength
newtype Entropy = Entropy { _bytes :: B.ByteString }
  deriving (Eq, Show)

bytes :: Entropy -> B.ByteString
bytes = _bytes

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

generateEntropyStdGen :: Strength -> IO Entropy
generateEntropyStdGen strength = generateEntropy <$> newStdGen <*> return strength

generateEntropy :: RandomGen g => g -> Strength -> Entropy
generateEntropy gen strength = Entropy (bs <> calcChecksum bs)
  where
    bs = randomBytes (bitCount strength `div` 8) gen

entropyToMnemonic :: Entropy -> [String]
entropyToMnemonic = fmap (`Set.elemAt` WordList.english) . entropyToIndices

mnemonicToEntropy :: [String] -> Entropy
mnemonicToEntropy = indicesToBytes . seedToIndices

fromBytes :: B.ByteString -> Maybe Entropy
fromBytes bs = if B.length bs == 33 && verifyChecksum (Entropy bs)
    then Just (Entropy bs)
    else Nothing

verifyChecksum :: Entropy -> Bool
verifyChecksum (Entropy bs) = calcChecksum (B.take 32 bs) == B.drop 32 bs


-- Utils -----------------------------------------------------------------------------------------------------

randomBytes :: RandomGen g => Int -> g -> B.ByteString
randomBytes x = B.pack . take x . randoms


calcChecksum :: B.ByteString -> B.ByteString
calcChecksum bs = B.take x $ SHA256.hash bs
  where
    -- TODO: need to take x bits
    -- this only works because it just happens to be a full byte
    x = B.length bs `div` 32


entropyToIndices :: Entropy -> [Int]
entropyToIndices (Entropy bs) = runGet (runBitGet bitGet) (L8.fromStrict bs)
  where
    x = (B.length bs * 8) `div` 11
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
