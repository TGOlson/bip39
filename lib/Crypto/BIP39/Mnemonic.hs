module Crypto.BIP39.Mnemonic
    ( Mnemonic
    , toWords
    , mnemonic
    , toEntropy
    -- , fromWordList -- TODO: return maybe, verify checksum
    ) where

import           Control.Monad
import qualified Crypto.Hash.SHA256    as SHA256
import           Data.Binary.Bits.Get
import           Data.Binary.Bits.Put
import           Data.Binary.Get       (runGet)
import           Data.Binary.Put       (runPut)
import           Data.Bits
import qualified Data.ByteString       as B
import qualified Data.ByteString.Lazy  as L8
import           Data.Maybe
import           Data.Monoid
import qualified Data.Set              as Set
import           Data.Word

import qualified Crypto.BIP39.Entropy  as Entropy
import qualified Crypto.BIP39.WordList as WordList

newtype Mnemonic = Mnemonic { _words :: [WordList.BIP39Word] }
  deriving (Eq, Show)

toWords :: Mnemonic -> [WordList.BIP39Word]
toWords = _words

mnemonic :: Entropy.Entropy -> Mnemonic
mnemonic entropy = Mnemonic $ (`Set.elemAt` WordList.wordList) <$> indices
  where
    bytes = Entropy.bytes entropy
    checksum = calcChecksum bytes
    indices = bytesToIndices (bytes <> checksum)

toEntropy :: Mnemonic -> Entropy.Entropy
toEntropy (Mnemonic ws) = forceEntropy entropyBytes
  where
    entropyBytes = B.take numBytesEntropy allBytes
    numBytesEntropy = case length ws of
        12 -> 16
        15 -> 20
        18 -> 24
        21 -> 28
        24 -> 32
        _  -> error "unexpected poop"
    allBytes = indicesToBytes (seedToIndices ws)
    forceEntropy = fromMaybe (error "unexpected error converting back to entropy") . Entropy.entropy

seedToIndices :: [WordList.BIP39Word] -> [Int]
seedToIndices ws = (`Set.findIndex` WordList.wordList) <$> ws

indicesToBytes :: [Int] -> B.ByteString
indicesToBytes ixs = L8.toStrict $ runPut (runBitPut bitPut)
  where
    ws :: [Word16]
    ws = fromIntegral <$> ixs

    bitPut :: BitPut ()
    bitPut = void $ sequence $ putWord16be 11 <$> ws


-- verifyChecksum :: Mnemonic -> Bool
-- verifyChecksum mn = calcChecksum (B.take 32 bytes) == B.drop 32 bytes
--   where
--     bytes = Entropy.bytes (toEntropy mn)


calcChecksum :: B.ByteString -> B.ByteString
calcChecksum bytes = L8.toStrict $ runPut (runBitPut bitPut)
  where
    hashedBytes = SHA256.hash bytes

    -- Note: taking the first byte works because we know at most the checksum will be a single byte in size.
    -- This approach would not work for mnemonics with entropies larger than 256
    firstByte = head (B.unpack hashedBytes)
    bitPut :: BitPut ()
    bitPut = void $ sequence $ putBool <$> checksumBits

    checksumBits = take checksumNumBits $ reverse $ testBit firstByte <$> [0 .. 7]
    checksumNumBits = (B.length bytes * 8) `div` 32


bytesToIndices :: B.ByteString -> [Int]
bytesToIndices bytes = runGet (runBitGet bitGet) (L8.fromStrict bytes)
  where
    x = (B.length bytes * 8) `div` 11
    bitGet = block $ sequenceA $ replicate x getInt11
    getInt11 = fromIntegral <$> word16be 11
