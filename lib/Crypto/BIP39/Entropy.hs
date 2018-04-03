module Crypto.BIP39.Entropy
    ( Entropy
    , toBytes
    , entropy128
    , entropy160
    , entropy192
    , entropy224
    , entropy256
    ) where

import           Data.Bits
import qualified Data.ByteString       as B
import           Data.Word

import           Crypto.BIP39.Strength

newtype Entropy a = Entropy { _bytes :: B.ByteString }
  deriving (Eq, Show)

toBytes :: Entropy a -> B.ByteString
toBytes = _bytes

entropy128
    :: Word32
    -> Word32
    -> Word32
    -> Word32
    -> Entropy Strength128
entropy128 bs1 bs2 bs3 bs4 =
    buildFromBytes [bs1, bs2, bs3, bs4]

entropy160
    :: Word32
    -> Word32
    -> Word32
    -> Word32
    -> Word32
    -> Entropy Strength160
entropy160 bs1 bs2 bs3 bs4 bs5 =
    buildFromBytes [bs1, bs2, bs3, bs4, bs5]

entropy192
    :: Word32
    -> Word32
    -> Word32
    -> Word32
    -> Word32
    -> Word32
    -> Entropy Strength192
entropy192 bs1 bs2 bs3 bs4 bs5 bs6 =
    buildFromBytes [bs1, bs2, bs3, bs4, bs5, bs6]

entropy224
    :: Word32
    -> Word32
    -> Word32
    -> Word32
    -> Word32
    -> Word32
    -> Word32
    -> Entropy Strength224
entropy224 bs1 bs2 bs3 bs4 bs5 bs6 bs7 =
    buildFromBytes [bs1, bs2, bs3, bs4, bs5, bs6, bs7]

entropy256
    :: Word32
    -> Word32
    -> Word32
    -> Word32
    -> Word32
    -> Word32
    -> Word32
    -> Word32
    -> Entropy Strength256
entropy256 bs1 bs2 bs3 bs4 bs5 bs6 bs7 bs8 =
    buildFromBytes [bs1, bs2, bs3, bs4, bs5, bs6, bs7, bs8]

buildFromBytes :: [Word32] -> Entropy a
buildFromBytes word32s = Entropy bytes
  where
    bytes = B.pack (word32s >>= splitWord32)

splitWord32 :: Word32 -> [Word8]
splitWord32 bytes = [fromOffset 24, fromOffset 16, fromOffset 8, fromOffset 0]
  where
    fromOffset x = foldl (\bs i -> if testBit bytes i then setBit bs (i - x) else bs) 0 [x .. x + 7]
