# bip39

Haskell implementation of [the bip39 protocol](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).

Note: only the default wordlist is supported.

```
$ stack build
$ stack test
$ stack exec -- bip39 <128/160/192/224/256>
```

TODO:
  * support mnemonic to seed
  * add `fromWordList :: [BIP39Word] -> Maybe Mnemonic`

```
CS = ENT / 32
MS = (ENT + CS) / 11

|  ENT  | CS | ENT+CS |  MS  |
+-------+----+--------+------+
|  128  |  4 |   132  |  12  |
|  160  |  5 |   165  |  15  |
|  192  |  6 |   198  |  18  |
|  224  |  7 |   231  |  21  |
|  256  |  8 |   264  |  24  |
```
