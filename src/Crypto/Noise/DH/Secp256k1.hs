{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.Noise.DH.Secp256k1
  ( Secp256k1
  , dhFromSecKey
  , dhFromPubKey
  ) where

import Crypto.Random.Entropy       (getEntropy)
import Data.ByteString             (ByteString)
import Data.ByteArray              (ScrubbedBytes, convert)
import Crypto.Noise.DH

import qualified Crypto.Secp256k1 as S

data Secp256k1

instance DH Secp256k1 where
  newtype PublicKey Secp256k1 = PKSecp256k1 S.PubKey
  newtype SecretKey Secp256k1 = SKSecp256k1 S.SecKey

  dhName _      = "secp256k1"
  dhLength _    = 33
  dhGenKey      = genKey
  dhPerform     = dh
  dhPubToBytes  = pubToBytes
  dhBytesToPub  = bytesToPub
  dhSecToBytes  = secToBytes
  dhBytesToPair = bytesToPair
  dhPubEq       = pubEq

genKey :: IO (KeyPair Secp256k1)
genKey = do
  r <- getEntropy 32 :: IO ByteString
  let (Just sec) = S.secKey r
  return $ dhFromSecKey sec

dh :: SecretKey Secp256k1 -> PublicKey Secp256k1 -> ScrubbedBytes
dh (SKSecp256k1 sk) (PKSecp256k1 pk) = convert $ S.ecdh pk sk

pubToBytes :: PublicKey Secp256k1 -> ScrubbedBytes
pubToBytes (PKSecp256k1 pk) = convert $ S.exportPubKey True pk

bytesToPub :: ScrubbedBytes -> Maybe (PublicKey Secp256k1)
bytesToPub b = PKSecp256k1 <$> S.importPubKey (convert b)

secToBytes :: SecretKey Secp256k1 -> ScrubbedBytes
secToBytes (SKSecp256k1 sk) = convert $ S.getSecKey sk

bytesToPair :: ScrubbedBytes -> Maybe (KeyPair Secp256k1)
bytesToPair b = dhFromSecKey <$> S.secKey (convert b)

pubEq :: PublicKey Secp256k1 -> PublicKey Secp256k1 -> Bool
pubEq = (==)

dhFromSecKey :: S.SecKey -> KeyPair Secp256k1
dhFromSecKey sk = (SKSecp256k1 sk, PKSecp256k1 (S.derivePubKey sk))

dhFromPubKey :: S.PubKey -> PublicKey Secp256k1
dhFromPubKey = PKSecp256k1
