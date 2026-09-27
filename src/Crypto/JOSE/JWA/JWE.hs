-- Copyright (C) 2013, 2015, 2016, 2026  Fraser Tweedale
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

{-|

Cryptographic algorithms for JSON Web Encryption, as specified in
<https://tools.ietf.org/html/rfc7518 RFC 7518> (JSON Web Algorithms).

This module provides the /content encryption/ algorithms (§5) and
the primitives used by the /key management/ algorithms (§4).  Most
applications should use the higher-level functions in
"Crypto.JOSE.JWE" instead.

-}
module Crypto.JOSE.JWA.JWE
  (
  -- * Algorithm identifiers
    Alg(..)
  , Enc(..)

  -- * Content encryption
  , cekLength
  , encryptContent
  , encryptContentWithIV
  , decryptContent

  -- * Key management primitives
  -- ** AES Key Wrap
  , aesKeyWrapCEK
  , aesKeyUnwrapCEK
  -- ** AES GCM key encryption
  , aesGCMKeyWrap
  , aesGCMKeyUnwrap
  -- ** RSA key encryption
  , rsaEncryptCEK
  , rsaDecryptCEK
  -- ** Elliptic Curve Diffie-Hellman key agreement
  , ecdhSharedSecret
  , concatKDF
  -- ** PBES2 key derivation
  , pbes2DeriveKey
  ) where

import Control.Monad (unless, when)
import Control.Monad.Except (MonadError)
import Data.Bits (shiftR)
import Data.Word (Word64)

import Control.Lens (view)
import Control.Monad.Error.Lens (throwing, throwing_)
import Crypto.Cipher.AES (AES128, AES192, AES256)
import Crypto.Cipher.Types
import Crypto.Data.Padding (Format(PKCS7), pad, unpad)
import Crypto.Error (CryptoError(..), CryptoFailable, onCryptoFailure)
import Crypto.Hash
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import Crypto.MAC.HMAC (HMAC, hmac)
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Curve448 as Curve448
import qualified Crypto.PubKey.ECC.DH as ECDH
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B

import Crypto.JOSE.AESKW
import Crypto.JOSE.Error
import Crypto.JOSE.JWA.JWE.Alg
import Crypto.JOSE.JWA.JWK
import Crypto.JOSE.TH
import qualified Crypto.JOSE.Types as Types


-- | RFC 7518 §5  Cryptographic Algorithms for Content Encryption
--
$(deriveJOSEType "Enc" [
  "A128CBC-HS256"   -- AES HMAC SHA authenticated encryption  Required
  , "A192CBC-HS384" -- AES HMAC SHA authenticated encryption  Optional
  , "A256CBC-HS512" -- AES HMAC SHA authenticated encryption  Required
  , "A128GCM"       -- AES in Galois/Counter Mode             Recommended
  , "A192GCM"       -- AES in Galois/Counter Mode             Optional
  , "A256GCM"       -- AES in Galois/Counter Mode             Recommended
  ])


-- | The size (in octets) of the Content Encryption Key (CEK)
-- for the given content encryption algorithm.
--
cekLength :: Enc -> Int
cekLength A128CBC_HS256 = 32
cekLength A192CBC_HS384 = 48
cekLength A256CBC_HS512 = 64
cekLength A128GCM       = 16
cekLength A192GCM       = 24
cekLength A256GCM       = 32

-- | Size of the IV for the given content encryption algorithm.
--
ivLength :: Enc -> Int
ivLength A128CBC_HS256 = 16
ivLength A192CBC_HS384 = 16
ivLength A256CBC_HS512 = 16
ivLength A128GCM       = 12
ivLength A192GCM       = 12
ivLength A256GCM       = 12


cryptoFailable :: (MonadError e m, AsError e) => CryptoFailable a -> m a
cryptoFailable = onCryptoFailure (throwing _CryptoError) pure

-- | Initialise an AES cipher with a 128-, 192- or 256-bit key and
-- pass it to the continuation.
--
withAESCipher
  :: (MonadError e m, AsError e)
  => B.ByteString
  -> (forall cipher. BlockCipher128 cipher => cipher -> m r)
  -> m r
withAESCipher k f = case B.length k of
  16 -> cryptoFailable (cipherInit k :: CryptoFailable AES128) >>= f
  24 -> cryptoFailable (cipherInit k :: CryptoFailable AES192) >>= f
  32 -> cryptoFailable (cipherInit k :: CryptoFailable AES256) >>= f
  _  -> throwing _CryptoError CryptoError_KeySizeInvalid

-- | 32-bit big-endian encoding of an integer
--
be32 :: Int -> B.ByteString
be32 n = B.pack [fromIntegral (n `shiftR` s) | s <- [24, 16, 8, 0]]

-- | 64-bit big-endian encoding of an integer
--
be64 :: Word64 -> B.ByteString
be64 n = B.pack [fromIntegral (n `shiftR` s) | s <- [56, 48 .. 0]]


-- | Encrypt content with a random Initialization Vector.
--
-- Returns the IV, ciphertext and authentication tag.
--
encryptContent
  :: (MonadRandom m, MonadError e m, AsError e)
  => Enc
  -> B.ByteString  -- ^ Content Encryption Key
  -> B.ByteString  -- ^ Additional Authenticated Data
  -> B.ByteString  -- ^ plaintext
  -> m (B.ByteString, B.ByteString, B.ByteString)
encryptContent enc cek aad m = do
  iv <- getRandomBytes (ivLength enc)
  (c, tag) <- encryptContentWithIV enc iv cek aad m
  pure (iv, c, tag)

-- | Encrypt content with the given Initialization Vector.
-- __The IV must never be reused with the same key.__  Most applications
-- should use 'encryptContent', which generates a random IV.
--
-- Returns the ciphertext and authentication tag.
--
encryptContentWithIV
  :: (MonadError e m, AsError e)
  => Enc
  -> B.ByteString  -- ^ Initialization Vector
  -> B.ByteString  -- ^ Content Encryption Key
  -> B.ByteString  -- ^ Additional Authenticated Data
  -> B.ByteString  -- ^ plaintext
  -> m (B.ByteString, B.ByteString)
encryptContentWithIV enc iv cek aad m = do
  checkSizes enc iv cek
  case enc of
    A128CBC_HS256 -> cbcHmacEncrypt SHA256
    A192CBC_HS384 -> cbcHmacEncrypt SHA384
    A256CBC_HS512 -> cbcHmacEncrypt SHA512
    A128GCM       -> gcm
    A192GCM       -> gcm
    A256GCM       -> gcm
  where
    cbcHmacEncrypt h =
      let (macKey, encKey) = B.splitAt (B.length cek `div` 2) cek
      in withAESCipher encKey $ \cipher -> do
        iv' <- maybe (throwing _CryptoError CryptoError_IvSizeInvalid) pure (makeIV iv)
        let c = cbcEncrypt cipher iv' (pad (PKCS7 (blockSize cipher)) m)
        pure (c, cbcHmacTag h macKey aad iv c)
    gcm = withAESCipher cek $ \cipher -> gcmEncrypt cipher iv aad m

-- | Decrypt content, returning the plaintext.
--
-- Throws 'JWEIntegrityFailed' if the authentication tag does not
-- verify or the ciphertext is malformed.
--
decryptContent
  :: (MonadError e m, AsError e)
  => Enc
  -> B.ByteString  -- ^ Content Encryption Key
  -> B.ByteString  -- ^ Additional Authenticated Data
  -> B.ByteString  -- ^ Initialization Vector
  -> B.ByteString  -- ^ ciphertext
  -> B.ByteString  -- ^ authentication tag
  -> m B.ByteString
decryptContent enc cek aad iv c tag = do
  checkSizes enc iv cek
  case enc of
    A128CBC_HS256 -> cbcHmacDecrypt SHA256
    A192CBC_HS384 -> cbcHmacDecrypt SHA384
    A256CBC_HS512 -> cbcHmacDecrypt SHA512
    A128GCM       -> gcm
    A192GCM       -> gcm
    A256GCM       -> gcm
  where
    cbcHmacDecrypt h =
      let (macKey, encKey) = B.splitAt (B.length cek `div` 2) cek
      in withAESCipher encKey $ \cipher -> do
        -- Verify the tag before doing anything else
        unless (BA.constEq tag (cbcHmacTag h macKey aad iv c)) $
          throwing_ _JWEIntegrityFailed
        let n = blockSize cipher
        when (B.null c || B.length c `mod` n /= 0) $
          throwing_ _JWEIntegrityFailed
        iv' <- maybe (throwing _CryptoError CryptoError_IvSizeInvalid) pure (makeIV iv)
        maybe (throwing_ _JWEIntegrityFailed) pure
          (unpad (PKCS7 n) (cbcDecrypt cipher iv' c))
    gcm = withAESCipher cek $ \cipher -> gcmDecrypt cipher iv aad c tag

checkSizes :: (MonadError e m, AsError e) => Enc -> B.ByteString -> B.ByteString -> m ()
checkSizes enc iv cek = do
  unless (B.length cek == cekLength enc) $
    throwing _CryptoError CryptoError_KeySizeInvalid
  unless (B.length iv == ivLength enc) $
    throwing _CryptoError CryptoError_IvSizeInvalid

-- | RFC 7518 §5.2.2.1.  Compute the authentication tag for
-- AES_CBC_HMAC_SHA2.  The tag is truncated to the length of the
-- MAC key.
--
cbcHmacTag
  :: forall h. HashAlgorithm h
  => h
  -> B.ByteString  -- ^ MAC key
  -> B.ByteString  -- ^ Additional Authenticated Data
  -> B.ByteString  -- ^ IV
  -> B.ByteString  -- ^ ciphertext
  -> B.ByteString
cbcHmacTag _ macKey aad iv c =
  B.take (B.length macKey) (BA.convert (hmac macKey macInput :: HMAC h))
  where
    al = be64 (fromIntegral (B.length aad) * 8)
    macInput = B.concat [aad, iv, c, al]

gcmEncrypt
  :: (BlockCipher cipher, MonadError e m, AsError e)
  => cipher
  -> B.ByteString  -- ^ IV
  -> B.ByteString  -- ^ Additional Authenticated Data
  -> B.ByteString  -- ^ plaintext
  -> m (B.ByteString, B.ByteString)  -- ^ ciphertext and tag
gcmEncrypt cipher iv aad m = do
  aead <- cryptoFailable (aeadInit AEAD_GCM cipher iv)
  let (AuthTag tag, c) = aeadSimpleEncrypt aead aad m 16
  pure (c, BA.convert tag)

gcmDecrypt
  :: (BlockCipher cipher, MonadError e m, AsError e)
  => cipher
  -> B.ByteString  -- ^ IV
  -> B.ByteString  -- ^ Additional Authenticated Data
  -> B.ByteString  -- ^ ciphertext
  -> B.ByteString  -- ^ tag
  -> m B.ByteString
gcmDecrypt cipher iv aad c tag = do
  unless (B.length tag == 16) $ throwing_ _JWEIntegrityFailed
  aead <- cryptoFailable (aeadInit AEAD_GCM cipher iv)
  maybe (throwing_ _JWEIntegrityFailed) pure
    (aeadSimpleDecrypt aead aad c (AuthTag (BA.convert tag)))


-- | RFC 7518 §4.4.  Key Wrapping with AES Key Wrap.
--
-- The KEK must be 128, 192 or 256 bits.  The CEK must be a multiple
-- of 64 bits and at least 128 bits.
--
aesKeyWrapCEK
  :: (MonadError e m, AsError e)
  => B.ByteString  -- ^ Key Encryption Key
  -> B.ByteString  -- ^ Content Encryption Key
  -> m B.ByteString
aesKeyWrapCEK kek cek = do
  unless (B.length cek >= 16 && B.length cek `mod` 8 == 0) $
    throwing _CryptoError CryptoError_KeySizeInvalid
  withAESCipher kek $ \cipher -> pure (aesKeyWrap cipher cek)

-- | RFC 7518 §4.4.  Key Unwrapping with AES Key Wrap.
--
-- Throws 'JWEIntegrityFailed' if the integrity check fails.
--
aesKeyUnwrapCEK
  :: (MonadError e m, AsError e)
  => B.ByteString  -- ^ Key Encryption Key
  -> B.ByteString  -- ^ wrapped Content Encryption Key
  -> m B.ByteString
aesKeyUnwrapCEK kek c = do
  unless (B.length c >= 24 && B.length c `mod` 8 == 0) $
    throwing_ _JWEIntegrityFailed
  withAESCipher kek $ \cipher ->
    maybe (throwing_ _JWEIntegrityFailed) pure (aesKeyUnwrap cipher c)


-- | RFC 7518 §4.7.  Key Encryption with AES GCM.
--
-- Returns the (random, 96-bit) Initialization Vector, the
-- Authentication Tag and the encrypted key.
--
aesGCMKeyWrap
  :: (MonadRandom m, MonadError e m, AsError e)
  => B.ByteString  -- ^ Key Encryption Key
  -> B.ByteString  -- ^ Content Encryption Key
  -> m (B.ByteString, B.ByteString, B.ByteString)
aesGCMKeyWrap kek cek = do
  iv <- getRandomBytes 12
  (c, tag) <- withAESCipher kek $ \cipher -> gcmEncrypt cipher iv "" cek
  pure (iv, tag, c)

-- | RFC 7518 §4.7.  Key Decryption with AES GCM.
--
aesGCMKeyUnwrap
  :: (MonadError e m, AsError e)
  => B.ByteString  -- ^ Key Encryption Key
  -> B.ByteString  -- ^ Initialization Vector
  -> B.ByteString  -- ^ Authentication Tag
  -> B.ByteString  -- ^ encrypted Content Encryption Key
  -> m B.ByteString
aesGCMKeyUnwrap kek iv tag c = do
  unless (B.length iv == 12) $ throwing _CryptoError CryptoError_IvSizeInvalid
  withAESCipher kek $ \cipher -> gcmDecrypt cipher iv "" c tag


-- | RFC 7518 §4.2 and §4.3.  Key Encryption with RSAES-PKCS1-v1_5
-- or RSAES OAEP.
--
-- Throws 'AlgorithmMismatch' if the algorithm is not an RSA key
-- encryption algorithm, or 'KeySizeTooSmall' if the key is smaller
-- than 2048 bits.
--
rsaEncryptCEK
  :: (MonadRandom m, MonadError e m, AsError e)
  => Alg
  -> RSAKeyParameters
  -> B.ByteString  -- ^ Content Encryption Key
  -> m B.ByteString
rsaEncryptCEK alg k cek = do
  let Types.Base64Integer n = view rsaN k
  when (n < 2 ^ (2040 :: Integer)) $ throwing_ _KeySizeTooSmall
  let pub = rsaPublicKey k
  r <- case alg of
    RSA1_5        -> PKCS15.encrypt pub cek
    RSA_OAEP      -> OAEP.encrypt (OAEP.defaultOAEPParams SHA1) pub cek
    RSA_OAEP_256  -> OAEP.encrypt (OAEP.defaultOAEPParams SHA256) pub cek
    _ -> throwing _AlgorithmMismatch (show alg <> " is not an RSA key encryption algorithm")
  either (throwing _RSAError) pure r

-- | RFC 7518 §4.2 and §4.3.  Key Decryption with RSAES-PKCS1-v1_5
-- or RSAES OAEP.
--
rsaDecryptCEK
  :: (MonadRandom m, MonadError e m, AsError e)
  => Alg
  -> RSAKeyParameters
  -> B.ByteString  -- ^ encrypted Content Encryption Key
  -> m B.ByteString
rsaDecryptCEK alg k c = do
  priv <- rsaPrivateKey k
  r <- case alg of
    RSA1_5        -> PKCS15.decryptSafer priv c
    RSA_OAEP      -> OAEP.decryptSafer (OAEP.defaultOAEPParams SHA1) priv c
    RSA_OAEP_256  -> OAEP.decryptSafer (OAEP.defaultOAEPParams SHA256) priv c
    _ -> throwing _AlgorithmMismatch (show alg <> " is not an RSA key encryption algorithm")
  either (throwing _RSAError) pure r


-- | RFC 7518 §4.6.  Compute the ECDH shared secret /Z/ from a
-- private key and a public key.  Supports the NIST curves P-256,
-- P-384 and P-521, and the CFRG curves X25519 and X448
-- (<https://tools.ietf.org/html/rfc8037 RFC 8037>).
--
-- Throws 'KeyMismatch' if the keys are of different types or
-- curves, if the private key material is absent, or if the curve
-- is not suitable for use with ECDH-ES.
--
ecdhSharedSecret
  :: (MonadError e m, AsError e)
  => KeyMaterial  -- ^ private key
  -> KeyMaterial  -- ^ public key
  -> m B.ByteString
ecdhSharedSecret (ECKeyMaterial priv) (ECKeyMaterial pub)
  | view ecCrv priv /= view ecCrv pub =
      throwing _KeyMismatch "EC keys are on different curves"
  | view ecCrv priv == Secp256k1 =
      throwing _KeyMismatch "secp256k1 cannot be used for ECDH-ES"
  | otherwise = do
      d <- ecPrivateKey priv
      pure $ BA.convert $ ECDH.getShared (curve (view ecCrv priv)) d (point pub)
ecdhSharedSecret (OKPKeyMaterial (X25519Key _ (Just sk))) (OKPKeyMaterial (X25519Key pk _)) =
  checkNonZero $ BA.convert $ Curve25519.dh pk sk
ecdhSharedSecret (OKPKeyMaterial (X448Key _ (Just sk))) (OKPKeyMaterial (X448Key pk _)) =
  checkNonZero $ BA.convert $ Curve448.dh pk sk
ecdhSharedSecret (OKPKeyMaterial (X25519Key _ Nothing)) (OKPKeyMaterial (X25519Key _ _)) =
  throwing _KeyMismatch "not an X25519 private key"
ecdhSharedSecret (OKPKeyMaterial (X448Key _ Nothing)) (OKPKeyMaterial (X448Key _ _)) =
  throwing _KeyMismatch "not an X448 private key"
ecdhSharedSecret _ _ =
  throwing _KeyMismatch "key pair not suitable for ECDH-ES"

-- Reject the all-zero shared secret that results from a low-order
-- public key (RFC 7748 §6.1).
--
checkNonZero :: (MonadError e m, AsError e) => B.ByteString -> m B.ByteString
checkNonZero z
  | B.all (== 0) z = throwing _KeyMismatch "invalid ECDH public key"
  | otherwise = pure z

-- | The Concat KDF, as defined in Section 5.8.1 of
-- <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-56ar.pdf NIST SP 800-56A>
-- using SHA-256, with the /OtherInfo/ structure specified in
-- <https://tools.ietf.org/html/rfc7518#section-4.6.2 RFC 7518 §4.6.2>.
--
concatKDF
  :: Int           -- ^ length of derived key (in octets)
  -> B.ByteString  -- ^ shared secret /Z/
  -> B.ByteString  -- ^ /AlgorithmID/
  -> B.ByteString  -- ^ /PartyUInfo/ (@"apu"@)
  -> B.ByteString  -- ^ /PartyVInfo/ (@"apv"@)
  -> B.ByteString
concatKDF len z algId apu apv =
  B.take len $ B.concat
    [ BA.convert (hashWith SHA256 (be32 i <> z <> otherInfo)) | i <- [1 .. reps] ]
  where
    reps = (len + 31) `div` 32
    lenPrefixed s = be32 (B.length s) <> s
    otherInfo = B.concat
      [ lenPrefixed algId
      , lenPrefixed apu
      , lenPrefixed apv
      , be32 (len * 8)  -- SuppPubInfo
      ]


-- | RFC 7518 §4.8.  Derive a key using PBES2 (PBKDF2 with HMAC SHA-2)
-- for the given algorithm.  The salt is computed as
-- @UTF8(Alg) || 0x00 || p2s@.
--
-- Throws 'AlgorithmMismatch' if the algorithm is not a PBES2
-- algorithm.
--
pbes2DeriveKey
  :: (MonadError e m, AsError e)
  => Alg
  -> B.ByteString  -- ^ password
  -> B.ByteString  -- ^ salt input (@"p2s"@)
  -> Int           -- ^ iteration count (@"p2c"@)
  -> m B.ByteString
pbes2DeriveKey alg pw p2s p2c = case alg of
  PBES2_HS256_A128KW -> pure $ PBKDF2.fastPBKDF2_SHA256 (params 16) pw (salt "PBES2-HS256+A128KW")
  PBES2_HS384_A192KW -> pure $ PBKDF2.generate (PBKDF2.prfHMAC SHA384) (params 24) pw (salt "PBES2-HS384+A192KW")
  PBES2_HS512_A256KW -> pure $ PBKDF2.fastPBKDF2_SHA512 (params 32) pw (salt "PBES2-HS512+A256KW")
  _ -> throwing _AlgorithmMismatch (show alg <> " is not a PBES2 algorithm")
  where
    params n = PBKDF2.Parameters { PBKDF2.iterCounts = p2c, PBKDF2.outputLength = n }
    salt algName = algName <> B.singleton 0 <> p2s
