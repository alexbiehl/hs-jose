-- Copyright (C) 2015, 2016  Fraser Tweedale
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

{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Properties
  ( properties
  ) where

import Control.Monad.IO.Class

import Control.Lens ((&), over, set, view)
import Crypto.Number.Basic (log2)
import Crypto.Random
import Data.Aeson (FromJSON, ToJSON, decode, encode)
import qualified Data.ByteString as B
import qualified Data.Set as S

import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Test.Tasty
import Test.Tasty.Hedgehog

import Crypto.JOSE.Types
import qualified Crypto.JOSE.JWA.JWE as JWE
import Crypto.JOSE.JWA.JWE (Alg(..), Enc(..))
import Crypto.JOSE.JWE
  ( newJWEHeader, jweP2c, encryptJWE, decryptJWE
  , defaultDecryptionSettings, decryptionSettingsAlgorithms )
import Crypto.JOSE.JWK
import Crypto.JOSE.JWS


instance (MonadIO m) => MonadRandom (PropertyT m) where
  getRandomBytes = liftIO . getRandomBytes

properties :: TestTree
properties = testGroup "Properties"
  [ let n = "SizedBase64Integer round-trip" in testPropertyNamed n n (prop_roundTrip genSizedBase64Integer)
  , let n = "JWK round-trip" in testPropertyNamed n n (prop_roundTrip genJWK')
  , let n = "RSA gen, sign and verify" in testPropertyNamed n n prop_rsaSignAndVerify
  , let n = "gen, sign with best alg, verify" in testPropertyNamed n n prop_bestJWSAlg
  , let n = "JWE gen, encrypt and decrypt" in testPropertyNamed n n prop_jweRoundTrip
  ]

genBigInteger :: Gen Integer
genBigInteger = Gen.integral $ Range.exponential 0 (2 ^ (4096 :: Integer))

genBase64Integer :: Gen Base64Integer
genBase64Integer = Base64Integer <$> genBigInteger

genSizedBase64Integer :: Gen SizedBase64Integer
genSizedBase64Integer = do
  x <- genBigInteger
  l <- Gen.element [0, 1, 2]  -- number of leading zero-bytes
  pure $ SizedBase64Integer ((log2 x `div` 8) + 1 + l) x


prop_roundTrip :: (Eq a, Show a, ToJSON a, FromJSON a) => Gen a -> Property
prop_roundTrip gen = property $
  forAll gen >>= \a -> decode (encode [a]) === Just [a]

prop_rsaSignAndVerify :: Property
prop_rsaSignAndVerify = property $ do
  msg <- forAll $ Gen.bytes (Range.linear 0 100)
  keylen <- forAll $ Gen.element ((`div` 8) <$> [2048, 3072, 4096])
  k <- evalIO $ genJWK (RSAGenParam keylen)
  alg_ <- forAll $ Gen.element [RS256, RS384, RS512, PS256, PS384, PS512]
  collect alg_
  msg' <- evalExceptT $ unwrapJOSE
    ( signJWS msg [(newJWSHeader (Protected, alg_), k)]
      >>= verifyJWS defaultValidationSettings k
      :: JOSE Error (PropertyT IO) B.ByteString
    )
  msg' === msg


genCrv :: Gen Crv
genCrv = Gen.element [P_256, P_384, P_521, Secp256k1]

genOKPCrv :: Gen OKPCrv
genOKPCrv = Gen.element [Ed25519, Ed448, X25519, X448]

genKeyMaterialGenParam :: Gen KeyMaterialGenParam
genKeyMaterialGenParam = Gen.choice
  [ ECGenParam <$> genCrv
  , RSAGenParam <$> Gen.element ((`div` 8) <$> [2048, 3072, 4096])
  , OctGenParam <$> ((+) <$> Gen.integral (Range.exponential 0 64) <*> Gen.element [32, 48, 64])
  , OKPGenParam <$> genOKPCrv
  ]

prop_bestJWSAlg :: Property
prop_bestJWSAlg = property $ do
  msg <- forAll $ Gen.bytes (Range.linear 0 100)

  genParam <- forAll $ genKeyMaterialGenParam
  k <- evalIO $ genJWK genParam

  case bestJWSAlg k of
    Left (KeyMismatch _) -> discard   -- skip non-signing keys
    Left _ -> assert False
    Right alg_ -> do
      collect alg_
      msg' <- evalExceptT $ unwrapJOSE
        ( signJWS msg [(newJWSHeader (Protected, alg_), k)]
          >>= verifyJWS defaultValidationSettings k
          :: JOSE Error (PropertyT IO) B.ByteString
        )
      msg' === msg




genEnc :: Gen JWE.Enc
genEnc = Gen.element
  [A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM, A256GCM]

-- | Generate a JWE key management algorithm along with parameters
-- for generating a suitable key.  For "dir", the key size depends
-- on the content encryption algorithm.
--
genJWEAlgAndKeyParam :: JWE.Enc -> Gen (JWE.Alg, KeyMaterialGenParam)
genJWEAlgAndKeyParam enc_ = Gen.choice
  [ (,) <$> Gen.element [RSA1_5, RSA_OAEP, RSA_OAEP_256] <*> pure (RSAGenParam (2048 `div` 8))
  , Gen.element [(A128KW, OctGenParam 16), (A192KW, OctGenParam 24), (A256KW, OctGenParam 32)]
  , Gen.element [(A128GCMKW, OctGenParam 16), (A192GCMKW, OctGenParam 24), (A256GCMKW, OctGenParam 32)]
  , (,)
    <$> Gen.element [ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW]
    <*> Gen.choice
      [ ECGenParam <$> Gen.element [P_256, P_384, P_521]
      , OKPGenParam <$> Gen.element [X25519, X448]
      ]
  , (,)
    <$> Gen.element [PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW]
    <*> (OctGenParam <$> Gen.integral (Range.linear 1 64))
  , pure (Dir, OctGenParam (JWE.cekLength enc_))
  ]

prop_jweRoundTrip :: Property
prop_jweRoundTrip = property $ do
  msg <- forAll $ Gen.bytes (Range.linear 0 100)
  enc_ <- forAll genEnc
  (alg_, genParam) <- forAll (genJWEAlgAndKeyParam enc_)
  k <- evalIO $ genJWK genParam
  collect (alg_, enc_)
  let
    -- use a small PBES2 iteration count to keep the test fast
    p2c = case alg_ of
      PBES2_HS256_A128KW -> Just 1000
      PBES2_HS384_A192KW -> Just 1000
      PBES2_HS512_A256KW -> Just 1000
      _ -> Nothing
    h = newJWEHeader (Protected, alg_) (Protected, enc_)
      & set jweP2c (HeaderParam Protected <$> p2c)
    conf = defaultDecryptionSettings
      & over decryptionSettingsAlgorithms (S.insert RSA1_5)
  msg' <- evalExceptT $ unwrapJOSE
    ( encryptJWE msg [(h, k)]
      >>= decryptJWE conf k
      :: JOSE Error (PropertyT IO) B.ByteString
    )
  msg' === msg


genRSAPrivateKeyOthElem :: Gen RSAPrivateKeyOthElem
genRSAPrivateKeyOthElem =
  RSAPrivateKeyOthElem <$> genBase64Integer <*> genBase64Integer <*> genBase64Integer

genRSAPrivateKeyOptionalParameters :: Gen RSAPrivateKeyOptionalParameters
genRSAPrivateKeyOptionalParameters =
  RSAPrivateKeyOptionalParameters
    <$> genBase64Integer
    <*> genBase64Integer
    <*> genBase64Integer
    <*> genBase64Integer
    <*> genBase64Integer
    <*> Gen.maybe (Gen.nonEmpty (Range.linear 1 3) genRSAPrivateKeyOthElem)

genRSAPrivateKeyParameters :: Gen RSAPrivateKeyParameters
genRSAPrivateKeyParameters =
  RSAPrivateKeyParameters
    <$> genBase64Integer
    <*> Gen.maybe (genRSAPrivateKeyOptionalParameters)

genRSAKeyParameters :: Gen RSAKeyParameters
genRSAKeyParameters =
  RSAKeyParameters
    <$> genBase64Integer
    <*> genBase64Integer
    <*> Gen.maybe (genRSAPrivateKeyParameters)

genDRG :: Gen ChaChaDRG
genDRG = do
  let word64 = Gen.word64 Range.constantBounded
  seed <- (,,,,) <$> word64 <*> word64 <*> word64 <*> word64 <*> word64
  pure $ drgNewTest seed

genECKeyParameters :: Gen ECKeyParameters
genECKeyParameters = do
    drg <- genDRG
    crv <- genCrv
    let (k, _) = withDRG drg (genEC crv)
    includePrivate <- Gen.bool
    pure $ if includePrivate
      then k
      else (let Just a = view asPublicKey k in a)

genOctKeyParameters :: Gen OctKeyParameters
genOctKeyParameters = OctKeyParameters . Base64Octets <$> Gen.bytes (Range.linear 16 128)

genOKPKeyParameters :: Gen OKPKeyParameters
genOKPKeyParameters = do
  drg <- genDRG
  crv <- genOKPCrv
  let (k, _) = withDRG drg (genOKP crv)
  includePrivate <- Gen.bool
  pure $ if includePrivate
    then k
    else (let Just a = view asPublicKey k in a)

genKeyMaterial' :: Gen KeyMaterial
genKeyMaterial' = Gen.choice
  [ ECKeyMaterial <$> genECKeyParameters
  , RSAKeyMaterial <$> genRSAKeyParameters
  , OctKeyMaterial <$> genOctKeyParameters
  , OKPKeyMaterial <$> genOKPKeyParameters
  ]

genBase64SHA1 :: Gen Base64SHA1
genBase64SHA1 = Base64SHA1 <$> Gen.bytes (Range.singleton 20)

genBase64SHA256 :: Gen Base64SHA256
genBase64SHA256 = Base64SHA256 <$> Gen.bytes (Range.singleton 32)

genJWK' :: Gen JWK
genJWK' = do
  key <- genKeyMaterial'
  kid_ <- Gen.text (Range.linear 8 16) Gen.hexit
  x5t_ <- genBase64SHA1
  x5tS256_ <- genBase64SHA256
  pure $ fromKeyMaterial key
    & set jwkKid (Just kid_)
    & set jwkX5t (Just x5t_)
    & set jwkX5tS256 (Just x5tS256_)
