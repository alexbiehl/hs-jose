-- Copyright (C) 2026  Fraser Tweedale
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

module JWE
  ( spec
  ) where

import Data.Maybe (fromJust, fromMaybe, isJust)

import Control.Lens hiding ((.=))
import Control.Lens.Extras (is)
import Control.Monad.Error.Lens (throwing)
import Data.Aeson
import qualified Data.Aeson.KeyMap as M
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Base64.URL as B64U
import qualified Data.Set as S
import Network.URI (parseURI)
import Test.Hspec

import Crypto.JOSE.Compact
import Crypto.JOSE.JWA.JWE
import Crypto.JOSE.JWE
import Crypto.JOSE.JWK.Store (DecryptionKeyStore)
import qualified Crypto.JOSE.Types as Types


drg :: ChaChaDRG
drg = drgNewTest (1,2,3,4,5)

-- | Run a JOSE computation with a deterministic random generator.
--
runDRG :: JOSE Error (MonadPseudoRandom ChaChaDRG) a -> Either Error a
runDRG = fst . withDRG drg . runJOSE

genKey :: KeyMaterialGenParam -> JWK
genKey = fst . withDRG drg . genJWK

-- | Decryption settings that also allow RSA1_5
allAlgs :: DecryptionSettings
allAlgs = defaultDecryptionSettings
  & decryptionSettingsAlgorithms %~ S.insert RSA1_5

spec :: Spec
spec = do
  headerSpec
  appendixA1Spec
  appendixA2Spec
  appendixA3Spec
  appendixA4Spec
  appendixA5Spec
  ecdhSpec
  roundTripSpec
  errorSpec
  makeJWEHeaderSpec


-- | Build a flattened JWE JSON serialisation with the given protected
-- header (JSON) and per-recipient header (JSON), and dummy
-- ciphertext fields.
--
flattened :: BS.ByteString -> BS.ByteString -> L.ByteString
flattened prot hdr = L.fromStrict $
  "{\"protected\":\"" <> B64U.encodeUnpadded prot <> "\","
  <> "\"header\":" <> hdr <> ","
  <> "\"encrypted_key\":\"\",\"iv\":\"AA\",\"ciphertext\":\"AA\",\"tag\":\"AA\"}"

headerSpec :: Spec
headerSpec = describe "JWE Header" $ do
  it "parses headers correctly" $ do
    let
      -- protected header: {"alg":"A128KW","enc":"A128CBC-HS256"}
      s = "{\"protected\":\"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\
          \\"unprotected\":{\"kid\":\"7\"},\"header\":{\"typ\":\"JWE\"},\
          \\"encrypted_key\":\"AA\",\"iv\":\"AA\",\"ciphertext\":\"AA\",\"tag\":\"AA\"}"
      h = newJWEHeaderProtected A128KW A128CBC_HS256
        & jweKid .~ Just (HeaderParam Unprotected "7")
        & jweTyp .~ Just (HeaderParam Unprotected "JWE")
      jwe = eitherDecode s :: Either String (FlattenedJWE JWEHeader)
    jwe ^? _Right . recipients . recipientHeader `shouldBe` Just h
    jwe ^? _Right . recipients . encryptedKey `shouldBe` Just (BS.pack [0])

  it "rejects duplicate headers" $
    (eitherDecode (flattened "{\"alg\":\"A128KW\",\"enc\":\"A128GCM\"}" "{\"alg\":\"A128KW\"}")
      :: Either String (FlattenedJWE JWEHeader))
      `shouldSatisfy` is _Left

  it "rejects duplicate headers in shared and per-recipient unprotected headers" $
    let
      s = "{\"protected\":\"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\
          \\"unprotected\":{\"kid\":\"7\"},\"header\":{\"kid\":\"8\"},\
          \\"iv\":\"AA\",\"ciphertext\":\"AA\",\"tag\":\"AA\"}"
    in
      (eitherDecode s :: Either String (FlattenedJWE JWEHeader))
        `shouldSatisfy` is _Left

  it "rejects unprotected \"zip\" header" $
    (eitherDecode (flattened "{\"alg\":\"A128KW\",\"enc\":\"A128GCM\"}" "{\"zip\":\"DEF\"}")
      :: Either String (FlattenedJWE JWEHeader))
      `shouldSatisfy` is _Left

  it "accepts protected \"zip\" header" $
    (eitherDecode (flattened "{\"alg\":\"A128KW\",\"enc\":\"A128GCM\",\"zip\":\"DEF\"}" "{}")
      :: Either String (FlattenedJWE JWEHeader))
      ^? _Right . recipients . recipientHeader . jweZip `shouldBe` Just (Just "DEF")

  it "rejects ECDH-ES header without \"epk\"" $
    (eitherDecode (flattened "{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\"}" "{}")
      :: Either String (FlattenedJWE JWEHeader))
      `shouldSatisfy` is _Left

  it "rejects AES GCM key wrap header without \"iv\" and \"tag\"" $
    (eitherDecode (flattened "{\"alg\":\"A128GCMKW\",\"enc\":\"A128GCM\",\"iv\":\"AA\"}" "{}")
      :: Either String (FlattenedJWE JWEHeader))
      `shouldSatisfy` is _Left

  it "rejects PBES2 header without \"p2s\" and \"p2c\"" $
    (eitherDecode (flattened "{\"alg\":\"PBES2-HS256+A128KW\",\"enc\":\"A128GCM\",\"p2c\":1000}" "{}")
      :: Either String (FlattenedJWE JWEHeader))
      `shouldSatisfy` is _Left

  it "rejects non-positive \"p2c\"" $
    (eitherDecode (flattened "{\"alg\":\"PBES2-HS256+A128KW\",\"enc\":\"A128GCM\",\"p2s\":\"AAAAAAAAAAA\",\"p2c\":0}" "{}")
      :: Either String (FlattenedJWE JWEHeader))
      `shouldSatisfy` is _Left

  it "rejects \"p2s\" shorter than 8 octets" $
    (eitherDecode (flattened "{\"alg\":\"PBES2-HS256+A128KW\",\"enc\":\"A128GCM\",\"p2s\":\"AAAA\",\"p2c\":1000}" "{}")
      :: Either String (FlattenedJWE JWEHeader))
      `shouldSatisfy` is _Left

  it "accepts valid PBES2 header" $
    (eitherDecode (flattened "{\"alg\":\"PBES2-HS256+A128KW\",\"enc\":\"A128GCM\",\"p2s\":\"AAAAAAAAAAA\",\"p2c\":1000}" "{}")
      :: Either String (FlattenedJWE JWEHeader))
      ^? _Right . recipients . recipientHeader . jweP2c . _Just . param `shouldBe` Just 1000

  it "rejects reserved crit parameters" $
    (eitherDecode (flattened "{\"alg\":\"A128KW\",\"enc\":\"A128GCM\",\"crit\":[\"kid\"],\"kid\":\"\"}" "{}")
      :: Either String (FlattenedJWE JWEHeader))
      `shouldSatisfy` is _Left

  it "rejects unknown crit parameters" $
    (eitherDecode (flattened "{\"alg\":\"A128KW\",\"enc\":\"A128GCM\",\"crit\":[\"foo\"],\"foo\":\"\"}" "{}")
      :: Either String (FlattenedJWE JWEHeader))
      `shouldSatisfy` is _Left

  it "accepts unprotected \"alg\" param with 'OptionalProtection' protection indicator" $
    (eitherDecode (flattened "{\"enc\":\"A128GCM\"}" "{\"alg\":\"A128KW\"}")
      :: Either String (FlattenedJWE JWEHeader))
      `shouldSatisfy` is _Right

  it "rejects unprotected \"alg\" param with 'RequiredProtection' protection indicator" $
    (eitherDecode (flattened "{\"enc\":\"A128GCM\"}" "{\"alg\":\"A128KW\"}")
      :: Either String (CompactJWE JWEHeader))
      `shouldSatisfy` is _Left

  it "fails to decode flattened JWE when \"recipients\" key is present" $
    let
      s = "{\"protected\":\"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\
          \\"iv\":\"AA\",\"ciphertext\":\"AA\",\"tag\":\"AA\",\"recipients\":[{}]}"
    in
      (eitherDecode s :: Either String (FlattenedJWE JWEHeader))
        `shouldSatisfy` is _Left

  it "preserves raw protected header value on reserialisation" $ do
    let
      check prot = do
        let
          protB64 = B64U.encodeUnpadded prot
          jwe = eitherDecode (flattened prot "{}") :: Either String (FlattenedJWE JWEHeader)
          o = jwe >>= eitherDecode . encode :: Either String Object
        jwe `shouldSatisfy` is _Right
        fmap (M.lookup "protected") o
          `shouldBe` Right (Just (toJSON (Types.Base64Octets prot)))
        -- and the same result after decoding the reserialised object
        (jwe >>= eitherDecode . encode :: Either String (FlattenedJWE JWEHeader))
          `shouldBe` jwe
        protB64 `shouldSatisfy` const True
    check "{\"kid\":\"0\",\"alg\":\"A128KW\",\"enc\":\"A128GCM\"}"
    check "{\"alg\":\"A128KW\",\"enc\":\"A128GCM\",\"kid\":\"0\"}"


-- | Decode the compact JWE and decrypt it with the given settings and key.
--
decryptCompact
  :: DecryptionKeyStore (JOSE Error (MonadPseudoRandom ChaChaDRG)) (JWEHeader RequiredProtection) k
  => DecryptionSettings -> k -> L.ByteString -> Either Error BS.ByteString
decryptCompact conf k s = runDRG $
  decodeCompact s >>= \jwe -> decryptJWE conf k (jwe :: CompactJWE JWEHeader)

-- | Decode JSON, reporting failure as 'JSONDecodeError'
decodeJSON :: FromJSON a => L.ByteString -> Either Error a
decodeJSON = either (Left . JSONDecodeError) Right . eitherDecode

-- | Expected decryption failure
failsWith :: Error -> Either Error BS.ByteString
failsWith = Left

-- | Corrupt the last character of a compact serialisation
tamper :: L.ByteString -> L.ByteString
tamper s = L.init s <> (if L.last s == 65 then "B" else "A")


appendixA1Spec :: Spec
appendixA1Spec = describe "RFC 7516 A.1.  Example JWE using RSAES-OAEP and AES GCM" $ do
  it "decodes the example to the correct value" $ do
    jwe ^? _Right . recipients . recipientHeader `shouldBe` Just h
    jwe ^? _Right . recipients . encryptedKey `shouldBe` Just encryptedKeyOctets

  it "serialises the decoded JWE back to the original data" $
    fmap encodeCompact jwe `shouldBe` Right compactJWE

  it "encrypts the content correctly" $
    encryptContentWithIV A256GCM iv cek aad plaintext
      `shouldBe` (Right (ciphertext, tag) :: Either Error (BS.ByteString, BS.ByteString))

  it "decrypts the content correctly" $
    decryptContent A256GCM cek aad iv ciphertext tag
      `shouldBe` (Right plaintext :: Either Error BS.ByteString)

  it "rejects content with wrong tag" $
    decryptContent A256GCM cek aad iv ciphertext (BS.map (+ 1) tag)
      `shouldBe` (Left JWEIntegrityFailed :: Either Error BS.ByteString)

  it "decrypts the JWE correctly" $
    decryptCompact defaultDecryptionSettings k compactJWE `shouldBe` Right plaintext

  it "fails to decrypt with the wrong key" $
    decryptCompact defaultDecryptionSettings jwkRSA2 compactJWE
      `shouldBe` Left JWEIntegrityFailed

  it "fails to decrypt tampered JWE" $
    decryptCompact defaultDecryptionSettings k (tamper compactJWE)
      `shouldBe` Left JWEIntegrityFailed

  where
    compactJWE = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.\
      \OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe\
      \ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb\
      \Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV\
      \mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8\
      \1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi\
      \6UklfCpIMfIjf7iGdXKHzg.\
      \48V1_ALb6US04U3b.\
      \5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji\
      \SdiwkIr3ajwQzaBtQD_A.\
      \XFBoMYUZodetZdvTiFvSkQ"
    jwe = decodeCompact compactJWE :: Either Error (CompactJWE JWEHeader)
    h = newJWEHeaderProtected RSA_OAEP A256GCM
    plaintext = "The true sign of intelligence is not knowledge but imagination."
    cek = BS.pack
      [177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
       212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
       234, 64, 252]
    iv = BS.pack [227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]
    aad = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"
    ciphertext = BS.pack
      [229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
       233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
       104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
       123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
       160, 109, 64, 63, 192]
    tag = BS.pack
      [92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
       210, 145]
    encryptedKeyOctets = B64U.decodeLenient
      "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe\
      \ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb\
      \Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV\
      \mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8\
      \1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi\
      \6UklfCpIMfIjf7iGdXKHzg" :: BS.ByteString
    k = jwkRSA1

-- | RFC 7516 A.1.3.  Key Encryption (RSA private key)
jwkRSA1 :: JWK
jwkRSA1 = fromJust $ decode "\
  \{\"kty\":\"RSA\",\
  \ \"n\":\"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW\
        \cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S\
        \psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a\
        \sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS\
        \tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj\
        \YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw\",\
  \ \"e\":\"AQAB\",\
  \ \"d\":\"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N\
        \WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9\
        \3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk\
        \qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl\
        \t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd\
        \VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ\"\
  \}"

-- | RFC 7516 A.2.3.  Key Encryption (RSA private key)
jwkRSA2 :: JWK
jwkRSA2 = fromJust $ decode "\
  \{\"kty\":\"RSA\",\
  \ \"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl\
        \UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre\
        \cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_\
        \7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI\
        \Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU\
        \7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\",\
  \ \"e\":\"AQAB\",\
  \ \"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq\
        \1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry\
        \nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_\
        \0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj\
        \-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj\
        \T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\"\
  \}"

-- | RFC 7516 A.3.3.  Key Encryption (symmetric key)
jwkOct3 :: JWK
jwkOct3 = fromJust $ decode "{\"kty\":\"oct\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}"

-- | RFC 7516 A.2 and A.3 plaintext
plaintextA2 :: BS.ByteString
plaintextA2 = "Live long and prosper."

-- | RFC 7516 A.2 and A.3 Content Encryption Key
cekA2 :: BS.ByteString
cekA2 = BS.pack
  [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
   206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
   44, 207]

-- | RFC 7516 A.2 and A.3 Initialization Vector
ivA2 :: BS.ByteString
ivA2 = BS.pack
  [3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101]

-- | RFC 7516 A.2 and A.3 ciphertext
ciphertextA2 :: BS.ByteString
ciphertextA2 = BS.pack
  [40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
   75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143, 112,
   56, 102]

-- | RFC 7516 A.2 encrypted key (RSA1_5)
encryptedKeyA2 :: BS.ByteString
encryptedKeyA2 = B64U.decodeLenient
  "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm\
  \1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc\
  \HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF\
  \NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8\
  \rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv\
  \-B3oWh2TbqmScqXMR4gp_A"

-- | RFC 7516 A.3 encrypted key (A128KW)
encryptedKeyA3 :: BS.ByteString
encryptedKeyA3 = B64U.decodeLenient
  "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"


appendixA2Spec :: Spec
appendixA2Spec = describe "RFC 7516 A.2.  Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256" $ do
  it "decodes the example to the correct value" $ do
    jwe ^? _Right . recipients . recipientHeader `shouldBe` Just h
    jwe ^? _Right . recipients . encryptedKey `shouldBe` Just encryptedKeyA2

  it "serialises the decoded JWE back to the original data" $
    fmap encodeCompact jwe `shouldBe` Right compactJWE

  it "encrypts the content correctly" $
    encryptContentWithIV A128CBC_HS256 ivA2 cekA2 aad plaintextA2
      `shouldBe` (Right (ciphertextA2, tag) :: Either Error (BS.ByteString, BS.ByteString))

  it "decrypts the content correctly" $
    decryptContent A128CBC_HS256 cekA2 aad ivA2 ciphertextA2 tag
      `shouldBe` (Right plaintextA2 :: Either Error BS.ByteString)

  it "rejects content with wrong tag" $
    decryptContent A128CBC_HS256 cekA2 aad ivA2 ciphertextA2 (BS.map (+ 1) tag)
      `shouldBe` (Left JWEIntegrityFailed :: Either Error BS.ByteString)

  it "decrypts the encrypted key correctly" $
    runDRG (rsaDecryptCEK RSA1_5 rsaParams encryptedKeyA2) `shouldBe` Right cekA2

  it "decrypts the JWE correctly when RSA1_5 is allowed" $
    decryptCompact allAlgs jwkRSA2 compactJWE `shouldBe` Right plaintextA2

  it "refuses to decrypt the JWE with the default settings" $
    decryptCompact defaultDecryptionSettings jwkRSA2 compactJWE
      `shouldBe` Left JWENoRecipients

  it "fails to decrypt with the wrong key" $
    decryptCompact allAlgs jwkRSA1 compactJWE `shouldBe` Left JWEIntegrityFailed

  where
    compactJWE = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.\
      \UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm\
      \1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc\
      \HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF\
      \NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8\
      \rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv\
      \-B3oWh2TbqmScqXMR4gp_A.\
      \AxY8DCtDaGlsbGljb3RoZQ.\
      \KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.\
      \9hH0vgRfYgPnAHOd8stkvw"
    jwe = decodeCompact compactJWE :: Either Error (CompactJWE JWEHeader)
    h = newJWEHeaderProtected RSA1_5 A128CBC_HS256
    aad = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
    tag = BS.pack
      [246, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100, 191]
    rsaParams = case view jwkMaterial jwkRSA2 of
      RSAKeyMaterial p -> p
      _ -> error "not an RSA key"


appendixA3Spec :: Spec
appendixA3Spec = describe "RFC 7516 A.3.  Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256" $ do
  it "decodes the example to the correct value" $ do
    jwe ^? _Right . recipients . recipientHeader `shouldBe` Just h
    jwe ^? _Right . recipients . encryptedKey `shouldBe` Just encryptedKeyA3

  it "serialises the decoded JWE back to the original data" $
    fmap encodeCompact jwe `shouldBe` Right compactJWE

  it "wraps the key correctly" $
    aesKeyWrapCEK kek cekA2 `shouldBe` (Right encryptedKeyA3 :: Either Error BS.ByteString)

  it "unwraps the key correctly" $
    aesKeyUnwrapCEK kek encryptedKeyA3 `shouldBe` (Right cekA2 :: Either Error BS.ByteString)

  it "fails to unwrap a corrupted key" $
    aesKeyUnwrapCEK kek (BS.map (+ 1) encryptedKeyA3)
      `shouldBe` (Left JWEIntegrityFailed :: Either Error BS.ByteString)

  it "encrypts the content correctly" $
    encryptContentWithIV A128CBC_HS256 ivA2 cekA2 aad plaintextA2
      `shouldBe` (Right (ciphertextA2, tag) :: Either Error (BS.ByteString, BS.ByteString))

  it "decrypts the JWE correctly" $
    decryptCompact defaultDecryptionSettings jwkOct3 compactJWE `shouldBe` Right plaintextA2

  it "decrypts the JWE correctly using a JWK Set" $
    decryptCompact defaultDecryptionSettings (JWKSet [jwkRSA2, jwkOct3]) compactJWE
      `shouldBe` Right plaintextA2

  it "fails to decrypt tampered JWE" $
    decryptCompact defaultDecryptionSettings jwkOct3 (tamper compactJWE)
      `shouldBe` Left JWEIntegrityFailed

  it "fails to decrypt with the wrong key" $
    decryptCompact defaultDecryptionSettings (genKey (OctGenParam 16)) compactJWE
      `shouldBe` Left JWEIntegrityFailed

  it "encrypts and decrypts with the same key and header" $
    runDRG (encryptJWE plaintextA2 (Identity (h, jwkOct3))
      >>= \jwe' -> decryptJWE' jwkOct3 (jwe' :: CompactJWE JWEHeader))
      `shouldBe` Right plaintextA2

  where
    compactJWE = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.\
      \6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.\
      \AxY8DCtDaGlsbGljb3RoZQ.\
      \KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.\
      \U0m_YmjN04DJvceFICbCVQ"
    jwe = decodeCompact compactJWE :: Either Error (CompactJWE JWEHeader)
    h = newJWEHeaderProtected A128KW A128CBC_HS256
    aad = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
    tag = B64U.decodeLenient "U0m_YmjN04DJvceFICbCVQ"
    kek = B64U.decodeLenient "GawgguFyGrWKav7AX4VKUg"


-- | RFC 7516 A.4.7.  Complete JWE JSON Serialization Representation
--
exampleJWETwoRecipients :: L.ByteString
exampleJWETwoRecipients = "\
  \{\
  \ \"protected\":\
  \  \"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\
  \ \"unprotected\":\
  \  {\"jku\":\"https://server.example.com/keys.jwks\"},\
  \ \"recipients\":[\
  \  {\"header\":\
  \    {\"alg\":\"RSA1_5\",\"kid\":\"2011-04-29\"},\
  \   \"encrypted_key\":\
  \    \"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-\
       \kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx\
       \GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3\
       \YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh\
       \cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg\
       \wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A\"},\
  \  {\"header\":\
  \    {\"alg\":\"A128KW\",\"kid\":\"7\"},\
  \   \"encrypted_key\":\
  \    \"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ\"}],\
  \ \"iv\":\
  \  \"AxY8DCtDaGlsbGljb3RoZQ\",\
  \ \"ciphertext\":\
  \  \"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY\",\
  \ \"tag\":\
  \  \"Mz-VPPyU4RlcuYv1IwIvzw\"\
  \}"

-- | RFC 7516 A.5.  Example JWE Using General JWE JSON Serialization
--
exampleJWEFlattened :: L.ByteString
exampleJWEFlattened = "\
  \{\
  \ \"protected\":\
  \  \"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\
  \ \"unprotected\":\
  \  {\"jku\":\"https://server.example.com/keys.jwks\"},\
  \ \"header\":\
  \  {\"alg\":\"A128KW\",\"kid\":\"7\"},\
  \ \"encrypted_key\":\
  \  \"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ\",\
  \ \"iv\":\
  \  \"AxY8DCtDaGlsbGljb3RoZQ\",\
  \ \"ciphertext\":\
  \  \"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY\",\
  \ \"tag\":\
  \  \"Mz-VPPyU4RlcuYv1IwIvzw\"\
  \}"

-- | Header of the second recipient in A.4 (and the recipient in A.5)
headerA4Oct :: JWEHeader OptionalProtection
headerA4Oct = newJWEHeader (Unprotected, A128KW) (Protected, A128CBC_HS256)
  & jweKid .~ Just (HeaderParam Unprotected "7")
  & jweJku .~ Just (HeaderParam Unprotected jku')
  where jku' = fromJust (parseURI "https://server.example.com/keys.jwks")

appendixA4Spec :: Spec
appendixA4Spec = describe "RFC 7516 A.4.  Example JWE Using General JWE JSON Serialization" $ do
  it "decodes JWE with multiple recipients correctly" $ do
    lengthOf (_Right . recipients) jwe `shouldBe` 2
    jwe ^? _Right . recipients . recipientHeader `shouldBe` Just h1
    jwe ^? _Right . recipients . encryptedKey `shouldBe` Just encryptedKeyA2
    jwe ^? _Right . dropping 1 recipients . recipientHeader `shouldBe` Just headerA4Oct
    jwe ^? _Right . dropping 1 recipients . encryptedKey `shouldBe` Just encryptedKeyA3

  it "fails to decode multi-recipient JWE to 'JWE Identity'" $
    (eitherDecode exampleJWETwoRecipients :: Either String (FlattenedJWE JWEHeader))
      `shouldSatisfy` is _Left

  it "decrypts using the symmetric key" $
    (jwe >>= \j -> runDRG (decryptJWE' jwkOct3 j)) `shouldBe` Right plaintextA2

  it "decrypts using the RSA key when RSA1_5 is allowed" $
    (jwe >>= \j -> runDRG (decryptJWE allAlgs jwkRSA2 j)) `shouldBe` Right plaintextA2

  it "fails to decrypt using the RSA key with the default settings" $
    (jwe >>= \j -> runDRG (decryptJWE' jwkRSA2 j)) `shouldBe` failsWith JWEIntegrityFailed

  it "decrypts using a JWK Set" $
    (jwe >>= \j -> runDRG (decryptJWE' (JWKSet [jwkRSA2, jwkOct3]) j))
      `shouldBe` Right plaintextA2

  it "round-trips through the JSON serialisation" $ do
    let jwe' = jwe >>= decodeJSON . encode :: Either Error (GeneralJWE JWEHeader)
    jwe' `shouldBe` jwe
    (jwe' >>= \j -> runDRG (decryptJWE' jwkOct3 j)) `shouldBe` Right plaintextA2
    fmap (M.member "recipients") (jwe >>= decodeJSON . encode :: Either Error Object)
      `shouldBe` Right True

  where
    jwe = decodeJSON exampleJWETwoRecipients :: Either Error (GeneralJWE JWEHeader)
    h1 = newJWEHeader (Unprotected, RSA1_5) (Protected, A128CBC_HS256)
      & jweKid .~ Just (HeaderParam Unprotected "2011-04-29")
      & jweJku .~ view jweJku headerA4Oct


appendixA5Spec :: Spec
appendixA5Spec = describe "RFC 7516 A.5.  Example JWE Using Flattened JWE JSON Serialization" $ do
  it "decodes flattened JWE to 'JWE Identity' correctly" $ do
    jwe ^? _Right . recipients . recipientHeader `shouldBe` Just headerA4Oct
    jwe ^? _Right . recipients . encryptedKey `shouldBe` Just encryptedKeyA3

  it "decodes flattened JWE to 'JWE []' correctly" $ do
    let jwe' = decodeJSON exampleJWEFlattened :: Either Error (GeneralJWE JWEHeader)
    lengthOf (_Right . recipients) jwe' `shouldBe` 1
    jwe' ^? _Right . recipients . recipientHeader `shouldBe` Just headerA4Oct

  it "decrypts correctly" $
    (jwe >>= \j -> runDRG (decryptJWE' jwkOct3 j)) `shouldBe` Right plaintextA2

  it "round-trips through the JSON serialisation" $ do
    let jwe' = jwe >>= decodeJSON . encode :: Either Error (FlattenedJWE JWEHeader)
    jwe' `shouldBe` jwe
    (jwe' >>= \j -> runDRG (decryptJWE' jwkOct3 j)) `shouldBe` Right plaintextA2
    fmap (M.member "recipients") (jwe >>= decodeJSON . encode :: Either Error Object)
      `shouldBe` Right False

  where
    jwe = decodeJSON exampleJWEFlattened :: Either Error (FlattenedJWE JWEHeader)


ecdhSpec :: Spec
ecdhSpec = describe "RFC 7518 Appendix C.  Example ECDH-ES Key Agreement Computation" $ do
  it "computes the shared secret Z correctly" $
    ecdhSharedSecret (view jwkMaterial alice) (view jwkMaterial bob)
      `shouldBe` (Right z :: Either Error BS.ByteString)

  it "rejects public key without private key material" $
    (ecdhSharedSecret (view jwkMaterial alicePub) (view jwkMaterial bob)
      :: Either Error BS.ByteString) `shouldSatisfy` is _Left

  it "derives the key correctly" $
    concatKDF 16 z "A128GCM" "Alice" "Bob"
      `shouldBe` B64U.decodeLenient "VqqN6vgjbSBcIijNcacQGg"

  it "encrypts to Bob's public key and decrypts with Bob's private key" $ do
    let
      h = newJWEHeaderProtected ECDH_ES A128GCM
        & jweApu .~ Just (HeaderParam RequiredProtection (Types.Base64Octets "Alice"))
        & jweApv .~ Just (HeaderParam RequiredProtection (Types.Base64Octets "Bob"))
      r = runDRG $ do
        jwe <- encryptJWE msg (Identity (h, bobPub))
        jwe' <- decodeCompact (encodeCompact (jwe :: CompactJWE JWEHeader))
        pt <- decryptJWE' bob (jwe' :: CompactJWE JWEHeader)
        pure (jwe' :: CompactJWE JWEHeader, pt)
    fmap snd r `shouldBe` Right msg
    -- ephemeral public key is set, and has no private component
    fmap (isJust . preview (recipients . recipientHeader . jweEpk . _Just . param) . fst) r
      `shouldBe` Right True
    fmap (preview (recipients . recipientHeader . jweEpk . _Just . param . jwkMaterial . to hasPrivate) . fst) r
      `shouldBe` Right (Just False)
    -- other header parameters are preserved
    fmap (preview (recipients . recipientHeader . to (set jweEpk Nothing)) . fst) r
      `shouldBe` Right (Just h)
    -- and the encrypted key is empty
    fmap (preview (recipients . encryptedKey) . fst) r `shouldBe` Right (Just ("" :: BS.ByteString))
    -- Bob's public key cannot decrypt
    (r >>= \(jwe, _) -> runDRG (decryptJWE' bobPub jwe)) `shouldBe` failsWith JWEIntegrityFailed

  where
    msg = "Live long and prosper." :: BS.ByteString
    alice = fromJust $ decode "\
      \{\"kty\":\"EC\",\
      \ \"crv\":\"P-256\",\
      \ \"x\":\"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0\",\
      \ \"y\":\"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps\",\
      \ \"d\":\"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo\"\
      \}" :: JWK
    alicePub = fromJust (view asPublicKey alice)
    bob = fromJust $ decode "\
      \{\"kty\":\"EC\",\
      \ \"crv\":\"P-256\",\
      \ \"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ\",\
      \ \"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\",\
      \ \"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw\"\
      \}" :: JWK
    bobPub = fromJust (view asPublicKey bob)
    z = BS.pack
      [158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
       38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
       140, 254, 144, 196]
    hasPrivate (ECKeyMaterial k) = isJust (view ecD k)
    hasPrivate _ = True


rsaKey, oct16, oct24, oct32, password :: JWK
rsaKey = genKey (RSAGenParam 256)
oct16 = genKey (OctGenParam 16)
oct24 = genKey (OctGenParam 24)
oct32 = genKey (OctGenParam 32)
password = fromOctets ("correct horse battery staple" :: BS.ByteString)

keyDesc :: JWK -> String
keyDesc k = case view jwkMaterial k of
  ECKeyMaterial p -> show (view ecCrv p)
  RSAKeyMaterial _ -> "RSA"
  OctKeyMaterial _ -> "oct"
  OKPKeyMaterial (X25519Key _ _) -> "X25519"
  OKPKeyMaterial (X448Key _ _) -> "X448"
  OKPKeyMaterial _ -> "OKP"

-- | PBES2 iteration count to use in tests (the default is much
-- larger, which would make the tests slow).
--
pbes2Count :: Alg -> Maybe Int
pbes2Count PBES2_HS256_A128KW = Just 1000
pbes2Count PBES2_HS384_A192KW = Just 1000
pbes2Count PBES2_HS512_A256KW = Just 1000
pbes2Count _ = Nothing

roundTripSpec :: Spec
roundTripSpec = describe "encrypt/decrypt round trip" $ do
  let
    encs = [A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM, A256GCM]
    algKeys =
      [ (RSA1_5, rsaKey), (RSA_OAEP, rsaKey), (RSA_OAEP_256, rsaKey)
      , (A128KW, oct16), (A192KW, oct24), (A256KW, oct32)
      , (ECDH_ES, genKey (ECGenParam P_256))
      , (ECDH_ES, genKey (OKPGenParam X448))
      , (ECDH_ES_A128KW, genKey (ECGenParam P_384))
      , (ECDH_ES_A192KW, genKey (ECGenParam P_521))
      , (ECDH_ES_A256KW, genKey (OKPGenParam X25519))
      , (A128GCMKW, oct16), (A192GCMKW, oct24), (A256GCMKW, oct32)
      , (PBES2_HS256_A128KW, password)
      , (PBES2_HS384_A192KW, password)
      , (PBES2_HS512_A256KW, password)
      ]
    msg = "The true sign of intelligence is not knowledge but imagination." :: BS.ByteString

    check (algo, k) enc = it (show algo <> " / " <> show enc <> " / " <> keyDesc k) $ do
      let
        h = newJWEHeaderProtected algo enc
          & jweP2c .~ fmap (HeaderParam RequiredProtection) (pbes2Count algo)
        -- encrypt to the public key, where the key has one
        pub = fromMaybe k (view asPublicKey k)
        r = runDRG $ do
          jwe <- encryptJWE msg (Identity (h, pub))
          jwe' <- decodeCompact (encodeCompact (jwe :: CompactJWE JWEHeader))
          decryptJWE allAlgs k (jwe' :: CompactJWE JWEHeader)
      r `shouldBe` Right msg

  mapM_ (\ak -> mapM_ (check ak) encs) algKeys
  mapM_ (\enc -> check (Dir, genKey (OctGenParam (cekLength enc))) enc) encs

  it "round-trips empty plaintext" $
    runDRG (encryptJWE ("" :: BS.ByteString) (Identity (newJWEHeaderProtected A256KW A128CBC_HS256, oct32))
      >>= \jwe -> decryptJWE' oct32 (jwe :: CompactJWE JWEHeader))
      `shouldBe` Right ("" :: BS.ByteString)

  it "encrypts to multiple recipients using the general JSON serialisation" $ do
    let
      h1 = newJWEHeader (Unprotected, A128KW) (Protected, A256GCM)
        & jweKid .~ Just (HeaderParam Unprotected "oct")
      h2 = newJWEHeader (Unprotected, RSA_OAEP) (Protected, A256GCM)
        & jweKid .~ Just (HeaderParam Unprotected "rsa")
      h3 = newJWEHeader (Unprotected, A128GCMKW) (Protected, A256GCM)
        & jweKid .~ Just (HeaderParam Unprotected "gcmkw")
      r = runDRG $ do
        jwe <- encryptJWEWithAAD ("additional data" :: BS.ByteString) msg
          [(h1, oct16), (h2, fromJust (view asPublicKey rsaKey)), (h3, oct16)]
        o <- either (throwing _JSONDecodeError) pure (eitherDecode (encode (jwe :: GeneralJWE JWEHeader)))
        jwe' <- either (throwing _JSONDecodeError) pure (eitherDecode (encode jwe))
        p1 <- decryptJWE' oct16 (jwe' :: GeneralJWE JWEHeader)
        p2 <- decryptJWE' rsaKey jwe'
        p3 <- decryptJWE' (JWKSet [rsaKey, oct16]) jwe'
        pure (M.member "recipients" (o :: Object), M.member "aad" o, lengthOf recipients jwe', p1, p2, p3)
    r `shouldBe` Right (True, True, 3, msg, msg, msg)

  it "uses the flattened serialisation for a single recipient" $ do
    let
      h = newJWEHeader (Unprotected, A128KW) (Protected, A128GCM)
      r = runDRG $ do
        jwe <- encryptJWE msg [(h, oct16)]
        o <- either (throwing _JSONDecodeError) pure (eitherDecode (encode (jwe :: GeneralJWE JWEHeader)))
        jwe' <- either (throwing _JSONDecodeError) pure (eitherDecode (encode jwe))
        p <- decryptJWE' oct16 (jwe' :: FlattenedJWE JWEHeader)
        pure (M.member "recipients" (o :: Object), M.member "header" o, p)
    r `shouldBe` Right (False, True, msg)


errorSpec :: Spec
errorSpec = describe "error handling" $ do
  let
    msg = "Live long and prosper." :: BS.ByteString
    encryptGeneral
      :: [(JWEHeader OptionalProtection, JWK)] -> Either Error (GeneralJWE JWEHeader)
    encryptGeneral = runDRG . encryptJWE msg
    encryptCompact
      :: JWEHeader RequiredProtection -> JWK -> Either Error (CompactJWE JWEHeader)
    encryptCompact h k = runDRG (encryptJWE msg (Identity (h, k)))
    isAlgorithmMismatch = \case Left (AlgorithmMismatch _) -> True; _ -> False
    isKeyMismatch = \case Left (KeyMismatch _) -> True; _ -> False

  it "rejects direct encryption with multiple recipients" $
    encryptGeneral
      [ (newJWEHeaderProtected Dir A128GCM, oct16)
      , (newJWEHeaderProtected Dir A128GCM, oct16) ]
      `shouldSatisfy` isAlgorithmMismatch

  it "rejects direct key agreement with multiple recipients" $
    encryptGeneral
      [ (newJWEHeader (Unprotected, ECDH_ES) (Protected, A128GCM), genKey (ECGenParam P_256))
      , (newJWEHeader (Unprotected, ECDH_ES) (Protected, A128GCM), genKey (ECGenParam P_256)) ]
      `shouldSatisfy` isAlgorithmMismatch

  it "rejects recipients with different content encryption algorithms" $
    encryptGeneral
      [ (newJWEHeaderProtected A128KW A128GCM, oct16)
      , (newJWEHeaderProtected A256KW A256GCM, oct32) ]
      `shouldSatisfy` isAlgorithmMismatch

  it "rejects recipients with different protected headers" $
    encryptGeneral
      [ (newJWEHeaderProtected A128KW A128GCM & jweKid .~ Just (HeaderParam Protected "a"), oct16)
      , (newJWEHeaderProtected A128KW A128GCM & jweKid .~ Just (HeaderParam Protected "b"), oct16) ]
      `shouldBe` Left JWEProtectedHeaderMismatch

  it "rejects empty recipient list" $
    encryptGeneral [] `shouldBe` Left JWENoRecipients

  it "rejects key of wrong type" $ do
    encryptCompact (newJWEHeaderProtected A128KW A128GCM) rsaKey
      `shouldSatisfy` isAlgorithmMismatch
    encryptCompact (newJWEHeaderProtected RSA_OAEP A128GCM) oct16
      `shouldSatisfy` isAlgorithmMismatch
    encryptCompact (newJWEHeaderProtected ECDH_ES A128GCM) oct16
      `shouldSatisfy` isKeyMismatch
    encryptCompact (newJWEHeaderProtected ECDH_ES A128GCM) (genKey (OKPGenParam Ed25519))
      `shouldSatisfy` isKeyMismatch
    encryptCompact (newJWEHeaderProtected ECDH_ES A128GCM) (genKey (ECGenParam Secp256k1))
      `shouldSatisfy` isKeyMismatch

  it "rejects symmetric key of wrong size" $ do
    encryptCompact (newJWEHeaderProtected A128KW A128GCM) oct32
      `shouldSatisfy` isKeyMismatch
    encryptCompact (newJWEHeaderProtected A256GCMKW A128GCM) oct16
      `shouldSatisfy` isKeyMismatch
    encryptCompact (newJWEHeaderProtected Dir A256GCM) oct16
      `shouldSatisfy` \case Left (CryptoError _) -> True; _ -> False

  it "prohibits encrypting to 1024-bit RSA key" $
    encryptCompact (newJWEHeaderProtected RSA_OAEP A128GCM) jwkRSA1024
      `shouldBe` Left KeySizeTooSmall

  it "fails with JWENoRecipients when no recipient uses an acceptable algorithm" $ do
    let
      jwe = encryptCompact (newJWEHeaderProtected A128KW A128GCM) oct16
      conf = defaultDecryptionSettings & decryptionSettingsAlgorithms .~ S.empty
      conf' = defaultDecryptionSettings & decryptionSettingsEncryptionAlgorithms .~ S.empty
    (jwe >>= runDRG . decryptJWE conf oct16) `shouldBe` failsWith JWENoRecipients
    (jwe >>= runDRG . decryptJWE conf' oct16) `shouldBe` failsWith JWENoRecipients

  it "fails with NoUsableKeys when the key store is empty" $
    (encryptCompact (newJWEHeaderProtected A128KW A128GCM) oct16
      >>= runDRG . decryptJWE' (JWKSet []))
      `shouldBe` failsWith NoUsableKeys

  it "fails with JWEIntegrityFailed for wrong key" $
    (encryptCompact (newJWEHeaderProtected A128KW A128GCM) oct16
      >>= runDRG . decryptJWE' (genKey (OctGenParam 16) & jwkMaterial .~ view jwkMaterial (fromOctets (BS.replicate 16 1))))
      `shouldBe` failsWith JWEIntegrityFailed

  it "fails with AlgorithmNotImplemented for compressed content" $ do
    let
      jwe = eitherDecode
        (flattened "{\"alg\":\"A128KW\",\"enc\":\"A128GCM\",\"zip\":\"DEF\"}" "{}")
        :: Either String (FlattenedJWE JWEHeader)
    (either (Left . JSONDecodeError) Right jwe >>= runDRG . decryptJWE' oct16)
      `shouldBe` failsWith AlgorithmNotImplemented

  it "fails when PBES2 iteration count exceeds the maximum" $ do
    let
      h = newJWEHeaderProtected PBES2_HS256_A128KW A128GCM
        & jweP2c .~ Just (HeaderParam RequiredProtection 1000)
      jwe = encryptCompact h password
      conf = defaultDecryptionSettings & decryptionSettingsMaxPBES2Count .~ 999
    (jwe >>= runDRG . decryptJWE conf password) `shouldBe` failsWith JWEIntegrityFailed
    (jwe >>= runDRG . decryptJWE' password) `shouldBe` Right msg

  it "fails to decode compact serialisation with wrong number of parts" $
    (decodeCompact "a.b.c.d" :: Either Error (CompactJWE JWEHeader))
      `shouldBe` Left (CompactDecodeError (CompactInvalidNumberOfParts (InvalidNumberOfParts 5 4)))


makeJWEHeaderSpec :: Spec
makeJWEHeaderSpec = describe "makeJWEHeader" $ do
  it "chooses RSA-OAEP-256 for RSA keys and copies \"kid\"" $
    (makeJWEHeader (rsaKey & jwkKid .~ Just "k1") A256GCM
      :: Either Error (JWEHeader RequiredProtection))
      `shouldBe` Right (newJWEHeaderProtected RSA_OAEP_256 A256GCM
                          & jweKid .~ Just (HeaderParam RequiredProtection "k1"))

  it "chooses AES Key Wrap for symmetric keys" $ do
    fmap (view (jweAlg . param)) (makeJWEHeader oct16 A128GCM :: Either Error (JWEHeader RequiredProtection))
      `shouldBe` Right A128KW
    fmap (view (jweAlg . param)) (makeJWEHeader oct24 A128GCM :: Either Error (JWEHeader RequiredProtection))
      `shouldBe` Right A192KW
    fmap (view (jweAlg . param)) (makeJWEHeader oct32 A128GCM :: Either Error (JWEHeader RequiredProtection))
      `shouldBe` Right A256KW

  it "chooses ECDH-ES for EC and X25519/X448 keys" $ do
    fmap (view (jweAlg . param)) (makeJWEHeader (genKey (ECGenParam P_256)) A128GCM :: Either Error (JWEHeader RequiredProtection))
      `shouldBe` Right ECDH_ES
    fmap (view (jweAlg . param)) (makeJWEHeader (genKey (OKPGenParam X25519)) A128GCM :: Either Error (JWEHeader RequiredProtection))
      `shouldBe` Right ECDH_ES

  it "rejects keys that cannot be used for key management" $ do
    (makeJWEHeader (genKey (OKPGenParam Ed25519)) A128GCM :: Either Error (JWEHeader RequiredProtection))
      `shouldSatisfy` \case Left (KeyMismatch _) -> True; _ -> False
    (makeJWEHeader jwkRSA1024 A128GCM :: Either Error (JWEHeader RequiredProtection))
      `shouldBe` Left KeySizeTooSmall


jwkRSA1024 :: JWK
jwkRSA1024 = fromJust $ decode $
  "{\"qi\":\"qYMpiKTOyFktv0Z3pQbig1RNA1xH35HMtjwISviC_bGo2zvzrYztBC_RzWsw"
  <> "3Nwsc32n65HIdpNbau1UhB3EwQ\","
  <> "\"p\":\"3ovj_M4MMJamOtjhtjswZhhwSYBiK6f2TjIEWiji-XV9SRcoyJsnp5flpeX"
  <> "VTEXS_PgLmjtUi2MLGAvXLlTtyQ\","
  <> "\"n\":\"yy1luWS19u8F-9eAdJ2iwCvuFrjOKuj1YBeNegPZpMJ9mhi8YISQLg-FTFR"
  <> "J68FzMeZM0liJq9mm-tNfPsNFxU7VM_sha2jWuJI32u3W5m7myTb8vNjHAd8acvuIRJ"
  <> "3hoJpJtSc1XBHHHIUK6lXNepHwQMjSCWtTY2wjRMKvYBU\","
  <> "\"q\":\"6bgjSNOcMzZMh64q66kIU68_U6wHwdbSFyLLtwVORsEYPhQUjWEoO7thY9j"
  <> "7m5NLRWgumoPIdDlLhOOnEf_V7Q\","
  <> "\"d\":\"Mordhkv-VCpLs8V9KAVayjFjbfWVG-mNuNTDFfpFNw5GzoGewufXMg4cW8u"
  <> "QA_zAmkYvEBiETuK6_iR8yhErlqMwFA4mdS4Yq0OqOPd9rCalUOoJf8cV1W5scsWXmL"
  <> "-xX_TmnGnIpjYcDJw6Zw0KP7hvHKPTPUriY2Zb--LLhaE\","
  <> "\"dp\":\"EgxgUglX3bzqAE3EiGXmd_E1chCSZZ36kL7nsXQtbDPGFF5ndVV38tST0E"
  <> "-Ca-whv1hSgJCdO6ytoqabLeu_WQ\","
  <> "\"e\":\"AQAB\","
  <> "\"dq\":\"3gLqkY1hvUwBGomZf85LeKLp9uNdYwZa_1swRCSoHJHkI2QTudDm1QbEFo"
  <> "LRTxF12PKEAobYbX7Xe958n550aQ\","
  <> "\"kty\":\"RSA\"}"
