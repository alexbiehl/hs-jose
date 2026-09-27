-- Copyright (C) 2015, 2016, 2026  Fraser Tweedale
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

{-|

JSON Web Encryption (JWE) represents encrypted content using
JavaScript Object Notation (JSON) based data structures.  It is
defined in <https://tools.ietf.org/html/rfc7516 RFC 7516>.

@
import Crypto.JOSE

doJweEncrypt :: 'JWK' -> L.ByteString -> IO (Either 'Error' ('CompactJWE' 'JWEHeader'))
doJweEncrypt jwk plaintext = 'runJOSE' $ do
  h \<- 'makeJWEHeader' jwk 'A256GCM'
  'encryptJWE' plaintext (Identity (h, jwk))

doJweDecrypt :: 'JWK' -> 'CompactJWE' 'JWEHeader' -> IO (Either 'Error' L.ByteString)
doJweDecrypt jwk jwe = 'runJOSE' $
  'decryptJWE'' jwk jwe
@

All content encryption algorithms defined in RFC 7518 are
supported, as are all key management algorithms.  The @"zip"@
(compression) header parameter is recognised but compression is
not implemented; decryption of a JWE that uses compression fails
with 'AlgorithmNotImplemented'.

__Note__: this module exports the JWE 'Alg' type, and
"Crypto.JOSE.JWS" exports the JWS 'Crypto.JOSE.JWA.JWS.Alg' type.
If you import both modules unqualified you will need to qualify
uses of the /type/ name (the constructors do not conflict).

-}

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE UndecidableInstances #-}

module Crypto.JOSE.JWE
  (
  -- * Overview
    JWE
  , GeneralJWE
  , FlattenedJWE
  , CompactJWE

  -- ** Defining additional header parameters
  -- $extending

  -- * JWE creation
  , newJWEHeader
  , newJWEHeaderProtected
  , makeJWEHeader
  , encryptJWE
  , encryptJWEWithAAD

  -- * JWE decryption
  , decryptJWE
  , decryptJWE'

  -- ** JWE decryption settings
  , defaultDecryptionSettings
  , DecryptionSettings
  , HasDecryptionSettings(..)

  -- * Recipient data
  , recipients
  , Recipient
  , recipientHeader
  , encryptedKey

  -- * JWE headers
  , Alg(..)
  , Enc(..)
  , HasJWEHeader(..)
  , JWEHeader
  , jweAlg
  , jweEnc
  , jweZip
  , jweJku
  , jweJwk
  , jweKid
  , jweX5u
  , jweX5c
  , jweX5t
  , jweX5tS256
  , jweTyp
  , jweCty
  , jweCrit
  , jweEpk
  , jweApu
  , jweApv
  , jweIv
  , jweTag
  , jweP2s
  , jweP2c

  , module Crypto.JOSE.Error
  , module Crypto.JOSE.Header
  , module Crypto.JOSE.JWK
  ) where

import Control.Applicative ((<|>))
import Control.Monad (unless, when)
import Data.Foldable (toList)
import Data.List (nub)
import Data.Maybe (catMaybes, fromMaybe, isJust, isNothing)
import Data.List.NonEmpty (NonEmpty)
import Data.Word (Word8)

import Control.Lens hiding ((.=))
import Control.Lens.Cons.Extras (recons)
import Control.Monad.Error.Lens (throwing, throwing_)
import Control.Monad.Except (MonadError, catchError)
import Control.Monad.State (StateT(..), runStateT)
import Crypto.Error (CryptoError(..))
import Data.Aeson
import Data.Aeson.Types (Pair, Parser)
import qualified Data.Aeson.KeyMap as M
import qualified Data.ByteString as B
import qualified Data.Set as S
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

import Crypto.JOSE.Compact
import Crypto.JOSE.Error
import Crypto.JOSE.Header
import Crypto.JOSE.JWA.JWE
import Crypto.JOSE.JWK
import Crypto.JOSE.JWK.Store
import qualified Crypto.JOSE.Types as Types
import Crypto.JOSE.Types.URI
import qualified Crypto.JOSE.Types.Internal as Types

{- $extending

Several specifications extend JWE with additional header parameters.
The 'JWE' type is parameterised over the header type; this library
provides the 'JWEHeader' type which encompasses all the JWE header
parameters defined in RFC 7515 and RFC 7518.  To define an extended
header type declare the data type, and instances for 'HasJWEHeader'
and 'HasParams'.  For example:

@
data ExtHeader p = ExtHeader
  { _extJweHeader :: 'JWEHeader' p
  , _extNonce :: 'Types.Base64Octets'
  }

extJweHeader :: Lens' (ExtHeader p) (JWEHeader p)
extJweHeader f s\@(ExtHeader { _extJweHeader = a}) =
  fmap (\\a' -> s { _extJweHeader = a'}) (f a)

extNonce :: Lens' (ExtHeader p) Types.Base64Octets
extNonce f s\@(ExtHeader { _extNonce = a}) =
  fmap (\\a' -> s { _extNonce = a'}) (f a)

instance HasJWEHeader ExtHeader where
  jweHeader = extJweHeader

instance HasParams ExtHeader where
  'parseParamsFor' proxy hp hu = ExtHeader
    \<$> 'parseParamsFor' proxy hp hu
    \<*> 'headerRequiredProtected' "nonce" hp hu
  params h =
    (True, "nonce" .= view extNonce h)
    : 'params' (view extJweHeader h)
  'extensions' = const ["nonce"]
@

See also:

- 'HasParams'
- 'headerRequired'
- 'headerRequiredProtected'
- 'headerOptional'
- 'headerOptional''
- 'headerOptionalProtected'

-}


jweCritInvalidNames :: [T.Text]
jweCritInvalidNames = [
  "alg"
  , "enc"
  , "zip"
  , "jku"
  , "jwk"
  , "kid"
  , "x5u"
  , "x5c"
  , "x5t"
  , "x5t#S256"
  , "typ"
  , "cty"
  , "crit"
  , "epk"
  , "apu"
  , "apv"
  , "iv"
  , "tag"
  , "p2s"
  , "p2c"
  ]

-- | JWE Header data type.
--
-- In addition to the header parameters defined in RFC 7516, this
-- type includes the header parameters used by the key management
-- algorithms defined in RFC 7518: @"epk"@, @"apu"@ and @"apv"@
-- (ECDH-ES), @"iv"@ and @"tag"@ (AES GCM key wrapping) and @"p2s"@
-- and @"p2c"@ (PBES2).
--
data JWEHeader p = JWEHeader
  { _jweHeaderAlg :: HeaderParam p Alg
  , _jweHeaderEnc :: HeaderParam p Enc
  , _jweHeaderZip :: Maybe T.Text  -- ^ Compression algorithm; protected header only
  , _jweHeaderJku :: Maybe (HeaderParam p Types.URI)  -- ^ JWK Set URL
  , _jweHeaderJwk :: Maybe (HeaderParam p JWK)
  , _jweHeaderKid :: Maybe (HeaderParam p T.Text)  -- ^ interpretation unspecified
  , _jweHeaderX5u :: Maybe (HeaderParam p Types.URI)
  , _jweHeaderX5c :: Maybe (HeaderParam p (NonEmpty Types.SignedCertificate))
  , _jweHeaderX5t :: Maybe (HeaderParam p Types.Base64SHA1)
  , _jweHeaderX5tS256 :: Maybe (HeaderParam p Types.Base64SHA256)
  , _jweHeaderTyp :: Maybe (HeaderParam p T.Text)  -- ^ Content Type (of object)
  , _jweHeaderCty :: Maybe (HeaderParam p T.Text)  -- ^ Content Type (of payload)
  , _jweHeaderCrit :: Maybe (NonEmpty T.Text)
  , _jweHeaderEpk :: Maybe (HeaderParam p JWK)  -- ^ Ephemeral Public Key
  , _jweHeaderApu :: Maybe (HeaderParam p Types.Base64Octets)  -- ^ Agreement PartyUInfo
  , _jweHeaderApv :: Maybe (HeaderParam p Types.Base64Octets)  -- ^ Agreement PartyVInfo
  , _jweHeaderIv :: Maybe (HeaderParam p Types.Base64Octets)  -- ^ Key wrapping Initialization Vector
  , _jweHeaderTag :: Maybe (HeaderParam p Types.Base64Octets)  -- ^ Key wrapping Authentication Tag
  , _jweHeaderP2s :: Maybe (HeaderParam p Types.Base64Octets)  -- ^ PBES2 Salt Input
  , _jweHeaderP2c :: Maybe (HeaderParam p Int)  -- ^ PBES2 Count
  }
  deriving (Eq, Show)

class HasJWEHeader a where
  jweHeader :: Lens' (a p) (JWEHeader p)

instance HasJWEHeader JWEHeader where
  jweHeader = id

-- | @"alg"@ (Algorithm) Header Parameter
jweAlg :: HasJWEHeader a => Lens' (a p) (HeaderParam p Alg)
jweAlg = jweHeader . \f h@(JWEHeader { _jweHeaderAlg = a }) ->
  fmap (\a' -> h { _jweHeaderAlg = a' }) (f a)

-- | @"enc"@ (Encryption Algorithm) Header Parameter
jweEnc :: HasJWEHeader a => Lens' (a p) (HeaderParam p Enc)
jweEnc = jweHeader . \f h@(JWEHeader { _jweHeaderEnc = a }) ->
  fmap (\a' -> h { _jweHeaderEnc = a' }) (f a)

-- | @"zip"@ (Compression Algorithm) Header Parameter.  Compression
-- is not implemented; this parameter is recognised for
-- interoperability only.
jweZip :: HasJWEHeader a => Lens' (a p) (Maybe T.Text)
jweZip = jweHeader . \f h@(JWEHeader { _jweHeaderZip = a }) ->
  fmap (\a' -> h { _jweHeaderZip = a' }) (f a)

-- | @"jku"@ (JWK Set URL) Header Parameter
jweJku :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p Types.URI))
jweJku = jweHeader . \f h@(JWEHeader { _jweHeaderJku = a }) ->
  fmap (\a' -> h { _jweHeaderJku = a' }) (f a)

-- | @"jwk"@ (JSON Web Key) Header Parameter
jweJwk :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p JWK))
jweJwk = jweHeader . \f h@(JWEHeader { _jweHeaderJwk = a }) ->
  fmap (\a' -> h { _jweHeaderJwk = a' }) (f a)

-- | @"kid"@ (Key ID) Header Parameter
jweKid :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p T.Text))
jweKid = jweHeader . \f h@(JWEHeader { _jweHeaderKid = a }) ->
  fmap (\a' -> h { _jweHeaderKid = a' }) (f a)

-- | @"x5u"@ (X.509 URL) Header Parameter
jweX5u :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p Types.URI))
jweX5u = jweHeader . \f h@(JWEHeader { _jweHeaderX5u = a }) ->
  fmap (\a' -> h { _jweHeaderX5u = a' }) (f a)

-- | @"x5c"@ (X.509 Certificate Chain) Header Parameter
jweX5c :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p (NonEmpty Types.SignedCertificate)))
jweX5c = jweHeader . \f h@(JWEHeader { _jweHeaderX5c = a }) ->
  fmap (\a' -> h { _jweHeaderX5c = a' }) (f a)

-- | @"x5t"@ (X.509 Certificate SHA-1 Thumbprint) Header Parameter
jweX5t :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p Types.Base64SHA1))
jweX5t = jweHeader . \f h@(JWEHeader { _jweHeaderX5t = a }) ->
  fmap (\a' -> h { _jweHeaderX5t = a' }) (f a)

-- | @"x5t#S256"@ (X.509 Certificate SHA-256 Thumbprint) Header Parameter
jweX5tS256 :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p Types.Base64SHA256))
jweX5tS256 = jweHeader . \f h@(JWEHeader { _jweHeaderX5tS256 = a }) ->
  fmap (\a' -> h { _jweHeaderX5tS256 = a' }) (f a)

-- | @"typ"@ (Type) Header Parameter
jweTyp :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p T.Text))
jweTyp = jweHeader . \f h@(JWEHeader { _jweHeaderTyp = a }) ->
  fmap (\a' -> h { _jweHeaderTyp = a' }) (f a)

-- | @"cty"@ (Content Type) Header Parameter
jweCty :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p T.Text))
jweCty = jweHeader . \f h@(JWEHeader { _jweHeaderCty = a }) ->
  fmap (\a' -> h { _jweHeaderCty = a' }) (f a)

-- | @"crit"@ (Critical) Header Parameter
jweCrit :: HasJWEHeader a => Lens' (a p) (Maybe (NonEmpty T.Text))
jweCrit = jweHeader . \f h@(JWEHeader { _jweHeaderCrit = a }) ->
  fmap (\a' -> h { _jweHeaderCrit = a' }) (f a)

-- | @"epk"@ (Ephemeral Public Key) Header Parameter.  Used with the
-- ECDH-ES algorithms; set automatically by 'encryptJWE'.
jweEpk :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p JWK))
jweEpk = jweHeader . \f h@(JWEHeader { _jweHeaderEpk = a }) ->
  fmap (\a' -> h { _jweHeaderEpk = a' }) (f a)

-- | @"apu"@ (Agreement PartyUInfo) Header Parameter.  Used with the
-- ECDH-ES algorithms.
jweApu :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p Types.Base64Octets))
jweApu = jweHeader . \f h@(JWEHeader { _jweHeaderApu = a }) ->
  fmap (\a' -> h { _jweHeaderApu = a' }) (f a)

-- | @"apv"@ (Agreement PartyVInfo) Header Parameter.  Used with the
-- ECDH-ES algorithms.
jweApv :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p Types.Base64Octets))
jweApv = jweHeader . \f h@(JWEHeader { _jweHeaderApv = a }) ->
  fmap (\a' -> h { _jweHeaderApv = a' }) (f a)

-- | @"iv"@ (Initialization Vector) Header Parameter.  Used with the
-- AES GCM key wrapping algorithms; set automatically by 'encryptJWE'.
jweIv :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p Types.Base64Octets))
jweIv = jweHeader . \f h@(JWEHeader { _jweHeaderIv = a }) ->
  fmap (\a' -> h { _jweHeaderIv = a' }) (f a)

-- | @"tag"@ (Authentication Tag) Header Parameter.  Used with the
-- AES GCM key wrapping algorithms; set automatically by 'encryptJWE'.
jweTag :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p Types.Base64Octets))
jweTag = jweHeader . \f h@(JWEHeader { _jweHeaderTag = a }) ->
  fmap (\a' -> h { _jweHeaderTag = a' }) (f a)

-- | @"p2s"@ (PBES2 Salt Input) Header Parameter.  Used with the
-- PBES2 algorithms.  If not set, 'encryptJWE' generates a random
-- 128-bit salt.
jweP2s :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p Types.Base64Octets))
jweP2s = jweHeader . \f h@(JWEHeader { _jweHeaderP2s = a }) ->
  fmap (\a' -> h { _jweHeaderP2s = a' }) (f a)

-- | @"p2c"@ (PBES2 Count) Header Parameter.  Used with the PBES2
-- algorithms.  If not set, 'encryptJWE' uses an iteration count of
-- 100000.
jweP2c :: HasJWEHeader a => Lens' (a p) (Maybe (HeaderParam p Int))
jweP2c = jweHeader . \f h@(JWEHeader { _jweHeaderP2c = a }) ->
  fmap (\a' -> h { _jweHeaderP2c = a' }) (f a)


-- | Construct a minimal header with the given algorithms and
-- protection values for the @"alg"@ and @"enc"@ headers.
--
newJWEHeader :: (p, Alg) -> (p, Enc) -> JWEHeader p
newJWEHeader a e =
  JWEHeader (uncurry HeaderParam a) (uncurry HeaderParam e)
    z z z z z z z z z z z z z z z z z z
  where z = Nothing

-- | Construct a minimal JWE header with the given @"alg"@ and
-- @"enc"@ header values, to be carried as protected headers.
--
newJWEHeaderProtected :: (ProtectionSupport p) => Alg -> Enc -> JWEHeader p
newJWEHeaderProtected a e = newJWEHeader (getProtected, a) (getProtected, e)

-- | Make a JWE header for the given recipient key and content
-- encryption algorithm.
--
-- Uses 'bestJWEAlg' to choose the key management algorithm.
-- If set, the JWK's @"kid"@, @"x5u"@, @"x5c"@, @"x5t"@ and
-- @"x5t#S256"@ parameters are copied to the JWE header (as
-- protected parameters).
--
-- May return 'KeySizeTooSmall' or 'KeyMismatch'.
--
makeJWEHeader
  :: forall e m p. (MonadError e m, AsError e, ProtectionSupport p)
  => JWK
  -> Enc
  -> m (JWEHeader p)
makeJWEHeader k enc = do
  let
    p = getProtected
    f :: ASetter s t a (Maybe (HeaderParam p a1))
      -> Getting (Maybe a1) JWK (Maybe a1)
      -> s -> t
    f lh lk = set lh (HeaderParam p <$> view lk k)
  algo <- bestJWEAlg k
  pure $ newJWEHeader (p, algo) (p, enc)
    & f jweKid (jwkKid . to (fmap (view recons)))
    & f jweX5u jwkX5u
    & f jweX5c jwkX5c
    & f jweX5t jwkX5t
    & f jweX5tS256 jwkX5tS256


instance HasParams JWEHeader where
  parseParamsFor proxy hp hu = checkAlgParams =<< (JWEHeader
    <$> headerRequired "alg" hp hu
    <*> headerRequired "enc" hp hu
    <*> headerOptionalProtected "zip" hp hu
    <*> headerOptional' uriFromJSON "jku" hp hu
    <*> headerOptional "jwk" hp hu
    <*> headerOptional "kid" hp hu
    <*> headerOptional' uriFromJSON "x5u" hp hu
    <*> (fmap . fmap . fmap . fmap)
          (\(Types.Base64X509 cert) -> cert) (headerOptional "x5c" hp hu)
    <*> headerOptional "x5t" hp hu
    <*> headerOptional "x5t#S256" hp hu
    <*> headerOptional "typ" hp hu
    <*> headerOptional "cty" hp hu
    <*> (headerOptionalProtected "crit" hp hu
      >>= parseCrit jweCritInvalidNames (extensions proxy)
        (fromMaybe mempty hp <> fromMaybe mempty hu))
    <*> headerOptional "epk" hp hu
    <*> headerOptional "apu" hp hu
    <*> headerOptional "apv" hp hu
    <*> headerOptional "iv" hp hu
    <*> headerOptional "tag" hp hu
    <*> headerOptional' p2sFromJSON "p2s" hp hu
    <*> headerOptional' p2cFromJSON "p2c" hp hu
    )
  params h =
    catMaybes
      [ Just (view (jweAlg . isProtected) h, "alg" .= view (jweAlg . param) h)
      , Just (view (jweEnc . isProtected) h, "enc" .= view (jweEnc . param) h)
      , fmap (\p -> (True, "zip" .= p)) (view jweZip h)
      , fmap (\p -> (view isProtected p, "jku" .= views param uriToJSON p)) (view jweJku h)
      , fmap (\p -> (view isProtected p, "jwk" .= view param p)) (view jweJwk h)
      , fmap (\p -> (view isProtected p, "kid" .= view param p)) (view jweKid h)
      , fmap (\p -> (view isProtected p, "x5u" .= views param uriToJSON p)) (view jweX5u h)
      , fmap (\p -> (view isProtected p, "x5c" .= fmap Types.Base64X509 (view param p))) (view jweX5c h)
      , fmap (\p -> (view isProtected p, "x5t" .= view param p)) (view jweX5t h)
      , fmap (\p -> (view isProtected p, "x5t#S256" .= view param p)) (view jweX5tS256 h)
      , fmap (\p -> (view isProtected p, "typ" .= view param p)) (view jweTyp h)
      , fmap (\p -> (view isProtected p, "cty" .= view param p)) (view jweCty h)
      , fmap (\p -> (True, "crit" .= p)) (view jweCrit h)
      , fmap (\p -> (view isProtected p, "epk" .= view param p)) (view jweEpk h)
      , fmap (\p -> (view isProtected p, "apu" .= view param p)) (view jweApu h)
      , fmap (\p -> (view isProtected p, "apv" .= view param p)) (view jweApv h)
      , fmap (\p -> (view isProtected p, "iv" .= view param p)) (view jweIv h)
      , fmap (\p -> (view isProtected p, "tag" .= view param p)) (view jweTag h)
      , fmap (\p -> (view isProtected p, "p2s" .= view param p)) (view jweP2s h)
      , fmap (\p -> (view isProtected p, "p2c" .= view param p)) (view jweP2c h)
      ]

-- | RFC 7518 §4.8.1.1.  The salt input must be at least 8 octets.
p2sFromJSON :: Value -> Parser Types.Base64Octets
p2sFromJSON v = do
  s@(Types.Base64Octets bs) <- parseJSON v
  if B.length bs >= 8
    then pure s
    else fail "\"p2s\" must contain at least 8 octets"

-- | RFC 7518 §4.8.1.2.  The iteration count must be a positive integer.
p2cFromJSON :: Value -> Parser Int
p2cFromJSON v = do
  n <- parseJSON v
  if n > 0
    then pure n
    else fail "\"p2c\" must be a positive integer"

-- | Check that the header parameters required by the key management
-- algorithm are present.
--
checkAlgParams :: forall p. JWEHeader p -> Parser (JWEHeader p)
checkAlgParams h = h <$ case view (jweAlg . param) h of
  ECDH_ES             -> ecdh
  ECDH_ES_A128KW      -> ecdh
  ECDH_ES_A192KW      -> ecdh
  ECDH_ES_A256KW      -> ecdh
  A128GCMKW           -> gcmkw
  A192GCMKW           -> gcmkw
  A256GCMKW           -> gcmkw
  PBES2_HS256_A128KW  -> pbes2
  PBES2_HS384_A192KW  -> pbes2
  PBES2_HS512_A256KW  -> pbes2
  _                   -> pure ()
  where
    ecdh = req "epk" jweEpk
    gcmkw = req "iv" jweIv *> req "tag" jweTag
    pbes2 = req "p2s" jweP2s *> req "p2c" jweP2c
    req :: String -> Lens' (JWEHeader p) (Maybe (HeaderParam p a)) -> Parser ()
    req name l = when (isNothing (view l h)) $
      fail ("missing header parameter " <> show name <> " required by \"alg\"")


-- | Recipient object containing the header and the encrypted key.
--
-- The header is the union of the JWE Protected Header, the JWE
-- Shared Unprotected Header and the JWE Per-Recipient Unprotected
-- Header.
--
data Recipient p a = Recipient
  (a p)               -- Header
  Types.Base64Octets  -- Encrypted key
  deriving (Eq, Show)

-- | Getter for header of a recipient
recipientHeader :: Getter (Recipient p a) (a p)
recipientHeader = to (\(Recipient h _) -> h)

-- | Getter for the encrypted key.  Empty when the key management
-- algorithm is /Direct Encryption/ or /Direct Key Agreement/.
encryptedKey :: (Cons s s Word8 Word8, AsEmpty s) => Getter (Recipient p a) s
encryptedKey = to (\(Recipient _ (Types.Base64Octets k)) -> k) . recons
{-# INLINE encryptedKey #-}


-- | JSON Web Encryption data type.
--
-- Parameterised by the recipient container type, the header
-- 'ProtectionSupport' type, and the header record type.
--
-- Use 'encode' and 'decode' to convert a JWE to or from JSON.
-- When encoding a @'JWE' []@ with exactly one recipient, the
-- /flattened JWE JSON serialisation/ syntax is used, otherwise
-- the /general JWE JSON serialisation/ is used.
-- When decoding a @'JWE' []@ either serialisation is accepted.
--
-- @'JWE' 'Identity'@ uses the flattened JSON serialisation
-- or the /JWE compact serialisation/ (see 'decodeCompact' and
-- 'encodeCompact').
--
-- If it was decoded from a serialised JWE, it "remembers" how the
-- protected header was encoded; the remembered value is used when
-- computing the /Additional Authenticated Data/ and when
-- serialising the object.  The remembered value is not used in
-- equality checks.
--
-- Use 'encryptJWE' to create a JWE.
-- Use 'decryptJWE' or 'decryptJWE'' to decrypt a JWE and
-- recover the plaintext.
--
data JWE t p a = JWE
  (Maybe T.Text)              -- Encoded protected header, if available
  Types.Base64Octets          -- Initialization Vector
  (Maybe Types.Base64Octets)  -- Additional Authenticated Data
  Types.Base64Octets          -- Ciphertext
  Types.Base64Octets          -- Authentication Tag
  (t (Recipient p a))

-- | A JWE that allows multiple recipients, and cannot use
-- the /compact serialisation/.  Headers may be 'Protected'
-- or 'Unprotected'.
--
-- Corresponds to the /General JWE JSON Serialization/ syntax
-- (<https://tools.ietf.org/html/rfc7516#section-7.2.1 RFC 7516 §7.2.1>).
-- When there is exactly one recipient, the flattened syntax is
-- used when encoding.
--
type GeneralJWE = JWE [] OptionalProtection

-- | A JWE with one recipient, which uses the
-- /flattened serialisation/.  Headers may be 'Protected'
-- or 'Unprotected'.
--
-- Corresponds to the /Flattened JWE JSON Serialization/ syntax
-- (<https://tools.ietf.org/html/rfc7516#section-7.2.2 RFC 7516 §7.2.2>).
--
type FlattenedJWE = JWE Identity OptionalProtection

-- | A JWE with one recipient which only allows protected
-- parameters.  Can use the /flattened serialisation/ or
-- the /compact serialisation/.
--
-- Corresponds to the /JWE Compact Serialization/
-- (<https://tools.ietf.org/html/rfc7516#section-7.1 RFC 7516 §7.1>),
-- which permits only a single recipient and only protected header
-- parameters.
--
type CompactJWE = JWE Identity RequiredProtection

instance (Eq (t (Recipient p a))) => Eq (JWE t p a) where
  JWE _ iv aad c tag rs == JWE _ iv' aad' c' tag' rs' =
    iv == iv' && aad == aad' && c == c' && tag == tag' && rs == rs'

instance (Show (t (Recipient p a))) => Show (JWE t p a) where
  show (JWE _ iv aad c tag rs) =
    "JWE " <> show iv <> " " <> show aad <> " " <> show c
      <> " " <> show tag <> " " <> show rs

-- | Fold over the recipients of a JWE.
recipients :: Foldable t => Fold (JWE t p a) (Recipient p a)
recipients = folding (\(JWE _ _ _ _ _ rs) -> rs)


-- | Parse the protected header member, if present.
--
parseProtectedHeader :: Object -> Parser (Maybe Object)
parseProtectedHeader o = do
  hpB64 <- o .:? "protected"
  maybe
    (pure Nothing)
    (withText "base64url-encoded header params"
      (Types.parseB64Url (maybe
        (fail "protected header contains invalid JSON")
        pure . decode . view recons)))
    hpB64

-- | Parse a recipient from an object bearing the @"header"@ and
-- @"encrypted_key"@ members (either an element of the
-- @"recipients"@ array, or the top-level object of the flattened
-- serialisation).
--
parseRecipient
  :: (HasParams a, ProtectionSupport p)
  => Maybe Object  -- ^ protected header
  -> Maybe Object  -- ^ shared unprotected header
  -> Object
  -> Parser (Recipient p a)
parseRecipient hp hu o = do
  hr <- o .:? "header"
  hu' <- case (hu, hr) of
    (Just u, Just r)
      | M.size (M.union u r) /= M.size u + M.size r ->
          fail "duplicate header parameter in shared and per-recipient headers"
      | otherwise -> pure (Just (M.union u r))
    _ -> pure (hu <|> hr)
  Recipient
    <$> parseParams hp hu'
    <*> (fromMaybe (Types.Base64Octets "") <$> o .:? "encrypted_key")

parseJWE
  :: (Maybe Object -> Maybe Object -> Object -> Parser (t (Recipient p a)))
  -> Object
  -> Parser (JWE t p a)
parseJWE parseRecipients o = do
  hp <- parseProtectedHeader o
  hu <- o .:? "unprotected"
  JWE
    <$> (Just <$> (o .: "protected" <|> pure ""))  -- raw protected header
    <*> o .: "iv"
    <*> o .:? "aad"
    <*> o .: "ciphertext"
    <*> o .: "tag"
    <*> parseRecipients hp hu o

instance (HasParams a, ProtectionSupport p) => FromJSON (JWE [] p a) where
  parseJSON v =
    withObject "JWE JSON serialization" (parseJWE general) v
    <|> fmap (\(JWE raw iv aad c tag (Identity r)) -> JWE raw iv aad c tag [r]) (parseJSON v)
    where
      general hp hu o =
        o .: "recipients" >>= traverse (withObject "JWE recipient" (parseRecipient hp hu))

instance (HasParams a, ProtectionSupport p) => FromJSON (JWE Identity p a) where
  parseJSON =
    withObject "Flattened JWE JSON serialization" $ \o ->
      if M.member "recipients" o
      then fail "\"recipients\" member MUST NOT be present"
      else parseJWE (\hp hu o' -> Identity <$> parseRecipient hp hu o') o

recipientPairs :: (HasParams a, ProtectionSupport p) => Recipient p a -> [Pair]
recipientPairs (Recipient h ek) = catMaybes
  [ ("header" .=) <$> unprotectedParams h
  , case ek of
      Types.Base64Octets "" -> Nothing
      _ -> Just ("encrypted_key" .= ek)
  ]

-- | The members common to the general and flattened serialisations.
--
jwePairs :: (HasParams a, ProtectionSupport p, Foldable t) => JWE t p a -> [Pair]
jwePairs jwe@(JWE _ iv aad c tag _) = catMaybes
  [ case rawProtectedHeader jwe of
      "" -> Nothing
      bs -> Just ("protected" .= String (T.decodeUtf8 bs))
  , Just ("iv" .= iv)
  , ("aad" .=) <$> aad
  , Just ("ciphertext" .= c)
  , Just ("tag" .= tag)
  ]

instance (HasParams a, ProtectionSupport p) => ToJSON (JWE [] p a) where
  toJSON jwe@(JWE _ _ _ _ _ rs) = object $ jwePairs jwe <> case rs of
    [r] -> recipientPairs r
    _   -> ["recipients" .= fmap (object . recipientPairs) rs]

instance (HasParams a, ProtectionSupport p) => ToJSON (JWE Identity p a) where
  toJSON jwe@(JWE _ _ _ _ _ (Identity r)) = object $ jwePairs jwe <> recipientPairs r


-- | Return the raw base64url-encoded protected header value.
-- If the JWE was decoded from JSON, this returns the original
-- string value as-is.  Otherwise it is computed from the header
-- of the first recipient.
--
rawProtectedHeader
  :: (HasParams a, ProtectionSupport p, Foldable t)
  => JWE t p a -> B.ByteString
rawProtectedHeader (JWE raw _ _ _ _ rs) = case raw of
  Just s -> T.encodeUtf8 s
  Nothing -> case toList rs of
    (Recipient h _ : _) -> view recons (protectedParamsEncoded h)
    [] -> ""

-- | The /Additional Authenticated Data/ input to the content
-- encryption algorithm (RFC 7516 §5.1 step 14).
--
aadInput
  :: (HasParams a, ProtectionSupport p, Foldable t)
  => JWE t p a -> B.ByteString
aadInput jwe@(JWE _ _ aad _ _ _) =
  rawProtectedHeader jwe
    <> maybe "" (\(Types.Base64Octets a) -> "." <> review Types.base64url a) aad

instance (HasParams a) => ToCompact (JWE Identity RequiredProtection a) where
  toCompact jwe@(JWE _ (Types.Base64Octets iv) _ (Types.Base64Octets c)
                  (Types.Base64Octets tag) (Identity (Recipient _ (Types.Base64Octets ek)))) =
    [ view recons (rawProtectedHeader jwe)
    , review Types.base64url ek
    , review Types.base64url iv
    , review Types.base64url c
    , review Types.base64url tag
    ]

instance (HasParams a) => FromCompact (JWE Identity RequiredProtection a) where
  fromCompact xs = case xs of
    [h, k, iv, c, tag] -> do
      (h', k', iv', c', tag') <-
        (,,,,) <$> t 0 h <*> t 1 k <*> t 2 iv <*> t 3 c <*> t 4 tag
      let o = object
            [ ("protected", h'), ("encrypted_key", k'), ("iv", iv')
            , ("ciphertext", c'), ("tag", tag') ]
      case fromJSON o of
        Error e -> throwing _JSONDecodeError e
        Success a -> pure a
    xs' -> throwing (_CompactDecodeError . _CompactInvalidNumberOfParts)
            (InvalidNumberOfParts 5 (fromIntegral (length xs')))
    where
      l = _CompactDecodeError . _CompactInvalidText
      t n = either (throwing l . CompactTextError n) (pure . String)
        . T.decodeUtf8' . view recons


-- | Create a JWE with the given plaintext by traversing a
-- collection of @(header, key)@ hks.  Each pair specifies a
-- recipient.  All recipients must use the same content encryption
-- algorithm (@"enc"@), and the protected header parameters of all
-- recipients must be identical.  The /Direct Encryption/ (@dir@) and
-- /Direct Key Agreement/ (@ECDH-ES@) algorithms can only be used
-- when there is a single recipient.
--
-- Header parameters that are outputs of the key management
-- algorithm (@"epk"@, @"iv"@, @"tag"@, @"p2s"@ and @"p2c"@) are
-- set in the recipient headers by this function, with the same
-- protection as the @"alg"@ parameter.
--
encryptJWE
  :: ( Cons s s Word8 Word8
     , HasJWEHeader a, HasParams a, MonadRandom m, AsError e, MonadError e m
     , Traversable t
     , ProtectionSupport p
     )
  => s              -- ^ Plaintext
  -> t (a p, JWK)   -- ^ Traversable of header, key hks
  -> m (JWE t p a)
encryptJWE s = encryptJWEWithAAD' Nothing (view recons s)
{-# INLINE encryptJWE #-}

-- | Variant of 'encryptJWE' that includes /Additional Authenticated
-- Data/ (the @"aad"@ member).  The AAD is only supported by the JWE
-- JSON serialisations; do not use this function to create a JWE
-- that will use the compact serialisation.
--
encryptJWEWithAAD
  :: ( Cons s s Word8 Word8, Cons aad aad Word8 Word8
     , HasJWEHeader a, HasParams a, MonadRandom m, AsError e, MonadError e m
     , Traversable t
     , ProtectionSupport p
     )
  => aad            -- ^ Additional Authenticated Data
  -> s              -- ^ Plaintext
  -> t (a p, JWK)   -- ^ Traversable of header, key hks
  -> m (JWE t p a)
encryptJWEWithAAD aad s = encryptJWEWithAAD' (Just (view recons aad)) (view recons s)
{-# INLINE encryptJWEWithAAD #-}

encryptJWEWithAAD'
  :: ( HasJWEHeader a, HasParams a, MonadRandom m, AsError e, MonadError e m
     , Traversable t
     , ProtectionSupport p
     )
  => Maybe B.ByteString -> B.ByteString -> t (a p, JWK) -> m (JWE t p a)
encryptJWEWithAAD' aad m hks = do
  enc <- case nub (fmap (view (jweEnc . param) . fst) (toList hks)) of
    [enc] -> pure enc
    []    -> throwing_ _JWENoRecipients
    _     -> throwing _AlgorithmMismatch
              "all recipients must use the same content encryption algorithm"
  -- The first recipient determines the CEK (generating a random
  -- one, or deriving it for direct algorithms); subsequent
  -- recipients wrap the same CEK.
  (rs, mcek) <- runStateT (traverse (step enc) hks) Nothing
  cek <- maybe (throwing_ _JWENoRecipients) pure mcek
  raw <- protectedHeader rs
  let
    aad' = Types.Base64Octets <$> aad
    jwe0 = JWE (Just raw) (Types.Base64Octets "") aad' (Types.Base64Octets "") (Types.Base64Octets "") rs
  (iv, c, tag) <- encryptContent enc cek (aadInput jwe0) m
  pure $ JWE (Just raw) (Types.Base64Octets iv) aad'
    (Types.Base64Octets c) (Types.Base64Octets tag) rs
  where
    step enc (h, k) = StateT $ \mcek ->
      (\(r, cek) -> (r, Just cek)) <$> mkRecipient enc mcek h k

-- | Determine the protected header shared by all recipients.
--
protectedHeader
  :: (HasParams a, ProtectionSupport p, Foldable t, MonadError e m, AsError e)
  => t (Recipient p a) -> m T.Text
protectedHeader rs =
  case nub (fmap (\(Recipient h _) -> protectedParamsEncoded h) (toList rs)) of
    [raw] -> pure (T.decodeUtf8 (view recons raw))
    []    -> throwing_ _JWENoRecipients
    _     -> throwing_ _JWEProtectedHeaderMismatch

-- | Perform key management for a single recipient.  Returns the
-- recipient (with header updated as required by the key management
-- algorithm) and the CEK.
--
mkRecipient
  :: ( HasJWEHeader a, MonadRandom m, AsError e, MonadError e m )
  => Enc
  -> Maybe B.ByteString  -- ^ CEK, if already determined
  -> a p
  -> JWK
  -> m (Recipient p a, B.ByteString)
mkRecipient enc mcek h k =
  let
    algo = view (jweAlg . param) h
    material = view jwkMaterial k
    direct = when (isJust mcek) $ throwing _AlgorithmMismatch
      (show algo <> " can only be used with a single recipient")
  in case algo of
    Dir -> do
      direct
      cek <- octKey algo material
      unless (B.length cek == cekLength enc) $
        throwing _CryptoError CryptoError_KeySizeInvalid
      pure (Recipient h (Types.Base64Octets ""), cek)
    ECDH_ES -> do
      direct
      (h', z) <- ecdhAgree h material
      let cek = concatKDF (cekLength enc) z (algorithmID enc)
                  (partyInfo jweApu h) (partyInfo jweApv h)
      pure (Recipient h' (Types.Base64Octets ""), cek)
    _ -> do
      cek <- maybe (getRandomBytes (cekLength enc)) pure mcek
      (h', ek) <- wrapCEK algo h material cek
      pure (Recipient h' (Types.Base64Octets ek), cek)

-- | Wrap or encrypt the CEK for the recipient.  Returns the updated
-- header and the encrypted key.
--
wrapCEK
  :: ( HasJWEHeader a, MonadRandom m, AsError e, MonadError e m )
  => Alg
  -> a p
  -> KeyMaterial
  -> B.ByteString  -- ^ CEK
  -> m (a p, B.ByteString)
wrapCEK algo h material cek = case algo of
  RSA1_5              -> rsa
  RSA_OAEP            -> rsa
  RSA_OAEP_256        -> rsa
  A128KW              -> aeskw 16
  A192KW              -> aeskw 24
  A256KW              -> aeskw 32
  A128GCMKW           -> gcmkw 16
  A192GCMKW           -> gcmkw 24
  A256GCMKW           -> gcmkw 32
  ECDH_ES_A128KW      -> ecdhkw 16
  ECDH_ES_A192KW      -> ecdhkw 24
  ECDH_ES_A256KW      -> ecdhkw 32
  PBES2_HS256_A128KW  -> pbes2
  PBES2_HS384_A192KW  -> pbes2
  PBES2_HS512_A256KW  -> pbes2
  Dir                 -> notWrapping
  ECDH_ES             -> notWrapping
  where
    prot = view (jweAlg . protection) h
    setDefault l v = over l (<|> Just (HeaderParam prot v))
    notWrapping = throwing _AlgorithmMismatch
      (show algo <> " is not a key wrapping algorithm")
    rsa = case material of
      RSAKeyMaterial k -> (h,) <$> rsaEncryptCEK algo k cek
      _ -> throwing _AlgorithmMismatch (show algo <> " cannot be used with non-RSA key")
    aeskw n = do
      kek <- octKeyOfSize algo n material
      (h,) <$> aesKeyWrapCEK kek cek
    gcmkw n = do
      kek <- octKeyOfSize algo n material
      (iv, tag, ek) <- aesGCMKeyWrap kek cek
      let h' = h
            & jweIv ?~ HeaderParam prot (Types.Base64Octets iv)
            & jweTag ?~ HeaderParam prot (Types.Base64Octets tag)
      pure (h', ek)
    ecdhkw n = do
      (h', z) <- ecdhAgree h material
      let kek = concatKDF n z (algorithmID algo) (partyInfo jweApu h) (partyInfo jweApv h)
      (h',) <$> aesKeyWrapCEK kek cek
    pbes2 = do
      pw <- octKey algo material
      p2s <- case preview (jweP2s . _Just . param) h of
        Just (Types.Base64Octets s) -> pure s
        Nothing -> getRandomBytes 16
      let p2c = fromMaybe defaultPBES2Count (preview (jweP2c . _Just . param) h)
      kek <- pbes2DeriveKey algo pw p2s p2c
      ek <- aesKeyWrapCEK kek cek
      let h' = h
            & setDefault jweP2s (Types.Base64Octets p2s)
            & setDefault jweP2c p2c
      pure (h', ek)

-- | Default PBES2 iteration count used when the header does not
-- specify one.
--
defaultPBES2Count :: Int
defaultPBES2Count = 100000

-- | Generate an ephemeral key for ECDH-ES, record its public key
-- in the @"epk"@ header parameter, and compute the shared secret.
--
ecdhAgree
  :: ( HasJWEHeader a, MonadRandom m, AsError e, MonadError e m )
  => a p
  -> KeyMaterial  -- ^ recipient (static) public key
  -> m (a p, B.ByteString)
ecdhAgree h material = do
  ephemeral <- case material of
    ECKeyMaterial k                 -> ECKeyMaterial <$> genEC (view ecCrv k)
    OKPKeyMaterial (X25519Key _ _)  -> OKPKeyMaterial <$> genOKP X25519
    OKPKeyMaterial (X448Key _ _)    -> OKPKeyMaterial <$> genOKP X448
    _ -> throwing _KeyMismatch "ECDH-ES requires an EC, X25519 or X448 key"
  z <- ecdhSharedSecret ephemeral material
  epk <- maybe
    (throwing _KeyMismatch "ephemeral key has no public component")
    (pure . fromKeyMaterial)
    (view asPublicKey ephemeral)
  pure (h & jweEpk ?~ HeaderParam (view (jweAlg . protection) h) epk, z)

-- | Get the octets of a symmetric key.
--
octKey :: (MonadError e m, AsError e) => Alg -> KeyMaterial -> m B.ByteString
octKey _ (OctKeyMaterial (OctKeyParameters (Types.Base64Octets k))) = pure k
octKey algo _ = throwing _AlgorithmMismatch
  (show algo <> " cannot be used with non-symmetric key")

-- | Get the octets of a symmetric key, checking that it has the
-- required size.
--
octKeyOfSize
  :: (MonadError e m, AsError e)
  => Alg -> Int -> KeyMaterial -> m B.ByteString
octKeyOfSize algo n material = do
  k <- octKey algo material
  unless (B.length k == n) $ throwing _KeyMismatch
    (T.pack (show algo <> " requires a " <> show (n * 8) <> "-bit key"))
  pure k

-- | The /AlgorithmID/ input to the Concat KDF; the ASCII encoding
-- of the algorithm name.
--
algorithmID :: ToJSON a => a -> B.ByteString
algorithmID a = case toJSON a of
  String s -> T.encodeUtf8 s
  _ -> ""

-- | Get the octets of the @"apu"@ or @"apv"@ parameter, or empty if
-- absent.
--
partyInfo
  :: Lens' (a p) (Maybe (HeaderParam p Types.Base64Octets)) -> a p -> B.ByteString
partyInfo l h = case preview (l . _Just . param) h of
  Just (Types.Base64Octets s) -> s
  Nothing -> ""


-- | Decryption settings:
--
-- * The set of acceptable key management algorithms
-- * The set of acceptable content encryption algorithms
-- * The maximum PBES2 iteration count
--
data DecryptionSettings = DecryptionSettings
  (S.Set Alg)
  (S.Set Enc)
  Int

-- | Types that carry 'DecryptionSettings'.
class HasDecryptionSettings a where
  decryptionSettings :: Lens' a DecryptionSettings

  -- | The set of acceptable key management (@"alg"@) algorithms.
  decryptionSettingsAlgorithms :: Lens' a (S.Set Alg)
  decryptionSettingsAlgorithms = decryptionSettings . go where
    go f (DecryptionSettings algs encs n) =
      (\algs' -> DecryptionSettings algs' encs n) <$> f algs

  -- | The set of acceptable content encryption (@"enc"@) algorithms.
  decryptionSettingsEncryptionAlgorithms :: Lens' a (S.Set Enc)
  decryptionSettingsEncryptionAlgorithms = decryptionSettings . go where
    go f (DecryptionSettings algs encs n) =
      (\encs' -> DecryptionSettings algs encs' n) <$> f encs

  -- | The maximum acceptable PBES2 iteration count (@"p2c"@).  A
  -- JWE that specifies a higher count will not be decrypted.  This
  -- guards against denial of service.
  decryptionSettingsMaxPBES2Count :: Lens' a Int
  decryptionSettingsMaxPBES2Count = decryptionSettings . go where
    go f (DecryptionSettings algs encs n) =
      DecryptionSettings algs encs <$> f n

instance HasDecryptionSettings DecryptionSettings where
  decryptionSettings = id

-- | The default decryption settings.
--
-- - All key management algorithms except @RSA1_5@ are acceptable.
--   RSAES-PKCS1-v1_5 is vulnerable to adaptive chosen-ciphertext
--   attacks and its use is discouraged
--   (<https://tools.ietf.org/html/rfc8725#section-3.1 RFC 8725 §3.1>).
-- - All content encryption algorithms are acceptable.
-- - The maximum PBES2 iteration count is 1000000.
--
defaultDecryptionSettings :: DecryptionSettings
defaultDecryptionSettings = DecryptionSettings
  ( S.fromList
    [ RSA_OAEP, RSA_OAEP_256
    , A128KW, A192KW, A256KW
    , Dir
    , ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW
    , A128GCMKW, A192GCMKW, A256GCMKW
    , PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW
    ] )
  ( S.fromList
    [ A128CBC_HS256, A192CBC_HS384, A256CBC_HS512
    , A128GCM, A192GCM, A256GCM
    ] )
  1000000

-- | Decrypt a JWE with the default decryption settings.
--
-- See also 'defaultDecryptionSettings'.
--
decryptJWE'
  ::  ( AsError e, MonadError e m, MonadRandom m
      , HasJWEHeader h, HasParams h
      , DecryptionKeyStore m (h p) k
      , Cons s s Word8 Word8, AsEmpty s
      , Foldable t
      , ProtectionSupport p
      )
  => k          -- ^ key or key store
  -> JWE t p h  -- ^ JWE
  -> m s
decryptJWE' = decryptJWE defaultDecryptionSettings
{-# INLINE decryptJWE' #-}

-- | Decrypt a JWE.
--
-- Recipients using unsupported algorithms are ignored.  For each
-- remaining recipient, the decryption keys are retrieved from the
-- key store and each is tried in turn.  The plaintext is returned
-- as soon as decryption succeeds.
--
-- Throws 'JWENoRecipients' if there are no recipients that use
-- acceptable algorithms, 'NoUsableKeys' if the key store did not
-- return any keys, or 'JWEIntegrityFailed' if decryption failed
-- for all candidate keys.
--
decryptJWE
  ::  ( HasDecryptionSettings a, AsError e, MonadError e m, MonadRandom m
      , HasJWEHeader h, HasParams h
      , DecryptionKeyStore m (h p) k
      , Cons s s Word8 Word8, AsEmpty s
      , Foldable t
      , ProtectionSupport p
      )
  => a          -- ^ decryption settings
  -> k          -- ^ key or key store
  -> JWE t p h  -- ^ JWE
  -> m s
decryptJWE conf k jwe@(JWE _ (Types.Base64Octets iv) _ (Types.Base64Octets c)
                          (Types.Base64Octets tag) rs) =
  let
    algs = view decryptionSettingsAlgorithms conf
    encs = view decryptionSettingsEncryptionAlgorithms conf
    maxP2c = view decryptionSettingsMaxPBES2Count conf
    acceptable r =
      view (recipientHeader . jweAlg . param) r `elem` algs
      && view (recipientHeader . jweEnc . param) r `elem` encs
    aad = aadInput jwe

    attempt r key = runJOSEError $ do
      let
        h = view recipientHeader r
        enc = view (jweEnc . param) h
      cek <- unwrapCEK maxP2c enc h (view jwkMaterial key) (view encryptedKey r)
      decryptContent enc cek aad iv c tag

    tryKeys _ [] = pure Nothing
    tryKeys r (key : keys) =
      attempt r key >>= either (const (tryKeys r keys)) (pure . Just)

    tryRecipients hadKeys []
      | hadKeys   = throwing_ _JWEIntegrityFailed
      | otherwise = throwing_ _NoUsableKeys
    tryRecipients hadKeys (r : more) = do
      keys <- getDecryptionKeys (view recipientHeader r) k
      tryKeys r keys >>= maybe (tryRecipients (hadKeys || not (null keys)) more) pure
  in do
    let candidates = filter acceptable (toList rs)
    when (null candidates) $ throwing_ _JWENoRecipients
    when (any (has (recipientHeader . jweZip . _Just)) candidates) $
      throwing_ _AlgorithmNotImplemented
    view recons <$> tryRecipients False candidates
{-# INLINE decryptJWE #-}

-- | 'runJOSE' with the error type fixed to 'Error'.  Used to
-- attempt decryption without propagating the specific failure.
--
runJOSEError :: JOSE Error m a -> m (Either Error a)
runJOSEError = runJOSE

-- | Unwrap or decrypt the CEK.  Any failure is reported as
-- 'JWEIntegrityFailed' by the caller.
--
unwrapCEK
  :: ( HasJWEHeader a, MonadRandom m, AsError e, MonadError e m )
  => Int  -- ^ maximum PBES2 iteration count
  -> Enc
  -> a p
  -> KeyMaterial
  -> B.ByteString  -- ^ encrypted key
  -> m B.ByteString
unwrapCEK maxP2c enc h material ek = case algo of
  Dir -> do
    unless (B.null ek) $ throwing_ _JWEIntegrityFailed
    octKey algo material >>= checkLength
  ECDH_ES -> do
    unless (B.null ek) $ throwing_ _JWEIntegrityFailed
    z <- agree
    pure $ concatKDF (cekLength enc) z (algorithmID enc) apu apv
  RSA1_5              -> rsa
  RSA_OAEP            -> rsa
  RSA_OAEP_256        -> rsa
  A128KW              -> aeskw 16
  A192KW              -> aeskw 24
  A256KW              -> aeskw 32
  A128GCMKW           -> gcmkw 16
  A192GCMKW           -> gcmkw 24
  A256GCMKW           -> gcmkw 32
  ECDH_ES_A128KW      -> ecdhkw 16
  ECDH_ES_A192KW      -> ecdhkw 24
  ECDH_ES_A256KW      -> ecdhkw 32
  PBES2_HS256_A128KW  -> pbes2
  PBES2_HS384_A192KW  -> pbes2
  PBES2_HS512_A256KW  -> pbes2
  where
    algo = view (jweAlg . param) h
    apu = partyInfo jweApu h
    apv = partyInfo jweApv h
    octets (Types.Base64Octets s) = s
    requireParam name = maybe
      (throwing _JSONDecodeError ("missing header parameter " <> show (name :: String)))
      pure
    checkLength cek
      | B.length cek == cekLength enc = pure cek
      | otherwise = throwing_ _JWEIntegrityFailed
    agree = do
      epk <- requireParam "epk" (preview (jweEpk . _Just . param) h)
      ecdhSharedSecret material (view jwkMaterial epk)
    rsa = case material of
      RSAKeyMaterial k -> do
        cek <- case algo of
          RSA1_5 -> do
            -- RFC 7516 §11.5: to avoid a padding oracle, substitute
            -- a random CEK when decryption fails, so that the
            -- failure manifests as an authentication tag mismatch.
            random <- getRandomBytes (cekLength enc)
            r <- (Just <$> rsaDecryptCEK algo k ek) `catchError` const (pure Nothing)
            pure $ case r of
              Just cek | B.length cek == cekLength enc -> cek
              _ -> random
          _ -> rsaDecryptCEK algo k ek
        checkLength cek
      _ -> throwing _AlgorithmMismatch (show algo <> " cannot be used with non-RSA key")
    aeskw n = do
      kek <- octKeyOfSize algo n material
      aesKeyUnwrapCEK kek ek >>= checkLength
    gcmkw n = do
      kek <- octKeyOfSize algo n material
      iv <- requireParam "iv" (octets <$> preview (jweIv . _Just . param) h)
      tag <- requireParam "tag" (octets <$> preview (jweTag . _Just . param) h)
      aesGCMKeyUnwrap kek iv tag ek >>= checkLength
    ecdhkw n = do
      z <- agree
      let kek = concatKDF n z (algorithmID algo) apu apv
      aesKeyUnwrapCEK kek ek >>= checkLength
    pbes2 = do
      pw <- octKey algo material
      p2s <- requireParam "p2s" (octets <$> preview (jweP2s . _Just . param) h)
      p2c <- requireParam "p2c" (preview (jweP2c . _Just . param) h)
      when (p2c > maxP2c) $ throwing _AlgorithmMismatch
        "PBES2 iteration count exceeds the configured maximum"
      kek <- pbes2DeriveKey algo pw p2s p2c
      aesKeyUnwrapCEK kek ek >>= checkLength
