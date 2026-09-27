## Version 0.14 (unreleased)

- Implemented JSON Web Encryption (JWE; RFC 7516).  The new
  `Crypto.JOSE.JWE` module follows the same design as
  `Crypto.JOSE.JWS`: the `JWE t p a` type is parameterised over the
  recipient container, header protection and header types, with
  `GeneralJWE`, `FlattenedJWE` and `CompactJWE` synonyms.  Use
  `encryptJWE` (or `encryptJWEWithAAD`) to create a JWE and
  `decryptJWE` or `decryptJWE'` to decrypt one.  Both the JSON
  serialisations and the compact serialisation are supported.

  All content encryption algorithms (`A128CBC-HS256`, `A192CBC-HS384`,
  `A256CBC-HS512`, `A128GCM`, `A192GCM`, `A256GCM`) and all key
  management algorithms (`RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`,
  `A128KW`, `A192KW`, `A256KW`, `dir`, `ECDH-ES`, `ECDH-ES+A128KW`,
  `ECDH-ES+A192KW`, `ECDH-ES+A256KW`, `A128GCMKW`, `A192GCMKW`,
  `A256GCMKW`, `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW` and
  `PBES2-HS512+A256KW`) defined in RFC 7518 are implemented.
  ECDH-ES supports the NIST curves and X25519/X448 (RFC 8037).
  The `"zip"` (compression) header parameter is parsed but
  compression is not implemented.

  The default decryption settings (`defaultDecryptionSettings`)
  exclude `RSA1_5`, which is vulnerable to adaptive chosen-ciphertext
  attacks.

- Added `DecryptionKeyStore` class to `Crypto.JOSE.JWK.Store`, with
  instances for `JWK` and `JWKSet`.  It is analogous to
  `VerificationKeyStore`, but the payload is not available because
  it has not yet been decrypted.

- Added `Crypto.JOSE.JWK.bestJWEAlg`, which chooses a JWE key
  management algorithm for a key, and `Crypto.JOSE.JWE.makeJWEHeader`.

- Added `JWENoRecipients`, `JWEIntegrityFailed` and
  `JWEProtectedHeaderMismatch` constructors to the `Error` type.

- `Crypto.JOSE.JWA.JWE` now exports the content encryption and key
  management primitives, and re-exports the JWE `Alg` type.  The
  never-functional `AlgWithParams`, `ECDHParameters`,
  `AESGCMParameters` and `PBES2Parameters` types were removed; the
  corresponding header parameters are now fields of `JWEHeader`.

- `Crypto.JOSE.JWA.JWK` now exports `rsaPrivateKey`.

- The `Crypto.JOSE` prelude module now re-exports `Crypto.JOSE.JWE`,
  except for the JWE `Alg` type (whose name conflicts with the JWS
  `Alg` type).  The JWE `Alg` constructors are re-exported.


## Version 0.13 (2026-06-06)

- Update to *crypton >= 1.1.0* and *ram*.  There are no
  functional changes in this release.  Until the release
  of 0.14, any behavioural changes (bug fixes, etc) will
  be released to both the 0.13 and 0.12 series.

## Version 0.12 (2025-08-18)

- GHC 9.6 is now the earliest supported version.

- Changed the header protection data types for better ergonomics
  ([#125](https://github.com/frasertweedale/hs-jose/issues/125)).
  Previously, `()` was used for serialisations that only support
  protected headers (thus, a single constructor).  This release
  introduces the new singleton data type `RequiredProtected` to
  replace the use of `()` for this purpose.  This is a breaking
  change and some library users will need to update their code.

  The `Protection` type has been renamed to `OptionalProtection`,
  with the old name retained as a (deprecated) type synonym.

  The `ProtectionIndicator` class has been renamed to
  `ProtectionSupport`, with the old name retained as a (deprecated)
  type synonym.

  Added some convenience header and header parameter constructors:
  `newJWSHeaderProtected`, `newHeaderParamProtected` and
  `newHeaderParamUnprotected`.

- Generalised the types of `signJWT`, `verifyJWT` and related
  functions to accept custom JWS header types.  Added new type
  synonym `SignedJWTWithHeader h`.  This change could break some
  applications by introducing ambiguity.  The solution is to use
  a type annotation, type application, or explicit coercion
  function, as in the below examples:

  ```haskell
  -- type application
  {-# LANGUAGE TypeApplications #-}
  decodeCompact @SignedJWT s >>= verifyClaims settings k

  -- type annotation
  do
    jwt <- decodeCompact s
    verifyClaims settings k (jwt :: SignedJWT)

  -- coercion function
  let
    fixType = id :: SignedJWT -> SignedJWT
  in
    verifyClaims settings k . fixType =<< decodeCompact s
  ```

- Added `unsafeGetPayload`, `unsafeGetJWTPayload` and
  `unsafeGetJWTClaimsSet` functions.  These enable access to
  the JWS/JWT payload without cryptographic verification.  As
  the name implies, these should be used with the utmost caution!
  ([#126](https://github.com/frasertweedale/hs-jose/issues/126))

- Add `Crypto.JOSE.JWK.negotiateJWSAlg` which chooses the
  cryptographically strongest JWS algorithm for a given key,
  restricted to a given set of algorithms.  ([#118][])

- Added new conversion functions `Crypto.JOSE.JWK.fromX509PubKey`
  and `Crypto.JOSE.JWK.fromX509PrivKey`.  These convert from the
  `Data.X509.PubKey` and `Data.X509.PrivKey` types, which can be
  read via the *crypton-x509-store* package.  They supports RSA,
  NIST ECC, and Edwards curve key types (Ed25519, Ed448, X25519,
  X448).

- Updated `Crypto.JOSE.JWK.fromX509Certificate` to support Edwards
  curve key types (Ed25519, Ed448, X25519, X448).

- Added `Crypto.JOSE.JWK.fromRSAPublic :: RSA.PublicKey -> JWK`.

- Added `Ord` instance for `StringOrURI` ([#134]; contributed by
  Chris Penner).

- Added `Semigroup` and `Monoid` instances for `JWKSet`
  ([#135]; contributed by Torgeir Strand Henriksen).

[#134]: https://github.com/frasertweedale/hs-jose/pull/134
[#135]: https://github.com/frasertweedale/hs-jose/pull/135


## Version 0.11 (2023-10-31)

- Migrate to the *crypton* library ecosystem.  *crypton* was a hard
  fork of *cryptonite*, which was no longer maintained.  With this
  change, the minimum supported version of GHC increased to 8.8.
  There are no other notable changes in this release.

- The `v0.10` series is the last release series to support
  *cryptonite*.  It will continue to receive important bug fixes
  until the end of 2024.


## Version 0.10 (2022-09-01)

- Introduce `newtype JOSE e m a` which behaves like `ExceptT e m a`
  but also has `instance (MonadRandom m) => MonadRandom (JOSE e m)`.
  The orphan `MonadRandom` instances were removed. ([#91][])

- Parameterise `JWT` over the claims data type.  This is a
  cleaner mechanism to support applications that use additional
  claims beyond those registered by RFC 7519.  `unregisteredClaims`
  and `addClaim` are deprecated and will be removed in a future
  release. ([#39][])

- Add Ed448 and X448 support. ([#74][])

- Add secp256k1 curve support (RFC 8812).

- Added `checkJWK :: (MonadError e m, AsError e) => JWK -> m ()`.
  This action performs some key usability checks.  In particular
  it identifies too-small symmetric keys.  ([#46][])

- Removed `QuickCheck` instances.  *jose* no longer depends on
  `QuickCheck`.  ([#106][])

- Removed orphan `ToJSON` and `FromJSON` instances for `URI`.

- Fail signature verification when curve does not match algorithm.
  This is an additional defence against curve substitution attacks.

- Improved error reporting when constructing a JWK from an X.509
  certificate with ECDSA key.

- Make compatible with `mtl == 2.3.*` ([#107][])

- Make compatible with `monad-time == 0.4`

[#39]: https://github.com/frasertweedale/hs-jose/issues/39
[#46]: https://github.com/frasertweedale/hs-jose/issues/46
[#74]: https://github.com/frasertweedale/hs-jose/issues/74
[#91]: https://github.com/frasertweedale/hs-jose/issues/91
[#106]: https://github.com/frasertweedale/hs-jose/issues/106
[#107]: https://github.com/frasertweedale/hs-jose/issues/107
[#118]: https://github.com/frasertweedale/hs-jose/issues/118
[#122]: https://github.com/frasertweedale/hs-jose/issues/122


## Older versions

See Git commit history
