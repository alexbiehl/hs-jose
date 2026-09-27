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

{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

module JWE
  ( doJweEncrypt
  , doJweDecrypt
  ) where

import System.Exit (exitFailure)

import Data.Aeson (decode, encode)
import qualified Data.ByteString.Lazy as L

import Crypto.JOSE.JWE

-- | Create a JWE.  Args are:
--
-- 1. filename of JWK
-- 2. filename of plaintext
--
-- Output is a JWE (JSON serialisation) encrypted with @A256GCM@.
--
doJweEncrypt :: [String] -> IO ()
doJweEncrypt [jwkFilename, plaintextFilename] = do
  Just k <- decode <$> L.readFile jwkFilename
  plaintext <- L.readFile plaintextFilename
  result <- runJOSE $ do
    h <- makeJWEHeader k A256GCM
    encryptJWE plaintext [(h :: JWEHeader OptionalProtection, k)]
  case result of
    Left e -> print (e :: Error) >> exitFailure
    Right jwe -> L.putStr (encode jwe)


-- | Decrypt a JWE and output the plaintext.  Args are:
--
-- 1. filename of JWK
-- 2. filename of JWE
--
-- Exit code indicates success.
--
doJweDecrypt :: [String] -> IO ()
doJweDecrypt [jwkFilename, jweFilename] = do
  Just k <- decode <$> L.readFile jwkFilename
  Just jwe <- decode <$> L.readFile jweFilename
  result <- runJOSE $ decryptJWE' (k :: JWK) (jwe :: GeneralJWE JWEHeader)
  case result of
    Left e -> print (e :: Error) >> exitFailure
    Right s -> L.putStr s
