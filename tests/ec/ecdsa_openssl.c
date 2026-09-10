/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/ec.h>
#include "../../src/pki_verify_internal.h"
#include "munit.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <string.h>

static MunitResult verify(const MunitParameter params[], void* data)
{
  static const char* groups[] = {"prime256v1", "secp384r1", "prime192v1"};
  static const TC_EC_curve curves[] = {TC_EC_P256, TC_EC_P384, TC_EC_P192};
  TC_ECDSA_workspace workspace;
  uint8_t digest[64], encoded[128], signature[96], public_key[97];
  size_t c, j;
  (void)params; (void)data;
  for (c = 0; c < 3; ++c) {
    size_t bytes = c == 0 ? 32 : c == 1 ? 48 : 24;
    EVP_PKEY* key = EVP_EC_gen(groups[c]);
    size_t public_len = sizeof public_key;
    munit_assert_not_null(key);
    munit_assert_int(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
        public_key, sizeof public_key, &public_len), ==, 1);
    for (j = 0; j < 4; ++j) {
      size_t digest_len = j == 0 ? 20 : j == 1 ? 32 : j == 2 ? 48 : 64;
      size_t encoded_len = sizeof encoded;
      const unsigned char* cursor = encoded;
      const BIGNUM *r, *s;
      ECDSA_SIG* parsed;
      EVP_PKEY_CTX* context = EVP_PKEY_CTX_new(key, NULL);
      memset(digest, (int)(j * 37), sizeof digest);
      munit_assert_not_null(context);
      munit_assert_int(EVP_PKEY_sign_init(context), ==, 1);
      munit_assert_int(EVP_PKEY_sign(context, encoded, &encoded_len, digest, digest_len), ==, 1);
      parsed = d2i_ECDSA_SIG(NULL, &cursor, (long)encoded_len);
      munit_assert_not_null(parsed);
      ECDSA_SIG_get0(parsed, &r, &s);
      munit_assert_int(BN_bn2binpad(r, signature, (int)bytes), ==, (int)bytes);
      munit_assert_int(BN_bn2binpad(s, signature + bytes, (int)bytes), ==, (int)bytes);
      munit_assert_int(TC_ECDSA_verify_digest(curves[c], public_key, public_len,
          digest, digest_len, signature, 2 * bytes, &workspace), ==, TC_OK);
      {
        TC_X509_public_key issuer = {0};
        TC_signature_algorithm algorithm = {TC_SIGNATURE_ECDSA,TC_HASH_SHA256,TC_HASH_UNKNOWN,0};
        algorithm.hash = j == 0 ? TC_HASH_SHA1 : j == 1 ? TC_HASH_SHA256 :
          j == 2 ? TC_HASH_SHA384 : TC_HASH_SHA512;
        issuer.type = TC_KEY_EC; issuer.curve = curves[c];
        issuer.key = (TC_bytes){public_key,public_len};
        munit_assert_int(tc_pki_verify_digest(&algorithm,&issuer,
            (TC_bytes){digest,digest_len},(TC_bytes){encoded,encoded_len},
            &workspace,NULL,32768), ==, TC_X509_SIGNATURE_VALID);
        munit_assert_int(tc_pki_verify_digest(&algorithm,&issuer,
            (TC_bytes){digest,digest_len},(TC_bytes){encoded,encoded_len},
            &workspace,NULL,0), ==, TC_X509_SIGNATURE_LIMIT);
        digest[0] ^= 1;
        munit_assert_int(tc_pki_verify_digest(&algorithm,&issuer,
            (TC_bytes){digest,digest_len},(TC_bytes){encoded,encoded_len},
            &workspace,NULL,32768), ==, TC_X509_SIGNATURE_INVALID);
        digest[0] ^= 1;
      }
      for (size_t k = 0; k < sizeof workspace; ++k)
        munit_assert_uint8(((uint8_t*)&workspace)[k], ==, 0);
      digest[0] ^= 1;
      munit_assert_int(TC_ECDSA_verify_digest(curves[c], public_key, public_len,
          digest, digest_len, signature, 2 * bytes, &workspace), ==, TC_MISMATCH);
      digest[0] ^= 1;
      signature[bytes - 1] ^= 1;
      munit_assert_int(TC_ECDSA_verify_digest(curves[c], public_key, public_len,
          digest, digest_len, signature, 2 * bytes, &workspace), ==, TC_MISMATCH);
      signature[bytes - 1] ^= 1;
      public_key[0] = 0;
      munit_assert_int(TC_ECDSA_verify_digest(curves[c], public_key, public_len,
          digest, digest_len, signature, 2 * bytes, &workspace), ==, TC_MISMATCH);
      public_key[0] = 4;
      munit_assert_int(TC_ECDSA_verify_digest(curves[c], public_key, public_len,
          digest, 0, signature, 2 * bytes, &workspace), ==, TC_ERROR);
      munit_assert_int(TC_ECDSA_verify_digest(curves[c], public_key, public_len,
          digest, digest_len, signature, 2 * bytes - 1, &workspace), ==, TC_ERROR);
      munit_assert_int(TC_ECDSA_verify_digest(curves[c], public_key, public_len,
          (const uint8_t*)&workspace, digest_len, signature, 2 * bytes, &workspace), ==, TC_ERROR);
      memset(signature + bytes, 0, bytes);
      munit_assert_int(TC_ECDSA_verify_digest(curves[c], public_key, public_len,
          digest, digest_len, signature, 2 * bytes, &workspace), ==, TC_MISMATCH);
      memset(signature, 0, bytes);
      munit_assert_int(TC_ECDSA_verify_digest(curves[c], public_key, public_len,
          digest, digest_len, signature, 2 * bytes, &workspace), ==, TC_MISMATCH);
      ECDSA_SIG_free(parsed);
      EVP_PKEY_CTX_free(context);
    }
    EVP_PKEY_free(key);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/verify", verify, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
  };
  MunitSuite suite = {"/ecdsa", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
