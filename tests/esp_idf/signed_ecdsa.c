/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "munit.h"
#include "secure_boot_signature_priv.h"
#include "rom/ecdsa.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <string.h>

static MunitResult verify(const MunitParameter params[], void* data)
{
  static const char* groups[] = {"prime192v1", "prime256v1"};
  ets_secure_boot_signature_t blocks;
  uint8_t digest[32] = {0}, public_key[65], raw[64], der[80];
  size_t c, i;
  (void)params; (void)data;
  for (c = 0; c < 2; ++c) {
    size_t bytes = c ? 32 : 24, public_len = sizeof public_key, der_len = sizeof der;
    const uint8_t* cursor = der;
    const BIGNUM *r, *s;
    EVP_PKEY* key = EVP_EC_gen(groups[c]);
    EVP_PKEY_CTX* context;
    ECDSA_SIG* signature;
    memset(&blocks, 0, sizeof blocks);
    munit_assert_not_null(key);
    context = EVP_PKEY_CTX_new(key, NULL);
    munit_assert_not_null(context);
    munit_assert_int(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
        public_key, sizeof public_key, &public_len), ==, 1);
    munit_assert_int(EVP_PKEY_sign_init(context), ==, 1);
    munit_assert_int(EVP_PKEY_sign(context, der, &der_len, digest, sizeof digest), ==, 1);
    signature = d2i_ECDSA_SIG(NULL, &cursor, (long)der_len);
    munit_assert_not_null(signature);
    ECDSA_SIG_get0(signature, &r, &s);
    munit_assert_int(BN_bn2binpad(r, raw, (int)bytes), ==, (int)bytes);
    munit_assert_int(BN_bn2binpad(s, raw + bytes, (int)bytes), ==, (int)bytes);
    blocks.block[0].ecdsa.key.curve_id = c ? ECDSA_CURVE_P256 : ECDSA_CURVE_P192;
    for (i = 0; i < bytes; ++i) {
      blocks.block[0].ecdsa.key.point[i] = public_key[bytes - i];
      blocks.block[0].ecdsa.key.point[bytes + i] = public_key[2 * bytes - i];
      blocks.block[0].ecdsa.signature[i] = raw[bytes - 1 - i];
      blocks.block[0].ecdsa.signature[bytes + i] = raw[2 * bytes - 1 - i];
    }
    munit_assert_int(verify_ecdsa_signature_block(&blocks, digest, &blocks.block[0]), ==, ESP_OK);
    digest[0] ^= 1;
    munit_assert_int(verify_ecdsa_signature_block(&blocks, digest, &blocks.block[0]), ==, ESP_ERR_IMAGE_INVALID);
    digest[0] ^= 1;
    blocks.block[0].ecdsa.signature[0] ^= 1;
    munit_assert_int(verify_ecdsa_signature_block(&blocks, digest, &blocks.block[0]), ==, ESP_ERR_IMAGE_INVALID);
    blocks.block[0].ecdsa.key.curve_id = 0xff;
    munit_assert_int(verify_ecdsa_signature_block(&blocks, digest, &blocks.block[0]), ==, ESP_ERR_INVALID_ARG);
    munit_assert_int(verify_ecdsa_signature_block(NULL, digest, &blocks.block[0]), ==, ESP_ERR_INVALID_ARG);
    ECDSA_SIG_free(signature);
    EVP_PKEY_CTX_free(context);
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
  MunitSuite suite = {"/idf-ecdsa", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
