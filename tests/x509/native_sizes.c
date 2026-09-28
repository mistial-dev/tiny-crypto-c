/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The native provider reports key sizes it does not implement as
 * UNSUPPORTED. Reporting them as INVALID would present an unverifiable
 * certificate as a forged one. */
#include <tiny_crypto/x509_crypto.h>
#include "munit.h"
#include <string.h>

static MunitResult unsupported_rsa_sizes(const MunitParameter params[], void* user)
{
  static uint8_t modulus[520], signature[520];
  static TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(4096)];
  static const uint8_t exponent[] = {1, 0, 1};
  static const uint8_t rsa_encryption[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1};
  static const uint8_t null_parameters[] = {5, 0};
  static uint8_t encoded_key[600];
  const size_t lengths[] = {96, 192, 520};
  uint8_t digest[32] = {0};
  TC_ECDSA_workspace ec;
  TC_RSA_workspace rsa = {words, sizeof words / sizeof *words};
  TC_X509_native_workspace scratch = {&ec, &rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&scratch);
  TC_signature_algorithm algorithm;
  (void)params;
  (void)user;
  memset(modulus, 0xff, sizeof modulus);
  memset(&algorithm, 0, sizeof algorithm);
  algorithm.scheme = TC_SIGNATURE_RSA_V15;
  algorithm.hash = TC_HASH_SHA256;
  algorithm.mgf_hash = TC_HASH_UNKNOWN;
  for (size_t i = 0; i < sizeof lengths / sizeof *lengths; ++i) {
    TC_X509_public_key key;
    size_t work = 1000000;
    memset(&key, 0, sizeof key);
    /* Only the fields a parsed key carries matter; the encoding is not re-read. */
    key.type = TC_KEY_RSA;
    key.algorithm.oid = (TC_bytes){rsa_encryption, sizeof rsa_encryption};
    key.algorithm.parameters = (TC_bytes){null_parameters, sizeof null_parameters};
    key.key = (TC_bytes){encoded_key, lengths[i] + 10};
    key.bits = lengths[i] * 8;
    key.modulus = (TC_bytes){modulus, lengths[i]};
    key.exponent = (TC_bytes){exponent, sizeof exponent};
    munit_assert_int(TC_X509_signature_verify_digest((TC_bytes){digest, sizeof digest},
                                                     &algorithm,
                                                     (TC_bytes){signature, lengths[i]}, &key,
                                                     &provider, &work),
                     ==, TC_X509_SIGNATURE_UNSUPPORTED);
  }
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/unsupported-rsa-sizes", unsupported_rsa_sizes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/x509-native-sizes", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
