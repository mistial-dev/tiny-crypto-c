/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Test the configured library target instead of recompiling its sources.
 */
#include "munit.h"

#include <string.h>

#include <tiny_crypto/config.h>
#include <tiny_crypto/common.h>
#if TC_ENABLE_AES
#include <tiny_crypto/aes.h>
#endif
#if TC_ENABLE_SHA1 || TC_ENABLE_SHA224 || TC_ENABLE_SHA256 || \
    TC_ENABLE_SHA384 || TC_ENABLE_SHA512
#include <tiny_crypto/hash.h>
#endif

#if (TC_ENABLE_AES && TC_AES_ENABLE_CTR) || TC_ENABLE_SHA256 || TC_ENABLE_SHA512
static int bytes_equal(const uint8_t* left, const uint8_t* right, size_t length)
{
  return memcmp(left, right, length) == 0;
}
#endif

static MunitResult test_profile(const MunitParameter params[], void* user)
{
  uint8_t cleared[16];
  size_t i;
  (void)params; (void)user;
  memset(cleared, 0xa5, sizeof cleared);
  TC_secure_zero(cleared, sizeof cleared);
  for (i = 0; i < sizeof cleared; ++i) munit_assert_uint8(cleared[i], ==, 0);
#if TC_ENABLE_AES && TC_AES_ENABLE_CTR
#if TC_AES_KEY_BITS == 256
  static const uint8_t expected[TC_AES_BLOCKLEN] = {
    0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
    0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87
  };
#elif TC_AES_KEY_BITS == 192
  static const uint8_t expected[TC_AES_BLOCKLEN] = {
    0xaa, 0xe0, 0x69, 0x92, 0xac, 0xbf, 0x52, 0xa3,
    0xe8, 0xf4, 0xa9, 0x6e, 0xc9, 0x30, 0x0b, 0xd7
  };
#else
  static const uint8_t expected[TC_AES_BLOCKLEN] = {
    0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
    0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e
  };
#endif
  uint8_t key[TC_AES_KEYLEN] = { 0 };
  uint8_t iv[TC_AES_BLOCKLEN] = { 0 };
  uint8_t block[TC_AES_BLOCKLEN] = { 0 };
  struct TC_AES_ctx aes;

#if TC_AES_SBOX_MODE == TC_AES_SBOX_MODE_RUNTIME
  TC_AES_init_sbox();
#endif
  munit_assert_int(TC_AES_init_ctx_iv(&aes, key, iv), ==, TC_OK);
  munit_assert_int(TC_AES_CTR_crypt(&aes, block, sizeof(block)), ==, TC_OK);
  munit_assert(bytes_equal(block, expected, sizeof(expected)));
#endif

#if TC_ENABLE_SHA256
  static const uint8_t expected_empty[TC_SHA256_DIGESTLEN] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
  };
  uint8_t digest[TC_SHA256_DIGESTLEN];
  struct TC_SHA256_ctx sha256;

  munit_assert_false(TC_SHA256_init(&sha256) != TC_OK ||
      TC_SHA256_final(&sha256, digest) != TC_OK ||
      !bytes_equal(digest, expected_empty, sizeof(expected_empty)));
#endif

#if TC_ENABLE_SHA512
  {
    static const uint8_t expected_empty512[TC_SHA512_DIGESTLEN] = {
      0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
      0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
      0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
      0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
    };
    uint8_t digest512[TC_SHA512_DIGESTLEN];
    struct TC_SHA512_ctx sha512;

    munit_assert_false(TC_SHA512_init(&sha512) != TC_OK ||
        TC_SHA512_final(&sha512, digest512) != TC_OK ||
        !bytes_equal(digest512, expected_empty512, sizeof(expected_empty512)));
  }
#endif

  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/profile", test_profile, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
static const MunitSuite suite = {"/default-profile", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{ return munit_suite_main(&suite, NULL, argc, argv); }
