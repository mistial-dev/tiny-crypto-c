/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "munit.h"

#include <string.h>

#include <tiny_crypto/aes.h>

static MunitResult test_profile(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  static const uint8_t expected_ciphertext[16] = {
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
    0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
  };
  static const uint8_t expected_tag[16] = {
    0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
    0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
  };
  uint8_t key[TC_AES_KEYLEN] = { 0 };
  uint8_t iv[12] = { 0 };
  uint8_t plaintext[16] = { 0 };
  uint8_t ciphertext[16];
  uint8_t recovered[16];
  uint8_t tag[16];

  munit_assert_false(TC_AES_GCM_encrypt(key, iv, sizeof(iv), NULL, 0, plaintext,
                         sizeof(plaintext), ciphertext, tag, sizeof(tag)) != TC_OK);
  munit_assert_false(memcmp(ciphertext, expected_ciphertext, sizeof(ciphertext)) != 0 ||
      memcmp(tag, expected_tag, sizeof(tag)) != 0);
  munit_assert_false(TC_AES_GCM_decrypt(key, iv, sizeof(iv), NULL, 0, ciphertext,
                         sizeof(ciphertext), tag, sizeof(tag), recovered) != TC_OK);
  return memcmp(recovered, plaintext, sizeof(plaintext)) == 0 ? 0 : 4;
}

static MunitTest tests[] = {
  {"/profile", test_profile, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
static const MunitSuite suite = {"/gcm-profile", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{ return munit_suite_main(&suite, NULL, argc, argv); }
