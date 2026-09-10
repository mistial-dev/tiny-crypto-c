/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "munit.h"

#include <stdio.h>
#include <string.h>

#include <tiny_crypto/des.h>


static const uint8_t weak_keys[16][TC_DES_KEYLEN] = {
  { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
  { 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe },
  { 0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1 },
  { 0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e },
  { 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe },
  { 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01 },
  { 0x1f, 0xe0, 0x1f, 0xe0, 0x0e, 0xf1, 0x0e, 0xf1 },
  { 0xe0, 0x1f, 0xe0, 0x1f, 0xf1, 0x0e, 0xf1, 0x0e },
  { 0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1 },
  { 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1, 0x01 },
  { 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe },
  { 0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e },
  { 0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e },
  { 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01 },
  { 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe },
  { 0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1 }
};

static int expect_key_status(TC_status status)
{
#if TC_DES_REJECT_WEAK_KEYS
  return status == TC_ERROR;
#else
  return status == TC_OK;
#endif
}

static MunitResult test_profile(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  static const uint8_t k1[TC_DES_KEYLEN] =
    { 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 };
  static const uint8_t k2[TC_DES_KEYLEN] =
    { 0x0e, 0x32, 0x92, 0x32, 0xea, 0x6d, 0x0d, 0x73 };
  static const uint8_t k3[TC_DES_KEYLEN] =
    { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18 };
  struct TC_DES_ctx des;
  struct TC_DES3_ctx des3;
#if TC_DES_ENABLE_CMAC
  struct TC_DES_CMAC_ctx cmac;
#endif
  uint8_t key[TC_DES3_KEYLEN_3KEY];
  size_t i;

  munit_assert(TC_DES_init_ctx(&des, k1) == TC_OK);
  for (i = 0; i < 16; ++i)
  {
    munit_assert(expect_key_status(TC_DES_init_ctx(&des, weak_keys[i])));
#if TC_DES_ENABLE_CMAC
    munit_assert(expect_key_status(TC_DES_CMAC_init(&cmac, weak_keys[i],
                                             TC_DES_KEYLEN)));
#endif
  }

  memcpy(key, weak_keys[0], TC_DES_KEYLEN);
  for (i = 0; i < TC_DES_KEYLEN; ++i)
    key[i] ^= 0x01u;
  munit_assert(expect_key_status(TC_DES_init_ctx(&des, key)));

  memcpy(key, k1, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN, k2, TC_DES_KEYLEN);
  munit_assert(TC_DES3_init_ctx(&des3, key, TC_DES3_KEYLEN_2KEY) == TC_OK);

  memcpy(key + TC_DES_KEYLEN, weak_keys[0], TC_DES_KEYLEN);
  munit_assert(expect_key_status(
    TC_DES3_init_ctx(&des3, key, TC_DES3_KEYLEN_2KEY)));
#if TC_DES_ENABLE_CMAC
  munit_assert(expect_key_status(TC_DES_CMAC_init(&cmac, key,
                                           TC_DES3_KEYLEN_2KEY)));
#endif

  memcpy(key + TC_DES_KEYLEN, k1, TC_DES_KEYLEN);
  munit_assert(expect_key_status(
    TC_DES3_init_ctx(&des3, key, TC_DES3_KEYLEN_2KEY)));
  for (i = TC_DES_KEYLEN; i < TC_DES3_KEYLEN_2KEY; ++i)
    key[i] ^= 0x01u;
  munit_assert(expect_key_status(
    TC_DES3_init_ctx(&des3, key, TC_DES3_KEYLEN_2KEY)));

  memcpy(key, k1, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN, k2, TC_DES_KEYLEN);
  memcpy(key + (2u * TC_DES_KEYLEN), k1, TC_DES_KEYLEN);
  munit_assert(TC_DES3_init_ctx(&des3, key, TC_DES3_KEYLEN_3KEY) == TC_OK);

  memcpy(key + (2u * TC_DES_KEYLEN), k3, TC_DES_KEYLEN);
  munit_assert(TC_DES3_init_ctx(&des3, key, TC_DES3_KEYLEN_3KEY) == TC_OK);

  memcpy(key, weak_keys[0], TC_DES_KEYLEN);
  munit_assert(expect_key_status(
    TC_DES3_init_ctx(&des3, key, TC_DES3_KEYLEN_3KEY)));

  memcpy(key, k1, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN, weak_keys[0], TC_DES_KEYLEN);
  munit_assert(expect_key_status(
    TC_DES3_init_ctx(&des3, key, TC_DES3_KEYLEN_3KEY)));

  memcpy(key + TC_DES_KEYLEN, k2, TC_DES_KEYLEN);
  memcpy(key + (2u * TC_DES_KEYLEN), weak_keys[0], TC_DES_KEYLEN);
  munit_assert(expect_key_status(
    TC_DES3_init_ctx(&des3, key, TC_DES3_KEYLEN_3KEY)));

  memcpy(key, k1, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN, k1, TC_DES_KEYLEN);
  memcpy(key + (2u * TC_DES_KEYLEN), k3, TC_DES_KEYLEN);
  munit_assert(expect_key_status(
    TC_DES3_init_ctx(&des3, key, TC_DES3_KEYLEN_3KEY)));

  memcpy(key, k1, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN, k2, TC_DES_KEYLEN);
  memcpy(key + (2u * TC_DES_KEYLEN), k2, TC_DES_KEYLEN);
  munit_assert(expect_key_status(
    TC_DES3_init_ctx(&des3, key, TC_DES3_KEYLEN_3KEY)));

  puts("DES weak-key policy: OK");
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/profile", test_profile, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
static const MunitSuite suite = {"/des-weak-keys", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{ return munit_suite_main(&suite, NULL, argc, argv); }
