/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "munit.h"

#include <stdio.h>
#include <string.h>

#include <tiny_crypto/des.h>

static const uint8_t weak_keys[16][TC_DES_KEYLEN] = {
    {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
    {0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe},
    {0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1},
    {0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e},
    {0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe},
    {0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01},
    {0x1f, 0xe0, 0x1f, 0xe0, 0x0e, 0xf1, 0x0e, 0xf1},
    {0xe0, 0x1f, 0xe0, 0x1f, 0xf1, 0x0e, 0xf1, 0x0e},
    {0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1},
    {0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1, 0x01},
    {0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe},
    {0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e},
    {0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e},
    {0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01},
    {0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe},
    {0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1}};

static int expect_key_status(TC_status status)
{
#if TC_DES_REJECT_WEAK_KEYS
  return status == TC_ERROR;
#else
  return status == TC_OK;
#endif
}

#if TC_DES_ENABLE_ISO9797
/* Check ISO 9797 init for Algorithm 1 and Algorithm 3 over one bundle. */
static int expect_iso9797_status(const uint8_t* key, size_t keylen, int accepted)
{
  struct TC_DES_ISO9797_ctx ctx;
  const TC_status alg1 =
      TC_DES_ISO9797_init(&ctx, TC_DES_ISO9797_ALG1, TC_DES_ISO9797_PAD2, key, keylen);
  const TC_status alg3 =
      TC_DES_ISO9797_init(&ctx, TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, key, keylen);
  TC_DES_ISO9797_ctx_clear(&ctx);
  if (accepted)
    return alg1 == TC_OK && alg3 == TC_OK;
  return expect_key_status(alg1) && expect_key_status(alg3);
}

/* ISO/IEC 9797-1:2011 clause 7.4 requires independent K and K'. Weak
 * components and K1 = K2 or K2 = K3 are rejected under the policy. */
static void check_iso9797_profile(const uint8_t* k1, const uint8_t* k2, const uint8_t* k3)
{
  uint8_t key[TC_DES_KEYLEN_3KEY];
  uint8_t tag[TC_DES_BLOCKLEN];
  static const uint8_t msg[TC_DES_BLOCKLEN] = {0};

  memcpy(key, k1, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN, k2, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN_2KEY, k3, TC_DES_KEYLEN);
  munit_assert(expect_iso9797_status(key, TC_DES_KEYLEN_2KEY, 1));
  munit_assert(expect_iso9797_status(key, TC_DES_KEYLEN_3KEY, 1));

  /* K1 = K3 stays a valid two-key form. */
  memcpy(key + TC_DES_KEYLEN_2KEY, k1, TC_DES_KEYLEN);
  munit_assert(expect_iso9797_status(key, TC_DES_KEYLEN_3KEY, 1));

  /* K1 = K2 reduces Algorithm 3 to Algorithm 1. */
  memcpy(key + TC_DES_KEYLEN, k1, TC_DES_KEYLEN);
  munit_assert(expect_iso9797_status(key, TC_DES_KEYLEN_2KEY, 0));
  memcpy(key + TC_DES_KEYLEN_2KEY, k3, TC_DES_KEYLEN);
  munit_assert(expect_iso9797_status(key, TC_DES_KEYLEN_3KEY, 0));

  /* K2 = K3 cancels the output transformation. */
  memcpy(key + TC_DES_KEYLEN, k2, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN_2KEY, k2, TC_DES_KEYLEN);
  munit_assert(expect_iso9797_status(key, TC_DES_KEYLEN_3KEY, 0));

  /* A weak component key in each position. */
  memcpy(key + TC_DES_KEYLEN_2KEY, k3, TC_DES_KEYLEN);
  memcpy(key, weak_keys[1], TC_DES_KEYLEN);
  munit_assert(expect_iso9797_status(key, TC_DES_KEYLEN_2KEY, 0));
  memcpy(key, k1, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN, weak_keys[4], TC_DES_KEYLEN);
  munit_assert(expect_iso9797_status(key, TC_DES_KEYLEN_2KEY, 0));
  memcpy(key + TC_DES_KEYLEN, k2, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN_2KEY, weak_keys[7], TC_DES_KEYLEN);
  munit_assert(expect_iso9797_status(key, TC_DES_KEYLEN_3KEY, 0));

  /* The one-shot MAC applies the same policy. */
  memcpy(key + TC_DES_KEYLEN, k1, TC_DES_KEYLEN);
  munit_assert(
      expect_key_status(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD_NONE, key,
                                           TC_DES_KEYLEN_2KEY, msg, sizeof msg, tag, sizeof tag)));
}
#endif

static MunitResult test_profile(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  static const uint8_t k1[TC_DES_KEYLEN] = {0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1};
  static const uint8_t k2[TC_DES_KEYLEN] = {0x0e, 0x32, 0x92, 0x32, 0xea, 0x6d, 0x0d, 0x73};
  static const uint8_t k3[TC_DES_KEYLEN] = {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18};
  struct TC_DES_ctx des;
  struct TC_DES_ctx des3;
#if TC_DES_ENABLE_CMAC
  struct TC_DES_CMAC_ctx cmac;
#endif
  uint8_t key[TC_DES_KEYLEN_3KEY];
  size_t i;

  munit_assert(TC_DES_init(&des, k1, TC_DES_KEYLEN) == TC_OK);
  for (i = 0; i < 16; ++i) {
    munit_assert(expect_key_status(TC_DES_init(&des, weak_keys[i], TC_DES_KEYLEN)));
#if TC_DES_ENABLE_CMAC
    munit_assert(expect_key_status(TC_DES_CMAC_init(&cmac, weak_keys[i], TC_DES_KEYLEN)));
#endif
  }

  memcpy(key, weak_keys[0], TC_DES_KEYLEN);
  for (i = 0; i < TC_DES_KEYLEN; ++i)
    key[i] ^= 0x01u;
  munit_assert(expect_key_status(TC_DES_init(&des, key, TC_DES_KEYLEN)));

  memcpy(key, k1, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN, k2, TC_DES_KEYLEN);
  munit_assert(TC_DES_init(&des3, key, TC_DES_KEYLEN_2KEY) == TC_OK);

  memcpy(key + TC_DES_KEYLEN, weak_keys[0], TC_DES_KEYLEN);
  munit_assert(expect_key_status(TC_DES_init(&des3, key, TC_DES_KEYLEN_2KEY)));
#if TC_DES_ENABLE_CMAC
  munit_assert(expect_key_status(TC_DES_CMAC_init(&cmac, key, TC_DES_KEYLEN_2KEY)));
#endif

  memcpy(key + TC_DES_KEYLEN, k1, TC_DES_KEYLEN);
  munit_assert(expect_key_status(TC_DES_init(&des3, key, TC_DES_KEYLEN_2KEY)));
  for (i = TC_DES_KEYLEN; i < TC_DES_KEYLEN_2KEY; ++i)
    key[i] ^= 0x01u;
  munit_assert(expect_key_status(TC_DES_init(&des3, key, TC_DES_KEYLEN_2KEY)));

  memcpy(key, k1, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN, k2, TC_DES_KEYLEN);
  memcpy(key + (2u * TC_DES_KEYLEN), k1, TC_DES_KEYLEN);
  munit_assert(TC_DES_init(&des3, key, TC_DES_KEYLEN_3KEY) == TC_OK);

  memcpy(key + (2u * TC_DES_KEYLEN), k3, TC_DES_KEYLEN);
  munit_assert(TC_DES_init(&des3, key, TC_DES_KEYLEN_3KEY) == TC_OK);

  memcpy(key, weak_keys[0], TC_DES_KEYLEN);
  munit_assert(expect_key_status(TC_DES_init(&des3, key, TC_DES_KEYLEN_3KEY)));

  memcpy(key, k1, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN, weak_keys[0], TC_DES_KEYLEN);
  munit_assert(expect_key_status(TC_DES_init(&des3, key, TC_DES_KEYLEN_3KEY)));

  memcpy(key + TC_DES_KEYLEN, k2, TC_DES_KEYLEN);
  memcpy(key + (2u * TC_DES_KEYLEN), weak_keys[0], TC_DES_KEYLEN);
  munit_assert(expect_key_status(TC_DES_init(&des3, key, TC_DES_KEYLEN_3KEY)));

  memcpy(key, k1, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN, k1, TC_DES_KEYLEN);
  memcpy(key + (2u * TC_DES_KEYLEN), k3, TC_DES_KEYLEN);
  munit_assert(expect_key_status(TC_DES_init(&des3, key, TC_DES_KEYLEN_3KEY)));

  memcpy(key, k1, TC_DES_KEYLEN);
  memcpy(key + TC_DES_KEYLEN, k2, TC_DES_KEYLEN);
  memcpy(key + (2u * TC_DES_KEYLEN), k2, TC_DES_KEYLEN);
  munit_assert(expect_key_status(TC_DES_init(&des3, key, TC_DES_KEYLEN_3KEY)));

#if TC_DES_ENABLE_ISO9797
  check_iso9797_profile(k1, k2, k3);
#endif

  puts("DES weak-key policy: OK");
  return MUNIT_OK;
}

static MunitTest tests[] = {{"/profile", test_profile, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/des-weak-keys", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
