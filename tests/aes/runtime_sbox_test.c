/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "munit.h"

#include <tiny_crypto/aes.h>

static MunitResult test_profile(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  struct TC_AES_ctx ctx;
  uint8_t key[TC_AES_KEYLEN] = { 0 };
  uint8_t tag[TC_AES_CMAC_TAG_MAX];

  munit_assert_false(TC_AES_init_ctx(&ctx, key) != TC_ERROR);
  munit_assert_false(TC_AES_CMAC(key, NULL, 0, tag, sizeof(tag)) != TC_ERROR);
  TC_AES_init_sbox();
  munit_assert_false(TC_AES_init_ctx(&ctx, key) != TC_OK);
  munit_assert_false(TC_AES_CMAC(key, NULL, 0, tag, sizeof(tag)) != TC_OK);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/profile", test_profile, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
static const MunitSuite suite = {"/runtime-sbox", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{ return munit_suite_main(&suite, NULL, argc, argv); }
