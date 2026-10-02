/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "munit.h"
#include "test_util.h"

#include <tiny_crypto/aes.h>
#include <tiny_crypto/aes_kw.h>
#include <string.h>

TC_TEST(test_profile)
{
  struct TC_AES_ctx ctx;
  uint8_t key[TC_AES_KEYLEN] = {0};
  uint8_t tag[TC_AES_CMAC_TAG_MAX];
  uint8_t key_data[16] = {0}, wrapped[24], unwrapped[16];
  const TC_bytes kek = {key, sizeof key};
  size_t length = SIZE_MAX;

  munit_assert_false(TC_AES_init(&ctx, (TC_bytes){key, TC_AES_KEYLEN}) != TC_ERROR);
  munit_assert_false(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){NULL, 0},
                                 (TC_buffer){tag, sizeof(tag)}) != TC_ERROR);
  /* Key wrap schedules its KEK before the first output write. */
  memset(wrapped, 0xa5, sizeof wrapped);
  munit_assert_int(TC_AES_KW_wrap(kek, (TC_bytes){key_data, sizeof key_data},
                                  (TC_buffer){wrapped, sizeof wrapped}),
                   ==, TC_ERROR);
  munit_assert_true(tc_test_all_value(wrapped, sizeof wrapped, 0xa5));
  memset(unwrapped, 0xa5, sizeof unwrapped);
  munit_assert_int(TC_AES_KWP_unwrap(kek, (TC_bytes){wrapped, sizeof wrapped},
                                     (TC_buffer){unwrapped, sizeof unwrapped}, &length),
                   ==, TC_ERROR);
  munit_assert_true(tc_test_all_value(unwrapped, sizeof unwrapped, 0xa5));
  munit_assert_size(length, ==, SIZE_MAX);
  TC_AES_init_sbox();
  munit_assert_false(TC_AES_init(&ctx, (TC_bytes){key, TC_AES_KEYLEN}) != TC_OK);
  munit_assert_false(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){NULL, 0},
                                 (TC_buffer){tag, sizeof(tag)}) != TC_OK);
  munit_assert_int(
      TC_AES_KWP_wrap(kek, (TC_bytes){key_data, 13}, (TC_buffer){wrapped, sizeof wrapped}), ==,
      TC_OK);
  munit_assert_int(TC_AES_KWP_unwrap(kek, (TC_bytes){wrapped, sizeof wrapped},
                                     (TC_buffer){unwrapped, sizeof unwrapped}, &length),
                   ==, TC_OK);
  munit_assert_size(length, ==, 13);
  munit_assert_int(TC_AES_KW_wrap(kek, (TC_bytes){key_data, sizeof key_data},
                                  (TC_buffer){wrapped, sizeof wrapped}),
                   ==, TC_OK);
  munit_assert_int(TC_AES_KW_unwrap(kek, (TC_bytes){wrapped, sizeof wrapped},
                                    (TC_buffer){unwrapped, sizeof unwrapped}),
                   ==, TC_OK);
  munit_assert_true(tc_test_all_zero(unwrapped, sizeof unwrapped));
  return MUNIT_OK;
}

static MunitTest tests[] = {{"/profile", test_profile, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/runtime-sbox", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
