/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "aes_platform_internal.h"
#include <tiny_crypto/aes_dynamic.h>
#include "munit.h"
#include <string.h>

static tc_aes_platform_result result;
static unsigned calls;
static int direction;

tc_aes_platform_result tc_aes_platform_block(const uint8_t* key, uint8_t rounds,
                                            uint8_t block[16], int decrypt)
{
  (void)key;
  munit_assert_uint8(rounds, ==, 10);
  ++calls;
  direction = decrypt;
  if (result != TC_AES_PLATFORM_UNSUPPORTED) memset(block, 0xab, 16);
  return result;
}

static MunitResult dispatch(const MunitParameter params[], void* user)
{
  static const uint8_t expected[16] = {
    0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,
    0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e
  };
  uint8_t key[16] = {0}, block[16] = {0}, zero[16] = {0};
  TC_AES_dynamic_key context;
  unsigned i;
  (void)params; (void)user;
  munit_assert_int(TC_AES_dynamic_key_init(&context, key, sizeof key), ==, TC_OK);
  result = TC_AES_PLATFORM_UNSUPPORTED; calls = 0;
  munit_assert_int(TC_AES_dynamic_encrypt(&context, block), ==, TC_OK);
  munit_assert_memory_equal(16, block, expected);
  munit_assert_uint(calls, ==, 1);
  munit_assert_int(direction, ==, 0);
  munit_assert_int(TC_AES_dynamic_decrypt(&context, block), ==, TC_OK);
  munit_assert_memory_equal(16, block, zero);
  munit_assert_int(direction, ==, 1);
  for (i = 0; i < 2; ++i) {
    result = i ? TC_AES_PLATFORM_ERROR : TC_AES_PLATFORM_OK;
    calls = 0;
    munit_assert_int(TC_AES_dynamic_encrypt(&context, block), ==, i ? TC_ERROR : TC_OK);
    munit_assert_uint(calls, ==, 1);
    munit_assert_uint8(block[0], ==, 0xab);
    munit_assert_int(TC_AES_dynamic_decrypt(&context, block), ==, i ? TC_ERROR : TC_OK);
    munit_assert_uint(calls, ==, 2);
    munit_assert_int(direction, ==, 1);
  }
  TC_AES_dynamic_key_clear(&context);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/dispatch", dispatch, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

int main(int argc, char** argv)
{
  MunitSuite suite = {"/aes-platform", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
