/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* A platform cipher failure part way through a buffer must not leave a
 * partly transformed buffer or a context that continues from a broken
 * chaining value. */
#include "aes_platform_internal.h"
#include <tiny_crypto/aes.h>
#include <tiny_crypto/aes_dynamic.h>
#include "munit.h"
#include "test_util.h"
#include <string.h>

static unsigned calls, fail_at;

tc_aes_platform_result tc_aes_platform_block(const uint8_t* key, uint8_t rounds, uint8_t block[16],
                                             int decrypt)
{
  (void)key;
  (void)rounds;
  (void)decrypt;
  if (++calls == fail_at) {
    memset(block, 0xa5, 16); /* A failed device may modify the block. */
    return TC_AES_PLATFORM_ERROR;
  }
  return TC_AES_PLATFORM_UNSUPPORTED;
}

typedef TC_status (*mode_fn)(struct TC_AES_ctx* ctx, uint8_t* buffer, size_t length);

static void check_fixed_mode(mode_fn mode, size_t length)
{
  static const uint8_t key[TC_AES_KEYLEN] = {1, 2, 3};
  static const uint8_t iv[TC_AES_BLOCKLEN] = {4, 5, 6};
  uint8_t buffer[48];
  struct TC_AES_ctx ctx;
  munit_assert_size(length, <=, sizeof buffer);
  munit_assert_int(TC_AES_init_ctx_iv(&ctx, key, iv), ==, TC_OK);
  memset(buffer, 0x11, sizeof buffer);
  calls = 0;
  fail_at = 2;
  munit_assert_int(mode(&ctx, buffer, length), ==, TC_ERROR);
  munit_assert_true(tc_test_all_zero(buffer, length));
  fail_at = 0;
  munit_assert_int(mode(&ctx, buffer, length), ==, TC_ERROR);
}

static MunitResult fixed_modes(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  check_fixed_mode(TC_AES_CBC_encrypt, 48);
  check_fixed_mode(TC_AES_CBC_decrypt, 48);
  check_fixed_mode(TC_AES_CTR_crypt, 40);
  check_fixed_mode(TC_AES_OFB_crypt, 40);
  return MUNIT_OK;
}

static MunitResult dynamic_cbc(const MunitParameter params[], void* user)
{
  static const uint8_t raw[16] = {7, 8, 9};
  TC_AES_dynamic_key key;
  uint8_t iv[16], buffer[48];
  (void)params;
  (void)user;
  munit_assert_int(TC_AES_dynamic_key_init(&key, raw, sizeof raw), ==, TC_OK);
  for (int decrypt = 0; decrypt < 2; ++decrypt) {
    memset(iv, 0x22, sizeof iv);
    memset(buffer, 0x11, sizeof buffer);
    calls = 0;
    fail_at = 2;
    munit_assert_int(decrypt ? TC_AES_dynamic_CBC_decrypt(&key, iv, buffer, sizeof buffer)
                             : TC_AES_dynamic_CBC_encrypt(&key, iv, buffer, sizeof buffer),
                     ==, TC_ERROR);
    munit_assert_true(tc_test_all_zero(buffer, sizeof buffer));
    munit_assert_true(tc_test_all_zero(iv, sizeof iv));
  }
  fail_at = 0;
  TC_AES_dynamic_key_clear(&key);
  return MUNIT_OK;
}

static MunitTest tests[] = {{"/fixed", fixed_modes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {"/dynamic-cbc", dynamic_cbc, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

int main(int argc, char** argv)
{
  MunitSuite suite = {"/aes-mode-failure", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
