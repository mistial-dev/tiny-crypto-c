/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* A cipher failure part way through a buffer must not leave a partly
 * transformed buffer or a context that continues from a broken chaining
 * value. The build compiles aes_modes.c and block_modes.c into this test with
 * the block cipher renamed to the wrappers below, which call the library's
 * cipher and fail a chosen block. */
#include "aes_internal.h"
#include <tiny_crypto/aes_dynamic.h>
#include "munit.h"
#include "test_util.h"
#include <string.h>

#undef tc_aes_cipher_rounds
#undef tc_aes_inverse_rounds
TC_status tc_aes_cipher_rounds(state_t*, const uint8_t*, uint8_t);
TC_status tc_aes_inverse_rounds(state_t*, const uint8_t*, uint8_t);

static unsigned calls, fail_at;

/* Returns 1 when this block cipher call is the one chosen to fail. A failed
 * device may leave the block modified. */
static int fail_this_call(state_t* state)
{
  if (++calls != fail_at)
    return 0;
  memset(state, 0xa5, sizeof *state);
  return 1;
}

TC_status tc_test_cipher_rounds(state_t* state, const uint8_t* key, uint8_t rounds)
{
  return fail_this_call(state) ? TC_ERROR : tc_aes_cipher_rounds(state, key, rounds);
}

TC_status tc_test_inverse_rounds(state_t* state, const uint8_t* key, uint8_t rounds)
{
  return fail_this_call(state) ? TC_ERROR : tc_aes_inverse_rounds(state, key, rounds);
}

TC_status tc_test_cipher(state_t* state, const uint8_t* key)
{
  return tc_test_cipher_rounds(state, key, TC_AES_FIXED_ROUNDS);
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
  fail_at = 0;
  munit_assert_int(mode(&ctx, buffer, length), ==, TC_OK);
  munit_assert_uint(calls, >, 1);
  munit_assert_int(TC_AES_ctx_set_iv(&ctx, iv), ==, TC_OK);
  calls = 0;
  fail_at = 2;
  munit_assert_int(mode(&ctx, buffer, length), ==, TC_ERROR);
  munit_assert_true(tc_test_all_zero(buffer, length));
  munit_assert_true(tc_test_all_zero(&ctx, sizeof ctx));
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

static MunitResult ecb(const MunitParameter params[], void* user)
{
  static const uint8_t key[TC_AES_KEYLEN] = {1};
  struct TC_AES_key_ctx schedule;
  uint8_t block[TC_AES_BLOCKLEN] = {0};
  (void)params;
  (void)user;
  munit_assert_int(TC_AES_key_init(&schedule, key), ==, TC_OK);
  /* A failed block cipher call leaves no partly transformed block. */
  calls = 0;
  fail_at = 1;
  memset(block, 0x33, sizeof block);
  munit_assert_int(TC_AES_ECB_encrypt(&schedule, block), ==, TC_ERROR);
  munit_assert_true(tc_test_all_zero(block, sizeof block));
  calls = 0;
  memset(block, 0x33, sizeof block);
  munit_assert_int(TC_AES_ECB_decrypt(&schedule, block), ==, TC_ERROR);
  munit_assert_true(tc_test_all_zero(block, sizeof block));
  fail_at = 0;
  munit_assert_int(TC_AES_ECB_encrypt(&schedule, block), ==, TC_OK);
  TC_AES_key_ctx_clear(&schedule);
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
                            {"/ecb", ecb, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {"/dynamic-cbc", dynamic_cbc, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

int main(int argc, char** argv)
{
  MunitSuite suite = {"/aes-mode-failure", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
