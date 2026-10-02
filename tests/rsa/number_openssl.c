/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "../../src/mp_inverse_internal.h"
#include "munit.h"
#include "test_util.h"
#include <openssl/bn.h>

enum { MAX_BYTES = 512, MAX_WORDS = MAX_BYTES / sizeof(tc_mp_word), SAMPLES = 24 };

static void to_words(tc_mp_word* out, const BIGNUM* value, size_t bytes)
{
  uint8_t buffer[2 * MAX_BYTES];
  munit_assert_int(BN_bn2binpad(value, buffer, (int)bytes), ==, (int)bytes);
  tc_mp_from_be(out, buffer, bytes);
}

static void assert_equal(const tc_mp_word* words, const BIGNUM* expected, size_t bytes)
{
  uint8_t actual[2 * MAX_BYTES], wanted[2 * MAX_BYTES];
  tc_mp_to_be(actual, words, bytes);
  munit_assert_int(BN_bn2binpad(expected, wanted, (int)bytes), ==, (int)bytes);
  munit_assert_memory_equal(bytes, actual, wanted);
}

/* Random value of at most bits bits, sometimes with its top bit forced. */
static void random_value(BIGNUM* out, int bits)
{
  const int top = munit_rand_int_range(0, 1) ? BN_RAND_TOP_ONE : BN_RAND_TOP_ANY;
  munit_assert_int(BN_rand(out, munit_rand_int_range(2, bits), top, BN_RAND_BOTTOM_ANY), ==, 1);
}

/* tc_mp_divide_words matches BN_div for quotient and remainder. */
TC_TEST(divide)
{
  static tc_mp_word input[2 * MAX_WORDS], divisor[MAX_WORDS], quotient[2 * MAX_WORDS],
      remainder[MAX_WORDS], scratch[MAX_WORDS];
  BN_CTX* context = BN_CTX_new();
  BIGNUM *a = BN_new(), *d = BN_new(), *q = BN_new(), *r = BN_new();
  munit_assert_not_null(context);
  for (size_t bytes = 16; bytes <= MAX_BYTES; bytes *= 2) {
    const size_t n = bytes / sizeof(tc_mp_word);
    for (unsigned sample = 0; sample < SAMPLES; ++sample) {
      random_value(a, (int)(16 * bytes));
      do
        random_value(d, (int)(8 * bytes));
      while (BN_is_one(d) || BN_is_zero(d));
      if (sample == 0)
        BN_set_word(d, 2);
      munit_assert_int(BN_div(q, r, a, d, context), ==, 1);
      to_words(input, a, 2 * bytes);
      to_words(divisor, d, bytes);
      tc_mp_divide_words(quotient, remainder, input, 2 * n, divisor, n, scratch);
      assert_equal(quotient, q, 2 * bytes);
      assert_equal(remainder, r, bytes);
      /* Remainder-only form. */
      memset(remainder, 0xa5, sizeof remainder);
      tc_mp_reduce_words(remainder, input, 2 * n, divisor, n, scratch);
      assert_equal(remainder, r, bytes);
    }
  }
  BN_free(a);
  BN_free(d);
  BN_free(q);
  BN_free(r);
  BN_CTX_free(context);
  return MUNIT_OK;
}

/* tc_mp_gcd matches BN_gcd, including shared powers of two. */
TC_TEST(gcd)
{
  static tc_mp_word x[MAX_WORDS], y[MAX_WORDS], out[MAX_WORDS], scratch[3 * MAX_WORDS];
  BN_CTX* context = BN_CTX_new();
  BIGNUM *a = BN_new(), *b = BN_new(), *g = BN_new(), *common = BN_new();
  munit_assert_not_null(context);
  for (size_t bytes = 16; bytes <= MAX_BYTES / 2; bytes *= 2) {
    const size_t n = bytes / sizeof(tc_mp_word);
    for (unsigned sample = 0; sample < SAMPLES; ++sample) {
      do {
        random_value(a, (int)(8 * bytes) - 16);
        random_value(b, (int)(8 * bytes) - 16);
      } while (BN_is_zero(a) || BN_is_zero(b));
      /* Share a random factor, then vary the power of two on each side. */
      random_value(common, 16);
      if (!BN_is_zero(common)) {
        munit_assert_int(BN_mul(a, a, common, context), ==, 1);
        munit_assert_int(BN_mul(b, b, common, context), ==, 1);
      }
      if (sample % 3 == 0) {
        munit_assert_int(BN_lshift(a, a, 5), ==, 1);
        munit_assert_int(BN_lshift(b, b, 3), ==, 1);
      }
      if (sample == 1)
        BN_copy(b, a);
      if (BN_num_bytes(a) > (int)bytes || BN_num_bytes(b) > (int)bytes)
        continue;
      munit_assert_int(BN_gcd(g, a, b, context), ==, 1);
      to_words(x, a, bytes);
      to_words(y, b, bytes);
      tc_mp_gcd(out, x, y, n, scratch);
      assert_equal(out, g, bytes);
    }
  }
  BN_free(a);
  BN_free(b);
  BN_free(g);
  BN_free(common);
  BN_CTX_free(context);
  return MUNIT_OK;
}

/* The small-divisor helpers match BN_div_word and BN_mod_word. */
TC_TEST(small_divisor)
{
  static const uint32_t divisors[] = {3, 7, 251, 65537, 0x7fffffffu};
  static tc_mp_word words[MAX_WORDS], quotient[MAX_WORDS];
  uint8_t bytes[MAX_BYTES];
  BIGNUM *a = BN_new(), *q = BN_new();
  for (unsigned sample = 0; sample < SAMPLES; ++sample)
    for (size_t i = 0; i < sizeof divisors / sizeof *divisors; ++i) {
      random_value(a, 8 * MAX_BYTES);
      munit_assert_int(BN_bn2binpad(a, bytes, MAX_BYTES), ==, MAX_BYTES);
      const BN_ULONG expected = BN_mod_word(a, divisors[i]);
      munit_assert_uint32(tc_mp_mod_u32_be(bytes, MAX_BYTES, divisors[i]), ==, (uint32_t)expected);
      tc_mp_from_be(words, bytes, MAX_BYTES);
      munit_assert_uint32(tc_mp_divide_u32(quotient, words, MAX_WORDS, divisors[i]), ==,
                          (uint32_t)expected);
      BN_copy(q, a);
      BN_div_word(q, divisors[i]);
      assert_equal(quotient, q, MAX_BYTES);
    }
  BN_free(a);
  BN_free(q);
  return MUNIT_OK;
}

TC_TEST(zero_mask)
{
  tc_mp_word value[4] = {0};
  munit_assert_uint((unsigned)tc_mp_zero_mask(value, 4), ==, (unsigned)(tc_mp_word)~0u);
  for (size_t i = 0; i < 4; ++i)
    for (unsigned bit = 0; bit < TC_MP_WORD_BITS; ++bit) {
      memset(value, 0, sizeof value);
      value[i] = (tc_mp_word)((tc_mp_word)1u << bit);
      munit_assert_uint((unsigned)tc_mp_zero_mask(value, 4), ==, 0);
    }
  return MUNIT_OK;
}

int main(int argc, char* argv[])
{
  MunitTest tests[] = {{"/divide", divide, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/gcd", gcd, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/small-divisor", small_divisor, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/zero-mask", zero_mask, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/rsa/number", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
