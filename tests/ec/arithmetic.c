/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/ec.h>
#define TC_MP_WORD_BITS TC_EC_WORD_BITS
#include "../../src/mp_internal.h"
#include "../../src/rsa_internal.h"
#include "munit.h"
#include "test_util.h"

static void encode(tc_mp_word* out, uint32_t value, size_t n)
{
  uint64_t remaining = value;
  for (size_t i = 0; i < n; ++i) {
    out[i] = (tc_mp_word)remaining;
    remaining >>= TC_MP_WORD_BITS;
  }
}

static uint32_t power(uint32_t value, uint32_t exponent, uint32_t modulus)
{
  uint64_t result = 1, base = value;
  while (exponent) {
    if (exponent & 1)
      result = result * base % modulus;
    base = base * base % modulus;
    exponent >>= 1;
  }
  return (uint32_t)result;
}

TC_TEST(montgomery)
{
  enum { MAX_WORDS = 3072 / TC_MP_WORD_BITS };
  static const uint32_t primes[] = {251, 65521, 2147483647};
  tc_mp_word a[MAX_WORDS], b[MAX_WORDS], p[MAX_WORDS], out[MAX_WORDS];
  tc_mp_word product[2 * MAX_WORDS + 2], reduced[MAX_WORDS];
  for (size_t k = 0; k < sizeof primes / sizeof *primes; ++k) {
    uint32_t modulus = primes[k];
    for (size_t bytes = 4; bytes <= 384; bytes = bytes == 4 ? 128 : bytes + 128) {
      size_t n = bytes / sizeof(tc_mp_word);
      uint64_t radix = 1;
      tc_mp_word n0;
      uint32_t state = 7;
      encode(p, modulus, n);
      n0 = tc_mp_montgomery_factor(p[0]);
      munit_assert_uint((tc_mp_word)((tc_mp_wide)p[0] * n0), ==, (tc_mp_word) ~(tc_mp_word)0);
      for (size_t bit = 0; bit < bytes * 8; ++bit)
        radix = radix * 2 % modulus;
      tc_mp_montgomery_r2(out, p, n, reduced);
      encode(a, (uint32_t)(radix * radix % modulus), n);
      munit_assert_memory_equal(n * sizeof *out, out, a);
      /* Fermat inversion is independent of the limb reduction implementation. */
      uint32_t reciprocal = power((uint32_t)radix, modulus - 2, modulus);
      for (unsigned sample = 0; sample < (bytes == 4 ? 256u : 4u); ++sample) {
        uint32_t left, right, expected;
        state = state * 1664525u + 1013904223u;
        left = state % modulus;
        state = state * 1664525u + 1013904223u;
        right = state % modulus;
        if (sample == 0)
          left = 0;
        if (sample == 1)
          left = right = modulus - 1;
        expected = (uint32_t)(((uint64_t)left * right % modulus) * reciprocal % modulus);
        encode(a, left, n);
        encode(b, right, n);
        const tc_mp_modulus field = {p, n, n0, product, reduced};
        tc_mp_montgomery(out, a, b, &field);
        encode(reduced, expected, n);
        munit_assert_memory_equal(n * sizeof *out, out, reduced);
        tc_mp_montgomery(a, a, b, &field);
        munit_assert_memory_equal(n * sizeof *out, out, a);
      }
    }
  }
  return MUNIT_OK;
}

TC_TEST(full_width)
{
  enum { MAX_WORDS = 3072 / TC_MP_WORD_BITS };
  tc_mp_word p[MAX_WORDS], a[MAX_WORDS], r2[MAX_WORDS], expected[MAX_WORDS];
  tc_mp_word product[2 * MAX_WORDS + 2], reduced[MAX_WORDS];
  for (size_t bytes = 128; bytes <= 384; bytes += 128) {
    size_t n = bytes / sizeof(tc_mp_word);
    tc_mp_word factor;
    /* For p = R-45, R^2 mod p = 2025 and (p-1)^2 mod p = 1. */
    memset(p, 0xff, n * sizeof *p);
    p[0] -= 44;
    factor = tc_mp_montgomery_factor(p[0]);
    tc_mp_montgomery_r2(r2, p, n, reduced);
    encode(expected, 2025, n);
    munit_assert_memory_equal(n * sizeof *r2, r2, expected);
    memcpy(a, p, n * sizeof *a);
    --a[0];
    const tc_mp_modulus field = {p, n, factor, product, reduced};
    tc_mp_montgomery(a, a, r2, &field);
    memcpy(expected, p, n * sizeof *expected);
    expected[0] -= 45;
    munit_assert_memory_equal(n * sizeof *a, a, expected);
    tc_mp_montgomery(a, a, a, &field);
    encode(expected, 45, n);
    munit_assert_memory_equal(n * sizeof *a, a, expected);
    encode(expected, 1, n);
    tc_mp_montgomery(a, a, expected, &field);
    munit_assert_memory_equal(n * sizeof *a, a, expected);
  }
  return MUNIT_OK;
}

TC_TEST(exponentiation)
{
  enum { N = 32 / TC_MP_WORD_BITS };
  tc_mp_word p[N], base[N], one[N], out[N], temporary[N], product[2 * N + 2], reduced[N];
  const uint32_t modulus = 65521;
  tc_mp_word factor;
  uint64_t radix = 1;
  encode(p, modulus, N);
  factor = tc_mp_montgomery_factor(p[0]);
  for (unsigned bit = 0; bit < 32; ++bit)
    radix = radix * 2 % modulus;
  encode(one, (uint32_t)radix, N);
  const tc_mp_modulus field = {p, N, factor, product, reduced};
  for (unsigned sample = 0; sample < 128; ++sample) {
    uint32_t value = sample ? (sample * 719u) % modulus : 0;
    uint32_t exponent = sample ? sample * 509u : 0;
    uint8_t encoded[] = {0, (uint8_t)(exponent >> 8), (uint8_t)exponent};
    encode(base, (uint32_t)(value * radix % modulus), N);
    tc_mp_power(out, base, (TC_bytes){encoded, sizeof encoded}, one, &field, temporary);
    encode(temporary, (uint32_t)(power(value, exponent, modulus) * radix % modulus), N);
    munit_assert_memory_equal(sizeof out, out, temporary);
    tc_mp_power(out, base, (TC_bytes){encoded + 1, 2}, one, &field, temporary);
    encode(temporary, (uint32_t)(power(value, exponent, modulus) * radix % modulus), N);
    munit_assert_memory_equal(sizeof out, out, temporary);
    for (size_t width = 2; width <= 5; ++width) {
      tc_mp_power_padded(out, base, (TC_bytes){encoded + 1, 2}, width, one, &field, temporary);
      encode(temporary, (uint32_t)(power(value, exponent, modulus) * radix % modulus), N);
      munit_assert_memory_equal(sizeof out, out, temporary);
    }
  }
  tc_mp_power(out, base, (TC_bytes){NULL, 0}, one, &field, temporary);
  munit_assert_memory_equal(sizeof out, out, one);
  tc_mp_power_padded(out, base, (TC_bytes){NULL, 0}, 4, one, &field, temporary);
  munit_assert_memory_equal(sizeof out, out, one);
  return MUNIT_OK;
}

TC_TEST(public_operation)
{
  uint8_t modulus[128], input[128] = {0}, output[128], saved[128], exponent[] = {3};
  tc_mp_word scratch[8 * 128 / sizeof(tc_mp_word) + 2];
  const size_t capacity = sizeof scratch / sizeof *scratch, cost = 16 * 128 + 16 + 4;
  uint32_t work;
  memset(modulus, 0xff, sizeof modulus);
  modulus[127] = 0xd3;
  input[127] = 1;
  memset(output, 0xa5, sizeof output);
  memcpy(saved, output, sizeof saved);
  work = cost - 1;
  munit_assert_int(tc_rsa_public_operation(&(TC_RSA_public_key){{modulus, 128}, {exponent, 1}},
                                           input, output, (tc_mp_scratch){scratch, capacity}, &work,
                                           NULL),
                   ==, TC_RSA_LIMIT);
  munit_assert_memory_equal(sizeof output, output, saved);
  work = cost;
  munit_assert_int(tc_rsa_public_operation(&(TC_RSA_public_key){{modulus, 128}, {exponent, 1}},
                                           input, output, (tc_mp_scratch){scratch, capacity - 1},
                                           &work, NULL),
                   ==, TC_RSA_LIMIT);
  munit_assert_size(work, ==, cost);
  munit_assert_memory_equal(sizeof output, output, saved);
  /* Key shape is checked at the public entries. The kernel checks the
   * representative against the modulus. */
  munit_assert_int(tc_rsa_public_operation(&(TC_RSA_public_key){{modulus, 128}, {exponent, 1}},
                                           modulus, output, (tc_mp_scratch){scratch, capacity},
                                           &work, NULL),
                   ==, TC_RSA_INVALID);
  munit_assert_memory_equal(sizeof output, output, saved);
  munit_assert_int(tc_rsa_public_operation(&(TC_RSA_public_key){{modulus, 128}, {exponent, 1}},
                                           input, output, (tc_mp_scratch){scratch, capacity}, &work,
                                           NULL),
                   ==, TC_RSA_OK);
  munit_assert_memory_equal(sizeof output, output, input);
  munit_assert_size(work, ==, 0);
  for (size_t i = 0; i < capacity; ++i)
    munit_assert_uint(scratch[i], ==, 0);
  return MUNIT_OK;
}

TC_TEST(padded_input)
{
  enum { WIDTH = 16 };
  uint8_t input[WIDTH], encoded[WIDTH];
  tc_mp_word words[WIDTH / sizeof(tc_mp_word) + 1];
  for (size_t i = 0; i < WIDTH; ++i)
    input[i] = (uint8_t)(i + 1);
  for (size_t length = 0; length <= WIDTH; ++length) {
    memset(words, 0xa5, sizeof words);
    tc_mp_from_be_padded(words, length ? input : NULL, length, WIDTH);
    tc_mp_to_be(encoded, words, WIDTH);
    for (size_t i = 0; i < WIDTH - length; ++i)
      munit_assert_uint(encoded[i], ==, 0);
    if (length)
      munit_assert_memory_equal(length, encoded + WIDTH - length, input);
    for (size_t i = WIDTH; i < sizeof words; ++i)
      munit_assert_uint(((uint8_t*)words)[i], ==, 0xa5);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/padded-input", padded_input, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/montgomery", montgomery, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/full-width", full_width, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/exponentiation", exponentiation, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/rsa-public", public_operation, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/arithmetic", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
