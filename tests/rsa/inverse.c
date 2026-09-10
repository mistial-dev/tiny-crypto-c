/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "../../src/mp_inverse_internal.h"
#include "munit.h"

static uint32_t gcd(uint32_t a, uint32_t b)
{
  while (b) { uint32_t remainder = a % b; a = b; b = remainder; }
  return a;
}

static void check(uint32_t value, uint32_t modulus)
{
  enum { BYTES = 4, WORDS = BYTES / sizeof(tc_mp_word) };
  uint8_t a_bytes[BYTES], p_bytes[BYTES], output[BYTES];
  tc_mp_word a[WORDS], p[WORDS], inverse[WORDS], scratch[6 * WORDS];
  for (size_t i = 0; i < BYTES; ++i) {
    a_bytes[BYTES - 1 - i] = (uint8_t)(value >> (8 * i));
    p_bytes[BYTES - 1 - i] = (uint8_t)(modulus >> (8 * i));
  }
  tc_mp_from_be(a,a_bytes,sizeof a_bytes); tc_mp_from_be(p,p_bytes,sizeof p_bytes);
  memset(inverse,0xa5,sizeof inverse);
  const int invertible = gcd(value,modulus) == 1;
  munit_assert_int(tc_mp_inverse(inverse,a,p,WORDS,scratch), ==, invertible);
  tc_mp_to_be(output,inverse,sizeof output);
  if (invertible) {
    uint32_t result = 0;
    for (size_t i = 0; i < sizeof output; ++i) result = (result << 8) | output[i];
    munit_assert_uint(result, <, modulus);
    munit_assert_uint64(((uint64_t)value * result) % modulus, ==, 1);
  } else {
    for (size_t i = 0; i < sizeof output; ++i) munit_assert_uint(output[i], ==, 0xa5);
  }
}

static MunitResult small_moduli(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  for (uint32_t p = 3; p <= 255; p += 2)
    for (uint32_t a = 0; a < p; ++a) check(a,p);
  return MUNIT_OK;
}

static MunitResult carry_boundaries(const MunitParameter params[], void* user)
{
  static const uint32_t moduli[] = {257,65535,65537,0x7fffffffu,0x80000001u,0xfffffffbu,UINT32_MAX};
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof moduli / sizeof *moduli; ++i) {
    const uint32_t p = moduli[i], values[] = {0,1,2,3,p / 2,p - 2,p - 1};
    for (size_t j = 0; j < sizeof values / sizeof *values; ++j) check(values[j],p);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/small-moduli",small_moduli,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/carry-boundaries",carry_boundaries,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/mp/inverse",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
