/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "../../src/mp_prime_internal.h"
#include "../../src/rsa_prime_internal.h"
#include "munit.h"

static uint32_t power(uint32_t base, uint32_t exponent, uint32_t modulus)
{
  uint64_t result = 1;
  while (exponent) {
    if (exponent & 1u) result = result * base % modulus;
    base = (uint32_t)((uint64_t)base * base % modulus);
    exponent >>= 1;
  }
  return (uint32_t)result;
}

static int reference(uint32_t p, uint32_t base)
{
  uint32_t odd = p - 1;
  unsigned twos = 0;
  while (!(odd & 1u)) { odd >>= 1; ++twos; }
  uint32_t value = power(base,odd,p);
  if (value == 1 || value == p - 1) return 1;
  for (unsigned i = 1; i < twos; ++i) {
    value = (uint32_t)((uint64_t)value * value % p);
    if (value == p - 1) return 1;
    if (value == 1) return 0;
  }
  return 0;
}

static int check(uint32_t candidate, uint32_t witness)
{
  enum { BYTES = 4, WORDS = BYTES / sizeof(tc_mp_word) };
  tc_mp_word p[WORDS], base[WORDS], scratch[10 * WORDS + 2];
  uint8_t p_bytes[BYTES], base_bytes[BYTES];
  for (size_t i = 0; i < BYTES; ++i) {
    p_bytes[BYTES - 1 - i] = (uint8_t)(candidate >> (8 * i));
    base_bytes[BYTES - 1 - i] = (uint8_t)(witness >> (8 * i));
  }
  tc_mp_from_be(p,p_bytes,sizeof p_bytes); tc_mp_from_be(base,base_bytes,sizeof base_bytes);
  int result = tc_mp_miller_rabin(p,base,WORDS,scratch);
  munit_assert_int(result, ==, reference(candidate,witness));
  return result;
}

static MunitResult small_candidates(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  for (uint32_t p = 5; p < 128; p += 2)
    for (uint32_t base = 2; base < p - 1; ++base) check(p,base);
  return MUNIT_OK;
}

static MunitResult pseudoprimes(const MunitParameter params[], void* user)
{
  static const uint32_t candidates[] = {257,561,641,1105,1729,2047,65537,1373653,0xfffffffbu,UINT32_MAX};
  static const uint32_t bases[] = {2,3,5,7,11,17};
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof candidates / sizeof *candidates; ++i)
    for (size_t j = 0; j < sizeof bases / sizeof *bases; ++j) check(candidates[i],bases[j]);
  munit_assert_int(check(2047,2), ==, 1);
  munit_assert_int(check(2047,3), ==, 0);
  munit_assert_int(check(1373653,2), ==, 1);
  munit_assert_int(check(1373653,3), ==, 1);
  munit_assert_int(check(1373653,5), ==, 0);
  return MUNIT_OK;
}

static MunitResult prepared_rounds(const MunitParameter params[], void* user)
{
  enum { BYTES = 4, WORDS = BYTES / sizeof(tc_mp_word) };
  static const uint8_t candidate[] = {0,0,7,255}; /* 2047 passes base2, fails base3. */
  static const uint8_t witnesses[] = {2,3,2};
  tc_mp_word p[WORDS], base[WORDS], scratch[10 * WORDS + 2], setup[4 * WORDS];
  (void)params; (void)user;
  tc_mp_from_be(p,candidate,BYTES);
  size_t twos = tc_mp_miller_rabin_prepare(p,WORDS,scratch);
  memcpy(setup,scratch,sizeof setup);
  for (size_t i = 0; i < sizeof witnesses; ++i) {
    memset(base,0,sizeof base); base[0] = witnesses[i];
    munit_assert_int(tc_mp_miller_rabin_round(p,base,WORDS,twos,scratch), ==,
        reference(2047,witnesses[i]));
    munit_assert_memory_equal(sizeof setup,scratch,setup);
  }
  return MUNIT_OK;
}

typedef struct {
  unsigned calls;
  unsigned reject;
  TC_status status;
} random_source;

static TC_status random_base(void* context, uint8_t* output, size_t length)
{
  random_source* source = context;
  memset(output,0,length);
  output[length - 1] = source->calls++ < source->reject ? 1 : 2;
  return source->status;
}

static MunitResult sampling(const MunitParameter params[], void* user)
{
  enum { BYTES = 4, WORDS = BYTES / sizeof(tc_mp_word), REQUIRED = 12 * WORDS + 2 };
  static const uint8_t prime[] = {0xff,0xff,0xff,0xfb};
  static const uint8_t composite[] = {0xff,0xff,0xff,0xff};
  const size_t round_work = 48 * BYTES + 4;
  const size_t two_round_work = 24 * BYTES + 3 + 2 * (24 * BYTES + 2);
  tc_mp_word scratch[REQUIRED + 1];
  (void)params; (void)user;
  for (unsigned scenario = 0; scenario < 5; ++scenario) {
    random_source source = {0,scenario == 1 ? 1u : scenario == 2 ? 3u : 0u,
        scenario == 3 ? TC_ERROR : TC_OK};
    uint32_t work = (uint32_t)two_round_work + 1;
    memset(scratch,0xa5,sizeof scratch);
    TC_RSA_result result = tc_rsa_probable_prime(scenario == 4 ? composite : prime,
        BYTES,2,random_base,&source,3,scratch,REQUIRED,&work);
    munit_assert_int(result, ==, scenario == 2 ? TC_RSA_LIMIT :
        scenario == 3 ? TC_RSA_ERROR : scenario == 4 ? TC_RSA_INVALID : TC_RSA_OK);
    for (size_t i = 0; i < REQUIRED; ++i) munit_assert_uint(scratch[i], ==, 0);
    const uint8_t* tail = (const uint8_t*)(scratch + REQUIRED);
    for (size_t i = 0; i < sizeof *scratch; ++i) munit_assert_uint(tail[i], ==, 0xa5);
    munit_assert_uint(source.calls, ==, scenario == 0 ? 2 : scenario < 3 ? 3 : 1);
  }
  for (unsigned short_work = 0; short_work < 2; ++short_work) {
    random_source source = {0,0,TC_OK};
    uint32_t work = (uint32_t)round_work + short_work;
    memset(scratch,0xa5,sizeof scratch);
    munit_assert_int(tc_rsa_probable_prime(prime,BYTES,1,random_base,&source,1,
        scratch,REQUIRED,&work), ==, short_work ? TC_RSA_OK : TC_RSA_LIMIT);
    munit_assert_uint(source.calls, ==, short_work);
    if (short_work) munit_assert_size(work, ==, 0);
    else {
      const uint8_t* untouched = (const uint8_t*)scratch;
      for (size_t i = 0; i < sizeof scratch; ++i) munit_assert_uint(untouched[i], ==, 0xa5);
    }
  }
  for (unsigned scenario = 0; scenario < 4; ++scenario) {
    random_source source = {0,0,TC_OK};
    uint32_t work = (uint32_t)two_round_work - (scenario == 3);
    memset(scratch,0xa5,sizeof scratch);
    TC_RSA_result result = tc_rsa_probable_prime(prime,BYTES,scenario == 0 ? 0 : 2,
        random_base,&source,scenario == 1 ? 1 : 2,scratch,
        scenario == 2 ? REQUIRED - 1 : REQUIRED,&work);
    munit_assert_int(result, ==, scenario == 0 ? TC_RSA_ARGUMENT : TC_RSA_LIMIT);
    munit_assert_uint(source.calls, ==, scenario == 3 ? 1 : 0);
    const uint8_t* bytes = (const uint8_t*)scratch;
    for (size_t i = 0; i < REQUIRED * sizeof *scratch; ++i)
      munit_assert_uint(bytes[i], ==, scenario == 3 ? 0 : 0xa5);
  }
  return MUNIT_OK;
}

static TC_status fixed_base(void* context, uint8_t* output, size_t length)
{
  memcpy(output,context,length);
  return TC_OK;
}

static MunitResult padded_sampling(const MunitParameter params[], void* user)
{
  enum { BYTES = 4, WORDS = BYTES / sizeof(tc_mp_word), REQUIRED = 12 * WORDS + 2 };
  tc_mp_word scratch[REQUIRED];
  uint8_t candidate[BYTES], bytes[BYTES];
  static const uint32_t wider[] = {257,65537,0x7fffffffu};
  enum { SMALL_FIRST = 5, SMALL_LIMIT = 128, SMALL_COUNT = (SMALL_LIMIT - SMALL_FIRST + 1) / 2 };
  (void)params; (void)user;
  for (size_t sample = 0; sample < SMALL_COUNT + sizeof wider / sizeof *wider; ++sample) {
    uint32_t p = sample < SMALL_COUNT ? SMALL_FIRST + 2 * (uint32_t)sample : wider[sample - SMALL_COUNT];
    for (size_t i = 0; i < BYTES; ++i) candidate[BYTES - 1 - i] = (uint8_t)(p >> (8 * i));
    unsigned mask = p;
    mask |= mask >> 1; mask |= mask >> 2; mask |= mask >> 4;
    mask |= mask >> 8; mask |= mask >> 16;
    for (unsigned base = 0; base < 256; ++base) {
      /* High padding bits must be discarded before the range check. */
      memset(bytes,0xff,sizeof bytes); bytes[BYTES - 1] = (uint8_t)base;
      uint32_t work = 48 * BYTES + 5;
      unsigned selected = (0xffffff00u | base) & mask;
      TC_RSA_result expected = selected < 2 || selected >= p - 1 ? TC_RSA_LIMIT :
          reference(p,selected) ? TC_RSA_OK : TC_RSA_INVALID;
      munit_assert_int(tc_rsa_probable_prime(candidate,BYTES,1,fixed_base,bytes,1,
          scratch,REQUIRED,&work), ==, expected);
      for (size_t i = 0; i < REQUIRED; ++i) munit_assert_uint(scratch[i], ==, 0);
      const uint32_t remaining = work;
      TC_bytes magnitude = {candidate,BYTES};
      while (magnitude.length > 1 && magnitude.data[0] == 0) {
        ++magnitude.data; --magnitude.length;
      }
      work = 48 * BYTES + 5;
      memset(scratch,0xa5,sizeof scratch);
      munit_assert_int(tc_rsa_probable_prime_magnitude(magnitude,BYTES,1,fixed_base,bytes,1,
          scratch,REQUIRED,&work), ==, expected);
      munit_assert_uint(work, ==, remaining);
      for (size_t i = 0; i < REQUIRED; ++i) munit_assert_uint(scratch[i], ==, 0);
    }
  }
  for (unsigned p = 0; p <= 4; ++p) {
    memset(candidate,0,sizeof candidate); candidate[BYTES - 1] = (uint8_t)p;
    random_source source = {0,0,TC_OK};
    uint32_t work = 1000;
    memset(scratch,0xa5,sizeof scratch);
    munit_assert_int(tc_rsa_probable_prime(candidate,BYTES,1,random_base,&source,1,
        scratch,REQUIRED,&work), ==, p == 3 ? TC_RSA_OK : TC_RSA_INVALID);
    munit_assert_uint(source.calls, ==, 0);
    munit_assert_size(work, ==, 1000);
    for (size_t i = 0; i < sizeof scratch; ++i)
      munit_assert_uint(((uint8_t*)scratch)[i], ==, 0xa5);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/small-candidates",small_candidates,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/pseudoprimes",pseudoprimes,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/prepared-rounds",prepared_rounds,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/sampling",sampling,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/padded-sampling",padded_sampling,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/mp/miller-rabin",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
