/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "../../src/mp_prime_internal.h"
#include "../../src/rsa_prime_internal.h"
#include "munit.h"
#include <openssl/bn.h>
#include <stdlib.h>

static int reference(const BIGNUM* p, const BIGNUM* base, BN_CTX* context)
{
  BN_CTX_start(context);
  BIGNUM* last = BN_CTX_get(context);
  BIGNUM* odd = BN_CTX_get(context);
  BIGNUM* value = BN_CTX_get(context);
  munit_assert_not_null(value);
  munit_assert_not_null(BN_copy(last,p));
  munit_assert_int(BN_sub_word(last,1), ==, 1);
  munit_assert_not_null(BN_copy(odd,last));
  unsigned twos = 0;
  while (!BN_is_odd(odd)) {
    munit_assert_int(BN_rshift1(odd,odd), ==, 1);
    ++twos;
  }
  munit_assert_int(BN_mod_exp(value,base,odd,p,context), ==, 1);
  int passed = BN_is_one(value) || BN_cmp(value,last) == 0;
  for (unsigned i = 1; !passed && i < twos; ++i) {
    munit_assert_int(BN_mod_sqr(value,value,p,context), ==, 1);
    passed = BN_cmp(value,last) == 0;
    if (BN_is_one(value)) break;
  }
  BN_CTX_end(context);
  return passed;
}

static TC_status fixed_base(void* context, uint8_t* output, size_t length)
{
  memcpy(output,context,length);
  return TC_OK;
}

static MunitResult rounds(const MunitParameter params[], void* user)
{
  enum { MAX_BYTES = 192, MAX_WORDS = MAX_BYTES / sizeof(tc_mp_word) };
  const size_t width = (size_t)atoi(munit_parameters_get(params,"bits")) / 8;
  const size_t words = width / sizeof(tc_mp_word);
  uint8_t encoded[MAX_BYTES], candidate_bytes[MAX_BYTES];
  tc_mp_word p[MAX_WORDS], base[MAX_WORDS], scratch[12 * MAX_WORDS + 3];
  BN_CTX* context = BN_CTX_new();
  BIGNUM* candidate = BN_new();
  BIGNUM* witness = BN_new();
  (void)user;
  munit_assert_not_null(context); munit_assert_not_null(candidate); munit_assert_not_null(witness);
  for (unsigned sample = 0; sample < 5; ++sample) {
    /* Exercise trailing-zero counts across limb boundaries in p-1. */
    memset(encoded,0xff,width);
    if (sample < 3) {
      size_t zero_bytes = sample == 0 ? 1 : sample == 1 ? width / 2 : width - 1;
      memset(encoded + width - zero_bytes,0,zero_bytes);
      encoded[width - 1] = 1;
    }
    munit_assert_ptr_equal(BN_bin2bn(encoded,(int)width,candidate),candidate);
    if (sample == 4) {
      /* Known Mersenne primes also exercise zero-padded representations. */
      BN_zero(candidate);
      munit_assert_int(BN_set_bit(candidate,width == 64 ? 127 : 521), ==, 1);
      munit_assert_int(BN_sub_word(candidate,1), ==, 1);
      munit_assert_int(BN_bn2binpad(candidate,encoded,(int)width), ==, (int)width);
    }
    tc_mp_from_be(p,encoded,width);
    memcpy(candidate_bytes,encoded,width);
    for (unsigned b = 2; b <= 3; ++b) {
      munit_assert_int(BN_set_word(witness,b), ==, 1);
      munit_assert_int(BN_bn2binpad(witness,encoded,(int)width), ==, (int)width);
      tc_mp_from_be(base,encoded,width);
      memset(scratch,0xa5,sizeof scratch);
      int expected = reference(candidate,witness,context);
      if (sample == 4) munit_assert_int(expected, ==, 1);
      munit_assert_int(tc_mp_miller_rabin(p,base,words,scratch), ==, expected);
      const uint8_t* tail = (const uint8_t*)(scratch + 10 * words + 2);
      for (size_t i = 0; i < sizeof(tc_mp_word); ++i)
        munit_assert_uint(tail[i], ==, 0xa5);
      if (b == 2) {
        uint32_t work = UINT32_C(48) * (uint32_t)width + 5;
        munit_assert_int(tc_rsa_probable_prime(candidate_bytes,width,1,fixed_base,
            encoded,1,scratch,12 * words + 2,&work), ==,
            expected ? TC_RSA_OK : TC_RSA_INVALID);
        munit_assert_size(work, ==, 0);
        for (size_t i = 0; i < 12 * words + 2; ++i)
          munit_assert_uint(scratch[i], ==, 0);
      }
    }
  }
  BN_free(witness); BN_free(candidate); BN_CTX_free(context);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  char* widths[] = {"512","1024","1536",NULL};
  MunitParameterEnum parameters[] = {{"bits",widths},{NULL,NULL}};
  MunitTest tests[] = {
    {"/openssl",rounds,NULL,NULL,MUNIT_TEST_OPTION_NONE,parameters},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/mp/miller-rabin",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
