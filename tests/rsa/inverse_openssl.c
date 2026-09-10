/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "../../src/mp_inverse_internal.h"
#include "munit.h"
#include <openssl/bn.h>
#include <openssl/err.h>

static MunitResult inverse(const MunitParameter params[], void* user)
{
  enum { MAX_BYTES = 384, MAX_WORDS = MAX_BYTES / sizeof(tc_mp_word), SAMPLES = 4 };
  uint8_t input[MAX_BYTES], modulus[MAX_BYTES], expected[MAX_BYTES], actual[MAX_BYTES];
  tc_mp_word a[MAX_WORDS], p[MAX_WORDS], out[MAX_WORDS], scratch[6 * MAX_WORDS];
  BN_CTX* context = BN_CTX_new();
  BIGNUM* value = BN_new();
  BIGNUM* modulus_bn = BN_new();
  (void)params; (void)user;
  munit_assert_not_null(context); munit_assert_not_null(value); munit_assert_not_null(modulus_bn);
  for (size_t width = 128; width <= MAX_BYTES; width += 128) {
    for (unsigned sample = 0; sample < SAMPLES + 2; ++sample) {
      if (sample < SAMPLES) {
        munit_assert_int(BN_rand(modulus_bn,(int)(width * 8),BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ODD), ==, 1);
        munit_assert_int(BN_rand_range(value,modulus_bn), ==, 1);
      } else {
        /* 2^bits-1 is divisible by three for these even bit lengths. */
        memset(modulus,0xff,width);
        munit_assert_ptr_equal(BN_bin2bn(modulus,(int)width,modulus_bn),modulus_bn);
        munit_assert_int(BN_set_word(value,sample == SAMPLES ? 3 : 2), ==, 1);
      }
      munit_assert_int(BN_bn2binpad(modulus_bn,modulus,(int)width), ==, (int)width);
      munit_assert_int(BN_bn2binpad(value,input,(int)width), ==, (int)width);
      BIGNUM* reference = BN_mod_inverse(NULL,value,modulus_bn,context);
      tc_mp_from_be(p,modulus,width); tc_mp_from_be(a,input,width);
      memset(out,0xa5,sizeof out);
      munit_assert_int(tc_mp_inverse(out,a,p,width / sizeof *p,scratch), ==, reference != NULL);
      tc_mp_to_be(actual,out,width);
      if (reference) {
        munit_assert_int(BN_bn2binpad(reference,expected,(int)width), ==, (int)width);
        munit_assert_memory_equal(width,actual,expected);
      } else {
        for (size_t i = 0; i < width; ++i) munit_assert_uint(actual[i], ==, 0xa5);
        ERR_clear_error();
      }
      BN_free(reference);
    }
  }
  BN_free(modulus_bn); BN_free(value); BN_CTX_free(context);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/openssl",inverse,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/mp/inverse",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
