/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/ec.h>
#define TC_MP_WORD_BITS TC_EC_WORD_BITS
#include "../../src/mp_internal.h"
#include "../../src/rsa_internal.h"
#include "munit.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

enum { MAX_BYTES = 384, MAX_WORDS = MAX_BYTES / sizeof(tc_mp_word) };

static void limbs(tc_mp_word* out, const uint8_t* bytes, size_t length)
{
  tc_mp_from_be(out,bytes,length);
}

static void equal_bn(const tc_mp_word* value, size_t length, const BIGNUM* expected)
{
  uint8_t bytes[MAX_BYTES];
  tc_mp_word words[MAX_WORDS];
  munit_assert_int(BN_bn2binpad(expected,bytes,(int)length), ==, (int)length);
  limbs(words,bytes,length);
  munit_assert_memory_equal(length,value,words);
}

static MunitResult oracle(const MunitParameter params[], void* user)
{
  tc_mp_word p[MAX_WORDS], base[MAX_WORDS], r2[MAX_WORDS], one[MAX_WORDS];
  tc_mp_word out[MAX_WORDS], temporary[MAX_WORDS], product[2 * MAX_WORDS + 2], reduced[MAX_WORDS];
  uint8_t modulus[MAX_BYTES], input[MAX_BYTES], exponent[MAX_BYTES];
  uint32_t state = 0x694e762d;
  BN_CTX* context = BN_CTX_new();
  BIGNUM *mod = BN_new(), *a = BN_new(), *e = BN_new(), *radix = BN_new(), *expected = BN_new();
  (void)params; (void)user;
  munit_assert_not_null(context); munit_assert_not_null(mod); munit_assert_not_null(a);
  munit_assert_not_null(e); munit_assert_not_null(radix); munit_assert_not_null(expected);
  for (size_t length = 128; length <= MAX_BYTES; length += 128) {
    size_t n = length / sizeof(tc_mp_word);
    for (unsigned sample = 0; sample < 2; ++sample) {
      tc_mp_word factor;
      size_t exponent_length = sample ? (TC_MP_WORD_BITS == 8 ? 16 : length) : 3;
      /* Fixed test data, not a key-generation RNG. */
      for (size_t i = 0; i < length; ++i) {
        state = state * 1664525u + 1013904223u; modulus[i] = (uint8_t)(state >> 24);
        state = state * 1664525u + 1013904223u; input[i] = (uint8_t)(state >> 24);
        state = state * 1664525u + 1013904223u; exponent[i] = (uint8_t)(state >> 24);
      }
      modulus[0] |= 0x80; modulus[length - 1] |= 1; input[0] &= 0x7f;
      if (!sample) { exponent[0] = 1; exponent[1] = 0; exponent[2] = 1; }
      munit_assert_not_null(BN_bin2bn(modulus,(int)length,mod));
      munit_assert_not_null(BN_bin2bn(input,(int)length,a));
      munit_assert_not_null(BN_bin2bn(exponent,(int)exponent_length,e));
      limbs(p,modulus,length); limbs(base,input,length);
      factor = tc_mp_montgomery_factor(p[0]);
      tc_mp_montgomery_r2(r2,p,n,reduced);
      munit_assert_int(BN_one(radix), ==, 1);
      munit_assert_int(BN_lshift(radix,radix,(int)(8 * length)), ==, 1);
      munit_assert_int(BN_mod_sqr(expected,radix,mod,context), ==, 1);
      equal_bn(r2,length,expected);
      memset(one,0,length); one[0] = 1;
      tc_mp_montgomery(one,one,r2,p,n,factor,product,reduced);
      tc_mp_montgomery(base,base,r2,p,n,factor,product,reduced);
      tc_mp_power(out,base,exponent,exponent_length,one,p,n,factor,temporary,product,reduced);
      memset(one,0,length); one[0] = 1;
      tc_mp_montgomery(out,out,one,p,n,factor,product,reduced);
      munit_assert_int(BN_mod_exp(expected,a,e,mod,context), ==, 1);
      equal_bn(out,length,expected);
      if (!sample) {
        tc_mp_word scratch[8 * MAX_WORDS + 2];
        uint8_t output[MAX_BYTES], expected_bytes[MAX_BYTES];
        size_t work = 16 * length + 16 * exponent_length + 4;
        memset(scratch,0xa5,sizeof scratch);
        munit_assert_int(tc_rsa_public_operation(modulus,length,exponent,exponent_length,
            input,output,scratch,sizeof scratch / sizeof *scratch,&work), ==, TC_RSA_OK);
        munit_assert_size(work, ==, 0);
        munit_assert_int(BN_bn2binpad(expected,expected_bytes,(int)length), ==, (int)length);
        munit_assert_memory_equal(length,output,expected_bytes);
        for (size_t i = 0; i < 8 * n + 2; ++i) munit_assert_uint(scratch[i], ==, 0);
      }
    }
  }
  BN_free(expected); BN_free(radix); BN_free(e); BN_free(a); BN_free(mod); BN_CTX_free(context);
  return MUNIT_OK;
}

static MunitResult signatures(const MunitParameter params[], void* user)
{
  uint8_t modulus[MAX_BYTES], exponent[MAX_BYTES], signature[MAX_BYTES], digest[64] = {0};
  const EVP_MD* hashes[] = {EVP_sha1(),EVP_sha224(),EVP_sha256(),EVP_sha384(),EVP_sha512()};
  tc_mp_word scratch[9 * MAX_WORDS + 2];
  (void)params; (void)user;
  for (size_t length = 128; length <= MAX_BYTES; length += 128) {
    EVP_PKEY* key = EVP_RSA_gen((unsigned)(length * 8));
    EVP_PKEY_CTX* context;
    BIGNUM *n = NULL, *e = NULL;
    size_t signature_length = sizeof signature, exponent_length, work, cost;
    munit_assert_not_null(key);
    munit_assert_int(EVP_PKEY_get_bn_param(key,OSSL_PKEY_PARAM_RSA_N,&n), ==, 1);
    munit_assert_int(EVP_PKEY_get_bn_param(key,OSSL_PKEY_PARAM_RSA_E,&e), ==, 1);
    munit_assert_int(BN_bn2binpad(n,modulus,(int)length), ==, (int)length);
    exponent_length = (size_t)BN_num_bytes(e);
    munit_assert_int(BN_bn2bin(e,exponent), ==, (int)exponent_length);
    for (unsigned hash_index = 0; hash_index < 5; ++hash_index) {
      TC_hash_algorithm hash = (TC_hash_algorithm)(TC_HASH_SHA1 + hash_index);
      size_t digest_length = (size_t)EVP_MD_get_size(hashes[hash_index]);
      signature_length = sizeof signature;
      context = EVP_PKEY_CTX_new(key,NULL); munit_assert_not_null(context);
      munit_assert_int(EVP_PKEY_sign_init(context), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(context,RSA_PKCS1_PADDING), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_signature_md(context,hashes[hash_index]), ==, 1);
      munit_assert_int(EVP_PKEY_sign(context,signature,&signature_length,digest,digest_length), ==, 1);
      munit_assert_size(signature_length, ==, length);
      cost = 17 * length + 16 * exponent_length + 4;
      work = cost;
      munit_assert_int(tc_rsa_verify_v15(modulus,length,exponent,exponent_length,signature,signature_length,
          hash,digest,digest_length,scratch,9 * length / sizeof *scratch + 2,&work), ==, TC_RSA_OK);
      munit_assert_size(work, ==, 0);
      for (size_t i = 0; i < 9 * length / sizeof *scratch + 2; ++i) munit_assert_uint(scratch[i], ==, 0);
      {
        TC_RSA_public_key public_key = {{modulus,length},{exponent,exponent_length}};
        TC_RSA_workspace workspace = {scratch,TC_RSA_verify_workspace_words(length * 8)};
        TC_bytes hashed = {digest,digest_length}, signed_bytes = {signature,signature_length};
        TC_RSA_v15_options options = {hash};
        TC_work_budget budget = {(uint32_t)cost};
        munit_assert_int(TC_RSA_verify_v15_digest(&public_key,&options,hashed,signed_bytes,&workspace,&budget), ==, TC_RSA_OK);
        budget.remaining = (uint32_t)cost - 1;
        munit_assert_int(TC_RSA_verify_v15_digest(&public_key,&options,hashed,signed_bytes,&workspace,&budget), ==, TC_RSA_LIMIT);
        hashed.length--;
        budget.remaining = (uint32_t)cost;
        munit_assert_int(TC_RSA_verify_v15_digest(&public_key,&options,hashed,signed_bytes,&workspace,&budget), ==, TC_RSA_ARGUMENT);
        hashed.length++;
        hashed.data = (const uint8_t*)scratch;
        munit_assert_int(TC_RSA_verify_v15_digest(&public_key,&options,hashed,signed_bytes,&workspace,&budget), ==, TC_RSA_ARGUMENT);
        hashed.data = digest;
        options.hash = TC_HASH_UNKNOWN;
        munit_assert_int(TC_RSA_verify_v15_digest(&public_key,&options,hashed,signed_bytes,&workspace,&budget), ==, TC_RSA_UNSUPPORTED);
      }
      digest[0] ^= 1; work = cost;
      munit_assert_int(tc_rsa_verify_v15(modulus,length,exponent,exponent_length,signature,signature_length,
          hash,digest,digest_length,scratch,9 * length / sizeof *scratch + 2,&work), ==, TC_RSA_INVALID);
      digest[0] ^= 1;
      signature[length - 1] ^= 1; work = cost;
      munit_assert_int(tc_rsa_verify_v15(modulus,length,exponent,exponent_length,signature,signature_length,
          hash,digest,digest_length,scratch,9 * length / sizeof *scratch + 2,&work), ==, TC_RSA_INVALID);
      signature[length - 1] ^= 1; work = cost - 1;
      munit_assert_int(tc_rsa_verify_v15(modulus,length,exponent,exponent_length,signature,signature_length,
          hash,digest,digest_length,scratch,9 * length / sizeof *scratch + 2,&work), ==, TC_RSA_LIMIT);
      work = cost;
      munit_assert_int(tc_rsa_verify_v15(modulus,length,exponent,exponent_length,signature,signature_length - 1,
          hash,digest,digest_length,scratch,9 * length / sizeof *scratch + 2,&work), ==, TC_RSA_INVALID);
      EVP_PKEY_CTX_free(context);
    }
    BN_free(e); BN_free(n); EVP_PKEY_free(key);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/openssl",oracle,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/rsa-signatures",signatures,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/arithmetic",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
