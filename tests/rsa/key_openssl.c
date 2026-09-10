/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/der.h>
#include <tiny_crypto/rsa.h>
#include "openssl_key.h"
#include "../../examples/rsa_read.h"
#include <tiny_crypto/key.h>
#include "munit.h"
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

static TC_status failed_random(void* context, uint8_t* output, size_t length)
{
  size_t* calls = context;
  (void)output;
  (void)length;
  ++*calls;
  return TC_ERROR;
}

static void rejected_key(TC_bytes der, size_t signature_length, size_t scratch_words,
    TC_RSA_result expected, size_t expected_calls)
{
  TC_RSA_word words[TC_RSA_SIGN_WORKSPACE_WORDS(3072)];
  uint8_t digest[32] = {0}, signature[TC_TEST_RSA_MAX_BYTES];
  uint8_t unchanged[sizeof signature];
  size_t calls = 0;
  memset(words,0xa5,sizeof words);
  memset(signature,0xa5,sizeof signature);
  memcpy(unchanged,signature,sizeof signature);
  munit_assert_int(example_sign_rsa_der(der,TC_HASH_SHA256,
      (TC_bytes){digest,sizeof digest},signature,signature_length,failed_random,
      &calls,words,scratch_words), ==, expected);
  munit_assert_size(calls, ==, expected_calls);
  munit_assert_memory_equal(sizeof signature,signature,unchanged);
  if (calls) {
    const size_t used_bytes = TC_RSA_validate_workspace_words(signature_length * 8) * sizeof *words;
    const uint8_t* bytes = (const uint8_t*)words;
    for (size_t i = 0; i < sizeof words; ++i)
      munit_assert_uint(bytes[i], ==, i < used_bytes ? 0 : 0xa5);
  }
}

static TC_status random_bytes(void* context, uint8_t* output, size_t length)
{
  (void)context;
  return RAND_bytes(output,(int)length) == 1 ? TC_OK : TC_ERROR;
}

static MunitResult generated_key(const MunitParameter params[], void* data)
{
  const size_t bits = strtoul(munit_parameters_get(params,"bits"),NULL,10);
  const size_t length = bits / 8, prime_length = length / 2;
  TC_RSA_word words[TC_RSA_KEYGEN_WORKSPACE_WORDS(3072)];
  uint8_t modulus[384], exponent[3], d[384], p[192], q[192];
  TC_RSA_keygen_output output = {
    {modulus,length},{exponent,sizeof exponent},{d,length},
    {p,prime_length},{q,prime_length}
  };
  TC_RSA_workspace workspace = {words,TC_RSA_keygen_workspace_words(bits)};
  TC_RSA_keygen_state state = {0};
  (void)data;
  munit_assert_int(TC_RSA_keygen_init(&state,bits,&output,
      (TC_RSA_keygen_limits){20000,50000},&workspace), ==, TC_RSA_OK);
  TC_RSA_result result;
  do {
    TC_work_budget work = {100000};
    result = TC_RSA_keygen_step(&state,(TC_random_source){random_bytes,NULL},
        NULL,NULL,&work);
  } while (result == TC_RSA_IN_PROGRESS);
  munit_assert_int(result, ==, TC_RSA_OK);
  BN_CTX* context = BN_CTX_new();
  BIGNUM* n = BN_bin2bn(modulus,(int)length,NULL);
  BIGNUM* e = BN_bin2bn(exponent,sizeof exponent,NULL);
  BIGNUM* private_exponent = BN_bin2bn(d,(int)length,NULL);
  BIGNUM* prime1 = BN_bin2bn(p,(int)prime_length,NULL);
  BIGNUM* prime2 = BN_bin2bn(q,(int)prime_length,NULL);
  BIGNUM* product = BN_new();
  BIGNUM* phi = BN_new();
  BIGNUM* check = BN_new();
  munit_assert_not_null(context); munit_assert_not_null(check);
  munit_assert_int(BN_check_prime(prime1,context,NULL), ==, 1);
  munit_assert_int(BN_check_prime(prime2,context,NULL), ==, 1);
  munit_assert_int(BN_mul(product,prime1,prime2,context), ==, 1);
  munit_assert_int(BN_cmp(product,n), ==, 0);
  munit_assert_int(BN_sub_word(prime1,1), ==, 1);
  munit_assert_int(BN_sub_word(prime2,1), ==, 1);
  munit_assert_int(BN_mul(phi,prime1,prime2,context), ==, 1);
  munit_assert_int(BN_mod_mul(check,e,private_exponent,phi,context), ==, 1);
  munit_assert_true(BN_is_one(check));
  BN_clear_free(check); BN_clear_free(phi); BN_clear_free(product);
  BN_clear_free(prime2); BN_clear_free(prime1); BN_clear_free(private_exponent);
  BN_free(e); BN_free(n); BN_CTX_free(context);
  return MUNIT_OK;
}

typedef struct {
  size_t salt_length, calls, failures;
} salt_failure;

static TC_status fail_salt(void* context, uint8_t* output, size_t length)
{
  salt_failure* fault = context;
  ++fault->calls;
  /* Primality and blinding request a modulus-width buffer; salt is shorter. */
  if (length == fault->salt_length) {
    ++fault->failures;
    memset(output,0x3c,length);
    return TC_ERROR;
  }
  return random_bytes(NULL,output,length);
}

static void verify_signature(EVP_PKEY* generated, int pss, TC_bytes signature, TC_bytes digest)
{
  EVP_PKEY_CTX* verify = EVP_PKEY_CTX_new(generated,NULL);
  munit_assert_not_null(verify);
  munit_assert_int(EVP_PKEY_verify_init(verify), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(verify,pss ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_signature_md(verify,EVP_sha256()), ==, 1);
  if (pss) {
    munit_assert_int(EVP_PKEY_CTX_set_rsa_mgf1_md(verify,EVP_sha256()), ==, 1);
    munit_assert_int(EVP_PKEY_CTX_set_rsa_pss_saltlen(verify,(int)digest.length), ==, 1);
  }
  munit_assert_int(EVP_PKEY_verify(verify,signature.data,signature.length,digest.data,digest.length), ==, 1);
  EVP_PKEY_CTX_free(verify);
}

static MunitResult private_key(const MunitParameter params[], void* data)
{
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params,"bits"),NULL,10);
  const char* format = munit_parameters_get(params,"format");
  const int pkcs8 = strcmp(format,"pkcs1") != 0;
  const int pss = strcmp(format,"pkcs8-pss") == 0;
  EVP_PKEY* generated = EVP_RSA_gen(bits);
  unsigned char* encoded = NULL;
  (void)data;
  munit_assert_not_null(generated);
  const int length = i2d_PrivateKey(generated,&encoded);
  munit_assert_int(length, >, 0);
  TC_DER_rsa_private_key parsed;
  munit_assert_int(TC_DER_rsa_private(encoded,(size_t)length,&parsed), ==, TC_TLV_OK);
  unsigned char* public_der = NULL;
  const int public_length = i2d_PublicKey(generated,&public_der);
  munit_assert_int(public_length, >, 0);
  TC_DER_rsa_public_key public_key;
  munit_assert_int(TC_DER_rsa_public(public_der,(size_t)public_length,&public_key), ==, TC_TLV_OK);
  munit_assert_size(public_key.modulus.length, ==, parsed.modulus.length);
  munit_assert_memory_equal(parsed.modulus.length,public_key.modulus.data,parsed.modulus.data);
  munit_assert_size(public_key.exponent.length, ==, parsed.public_exponent.length);
  munit_assert_memory_equal(parsed.public_exponent.length,public_key.exponent.data,parsed.public_exponent.data);
  OPENSSL_free(public_der);
  PKCS8_PRIV_KEY_INFO* container = EVP_PKEY2PKCS8(generated);
  unsigned char* wrapped = NULL;
  munit_assert_not_null(container);
  const int wrapped_length = i2d_PKCS8_PRIV_KEY_INFO(container,&wrapped);
  munit_assert_int(wrapped_length, >, 0);
  TC_DER_private_key info;
  munit_assert_int(TC_DER_private_key_info(wrapped,(size_t)wrapped_length,&info), ==, TC_TLV_OK);
  munit_assert_size(info.key.length, ==, (size_t)length);
  munit_assert_memory_equal((size_t)length,info.key.data,encoded);
  munit_assert_true(info.key.data >= wrapped);
  munit_assert_true(info.key.data + info.key.length <= wrapped + wrapped_length);
  munit_assert_null(info.attributes.data);
  munit_assert_int(TC_DER_null(info.algorithm.parameters.data,
      info.algorithm.parameters.length), ==, TC_TLV_OK);
  TC_KEY_rsa_private_key imported;
  munit_assert_int(TC_KEY_rsa_private_read((TC_bytes){wrapped,(size_t)wrapped_length},
      &imported), ==, TC_TLV_OK);
  munit_assert_int(imported.type, ==, TC_KEY_RSA);
  munit_assert_ptr_equal(imported.container.key.data,info.key.data);
  munit_assert_size(imported.components.modulus.length, ==, parsed.modulus.length);
  munit_assert_memory_equal(parsed.modulus.length,imported.components.modulus.data,parsed.modulus.data);
  PKCS8_PRIV_KEY_INFO_free(container);
  const TC_bytes components[] = {parsed.modulus,parsed.public_exponent,parsed.private_exponent,
    parsed.prime1,parsed.prime2,parsed.exponent1,parsed.exponent2,parsed.coefficient};
  const char* names[] = {OSSL_PKEY_PARAM_RSA_N,OSSL_PKEY_PARAM_RSA_E,OSSL_PKEY_PARAM_RSA_D,
    OSSL_PKEY_PARAM_RSA_FACTOR1,OSSL_PKEY_PARAM_RSA_FACTOR2,OSSL_PKEY_PARAM_RSA_EXPONENT1,
    OSSL_PKEY_PARAM_RSA_EXPONENT2,OSSL_PKEY_PARAM_RSA_COEFFICIENT1};
  uint8_t expected[TC_TEST_RSA_MAX_BYTES];
  for (size_t i = 0; i < sizeof components / sizeof *components; ++i) {
    const size_t size = tc_test_rsa_component(generated,names[i],expected,sizeof expected,0);
    munit_assert_size(size, >, 0);
    munit_assert_size(components[i].length, ==, size);
    munit_assert_memory_equal(size,components[i].data,expected);
    munit_assert_true((uintptr_t)components[i].data >= (uintptr_t)encoded);
    munit_assert_true((uintptr_t)components[i].data + size <= (uintptr_t)encoded + (size_t)length);
  }
  TC_RSA_word words[TC_RSA_SIGN_WORKSPACE_WORDS(3072)];
  uint8_t digest[32] = {0}, signature[TC_TEST_RSA_MAX_BYTES];
  /* A PSS-only container must reject v1.5 before requesting entropy. */
  const size_t oid_last = (size_t)(info.algorithm.oid.data - wrapped) + info.algorithm.oid.length - 1;
  const size_t parameters_tag = (size_t)(info.algorithm.parameters.data - wrapped);
  wrapped[oid_last] = 10;
  wrapped[parameters_tag] = 0x30;
  size_t calls = 0;
  memset(signature,0xa5,sizeof signature);
  munit_assert_int(example_sign_rsa_pkcs8((TC_bytes){wrapped,(size_t)wrapped_length},
      TC_HASH_SHA256,(TC_bytes){digest,sizeof digest},signature,bits / 8,
      failed_random,&calls,words,sizeof words / sizeof *words), ==, TC_RSA_INVALID);
  munit_assert_size(calls, ==, 0);
  for (size_t i = 0; i < sizeof signature; ++i) munit_assert_uint(signature[i], ==, 0xa5);
  /* Empty PSS parameters select SHA-1, which conflicts with this example. */
  munit_assert_int(example_sign_rsa_pkcs8_pss_sha256((TC_bytes){wrapped,(size_t)wrapped_length},
      (TC_bytes){digest,sizeof digest},signature,bits / 8,
      failed_random,&calls,words,sizeof words / sizeof *words), ==, TC_RSA_INVALID);
  munit_assert_size(calls, ==, 0);
  for (size_t i = 0; i < sizeof signature; ++i) munit_assert_uint(signature[i], ==, 0xa5);
  wrapped[oid_last] = 1;
  wrapped[parameters_tag] = 5;
  const size_t scratch_words = sizeof words / sizeof *words;
  rejected_key((TC_bytes){NULL,0},bits / 8,scratch_words,TC_RSA_ARGUMENT,0);
  /* Every incomplete encoding must fail before requesting randomness. */
  for (size_t end = 0; end < (size_t)length; ++end)
    rejected_key((TC_bytes){encoded,end},bits / 8,scratch_words,TC_RSA_INVALID,0);
  rejected_key((TC_bytes){encoded,(size_t)length},bits / 8,
      TC_RSA_validate_workspace_words(bits) - 1,TC_RSA_LIMIT,0);
  rejected_key((TC_bytes){encoded,(size_t)length},bits / 8,scratch_words,TC_RSA_ERROR,1);
  /* Change the modulus while preserving the INTEGER encoding. */
  const size_t last_modulus = (size_t)(parsed.modulus.data - encoded) + parsed.modulus.length - 1;
  encoded[last_modulus] ^= 1;
  rejected_key((TC_bytes){encoded,(size_t)length},bits / 8,scratch_words,TC_RSA_INVALID,0);
  encoded[last_modulus] ^= 1;
  TC_RSA_result signed_key = TC_RSA_LIMIT;
  /* Corrupt each CRT field without changing the DER structure or factors. */
  if (bits == 1024 && !pkcs8) {
    const TC_bytes crt[] = {parsed.exponent1,parsed.exponent2,parsed.coefficient};
    for (size_t field = 0; field < sizeof crt / sizeof *crt; ++field) {
      const size_t last = (size_t)(crt[field].data - encoded) + crt[field].length - 1;
      encoded[last] ^= 1;
      memset(signature,0xa5,sizeof signature);
      munit_assert_int(example_sign_rsa_der((TC_bytes){encoded,(size_t)length},
          TC_HASH_SHA256,(TC_bytes){digest,sizeof digest},signature,bits / 8,
          random_bytes,NULL,words,scratch_words), ==, TC_RSA_INVALID);
      for (size_t i = 0; i < sizeof signature; ++i)
        munit_assert_uint(signature[i], ==, 0xa5);
      encoded[last] ^= 1;
    }
  }
  /* Random candidate rejection can exhaust an individual call's attempt limit. */
  for (unsigned attempt = 0; attempt < 8 && signed_key == TC_RSA_LIMIT; ++attempt) {
    if (pss)
      signed_key = example_sign_rsa_pkcs8_pss_sha256((TC_bytes){wrapped,(size_t)wrapped_length},
          (TC_bytes){digest,sizeof digest},signature,bits / 8,
          random_bytes,NULL,words,sizeof words / sizeof *words);
    else signed_key = (pkcs8 ? example_sign_rsa_pkcs8 : example_sign_rsa_der)(
        pkcs8 ? (TC_bytes){wrapped,(size_t)wrapped_length} : (TC_bytes){encoded,(size_t)length},
        TC_HASH_SHA256,(TC_bytes){digest,sizeof digest},signature,bits / 8,
        random_bytes,NULL,words,sizeof words / sizeof *words);
  }
  munit_assert_int(signed_key, ==, TC_RSA_OK);
  verify_signature(generated,pss,(TC_bytes){signature,bits / 8},(TC_bytes){digest,sizeof digest});
  OPENSSL_clear_free(wrapped,(size_t)wrapped_length);
  OPENSSL_clear_free(encoded,(size_t)length);
  EVP_PKEY_free(generated);
  return MUNIT_OK;
}

static MunitResult restricted_pss(const MunitParameter params[], void* data)
{
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params,"bits"),NULL,10);
  enum { DIGEST_BYTES = 32 };
  EVP_PKEY_CTX* generation = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS,NULL);
  EVP_PKEY* generated = NULL;
  (void)data;
  munit_assert_not_null(generation);
  munit_assert_int(EVP_PKEY_keygen_init(generation), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_keygen_bits(generation,(int)bits), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_pss_keygen_md(generation,EVP_sha256()), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(generation,EVP_sha256()), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(generation,DIGEST_BYTES), ==, 1);
  munit_assert_int(EVP_PKEY_keygen(generation,&generated), ==, 1);
  EVP_PKEY_CTX_free(generation);
  PKCS8_PRIV_KEY_INFO* container = EVP_PKEY2PKCS8(generated);
  unsigned char* encoded = NULL;
  munit_assert_not_null(container);
  const int length = i2d_PKCS8_PRIV_KEY_INFO(container,&encoded);
  munit_assert_int(length, >, 0);
  TC_KEY_rsa_private_key key;
  munit_assert_int(TC_KEY_rsa_private_read((TC_bytes){encoded,(size_t)length},&key), ==, TC_TLV_OK);
  munit_assert_int(key.type, ==, TC_KEY_RSA_PSS);
  TC_signature_algorithm operation = {TC_SIGNATURE_RSA_PSS,TC_HASH_SHA256,TC_HASH_SHA256,DIGEST_BYTES};
  munit_assert_int(TC_KEY_rsa_private_signature_check(&key,&operation), ==, TC_TLV_OK);
  --operation.salt_length;
  munit_assert_int(TC_KEY_rsa_private_signature_check(&key,&operation), ==, TC_TLV_INVALID);
  TC_RSA_word words[TC_RSA_SIGN_WORKSPACE_WORDS(3072)];
  uint8_t digest[DIGEST_BYTES] = {0}, signature[TC_TEST_RSA_MAX_BYTES];
  size_t calls = 0;
  memset(signature,0xa5,sizeof signature);
  munit_assert_int(example_sign_rsa_pkcs8((TC_bytes){encoded,(size_t)length},TC_HASH_SHA256,
      (TC_bytes){digest,sizeof digest},signature,bits / 8,failed_random,&calls,
      words,sizeof words / sizeof *words), ==, TC_RSA_INVALID);
  munit_assert_size(calls, ==, 0);
  for (size_t i = 0; i < sizeof signature; ++i) munit_assert_uint(signature[i], ==, 0xa5);
  TC_RSA_result result = TC_RSA_LIMIT;
  for (unsigned attempt = 0; attempt < 8 && result == TC_RSA_LIMIT; ++attempt)
    result = example_sign_rsa_pkcs8_pss_sha256((TC_bytes){encoded,(size_t)length},
        (TC_bytes){digest,sizeof digest},signature,bits / 8,random_bytes,NULL,
        words,sizeof words / sizeof *words);
  munit_assert_int(result, ==, TC_RSA_OK);
  verify_signature(generated,1,(TC_bytes){signature,bits / 8},(TC_bytes){digest,sizeof digest});
  salt_failure fault = {sizeof digest,0,0};
  memset(words,0xa5,sizeof words);
  memset(signature,0xa5,sizeof signature);
  result = TC_RSA_LIMIT;
  for (unsigned attempt = 0; attempt < 8 && result == TC_RSA_LIMIT; ++attempt)
    result = example_sign_rsa_pkcs8_pss_sha256((TC_bytes){encoded,(size_t)length},
        (TC_bytes){digest,sizeof digest},signature,bits / 8,fail_salt,&fault,
        words,sizeof words / sizeof *words);
  munit_assert_int(result, ==, TC_RSA_ERROR);
  munit_assert_size(fault.failures, ==, 1);
  munit_assert_size(fault.calls, >, 2 * TC_RSA_VALIDATION_ROUNDS);
  for (size_t i = 0; i < sizeof signature; ++i) munit_assert_uint(signature[i], ==, 0xa5);
  const size_t used = TC_RSA_sign_workspace_words(bits) * sizeof *words;
  const uint8_t* scratch = (const uint8_t*)words;
  for (size_t i = 0; i < sizeof words; ++i)
    munit_assert_uint(scratch[i], ==, i < used ? 0 : 0xa5);
  OPENSSL_clear_free(encoded,(size_t)length);
  PKCS8_PRIV_KEY_INFO_free(container);
  EVP_PKEY_free(generated);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  char* bits[] = {"1024","2048","3072",NULL};
  char* formats[] = {"pkcs1","pkcs8","pkcs8-pss",NULL};
  MunitParameterEnum parameters[] = {{"bits",bits},{"format",formats},{NULL,NULL}};
  MunitParameterEnum restricted_parameters[] = {{"bits",bits},{NULL,NULL}};
  MunitTest tests[] = {{"/private",private_key,NULL,NULL,MUNIT_TEST_OPTION_NONE,parameters},
    {"/generated",generated_key,NULL,NULL,MUNIT_TEST_OPTION_NONE,restricted_parameters},
    {"/restricted-pss",restricted_pss,NULL,NULL,MUNIT_TEST_OPTION_NONE,restricted_parameters},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/rsa/key",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
