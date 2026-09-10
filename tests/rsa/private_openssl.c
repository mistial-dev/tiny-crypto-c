/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "../../src/rsa_private_internal.h"
#include "../../src/rsa_crt_internal.h"
#include "../../examples/rsa_validate.h"
#include "../../examples/rsa_sign.h"
#include "munit.h"
#include "test_util.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <stdlib.h>
#include <string.h>
#include "openssl_hash.h"
#include "openssl_key.h"

enum { MAX_BYTES = TC_TEST_RSA_MAX_BYTES, MAX_WORDS = MAX_BYTES / sizeof(tc_mp_word), WORK_BUDGET = 100000 };
typedef struct {
  const uint8_t* first;
  const uint8_t* next;
  size_t length, calls;
  TC_status status;
} random_source;

static TC_status random_bytes(void* context, uint8_t* output, size_t length)
{
  random_source* source = context;
  munit_assert_size(length, ==, source->length);
  const uint8_t* bytes = source->calls++ ? source->next : source->first;
  if (bytes) memcpy(output,bytes,length); else memset(output,0,length);
  return source->status;
}

static TC_RSA_result validate_key(const TC_RSA_private_key* key,
    TC_random_fn random, void* context, size_t attempts,
    const TC_RSA_workspace* workspace, uint32_t work)
{
  TC_RSA_execution execution = {{random,context},attempts,{work}};
  return TC_RSA_validate_private_key(key,workspace,&execution);
}

static TC_RSA_result sign_v15(TC_RSA_private_key* key, TC_hash_algorithm hash,
    TC_bytes digest, uint8_t* output, size_t length, TC_random_fn random,
    void* context, size_t attempts, const TC_RSA_workspace* workspace,
    uint32_t work)
{
  const TC_RSA_v15_options options = {hash};
  TC_RSA_execution execution = {{random,context},attempts,{work}};
  return TC_RSA_sign_v15_digest(key,&options,digest,workspace,
      (TC_buffer){output,length},&execution);
}

static TC_RSA_result verify_v15(const TC_RSA_public_key* key,
    TC_hash_algorithm hash, TC_bytes digest, TC_bytes signature,
    const TC_RSA_workspace* workspace, uint32_t work)
{
  const TC_RSA_v15_options options = {hash};
  TC_work_budget budget = {work};
  return TC_RSA_verify_v15_digest(key,&options,digest,signature,workspace,&budget);
}

static TC_RSA_result validate_crt(const TC_RSA_private_key* key,
    const TC_RSA_crt* crt, const TC_RSA_workspace* workspace, uint32_t work)
{
  TC_work_budget budget = {work};
  return TC_RSA_validate_crt(key,crt,workspace,&budget);
}

static void component(EVP_PKEY* key, const char* name, uint8_t* output, size_t length)
{
  munit_assert_size(tc_test_rsa_component(key,name,output,length,length), ==, length);
}

static MunitResult private_operation(const MunitParameter params[], void* user)
{
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params,"bits"),NULL,10);
  munit_assert_true(bits == 1024 || bits == 2048 || bits == 3072);
#if TC_RSA_SMALL
  if (bits > 1024) return MUNIT_SKIP;
#endif
  const size_t width = bits / 8, words = 13 * width / sizeof(tc_mp_word);
  uint8_t modulus[MAX_BYTES], d[MAX_BYTES], factor[MAX_BYTES], input[MAX_BYTES] = {0};
  uint8_t other_factor[MAX_BYTES], changed_factor[MAX_BYTES];
  uint8_t dp[MAX_BYTES / 2], dq[MAX_BYTES / 2], q_inverse[MAX_BYTES / 2];
  uint8_t actual[MAX_BYTES], expected[MAX_BYTES], seed[MAX_BYTES] = {0}, bad_d[MAX_BYTES];
  static const uint8_t exponent[] = {1,0,1};
  tc_mp_word scratch[13 * MAX_WORDS + 1];
  EVP_PKEY* key = EVP_RSA_gen(bits);
  EVP_PKEY_CTX* decrypt;
  (void)user;
  munit_assert_not_null(key);
  component(key,OSSL_PKEY_PARAM_RSA_N,modulus,width);
  component(key,OSSL_PKEY_PARAM_RSA_D,d,width);
  component(key,OSSL_PKEY_PARAM_RSA_FACTOR1,factor,width);
  component(key,OSSL_PKEY_PARAM_RSA_FACTOR2,other_factor,width);
  component(key,OSSL_PKEY_PARAM_RSA_EXPONENT1,dp,width / 2);
  component(key,OSSL_PKEY_PARAM_RSA_EXPONENT2,dq,width / 2);
  component(key,OSSL_PKEY_PARAM_RSA_COEFFICIENT1,q_inverse,width / 2);
  const size_t key_words = 8 * width / sizeof(tc_mp_word);
  enum { KEY_VALID, KEY_SWAPPED, KEY_D_CHANGED, KEY_FACTOR_CHANGED, KEY_FACTOR_ONE,
    KEY_FACTOR_EVEN, KEY_FACTORS_EQUAL, KEY_CASE_COUNT };
  for (unsigned scenario = 0; scenario < KEY_CASE_COUNT; ++scenario) {
    memcpy(bad_d,d,width); memcpy(changed_factor,factor,width);
    if (scenario == KEY_D_CHANGED) bad_d[width - 1] ^= 2;
    if (scenario == KEY_FACTOR_CHANGED) changed_factor[width - 1] ^= 2;
    if (scenario == KEY_FACTOR_ONE) { memset(changed_factor,0,width); changed_factor[width - 1] = 1; }
    if (scenario == KEY_FACTOR_EVEN) changed_factor[width - 1] ^= 1;
    if (scenario == KEY_FACTORS_EQUAL) memcpy(changed_factor,other_factor,width);
    size_t key_work = WORK_BUDGET;
    memset(scratch,0xa5,sizeof scratch);
    munit_assert_int(tc_rsa_private_key_consistent(modulus,width,exponent,sizeof exponent,bad_d,
        scenario == KEY_SWAPPED ? other_factor : changed_factor,
        scenario == KEY_SWAPPED ? changed_factor : other_factor,scratch,key_words,&key_work), ==,
        scenario <= KEY_SWAPPED ? TC_RSA_OK : TC_RSA_INVALID);
    munit_assert_true(tc_test_all_zero(scratch,key_words * sizeof *scratch));
    munit_assert_uint(((uint8_t*)scratch)[key_words * sizeof *scratch], ==, 0xa5);
  }
  size_t key_work = WORK_BUDGET;
  munit_assert_int(tc_rsa_private_key_consistent(modulus,width,exponent,sizeof exponent,d,
      factor,other_factor,scratch,key_words,&key_work), ==, TC_RSA_OK);
  const size_t key_cost = WORK_BUDGET - key_work;
  TC_bytes magnitudes[] = {{d,width},{factor,width},{other_factor,width}};
  for (size_t i = 0; i < sizeof magnitudes / sizeof *magnitudes; ++i)
    while (magnitudes[i].length > 1 && magnitudes[i].data[0] == 0) {
      ++magnitudes[i].data; --magnitudes[i].length;
    }
  munit_assert_size(magnitudes[1].length, <, width);
  munit_assert_size(magnitudes[2].length, <, width);
  key_work = key_cost;
  memset(scratch,0xa5,sizeof scratch);
  munit_assert_int(tc_rsa_private_magnitudes_consistent(modulus,width,exponent,sizeof exponent,
      magnitudes[0],magnitudes[1],magnitudes[2],scratch,key_words,&key_work), ==, TC_RSA_OK);
  munit_assert_size(key_work, ==, 0);
  munit_assert_true(tc_test_all_zero(scratch,key_words * sizeof *scratch));
  munit_assert_uint(((uint8_t*)scratch)[key_words * sizeof *scratch], ==, 0xa5);
  for (unsigned short_work = 0; short_work < 2; ++short_work) {
    key_work = key_cost - short_work; memset(scratch,0xa5,sizeof scratch);
    munit_assert_int(tc_rsa_private_key_consistent(modulus,width,exponent,sizeof exponent,d,
        factor,other_factor,scratch,key_words,&key_work), ==, short_work ? TC_RSA_LIMIT : TC_RSA_OK);
    if (!short_work) munit_assert_true(tc_test_all_zero(scratch,key_words * sizeof *scratch));
    else for (size_t i = 0; i < key_words * sizeof *scratch; ++i)
      munit_assert_uint(((uint8_t*)scratch)[i], ==, 0xa5);
  }
  input[width - 1] = 42; seed[width - 1] = 2;
  const size_t validation_words = 12 * width / sizeof(tc_mp_word) + 2;
  const size_t validation_cost = key_cost + 2 * (48 * width + 5);
  enum { VALIDATION_OK, VALIDATION_WORK, VALIDATION_RNG, VALIDATION_D,
    VALIDATION_STORAGE, VALIDATION_CASES };
  for (unsigned scenario = 0; scenario < VALIDATION_CASES; ++scenario) {
    random_source source = {seed,seed,width,0,scenario == VALIDATION_RNG ? TC_ERROR : TC_OK};
    uint32_t budget = (uint32_t)validation_cost - (scenario == VALIDATION_WORK);
    memcpy(bad_d,d,width);
    if (scenario == VALIDATION_D) bad_d[width - 1] ^= 2;
    memset(scratch,0xa5,sizeof scratch);
    TC_RSA_result result = tc_rsa_private_key_check(modulus,width,exponent,sizeof exponent,
        bad_d,factor,other_factor,1,random_bytes,&source,1,scratch,
        validation_words - (scenario == VALIDATION_STORAGE),&budget);
    munit_assert_int(result, ==, scenario == VALIDATION_OK ? TC_RSA_OK :
        scenario == VALIDATION_RNG ? TC_RSA_ERROR :
        scenario == VALIDATION_D ? TC_RSA_INVALID : TC_RSA_LIMIT);
    munit_assert_size(source.calls, ==, scenario == VALIDATION_OK ? 2 :
        scenario <= VALIDATION_RNG ? 1 : 0);
    if (scenario == VALIDATION_OK) munit_assert_size(budget, ==, 0);
    if (scenario == VALIDATION_STORAGE) {
      for (size_t i = 0; i < sizeof scratch; ++i)
        munit_assert_uint(((uint8_t*)scratch)[i], ==, 0xa5);
    } else munit_assert_true(tc_test_all_zero(scratch,validation_words * sizeof *scratch));
    munit_assert_uint(((uint8_t*)scratch)[validation_words * sizeof *scratch], ==, 0xa5);
  }
  TC_RSA_private_key public_components = {
    {{modulus,width},{exponent,sizeof exponent}}, magnitudes[0],magnitudes[1],magnitudes[2],NULL
  };
  TC_RSA_workspace public_workspace = {scratch,validation_words};
  munit_assert_size(TC_RSA_validate_workspace_words(bits), ==, validation_words);
  munit_assert_size(TC_RSA_validate_workspace_words(4096), ==, 0);
  {
    random_source source = {seed,seed,width,0,TC_OK};
    munit_assert_int(example_validate_rsa_key(&public_components,random_bytes,&source,
        scratch,validation_words), ==, TC_RSA_OK);
    munit_assert_size(source.calls, ==, 2 * TC_RSA_VALIDATION_ROUNDS);
    munit_assert_true(tc_test_all_zero(scratch,validation_words * sizeof *scratch));
  }
  for (unsigned scenario = 0; scenario < 4; ++scenario) {
    random_source source = {seed,seed,width,0,TC_OK};
    TC_RSA_private_key checked = public_components;
    TC_RSA_workspace storage = public_workspace;
    if (scenario == 0) checked.p.length = width + 1;
    if (scenario == 1) storage.words = (TC_RSA_word*)&checked;
    if (scenario == 2) --storage.capacity;
    memset(scratch,0xa5,sizeof scratch);
    munit_assert_int(validate_key(&checked,random_bytes,&source,
        scenario == 3 ? TC_RSA_VALIDATION_ROUNDS - 1 : TC_RSA_VALIDATION_ROUNDS,
        &storage,UINT32_MAX), ==, scenario == 0 ? TC_RSA_INVALID :
        scenario == 1 ? TC_RSA_ARGUMENT : TC_RSA_LIMIT);
    munit_assert_size(source.calls, ==, 0);
    for (size_t i = 0; i < sizeof scratch; ++i)
      munit_assert_uint(((uint8_t*)scratch)[i], ==, 0xa5);
  }
  decrypt = EVP_PKEY_CTX_new(key,NULL);
  munit_assert_not_null(decrypt);
  munit_assert_int(EVP_PKEY_decrypt_init(decrypt), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(decrypt,RSA_NO_PADDING), ==, 1);
  size_t recovered = sizeof expected;
  munit_assert_int(EVP_PKEY_decrypt(decrypt,expected,&recovered,input,width), ==, 1);
  munit_assert_size(recovered, ==, width);

  TC_RSA_crt crt = {{dp,width / 2},{dq,width / 2},{q_inverse,width / 2}};
  random_source crt_random = {seed,seed,width,0,TC_OK};
  size_t crt_work = 64 * width + 32 * sizeof exponent + 13;
  memset(actual,0xa5,sizeof actual); memset(scratch,0xa5,sizeof scratch);
  munit_assert_int(tc_rsa_crt_private_operation(modulus,width,exponent,sizeof exponent,
      (TC_bytes){factor + width / 2,width / 2},
      (TC_bytes){other_factor + width / 2,width / 2},&crt,
      input,actual,random_bytes,&crt_random,1,scratch,words,&crt_work), ==, TC_RSA_OK);
  munit_assert_size(crt_work, ==, 0);
  munit_assert_memory_equal(width,actual,expected);
  munit_assert_true(tc_test_all_zero(scratch,words * sizeof *scratch));
  crt_random = (random_source){factor,seed,width,0,TC_OK};
  crt_work = WORK_BUDGET;
  munit_assert_int(tc_rsa_crt_private_operation(modulus,width,exponent,sizeof exponent,
      (TC_bytes){factor + width / 2,width / 2},
      (TC_bytes){other_factor + width / 2,width / 2},&crt,
      input,actual,random_bytes,&crt_random,2,scratch,words,&crt_work), ==, TC_RSA_OK);
  munit_assert_size(crt_random.calls, ==, 2);
  munit_assert_memory_equal(width,actual,expected);
  for (size_t field = 0; field < 3; ++field) {
    uint8_t* corrupted = field == 0 ? dp : field == 1 ? dq : q_inverse;
    corrupted[width / 2 - 1] ^= 2;
    crt_random = (random_source){seed,seed,width,0,TC_OK}; crt_work = WORK_BUDGET;
    memset(actual,0xa5,sizeof actual); memset(scratch,0xa5,sizeof scratch);
    munit_assert_int(tc_rsa_crt_private_operation(modulus,width,exponent,sizeof exponent,
        (TC_bytes){factor + width / 2,width / 2},
        (TC_bytes){other_factor + width / 2,width / 2},&crt,
        input,actual,random_bytes,&crt_random,1,scratch,words,&crt_work), ==, TC_RSA_ERROR);
    for (size_t i = 0; i < width; ++i) munit_assert_uint(actual[i], ==, 0xa5);
    munit_assert_true(tc_test_all_zero(scratch,words * sizeof *scratch));
    corrupted[width / 2 - 1] ^= 2;
  }

  random_source random = {seed,seed,width,0,TC_OK};
  size_t work = WORK_BUDGET;
  memset(scratch,0xa5,sizeof scratch); memset(actual,0xa5,sizeof actual);
  munit_assert_int(tc_rsa_private_operation(modulus,width,exponent,sizeof exponent,d,input,actual,
      random_bytes,&random,2,scratch,words,&work), ==, TC_RSA_OK);
  munit_assert_memory_equal(width,actual,expected);
  munit_assert_size(random.calls, ==, 1);
  munit_assert_true(tc_test_all_zero(scratch,words * sizeof *scratch));
  munit_assert_uint(((uint8_t*)scratch)[words * sizeof *scratch], ==, 0xa5);
  const size_t required = WORK_BUDGET - work;
  random.calls = 0; work = required;
  memset(actual,0xa5,sizeof actual); memset(scratch,0xa5,sizeof scratch);
  munit_assert_int(tc_rsa_private_operation_magnitude(modulus,width,exponent,sizeof exponent,
      magnitudes[0],input,actual,random_bytes,&random,2,scratch,words,&work), ==, TC_RSA_OK);
  munit_assert_memory_equal(width,actual,expected);
  munit_assert_size(work, ==, 0);
  munit_assert_size(random.calls, ==, 1);
  munit_assert_true(tc_test_all_zero(scratch,words * sizeof *scratch));
  munit_assert_uint(((uint8_t*)scratch)[words * sizeof *scratch], ==, 0xa5);
  for (unsigned short_work = 0; short_work < 2; ++short_work) {
    random.calls = 0; work = required - short_work;
    memset(actual,0xa5,sizeof actual); memset(scratch,0xa5,sizeof scratch);
    munit_assert_int(tc_rsa_private_operation(modulus,width,exponent,sizeof exponent,d,input,actual,
        random_bytes,&random,2,scratch,words,&work), ==, short_work ? TC_RSA_LIMIT : TC_RSA_OK);
    munit_assert_true(tc_test_all_zero(scratch,words * sizeof *scratch));
    if (!short_work) munit_assert_memory_equal(width,actual,expected);
    else for (size_t i = 0; i < width; ++i) munit_assert_uint(actual[i], ==, 0xa5);
  }
  random = (random_source){factor,seed,width,0,TC_OK}; work = WORK_BUDGET;
  munit_assert_int(tc_rsa_private_operation(modulus,width,exponent,sizeof exponent,d,input,actual,
      random_bytes,&random,2,scratch,words,&work), ==, TC_RSA_OK);
  munit_assert_size(random.calls, ==, 2);
  munit_assert_memory_equal(width,actual,expected);

  const struct { const uint8_t* bytes; TC_status random_status; TC_RSA_result expected; } failures[] = {
    {NULL,TC_OK,TC_RSA_LIMIT},{modulus,TC_OK,TC_RSA_LIMIT},
    {factor,TC_OK,TC_RSA_LIMIT},{seed,TC_ERROR,TC_RSA_ERROR}
  };
  for (size_t failure = 0; failure < sizeof failures / sizeof *failures; ++failure) {
    random = (random_source){failures[failure].bytes,failures[failure].bytes,width,0,failures[failure].random_status};
    work = WORK_BUDGET; memset(actual,0xa5,sizeof actual); memset(scratch,0xa5,sizeof scratch);
    munit_assert_int(tc_rsa_private_operation(modulus,width,exponent,sizeof exponent,d,input,actual,
        random_bytes,&random,2,scratch,words,&work), ==, failures[failure].expected);
    munit_assert_size(random.calls, ==, failures[failure].random_status == TC_OK ? 2 : 1);
    munit_assert_true(tc_test_all_zero(scratch,words * sizeof *scratch));
    for (size_t i = 0; i < width; ++i) munit_assert_uint(actual[i], ==, 0xa5);
  }
  /* A changed odd exponent reaches the final public-exponent check. */
  memcpy(bad_d,d,width); bad_d[width - 1] ^= 2;
  random = (random_source){seed,seed,width,0,TC_OK}; work = WORK_BUDGET;
  memset(actual,0xa5,sizeof actual); memset(scratch,0xa5,sizeof scratch);
  munit_assert_int(tc_rsa_private_operation(modulus,width,exponent,sizeof exponent,bad_d,input,actual,
      random_bytes,&random,2,scratch,words,&work), ==, TC_RSA_ERROR);
  munit_assert_true(tc_test_all_zero(scratch,words * sizeof *scratch));
  for (size_t i = 0; i < width; ++i) munit_assert_uint(actual[i], ==, 0xa5);
  enum { NO_RANDOM, NO_ATTEMPTS, SHORT_SCRATCH, NO_WORK, ZERO_D, EVEN_D, D_EQUALS_N, INPUT_EQUALS_N, CASE_COUNT };
  for (unsigned scenario = 0; scenario < CASE_COUNT; ++scenario) {
    const uint8_t* checked_d = d;
    const uint8_t* checked_input = input;
    if (scenario == ZERO_D) { memset(bad_d,0,width); checked_d = bad_d; }
    if (scenario == EVEN_D) { memcpy(bad_d,d,width); bad_d[width - 1] ^= 1; checked_d = bad_d; }
    if (scenario == D_EQUALS_N) { memcpy(bad_d,modulus,width); checked_d = bad_d; }
    if (scenario == INPUT_EQUALS_N) { memcpy(bad_d,modulus,width); checked_input = bad_d; }
    random = (random_source){seed,seed,width,0,TC_OK};
    work = scenario == NO_WORK ? 0 : WORK_BUDGET;
    memset(actual,0xa5,sizeof actual); memset(scratch,0xa5,sizeof scratch);
    const TC_RSA_result expected_status = scenario == NO_RANDOM ? TC_RSA_ARGUMENT :
      scenario < ZERO_D ? TC_RSA_LIMIT : TC_RSA_INVALID;
    munit_assert_int(tc_rsa_private_operation(modulus,width,exponent,sizeof exponent,checked_d,checked_input,actual,
        scenario == NO_RANDOM ? NULL : random_bytes,&random,scenario == NO_ATTEMPTS ? 0 : 2,
        scratch,scenario == SHORT_SCRATCH ? words - 1 : words,&work), ==, expected_status);
    munit_assert_size(random.calls, ==, 0);
    for (size_t i = 0; i < width; ++i) munit_assert_uint(actual[i], ==, 0xa5);
    if (scenario >= ZERO_D) munit_assert_true(tc_test_all_zero(scratch,words * sizeof *scratch));
    else for (size_t i = 0; i < words * sizeof *scratch; ++i)
      munit_assert_uint(((uint8_t*)scratch)[i], ==, 0xa5);
  }
  EVP_PKEY_CTX_free(decrypt); EVP_PKEY_free(key);
  return MUNIT_OK;
}

static MunitResult composite_components(const MunitParameter params[], void* user)
{
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params,"bits"),NULL,10);
  const size_t width = bits / 8, words = 12 * width / sizeof(tc_mp_word) + 2;
  uint8_t modulus[MAX_BYTES], d[MAX_BYTES], p[MAX_BYTES], q[MAX_BYTES], seed[MAX_BYTES] = {0};
  static const uint8_t exponent[] = {1,0,1};
  tc_mp_word scratch[12 * MAX_WORDS + 2];
  BN_CTX* context = BN_CTX_new();
  munit_assert_not_null(context);
  BN_CTX_start(context);
  BIGNUM* factor = BN_CTX_get(context);
  BIGNUM* other = BN_CTX_get(context);
  BIGNUM* product = BN_CTX_get(context);
  BIGNUM* order = BN_CTX_get(context);
  BIGNUM* e = BN_CTX_get(context);
  BIGNUM* private_exponent = BN_CTX_get(context);
  munit_assert_not_null(private_exponent);
  (void)user;
  /* p=9, q=2^(bits-4)-1; lcm(p-1,q-1)=4*(q-1). */
  munit_assert_int(BN_set_word(factor,9), ==, 1);
  munit_assert_int(BN_set_bit(other,(int)bits - 4), ==, 1);
  munit_assert_int(BN_sub_word(other,1), ==, 1);
  munit_assert_int(BN_mul(product,factor,other,context), ==, 1);
  munit_assert_not_null(BN_copy(order,other));
  munit_assert_int(BN_sub_word(order,1), ==, 1);
  munit_assert_int(BN_lshift(order,order,2), ==, 1);
  munit_assert_int(BN_set_word(e,65537), ==, 1);
  munit_assert_not_null(BN_mod_inverse(private_exponent,e,order,context));
  munit_assert_int(BN_bn2binpad(product,modulus,(int)width), ==, (int)width);
  munit_assert_int(BN_bn2binpad(private_exponent,d,(int)width), ==, (int)width);
  munit_assert_int(BN_bn2binpad(factor,p,(int)width), ==, (int)width);
  munit_assert_int(BN_bn2binpad(other,q,(int)width), ==, (int)width);
  size_t work = WORK_BUDGET;
  munit_assert_int(tc_rsa_private_key_consistent(modulus,width,exponent,sizeof exponent,
      d,p,q,scratch,words,&work), ==, TC_RSA_OK);
  seed[width - 1] = 2;
  random_source random = {seed,seed,width,0,TC_OK};
  uint32_t validation_work = WORK_BUDGET;
  munit_assert_int(tc_rsa_private_key_check(modulus,width,exponent,sizeof exponent,
      d,p,q,1,random_bytes,&random,1,scratch,words,&validation_work), ==, TC_RSA_INVALID);
  munit_assert_size(random.calls, ==, 1);
  munit_assert_true(tc_test_all_zero(scratch,words * sizeof *scratch));
  BN_CTX_end(context); BN_CTX_free(context);
  return MUNIT_OK;
}

static MunitResult signing(const MunitParameter params[], void* user)
{
  const char* hash_name = munit_parameters_get(params,"hash");
  const tc_test_openssl_hash* selected = tc_test_openssl_hash_get(hash_name);
  const EVP_MD* method = selected->method();
  const TC_hash_algorithm hash = selected->algorithm;
  const size_t digest_length = (size_t)EVP_MD_get_size(method);
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params,"bits"),NULL,10);
#if TC_RSA_SMALL
  if (bits > 1024 && strcmp(hash_name,"SHA256")) return MUNIT_SKIP;
#endif
  const size_t width = bits / 8;
  uint8_t modulus[MAX_BYTES], d[MAX_BYTES], p[MAX_BYTES], q[MAX_BYTES];
  uint8_t dp[MAX_BYTES / 2], dq[MAX_BYTES / 2], inverse[MAX_BYTES / 2];
  uint8_t digest[64], signature[MAX_BYTES], seed[MAX_BYTES] = {0};
  for (size_t i = 0; i < sizeof digest; ++i) digest[i] = (uint8_t)i;
  static const uint8_t exponent[] = {1,0,1};
  TC_RSA_word scratch[TC_RSA_SIGN_WORKSPACE_WORDS(3072) + 1];
  TC_RSA_workspace workspace = {scratch,TC_RSA_sign_workspace_words(bits)};
  EVP_PKEY* key = EVP_RSA_gen(bits);
  (void)user;
  munit_assert_not_null(key);
  component(key,OSSL_PKEY_PARAM_RSA_N,modulus,width);
  component(key,OSSL_PKEY_PARAM_RSA_D,d,width);
  component(key,OSSL_PKEY_PARAM_RSA_FACTOR1,p,width);
  component(key,OSSL_PKEY_PARAM_RSA_FACTOR2,q,width);
  component(key,OSSL_PKEY_PARAM_RSA_EXPONENT1,dp,width / 2);
  component(key,OSSL_PKEY_PARAM_RSA_EXPONENT2,dq,width / 2);
  component(key,OSSL_PKEY_PARAM_RSA_COEFFICIENT1,inverse,width / 2);
  TC_RSA_private_key private_key = {{{modulus,width},{exponent,sizeof exponent}},
      {d,width},{p,width},{q,width},NULL};
  TC_RSA_crt crt = {{dp,width / 2},{dq,width / 2},{inverse,width / 2}};
  seed[width - 1] = 2;
  const size_t cost = 49 * width + 32 * sizeof exponent + 9;
  for (unsigned scenario = 0; scenario < 4; ++scenario) {
    random_source source = {seed,seed,width,0,scenario == 2 ? TC_ERROR : TC_OK};
    memset(signature,0xa5,sizeof signature); memset(scratch,0xa5,sizeof scratch);
    TC_RSA_result result = scenario == 3 ? example_sign_rsa_v15_digest(&private_key,hash,
        (TC_bytes){digest,digest_length},signature,width,random_bytes,&source,
        scratch,workspace.capacity) : sign_v15(&private_key,hash,
        (TC_bytes){digest,digest_length},signature,width,random_bytes,&source,1,
        &workspace,cost - (scenario == 1));
    munit_assert_int(result, ==,
        scenario == 1 ? TC_RSA_LIMIT : scenario == 2 ? TC_RSA_ERROR : TC_RSA_OK);
    munit_assert_true(tc_test_all_zero(scratch,workspace.capacity * sizeof *scratch));
    munit_assert_uint(((uint8_t*)scratch)[workspace.capacity * sizeof *scratch], ==, 0xa5);
    munit_assert_size(source.calls, ==, scenario == 1 ? 0 : 1);
    if (scenario == 0 || scenario == 3) {
      EVP_PKEY_CTX* verify = EVP_PKEY_CTX_new(key,NULL);
      munit_assert_not_null(verify);
      munit_assert_int(EVP_PKEY_verify_init(verify), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(verify,RSA_PKCS1_PADDING), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_signature_md(verify,method), ==, 1);
      munit_assert_int(EVP_PKEY_verify(verify,signature,width,digest,digest_length), ==, 1);
      EVP_PKEY_CTX_free(verify);
      munit_assert_int(verify_v15(&private_key.public_key,hash,
          (TC_bytes){digest,digest_length},(TC_bytes){signature,width},&workspace,
          WORK_BUDGET), ==, TC_RSA_OK);
    } else {
      for (size_t i = 0; i < sizeof signature; ++i)
        munit_assert_uint(signature[i], ==, 0xa5);
    }
  }
  random_source source = {seed,seed,width,0,TC_OK};
  memset(signature,0xa5,sizeof signature);
  private_key.crt = &crt;
  munit_assert_int(sign_v15(&private_key,hash,
      (TC_bytes){digest,digest_length},signature,width,random_bytes,&source,1,
      &workspace,65 * width + 32 * sizeof exponent + 13), ==, TC_RSA_OK);
  EVP_PKEY_CTX* verify = EVP_PKEY_CTX_new(key,NULL);
  munit_assert_not_null(verify);
  munit_assert_int(EVP_PKEY_verify_init(verify), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(verify,RSA_PKCS1_PADDING), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_signature_md(verify,method), ==, 1);
  munit_assert_int(EVP_PKEY_verify(verify,signature,width,digest,digest_length), ==, 1);
  EVP_PKEY_CTX_free(verify);
  EVP_PKEY_free(key);
  return MUNIT_OK;
}

static MunitResult crt_components(const MunitParameter params[], void* user)
{
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params,"bits"),NULL,10);
  const size_t width = bits / 8, required = 8 * width / sizeof(tc_mp_word);
  const size_t cost = 32 * width + 1;
  EVP_PKEY* key = EVP_RSA_gen(bits);
  const char* names[] = {OSSL_PKEY_PARAM_RSA_D,OSSL_PKEY_PARAM_RSA_FACTOR1,
    OSSL_PKEY_PARAM_RSA_FACTOR2,OSSL_PKEY_PARAM_RSA_EXPONENT1,
    OSSL_PKEY_PARAM_RSA_EXPONENT2,OSSL_PKEY_PARAM_RSA_COEFFICIENT1};
  uint8_t bytes[6][MAX_BYTES];
  TC_bytes values[6];
  tc_mp_word scratch[8 * MAX_WORDS + 1];
  (void)user;
  munit_assert_not_null(key);
  for (size_t i = 0; i < sizeof values / sizeof *values; ++i) {
    const size_t length = tc_test_rsa_component(key,names[i],bytes[i],sizeof bytes[i],0);
    munit_assert_size(length, >, 0);
    values[i] = (TC_bytes){bytes[i],length};
  }
  /* The generated key supplies validated d/p/q; corrupt each CRT field alone. */
  uint8_t modulus_bytes[MAX_BYTES];
  static const uint8_t public_exponent[] = {1,0,1};
  component(key,OSSL_PKEY_PARAM_RSA_N,modulus_bytes,width);
  const TC_RSA_private_key private_key = {
    {{modulus_bytes,width},{public_exponent,sizeof public_exponent}},values[0],values[1],values[2],NULL
  };
  TC_RSA_workspace workspace = {scratch,required};
  munit_assert_size(TC_RSA_crt_workspace_words(bits), ==, required);
  munit_assert_size(TC_RSA_crt_workspace_words(1536), ==, 0);
  {
    uint8_t derived[3][MAX_BYTES / 2];
    TC_RSA_crt_output output = {
      {derived[0],width / 2},{derived[1],width / 2},{derived[2],width / 2}
    };
    memset(derived,0xa5,sizeof derived); memset(scratch,0xa5,sizeof scratch);
    TC_work_budget derive_work = {(uint32_t)(48 * width + 3)};
    munit_assert_int(TC_RSA_derive_crt(&private_key,&output,&workspace,
        &derive_work), ==, TC_RSA_OK);
    for (size_t i = 0; i < 3; ++i) {
      uint8_t expected[MAX_BYTES / 2] = {0};
      munit_assert_size(values[i + 3].length, <=, width / 2);
      memcpy(expected + width / 2 - values[i + 3].length,
          values[i + 3].data,values[i + 3].length);
      munit_assert_memory_equal(width / 2,derived[i],expected);
    }
    munit_assert_true(tc_test_all_zero(scratch,required * sizeof *scratch));
  }
  for (unsigned scenario = 0; scenario < 4; ++scenario) {
    const size_t field = scenario + 2;
    if (scenario) bytes[field][values[field].length - 1] ^= 2;
    memset(scratch,0xa5,sizeof scratch);
    size_t work = cost;
    munit_assert_int(tc_rsa_crt_consistent(width,values[0],values[1],values[2],
        values[3],values[4],values[5],scratch,required,&work), ==,
        scenario ? TC_RSA_INVALID : TC_RSA_OK);
    munit_assert_size(work, ==, 0);
    const TC_RSA_crt crt = {values[3],values[4],values[5]};
    munit_assert_int(validate_crt(&private_key,&crt,&workspace,(uint32_t)cost), ==,
        scenario ? TC_RSA_INVALID : TC_RSA_OK);
    const uint8_t* wiped = (const uint8_t*)scratch;
    for (size_t i = 0; i < sizeof scratch; ++i)
      munit_assert_uint(wiped[i], ==, i < required * sizeof *scratch ? 0 : 0xa5);
    if (scenario) bytes[field][values[field].length - 1] ^= 2;
  }
  /* Adding the corresponding modulus preserves the congruence but exceeds
   * the CRT component's range. */
  for (size_t field = 3; field < 6; ++field) {
    const TC_bytes original = values[field];
    const TC_bytes factor = values[field == 4 ? 2 : 1];
    BIGNUM* enlarged = BN_bin2bn(original.data,(int)original.length,NULL);
    BIGNUM* modulus = BN_bin2bn(factor.data,(int)factor.length,NULL);
    uint8_t replacement[MAX_BYTES] = {0};
    munit_assert_not_null(enlarged);
    munit_assert_not_null(modulus);
    if (field != 5) munit_assert_int(BN_sub_word(modulus,1), ==, 1);
    munit_assert_int(BN_add(enlarged,enlarged,modulus), ==, 1);
    munit_assert_int(BN_bn2binpad(enlarged,replacement,(int)width), ==, (int)width);
    values[field] = (TC_bytes){replacement,width};
    for (unsigned zero = 0; zero < 2; ++zero) {
      if (zero) memset(replacement,0,width);
      size_t work = cost;
      munit_assert_int(tc_rsa_crt_consistent(width,values[0],values[1],values[2],
          values[3],values[4],values[5],scratch,required,&work), ==, TC_RSA_INVALID);
      munit_assert_size(work, ==, 0);
    }
    /* Leading zero bytes preserve a valid magnitude. */
    memcpy(replacement + width - original.length,original.data,original.length);
    size_t work = cost;
    munit_assert_int(tc_rsa_crt_consistent(width,values[0],values[1],values[2],
        values[3],values[4],values[5],scratch,required,&work), ==, TC_RSA_OK);
    values[field] = original;
    BN_clear_free(enlarged);
    BN_clear_free(modulus);
  }
  memset(scratch,0xa5,sizeof scratch);
  TC_RSA_crt crt = {values[3],values[4],values[5]};
  TC_bytes* fields[] = {&crt.dp,&crt.dq,&crt.q_inverse};
  for (size_t i = 0; i < sizeof fields / sizeof *fields; ++i) {
    const TC_bytes saved = *fields[i];
    *fields[i] = (TC_bytes){(const uint8_t*)scratch,width};
    munit_assert_int(validate_crt(&private_key,&crt,&workspace,(uint32_t)cost), ==, TC_RSA_ARGUMENT);
    *fields[i] = saved;
  }
  /* Reject malformed spans before touching scratch. */
  uint8_t oversized[MAX_BYTES + 1] = {0};
  const TC_bytes malformed[] = {{NULL,1},{oversized,0},{oversized,width + 1}};
  for (size_t field = 0; field < sizeof fields / sizeof *fields; ++field) {
    const TC_bytes saved = *fields[field];
    for (size_t bad = 0; bad < sizeof malformed / sizeof *malformed; ++bad) {
      *fields[field] = malformed[bad];
      munit_assert_int(validate_crt(&private_key,&crt,&workspace,(uint32_t)cost), ==,
          bad == 0 ? TC_RSA_ARGUMENT : TC_RSA_INVALID);
      const uint8_t* unchanged = (const uint8_t*)scratch;
      for (size_t i = 0; i < sizeof scratch; ++i)
        munit_assert_uint(unchanged[i], ==, 0xa5);
    }
    *fields[field] = saved;
  }
  const TC_RSA_crt saved_crt = crt;
  TC_RSA_workspace metadata_overlap = {(TC_RSA_word*)&crt,sizeof crt / sizeof(TC_RSA_word)};
  munit_assert_int(validate_crt(&private_key,&crt,&metadata_overlap,(uint32_t)cost), ==, TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof crt,&crt,&saved_crt);
  munit_assert_int(validate_crt(NULL,&crt,&workspace,(uint32_t)cost), ==, TC_RSA_ARGUMENT);
  munit_assert_int(validate_crt(&private_key,NULL,&workspace,(uint32_t)cost), ==, TC_RSA_ARGUMENT);
  munit_assert_int(validate_crt(&private_key,&crt,NULL,(uint32_t)cost), ==, TC_RSA_ARGUMENT);
  for (unsigned short_workspace = 0; short_workspace < 2; ++short_workspace) {
    size_t work = cost - !short_workspace;
    const size_t saved_work = work;
    munit_assert_int(tc_rsa_crt_consistent(width,values[0],values[1],values[2],
        values[3],values[4],values[5],scratch,required - short_workspace,&work), ==, TC_RSA_LIMIT);
    munit_assert_size(work, ==, saved_work);
    const TC_RSA_workspace limited = {scratch,required - short_workspace};
    munit_assert_int(validate_crt(&private_key,&crt,&limited,(uint32_t)saved_work), ==, TC_RSA_LIMIT);
    const uint8_t* unchanged = (const uint8_t*)scratch;
    for (size_t i = 0; i < sizeof scratch; ++i) munit_assert_uint(unchanged[i], ==, 0xa5);
  }
  EVP_PKEY_free(key);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  static char* sizes[] = {"1024","2048","3072",NULL};
  static MunitParameterEnum parameters[] = {{"bits",sizes},{NULL,NULL}};
  static char* hashes[] = {"SHA1","SHA224","SHA256","SHA384","SHA512",NULL};
  static MunitParameterEnum signing_parameters[] = {{"bits",sizes},{"hash",hashes},{NULL,NULL}};
  MunitTest tests[] = {
    {"/crt-components",crt_components,NULL,NULL,MUNIT_TEST_OPTION_NONE,parameters},
    {"/operation",private_operation,NULL,NULL,MUNIT_TEST_OPTION_NONE,parameters},
    {"/composite-components",composite_components,NULL,NULL,MUNIT_TEST_OPTION_NONE,parameters},
    {"/signing",signing,NULL,NULL,MUNIT_TEST_OPTION_NONE,signing_parameters},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/rsa/private",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
