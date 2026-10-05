/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "../../src/rsa_private_internal.h"
#include "../../examples/rsa_validate.h"
#include "../../examples/rsa_sign.h"
#include "munit.h"
#include "test_util.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <stdlib.h>
#include <string.h>
#include "openssl_hash.h"
#include "openssl_key.h"

/* Pointer-and-length forms of the span-based private-key helpers. */
/* A view over full-width components, as the component check accepts them. */
static tc_rsa_private_view full_width_view(const TC_RSA_public_key* public_key, TC_bytes d,
                                           TC_bytes p, TC_bytes q)
{
  const tc_rsa_private_view view = {public_key, d, p, q, 0, {NULL, 0}, {NULL, 0}, {NULL, 0}};
  return view;
}

/* The private components share the modulus length. */
static TC_RSA_result key_consistent(const TC_RSA_public_key* public_key, const uint8_t* d,
                                    const uint8_t* p, const uint8_t* q, tc_mp_scratch scratch,
                                    uint32_t* work)
{
  const size_t length = public_key->modulus.length;
  const tc_rsa_private_view view = full_width_view(public_key, (TC_bytes){d, length},
                                                   (TC_bytes){p, length}, (TC_bytes){q, length});
  return tc_rsa_private_magnitudes_consistent(&view, TC_RSA_EXPONENT_FIPS, scratch, work);
}

/* The private components share the modulus length. The entry checks build
 * the view, as TC_RSA_validate_private_key does. */
static TC_RSA_result key_check(const TC_RSA_public_key* public_key, const uint8_t* d,
                               const uint8_t* p, const uint8_t* q, size_t rounds,
                               const tc_rsa_random* rng, tc_mp_scratch scratch, uint32_t* work)
{
  const size_t length = public_key->modulus.length;
  const TC_RSA_private_key key = {*public_key, {d, length}, {p, length}, {q, length}, NULL};
  tc_rsa_private_view view;
  const TC_RSA_result checked = tc_rsa_private_view_init(&key, NULL, &view);
  if (checked != TC_RSA_OK)
    return checked;
  return tc_rsa_private_magnitudes_check(&view, TC_RSA_EXPONENT_FIPS, rounds, rng, scratch, work);
}

/* A CRT view over half-width factors and CRT values. */
static tc_rsa_private_view crt_view(const TC_RSA_public_key* public_key, TC_bytes p, TC_bytes q,
                                    const TC_RSA_crt* crt)
{
  const tc_rsa_private_view view = {public_key, {NULL, 0}, p,       q,
                                    1,          crt->dp,   crt->dq, crt->q_inverse};
  return view;
}

static TC_RSA_result full_width_private(const TC_RSA_public_key* public_key, const uint8_t* d,
                                        const uint8_t* input, uint8_t* output,
                                        const tc_rsa_random* rng, tc_mp_scratch scratch,
                                        uint32_t* work)
{
  return tc_rsa_private_operation_magnitude(public_key, (TC_bytes){d, public_key->modulus.length},
                                            input, output, rng, scratch, work);
}

enum {
  MAX_BYTES = TC_TEST_RSA_MAX_BYTES,
  MAX_WORDS = MAX_BYTES / sizeof(tc_mp_word),
  WORK_BUDGET = 100000
};
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
  if (bytes)
    memcpy(output, bytes, length);
  else
    memset(output, 0, length);
  return source->status;
}

static TC_RSA_result validate_key(const TC_RSA_private_key* key, TC_random_fn random, void* context,
                                  size_t attempts, const TC_RSA_workspace* workspace, uint32_t work)
{
  TC_RSA_execution execution = {{random, context}, attempts, {work}};
  return TC_RSA_validate_private_key(key, TC_RSA_EXPONENT_FIPS, TC_PERMIT_DISALLOWED, workspace,
                                     &execution);
}

static TC_RSA_result sign_v15(const TC_RSA_private_key* key, TC_hash_algorithm hash,
                              TC_bytes digest, TC_buffer output, const TC_RSA_workspace* workspace,
                              TC_RSA_execution execution)
{
  const TC_RSA_v15_options options = {hash};
  return TC_RSA_sign_v15_digest(key, &options, digest, output, workspace, &execution);
}

static TC_RSA_result verify_v15(const TC_RSA_public_key* key, TC_hash_algorithm hash,
                                TC_bytes digest, TC_bytes signature,
                                const TC_RSA_workspace* workspace, uint32_t work)
{
  const TC_RSA_v15_options options = {hash};
  TC_work_budget budget = {work};
  return TC_RSA_verify_v15_digest(key, &options, digest, signature, workspace, &budget);
}

static TC_RSA_result validate_crt(const TC_RSA_private_key* key, const TC_RSA_crt* crt,
                                  const TC_RSA_workspace* workspace, uint32_t work)
{
  TC_work_budget budget = {work};
  return TC_RSA_validate_crt(key, crt, workspace, &budget);
}

/* Replace d with e^-1 mod LCM(p-1, q-1). OpenSSL reduces d modulo
 * (p-1)(q-1) for some key sizes, which FIPS 186-5 A.1.1 rejects. */
static void lambda_exponent(uint8_t* d, const uint8_t* p, const uint8_t* q, size_t width)
{
  BN_CTX* context = BN_CTX_new();
  BIGNUM *p1 = BN_bin2bn(p, (int)width, NULL), *q1 = BN_bin2bn(q, (int)width, NULL);
  BIGNUM *phi = BN_new(), *g = BN_new(), *lambda = BN_new(), *e = BN_new(), *out = BN_new();
  munit_assert_not_null(context);
  munit_assert_not_null(out);
  munit_assert_int(BN_sub_word(p1, 1), ==, 1);
  munit_assert_int(BN_sub_word(q1, 1), ==, 1);
  munit_assert_int(BN_mul(phi, p1, q1, context), ==, 1);
  munit_assert_int(BN_gcd(g, p1, q1, context), ==, 1);
  munit_assert_int(BN_div(lambda, NULL, phi, g, context), ==, 1);
  munit_assert_int(BN_set_word(e, 65537), ==, 1);
  munit_assert_not_null(BN_mod_inverse(out, e, lambda, context));
  munit_assert_int(BN_bn2binpad(out, d, (int)width), ==, (int)width);
  BN_clear_free(out);
  BN_free(e);
  BN_clear_free(lambda);
  BN_clear_free(g);
  BN_clear_free(phi);
  BN_clear_free(q1);
  BN_clear_free(p1);
  BN_CTX_free(context);
}

static void component(EVP_PKEY* key, const char* name, uint8_t* output, size_t length)
{
  munit_assert_size(tc_test_rsa_component(key, name, output, length, length), ==, length);
}

static MunitResult private_operation(const MunitParameter params[], void* user)
{
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params, "bits"), NULL, 10);
  munit_assert_true(bits == 1024 || bits == 2048 || bits == 3072 || bits == 4096);
#if TC_RSA_SMALL
  if (bits > 1024)
    return MUNIT_SKIP;
#endif
  const size_t width = bits / 8, words = 13 * width / sizeof(tc_mp_word);
  uint8_t modulus[MAX_BYTES], d[MAX_BYTES], factor[MAX_BYTES], input[MAX_BYTES] = {0};
  uint8_t other_factor[MAX_BYTES], changed_factor[MAX_BYTES];
  uint8_t dp[MAX_BYTES / 2], dq[MAX_BYTES / 2], q_inverse[MAX_BYTES / 2];
  uint8_t actual[MAX_BYTES], expected[MAX_BYTES], seed[MAX_BYTES] = {0}, bad_d[MAX_BYTES];
  static const uint8_t exponent[] = {1, 0, 1};
  tc_mp_word scratch[13 * MAX_WORDS + 1];
  EVP_PKEY* key = EVP_RSA_gen(bits);
  EVP_PKEY_CTX* decrypt;
  (void)user;
  munit_assert_not_null(key);
  component(key, OSSL_PKEY_PARAM_RSA_N, modulus, width);
  component(key, OSSL_PKEY_PARAM_RSA_D, d, width);
  component(key, OSSL_PKEY_PARAM_RSA_FACTOR1, factor, width);
  component(key, OSSL_PKEY_PARAM_RSA_FACTOR2, other_factor, width);
  lambda_exponent(d, factor, other_factor, width);
  component(key, OSSL_PKEY_PARAM_RSA_EXPONENT1, dp, width / 2);
  component(key, OSSL_PKEY_PARAM_RSA_EXPONENT2, dq, width / 2);
  component(key, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, q_inverse, width / 2);
  const size_t key_words = 12 * width / sizeof(tc_mp_word);
  enum {
    KEY_VALID,
    KEY_SWAPPED,
    KEY_D_CHANGED,
    KEY_FACTOR_CHANGED,
    KEY_FACTOR_ONE,
    KEY_FACTOR_EVEN,
    KEY_FACTORS_EQUAL,
    KEY_CASE_COUNT
  };
  for (unsigned scenario = 0; scenario < KEY_CASE_COUNT; ++scenario) {
    memcpy(bad_d, d, width);
    memcpy(changed_factor, factor, width);
    if (scenario == KEY_D_CHANGED)
      bad_d[width - 1] ^= 2;
    if (scenario == KEY_FACTOR_CHANGED)
      changed_factor[width - 1] ^= 2;
    if (scenario == KEY_FACTOR_ONE) {
      memset(changed_factor, 0, width);
      changed_factor[width - 1] = 1;
    }
    if (scenario == KEY_FACTOR_EVEN)
      changed_factor[width - 1] ^= 1;
    if (scenario == KEY_FACTORS_EQUAL)
      memcpy(changed_factor, other_factor, width);
    uint32_t key_work = WORK_BUDGET;
    memset(scratch, 0xa5, sizeof scratch);
    munit_assert_int(
        key_consistent(&(TC_RSA_public_key){{modulus, width}, {exponent, sizeof exponent}}, bad_d,
                       scenario == KEY_SWAPPED ? other_factor : changed_factor,
                       scenario == KEY_SWAPPED ? changed_factor : other_factor,
                       (tc_mp_scratch){scratch, key_words}, &key_work),
        ==, scenario <= KEY_SWAPPED ? TC_RSA_OK : TC_RSA_INVALID);
    munit_assert_true(tc_test_all_zero(scratch, key_words * sizeof *scratch));
    munit_assert_uint(((uint8_t*)scratch)[key_words * sizeof *scratch], ==, 0xa5);
  }
  uint32_t key_work = WORK_BUDGET;
  munit_assert_int(
      key_consistent(&(TC_RSA_public_key){{modulus, width}, {exponent, sizeof exponent}}, d, factor,
                     other_factor, (tc_mp_scratch){scratch, key_words}, &key_work),
      ==, TC_RSA_OK);
  const size_t key_cost = WORK_BUDGET - key_work;
  TC_bytes magnitudes[] = {{d, width}, {factor, width}, {other_factor, width}};
  for (size_t i = 0; i < sizeof magnitudes / sizeof *magnitudes; ++i)
    while (magnitudes[i].length > 1 && magnitudes[i].data[0] == 0) {
      ++magnitudes[i].data;
      --magnitudes[i].length;
    }
  munit_assert_size(magnitudes[1].length, <, width);
  munit_assert_size(magnitudes[2].length, <, width);
  key_work = key_cost;
  memset(scratch, 0xa5, sizeof scratch);
  const TC_RSA_public_key stripped_public = {{modulus, width}, {exponent, sizeof exponent}};
  const tc_rsa_private_view stripped =
      full_width_view(&stripped_public, magnitudes[0], magnitudes[1], magnitudes[2]);
  munit_assert_int(tc_rsa_private_magnitudes_consistent(&stripped, TC_RSA_EXPONENT_FIPS,
                                                        (tc_mp_scratch){scratch, key_words},
                                                        &key_work),
                   ==, TC_RSA_OK);
  munit_assert_size(key_work, ==, 0);
  munit_assert_true(tc_test_all_zero(scratch, key_words * sizeof *scratch));
  munit_assert_uint(((uint8_t*)scratch)[key_words * sizeof *scratch], ==, 0xa5);
  for (unsigned short_work = 0; short_work < 2; ++short_work) {
    key_work = key_cost - short_work;
    memset(scratch, 0xa5, sizeof scratch);
    munit_assert_int(
        key_consistent(&(TC_RSA_public_key){{modulus, width}, {exponent, sizeof exponent}}, d,
                       factor, other_factor, (tc_mp_scratch){scratch, key_words}, &key_work),
        ==, short_work ? TC_RSA_LIMIT : TC_RSA_OK);
    if (!short_work)
      munit_assert_true(tc_test_all_zero(scratch, key_words * sizeof *scratch));
    else
      for (size_t i = 0; i < key_words * sizeof *scratch; ++i)
        munit_assert_uint(((uint8_t*)scratch)[i], ==, 0xa5);
  }
  input[width - 1] = 42;
  seed[width - 1] = 2;
  /* Miller-Rabin runs at the half-width factor size and draws base 2. */
  uint8_t witness[MAX_BYTES] = {0};
  witness[width / 2 - 1] = 2;
  const size_t validation_words = 12 * width / sizeof(tc_mp_word) + 2;
  const size_t validation_cost = key_cost + 2 * (24 * width + 5);
  enum {
    VALIDATION_OK,
    VALIDATION_WORK,
    VALIDATION_RNG,
    VALIDATION_D,
    VALIDATION_STORAGE,
    VALIDATION_CASES
  };
  for (unsigned scenario = 0; scenario < VALIDATION_CASES; ++scenario) {
    random_source source = {witness, witness, width / 2, 0,
                            scenario == VALIDATION_RNG ? TC_ERROR : TC_OK};
    uint32_t budget = (uint32_t)validation_cost - (scenario == VALIDATION_WORK);
    memcpy(bad_d, d, width);
    if (scenario == VALIDATION_D)
      bad_d[width - 1] ^= 2;
    memset(scratch, 0xa5, sizeof scratch);
    TC_RSA_result result = key_check(
        &(TC_RSA_public_key){{modulus, width}, {exponent, sizeof exponent}}, bad_d, factor,
        other_factor, 1, &(tc_rsa_random){{random_bytes, &source}, 1},
        (tc_mp_scratch){scratch, validation_words - (scenario == VALIDATION_STORAGE)}, &budget);
    munit_assert_int(result, ==,
                     scenario == VALIDATION_OK    ? TC_RSA_OK
                     : scenario == VALIDATION_RNG ? TC_RSA_ERROR
                     : scenario == VALIDATION_D   ? TC_RSA_INVALID
                                                  : TC_RSA_LIMIT);
    /* A budget one unit below the full cost fails the preflight, so no RNG
     * request, work or scratch is used. */
    munit_assert_size(source.calls, ==,
                      scenario == VALIDATION_OK    ? 2
                      : scenario == VALIDATION_RNG ? 1
                                                   : 0);
    if (scenario == VALIDATION_OK)
      munit_assert_size(budget, ==, 0);
    if (scenario == VALIDATION_WORK)
      munit_assert_uint32(budget, ==, (uint32_t)validation_cost - 1u);
    if (scenario == VALIDATION_STORAGE || scenario == VALIDATION_WORK) {
      for (size_t i = 0; i < sizeof scratch; ++i)
        munit_assert_uint(((uint8_t*)scratch)[i], ==, 0xa5);
    } else
      munit_assert_true(tc_test_all_zero(scratch, validation_words * sizeof *scratch));
    munit_assert_uint(((uint8_t*)scratch)[validation_words * sizeof *scratch], ==, 0xa5);
  }
  TC_RSA_private_key public_components = {{{modulus, width}, {exponent, sizeof exponent}},
                                          magnitudes[0],
                                          magnitudes[1],
                                          magnitudes[2],
                                          NULL};
  TC_RSA_workspace public_workspace = {scratch, validation_words};
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_VALIDATE, bits), ==, validation_words);
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_VALIDATE, 4096), ==,
                    TC_RSA_VALIDATE_WORKSPACE_WORDS(4096));
  {
    random_source source = {witness, witness, width / 2, 0, TC_OK};
    /* The default FIPS 186-5 size limit refuses RSA-1024 before any RNG
     * request. TC_PERMIT_DISALLOWED accepts it. */
    munit_assert_int(example_validate_rsa_key(&public_components, TC_APPROVED_ONLY,
                                              (TC_random_source){random_bytes, &source},
                                              &(TC_RSA_workspace){scratch, validation_words}),
                     ==, bits < 2048 ? TC_RSA_UNSUPPORTED : TC_RSA_OK);
    munit_assert_size(source.calls, ==, bits < 2048 ? 0 : 2 * TC_RSA_VALIDATION_ROUNDS);
    source.calls = 0;
    munit_assert_int(example_validate_rsa_key(&public_components, TC_PERMIT_DISALLOWED,
                                              (TC_random_source){random_bytes, &source},
                                              &(TC_RSA_workspace){scratch, validation_words}),
                     ==, TC_RSA_OK);
    munit_assert_size(source.calls, ==, 2 * TC_RSA_VALIDATION_ROUNDS);
    munit_assert_true(tc_test_all_zero(scratch, validation_words * sizeof *scratch));
  }
  for (unsigned scenario = 0; scenario < 4; ++scenario) {
    random_source source = {witness, witness, width / 2, 0, TC_OK};
    TC_RSA_private_key checked = public_components;
    TC_RSA_workspace storage = public_workspace;
    if (scenario == 0)
      checked.p.length = width + 1;
    if (scenario == 1)
      storage.words = (TC_RSA_word*)&checked;
    if (scenario == 2)
      --storage.capacity;
    memset(scratch, 0xa5, sizeof scratch);
    munit_assert_int(
        validate_key(&checked, random_bytes, &source,
                     scenario == 3 ? TC_RSA_VALIDATION_ROUNDS - 1 : TC_RSA_VALIDATION_ROUNDS,
                     &storage, UINT32_MAX),
        ==,
        scenario == 0   ? TC_RSA_INVALID
        : scenario == 1 ? TC_RSA_ARGUMENT
                        : TC_RSA_LIMIT);
    munit_assert_size(source.calls, ==, 0);
    for (size_t i = 0; i < sizeof scratch; ++i)
      munit_assert_uint(((uint8_t*)scratch)[i], ==, 0xa5);
  }
  decrypt = EVP_PKEY_CTX_new(key, NULL);
  munit_assert_not_null(decrypt);
  munit_assert_int(EVP_PKEY_decrypt_init(decrypt), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(decrypt, RSA_NO_PADDING), ==, 1);
  size_t recovered = sizeof expected;
  munit_assert_int(EVP_PKEY_decrypt(decrypt, expected, &recovered, input, width), ==, 1);
  munit_assert_size(recovered, ==, width);

  TC_RSA_crt crt = {{dp, width / 2}, {dq, width / 2}, {q_inverse, width / 2}};
  const TC_RSA_public_key crt_public = {{modulus, width}, {exponent, sizeof exponent}};
  const tc_rsa_private_view private_crt =
      crt_view(&crt_public, (TC_bytes){factor + width / 2, width / 2},
               (TC_bytes){other_factor + width / 2, width / 2}, &crt);
  random_source crt_random = {seed, seed, width, 0, TC_OK};
  uint32_t crt_work = 64 * width + 32 * sizeof exponent + 13;
  memset(actual, 0xa5, sizeof actual);
  memset(scratch, 0xa5, sizeof scratch);
  munit_assert_int(tc_rsa_crt_private_operation(&private_crt, input, actual,
                                                &(tc_rsa_random){{random_bytes, &crt_random}, 1},
                                                (tc_mp_scratch){scratch, words}, &crt_work),
                   ==, TC_RSA_OK);
  munit_assert_size(crt_work, ==, 0);
  munit_assert_memory_equal(width, actual, expected);
  munit_assert_true(tc_test_all_zero(scratch, words * sizeof *scratch));
  crt_random = (random_source){factor, seed, width, 0, TC_OK};
  crt_work = WORK_BUDGET;
  munit_assert_int(tc_rsa_crt_private_operation(&private_crt, input, actual,
                                                &(tc_rsa_random){{random_bytes, &crt_random}, 2},
                                                (tc_mp_scratch){scratch, words}, &crt_work),
                   ==, TC_RSA_OK);
  munit_assert_size(crt_random.calls, ==, 2);
  munit_assert_memory_equal(width, actual, expected);
  for (size_t field = 0; field < 3; ++field) {
    uint8_t* corrupted = field == 0 ? dp : field == 1 ? dq : q_inverse;
    corrupted[width / 2 - 1] ^= 2;
    crt_random = (random_source){seed, seed, width, 0, TC_OK};
    crt_work = WORK_BUDGET;
    memset(actual, 0xa5, sizeof actual);
    memset(scratch, 0xa5, sizeof scratch);
    munit_assert_int(tc_rsa_crt_private_operation(&private_crt, input, actual,
                                                  &(tc_rsa_random){{random_bytes, &crt_random}, 1},
                                                  (tc_mp_scratch){scratch, words}, &crt_work),
                     ==, TC_RSA_ERROR);
    for (size_t i = 0; i < width; ++i)
      munit_assert_uint(actual[i], ==, 0xa5);
    munit_assert_true(tc_test_all_zero(scratch, words * sizeof *scratch));
    corrupted[width / 2 - 1] ^= 2;
  }

  random_source random = {seed, seed, width, 0, TC_OK};
  uint32_t work = WORK_BUDGET;
  memset(scratch, 0xa5, sizeof scratch);
  memset(actual, 0xa5, sizeof actual);
  munit_assert_int(
      full_width_private(&(TC_RSA_public_key){{modulus, width}, {exponent, sizeof exponent}}, d,
                         input, actual, &(tc_rsa_random){{random_bytes, &random}, 2},
                         (tc_mp_scratch){scratch, words}, &work),
      ==, TC_RSA_OK);
  munit_assert_memory_equal(width, actual, expected);
  munit_assert_size(random.calls, ==, 1);
  munit_assert_true(tc_test_all_zero(scratch, words * sizeof *scratch));
  munit_assert_uint(((uint8_t*)scratch)[words * sizeof *scratch], ==, 0xa5);
  const size_t required = WORK_BUDGET - work;
  random.calls = 0;
  work = required;
  memset(actual, 0xa5, sizeof actual);
  memset(scratch, 0xa5, sizeof scratch);
  munit_assert_int(tc_rsa_private_operation_magnitude(
                       &(TC_RSA_public_key){{modulus, width}, {exponent, sizeof exponent}},
                       magnitudes[0], input, actual, &(tc_rsa_random){{random_bytes, &random}, 2},
                       (tc_mp_scratch){scratch, words}, &work),
                   ==, TC_RSA_OK);
  munit_assert_memory_equal(width, actual, expected);
  munit_assert_size(work, ==, 0);
  munit_assert_size(random.calls, ==, 1);
  munit_assert_true(tc_test_all_zero(scratch, words * sizeof *scratch));
  munit_assert_uint(((uint8_t*)scratch)[words * sizeof *scratch], ==, 0xa5);
  for (unsigned short_work = 0; short_work < 2; ++short_work) {
    random.calls = 0;
    work = required - short_work;
    memset(actual, 0xa5, sizeof actual);
    memset(scratch, 0xa5, sizeof scratch);
    munit_assert_int(
        full_width_private(&(TC_RSA_public_key){{modulus, width}, {exponent, sizeof exponent}}, d,
                           input, actual, &(tc_rsa_random){{random_bytes, &random}, 2},
                           (tc_mp_scratch){scratch, words}, &work),
        ==, short_work ? TC_RSA_LIMIT : TC_RSA_OK);
    munit_assert_true(tc_test_all_zero(scratch, words * sizeof *scratch));
    if (!short_work)
      munit_assert_memory_equal(width, actual, expected);
    else
      for (size_t i = 0; i < width; ++i)
        munit_assert_uint(actual[i], ==, 0xa5);
  }
  random = (random_source){factor, seed, width, 0, TC_OK};
  work = WORK_BUDGET;
  munit_assert_int(
      full_width_private(&(TC_RSA_public_key){{modulus, width}, {exponent, sizeof exponent}}, d,
                         input, actual, &(tc_rsa_random){{random_bytes, &random}, 2},
                         (tc_mp_scratch){scratch, words}, &work),
      ==, TC_RSA_OK);
  munit_assert_size(random.calls, ==, 2);
  munit_assert_memory_equal(width, actual, expected);

  const struct {
    const uint8_t* bytes;
    TC_status random_status;
    TC_RSA_result expected;
  } failures[] = {{NULL, TC_OK, TC_RSA_LIMIT},
                  {modulus, TC_OK, TC_RSA_LIMIT},
                  {factor, TC_OK, TC_RSA_LIMIT},
                  {seed, TC_ERROR, TC_RSA_ERROR}};
  for (size_t failure = 0; failure < sizeof failures / sizeof *failures; ++failure) {
    random = (random_source){failures[failure].bytes, failures[failure].bytes, width, 0,
                             failures[failure].random_status};
    work = WORK_BUDGET;
    memset(actual, 0xa5, sizeof actual);
    memset(scratch, 0xa5, sizeof scratch);
    munit_assert_int(
        full_width_private(&(TC_RSA_public_key){{modulus, width}, {exponent, sizeof exponent}}, d,
                           input, actual, &(tc_rsa_random){{random_bytes, &random}, 2},
                           (tc_mp_scratch){scratch, words}, &work),
        ==, failures[failure].expected);
    munit_assert_size(random.calls, ==, failures[failure].random_status == TC_OK ? 2 : 1);
    munit_assert_true(tc_test_all_zero(scratch, words * sizeof *scratch));
    for (size_t i = 0; i < width; ++i)
      munit_assert_uint(actual[i], ==, 0xa5);
  }
  /* A changed odd exponent reaches the final public-exponent check. */
  memcpy(bad_d, d, width);
  bad_d[width - 1] ^= 2;
  random = (random_source){seed, seed, width, 0, TC_OK};
  work = WORK_BUDGET;
  memset(actual, 0xa5, sizeof actual);
  memset(scratch, 0xa5, sizeof scratch);
  munit_assert_int(
      full_width_private(&(TC_RSA_public_key){{modulus, width}, {exponent, sizeof exponent}}, bad_d,
                         input, actual, &(tc_rsa_random){{random_bytes, &random}, 2},
                         (tc_mp_scratch){scratch, words}, &work),
      ==, TC_RSA_ERROR);
  munit_assert_true(tc_test_all_zero(scratch, words * sizeof *scratch));
  for (size_t i = 0; i < width; ++i)
    munit_assert_uint(actual[i], ==, 0xa5);
  /* The entry checks reject a NULL RNG before the kernel runs. */
  enum {
    NO_ATTEMPTS,
    SHORT_SCRATCH,
    NO_WORK,
    ZERO_D,
    EVEN_D,
    D_EQUALS_N,
    INPUT_EQUALS_N,
    CASE_COUNT
  };
  for (unsigned scenario = 0; scenario < CASE_COUNT; ++scenario) {
    const uint8_t* checked_d = d;
    const uint8_t* checked_input = input;
    if (scenario == ZERO_D) {
      memset(bad_d, 0, width);
      checked_d = bad_d;
    }
    if (scenario == EVEN_D) {
      memcpy(bad_d, d, width);
      bad_d[width - 1] ^= 1;
      checked_d = bad_d;
    }
    if (scenario == D_EQUALS_N) {
      memcpy(bad_d, modulus, width);
      checked_d = bad_d;
    }
    if (scenario == INPUT_EQUALS_N) {
      memcpy(bad_d, modulus, width);
      checked_input = bad_d;
    }
    random = (random_source){seed, seed, width, 0, TC_OK};
    work = scenario == NO_WORK ? 0 : WORK_BUDGET;
    memset(actual, 0xa5, sizeof actual);
    memset(scratch, 0xa5, sizeof scratch);
    const TC_RSA_result expected_status = scenario < ZERO_D ? TC_RSA_LIMIT : TC_RSA_INVALID;
    munit_assert_int(full_width_private(
                         &(TC_RSA_public_key){{modulus, width}, {exponent, sizeof exponent}},
                         checked_d, checked_input, actual,
                         &(tc_rsa_random){{random_bytes, &random}, scenario == NO_ATTEMPTS ? 0 : 2},
                         (tc_mp_scratch){scratch, scenario == SHORT_SCRATCH ? words - 1 : words},
                         &work),
                     ==, expected_status);
    munit_assert_size(random.calls, ==, 0);
    for (size_t i = 0; i < width; ++i)
      munit_assert_uint(actual[i], ==, 0xa5);
    if (scenario >= ZERO_D)
      munit_assert_true(tc_test_all_zero(scratch, words * sizeof *scratch));
    else
      for (size_t i = 0; i < words * sizeof *scratch; ++i)
        munit_assert_uint(((uint8_t*)scratch)[i], ==, 0xa5);
  }
  EVP_PKEY_CTX_free(decrypt);
  EVP_PKEY_free(key);
  return MUNIT_OK;
}

static MunitResult composite_components(const MunitParameter params[], void* user)
{
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params, "bits"), NULL, 10);
  const size_t width = bits / 8, words = 12 * width / sizeof(tc_mp_word) + 2;
  uint8_t modulus[MAX_BYTES], d[MAX_BYTES], p[MAX_BYTES], q[MAX_BYTES], seed[MAX_BYTES] = {0};
  static const uint8_t exponent[] = {1, 0, 1};
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
  munit_assert_int(BN_set_word(factor, 9), ==, 1);
  munit_assert_int(BN_set_bit(other, (int)bits - 4), ==, 1);
  munit_assert_int(BN_sub_word(other, 1), ==, 1);
  munit_assert_int(BN_mul(product, factor, other, context), ==, 1);
  munit_assert_not_null(BN_copy(order, other));
  munit_assert_int(BN_sub_word(order, 1), ==, 1);
  munit_assert_int(BN_lshift(order, order, 2), ==, 1);
  munit_assert_int(BN_set_word(e, 65537), ==, 1);
  munit_assert_not_null(BN_mod_inverse(private_exponent, e, order, context));
  munit_assert_int(BN_bn2binpad(product, modulus, (int)width), ==, (int)width);
  munit_assert_int(BN_bn2binpad(private_exponent, d, (int)width), ==, (int)width);
  munit_assert_int(BN_bn2binpad(factor, p, (int)width), ==, (int)width);
  munit_assert_int(BN_bn2binpad(other, q, (int)width), ==, (int)width);
  uint32_t work = WORK_BUDGET;
  munit_assert_int(
      key_consistent(&(TC_RSA_public_key){{modulus, width}, {exponent, sizeof exponent}}, d, p, q,
                     (tc_mp_scratch){scratch, words}, &work),
      ==, TC_RSA_INVALID);
  seed[width - 1] = 2;
  random_source random = {seed, seed, width, 0, TC_OK};
  uint32_t validation_work = WORK_BUDGET;
  /* The entry checks reject q, which is wider than half the modulus, before
   * any scratch or work is used. */
  memset(scratch, 0xa5, sizeof scratch);
  munit_assert_int(key_check(&(TC_RSA_public_key){{modulus, width}, {exponent, sizeof exponent}}, d,
                             p, q, 1, &(tc_rsa_random){{random_bytes, &random}, 1},
                             (tc_mp_scratch){scratch, words}, &validation_work),
                   ==, TC_RSA_INVALID);
  munit_assert_size(random.calls, ==, 0);
  munit_assert_uint32(validation_work, ==, WORK_BUDGET);
  for (size_t i = 0; i < sizeof scratch; ++i)
    munit_assert_uint(((uint8_t*)scratch)[i], ==, 0xa5);
  BN_CTX_end(context);
  BN_CTX_free(context);
  return MUNIT_OK;
}

static MunitResult signing(const MunitParameter params[], void* user)
{
  const char* hash_name = munit_parameters_get(params, "hash");
  const tc_test_openssl_hash* selected = tc_test_openssl_hash_get(hash_name);
  const EVP_MD* method = selected->method();
  const TC_hash_algorithm hash = selected->algorithm;
  const size_t digest_length = (size_t)EVP_MD_get_size(method);
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params, "bits"), NULL, 10);
#if TC_RSA_SMALL
  if (bits > 1024 && strcmp(hash_name, "SHA256"))
    return MUNIT_SKIP;
#endif
  const size_t width = bits / 8;
  uint8_t modulus[MAX_BYTES], d[MAX_BYTES], p[MAX_BYTES], q[MAX_BYTES];
  uint8_t dp[MAX_BYTES / 2], dq[MAX_BYTES / 2], inverse[MAX_BYTES / 2];
  uint8_t digest[64], signature[MAX_BYTES], seed[MAX_BYTES] = {0};
  for (size_t i = 0; i < sizeof digest; ++i)
    digest[i] = (uint8_t)i;
  static const uint8_t exponent[] = {1, 0, 1};
  TC_RSA_word scratch[TC_RSA_SIGN_WORKSPACE_WORDS(4096) + 1];
  TC_RSA_workspace workspace = {scratch, TC_RSA_workspace_words(TC_RSA_OPERATION_SIGN, bits)};
  EVP_PKEY* key = EVP_RSA_gen(bits);
  (void)user;
  munit_assert_not_null(key);
  component(key, OSSL_PKEY_PARAM_RSA_N, modulus, width);
  component(key, OSSL_PKEY_PARAM_RSA_D, d, width);
  component(key, OSSL_PKEY_PARAM_RSA_FACTOR1, p, width);
  component(key, OSSL_PKEY_PARAM_RSA_FACTOR2, q, width);
  lambda_exponent(d, p, q, width);
  component(key, OSSL_PKEY_PARAM_RSA_EXPONENT1, dp, width / 2);
  component(key, OSSL_PKEY_PARAM_RSA_EXPONENT2, dq, width / 2);
  component(key, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, inverse, width / 2);
  TC_RSA_private_key private_key = {
      {{modulus, width}, {exponent, sizeof exponent}}, {d, width}, {p, width}, {q, width}, NULL};
  TC_RSA_crt crt = {{dp, width / 2}, {dq, width / 2}, {inverse, width / 2}};
  seed[width - 1] = 2;
  const size_t cost = 49 * width + 32 * sizeof exponent + 9;
  for (unsigned scenario = 0; scenario < 4; ++scenario) {
    random_source source = {seed, seed, width, 0, scenario == 2 ? TC_ERROR : TC_OK};
    memset(signature, 0xa5, sizeof signature);
    memset(scratch, 0xa5, sizeof scratch);
    TC_RSA_result result =
        scenario == 3
            ? example_sign_rsa_v15_digest(&private_key, hash, (TC_bytes){digest, digest_length},
                                          (TC_buffer){signature, width},
                                          (TC_random_source){random_bytes, &source},
                                          &(TC_RSA_workspace){scratch, workspace.capacity})
            : sign_v15(&private_key, hash, (TC_bytes){digest, digest_length},
                       (TC_buffer){signature, width}, &workspace,
                       (TC_RSA_execution){{random_bytes, &source}, 1, {cost - (scenario == 1)}});
    munit_assert_int(result, ==,
                     scenario == 1   ? TC_RSA_LIMIT
                     : scenario == 2 ? TC_RSA_ERROR
                                     : TC_RSA_OK);
    /* A short budget fails before encoding and leaves scratch unused. */
    if (scenario == 1)
      for (size_t i = 0; i < sizeof scratch; ++i)
        munit_assert_uint(((uint8_t*)scratch)[i], ==, 0xa5);
    else
      munit_assert_true(tc_test_all_zero(scratch, workspace.capacity * sizeof *scratch));
    munit_assert_uint(((uint8_t*)scratch)[workspace.capacity * sizeof *scratch], ==, 0xa5);
    munit_assert_size(source.calls, ==, scenario == 1 ? 0 : 1);
    if (scenario == 0 || scenario == 3) {
      EVP_PKEY_CTX* verify = EVP_PKEY_CTX_new(key, NULL);
      munit_assert_not_null(verify);
      munit_assert_int(EVP_PKEY_verify_init(verify), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(verify, RSA_PKCS1_PADDING), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_signature_md(verify, method), ==, 1);
      munit_assert_int(EVP_PKEY_verify(verify, signature, width, digest, digest_length), ==, 1);
      EVP_PKEY_CTX_free(verify);
      munit_assert_int(verify_v15(&private_key.public_key, hash, (TC_bytes){digest, digest_length},
                                  (TC_bytes){signature, width}, &workspace, WORK_BUDGET),
                       ==, TC_RSA_OK);
      if (scenario == 0) {
        TC_RSA_prepared_public_key prepared = {0};
        TC_RSA_word cache_words[TC_RSA_RAW_PUBLIC_WORKSPACE_WORDS(4096)];
        TC_RSA_workspace cache = {cache_words, width / sizeof *cache_words};
        TC_work_budget setup_work = {(uint32_t)(16 * width + 1)};
        munit_assert_int(TC_RSA_prepare_public_key(&prepared, &private_key.public_key, &cache,
                                                   &workspace, &setup_work),
                         ==, TC_RSA_OK);
        munit_assert_uint(setup_work.remaining, ==, 0);
        for (unsigned repeat = 0; repeat < 2; ++repeat) {
          TC_work_budget verify_work = {(uint32_t)(width + 16 * sizeof exponent + 4)};
          munit_assert_int(TC_RSA_verify_v15_prepared(&prepared, &(TC_RSA_v15_options){hash},
                                                      (TC_bytes){digest, digest_length},
                                                      (TC_bytes){signature, width}, &workspace,
                                                      &verify_work),
                           ==, TC_RSA_OK);
          munit_assert_uint(verify_work.remaining, ==, 0);
        }
        signature[width - 1] ^= 1;
        TC_work_budget invalid_work = {WORK_BUDGET};
        munit_assert_int(TC_RSA_verify_v15_prepared(&prepared, &(TC_RSA_v15_options){hash},
                                                    (TC_bytes){digest, digest_length},
                                                    (TC_bytes){signature, width}, &workspace,
                                                    &invalid_work),
                         ==, TC_RSA_INVALID);
        signature[width - 1] ^= 1;
        TC_RSA_prepared_public_key_clear(&prepared);
        munit_assert_true(tc_test_all_zero(&prepared, sizeof prepared));
      }
    } else {
      for (size_t i = 0; i < sizeof signature; ++i)
        munit_assert_uint(signature[i], ==, 0xa5);
    }
  }
  random_source source = {seed, seed, width, 0, TC_OK};
  memset(signature, 0xa5, sizeof signature);
  private_key.crt = &crt;
  munit_assert_int(
      sign_v15(
          &private_key, hash, (TC_bytes){digest, digest_length}, (TC_buffer){signature, width},
          &workspace,
          (TC_RSA_execution){{random_bytes, &source}, 1, {65 * width + 32 * sizeof exponent + 13}}),
      ==, TC_RSA_OK);
  EVP_PKEY_CTX* verify = EVP_PKEY_CTX_new(key, NULL);
  munit_assert_not_null(verify);
  munit_assert_int(EVP_PKEY_verify_init(verify), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(verify, RSA_PKCS1_PADDING), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_signature_md(verify, method), ==, 1);
  munit_assert_int(EVP_PKEY_verify(verify, signature, width, digest, digest_length), ==, 1);
  EVP_PKEY_CTX_free(verify);
  EVP_PKEY_free(key);
  return MUNIT_OK;
}

static MunitResult crt_components(const MunitParameter params[], void* user)
{
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params, "bits"), NULL, 10);
  const size_t width = bits / 8, required = 8 * width / sizeof(tc_mp_word);
  const size_t cost = 32 * width + 1;
  EVP_PKEY* key = EVP_RSA_gen(bits);
  const char* names[] = {OSSL_PKEY_PARAM_RSA_D,         OSSL_PKEY_PARAM_RSA_FACTOR1,
                         OSSL_PKEY_PARAM_RSA_FACTOR2,   OSSL_PKEY_PARAM_RSA_EXPONENT1,
                         OSSL_PKEY_PARAM_RSA_EXPONENT2, OSSL_PKEY_PARAM_RSA_COEFFICIENT1};
  uint8_t bytes[6][MAX_BYTES];
  TC_bytes values[6];
  tc_mp_word scratch[8 * MAX_WORDS + 1];
  (void)user;
  munit_assert_not_null(key);
  for (size_t i = 0; i < sizeof values / sizeof *values; ++i) {
    const size_t length = tc_test_rsa_component(key, names[i], bytes[i], sizeof bytes[i], 0);
    munit_assert_size(length, >, 0);
    values[i] = (TC_bytes){bytes[i], length};
  }
  /* The generated key supplies validated d/p/q; corrupt each CRT field alone. */
  uint8_t modulus_bytes[MAX_BYTES];
  static const uint8_t public_exponent[] = {1, 0, 1};
  component(key, OSSL_PKEY_PARAM_RSA_N, modulus_bytes, width);
  const TC_RSA_private_key private_key = {
      {{modulus_bytes, width}, {public_exponent, sizeof public_exponent}},
      values[0],
      values[1],
      values[2],
      NULL};
  TC_RSA_workspace workspace = {scratch, required};
  /* The CRT kernel reads only the modulus length from the public key. */
  const TC_RSA_public_key unchecked_public = {{NULL, width}, {NULL, 0}};
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_CRT, bits), ==, required);
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_CRT, 1536), ==, 0);
  {
    uint8_t derived[3][MAX_BYTES / 2];
    TC_RSA_crt_output output = {
        {derived[0], width / 2}, {derived[1], width / 2}, {derived[2], width / 2}};
    memset(derived, 0xa5, sizeof derived);
    memset(scratch, 0xa5, sizeof scratch);
    TC_work_budget derive_work = {(uint32_t)(48 * width + 3)};
    munit_assert_int(TC_RSA_derive_crt(&private_key, &output, &workspace, &derive_work), ==,
                     TC_RSA_OK);
    for (size_t i = 0; i < 3; ++i) {
      uint8_t expected[MAX_BYTES / 2] = {0};
      munit_assert_size(values[i + 3].length, <=, width / 2);
      memcpy(expected + width / 2 - values[i + 3].length, values[i + 3].data, values[i + 3].length);
      munit_assert_memory_equal(width / 2, derived[i], expected);
    }
    munit_assert_true(tc_test_all_zero(scratch, required * sizeof *scratch));
  }
  for (unsigned scenario = 0; scenario < 4; ++scenario) {
    const size_t field = scenario + 2;
    if (scenario)
      bytes[field][values[field].length - 1] ^= 2;
    memset(scratch, 0xa5, sizeof scratch);
    uint32_t work = cost;
    munit_assert_int(
        tc_rsa_crt_consistent(&(tc_rsa_private_view){&unchecked_public, values[0], values[1],
                                                     values[2], 1, values[3], values[4], values[5]},
                              (tc_mp_scratch){scratch, required}, &work),
        ==, scenario ? TC_RSA_INVALID : TC_RSA_OK);
    munit_assert_size(work, ==, 0);
    const TC_RSA_crt crt = {values[3], values[4], values[5]};
    munit_assert_int(validate_crt(&private_key, &crt, &workspace, (uint32_t)cost), ==,
                     scenario ? TC_RSA_INVALID : TC_RSA_OK);
    const uint8_t* wiped = (const uint8_t*)scratch;
    for (size_t i = 0; i < sizeof scratch; ++i)
      munit_assert_uint(wiped[i], ==, i < required * sizeof *scratch ? 0 : 0xa5);
    if (scenario)
      bytes[field][values[field].length - 1] ^= 2;
  }
  /* Adding the corresponding modulus preserves the congruence but exceeds
   * the CRT component's range. */
  for (size_t field = 3; field < 6; ++field) {
    const TC_bytes original = values[field];
    const TC_bytes factor = values[field == 4 ? 2 : 1];
    BIGNUM* enlarged = BN_bin2bn(original.data, (int)original.length, NULL);
    BIGNUM* modulus = BN_bin2bn(factor.data, (int)factor.length, NULL);
    uint8_t replacement[MAX_BYTES] = {0};
    munit_assert_not_null(enlarged);
    munit_assert_not_null(modulus);
    if (field != 5)
      munit_assert_int(BN_sub_word(modulus, 1), ==, 1);
    munit_assert_int(BN_add(enlarged, enlarged, modulus), ==, 1);
    munit_assert_int(BN_bn2binpad(enlarged, replacement, (int)width), ==, (int)width);
    values[field] = (TC_bytes){replacement, width};
    for (unsigned zero = 0; zero < 2; ++zero) {
      if (zero)
        memset(replacement, 0, width);
      uint32_t work = cost;
      munit_assert_int(tc_rsa_crt_consistent(
                           &(tc_rsa_private_view){&unchecked_public, values[0], values[1],
                                                  values[2], 1, values[3], values[4], values[5]},
                           (tc_mp_scratch){scratch, required}, &work),
                       ==, TC_RSA_INVALID);
      munit_assert_size(work, ==, 0);
    }
    /* Leading zero bytes preserve a valid magnitude. */
    memcpy(replacement + width - original.length, original.data, original.length);
    uint32_t work = cost;
    munit_assert_int(
        tc_rsa_crt_consistent(&(tc_rsa_private_view){&unchecked_public, values[0], values[1],
                                                     values[2], 1, values[3], values[4], values[5]},
                              (tc_mp_scratch){scratch, required}, &work),
        ==, TC_RSA_OK);
    values[field] = original;
    BN_clear_free(enlarged);
    BN_clear_free(modulus);
  }
  memset(scratch, 0xa5, sizeof scratch);
  TC_RSA_crt crt = {values[3], values[4], values[5]};
  TC_bytes* fields[] = {&crt.dp, &crt.dq, &crt.q_inverse};
  for (size_t i = 0; i < sizeof fields / sizeof *fields; ++i) {
    const TC_bytes saved = *fields[i];
    *fields[i] = (TC_bytes){(const uint8_t*)scratch, width};
    munit_assert_int(validate_crt(&private_key, &crt, &workspace, (uint32_t)cost), ==,
                     TC_RSA_ARGUMENT);
    *fields[i] = saved;
  }
  /* Reject malformed spans before touching scratch. */
  uint8_t oversized[MAX_BYTES + 1] = {0};
  const TC_bytes malformed[] = {{NULL, 1}, {oversized, 0}, {oversized, width + 1}};
  for (size_t field = 0; field < sizeof fields / sizeof *fields; ++field) {
    const TC_bytes saved = *fields[field];
    for (size_t bad = 0; bad < sizeof malformed / sizeof *malformed; ++bad) {
      *fields[field] = malformed[bad];
      munit_assert_int(validate_crt(&private_key, &crt, &workspace, (uint32_t)cost), ==,
                       bad == 0 ? TC_RSA_ARGUMENT : TC_RSA_INVALID);
      const uint8_t* unchanged = (const uint8_t*)scratch;
      for (size_t i = 0; i < sizeof scratch; ++i)
        munit_assert_uint(unchanged[i], ==, 0xa5);
    }
    *fields[field] = saved;
  }
  const TC_RSA_crt saved_crt = crt;
  TC_RSA_workspace metadata_overlap = {(TC_RSA_word*)&crt, sizeof crt / sizeof(TC_RSA_word)};
  munit_assert_int(validate_crt(&private_key, &crt, &metadata_overlap, (uint32_t)cost), ==,
                   TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof crt, &crt, &saved_crt);
  munit_assert_int(validate_crt(NULL, &crt, &workspace, (uint32_t)cost), ==, TC_RSA_ARGUMENT);
  munit_assert_int(validate_crt(&private_key, NULL, &workspace, (uint32_t)cost), ==,
                   TC_RSA_ARGUMENT);
  munit_assert_int(validate_crt(&private_key, &crt, NULL, (uint32_t)cost), ==, TC_RSA_ARGUMENT);
  for (unsigned short_workspace = 0; short_workspace < 2; ++short_workspace) {
    uint32_t work = cost - !short_workspace;
    const size_t saved_work = work;
    munit_assert_int(
        tc_rsa_crt_consistent(&(tc_rsa_private_view){&unchecked_public, values[0], values[1],
                                                     values[2], 1, values[3], values[4], values[5]},
                              (tc_mp_scratch){scratch, required - short_workspace}, &work),
        ==, TC_RSA_LIMIT);
    munit_assert_size(work, ==, saved_work);
    const TC_RSA_workspace limited = {scratch, required - short_workspace};
    munit_assert_int(validate_crt(&private_key, &crt, &limited, (uint32_t)saved_work), ==,
                     TC_RSA_LIMIT);
    const uint8_t* unchanged = (const uint8_t*)scratch;
    for (size_t i = 0; i < sizeof scratch; ++i)
      munit_assert_uint(unchanged[i], ==, 0xa5);
  }
  EVP_PKEY_free(key);
  return MUNIT_OK;
}

/* A random k-bit prime whose top bits are 11, or 10 with p < sqrt(2) 2^(k-1). */
static void fips_prime(BIGNUM* out, int bits, int below_bound, BN_CTX* context)
{
  BIGNUM* square = BN_new();
  BIGNUM* bound = BN_new();
  munit_assert_not_null(bound);
  munit_assert_int(BN_set_word(bound, 1), ==, 1);
  munit_assert_int(BN_lshift(bound, bound, 2 * bits - 1), ==, 1);
  for (;;) {
    munit_assert_int(
        BN_rand(out, bits, below_bound ? BN_RAND_TOP_ONE : BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD), ==,
        1);
    munit_assert_int(BN_sqr(square, out, context), ==, 1);
    if ((BN_cmp(square, bound) < 0) != below_bound)
      continue;
    /* Keep p - 1 coprime to 65537 and to 3 for the e = 3 case. */
    if (BN_mod_word(out, 65537) == 1 || BN_mod_word(out, 3) != 2)
      continue;
    if (BN_check_prime(out, context, NULL) == 1)
      break;
  }
  BN_free(bound);
  BN_free(square);
}

typedef struct {
  uint8_t modulus[MAX_BYTES], exponent[MAX_BYTES], d[MAX_BYTES], p[MAX_BYTES], q[MAX_BYTES];
  size_t exponent_length;
  TC_RSA_private_key key;
} built_key;

/* n = p q and d = e^-1 mod LCM(p-1, q-1), plus lambda_multiple * LCM. */
static void build_key(built_key* out, const BIGNUM* p, const BIGNUM* q, const BIGNUM* e,
                      unsigned lambda_multiple, size_t width, BN_CTX* context)
{
  BIGNUM *n = BN_new(), *p1 = BN_new(), *q1 = BN_new(), *phi = BN_new(), *g = BN_new();
  BIGNUM *lambda = BN_new(), *d = BN_new(), *extra = BN_new();
  munit_assert_not_null(extra);
  munit_assert_int(BN_mul(n, p, q, context), ==, 1);
  munit_assert_not_null(BN_copy(p1, p));
  munit_assert_not_null(BN_copy(q1, q));
  munit_assert_int(BN_sub_word(p1, 1), ==, 1);
  munit_assert_int(BN_sub_word(q1, 1), ==, 1);
  munit_assert_int(BN_mul(phi, p1, q1, context), ==, 1);
  munit_assert_int(BN_gcd(g, p1, q1, context), ==, 1);
  munit_assert_int(BN_div(lambda, NULL, phi, g, context), ==, 1);
  munit_assert_not_null(BN_mod_inverse(d, e, lambda, context));
  munit_assert_not_null(BN_copy(extra, lambda));
  munit_assert_int(BN_mul_word(extra, lambda_multiple), ==, 1);
  munit_assert_int(BN_add(d, d, extra), ==, 1);
  out->exponent_length = (size_t)BN_num_bytes(e);
  munit_assert_int(BN_bn2binpad(n, out->modulus, (int)width), ==, (int)width);
  munit_assert_int(BN_bn2bin(e, out->exponent), ==, (int)out->exponent_length);
  munit_assert_int(BN_bn2binpad(d, out->d, (int)width), ==, (int)width);
  munit_assert_int(BN_bn2binpad(p, out->p, (int)width / 2), ==, (int)width / 2);
  munit_assert_int(BN_bn2binpad(q, out->q, (int)width / 2), ==, (int)width / 2);
  out->key = (TC_RSA_private_key){{{out->modulus, width}, {out->exponent, out->exponent_length}},
                                  {out->d, width},
                                  {out->p, width / 2},
                                  {out->q, width / 2},
                                  NULL};
  BN_clear_free(extra);
  BN_clear_free(d);
  BN_clear_free(lambda);
  BN_clear_free(g);
  BN_clear_free(phi);
  BN_clear_free(q1);
  BN_clear_free(p1);
  BN_free(n);
}

static TC_status system_random(void* context, uint8_t* output, size_t length)
{
  (void)context;
  return RAND_bytes(output, (int)length) == 1 ? TC_OK : TC_ERROR;
}

static TC_RSA_result validate_policy(const TC_RSA_private_key* key, TC_RSA_exponent_policy policy)
{
  static tc_mp_word scratch[12 * MAX_WORDS + 2];
  const size_t bits = key->public_key.modulus.length * 8;
  const TC_RSA_workspace workspace = {scratch, TC_RSA_VALIDATE_WORKSPACE_WORDS(bits)};
  TC_RSA_execution execution = {{system_random, NULL},
                                4 * TC_RSA_VALIDATION_ROUNDS,
                                {TC_RSA_VALIDATE_WORK(bits, 4 * TC_RSA_VALIDATION_ROUNDS)}};
  return TC_RSA_validate_private_key(key, policy, TC_PERMIT_DISALLOWED, &workspace, &execution);
}

/* FIPS 186-5 A.1.1 criteria beyond the component equations. Each rejected
 * key satisfies n = p q and e d = 1 mod (p-1) and (q-1). */
static MunitResult fips_criteria(const MunitParameter params[], void* user)
{
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params, "bits"), NULL, 10);
  const size_t width = bits / 8;
  const int k = (int)bits / 2;
  static built_key built;
  BN_CTX* context = BN_CTX_new();
  BIGNUM *p = BN_new(), *q = BN_new(), *e = BN_new(), *low = BN_new();
  (void)user;
  munit_assert_not_null(context);
  munit_assert_not_null(low);
  fips_prime(p, k, 0, context);
  fips_prime(q, k, 0, context);
  munit_assert_int(BN_set_word(e, 65537), ==, 1);
  build_key(&built, p, q, e, 0, width, context);
  munit_assert_int(validate_policy(&built.key, TC_RSA_EXPONENT_FIPS), ==, TC_RSA_OK);
  munit_assert_int(validate_policy(&built.key, TC_RSA_EXPONENT_ANY_ODD), ==, TC_RSA_OK);
  munit_assert_int(validate_policy(&built.key, (TC_RSA_exponent_policy)2), ==, TC_RSA_ARGUMENT);
  /* d + LCM still satisfies e d = 1 mod (p-1) and (q-1), but d >= LCM. */
  build_key(&built, p, q, e, 1, width, context);
  munit_assert_int(validate_policy(&built.key, TC_RSA_EXPONENT_FIPS), ==, TC_RSA_INVALID);
  /* e = 3 is outside the FIPS range. */
  munit_assert_int(BN_set_word(e, 3), ==, 1);
  build_key(&built, p, q, e, 0, width, context);
  munit_assert_int(validate_policy(&built.key, TC_RSA_EXPONENT_FIPS), ==, TC_RSA_INVALID);
  munit_assert_int(validate_policy(&built.key, TC_RSA_EXPONENT_ANY_ODD), ==, TC_RSA_OK);
  /* d <= 2^(nlen/2): choose a small d and derive a large e from it. */
  BIGNUM *p1 = BN_new(), *q1 = BN_new(), *phi = BN_new(), *g = BN_new(), *lambda = BN_new();
  munit_assert_not_null(lambda);
  munit_assert_not_null(BN_copy(p1, p));
  munit_assert_not_null(BN_copy(q1, q));
  munit_assert_int(BN_sub_word(p1, 1), ==, 1);
  munit_assert_int(BN_sub_word(q1, 1), ==, 1);
  munit_assert_int(BN_mul(phi, p1, q1, context), ==, 1);
  munit_assert_int(BN_gcd(g, p1, q1, context), ==, 1);
  munit_assert_int(BN_div(lambda, NULL, phi, g, context), ==, 1);
  do {
    munit_assert_int(BN_rand(low, k - 8, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD), ==, 1);
  } while (!BN_mod_inverse(e, low, lambda, context));
  build_key(&built, p, q, e, 0, width, context);
  munit_assert_int(validate_policy(&built.key, TC_RSA_EXPONENT_ANY_ODD), ==, TC_RSA_INVALID);
  /* A prime below sqrt(2) 2^(k-1). */
  munit_assert_int(BN_set_word(e, 65537), ==, 1);
  BIGNUM* small = BN_new();
  munit_assert_not_null(small);
  fips_prime(small, k, 1, context);
  build_key(&built, small, q, e, 0, width, context);
  munit_assert_int(validate_policy(&built.key, TC_RSA_EXPONENT_FIPS), ==, TC_RSA_INVALID);
  build_key(&built, p, small, e, 0, width, context);
  munit_assert_int(validate_policy(&built.key, TC_RSA_EXPONENT_FIPS), ==, TC_RSA_INVALID);
  /* |p - q| <= 2^(k-100): the next suitable prime after p. */
  munit_assert_not_null(BN_copy(small, p));
  do
    munit_assert_int(BN_add_word(small, 2), ==, 1);
  while (BN_mod_word(small, 65537) == 1 || BN_check_prime(small, context, NULL) != 1);
  build_key(&built, p, small, e, 0, width, context);
  munit_assert_int(validate_policy(&built.key, TC_RSA_EXPONENT_FIPS), ==, TC_RSA_INVALID);
  BN_free(small);
  BN_clear_free(lambda);
  BN_clear_free(g);
  BN_clear_free(phi);
  BN_clear_free(q1);
  BN_clear_free(p1);
  BN_clear_free(low);
  BN_free(e);
  BN_clear_free(q);
  BN_clear_free(p);
  BN_CTX_free(context);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  static char* sizes[] = {"1024", "2048", "3072", "4096", NULL};
  static MunitParameterEnum parameters[] = {{"bits", sizes}, {NULL, NULL}};
#if TC_RSA_SMALL
  /* Byte limbs make the constant-time LCM slow; one size covers the logic. */
  static char* fips_sizes[] = {"1024", NULL};
#else
  static char* fips_sizes[] = {"1024", "2048", NULL};
#endif
  static MunitParameterEnum fips_parameters[] = {{"bits", fips_sizes}, {NULL, NULL}};
  static char* hashes[] = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512", NULL};
  static MunitParameterEnum signing_parameters[] = {
      {"bits", sizes}, {"hash", hashes}, {NULL, NULL}};
  MunitTest tests[] = {
      {"/crt-components", crt_components, NULL, NULL, MUNIT_TEST_OPTION_NONE, parameters},
      {"/operation", private_operation, NULL, NULL, MUNIT_TEST_OPTION_NONE, parameters},
      {"/composite-components", composite_components, NULL, NULL, MUNIT_TEST_OPTION_NONE,
       parameters},
      {"/signing", signing, NULL, NULL, MUNIT_TEST_OPTION_NONE, signing_parameters},
      {"/fips-criteria", fips_criteria, NULL, NULL, MUNIT_TEST_OPTION_NONE, fips_parameters},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/rsa/private", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
