/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * SP 800-90A DRBG envelope behavior: lifecycle, argument checks, request and
 * input limits, entropy failures, reseed scheduling, sticky errors, state
 * wiping and the TC_random_fn adapter. Known answers are in cavp.c. */
#include "munit.h"
#include <tiny_crypto/drbg.h>
#include <string.h>

/* Deterministic entropy: byte i of call n is (n * 31 + i) mod 256. fail_at
 * makes that call (1-based) fail. */
typedef struct {
  unsigned calls, fail_at;
  size_t last_length;
} counter_source;

static TC_status counter_fill(void* user, uint8_t* output, size_t length)
{
  counter_source* source = (counter_source*)user;
  size_t i;
  ++source->calls;
  source->last_length = length;
  if (source->calls == source->fail_at)
    return TC_ERROR;
  for (i = 0; i < length; ++i)
    output[i] = (uint8_t)(source->calls * 31u + i);
  return TC_OK;
}

static const TC_bytes empty = {NULL, 0};

static TC_DRBG_config config_for(TC_DRBG_mechanism mechanism)
{
  TC_DRBG_config config;
  memset(&config, 0, sizeof config);
  config.mechanism = mechanism;
  config.hash = TC_HASH_SHA256;
  config.aes_key_bytes = 32;
  config.derivation_function = 1;
  return config;
}

static const TC_DRBG_mechanism mechanisms[] = {TC_DRBG_HASH, TC_DRBG_HMAC, TC_DRBG_CTR};

static int all_zero(const void* data, size_t length)
{
  const uint8_t* bytes = (const uint8_t*)data;
  size_t i;
  for (i = 0; i < length; ++i)
    if (bytes[i] != 0)
      return 0;
  return 1;
}

static MunitResult test_lifecycle(const MunitParameter params[], void* data)
{
  static TC_DRBG drbg;
  uint8_t out[64], again[64];
  size_t m;
  (void)params;
  (void)data;
  for (m = 0; m < sizeof mechanisms / sizeof mechanisms[0]; ++m) {
    counter_source source = {0, 0, 0};
    TC_random_source entropy = {counter_fill, &source};
    const TC_DRBG_config config = config_for(mechanisms[m]);

    /* Use before instantiation fails and wipes the output. */
    memset(out, 0xa5, sizeof out);
    memset(&drbg, 0, sizeof drbg);
    munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 0, empty), ==, TC_DRBG_ARGUMENT);
    munit_assert_true(all_zero(out, sizeof out));
    munit_assert_int(TC_DRBG_reseed(&drbg, empty), ==, TC_DRBG_ARGUMENT);

    /* Deterministic replay: the same entropy gives the same output. */
    munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, empty, empty), ==, TC_DRBG_OK);
    munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 0, empty), ==, TC_DRBG_OK);
    source.calls = 0;
    munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, empty, empty), ==, TC_DRBG_OK);
    munit_assert_int(TC_DRBG_generate(&drbg, again, sizeof again, 0, empty), ==, TC_DRBG_OK);
    munit_assert_memory_equal(sizeof out, out, again);
    /* A drawn nonce makes one entropy request: 32 entropy + 16 nonce bytes. */
    munit_assert_uint(source.calls, ==, 1);
    munit_assert_size(source.last_length, ==, 48);

    /* Successive outputs differ, and uninstantiate wipes the context. */
    munit_assert_int(TC_DRBG_generate(&drbg, again, sizeof again, 0, empty), ==, TC_DRBG_OK);
    munit_assert_memory_not_equal(sizeof out, out, again);
    TC_DRBG_uninstantiate(&drbg);
    munit_assert_true(all_zero(&drbg, sizeof drbg));
    munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 0, empty), ==, TC_DRBG_ARGUMENT);
  }
  TC_DRBG_uninstantiate(NULL);
  return MUNIT_OK;
}

static MunitResult test_arguments(const MunitParameter params[], void* data)
{
  static TC_DRBG drbg;
  static uint8_t big[TC_DRBG_MAX_REQUEST_BYTES + 1];
  counter_source source = {0, 0, 0};
  TC_random_source entropy = {counter_fill, &source};
  TC_random_source missing = {NULL, NULL};
  TC_DRBG_config config = config_for(TC_DRBG_HMAC);
  uint8_t nonce[16] = {1}, out[16];
  const TC_bytes short_nonce = {nonce, 15}, good_nonce = {nonce, 16};
  (void)params;
  (void)data;

  munit_assert_int(TC_DRBG_instantiate(NULL, &config, entropy, empty, empty), ==, TC_DRBG_ARGUMENT);
  munit_assert_int(TC_DRBG_instantiate(&drbg, NULL, entropy, empty, empty), ==, TC_DRBG_ARGUMENT);
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, missing, empty, empty), ==,
                   TC_DRBG_ARGUMENT);
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, short_nonce, empty), ==,
                   TC_DRBG_ARGUMENT);
  config.entropy_bytes = 31; /* below the 256-bit strength */
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, good_nonce, empty), ==,
                   TC_DRBG_ARGUMENT);
  config.entropy_bytes = TC_DRBG_MAX_ENTROPY_BYTES + 1;
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, good_nonce, empty), ==,
                   TC_DRBG_ARGUMENT);
  config.entropy_bytes = 0;
  config.reseed_interval = TC_DRBG_MAX_RESEED_INTERVAL + 1;
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, good_nonce, empty), ==,
                   TC_DRBG_ARGUMENT);
  config.reseed_interval = 0;
  config.hash = TC_HASH_UNKNOWN;
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, good_nonce, empty), ==,
                   TC_DRBG_ARGUMENT);
  config.hash = TC_HASH_SHA256;
  config.mechanism = (TC_DRBG_mechanism)9;
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, good_nonce, empty), ==,
                   TC_DRBG_ARGUMENT);
  munit_assert_true(all_zero(&drbg, sizeof drbg));

  /* A nonce that overlaps the context is rejected. */
  config.mechanism = TC_DRBG_HMAC;
  {
    const TC_bytes inside = {(const uint8_t*)&drbg, 16};
    munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, inside, empty), ==,
                     TC_DRBG_ARGUMENT);
  }

  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, good_nonce, empty), ==, TC_DRBG_OK);
  /* 65536 bytes is the SP 800-90A maximum per request. */
  munit_assert_int(TC_DRBG_generate(&drbg, big, TC_DRBG_MAX_REQUEST_BYTES, 0, empty), ==,
                   TC_DRBG_OK);
  memset(big, 0xa5, sizeof big);
  munit_assert_int(TC_DRBG_generate(&drbg, big, sizeof big, 0, empty), ==, TC_DRBG_LIMIT);
  munit_assert_true(all_zero(big, sizeof big));
  munit_assert_int(TC_DRBG_generate(&drbg, NULL, 1, 0, empty), ==, TC_DRBG_ARGUMENT);
  munit_assert_int(TC_DRBG_generate(&drbg, (uint8_t*)&drbg, 16, 0, empty), ==, TC_DRBG_ARGUMENT);
  {
    const TC_bytes overlap = {out + 8, 8};
    munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 0, overlap), ==, TC_DRBG_ARGUMENT);
  }
  /* Prediction resistance needs an instantiation that allows it. */
  munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 1, empty), ==, TC_DRBG_ARGUMENT);
  munit_assert_int(TC_DRBG_generate(&drbg, out, 0, 0, empty), ==, TC_DRBG_OK);
  TC_DRBG_uninstantiate(&drbg);
  return MUNIT_OK;
}

static MunitResult test_ctr_without_df(const MunitParameter params[], void* data)
{
  static TC_DRBG drbg;
  counter_source source = {0, 0, 0};
  TC_random_source entropy = {counter_fill, &source};
  TC_DRBG_config config = config_for(TC_DRBG_CTR);
  uint8_t input[49] = {0}, out[16];
  const TC_bytes seedlen = {input, 48}, too_long = {input, 49}, nonce = {input, 16};
  (void)params;
  (void)data;

  config.derivation_function = 0;
  /* No nonce, inputs at most seedlen, entropy exactly seedlen. */
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, nonce, empty), ==,
                   TC_DRBG_ARGUMENT);
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, empty, too_long), ==,
                   TC_DRBG_ARGUMENT);
  config.entropy_bytes = 49;
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, empty, empty), ==,
                   TC_DRBG_ARGUMENT);
  config.entropy_bytes = 0;
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, empty, seedlen), ==, TC_DRBG_OK);
  munit_assert_size(source.last_length, ==, 48);
  munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 0, too_long), ==, TC_DRBG_ARGUMENT);
  munit_assert_int(TC_DRBG_reseed(&drbg, too_long), ==, TC_DRBG_ARGUMENT);
  munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 0, seedlen), ==, TC_DRBG_OK);
  config.aes_key_bytes = 20;
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, empty, empty), ==,
                   TC_DRBG_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult test_entropy_failures(const MunitParameter params[], void* data)
{
  static TC_DRBG drbg, saved;
  size_t m;
  (void)params;
  (void)data;
  for (m = 0; m < sizeof mechanisms / sizeof mechanisms[0]; ++m) {
    counter_source source = {0, 1, 0};
    TC_random_source entropy = {counter_fill, &source};
    TC_DRBG_config config = config_for(mechanisms[m]);
    uint8_t out[32];

    /* Instantiate: a failed source leaves the context wiped. */
    munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, empty, empty), ==,
                     TC_DRBG_ENTROPY);
    munit_assert_true(all_zero(&drbg, sizeof drbg));

    /* Reseed and prediction-resistant generate: the state is unchanged and
     * the output is wiped. */
    config.prediction_resistance = 1;
    source.calls = 0;
    source.fail_at = 2;
    munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, empty, empty), ==, TC_DRBG_OK);
    saved = drbg;
    munit_assert_int(TC_DRBG_reseed(&drbg, empty), ==, TC_DRBG_ENTROPY);
    munit_assert_memory_equal(sizeof drbg, &drbg, &saved);
    source.fail_at = 3;
    memset(out, 0xa5, sizeof out);
    munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 1, empty), ==, TC_DRBG_ENTROPY);
    munit_assert_true(all_zero(out, sizeof out));
    munit_assert_memory_equal(sizeof drbg, &drbg, &saved);
    source.fail_at = 0;
    munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 1, empty), ==, TC_DRBG_OK);
    munit_assert_uint(source.calls, ==, 4);
    TC_DRBG_uninstantiate(&drbg);
  }
  return MUNIT_OK;
}

static MunitResult test_reseed_interval(const MunitParameter params[], void* data)
{
  static TC_DRBG drbg;
  counter_source source = {0, 0, 0};
  TC_random_source entropy = {counter_fill, &source};
  TC_DRBG_config config = config_for(TC_DRBG_HASH);
  uint8_t out[16];
  int i;
  (void)params;
  (void)data;

  config.reseed_interval = 2;
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, empty, empty), ==, TC_DRBG_OK);
  for (i = 0; i < 2; ++i)
    munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 0, empty), ==, TC_DRBG_OK);
  munit_assert_uint(source.calls, ==, 1);
  /* The third request exceeds the interval and reseeds from the source. */
  munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 0, empty), ==, TC_DRBG_OK);
  munit_assert_uint(source.calls, ==, 2);
  munit_assert_size(source.last_length, ==, 32);
  /* When that reseed fails, generation stops with TC_DRBG_ENTROPY. */
  for (i = 0; i < 1; ++i)
    munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 0, empty), ==, TC_DRBG_OK);
  source.fail_at = 3;
  munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 0, empty), ==, TC_DRBG_ENTROPY);
  source.fail_at = 0;
  munit_assert_int(TC_DRBG_generate(&drbg, out, sizeof out, 0, empty), ==, TC_DRBG_OK);
  TC_DRBG_uninstantiate(&drbg);
  return MUNIT_OK;
}

static MunitResult test_random_source(const MunitParameter params[], void* data)
{
  static TC_DRBG drbg;
  static uint8_t large[200000], reference[200000];
  counter_source source = {0, 0, 0};
  TC_random_source entropy = {counter_fill, &source};
  const TC_DRBG_config config = config_for(TC_DRBG_CTR);
  TC_random_source random;
  size_t offset;
  (void)params;
  (void)data;

  /* The adapter splits a 200000-byte request into maximum-size calls. */
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, empty, empty), ==, TC_DRBG_OK);
  random = TC_DRBG_random_source(&drbg);
  munit_assert_int(random.fill(random.context, large, sizeof large), ==, TC_OK);
  source.calls = 0;
  munit_assert_int(TC_DRBG_instantiate(&drbg, &config, entropy, empty, empty), ==, TC_DRBG_OK);
  for (offset = 0; offset < sizeof reference; offset += TC_DRBG_MAX_REQUEST_BYTES) {
    const size_t chunk = sizeof reference - offset < TC_DRBG_MAX_REQUEST_BYTES
                             ? sizeof reference - offset
                             : TC_DRBG_MAX_REQUEST_BYTES;
    munit_assert_int(TC_DRBG_generate(&drbg, reference + offset, chunk, 0, empty), ==, TC_DRBG_OK);
  }
  munit_assert_memory_equal(sizeof large, large, reference);
  TC_DRBG_uninstantiate(&drbg);
  munit_assert_int(random.fill(random.context, large, 16), ==, TC_ERROR);
  munit_assert_true(all_zero(large, 16));
  return MUNIT_OK;
}

/* SP 800-90A Table 2 and Table 3 bound personalization, nonce and
 * additional input at 2^35 bits. An oversized input is a caller error: it is
 * rejected before any entropy is drawn and the DRBG stays usable. */
static MunitResult test_input_limits(const MunitParameter params[], void* data)
{
#if SIZE_MAX > UINT32_MAX
  static TC_DRBG drbg[2];
  /* The span starts after the DRBG, so only its length can reject it. It is
   * never read: the length check comes first. */
  const TC_bytes oversized = {(const uint8_t*)&drbg[1], (size_t)TC_DRBG_MAX_INPUT_BYTES + 1u};
  uint8_t out[16];
  size_t m;
  (void)params;
  (void)data;
  for (m = 0; m < sizeof mechanisms / sizeof mechanisms[0]; ++m) {
    counter_source source = {0, 0, 0};
    TC_random_source entropy = {counter_fill, &source};
    TC_DRBG_config config = config_for(mechanisms[m]);
    config.prediction_resistance = 1;
    munit_assert_int(TC_DRBG_instantiate(&drbg[0], &config, entropy, empty, oversized), ==,
                     TC_DRBG_ARGUMENT);
    munit_assert_uint(source.calls, ==, 0);
    munit_assert_int(TC_DRBG_instantiate(&drbg[0], &config, entropy, empty, empty), ==, TC_DRBG_OK);
    source.calls = 0;
    munit_assert_int(TC_DRBG_reseed(&drbg[0], oversized), ==, TC_DRBG_ARGUMENT);
    munit_assert_int(TC_DRBG_generate(&drbg[0], out, sizeof out, 1, oversized), ==,
                     TC_DRBG_ARGUMENT);
    munit_assert_int(TC_DRBG_generate(&drbg[0], out, sizeof out, 0, oversized), ==,
                     TC_DRBG_ARGUMENT);
    munit_assert_uint(source.calls, ==, 0);
    munit_assert_int(TC_DRBG_generate(&drbg[0], out, sizeof out, 0, empty), ==, TC_DRBG_OK);
    TC_DRBG_uninstantiate(&drbg[0]);
  }
  return MUNIT_OK;
#else
  (void)params;
  (void)data;
  return MUNIT_SKIP;
#endif
}

static MunitTest tests[] = {
    {"/input-limits", test_input_limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/lifecycle", test_lifecycle, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/arguments", test_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/ctr-without-df", test_ctr_without_df, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/entropy-failures", test_entropy_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/reseed-interval", test_reseed_interval, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/random-source", test_random_source, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite suite = {"/drbg", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char** argv)
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
