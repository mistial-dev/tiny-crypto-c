/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * NIST CAVP DRBGVS answers for SP 800-90A (tests/vectors/drbg/cavp). Each
 * trial follows the DRBGVS procedure for its variant:
 *   pr_true:   instantiate, generate (EntropyInputPR), generate (EntropyInputPR)
 *   pr_false:  instantiate, reseed, generate, generate
 *   no_reseed: instantiate, generate, generate
 * and compares the second generate's output with ReturnedBits. A replay
 * entropy source serves each recorded entropy input once and checks that the
 * DRBG requests exactly its length. Every file asserts the trials run and
 * the trials skipped for options outside this library. */
#include "cavp.h"
#include "munit.h"
#include <tiny_crypto/drbg.h>
#include <stdlib.h>
#include <string.h>

#ifndef DRBG_CAVP_DIR
#define DRBG_CAVP_DIR "tests/vectors/drbg/cavp"
#endif

enum { MAX_VALUE = 64, MAX_OUTPUT = 256, MAX_QUEUE = 3 };

typedef struct {
  uint8_t data[MAX_VALUE];
  size_t length;
} value;

typedef struct {
  value entropy, nonce, personalization, entropy_reseed, additional_reseed;
  value additional[2], entropy_pr[2];
  uint8_t returned[MAX_OUTPUT];
  size_t returned_length;
  size_t additional_count, entropy_pr_count;
  long count;
} trial;

/* Entropy inputs in the order the DRBG must request them. */
typedef struct {
  const value* queue[MAX_QUEUE];
  size_t used, count;
} replay;

static TC_status replay_fill(void* user, uint8_t* output, size_t length)
{
  replay* source = (replay*)user;
  const value* next;
  if (source->used == source->count)
    return TC_ERROR;
  next = source->queue[source->used++];
  munit_assert_size(length, ==, next->length);
  memcpy(output, next->data, length);
  return TC_OK;
}

static TC_bytes span(const value* v)
{
  TC_bytes result = {v->length ? v->data : NULL, v->length};
  return result;
}

static void take(value* v, const char* hex)
{
  const long length = tc_cavp_parse_hex(hex, v->data, sizeof v->data);
  munit_assert_long(length, >=, 0);
  v->length = (size_t)length;
}

/* Map a DRBGVS option header to a configuration. Returns 0 for options this
 * library leaves out: SHA-512/224, SHA-512/256 and TDEA. */
static int option_config(const char* option, TC_DRBG_mechanism mechanism, TC_DRBG_config* config)
{
  static const struct {
    const char* name;
    TC_hash_algorithm hash;
  } hashes[] = {{"SHA-1", TC_HASH_SHA1},
                {"SHA-224", TC_HASH_SHA224},
                {"SHA-256", TC_HASH_SHA256},
                {"SHA-384", TC_HASH_SHA384},
                {"SHA-512", TC_HASH_SHA512}};
  size_t i;
  memset(config, 0, sizeof *config);
  config->mechanism = mechanism;
  if (mechanism == TC_DRBG_CTR) {
    unsigned bits;
    char df[8];
    if (sscanf(option, "AES-%u %7s df", &bits, df) != 2)
      return 0;
    config->aes_key_bytes = (uint8_t)(bits / 8u);
    config->derivation_function = strcmp(df, "use") == 0;
    return 1;
  }
  for (i = 0; i < sizeof hashes / sizeof hashes[0]; ++i)
    if (strcmp(option, hashes[i].name) == 0) {
      config->hash = hashes[i].hash;
      return 1;
    }
  return 0;
}

typedef enum { VARIANT_PR_TRUE, VARIANT_PR_FALSE, VARIANT_NO_RESEED } variant;

static void run_trial(variant kind, const TC_DRBG_config* config, const trial* t, const char* file,
                      const char* option)
{
  static TC_DRBG drbg;
  uint8_t output[MAX_OUTPUT];
  replay source = {{&t->entropy}, 0, 1};
  TC_random_source entropy = {replay_fill, &source};
  const int pr = kind == VARIANT_PR_TRUE;
  int call;

  munit_assert_size(t->additional_count, ==, 2);
  if (kind == VARIANT_PR_TRUE) {
    munit_assert_size(t->entropy_pr_count, ==, 2);
    source.queue[1] = &t->entropy_pr[0];
    source.queue[2] = &t->entropy_pr[1];
    source.count = 3;
  } else if (kind == VARIANT_PR_FALSE) {
    source.queue[1] = &t->entropy_reseed;
    source.count = 2;
  }
  munit_assert_int(
      TC_DRBG_instantiate(&drbg, config, entropy, span(&t->nonce), span(&t->personalization)), ==,
      TC_DRBG_OK);
  if (kind == VARIANT_PR_FALSE)
    munit_assert_int(TC_DRBG_reseed(&drbg, span(&t->additional_reseed)), ==, TC_DRBG_OK);
  for (call = 0; call < 2; ++call)
    munit_assert_int(
        TC_DRBG_generate(&drbg, output, t->returned_length, pr, span(&t->additional[call])), ==,
        TC_DRBG_OK);
  munit_assert_size(source.used, ==, source.count);
  if (memcmp(output, t->returned, t->returned_length) != 0) {
    fprintf(stderr, "DRBG CAVP mismatch %s [%s] COUNT = %ld\n", file, option, t->count);
    tc_cavp_print_bytes("expected", t->returned, t->returned_length);
    tc_cavp_print_bytes("actual  ", output, t->returned_length);
    munit_error("DRBG CAVP answer mismatch");
  }
  TC_DRBG_uninstantiate(&drbg);
}

static void run_file(const char* directory, variant kind, const char* name,
                     TC_DRBG_mechanism mechanism, long expected_run, long expected_skipped)
{
  static char line[4096];
  char relative[128];
  char option[TC_CAVP_HEADER_BYTES] = "";
  tc_cavp_reader reader;
  tc_cavp_event event;
  TC_DRBG_config config;
  trial t;
  int supported = 0;
  long run = 0, skipped = 0;

  memset(&t, 0, sizeof t);
  snprintf(relative, sizeof relative, "%s/%s", directory, name);
  munit_assert_true(tc_cavp_open(&reader, DRBG_CAVP_DIR, relative, line, sizeof line));
  while ((event = tc_cavp_next(&reader)) != TC_CAVP_END) {
    const char* v = reader.value;
    munit_assert_int(event, !=, TC_CAVP_FAILURE);
    if (event == TC_CAVP_HEADER) {
      /* The option label is the one header without a NAME = VALUE form. */
      if (strchr(reader.name, '=') == NULL) {
        snprintf(option, sizeof option, "%s", reader.name);
        supported = option_config(option, mechanism, &config);
        config.prediction_resistance = kind == VARIANT_PR_TRUE;
      }
      continue;
    }
    if (event == TC_CAVP_RECORD_END)
      continue;
    if (tc_cavp_is(&reader, "COUNT")) {
      memset(&t, 0, sizeof t);
      t.count = strtol(v, NULL, 10);
    } else if (tc_cavp_is(&reader, "EntropyInput")) {
      take(&t.entropy, v);
    } else if (tc_cavp_is(&reader, "Nonce")) {
      take(&t.nonce, v);
    } else if (tc_cavp_is(&reader, "PersonalizationString")) {
      take(&t.personalization, v);
    } else if (tc_cavp_is(&reader, "EntropyInputReseed")) {
      take(&t.entropy_reseed, v);
    } else if (tc_cavp_is(&reader, "AdditionalInputReseed")) {
      take(&t.additional_reseed, v);
    } else if (tc_cavp_is(&reader, "AdditionalInput")) {
      munit_assert_size(t.additional_count, <, 2);
      take(&t.additional[t.additional_count++], v);
    } else if (tc_cavp_is(&reader, "EntropyInputPR")) {
      munit_assert_size(t.entropy_pr_count, <, 2);
      take(&t.entropy_pr[t.entropy_pr_count++], v);
    } else if (tc_cavp_is(&reader, "ReturnedBits")) {
      const long length = tc_cavp_parse_hex(v, t.returned, sizeof t.returned);
      munit_assert_long(length, >, 0);
      t.returned_length = (size_t)length;
      if (supported) {
        run_trial(kind, &config, &t, relative, option);
        ++run;
      } else {
        ++skipped;
      }
    }
  }
  tc_cavp_close(&reader);
  printf("%s: %ld trials, %ld skipped\n", relative, run, skipped);
  munit_assert_long(run, ==, expected_run);
  munit_assert_long(skipped, ==, expected_skipped);
}

/* Each option has 16 parameter groups of 15 trials. Hash_DRBG and HMAC_DRBG
 * files carry 7 options, 2 of them SHA-512/t. CTR_DRBG files carry 6 AES and
 * 2 TDEA options. */
#define TRIALS_PER_OPTION 240L

static void run_variant(const char* directory, variant kind)
{
  run_file(directory, kind, "Hash_DRBG.rsp", TC_DRBG_HASH, 5 * TRIALS_PER_OPTION,
           2 * TRIALS_PER_OPTION);
  run_file(directory, kind, "HMAC_DRBG.rsp", TC_DRBG_HMAC, 5 * TRIALS_PER_OPTION,
           2 * TRIALS_PER_OPTION);
  run_file(directory, kind, "CTR_DRBG.rsp", TC_DRBG_CTR, 6 * TRIALS_PER_OPTION,
           2 * TRIALS_PER_OPTION);
}

static MunitResult test_pr_true(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
  run_variant("pr_true", VARIANT_PR_TRUE);
  return MUNIT_OK;
}

static MunitResult test_pr_false(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
  run_variant("pr_false", VARIANT_PR_FALSE);
  return MUNIT_OK;
}

static MunitResult test_no_reseed(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
  run_variant("no_reseed", VARIANT_NO_RESEED);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/prediction-resistance", test_pr_true, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/reseed", test_pr_false, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/no-reseed", test_no_reseed, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite suite = {"/drbg-cavp", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char** argv)
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
