/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Builds and runs examples/drbg.c against deterministic and failing
 * entropy sources. */
#include "munit.h"
#include "drbg.h"
#include <string.h>

typedef struct {
  unsigned calls, fail_at;
} source_state;

static TC_status fill(void* user, uint8_t* output, size_t length)
{
  source_state* state = (source_state*)user;
  size_t i;
  if (++state->calls == state->fail_at)
    return TC_ERROR;
  for (i = 0; i < length; ++i)
    output[i] = (uint8_t)(state->calls + i);
  return TC_OK;
}

static MunitResult test_example(const MunitParameter params[], void* data)
{
  static ExampleRandom random;
  static const uint8_t device[] = "unit-0042";
  static const uint8_t first_label[] = "tls", second_label[] = "storage";
  const TC_bytes device_id = {device, sizeof device - 1};
  const TC_bytes tls = {first_label, sizeof first_label - 1};
  const TC_bytes storage = {second_label, sizeof second_label - 1};
  source_state state = {0, 0};
  TC_random_source entropy = {fill, &state};
  uint8_t a[32], b[32];
  (void)params;
  (void)data;

  munit_assert_int(example_random_start(&random, entropy, device_id), ==, TC_DRBG_OK);
  munit_assert_int(example_random_session_key(&random, tls, a), ==, TC_DRBG_OK);
  munit_assert_int(example_random_session_key(&random, storage, b), ==, TC_DRBG_OK);
  munit_assert_memory_not_equal(sizeof a, a, b);
  munit_assert_int(example_random_refresh(&random), ==, TC_DRBG_OK);

  /* A failed refresh keeps the generator usable. */
  state.fail_at = state.calls + 1;
  munit_assert_int(example_random_refresh(&random), ==, TC_DRBG_ENTROPY);
  munit_assert_int(example_random_session_key(&random, tls, a), ==, TC_DRBG_OK);
  example_random_stop(&random);
  munit_assert_int(example_random_session_key(&random, tls, a), ==, TC_DRBG_ARGUMENT);

  /* A failed start leaves a stopped generator. */
  state.calls = 0;
  state.fail_at = 1;
  munit_assert_int(example_random_start(&random, entropy, device_id), ==, TC_DRBG_ENTROPY);
  munit_assert_int(example_random_session_key(&random, tls, a), ==, TC_DRBG_ARGUMENT);
  return MUNIT_OK;
}

static MunitTest tests[] = {{"/example", test_example, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite suite = {"/drbg", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char** argv)
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
