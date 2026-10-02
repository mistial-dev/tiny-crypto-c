/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The evaluation time of the PIV hardware tests (tests/piv/hardware/
 * card_config.h): the fixture instant by default, TC_PIV_CARD_TIME as an
 * ISO 8601 UTC time, or now for the host clock. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "hardware/card_config.h"
#include "test_util.h"
#include <stdlib.h>

#ifndef TC_VECTOR_DIR
#error "TC_VECTOR_DIR must name tests/vectors"
#endif

static const char* const variables[] = {
    "TC_PIV_CARD_READER",     "TC_PIV_CARD_INTERFACE",   "TC_PIV_PIN",
    "TC_PIV_PAIRING_CODE",    "TC_PIV_CARD_MIN_RETRIES", "TC_PIV_CARD_EXPECT",
    "TC_PIV_CARD_ROOT",       "TC_PIV_CARD_ROOT_SHA256", "TC_PIV_CARD_CRL_DIR",
    "TC_PIV_CARD_REVOCATION", "TC_PIV_CARD_EXTENDED",    "TC_PIV_CARD_DUMP_DIR",
    "TC_PIV_CARD_TIME"};

static tc_piv_card_config config;

static void environment_clear(void)
{
  for (size_t i = 0; i < sizeof variables / sizeof *variables; ++i)
    munit_assert_int(unsetenv(variables[i]), ==, 0);
}

static void assert_time(const TC_X509_time* actual, const TC_X509_time* expected)
{
  munit_assert_uint(actual->year, ==, expected->year);
  munit_assert_uint(actual->month, ==, expected->month);
  munit_assert_uint(actual->day, ==, expected->day);
  munit_assert_uint(actual->hour, ==, expected->hour);
  munit_assert_uint(actual->minute, ==, expected->minute);
  munit_assert_uint(actual->second, ==, expected->second);
}

static const char* read_with_time(const char* value)
{
  environment_clear();
  if (value)
    munit_assert_int(setenv("TC_PIV_CARD_TIME", value, 1), ==, 0);
  const char* malformed = tc_piv_card_config_read(&config, TC_VECTOR_DIR);
  environment_clear();
  return malformed;
}

TC_TEST(evaluation_time)
{
  const TC_X509_time fixture = {2026, 9, 29, 18, 0, 0};
  const TC_X509_time fixed = TC_PIV_CARD_FIXTURE_TIME;
  assert_time(&fixed, &fixture);

  /* Unset and empty take the fixture instant. */
  munit_assert_null(read_with_time(NULL));
  assert_time(&config.at, &fixture);
  munit_assert_false(config.host_clock);
  munit_assert_null(read_with_time(""));
  assert_time(&config.at, &fixture);
  munit_assert_false(config.host_clock);

  const TC_X509_time chosen = {2027, 1, 2, 3, 4, 5};
  munit_assert_null(read_with_time("2027-01-02T03:04:05Z"));
  assert_time(&config.at, &chosen);
  munit_assert_false(config.host_clock);

  /* now keeps the fixture instant and asks the backend for the clock. */
  munit_assert_null(read_with_time("now"));
  munit_assert_true(config.host_clock);
  assert_time(&config.at, &fixture);

  static const char* const malformed[] = {"yesterday", "2026-09-29", "2026-09-29T18:00:00",
                                          "2026-02-30T00:00:00Z", "NOW"};
  for (size_t i = 0; i < sizeof malformed / sizeof *malformed; ++i)
    munit_assert_string_equal(read_with_time(malformed[i]), "TC_PIV_CARD_TIME");
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/evaluation-time", evaluation_time, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/piv/hardware/config", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
