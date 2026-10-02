/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/credential_text_internal.h"
#include "munit.h"
#include "test_util.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t* text(const char* value)
{
  return (const uint8_t*)value;
}

static void assert_time(const TC_X509_time* actual, unsigned year, unsigned month, unsigned day)
{
  munit_assert_uint(actual->year, ==, year);
  munit_assert_uint(actual->month, ==, month);
  munit_assert_uint(actual->day, ==, day);
  munit_assert_uint8(actual->hour, ==, 0);
  munit_assert_uint8(actual->minute, ==, 0);
  munit_assert_uint8(actual->second, ==, 0);
}

TC_TEST(decimal)
{
  size_t value = 7;
  munit_assert_true(tc_credential_decimal(text("0042"), 4, 9999, &value));
  munit_assert_size(value, ==, 42);
  munit_assert_true(tc_credential_decimal(text("31"), 2, 31, &value));
  munit_assert_size(value, ==, 31);

  /* Rejections leave the output unchanged. */
  value = 7;
  munit_assert_false(tc_credential_decimal(text("32"), 2, 31, &value));
  munit_assert_false(tc_credential_decimal(text("9"), 1, 8, &value));
  munit_assert_false(tc_credential_decimal(text("1x"), 2, 99, &value));
  munit_assert_false(tc_credential_decimal(text("/0"), 2, 99, &value));
  munit_assert_false(tc_credential_decimal(text(":0"), 2, 99, &value));
  munit_assert_false(tc_credential_decimal(text(""), 0, 99, &value));
  munit_assert_false(tc_credential_decimal(NULL, 2, 99, &value));
  munit_assert_false(tc_credential_decimal(text("12"), 2, 99, NULL));
  munit_assert_size(value, ==, 7);

  /* The bound applies before accumulation, so SIZE_MAX cannot wrap. */
  char digits[48];
  const int written = snprintf(digits, sizeof digits, "%zu", (size_t)SIZE_MAX);
  munit_assert_int(written, >, 0);
  munit_assert_true(tc_credential_decimal(text(digits), (size_t)written, SIZE_MAX, &value));
  munit_assert_size(value, ==, SIZE_MAX);
  digits[written - 1] = (char)(digits[written - 1] + 1);
  value = 7;
  munit_assert_false(tc_credential_decimal(text(digits), (size_t)written, SIZE_MAX, &value));
  munit_assert_size(value, ==, 7);

  munit_assert_true(tc_credential_digits(text("0123456789"), 10));
  munit_assert_false(tc_credential_digits(text("01234x"), 6));
  munit_assert_false(tc_credential_digits(text(""), 0));
  munit_assert_false(tc_credential_digits(NULL, 1));
  return MUNIT_OK;
}

TC_TEST(day_month_year)
{
  static const char* const rejected_upper[] = {"29FEB1900", "00JAN2024", "31APR2024", "01JAN0000",
                                               "01Jan2024", "01FOO2024", "32DEC2024", "0xJAN2024",
                                               "01JAN202x", "-1JAN2024", "01jan2024"};
  static const char* const rejected_title[] = {"01JAN2024", "01jan2024", "01jAN2024", "29Feb2023"};
  const TC_X509_time sentinel = {1, 2, 3, 4, 5, 6};
  TC_X509_time out = sentinel;
  munit_assert_true(tc_credential_day_month_year(text("29FEB2024"), 0, &out));
  assert_time(&out, 2024, 2, 29);
  munit_assert_true(tc_credential_day_month_year(text("31Dec9999"), 1, &out));
  assert_time(&out, 9999, 12, 31);
  for (size_t i = 0; i < sizeof rejected_upper / sizeof *rejected_upper; ++i) {
    out = sentinel;
    munit_assert_false(tc_credential_day_month_year(text(rejected_upper[i]), 0, &out));
    munit_assert_uint(out.year, ==, sentinel.year);
    munit_assert_uint8(out.hour, ==, sentinel.hour);
  }
  for (size_t i = 0; i < sizeof rejected_title / sizeof *rejected_title; ++i) {
    out = sentinel;
    munit_assert_false(tc_credential_day_month_year(text(rejected_title[i]), 1, &out));
    munit_assert_uint(out.year, ==, sentinel.year);
  }
  munit_assert_false(tc_credential_day_month_year(NULL, 0, &out));
  munit_assert_false(tc_credential_day_month_year(text("01JAN2024"), 0, NULL));
  return MUNIT_OK;
}

TC_TEST(yyyymmdd)
{
  unsigned year = 1, month = 2, day = 3;
  munit_assert_true(tc_credential_yyyymmdd(text("20240229"), 8, &year, &month, &day));
  munit_assert_uint(year, ==, 2024);
  munit_assert_uint(month, ==, 2);
  munit_assert_uint(day, ==, 29);
  munit_assert_true(tc_credential_yyyymmdd(text("20240229"), 8, NULL, NULL, NULL));
  year = 1;
  munit_assert_false(tc_credential_yyyymmdd(text("20230229"), 8, &year, &month, &day));
  munit_assert_false(tc_credential_yyyymmdd(text("20241301"), 8, &year, &month, &day));
  munit_assert_false(tc_credential_yyyymmdd(text("2024020x"), 8, &year, &month, &day));
  munit_assert_false(tc_credential_yyyymmdd(text("2024022"), 7, &year, &month, &day));
  munit_assert_false(tc_credential_yyyymmdd(NULL, 8, &year, &month, &day));
  munit_assert_uint(year, ==, 1);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/decimal", decimal, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/day-month-year", day_month_year, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/yyyymmdd", yyyymmdd, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

int main(int argc, char** argv)
{
  const MunitSuite suite = {"/credential/text", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
