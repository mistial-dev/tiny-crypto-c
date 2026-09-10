/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509.h>
#include "munit.h"
#include <string.h>

static MunitResult unix_time(const MunitParameter params[], void* user)
{
  static const struct { TC_X509_time time; int64_t seconds; } cases[] = {
    {{1,1,1,0,0,0},INT64_C(-62135596800)},
    {{1969,12,31,23,59,59},-1}, {{1970,1,1,0,0,0},0},
    {{2000,1,1,0,0,0},INT64_C(946684800)},
    {{2000,2,29,0,0,0},INT64_C(951782400)},
    {{2026,9,9,0,0,0},INT64_C(1788912000)},
    {{2038,1,19,3,14,7},INT64_C(2147483647)},
    {{2100,3,1,0,0,0},INT64_C(4107542400)},
    {{9999,12,31,23,59,59},INT64_C(253402300799)}
  };
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    int64_t seconds = 99;
    munit_assert_int(TC_X509_time_to_unix(&cases[i].time,&seconds), ==, TC_TLV_OK);
    munit_assert_int64(seconds, ==, cases[i].seconds);
  }
  /* Walk every calendar day independently of the conversion's year totals. */
  static const unsigned month_days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
  int64_t expected = INT64_C(-62135596800);
  for (unsigned year = 1; year <= 9999; ++year) {
    for (unsigned month = 1; month <= 12; ++month) {
      unsigned days = month_days[month - 1];
      if (month == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) ++days;
      for (unsigned day = 1; day <= days; ++day) {
        const TC_X509_time date = {year,(uint8_t)month,(uint8_t)day,0,0,0};
        int64_t seconds;
        munit_assert_int(TC_X509_time_to_unix(&date,&seconds), ==, TC_TLV_OK);
        munit_assert_int64(seconds, ==, expected);
        expected += 86400;
      }
    }
  }
  union { TC_X509_time time; int64_t seconds; } aliased;
  memset(&aliased,0,sizeof aliased);
  aliased.time.year = cases[0].time.year;
  aliased.time.month = cases[0].time.month;
  aliased.time.day = cases[0].time.day;
  aliased.time.hour = cases[0].time.hour;
  aliased.time.minute = cases[0].time.minute;
  aliased.time.second = cases[0].time.second;
  uint8_t saved[sizeof aliased];
  memcpy(saved,&aliased,sizeof saved);
  munit_assert_int(TC_X509_time_to_unix(&aliased.time,&aliased.seconds), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof saved,saved,&aliased);
  int64_t seconds = 99;
  munit_assert_int(TC_X509_time_to_unix(NULL,&seconds), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_time_to_unix(&cases[0].time,NULL), ==, TC_TLV_ARGUMENT);
  munit_assert_int64(seconds, ==, 99);
  (void)params; (void)user;
  return MUNIT_OK;
}

static MunitResult ordering(const MunitParameter params[], void* user)
{
  static const TC_X509_time times[] = {
    {1,1,1,0,0,0}, {1999,12,31,23,59,59}, {2000,1,1,0,0,0},
    {2000,2,28,23,59,59}, {2000,2,29,0,0,0}, {2000,3,1,0,0,0},
    {2049,12,31,23,59,59}, {2050,1,1,0,0,0},
    {2100,2,28,23,59,59}, {2100,3,1,0,0,0}, {9999,12,31,23,59,59}
  };
  size_t i, j;
  (void)params; (void)user;
  for (i = 0; i < sizeof times / sizeof times[0]; ++i)
    for (j = 0; j < sizeof times / sizeof times[0]; ++j) {
      int order = 99;
      munit_assert_int(TC_X509_time_compare(&times[i], &times[j], &order), ==, TC_TLV_OK);
      munit_assert_int(order, ==, i == j ? 0 : i < j ? -1 : 1);
    }
  return MUNIT_OK;
}

static MunitResult validity(const MunitParameter params[], void* user)
{
  TC_X509_certificate certificate = {0};
  TC_X509_time before = {2049,12,31,23,59,58}, first = {2049,12,31,23,59,59};
  TC_X509_time last = {2050,1,1,0,0,0}, after = {2050,1,1,0,0,1};
  int valid = 99;
  (void)params; (void)user;
  certificate.not_before = first; certificate.not_after = last;
  munit_assert_int(TC_X509_valid_at(&certificate, &before, &valid), ==, TC_TLV_OK);
  munit_assert_int(valid, ==, 0);
  munit_assert_int(TC_X509_valid_at(&certificate, &first, &valid), ==, TC_TLV_OK);
  munit_assert_int(valid, ==, 1);
  munit_assert_int(TC_X509_valid_at(&certificate, &last, &valid), ==, TC_TLV_OK);
  munit_assert_int(valid, ==, 1);
  munit_assert_int(TC_X509_valid_at(&certificate, &after, &valid), ==, TC_TLV_OK);
  munit_assert_int(valid, ==, 0);
  certificate.not_after = first;
  munit_assert_int(TC_X509_valid_at(&certificate, &first, &valid), ==, TC_TLV_OK);
  munit_assert_int(valid, ==, 1);
  certificate.not_before = last; valid = 99;
  munit_assert_int(TC_X509_valid_at(&certificate, &first, &valid), ==, TC_TLV_INVALID);
  munit_assert_int(valid, ==, 99);
  return MUNIT_OK;
}

static MunitResult invalid(const MunitParameter params[], void* user)
{
  static const TC_X509_time bad[] = {
    {0,1,1,0,0,0}, {10000,1,1,0,0,0}, {2000,0,1,0,0,0}, {2000,13,1,0,0,0},
    {2000,1,0,0,0,0}, {2000,1,32,0,0,0}, {2000,4,31,0,0,0}, {2000,2,30,0,0,0},
    {1900,2,29,0,0,0}, {2100,2,29,0,0,0}, {2000,1,1,24,0,0},
    {2000,1,1,0,60,0}, {2000,1,1,0,0,60}
  };
  TC_X509_certificate certificate = {0};
  const TC_X509_time good = {2000,1,1,0,0,0};
  size_t i;
  int output = 99;
  (void)params; (void)user;
  for (i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
    int64_t seconds = 99;
    munit_assert_int(TC_X509_time_to_unix(&bad[i],&seconds), ==, TC_TLV_INVALID);
    munit_assert_int64(seconds, ==, 99);
    munit_assert_int(TC_X509_time_compare(&bad[i], &good, &output), ==, TC_TLV_INVALID);
    munit_assert_int(TC_X509_time_compare(&good, &bad[i], &output), ==, TC_TLV_INVALID);
    certificate.not_before = certificate.not_after = good;
    munit_assert_int(TC_X509_valid_at(&certificate, &bad[i], &output), ==, TC_TLV_INVALID);
    certificate.not_before = bad[i];
    munit_assert_int(TC_X509_valid_at(&certificate, &good, &output), ==, TC_TLV_INVALID);
    certificate.not_before = good; certificate.not_after = bad[i];
    munit_assert_int(TC_X509_valid_at(&certificate, &good, &output), ==, TC_TLV_INVALID);
    munit_assert_int(output, ==, 99);
  }
  munit_assert_int(TC_X509_time_compare(NULL, &good, &output), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_valid_at(NULL, &good, &output), ==, TC_TLV_ARGUMENT);
  munit_assert_int(output, ==, 99);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/unix",unix_time,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/ordering",ordering,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/validity",validity,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/invalid",invalid,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/x509/time",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
