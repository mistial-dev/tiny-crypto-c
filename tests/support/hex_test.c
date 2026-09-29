/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Behaviour of the shared test hex decoder in tests/support/cavp.c. */
#include "cavp.h"
#include "munit.h"
#include <string.h>

static MunitResult field_format(const MunitParameter params[], void* user)
{
  static const char* const terminated[] = {"00aB\"",        "00aB\r\n", "00aB\n",     "00aB \t",
                                           "00aB\", \"x\"", "00aB \"x", "00aB\t\r\n", "00aB"};
  uint8_t output[4];
  size_t length, i;
  (void)params;
  (void)user;
  for (i = 0; i < sizeof terminated / sizeof *terminated; ++i) {
    length = 99;
    memset(output, 0xa5, sizeof output);
    munit_assert_true(
        tc_test_hex_decode(terminated[i], TC_TEST_HEX_FIELD, output, sizeof output, &length));
    munit_assert_size(length, ==, 2);
    munit_assert_uint8(output[0], ==, 0x00);
    munit_assert_uint8(output[1], ==, 0xab);
  }
  length = 99;
  munit_assert_true(tc_test_hex_decode("", TC_TEST_HEX_FIELD, output, 0, &length));
  munit_assert_size(length, ==, 0);
  munit_assert_size(tc_test_hex("0102", output, 2), ==, 2);
  munit_assert_uint8(output[1], ==, 0x02);
  return MUNIT_OK;
}

static MunitResult field_rejects(const MunitParameter params[], void* user)
{
  /* Only whitespace may follow the digits, before NUL or a closing quote. */
  static const char* const malformed[] = {"0",       "012",     "0g",     "g0",     "01:02",
                                          "0\"",     "0 1",     "00 01",  "00\t01", "00\r\n01",
                                          "00 rest", "00aB\tx", "00 \t x"};
  uint8_t output[4];
  size_t length, i;
  (void)params;
  (void)user;
  for (i = 0; i < sizeof malformed / sizeof *malformed; ++i) {
    length = 99;
    munit_assert_false(
        tc_test_hex_decode(malformed[i], TC_TEST_HEX_FIELD, output, sizeof output, &length));
    munit_assert_size(length, ==, 99);
  }
  /* Capacity is exact: four bytes fit in four, five do not. */
  munit_assert_true(tc_test_hex_decode("00010203", TC_TEST_HEX_FIELD, output, 4, &length));
  munit_assert_size(length, ==, 4);
  length = 99;
  munit_assert_false(tc_test_hex_decode("0001020304", TC_TEST_HEX_FIELD, output, 4, &length));
  munit_assert_size(length, ==, 99);
  munit_assert_false(tc_test_hex_decode("00", TC_TEST_HEX_FIELD, output, 0, &length));
  munit_assert_size(length, ==, 99);
  return MUNIT_OK;
}

static MunitResult separated_format(const MunitParameter params[], void* user)
{
  uint8_t output[4];
  size_t length = 99;
  (void)params;
  (void)user;
  munit_assert_true(tc_test_hex_decode("\"0a: 0B-\r\n\tff\"", TC_TEST_HEX_SEPARATED, output,
                                       sizeof output, &length));
  munit_assert_size(length, ==, 3);
  munit_assert_uint8(output[0], ==, 0x0a);
  munit_assert_uint8(output[1], ==, 0x0b);
  munit_assert_uint8(output[2], ==, 0xff);
  /* A separator may not split a byte, and a digit needs its partner. */
  length = 99;
  munit_assert_false(
      tc_test_hex_decode("0 a", TC_TEST_HEX_SEPARATED, output, sizeof output, &length));
  munit_assert_false(
      tc_test_hex_decode("0a b", TC_TEST_HEX_SEPARATED, output, sizeof output, &length));
  munit_assert_false(tc_test_hex_decode("00 01", TC_TEST_HEX_SEPARATED, output, 1, &length));
  munit_assert_size(length, ==, 99);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/field", field_format, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/field-rejects", field_rejects, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/separated", separated_format, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite suite = {"/test-hex", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
