/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Record contract of the shared CAVP reader in tests/support/cavp.h, checked
 * against small synthetic files written to the build directory. */
#include "cavp.h"
#include "munit.h"
#include "test_io.h"
#include "test_util.h"
#include <string.h>

typedef struct {
  tc_cavp_event event;
  const char* name;
  const char* value;
} expected_event;

static char line[64];

/* Write text to TC_TEST_RECORD_DIR/file and open a reader over it. Binary
 * mode keeps CR bytes on every host. */
static void open_text(tc_cavp_reader* reader, const char* file, const char* text, size_t capacity)
{
  char path[1024];
  FILE* output;
  munit_assert_int(snprintf(path, sizeof path, "%s/%s", TC_TEST_RECORD_DIR, file), <,
                   (int)sizeof path);
  output = tc_test_fopen(path, "wb");
  munit_assert_not_null(output);
  munit_assert_size(fwrite(text, 1, strlen(text), output), ==, strlen(text));
  munit_assert_int(fclose(output), ==, 0);
  munit_assert_size(capacity, <=, sizeof line);
  munit_assert_true(tc_cavp_open(reader, TC_TEST_RECORD_DIR, file, line, capacity));
}

/* Read one event and check its kind, name and value. */
static void expect(tc_cavp_reader* reader, const expected_event* expected)
{
  munit_assert_int(tc_cavp_next(reader), ==, expected->event);
  munit_assert_string_equal(reader->name, expected->name);
  munit_assert_string_equal(reader->value, expected->value);
}

TC_TEST(skipped_lines)
{
  /* Comments, including an indented one and one between fields, and blank or
   * whitespace-only lines are skipped. Only a blank line after a field ends a
   * record. Names and values lose surrounding whitespace, including CR. */
  static const char text[] = "# COUNT = 99\n"
                             "   # indented\n"
                             "\n"
                             " \t \r\n"
                             "  COUNT  =  7 \r\n"
                             "# Key = ff\n"
                             "Key=00ff\n"
                             "\t\n"
                             "\n"
                             "FAIL\n";
  static const expected_event events[] = {
      {TC_CAVP_FIELD, "COUNT", "7"}, {TC_CAVP_FIELD, "Key", "00ff"}, {TC_CAVP_RECORD_END, "", ""},
      {TC_CAVP_FIELD, "FAIL", ""},   {TC_CAVP_RECORD_END, "", ""},
  };
  tc_cavp_reader reader;
  open_text(&reader, "record_skipped.rsp", text, sizeof line);
  for (size_t i = 0; i < sizeof events / sizeof *events; ++i)
    expect(&reader, &events[i]);
  munit_assert_int(tc_cavp_next(&reader), ==, TC_CAVP_END);
  tc_cavp_close(&reader);
  return MUNIT_OK;
}

TC_TEST(final_record_at_end_of_file)
{
  /* The last line has no line ending and no blank line follows it. */
  tc_cavp_reader reader;
  open_text(&reader, "record_final.rsp", "COUNT = 1\nMsg = 01", sizeof line);
  expect(&reader, &(expected_event){TC_CAVP_FIELD, "COUNT", "1"});
  expect(&reader, &(expected_event){TC_CAVP_FIELD, "Msg", "01"});
  expect(&reader, &(expected_event){TC_CAVP_RECORD_END, "", ""});
  munit_assert_int(tc_cavp_next(&reader), ==, TC_CAVP_END);
  tc_cavp_close(&reader);
  return MUNIT_OK;
}

TC_TEST(header_groups)
{
  static const char text[] = "[SHA-256]\n"
                             "[ Alen = 0, Plen = 1234 ]\n"
                             "\n"
                             "COUNT = 0\n"
                             "\n"
                             "[SHA-384]\n"
                             "COUNT = 1\n"
                             "[SHA-512]\n"
                             "COUNT = 2\n";
  char value[8];
  tc_cavp_reader reader;
  open_text(&reader, "record_headers.rsp", text, sizeof line);
  /* Consecutive headers form one group. Header text loses the brackets and
   * surrounding whitespace, and a blank line keeps the group open. */
  expect(&reader, &(expected_event){TC_CAVP_HEADER, "SHA-256", ""});
  expect(&reader, &(expected_event){TC_CAVP_HEADER, "Alen = 0, Plen = 1234", ""});
  expect(&reader, &(expected_event){TC_CAVP_FIELD, "COUNT", "0"});
  munit_assert_true(tc_cavp_header_has(&reader, "SHA-256"));
  munit_assert_false(tc_cavp_header_has(&reader, "SHA"));
  munit_assert_string_equal(tc_cavp_header_value(&reader, "Alen", value, sizeof value), "0");
  munit_assert_string_equal(tc_cavp_header_value(&reader, "Plen", value, sizeof value), "1234");
  /* The value and its terminator must fit. */
  munit_assert_null(tc_cavp_header_value(&reader, "Plen", value, 4));
  munit_assert_null(tc_cavp_header_value(&reader, "Nlen", value, sizeof value));
  expect(&reader, &(expected_event){TC_CAVP_RECORD_END, "", ""});
  /* A header after a field replaces the group. */
  expect(&reader, &(expected_event){TC_CAVP_HEADER, "SHA-384", ""});
  munit_assert_true(tc_cavp_header_has(&reader, "SHA-384"));
  munit_assert_false(tc_cavp_header_has(&reader, "SHA-256"));
  munit_assert_null(tc_cavp_header_value(&reader, "Plen", value, sizeof value));
  expect(&reader, &(expected_event){TC_CAVP_FIELD, "COUNT", "1"});
  /* A header ends the group without a blank line, and it leaves the record
   * open, so both COUNT fields belong to one record. */
  expect(&reader, &(expected_event){TC_CAVP_HEADER, "SHA-512", ""});
  munit_assert_true(tc_cavp_header_has(&reader, "SHA-512"));
  munit_assert_false(tc_cavp_header_has(&reader, "SHA-384"));
  expect(&reader, &(expected_event){TC_CAVP_FIELD, "COUNT", "2"});
  expect(&reader, &(expected_event){TC_CAVP_RECORD_END, "", ""});
  munit_assert_int(tc_cavp_next(&reader), ==, TC_CAVP_END);
  tc_cavp_close(&reader);
  return MUNIT_OK;
}

TC_TEST(malformed_input)
{
  tc_cavp_reader reader;
  /* The buffer holds the line, its line ending and the terminator. */
  open_text(&reader, "record_fits.rsp", "K = 12\n", 8);
  expect(&reader, &(expected_event){TC_CAVP_FIELD, "K", "12"});
  tc_cavp_close(&reader);
  open_text(&reader, "record_long.rsp", "K = 123\n", 8);
  munit_assert_int(tc_cavp_next(&reader), ==, TC_CAVP_FAILURE);
  tc_cavp_close(&reader);
  /* A final line without a line ending needs only the terminator. */
  open_text(&reader, "record_fits_final.rsp", "K = 123", 8);
  expect(&reader, &(expected_event){TC_CAVP_FIELD, "K", "123"});
  tc_cavp_close(&reader);
  /* A header needs its closing bracket. */
  open_text(&reader, "record_open_header.rsp", "[SHA-256\nCOUNT = 0\n", sizeof line);
  munit_assert_int(tc_cavp_next(&reader), ==, TC_CAVP_FAILURE);
  tc_cavp_close(&reader);
  /* A missing file fails to open, and the reader then reports failure. */
  munit_assert_false(
      tc_cavp_open(&reader, TC_TEST_RECORD_DIR, "record_missing.rsp", line, sizeof line));
  munit_assert_int(tc_cavp_next(&reader), ==, TC_CAVP_FAILURE);
  tc_cavp_close(&reader);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/skipped-lines", skipped_lines, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/final-record", final_record_at_end_of_file, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/header-groups", header_groups, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/malformed", malformed_input, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite suite = {"/cavp-record", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
