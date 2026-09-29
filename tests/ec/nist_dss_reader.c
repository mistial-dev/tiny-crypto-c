/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/ec.h>
#include "munit.h"
#include "test_util.h"
#include "cavp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* vector_path;

TC_TEST(vectors)
{
  char line[1024];
  uint8_t scalar[48], point[128], actual[97];
  TC_EC_workspace workspace;
  size_t count = 0;
  FILE* file;
  if (!vector_path)
    return MUNIT_SKIP;
  file = fopen(vector_path, "r");
  munit_assert_not_null(file);
  while (fgets(line, sizeof line, file)) {
    char *fields[5], *token = strtok(line, " \t\r\n");
    size_t columns = 0;
    while (token) {
      munit_assert_size(columns, <, 5);
      fields[columns++] = token;
      token = strtok(NULL, " \t\r\n");
    }
    munit_assert_true(columns == 4 || columns == 5);
    unsigned bits = (unsigned)strtoul(fields[1], NULL, 10);
    munit_assert_true(bits == 192 || bits == 256 || bits == 384);
    TC_EC_curve curve = bits == 192 ? TC_EC_P192 : bits == 256 ? TC_EC_P256 : TC_EC_P384;
    size_t width = bits / 8;
    size_t length = tc_test_hex(fields[2], point, sizeof point);
    munit_assert_size(strlen(fields[2]), ==, 2 * length);
    if (!strcmp(fields[0], "pkv")) {
      munit_assert_size(columns, ==, 4);
      TC_work_budget work = {UINT32_MAX};
      TC_EC_result result =
          TC_EC_validate_public_key(curve, (TC_bytes){point, length}, &workspace, &work);
      munit_assert_true(!strcmp(fields[3], "valid") || !strcmp(fields[3], "invalid"));
      if ((result == TC_EC_OK) != !strcmp(fields[3], "valid"))
        munit_errorf("NIST ECDSA PKV %zu: status %d, expected %s", count, result, fields[3]);
    } else {
      munit_assert_string_equal(fields[0], "keypair");
      munit_assert_size(columns, ==, 4);
      munit_assert_size(length, ==, 1 + 2 * width);
      size_t scalar_length = tc_test_hex(fields[3], scalar, sizeof scalar);
      munit_assert_size(scalar_length, ==, width);
      munit_assert_size(strlen(fields[3]), ==, 2 * scalar_length);
      TC_work_budget work = {UINT32_MAX};
      TC_EC_result result = TC_EC_public_key(curve, (TC_bytes){scalar, width},
                                             (TC_buffer){actual, length}, &workspace, &work);
      if (result != TC_EC_OK || memcmp(actual, point, length))
        munit_errorf("NIST ECDSA KeyPair %zu: status %d or point mismatch", count, result);
    }
    ++count;
  }
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(count, >, 0);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/vectors", vectors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/nist-ecdsa", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  if (argc == 3 && !strcmp(argv[1], "--vectors")) {
    vector_path = argv[2];
    argc = 1;
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
