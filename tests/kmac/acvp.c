/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Pinned NIST ACVP and independently computed OpenSSL KMAC-256 answers. */
#include <tiny_crypto/kmac.h>
#include "munit.h"
#include "cavp.h"
#include <stdio.h>
#include <string.h>

#ifndef KMAC_ACVP_FILE
#error "KMAC_ACVP_FILE is required"
#endif

static size_t read_hex(const char* field, uint8_t* output, size_t capacity)
{
  return strcmp(field, "-") == 0 ? 0 : tc_test_hex(field, output, capacity);
}

static MunitResult fixed_output(const MunitParameter params[], void* user)
{
  char line[4096];
  uint8_t key[512], message[512], custom[128], expected[512], actual[512];
  FILE* file = fopen(KMAC_ACVP_FILE, "r");
  unsigned cases = 0, odd_output_lengths = 0, customized = 0;
  (void)params;
  (void)user;
  munit_assert_not_null(file);
  while (fgets(line, sizeof line, file)) {
    char* fields[5];
    char* token;
    size_t key_length, message_length, custom_length, tag_length;
    if (line[0] == '#' || line[0] == '\n')
      continue;
    munit_assert_not_null(strchr(line, '\n'));
    token = strtok(line, " \t\r\n");
    for (size_t i = 0; i < 5; ++i) {
      munit_assert_not_null(token);
      fields[i] = token;
      token = strtok(NULL, " \t\r\n");
    }
    munit_assert_null(token);
    key_length = read_hex(fields[0], key, sizeof key);
    message_length = read_hex(fields[1], message, sizeof message);
    custom_length = read_hex(fields[2], custom, sizeof custom);
    tag_length = read_hex(fields[3], expected, sizeof expected);
    munit_assert_size(key_length, >, 0);
    munit_assert_size(tag_length, >, 0);
    munit_assert_int(
        TC_KMAC256_digest((TC_bytes){key, key_length}, (TC_bytes){message, message_length},
                          (TC_bytes){custom, custom_length}, (TC_buffer){actual, tag_length}),
        ==, TC_OK);
    if (memcmp(actual, expected, tag_length))
      munit_errorf("KMAC-256 vector %s: incorrect tag", fields[4]);
    ++cases;
    odd_output_lengths += (unsigned)(tag_length % 2 != 0);
    customized += (unsigned)(custom_length != 0);
  }
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_uint(cases, ==, 7);
  munit_assert_uint(odd_output_lengths, ==, 6);
  munit_assert_uint(customized, ==, 6);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/fixed-output", fixed_output, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/kmac/acvp", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
