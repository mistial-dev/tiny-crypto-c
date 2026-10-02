/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/gzip.h>
#include "munit.h"
#include "test_util.h"
#include <string.h>

TC_TEST(result_order)
{
  munit_assert_int(TC_GZIP_OK, ==, TC_RESULT_OK);
  munit_assert_int(TC_GZIP_INVALID, ==, TC_RESULT_INVALID);
  munit_assert_int(TC_GZIP_LIMIT, ==, TC_RESULT_LIMIT);
  munit_assert_int(TC_GZIP_ARGUMENT, ==, TC_RESULT_ARGUMENT);
  munit_assert_int(TC_GZIP_UNSUPPORTED, ==, TC_RESULT_UNSUPPORTED);
  return MUNIT_OK;
}

TC_TEST(decode)
{
  uint8_t member[] = {0x1f, 0x8b, 8,    0, 0, 0,    0,    0,    2,  0xff, 0x4b, 0x4c, 0x4a,
                      0x4e, 0x44, 0x45, 0, 4, 0xc0, 0x26, 0xdc, 18, 0,    0,    0};
  uint8_t output[32], zeros[sizeof output] = {0};
  TC_GZIP_workspace workspace;
  size_t work = SIZE_MAX, length = SIZE_MAX;
  munit_assert_int(TC_GZIP_decode((TC_bytes){member, sizeof member}, &workspace, &work,
                                  (TC_buffer){output, sizeof output}, &length),
                   ==, TC_GZIP_OK);
  munit_assert_size(length, ==, 18);
  munit_assert_memory_equal(length, output, "abcabcabcabcabcabc");
  for (size_t i = 0; i < sizeof workspace; ++i)
    munit_assert_uint(((uint8_t*)&workspace)[i], ==, 0);
  member[17] ^= 1;
  work = SIZE_MAX;
  length = SIZE_MAX;
  munit_assert_int(TC_GZIP_decode((TC_bytes){member, sizeof member}, &workspace, &work,
                                  (TC_buffer){output, sizeof output}, &length),
                   ==, TC_GZIP_INVALID);
  munit_assert_size(length, ==, SIZE_MAX);
  munit_assert_memory_equal(sizeof output, output, zeros);
  member[17] ^= 1;
  work = 0;
  memset(output, 0x5a, sizeof output);
  munit_assert_int(TC_GZIP_decode((TC_bytes){member, sizeof member}, &workspace, &work,
                                  (TC_buffer){output, sizeof output}, &length),
                   ==, TC_GZIP_LIMIT);
  munit_assert_memory_equal(sizeof output, output, zeros);
  uint8_t saved[sizeof member];
  memcpy(saved, member, sizeof member);
  work = SIZE_MAX;
  munit_assert_int(TC_GZIP_decode((TC_bytes){member, sizeof member}, &workspace, &work,
                                  (TC_buffer){member, sizeof member}, &length),
                   ==, TC_GZIP_ARGUMENT);
  munit_assert_memory_equal(sizeof saved, member, saved);
  munit_assert_size(work, ==, SIZE_MAX);
  munit_assert_int(TC_GZIP_decode((TC_bytes){member, sizeof member}, &workspace, &work,
                                  (TC_buffer){output, sizeof output}, &work),
                   ==, TC_GZIP_ARGUMENT);
  munit_assert_size(work, ==, SIZE_MAX);
  munit_assert_int(TC_GZIP_decode((TC_bytes){member, sizeof member}, NULL, &work,
                                  (TC_buffer){output, sizeof output}, &length),
                   ==, TC_GZIP_ARGUMENT);
  munit_assert_int(TC_GZIP_decode((TC_bytes){member, sizeof member}, &workspace, &work,
                                  (TC_buffer){NULL, 1}, &length),
                   ==, TC_GZIP_ARGUMENT);
  munit_assert_size(work, ==, SIZE_MAX);
  /* A span with NULL data and a length is an argument error that keeps storage. */
  uint8_t filled[sizeof output];
  memset(output, 0x5a, sizeof output);
  memcpy(filled, output, sizeof output);
  length = SIZE_MAX;
  munit_assert_int(TC_GZIP_decode((TC_bytes){NULL, 1}, &workspace, &work,
                                  (TC_buffer){output, sizeof output}, &length),
                   ==, TC_GZIP_ARGUMENT);
  munit_assert_int(TC_GZIP_decode((TC_bytes){member, sizeof member}, NULL, &work,
                                  (TC_buffer){output, sizeof output}, &length),
                   ==, TC_GZIP_ARGUMENT);
  munit_assert_memory_equal(sizeof output, output, filled);
  munit_assert_size(length, ==, SIZE_MAX);
  munit_assert_size(work, ==, SIZE_MAX);
  /* RFC 1952 section 2.3.1: CM 8 is deflate, other methods are unsupported. */
  member[2] = 7;
  length = SIZE_MAX;
  memset(output, 0x5a, sizeof output);
  munit_assert_int(TC_GZIP_decode((TC_bytes){member, sizeof member}, &workspace, &work,
                                  (TC_buffer){output, sizeof output}, &length),
                   ==, TC_GZIP_UNSUPPORTED);
  munit_assert_size(length, ==, SIZE_MAX);
  munit_assert_memory_equal(sizeof output, output, zeros);
  return MUNIT_OK;
}

TC_TEST(spare_capacity)
{
  /* docs/gzip.md: success leaves bytes beyond the decoded length unchanged.
   * Two members, each with a back reference, decode into a larger buffer. */
  static const uint8_t member[] = {0x1f, 0x8b, 8,    0,    0,    0,    0,    0, 2,
                                   0xff, 0x4b, 0x4c, 0x4a, 0x4e, 0x44, 0x45, 0, 4,
                                   0xc0, 0x26, 0xdc, 18,   0,    0,    0};
  uint8_t input[2 * sizeof member], output[64];
  memcpy(input, member, sizeof member);
  memcpy(input + sizeof member, member, sizeof member);
  memset(output, 0x5a, sizeof output);
  TC_GZIP_workspace workspace;
  size_t work = SIZE_MAX, length = SIZE_MAX;
  munit_assert_int(TC_GZIP_decode((TC_bytes){input, sizeof input}, &workspace, &work,
                                  (TC_buffer){output, sizeof output}, &length),
                   ==, TC_GZIP_OK);
  munit_assert_size(length, ==, 36);
  munit_assert_memory_equal(length, output, "abcabcabcabcabcabcabcabcabcabcabcabc");
  for (size_t i = length; i < sizeof output; ++i)
    munit_assert_uint8(output[i], ==, 0x5a);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/result-order", result_order, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/decode", decode, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/spare-capacity", spare_capacity, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/gzip", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
