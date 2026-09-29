/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/gzip.h>
#include "munit.h"
#include <string.h>

static MunitResult result_order(const MunitParameter params[], void* context)
{
  /* GZIP shares the RSA and EC result order. */
  munit_assert_int(TC_GZIP_OK, ==, 0);
  munit_assert_int(TC_GZIP_INVALID, ==, 1);
  munit_assert_int(TC_GZIP_LIMIT, ==, 2);
  munit_assert_int(TC_GZIP_ARGUMENT, ==, 3);
  munit_assert_int(TC_GZIP_UNSUPPORTED, ==, 4);
  (void)params;
  (void)context;
  return MUNIT_OK;
}

static MunitResult decode(const MunitParameter params[], void* context)
{
  uint8_t member[] = {0x1f, 0x8b, 8,    0, 0, 0,    0,    0,    2,  0xff, 0x4b, 0x4c, 0x4a,
                      0x4e, 0x44, 0x45, 0, 4, 0xc0, 0x26, 0xdc, 18, 0,    0,    0};
  uint8_t output[32], zeros[sizeof output] = {0};
  TC_GZIP_workspace workspace;
  size_t work = SIZE_MAX, length = SIZE_MAX;
  munit_assert_int(
      TC_GZIP_decode(member, sizeof member, output, sizeof output, &workspace, &work, &length), ==,
      TC_GZIP_OK);
  munit_assert_size(length, ==, 18);
  munit_assert_memory_equal(length, output, "abcabcabcabcabcabc");
  for (size_t i = 0; i < sizeof workspace; ++i)
    munit_assert_uint(((uint8_t*)&workspace)[i], ==, 0);
  member[17] ^= 1;
  work = SIZE_MAX;
  length = SIZE_MAX;
  munit_assert_int(
      TC_GZIP_decode(member, sizeof member, output, sizeof output, &workspace, &work, &length), ==,
      TC_GZIP_INVALID);
  munit_assert_size(length, ==, SIZE_MAX);
  munit_assert_memory_equal(sizeof output, output, zeros);
  member[17] ^= 1;
  work = 0;
  memset(output, 0x5a, sizeof output);
  munit_assert_int(
      TC_GZIP_decode(member, sizeof member, output, sizeof output, &workspace, &work, &length), ==,
      TC_GZIP_LIMIT);
  munit_assert_memory_equal(sizeof output, output, zeros);
  uint8_t saved[sizeof member];
  memcpy(saved, member, sizeof member);
  work = SIZE_MAX;
  munit_assert_int(
      TC_GZIP_decode(member, sizeof member, member, sizeof member, &workspace, &work, &length), ==,
      TC_GZIP_ARGUMENT);
  munit_assert_memory_equal(sizeof saved, member, saved);
  munit_assert_size(work, ==, SIZE_MAX);
  munit_assert_int(
      TC_GZIP_decode(member, sizeof member, output, sizeof output, &workspace, &work, &work), ==,
      TC_GZIP_ARGUMENT);
  munit_assert_size(work, ==, SIZE_MAX);
  munit_assert_int(
      TC_GZIP_decode(member, sizeof member, output, sizeof output, NULL, &work, &length), ==,
      TC_GZIP_ARGUMENT);
  munit_assert_int(TC_GZIP_decode(member, sizeof member, NULL, 1, &workspace, &work, &length), ==,
                   TC_GZIP_ARGUMENT);
  munit_assert_size(work, ==, SIZE_MAX);
  /* RFC 1952 section 2.3.1: CM 8 is deflate, other methods are unsupported. */
  member[2] = 7;
  length = SIZE_MAX;
  memset(output, 0x5a, sizeof output);
  munit_assert_int(
      TC_GZIP_decode(member, sizeof member, output, sizeof output, &workspace, &work, &length), ==,
      TC_GZIP_UNSUPPORTED);
  munit_assert_size(length, ==, SIZE_MAX);
  munit_assert_memory_equal(sizeof output, output, zeros);
  (void)params;
  (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/result-order", result_order, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/decode", decode, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/gzip", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
