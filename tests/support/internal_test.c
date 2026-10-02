/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Shared byte-order, counter and span helpers from src/internal.h. */
#include "../../src/internal.h"
#include "munit.h"
#include "test_util.h"

TC_TEST(byte_order)
{
  static const uint8_t bytes[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
  uint8_t out[8];
  munit_assert_uint32(tc_internal_load_be32(bytes), ==, 0x01234567u);
  munit_assert_uint32(tc_internal_load_be32(bytes + 4), ==, 0x89abcdefu);
  tc_internal_store_be32(out, 0x89abcdefu);
  munit_assert_memory_equal(4, out, bytes + 4);
  munit_assert_uint64(tc_internal_load_be64(bytes), ==, UINT64_C(0x0123456789abcdef));
  tc_internal_store_be64(out, UINT64_C(0x0123456789abcdef));
  munit_assert_memory_equal(8, out, bytes);
  return MUNIT_OK;
}

TC_TEST(counters)
{
  uint8_t counter[4] = {0, 0, 0xff, 0xff};
  munit_assert_uint8(tc_internal_increment_be(counter, 4), ==, 0);
  munit_assert_uint8(counter[1], ==, 1);
  munit_assert_uint8(counter[3], ==, 0);
  counter[0] = counter[1] = counter[2] = counter[3] = 0xff;
  munit_assert_uint8(tc_internal_increment_be(counter, 4), ==, 1);
  munit_assert_true(!counter[0] && !counter[1] && !counter[2] && !counter[3]);
  /* A counter with n blocks left serves exactly n. */
  counter[3] = 0xfd;
  counter[0] = counter[1] = counter[2] = 0xff;
  munit_assert_true(tc_internal_counter_has_blocks(counter, 4, 3, 0));
  munit_assert_false(tc_internal_counter_has_blocks(counter, 4, 4, 0));
  /* A fresh zero counter has the whole 2^(8*length) space. An exhausted one has none. */
  counter[0] = counter[1] = counter[2] = counter[3] = 0;
#if SIZE_MAX > UINT32_MAX
  munit_assert_true(tc_internal_counter_has_blocks(counter, 4, (size_t)1 << 32, 0));
  munit_assert_false(tc_internal_counter_has_blocks(counter, 4, ((size_t)1 << 32) + 1, 0));
#else
  munit_assert_true(tc_internal_counter_has_blocks(counter, 4, SIZE_MAX, 0));
#endif
  munit_assert_true(tc_internal_counter_has_blocks(counter, 1, 256, 0));
  munit_assert_false(tc_internal_counter_has_blocks(counter, 1, 257, 0));
  {
    static const uint8_t zero_block[16] = {0};
    munit_assert_true(tc_internal_counter_has_blocks(zero_block, 16, SIZE_MAX, 0));
    munit_assert_true(tc_internal_counter_has_blocks(zero_block, 8, SIZE_MAX, 0));
  }
  munit_assert_false(tc_internal_counter_has_blocks(counter, 4, 1, 1));
  munit_assert_true(tc_internal_counter_has_blocks(counter, 4, 0, 1));
  return MUNIT_OK;
}

TC_TEST(spans)
{
  static const uint8_t byte = 0;
  munit_assert_true(tc_internal_span_valid(NULL, 0));
  munit_assert_true(tc_internal_span_valid(&byte, 0));
  munit_assert_true(tc_internal_span_valid(&byte, 1));
  munit_assert_false(tc_internal_span_valid(NULL, 1));
  return MUNIT_OK;
}

static MunitTest tests[] = {{"/byte-order", byte_order, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {"/counters", counters, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {"/spans", spans, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/internal", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
