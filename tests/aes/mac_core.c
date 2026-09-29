/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/mac_core_internal.h"
#include "munit.h"
#include "test_util.h"
#include <string.h>

static TC_status increment_block(const void* cipher, uint8_t* block)
{
  const size_t width = *(const size_t*)cipher;
  for (size_t i = 0; i < width; ++i)
    ++block[i];
  return TC_OK;
}

TC_TEST(block_boundaries)
{
  const size_t width = 8;
  const tc_block_cipher cipher = {8, &width, increment_block, NULL};
  const uint8_t input[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
  const uint8_t k1[8] = {1, 1, 1, 1, 1, 1, 1, 1};
  const uint8_t k2[8] = {2, 2, 2, 2, 2, 2, 2, 2};
  const uint8_t empty_tag[8] = {0x83, 3, 3, 3, 3, 3, 3, 3};
  const uint8_t complete_tag[8] = {1, 4, 3, 6, 5, 8, 7, 10};
  const uint8_t first_mac[8] = {2, 3, 4, 5, 6, 7, 8, 9};
  const uint8_t partial_tag[8] = {10, 130, 7, 8, 5, 6, 11, 12};
  uint8_t mac[8] = {0}, block[8] = {0}, tag[8];
  uint8_t used = 0;

  munit_assert_int(tc_mac_cmac_final(&cipher, mac, block, used, k1, k2, tag), ==, TC_OK);
  munit_assert_memory_equal(8, tag, empty_tag);

  memset(mac, 0, 8);
  memset(block, 0, 8);
  used = 0;
  munit_assert_int(tc_mac_cbc_update(&cipher, mac, block, &used, input, 8, 1), ==, TC_OK);
  munit_assert_uint8(used, ==, 8);
  munit_assert_memory_equal(8, mac, (const uint8_t[8]){0});
  munit_assert_int(tc_mac_cmac_final(&cipher, mac, block, used, k1, k2, tag), ==, TC_OK);
  munit_assert_memory_equal(8, tag, complete_tag);

  memset(mac, 0, 8);
  memset(block, 0, 8);
  used = 0;
  munit_assert_int(tc_mac_cbc_update(&cipher, mac, block, &used, input, 5, 1), ==, TC_OK);
  munit_assert_int(tc_mac_cbc_update(&cipher, mac, block, &used, input + 5, 4, 1), ==, TC_OK);
  munit_assert_uint8(used, ==, 1);
  munit_assert_memory_equal(8, mac, first_mac);
  munit_assert_int(tc_mac_cmac_final(&cipher, mac, block, used, k1, k2, tag), ==, TC_OK);
  munit_assert_memory_equal(8, tag, partial_tag);
  return MUNIT_OK;
}

TC_TEST(eager_padding)
{
  const size_t width = 8;
  const tc_block_cipher cipher = {8, &width, increment_block, NULL};
  const uint8_t input[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
  const uint8_t first_mac[8] = {2, 3, 4, 5, 6, 7, 8, 9};
  const uint8_t padded_mac[8] = {12, 4, 5, 6, 7, 8, 9, 10};
  uint8_t mac[8] = {0}, block[8] = {0};
  uint8_t used = 0;
  munit_assert_int(tc_mac_cbc_update(&cipher, mac, block, &used, input, 9, 0), ==, TC_OK);
  munit_assert_uint8(used, ==, 1);
  munit_assert_memory_equal(8, mac, first_mac);
  munit_assert_int(tc_mac_cbc_pad(&cipher, mac, block, &used), ==, TC_OK);
  munit_assert_uint8(used, ==, 0);
  munit_assert_memory_equal(8, mac, padded_mac);

  memset(mac, 0, 8);
  memset(block, 0, 8);
  used = 0;
  munit_assert_int(tc_mac_cbc_update(&cipher, mac, block, &used, input, 8, 0), ==, TC_OK);
  munit_assert_uint8(used, ==, 0);
  munit_assert_memory_equal(8, mac, first_mac);
  return MUNIT_OK;
}

TC_TEST(gf_doubling)
{
  const uint8_t input[16] = {0x80};
  const uint8_t expected_des[8] = {0, 0, 0, 0, 0, 0, 0, 0x1b};
  const uint8_t expected_aes[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87};
  uint8_t block[16];
  tc_mac_gf_double(block, input, 8, 0x1b);
  munit_assert_memory_equal(8, block, expected_des);
  memcpy(block, input, sizeof block);
  tc_mac_gf_double(block, block, sizeof block, 0x87);
  munit_assert_memory_equal(16, block, expected_aes);
  return MUNIT_OK;
}

/* CMAC over parts equals streaming the concatenation, for every split and
 * for a nonzero initial chaining value. */
TC_TEST(cmac_parts)
{
  const size_t width = 8;
  const tc_block_cipher cipher = {8, &width, increment_block, NULL};
  const uint8_t input[19] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19};
  const uint8_t k1[8] = {1, 1, 1, 1, 1, 1, 1, 1};
  const uint8_t k2[8] = {2, 2, 2, 2, 2, 2, 2, 2};
  const uint8_t initial[8] = {9, 8, 7, 6, 5, 4, 3, 2};
  for (size_t length = 0; length <= sizeof input; ++length)
    for (size_t split = 0; split <= length; ++split) {
      uint8_t mac[8], block[8] = {0}, expected[8], tag[8];
      uint8_t used = 0;
      memcpy(mac, initial, sizeof mac);
      munit_assert_int(tc_mac_cbc_update(&cipher, mac, block, &used, input, length, 1), ==, TC_OK);
      munit_assert_int(tc_mac_cmac_final(&cipher, mac, block, used, k1, k2, expected), ==, TC_OK);
      const TC_bytes parts[] = {{input, split}, {input + split, length - split}};
      munit_assert_int(tc_mac_cmac_parts(&cipher, initial, parts, 2, k1, k2, tag), ==, TC_OK);
      munit_assert_memory_equal(sizeof tag, tag, expected);
    }
  return MUNIT_OK;
}

/* SP 800-38B subkeys K1 = dbl(L), K2 = dbl(K1) with L = E(0). The reversed
 * form doubles toward higher byte indexes and reduces into byte zero. */
TC_TEST(subkeys)
{
  const size_t width = 8;
  const tc_block_cipher cipher = {8, &width, increment_block, NULL};
  /* The test cipher adds one to each byte, so L = 01..01. */
  const uint8_t k1[8] = {2, 2, 2, 2, 2, 2, 2, 2}, k2[8] = {4, 4, 4, 4, 4, 4, 4, 4};
  const uint8_t high[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80};
  uint8_t out1[16], out2[16];
  munit_assert_int(tc_mac_derive_subkeys(&cipher, 0x1b, 0, out1, out2), ==, TC_OK);
  munit_assert_memory_equal(8, out1, k1);
  munit_assert_memory_equal(8, out2, k2);
  munit_assert_int(tc_mac_derive_subkeys(&cipher, 0x1b, 1, out1, out2), ==, TC_OK);
  munit_assert_memory_equal(8, out1, k1);
  /* Reversed doubling of a high bit in the last byte carries into byte 0. */
  tc_mac_gf_double_reversed(out1, high, sizeof high, 0x87);
  munit_assert_uint8(out1[0], ==, 0x87);
  munit_assert_uint8(out1[15], ==, 0);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/cmac-parts", cmac_parts, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/subkeys", subkeys, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/boundaries", block_boundaries, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/eager-padding", eager_padding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/gf-doubling", gf_doubling, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/mac-core", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
