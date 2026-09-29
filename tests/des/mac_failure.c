/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* DES CMAC and ISO/IEC 9797-1 failure paths. The DES block cipher cannot
 * fail, so the library under test is built with TC_TEST_DES_FAULT and this
 * file supplies a forward cipher that fails at a chosen call. Each failure
 * must return TC_ERROR, wipe the context and leave the tag untouched, as
 * tiny_crypto/des.h documents. */
#include "des_internal.h"
#include "munit.h"
#include "test_util.h"
#include <string.h>

static unsigned calls, fail_at;

TC_status tc_test_des_block_encrypt(const void* key, uint8_t* block)
{
  ++calls;
  if (calls == fail_at) {
    memset(block, 0xa5, TC_DES_BLOCKLEN); /* A failed device may modify scratch. */
    return TC_ERROR;
  }
  return tc_des_block_encrypt(key, block);
}

static const uint8_t key[TC_DES_KEYLEN_3KEY] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                                0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
                                                0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23};

static TC_status cmac_stream(size_t keylen, const uint8_t* data, size_t length, uint8_t* tag,
                             struct TC_DES_CMAC_ctx* ctx)
{
  TC_status status = TC_DES_CMAC_init(ctx, key, keylen);
  if (status == TC_OK)
    status = TC_DES_CMAC_update(ctx, data, length);
  if (status == TC_OK)
    status = TC_DES_CMAC_final(ctx, tag);
  return status;
}

TC_TEST(cmac_failures)
{
  static const size_t keylens[] = {TC_DES_KEYLEN, TC_DES_KEYLEN_2KEY, TC_DES_KEYLEN_3KEY};
  static const size_t lengths[] = {0, 8, 17};
  uint8_t data[17], tag[TC_DES_CMAC_TAG_MAX], untouched[TC_DES_CMAC_TAG_MAX];
  tc_test_fill_incrementing(data, sizeof data);
  memset(untouched, 0x5a, sizeof untouched);
  for (size_t k = 0; k < sizeof keylens / sizeof *keylens; ++k) {
    for (size_t m = 0; m < sizeof lengths / sizeof *lengths; ++m) {
      struct TC_DES_CMAC_ctx ctx;
      uint8_t expected[TC_DES_CMAC_TAG_MAX];
      unsigned total;
      calls = 0;
      fail_at = 0;
      munit_assert_int(cmac_stream(keylens[k], data, lengths[m], expected, &ctx), ==, TC_OK);
      total = calls;
      /* Subkey derivation, one call per block and the final block. */
      munit_assert_uint(total, >=, 2);
      for (fail_at = 1; fail_at <= total; ++fail_at) {
        calls = 0;
        memcpy(tag, untouched, sizeof tag);
        munit_assert_int(cmac_stream(keylens[k], data, lengths[m], tag, &ctx), ==, TC_ERROR);
        munit_assert_true(tc_test_all_zero(&ctx, sizeof ctx));
        munit_assert_memory_equal(sizeof tag, tag, untouched);
        munit_assert_int(TC_DES_CMAC_update(&ctx, data, 1), ==, TC_ERROR);
        munit_assert_int(TC_DES_CMAC_final(&ctx, tag), ==, TC_ERROR);
        munit_assert_memory_equal(sizeof tag, tag, untouched);

        calls = 0;
        munit_assert_int(TC_DES_CMAC(key, keylens[k], data, lengths[m], tag, sizeof tag), ==,
                         TC_ERROR);
        munit_assert_memory_equal(sizeof tag, tag, untouched);
        calls = 0;
        munit_assert_int(
            TC_DES_CMAC_verify(key, keylens[k], data, lengths[m], expected, sizeof expected), ==,
            TC_ERROR);
      }
      fail_at = 0;
      calls = 0;
      munit_assert_int(
          TC_DES_CMAC_verify(key, keylens[k], data, lengths[m], expected, sizeof expected), ==,
          TC_OK);
    }
  }
  return MUNIT_OK;
}

static TC_status iso9797_stream(TC_DES_ISO9797_algorithm algorithm, TC_DES_ISO9797_padding padding,
                                size_t keylen, const uint8_t* data, size_t length, uint8_t* tag,
                                struct TC_DES_ISO9797_ctx* ctx)
{
  TC_status status = TC_DES_ISO9797_init(ctx, algorithm, padding, key, keylen);
  if (status == TC_OK)
    status = TC_DES_ISO9797_update(ctx, data, length);
  if (status == TC_OK)
    status = TC_DES_ISO9797_final(ctx, tag);
  return status;
}

TC_TEST(iso9797_failures)
{
  static const TC_DES_ISO9797_algorithm algorithms[] = {TC_DES_ISO9797_ALG1, TC_DES_ISO9797_ALG3};
  static const struct {
    TC_DES_ISO9797_padding padding;
    size_t length;
  } messages[] = {{TC_DES_ISO9797_PAD_NONE, 16}, {TC_DES_ISO9797_PAD1, 0},
                  {TC_DES_ISO9797_PAD1, 13},     {TC_DES_ISO9797_PAD1, 16},
                  {TC_DES_ISO9797_PAD2, 0},      {TC_DES_ISO9797_PAD2, 16}};
  static const size_t keylens[] = {TC_DES_KEYLEN_2KEY, TC_DES_KEYLEN_3KEY};
  uint8_t data[16], tag[TC_DES_BLOCKLEN], untouched[TC_DES_BLOCKLEN];
  tc_test_fill_incrementing(data, sizeof data);
  memset(untouched, 0x5a, sizeof untouched);
  for (size_t a = 0; a < sizeof algorithms / sizeof *algorithms; ++a) {
    for (size_t k = 0; k < sizeof keylens / sizeof *keylens; ++k) {
      for (size_t m = 0; m < sizeof messages / sizeof *messages; ++m) {
        const TC_DES_ISO9797_padding padding = messages[m].padding;
        const size_t length = messages[m].length;
        struct TC_DES_ISO9797_ctx ctx;
        uint8_t expected[TC_DES_BLOCKLEN];
        unsigned total;
        calls = 0;
        fail_at = 0;
        munit_assert_int(
            iso9797_stream(algorithms[a], padding, keylens[k], data, length, expected, &ctx), ==,
            TC_OK);
        total = calls;
        /* One CBC call per block, including the padding block. */
        munit_assert_uint(total, ==,
                          (length + (padding == TC_DES_ISO9797_PAD2 ? 8 : 7)) / 8 +
                              (padding == TC_DES_ISO9797_PAD1 && !length));
        for (fail_at = 1; fail_at <= total; ++fail_at) {
          calls = 0;
          memcpy(tag, untouched, sizeof tag);
          munit_assert_int(
              iso9797_stream(algorithms[a], padding, keylens[k], data, length, tag, &ctx), ==,
              TC_ERROR);
          munit_assert_true(tc_test_all_zero(&ctx, sizeof ctx));
          munit_assert_memory_equal(sizeof tag, tag, untouched);
          munit_assert_int(TC_DES_ISO9797_update(&ctx, data, 1), ==, TC_ERROR);
          munit_assert_int(TC_DES_ISO9797_final(&ctx, tag), ==, TC_ERROR);
          munit_assert_memory_equal(sizeof tag, tag, untouched);

          calls = 0;
          munit_assert_int(TC_DES_ISO9797_MAC(algorithms[a], padding, key, keylens[k], data, length,
                                              tag, sizeof tag),
                           ==, TC_ERROR);
          munit_assert_memory_equal(sizeof tag, tag, untouched);
          calls = 0;
          munit_assert_int(TC_DES_ISO9797_verify(algorithms[a], padding, key, keylens[k], data,
                                                 length, expected, sizeof expected),
                           ==, TC_ERROR);
        }
        fail_at = 0;
        calls = 0;
        munit_assert_int(TC_DES_ISO9797_verify(algorithms[a], padding, key, keylens[k], data,
                                               length, expected, sizeof expected),
                         ==, TC_OK);
      }
    }
  }
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/cmac", cmac_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/iso9797", iso9797_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite suite = {"/des/mac-failure", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
