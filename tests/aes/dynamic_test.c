/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/aes_dynamic.h>
#include "munit.h"
#include "test_util.h"
#include "mac_vectors.h"
#include <string.h>

static MunitResult block_vectors(const MunitParameter params[], void* user)
{
  static const char* answers[] = {
    "69c4e0d86a7b0430d8cdb78070b4c55a", "dda97ca4864cdfe06eaf70a0ec0d7191",
    "8ea2b7ca516745bfeafc49904b496089"
  };
  uint8_t key[32], plain[16], block[16], expected[16];
  TC_AES_dynamic_key ctx;
  size_t i;
  (void)params; (void)user;
  tc_test_fill_incrementing(key, sizeof key);
  munit_assert_size(tc_test_decode_hex("00112233445566778899aabbccddeeff", plain, 16), ==, 16);
  for (i = 0; i < 3; ++i) {
    munit_assert_size(tc_test_decode_hex(answers[i], expected, 16), ==, 16);
    memcpy(block, plain, 16);
    munit_assert_int(TC_AES_dynamic_key_init(&ctx, key, 16 + 8 * i), ==, TC_OK);
    munit_assert_int(TC_AES_dynamic_encrypt(&ctx, block), ==, TC_OK);
    munit_assert_memory_equal(16, block, expected);
    munit_assert_int(TC_AES_dynamic_decrypt(&ctx, block), ==, TC_OK);
    munit_assert_memory_equal(16, block, plain);
  }
  TC_AES_dynamic_key_clear(&ctx);
  munit_assert_true(tc_test_all_zero(&ctx, sizeof ctx));
  munit_assert_int(TC_AES_dynamic_encrypt(&ctx, block), ==, TC_ERROR);
  return MUNIT_OK;
}

static MunitResult cbc_and_cmac_vectors(const MunitParameter params[], void* user)
{
  static const char* keys[] = {
    "2b7e151628aed2a6abf7158809cf4f3c",
    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
  };
  static const char* cbc[] = {
    "7649abac8119b246cee98e9b12e9197d", "4f021db243bc633d7178183a9fa071e8",
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
  };
  static const char* tags[] = {
    "070a16b46b4d4144f79bdd9dd04a287c", "9e99a7bf31e710900662f65e617c5184",
    "28a7023f452e8f82bd4bf28d8c37c35c"
  };
  uint8_t key[32], plain[16], block[16], expected[16], iv[16], tag[16];
  TC_AES_dynamic_key ctx;
  TC_AES_dynamic_CMAC mac;
  size_t i, split, length;
  (void)params; (void)user;
  munit_assert_size(tc_test_decode_hex("6bc1bee22e409f96e93d7e117393172a", plain, 16), ==, 16);
  for (i = 0; i < 3; ++i) {
    length = tc_test_decode_hex(keys[i], key, sizeof key);
    munit_assert_size(length, ==, 16 + 8 * i);
    munit_assert_size(tc_test_decode_hex(cbc[i], expected, 16), ==, 16);
    munit_assert_int(TC_AES_dynamic_key_init(&ctx, key, length), ==, TC_OK);
    tc_test_fill_incrementing(iv, sizeof iv); memcpy(block, plain, 16);
    munit_assert_int(TC_AES_dynamic_CBC_encrypt(&ctx, iv, block, 16), ==, TC_OK);
    munit_assert_memory_equal(16, block, expected);
    munit_assert_memory_equal(16, iv, expected);
    tc_test_fill_incrementing(iv, sizeof iv);
    munit_assert_int(TC_AES_dynamic_CBC_decrypt(&ctx, iv, block, 16), ==, TC_OK);
    munit_assert_memory_equal(16, block, plain);
    munit_assert_memory_equal(16, iv, expected);
    munit_assert_size(tc_test_decode_hex(tags[i], expected, 16), ==, 16);
    for (split = 0; split <= 16; ++split) {
      munit_assert_int(TC_AES_dynamic_CMAC_init(&mac, key, length), ==, TC_OK);
      munit_assert_int(TC_AES_dynamic_CMAC_update(&mac, plain, split), ==, TC_OK);
      munit_assert_int(TC_AES_dynamic_CMAC_update(&mac, plain + split, 16 - split), ==, TC_OK);
      munit_assert_int(TC_AES_dynamic_CMAC_final(&mac, tag), ==, TC_OK);
      munit_assert_memory_equal(16, tag, expected);
      munit_assert_true(tc_test_all_zero(&mac, sizeof mac));
      munit_assert_int(TC_AES_dynamic_CMAC_final(&mac, tag), ==, TC_ERROR);
    }
  }
  return MUNIT_OK;
}

static MunitResult invalid_arguments(const MunitParameter params[], void* user)
{
  TC_AES_dynamic_key key, saved;
  TC_AES_dynamic_CMAC mac, saved_mac;
  uint8_t raw[32] = {0}, block[32] = {0}, iv[16] = {0};
  size_t i;
  (void)params; (void)user;
  memset(&key, 0xa5, sizeof key); saved = key;
  for (i = 0; i <= 33; ++i) {
    if (i == 16 || i == 24 || i == 32) continue;
    munit_assert_int(TC_AES_dynamic_key_init(&key, raw, i), ==, TC_ERROR);
    munit_assert_memory_equal(sizeof key, &key, &saved);
  }
  munit_assert_int(TC_AES_dynamic_key_init(&key, key.round_key, 16), ==, TC_ERROR);
  munit_assert_int(TC_AES_dynamic_key_init(&key, NULL, 16), ==, TC_ERROR);
  munit_assert_int(TC_AES_dynamic_key_init(&key, raw, 16), ==, TC_OK);
  saved = key;
  munit_assert_int(TC_AES_dynamic_encrypt(&key, key.round_key), ==, TC_ERROR);
  munit_assert_int(TC_AES_dynamic_CBC_encrypt(&key, iv, block, 15), ==, TC_ERROR);
  munit_assert_int(TC_AES_dynamic_CBC_encrypt(&key, iv, iv, 16), ==, TC_ERROR);
  munit_assert_int(TC_AES_dynamic_CBC_decrypt(&key, key.round_key, block, 16), ==, TC_ERROR);
  munit_assert_int(TC_AES_dynamic_CBC_encrypt(&key, iv, NULL, 0), ==, TC_OK);
  munit_assert_memory_equal(sizeof key, &key, &saved);
  munit_assert_true(tc_test_all_zero(iv, sizeof iv));
  munit_assert_true(tc_test_all_zero(block, sizeof block));
  munit_assert_int(TC_AES_dynamic_CMAC_init(&mac, raw, 16), ==, TC_OK);
  saved_mac = mac;
  munit_assert_int(TC_AES_dynamic_CMAC_update(&mac, NULL, 1), ==, TC_ERROR);
  munit_assert_int(TC_AES_dynamic_CMAC_update(&mac, mac.buffer, 1), ==, TC_ERROR);
  munit_assert_int(TC_AES_dynamic_CMAC_final(&mac, mac.buffer), ==, TC_ERROR);
  munit_assert_memory_equal(sizeof mac, &mac, &saved_mac);
  return MUNIT_OK;
}

static const char* vector_path;
static TC_status vector_cmac(const uint8_t* key, size_t key_length,
                              const uint8_t* message, size_t message_length,
                              uint8_t* output, size_t tag_length)
{
  TC_AES_dynamic_CMAC ctx;
  TC_status status = TC_AES_dynamic_CMAC_init(&ctx, key, key_length);
  if (status != TC_OK) return status;
  if (tag_length != 16) {
    TC_AES_dynamic_CMAC_clear(&ctx);
    return TC_ERROR;
  }
  status = TC_AES_dynamic_CMAC_update(&ctx, message, message_length);
  if (status == TC_OK) status = TC_AES_dynamic_CMAC_final(&ctx, output);
  TC_AES_dynamic_CMAC_clear(&ctx);
  return status;
}
static MunitResult wycheproof(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  return tc_test_mac_vectors(vector_path, vector_cmac);
}

static MunitTest tests[] = {
  {"/wycheproof", wycheproof, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/block-vectors", block_vectors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/cbc-cmac-vectors", cbc_and_cmac_vectors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/invalid-arguments", invalid_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
static const MunitSuite suite = {"/dynamic-aes", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  if (argc == 3 && strcmp(argv[1], "--vectors") == 0) {
    char* args[] = {argv[0], (char*)"/dynamic-aes/wycheproof"};
    vector_path = argv[2];
    return munit_suite_main(&suite, NULL, 2, args);
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
