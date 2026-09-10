/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/aes.h>
#include "munit.h"
#include "test_util.h"
#include <stdio.h>
#include <string.h>

typedef TC_status (*encrypt_fn)(const uint8_t*, const uint8_t*, size_t,
    const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, uint8_t*, size_t);
typedef TC_status (*decrypt_fn)(const uint8_t*, const uint8_t*, size_t,
    const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*);
static const char* vector_path;
static size_t siv_ad_count;

static TC_status siv_encrypt(const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
    const uint8_t* aad, size_t aad_len, const uint8_t* input, size_t input_len,
    uint8_t* output, uint8_t* tag, size_t tag_len)
{
  const uint8_t* ad[] = {aad, nonce};
  const size_t lengths[] = {aad_len, nonce_len};
  if (tag_len != 16) return TC_ERROR;
  return TC_AES_SIV_encrypt(key, ad, lengths, siv_ad_count, input, input_len, tag, output);
}

static TC_status siv_decrypt(const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
    const uint8_t* aad, size_t aad_len, const uint8_t* input, size_t input_len,
    const uint8_t* tag, size_t tag_len, uint8_t* output)
{
  const uint8_t* ad[] = {aad, nonce};
  const size_t lengths[] = {aad_len, nonce_len};
  if (tag_len != 16) return TC_ERROR;
  return TC_AES_SIV_decrypt(key, ad, lengths, siv_ad_count, tag, input, input_len, output);
}

static size_t decode(const char* text, uint8_t* output)
{
  size_t length;
  if (strcmp(text, "-") == 0) return 0;
  length = tc_test_decode_hex(text, output, 1024);
  munit_assert_size(strlen(text) % 2, ==, 0);
  munit_assert_size(length, ==, strlen(text) / 2);
  return length;
}

static MunitResult vectors(const MunitParameter params[], void* user)
{
  FILE* file;
  char mode[16], verdict[16], hex[6][2049];
  uint8_t value[6][1024], output[1024], generated[16], expected[1024];
  size_t length[6], i;
  unsigned id, count = 0;
  int fields;
  (void)params; (void)user;
  if (!vector_path) return MUNIT_SKIP;
  file = fopen(vector_path, "r");
  munit_assert_not_null(file);
  memset(expected, 0xa5, sizeof expected);
  while ((fields = fscanf(file, "%15s %u %15s %2048s %2048s %2048s %2048s %2048s %2048s",
      mode, &id, verdict, hex[0], hex[1], hex[2], hex[3], hex[4], hex[5])) == 9) {
    encrypt_fn encrypt = TC_AES_GCM_encrypt;
    decrypt_fn decrypt = TC_AES_GCM_decrypt;
    TC_status status;
    int valid = strcmp(verdict, "valid") == 0;
    int siv = strcmp(mode, "siv") == 0 || strcmp(mode, "siv-aead") == 0;
    if (strcmp(mode, "ccm") == 0) {
      encrypt = TC_AES_CCM_encrypt; decrypt = TC_AES_CCM_decrypt;
    } else if (strcmp(mode, "eax") == 0) {
      encrypt = TC_AES_EAX_encrypt; decrypt = TC_AES_EAX_decrypt;
    } else if (siv) {
      encrypt = siv_encrypt; decrypt = siv_decrypt;
      siv_ad_count = strcmp(mode, "siv-aead") == 0 ? 2 : 1;
    } else munit_assert_string_equal(mode, "gcm");
    munit_assert_true(valid || strcmp(verdict, "invalid") == 0);
    for (i = 0; i < 6; ++i) length[i] = decode(hex[i], value[i]);
    munit_assert_size(length[0], ==, siv ? TC_AES_SIV_KEYLEN : TC_AES_KEYLEN);
    munit_assert_size(length[5], <=, sizeof generated);
    memcpy(output, expected, sizeof output);
    status = decrypt(value[0], value[1], length[1], value[2], length[2],
                     value[4], length[4], value[5], length[5], output);
    if (valid) {
      if (status != TC_OK) munit_errorf("AEAD case %u: valid decrypt rejected (%d)", id, status);
      munit_assert_size(length[3], ==, length[4]);
      munit_assert_memory_equal(length[3], output, value[3]);
      munit_assert_memory_equal(sizeof output - length[3], output + length[3], expected + length[3]);
      munit_assert_int(encrypt(value[0], value[1], length[1], value[2], length[2],
                               value[3], length[3], output, generated, length[5]), ==, TC_OK);
      munit_assert_memory_equal(length[4], output, value[4]);
      munit_assert_memory_equal(length[5], generated, value[5]);
    } else {
      if (status != TC_ERROR && status != TC_MISMATCH)
        munit_errorf("AEAD case %u: invalid decrypt accepted", id);
      if (siv && status == TC_MISMATCH) {
        munit_assert_true(tc_test_all_zero(output, length[4]));
        munit_assert_memory_equal(sizeof output - length[4], output + length[4], expected + length[4]);
      } else munit_assert_memory_equal(sizeof output, output, expected);
    }
    memcpy(output, expected, sizeof output);
    memcpy(output, value[4], length[4]);
    status = decrypt(value[0], value[1], length[1], value[2], length[2],
                     output, length[4], value[5], length[5], output);
    if (valid) {
      munit_assert_int(status, ==, TC_OK);
      munit_assert_memory_equal(length[3], output, value[3]);
    } else if (status == TC_MISMATCH) {
      if (strcmp(mode, "eax") == 0)
        munit_assert_memory_equal(length[4], output, value[4]);
      else
        munit_assert_true(tc_test_all_zero(output, length[4]));
    } else {
      munit_assert_int(status, ==, TC_ERROR);
      munit_assert_memory_equal(length[4], output, value[4]);
    }
    munit_assert_memory_equal(sizeof output - length[4], output + length[4], expected + length[4]);
    ++count;
  }
  munit_assert_int(fields, ==, EOF);
  munit_assert_false(ferror(file));
  fclose(file);
  munit_assert_uint(count, >, 0);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/vectors", vectors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
static const MunitSuite suite = {"/aead", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  if (argc == 3 && strcmp(argv[1], "--vectors") == 0) {
    char* args[] = {argv[0], (char*)"/aead/vectors"};
    vector_path = argv[2];
    return munit_suite_main(&suite, NULL, 2, args);
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
