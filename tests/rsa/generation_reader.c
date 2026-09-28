/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Wycheproof deterministic PKCS#1 v1.5 signatures through raw RSA. */
#include <tiny_crypto/rsa.h>
#include "munit.h"
#include "test_util.h"
#include "hash_name.h"
#include <stdio.h>
#include <string.h>

enum { MAX_BYTES = 384, MAX_LINE = 8192 };
static const char* path;

static TC_status random_two(void* context, uint8_t* output, size_t length)
{
  (void)context;
  memset(output, 0, length);
  output[length - 1] = 2;
  return TC_OK;
}

static MunitResult vectors(const MunitParameter params[], void* data)
{
  char line[MAX_LINE];
  uint8_t modulus[MAX_BYTES], exponent[MAX_BYTES], private_exponent[MAX_BYTES];
  uint8_t digest[64], salt[64], encoded[MAX_BYTES], signature[MAX_BYTES], expected[MAX_BYTES];
  TC_RSA_word words[TC_RSA_RAW_PRIVATE_WORKSPACE_WORDS(3072)];
  const TC_RSA_workspace workspace = {words, sizeof words / sizeof words[0]};
  size_t count = 0;
  FILE* file;
  (void)params;
  (void)data;
  if (!path)
    return MUNIT_SKIP;
  file = fopen(path, "r");
  munit_assert_not_null(file);
  while (fgets(line, sizeof line, file)) {
    char* fields[9];
    char* token = strtok(line, " \t\r\n");
    size_t columns = 0;
    while (token) {
      munit_assert_size(columns, <, sizeof fields / sizeof fields[0]);
      fields[columns++] = token;
      token = strtok(NULL, " \t\r\n");
    }
    munit_assert_true(columns == 8 || columns == 9);
    const size_t n = tc_test_decode_hex(fields[0], modulus, sizeof modulus);
    size_t e = tc_test_decode_hex(fields[1], exponent, sizeof exponent);
    const size_t d = tc_test_decode_hex(fields[2], private_exponent, sizeof private_exponent);
    const size_t h = tc_test_decode_hex(fields[4], digest, sizeof digest);
    const size_t s = tc_test_decode_hex(fields[5], expected, sizeof expected);
    munit_assert_size(n * 2, ==, strlen(fields[0]));
    munit_assert_size(e * 2, ==, strlen(fields[1]));
    munit_assert_size(d * 2, ==, strlen(fields[2]));
    munit_assert_size(h * 2, ==, strlen(fields[4]));
    munit_assert_size(s * 2, ==, strlen(fields[5]));
    munit_assert_size(n, ==, s);
    munit_assert_string_equal(fields[6], "match");
    /* CAVP pads e to modulus width; the public API takes its magnitude. */
    size_t leading = 0;
    while (leading < e && exponent[leading] == 0)
      ++leading;
    munit_assert_size(leading, <, e);
    e -= leading;
    const TC_RSA_public_key key = {{modulus, n}, {exponent + leading, e}};
    const TC_hash_algorithm hash = hash_algorithm(fields[3]);
    const TC_RSA_v15_options options = {hash};
    TC_work_budget encode_work = {MAX_BYTES};
    TC_RSA_execution execution = {{random_two, NULL}, 8, {UINT32_MAX}};
    TC_RSA_result result;
    if (columns == 9) {
      size_t salt_length = tc_test_decode_hex(fields[8], salt, sizeof salt);
      munit_assert_size(salt_length * 2, ==, strlen(fields[8]));
      const TC_RSA_pss_options pss = {hash, hash, salt_length};
      encode_work.remaining = UINT32_MAX;
      result = TC_RSA_encode_pss_digest(&pss, (TC_bytes){digest, h}, (TC_bytes){salt, salt_length},
                                        (TC_buffer){encoded, n}, &encode_work);
    } else {
      result = TC_RSA_encode_v15_digest(&options, (TC_bytes){digest, h}, (TC_buffer){encoded, n},
                                        &encode_work);
    }
    if (result != TC_RSA_OK)
      munit_errorf("RSA generation vector %s: encoding status %d", fields[7], result);
    result = TC_RSA_raw_private(&key, (TC_bytes){private_exponent, d}, (TC_bytes){encoded, n},
                                &workspace, (TC_buffer){signature, n}, &execution);
    if (result != TC_RSA_OK)
      munit_errorf("RSA generation vector %s: raw operation status %d", fields[7], result);
    if (memcmp(signature, expected, n))
      munit_errorf("RSA generation vector %s: signature mismatch", fields[7]);
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
  MunitSuite suite = {"/rsa-generation", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  if (argc == 3 && !strcmp(argv[1], "--generation-vectors")) {
    path = argv[2];
    argc = 1;
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
