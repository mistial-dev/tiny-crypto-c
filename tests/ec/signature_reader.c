/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/ec.h>
#include <tiny_crypto/der.h>
#include "munit.h"
#include "test_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* path;
static int der;
static MunitResult vectors(const MunitParameter params[], void* data)
{
  char line[32768];
  uint8_t key[256], digest[128], signature[8192];
  TC_ECDSA_workspace workspace;
  size_t count = 0;
  FILE* file;
  (void)params; (void)data;
  if (!path) return MUNIT_SKIP;
  file = fopen(path, "r");
  munit_assert_not_null(file);
  while (fgets(line, sizeof line, file)) {
    char* fields[6];
    size_t columns = 0;
    char* token = strtok(line, " \t\r\n");
    while (token) {
      munit_assert_size(columns, <, 6);
      fields[columns++] = token;
      token = strtok(NULL, " \t\r\n");
    }
    munit_assert_size(columns, ==, 6);
    unsigned bits = (unsigned)strtoul(fields[0], NULL, 10);
    munit_assert_true(bits == 192 || bits == 256 || bits == 384);
    TC_EC_curve curve = bits == 192 ? TC_EC_P192 : bits == 256 ? TC_EC_P256 : TC_EC_P384;
    size_t key_len = tc_test_decode_hex(fields[1], key, sizeof key);
    size_t digest_len = tc_test_decode_hex(fields[2], digest, sizeof digest);
    size_t signature_len = strcmp(fields[3], "-") ? tc_test_decode_hex(fields[3], signature, sizeof signature) : 0;
    munit_assert_size(key_len * 2, ==, strlen(fields[1]));
    munit_assert_size(digest_len * 2, ==, strlen(fields[2]));
    if (strcmp(fields[3], "-")) munit_assert_size(signature_len * 2, ==, strlen(fields[3]));
    munit_assert_true(!strcmp(fields[4], "valid") || !strcmp(fields[4], "invalid"));
    uint8_t raw[96];
    const uint8_t* signature_bytes = signature;
    TC_status result = TC_ERROR;
    int decoded = 1;
    if (der) {
      TC_DER_signature_pair pair;
      size_t width = bits / 8;
      decoded = TC_DER_ecdsa_signature(signature, signature_len, &pair) == TC_TLV_OK;
      if (decoded) decoded = pair.r.length <= width && pair.s.length <= width;
      if (decoded) {
        /* The verifier takes fixed-width r || s; DER magnitudes borrow the input. */
        memset(raw, 0, sizeof raw);
        memcpy(raw + width - pair.r.length, pair.r.data, pair.r.length);
        memcpy(raw + 2 * width - pair.s.length, pair.s.data, pair.s.length);
        signature_bytes = raw;
        signature_len = 2 * width;
      }
    }
    if (decoded) result = TC_ECDSA_verify_digest(curve, key, key_len, digest, digest_len,
        signature_bytes, signature_len, &workspace);
    if ((result == TC_OK) != !strcmp(fields[4], "valid"))
      munit_errorf("ECDSA vector %s: status %d, expected %s", fields[5], result, fields[4]);
    ++count;
  }
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(count, >, 0);
  return MUNIT_OK;
}
int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/vectors", vectors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
  };
  MunitSuite suite = {"/ecdsa", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  if (argc == 3 && (!strcmp(argv[1], "--vectors") || !strcmp(argv[1], "--der-vectors"))) {
    der = !strcmp(argv[1], "--der-vectors");
    path = argv[2]; argc = 1;
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
