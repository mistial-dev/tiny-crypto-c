/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Validate NIST CAVP generated key material through the public RSA API. */
#include <tiny_crypto/rsa.h>
#include "munit.h"
#include "cavp.h"
#include <stdio.h>
#include <string.h>

static const char* vector_path;

static TC_status draw(void* context, uint8_t* output, size_t length)
{
  uint32_t* state = context;
  for (size_t i = 0; i < length; ++i) {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    output[i] = (uint8_t)*state;
  }
  return TC_OK;
}

static MunitResult vectors(const MunitParameter params[], void* data)
{
  char line[4096];
  uint8_t n[512], e[512], d[512], p[256], q[256];
  TC_RSA_word words[TC_RSA_VALIDATE_WORKSPACE_WORDS(4096)];
  TC_RSA_workspace workspace = {words, sizeof words / sizeof words[0]};
  uint32_t random_state = 0x12345678u;
  FILE* file;
  size_t count = 0;
  (void)params;
  (void)data;
  if (!vector_path)
    return MUNIT_SKIP;
  file = fopen(vector_path, "r");
  munit_assert_not_null(file);
  while (fgets(line, sizeof line, file)) {
    char *fields[6], *token = strtok(line, " \t\r\n");
    size_t columns = 0;
    while (token) {
      munit_assert_size(columns, <, 6);
      fields[columns++] = token;
      token = strtok(NULL, " \t\r\n");
    }
    munit_assert_size(columns, ==, 6);
    size_t nl = tc_test_hex(fields[0], n, sizeof n);
    size_t el = tc_test_hex(fields[1], e, sizeof e);
    size_t dl = tc_test_hex(fields[2], d, sizeof d);
    size_t pl = tc_test_hex(fields[3], p, sizeof p);
    size_t ql = tc_test_hex(fields[4], q, sizeof q);
    munit_assert_size(nl * 2, ==, strlen(fields[0]));
    munit_assert_size(el * 2, ==, strlen(fields[1]));
    munit_assert_size(dl * 2, ==, strlen(fields[2]));
    munit_assert_size(pl * 2, ==, strlen(fields[3]));
    munit_assert_size(ql * 2, ==, strlen(fields[4]));
    size_t leading = 0;
    while (leading < el && e[leading] == 0)
      ++leading;
    munit_assert_size(leading, <, el);
    el -= leading;
    const TC_RSA_private_key key = {{{n, nl}, {e + leading, el}}, {d, dl}, {p, pl}, {q, ql}, NULL};
    TC_RSA_execution execution = {{draw, &random_state}, 512, {UINT32_MAX}};
    /* Vectors with e outside the FIPS 186-5 range need the explicit override. */
    const TC_RSA_exponent_policy policy = TC_RSA_exponent_in_fips_range(key.public_key.exponent)
                                              ? TC_RSA_EXPONENT_FIPS
                                              : TC_RSA_EXPONENT_ANY_ODD;
    TC_RSA_result result = TC_RSA_validate_private_key(&key, policy, &workspace, &execution);
    if (result != TC_RSA_OK)
      munit_errorf("NIST RSA KeyGen record %s: status %d", fields[5], result);
    if (count == 0) {
      p[pl - 1] ^= 1u;
      result = TC_RSA_validate_private_key(&key, policy, &workspace, &execution);
      munit_assert_int(result, !=, TC_RSA_OK);
      p[pl - 1] ^= 1u;
    }
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
  MunitSuite suite = {"/nist-rsa-keygen", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  if (argc == 3 && !strcmp(argv[1], "--vectors")) {
    vector_path = argv[2];
    argc = 1;
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
