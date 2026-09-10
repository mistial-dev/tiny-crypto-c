/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#include "munit.h"
#include "test_util.h"
#include "hash_name.h"
#include <stdio.h>
#include <string.h>

static const char* path;
static MunitResult vectors(const MunitParameter params[], void* data)
{
  char line[32768];
  uint8_t modulus[384], exponent[384], digest[64], signature[8192];
  TC_RSA_word words[9 * (3072 / TC_RSA_WORD_BITS) + 2];
  TC_RSA_workspace workspace = {words, sizeof words / sizeof words[0]};
  size_t count = 0;
  FILE* file;
  (void)params; (void)data;
  if (!path) return MUNIT_SKIP;
  file = fopen(path, "r");
  munit_assert_not_null(file);
  while (fgets(line, sizeof line, file)) {
    char* fields[10];
    char* token = strtok(line, " \t\r\n");
    size_t columns = 0;
    while (token) {
      munit_assert_size(columns, <, sizeof fields / sizeof fields[0]);
      fields[columns++] = token;
      token = strtok(NULL, " \t\r\n");
    }
    munit_assert_size(columns, ==, 10);
    const char* n_text = fields[1];
    const char* e_text = fields[2];
    const char* h_text = fields[6];
    const char* s_text = fields[7];
    const char* verdict = fields[8];
    const char* id = fields[9];
    TC_hash_algorithm hash, mgf;
    size_t salt;
    int pss;
    {
      munit_assert_true(!strcmp(fields[0],"pss") || !strcmp(fields[0],"v15"));
      pss = !strcmp(fields[0],"pss");
      hash = hash_algorithm(fields[3]); mgf = hash_algorithm(fields[4]);
      salt = 0;
      for (const char* digit = fields[5]; *digit; ++digit) {
        munit_assert_true(*digit >= '0' && *digit <= '9');
        munit_assert_size(salt, <=, (SIZE_MAX - (size_t)(*digit - '0')) / 10);
        salt = salt * 10 + (size_t)(*digit - '0');
      }
    }
    size_t n = tc_test_decode_hex(n_text, modulus, sizeof modulus);
    size_t e = tc_test_decode_hex(e_text, exponent, sizeof exponent);
    size_t h = tc_test_decode_hex(h_text, digest, sizeof digest);
    size_t s = strcmp(s_text, "-") ? tc_test_decode_hex(s_text, signature, sizeof signature) : 0;
    munit_assert_size(n * 2, ==, strlen(n_text));
    munit_assert_size(e * 2, ==, strlen(e_text));
    munit_assert_size(h * 2, ==, strlen(h_text));
    if (strcmp(s_text, "-")) munit_assert_size(s * 2, ==, strlen(s_text));
    munit_assert_true(!strcmp(verdict, "valid") || !strcmp(verdict, "invalid"));
    TC_RSA_public_key key = {{modulus, n}, {exponent, e}};
    TC_work_budget budget = {32768};
    const TC_RSA_pss_options pss_options = {hash,mgf,salt};
    const TC_RSA_v15_options v15_options = {hash};
    TC_RSA_result result = pss ? TC_RSA_verify_pss_digest(&key,&pss_options,
        (TC_bytes){digest,h},(TC_bytes){signature,s},&workspace,&budget) :
        TC_RSA_verify_v15_digest(&key,&v15_options,(TC_bytes){digest,h},
            (TC_bytes){signature,s},&workspace,&budget);
    if (result != TC_RSA_OK && result != TC_RSA_INVALID)
      munit_errorf("RSA signature vector %s: unexpected status %d", id, result);
    if ((result == TC_RSA_OK) != !strcmp(verdict, "valid"))
      munit_errorf("RSA signature vector %s: status %d, expected %s", id, result, verdict);
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
  MunitSuite suite = {"/rsa-signatures", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  if (argc == 3 && !strcmp(argv[1], "--signature-vectors")) { path = argv[2]; argc = 1; }
  return munit_suite_main(&suite, NULL, argc, argv);
}
