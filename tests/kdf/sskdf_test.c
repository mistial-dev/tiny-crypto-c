/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/sskdf.h>
#include "munit.h"
#include "test_util.h"
#include <string.h>

typedef TC_status (*derive_fn)(TC_bytes, const TC_bytes*, size_t, TC_buffer);
static const derive_fn functions[] = {TC_SSKDF_SHA256, TC_SSKDF_SHA384};
static char** capture;

typedef struct {
  unsigned hash_bits;
  const char* z;
  const char* other_info;
  const char* dkm;
} nist_kas_vector;

static const nist_kas_vector nist_kas_vectors[] = {
#include "../vectors/kda/nist_kas_2014.inc"
};

static MunitResult nist_kas_answers(const MunitParameter params[], void* user)
{
  uint8_t z[512], other[256], expected[64], output[65];
  size_t i;
  (void)params;
  (void)user;
  for (i = 0; i < sizeof nist_kas_vectors / sizeof nist_kas_vectors[0]; ++i) {
    const nist_kas_vector* vector = &nist_kas_vectors[i];
    size_t z_len = tc_test_decode_hex(vector->z, z, sizeof z);
    size_t info_len = tc_test_decode_hex(vector->other_info, other, sizeof other);
    size_t output_len = tc_test_decode_hex(vector->dkm, expected, sizeof expected);
    size_t hash = vector->hash_bits == 256 ? 0 : 1;
    TC_bytes info[] = {{other, info_len / 2}, {other + info_len / 2, info_len - info_len / 2}};
    munit_assert_true(vector->hash_bits == 256 || vector->hash_bits == 384);
    munit_assert_size(z_len, >, 0);
    munit_assert_size(z_len, <=, sizeof z);
    munit_assert_size(info_len, >, 0);
    munit_assert_size(info_len, <=, sizeof other);
    munit_assert_size(output_len, >, 0);
    munit_assert_size(output_len, <, sizeof output);
    memset(output, 0xa5, sizeof output);
    munit_assert_int(
        functions[hash]((TC_bytes){z, z_len}, info, 2, (TC_buffer){output, output_len}), ==, TC_OK);
    munit_assert_memory_equal(output_len, output, expected);
    munit_assert_uint8(output[output_len], ==, 0xa5);
  }
  return MUNIT_OK;
}

static MunitResult captured_answer(const MunitParameter params[], void* user)
{
  uint8_t z[48], other[256], expected[192], output[192];
  TC_bytes info;
  size_t z_len, length, split, hash;
  (void)params;
  (void)user;
  if (!capture)
    return MUNIT_SKIP;
  munit_assert_true(strcmp(capture[0], "256") == 0 || strcmp(capture[0], "384") == 0);
  hash = strcmp(capture[0], "256") == 0 ? 0 : 1;
  z_len = tc_test_decode_hex(capture[1], z, sizeof z);
  info.data = other;
  info.length = tc_test_decode_hex(capture[2], other, sizeof other);
  length = tc_test_decode_hex(capture[3], expected, sizeof expected);
  munit_assert_size(z_len, >, 0);
  munit_assert_size(info.length, >, 0);
  munit_assert_size(length, >, 0);
  for (split = 0; split <= info.length; ++split) {
    const TC_bytes parts[] = {{other, split}, {other + split, info.length - split}};
    munit_assert_int(functions[hash]((TC_bytes){z, z_len}, parts, 2, (TC_buffer){output, length}),
                     ==, TC_OK);
    munit_assert_memory_equal(length, output, expected);
  }
  return MUNIT_OK;
}

static MunitResult known_answers(const MunitParameter params[], void* user)
{
  /* Python hashlib, counters 1 through 4, Z = 00..1f. */
  static const char* answers[] = {
      "786849806eb22bb04e0c03c193d744aaea14dccff32647cb22b21a593e3f6aceb9"
      "332326e7ca39d53dbcacfefd8c89263fa07e9dcedace6a1544d16c49123f4837a"
      "de3f772a83679254f05223f6214477e5df17a33f47180cce7256a6b29f521eb",
      "c247af748d630562879f66d69cdd322871af9ea338241f7d463515821c4f897a3"
      "42f37f5810c9a6a04e476773310509d3774172c88438d74b3f634f648724ec0dc"
      "28455ae34fe52118e41f0c6b66776db6106e276525d69b11827d244aeba3879c"};
  static const uint8_t text[] = "purposecontext";
  TC_bytes info[3];
  uint8_t z[32], output[98], expected[97];
  size_t f, split, length;
  (void)params;
  (void)user;
  tc_test_fill_incrementing(z, sizeof z);
  info[1].data = NULL;
  info[1].length = 0;
  for (f = 0; f < 2; ++f) {
    munit_assert_size(tc_test_decode_hex(answers[f], expected, sizeof expected), ==,
                      sizeof expected);
    for (split = 0; split < sizeof text; ++split) {
      info[0].data = text;
      info[0].length = split;
      info[2].data = text + split;
      info[2].length = sizeof text - 1 - split;
      for (length = 1; length <= sizeof expected; ++length) {
        memset(output, 0xa5, sizeof output);
        munit_assert_int(
            functions[f]((TC_bytes){z, sizeof z}, info, 3, (TC_buffer){output, length}), ==, TC_OK);
        munit_assert_memory_equal(length, output, expected);
        munit_assert_uint8(output[length], ==, 0xa5);
      }
    }
  }
  return MUNIT_OK;
}

static MunitResult invalid_arguments(const MunitParameter params[], void* user)
{
  uint8_t buffer[64], saved[64];
  TC_bytes info = {buffer, 16};
  size_t f;
  (void)params;
  (void)user;
  memset(buffer, 0xa5, sizeof buffer);
  memcpy(saved, buffer, sizeof saved);
  for (f = 0; f < 2; ++f) {
    munit_assert_int(functions[f]((TC_bytes){NULL, 1}, NULL, 0, (TC_buffer){buffer, 32}), ==,
                     TC_ERROR);
    munit_assert_int(functions[f]((TC_bytes){buffer, 0}, NULL, 0, (TC_buffer){buffer + 32, 32}), ==,
                     TC_ERROR);
    munit_assert_int(functions[f]((TC_bytes){buffer, 32}, NULL, 1, (TC_buffer){buffer + 32, 32}),
                     ==, TC_ERROR);
    munit_assert_int(functions[f]((TC_bytes){buffer, 32}, NULL, 0, (TC_buffer){NULL, 32}), ==,
                     TC_ERROR);
    munit_assert_int(functions[f]((TC_bytes){buffer, 32}, NULL, 0, (TC_buffer){buffer + 32, 0}), ==,
                     TC_ERROR);
    munit_assert_int(functions[f]((TC_bytes){buffer, 32}, NULL, 0, (TC_buffer){buffer + 16, 32}),
                     ==, TC_ERROR);
    munit_assert_int(functions[f]((TC_bytes){buffer + 32, 32}, &info, 1, (TC_buffer){buffer, 32}),
                     ==, TC_ERROR);
    munit_assert_int(
        functions[f]((TC_bytes){buffer, 32}, &info, 1, (TC_buffer){(uint8_t*)&info, sizeof info}),
        ==, TC_ERROR);
    info.data = NULL;
    info.length = 1;
    munit_assert_int(functions[f]((TC_bytes){buffer, 32}, &info, 1, (TC_buffer){buffer + 32, 32}),
                     ==, TC_ERROR);
    info.data = buffer;
    info.length = SIZE_MAX;
    munit_assert_int(functions[f]((TC_bytes){buffer, 32}, &info, 1, (TC_buffer){buffer + 32, 32}),
                     ==, TC_ERROR);
    info.length = 16;
    munit_assert_memory_equal(sizeof buffer, buffer, saved);
  }
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/nist-kas-2014", nist_kas_answers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/captured-answer", captured_answer, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/known-answers", known_answers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/invalid-arguments", invalid_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/sskdf", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  if (argc == 6 && strcmp(argv[1], "--capture") == 0) {
    char* args[] = {argv[0], (char*)"/sskdf/captured-answer", NULL};
    capture = argv + 2;
    return munit_suite_main(&suite, NULL, 2, args);
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
