/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/sskdf.h>
#include "munit.h"
#include "cavp.h"
#include "test_util.h"
#include <stdlib.h>
#include <string.h>

typedef TC_status (*derive_fn)(TC_bytes, const TC_bytes*, size_t, TC_buffer);

/* One entry per SSKDF family the profile builds, keyed by digest bits. */
typedef struct {
  unsigned hash_bits;
  derive_fn derive;
} sskdf_family;

static const sskdf_family families[] = {
#if TC_ENABLE_SHA1
    {160, TC_SSKDF_SHA1},
#endif
#if TC_ENABLE_SHA224
    {224, TC_SSKDF_SHA224},
#endif
#if TC_ENABLE_SHA256
    {256, TC_SSKDF_SHA256},
#endif
#if TC_ENABLE_SHA384
    {384, TC_SSKDF_SHA384},
#endif
#if TC_ENABLE_SHA512
    {512, TC_SSKDF_SHA512},
#endif
};
#define FAMILY_COUNT (sizeof families / sizeof families[0])
static char** capture;

static derive_fn family_for(unsigned hash_bits)
{
  size_t i;
  for (i = 0; i < FAMILY_COUNT; ++i)
    if (families[i].hash_bits == hash_bits)
      return families[i].derive;
  return NULL;
}

typedef struct {
  unsigned hash_bits;
  const char* z;
  const char* other_info;
  const char* dkm;
} nist_kas_vector;

static const nist_kas_vector nist_kas_vectors[] = {
#include "../vectors/kda/nist_kas_2014.inc"
};

/* ACVP fixedInfo fields in pattern order: t, U partyId, U ephemeralData,
 * V partyId, V ephemeralData and [L]_32. Revision 1 cases leave t empty. */
typedef struct {
  unsigned hash_bits;
  const char* z;
  const char* fixed_info[6];
  const char* dkm;
  int passed;
} acvp_one_step_vector;

static const acvp_one_step_vector acvp_vectors[] = {
#include "../vectors/kda/acvp_onestep.inc"
};

TC_TEST(nist_kas_answers)
{
  uint8_t z[512], other[256], expected[64], output[65];
  size_t i;
  for (i = 0; i < sizeof nist_kas_vectors / sizeof nist_kas_vectors[0]; ++i) {
    const nist_kas_vector* vector = &nist_kas_vectors[i];
    size_t z_len = tc_test_hex(vector->z, z, sizeof z);
    size_t info_len = tc_test_hex(vector->other_info, other, sizeof other);
    size_t output_len = tc_test_hex(vector->dkm, expected, sizeof expected);
    derive_fn derive = family_for(vector->hash_bits);
    TC_bytes info[] = {{other, info_len / 2}, {other + info_len / 2, info_len - info_len / 2}};
    if (!derive)
      continue;
    munit_assert_size(z_len, >, 0);
    munit_assert_size(z_len, <=, sizeof z);
    munit_assert_size(info_len, >, 0);
    munit_assert_size(info_len, <=, sizeof other);
    munit_assert_size(output_len, >, 0);
    munit_assert_size(output_len, <, sizeof output);
    memset(output, 0xa5, sizeof output);
    munit_assert_int(derive((TC_bytes){z, z_len}, info, 2, (TC_buffer){output, output_len}), ==,
                     TC_OK);
    munit_assert_memory_equal(output_len, output, expected);
    munit_assert_uint8(output[output_len], ==, 0xa5);
  }
  return MUNIT_OK;
}

/* AFT cases must reproduce the DKM. VAL cases must agree with the ACVP
 * verdict on the supplied DKM. Each fixedInfo field is its own span. */
TC_TEST(acvp_one_step_answers)
{
  uint8_t z[64], fields[6][64], expected[128], output[129];
  size_t i, f, ran = 0, rejected = 0;
  for (i = 0; i < sizeof acvp_vectors / sizeof acvp_vectors[0]; ++i) {
    const acvp_one_step_vector* vector = &acvp_vectors[i];
    derive_fn derive = family_for(vector->hash_bits);
    TC_bytes info[6];
    size_t z_len, dkm_len;
    if (!derive)
      continue;
    z_len = tc_test_hex(vector->z, z, sizeof z);
    dkm_len = tc_test_hex(vector->dkm, expected, sizeof expected);
    munit_assert_size(z_len * 2, ==, strlen(vector->z));
    munit_assert_size(dkm_len * 2, ==, strlen(vector->dkm));
    for (f = 0; f < 6; ++f) {
      info[f].data = fields[f];
      info[f].length = tc_test_hex(vector->fixed_info[f], fields[f], sizeof fields[f]);
      munit_assert_size(info[f].length * 2, ==, strlen(vector->fixed_info[f]));
    }
    memset(output, 0xa5, sizeof output);
    munit_assert_int(derive((TC_bytes){z, z_len}, info, 6, (TC_buffer){output, dkm_len}), ==,
                     TC_OK);
    munit_assert_int(memcmp(output, expected, dkm_len) == 0, ==, vector->passed);
    munit_assert_uint8(output[dkm_len], ==, 0xa5);
    ++ran;
    rejected += !vector->passed;
  }
#if TC_ENABLE_SHA224 && TC_ENABLE_SHA512
  /* The extracted corpus: 12 cases per hash, two of them failing VAL cases. */
  munit_assert_size(ran, ==, 24);
  munit_assert_size(rejected, ==, 2);
#endif
  if (!ran)
    return MUNIT_SKIP;
  return MUNIT_OK;
}

TC_TEST(captured_answer)
{
  uint8_t z[48], other[256], expected[192], output[192];
  TC_bytes info;
  size_t z_len, length, split;
  derive_fn derive;
  if (!capture)
    return MUNIT_SKIP;
  derive = family_for((unsigned)strtoul(capture[0], NULL, 10));
  munit_assert_true(derive != NULL);
  z_len = tc_test_hex(capture[1], z, sizeof z);
  info.data = other;
  info.length = tc_test_hex(capture[2], other, sizeof other);
  length = tc_test_hex(capture[3], expected, sizeof expected);
  munit_assert_size(z_len, >, 0);
  munit_assert_size(info.length, >, 0);
  munit_assert_size(length, >, 0);
  for (split = 0; split <= info.length; ++split) {
    const TC_bytes parts[] = {{other, split}, {other + split, info.length - split}};
    munit_assert_int(derive((TC_bytes){z, z_len}, parts, 2, (TC_buffer){output, length}), ==,
                     TC_OK);
    munit_assert_memory_equal(length, output, expected);
  }
  return MUNIT_OK;
}

TC_TEST(known_answers)
{
  /* Python hashlib: the first 97 bytes of hash([i]_32 || Z || info) blocks,
   * Z = 00..1f and info = "purposecontext". SHA-1 needs five blocks. NIST
   * publishes no one-step SHA-1 vectors, so this is its only answer. */
  static const struct {
    unsigned hash_bits;
    const char* answer;
  } answers[] = {{160, "76cc671c567e898d1da4d8236146fbc80e1a0d3bcf3f84aff69efd93d1f7e8cbb9"
                       "4aedcecbd8604c5e502936fa67931a7c6e99e1b29ebcdbcf9b020a88b6aa55bb29"
                       "71996267f795028e53ac1768caef3dda5f5438f14f5437ac383bf772310e95"},
                 {224, "056ae795b03f5534f55ee4c9207e7a416f94f810f9073155fc8c0789c800a32586"
                       "0cc7cfff8c67aed3fb12ea9c552569fcd105f7773fdff3d55bc405ba9ce704d32e"
                       "55c9db6c83b940c2eda9bc07b9af24929f93df93b66ace49e855c501929875"},
                 {256, "786849806eb22bb04e0c03c193d744aaea14dccff32647cb22b21a593e3f6aceb9"
                       "332326e7ca39d53dbcacfefd8c89263fa07e9dcedace6a1544d16c49123f4837a"
                       "de3f772a83679254f05223f6214477e5df17a33f47180cce7256a6b29f521eb"},
                 {384, "c247af748d630562879f66d69cdd322871af9ea338241f7d463515821c4f897a3"
                       "42f37f5810c9a6a04e476773310509d3774172c88438d74b3f634f648724ec0dc"
                       "28455ae34fe52118e41f0c6b66776db6106e276525d69b11827d244aeba3879c"},
                 {512, "52f5f8c83b55a174043a9bd2663342937b8b70faf0b4dba510055469bd16284"
                       "18ee7d28e3b596f378124e1982bcc781da606b01a097627ce87b3daa6b7b7d8bf"
                       "da145b179d3ef2d14fa04be68cda9b36819fe02d384a184c9b9c31ce3a39ab9fe9"}};
  static const uint8_t text[] = "purposecontext";
  TC_bytes info[3];
  uint8_t z[32], output[98], expected[97];
  size_t a, split, length, ran = 0;
  tc_test_fill_incrementing(z, sizeof z);
  info[1].data = NULL;
  info[1].length = 0;
  for (a = 0; a < sizeof answers / sizeof answers[0]; ++a) {
    derive_fn derive = family_for(answers[a].hash_bits);
    if (!derive)
      continue;
    ++ran;
    munit_assert_size(tc_test_hex(answers[a].answer, expected, sizeof expected), ==,
                      sizeof expected);
    for (split = 0; split < sizeof text; ++split) {
      info[0].data = text;
      info[0].length = split;
      info[2].data = text + split;
      info[2].length = sizeof text - 1 - split;
      for (length = 1; length <= sizeof expected; ++length) {
        memset(output, 0xa5, sizeof output);
        munit_assert_int(derive((TC_bytes){z, sizeof z}, info, 3, (TC_buffer){output, length}), ==,
                         TC_OK);
        munit_assert_memory_equal(length, output, expected);
        munit_assert_uint8(output[length], ==, 0xa5);
      }
    }
  }
  munit_assert_size(ran, ==, FAMILY_COUNT);
  return MUNIT_OK;
}

TC_TEST(invalid_arguments)
{
  uint8_t buffer[64], saved[64];
  TC_bytes info = {buffer, 16};
  size_t f;
  memset(buffer, 0xa5, sizeof buffer);
  memcpy(saved, buffer, sizeof saved);
  for (f = 0; f < FAMILY_COUNT; ++f) {
    const derive_fn derive = families[f].derive;
    munit_assert_int(derive((TC_bytes){NULL, 1}, NULL, 0, (TC_buffer){buffer, 32}), ==, TC_ERROR);
    munit_assert_int(derive((TC_bytes){buffer, 0}, NULL, 0, (TC_buffer){buffer + 32, 32}), ==,
                     TC_ERROR);
    munit_assert_int(derive((TC_bytes){buffer, 32}, NULL, 1, (TC_buffer){buffer + 32, 32}), ==,
                     TC_ERROR);
    munit_assert_int(derive((TC_bytes){buffer, 32}, NULL, 0, (TC_buffer){NULL, 32}), ==, TC_ERROR);
    munit_assert_int(derive((TC_bytes){buffer, 32}, NULL, 0, (TC_buffer){buffer + 32, 0}), ==,
                     TC_ERROR);
    munit_assert_int(derive((TC_bytes){buffer, 32}, NULL, 0, (TC_buffer){buffer + 16, 32}), ==,
                     TC_ERROR);
    munit_assert_int(derive((TC_bytes){buffer + 32, 32}, &info, 1, (TC_buffer){buffer, 32}), ==,
                     TC_ERROR);
    munit_assert_int(
        derive((TC_bytes){buffer, 32}, &info, 1, (TC_buffer){(uint8_t*)&info, sizeof info}), ==,
        TC_ERROR);
    info.data = NULL;
    info.length = 1;
    munit_assert_int(derive((TC_bytes){buffer, 32}, &info, 1, (TC_buffer){buffer + 32, 32}), ==,
                     TC_ERROR);
    info.data = buffer;
    info.length = SIZE_MAX;
    munit_assert_int(derive((TC_bytes){buffer, 32}, &info, 1, (TC_buffer){buffer + 32, 32}), ==,
                     TC_ERROR);
    info.length = 16;
    munit_assert_memory_equal(sizeof buffer, buffer, saved);
  }
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/nist-kas-2014", nist_kas_answers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/acvp-one-step", acvp_one_step_answers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
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
