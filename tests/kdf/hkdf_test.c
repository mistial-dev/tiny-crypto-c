/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include <tiny_crypto/hkdf.h>
#include "munit.h"
#include "test_util.h"

struct hkdf_vector {
  int hash;
  const char* ikm;
  const char* salt;
  const char* info;
  const char* prk;
  const char* okm;
};

#include "hkdf_vectors.h"

struct hkdf_family {
  int hash;
  size_t hash_len;
  TC_status (*extract)(TC_bytes, const TC_bytes*, size_t, uint8_t*);
  TC_status (*expand)(TC_bytes, TC_bytes, TC_buffer);
  TC_status (*derive)(TC_bytes, const TC_bytes*, size_t, TC_bytes, TC_buffer);
};

static const struct hkdf_family families[] = {
#if TC_ENABLE_SHA1
    {1, TC_SHA1_DIGESTLEN, TC_HKDF_SHA1_extract, TC_HKDF_SHA1_expand, TC_HKDF_SHA1_derive},
#endif
#if TC_ENABLE_SHA224
    {224, TC_SHA224_DIGESTLEN, TC_HKDF_SHA224_extract, TC_HKDF_SHA224_expand,
     TC_HKDF_SHA224_derive},
#endif
#if TC_ENABLE_SHA256
    {256, TC_SHA256_DIGESTLEN, TC_HKDF_SHA256_extract, TC_HKDF_SHA256_expand,
     TC_HKDF_SHA256_derive},
#endif
#if TC_ENABLE_SHA384
    {384, TC_SHA384_DIGESTLEN, TC_HKDF_SHA384_extract, TC_HKDF_SHA384_expand,
     TC_HKDF_SHA384_derive},
#endif
#if TC_ENABLE_SHA512
    {512, TC_SHA512_DIGESTLEN, TC_HKDF_SHA512_extract, TC_HKDF_SHA512_expand,
     TC_HKDF_SHA512_derive},
#endif
};

static const struct hkdf_family* find_family(int hash)
{
  size_t i;
  for (i = 0; i < sizeof families / sizeof families[0]; ++i)
    if (families[i].hash == hash)
      return &families[i];
  return NULL;
}

static size_t decode(const char* text, uint8_t* output, size_t capacity)
{
  size_t length = tc_test_decode_hex(text, output, capacity);
  munit_assert_size(length, ==, strlen(text) / 2u);
  return length;
}

static MunitResult test_hkdf_vectors(const MunitParameter params[], void* data)
{
  size_t i;
  (void)params;
  (void)data;
  for (i = 0; i < sizeof hkdf_vectors / sizeof hkdf_vectors[0]; ++i) {
    const struct hkdf_vector* v = &hkdf_vectors[i];
    const struct hkdf_family* f = find_family(v->hash);
    uint8_t ikm[80], salt[80], info[80], prk[64], expected_prk[64], output[82], expected[82];
    size_t ikm_len, salt_len, info_len, prk_len, output_len;
    if (!f)
      continue;
    ikm_len = decode(v->ikm, ikm, sizeof ikm);
    salt_len = decode(v->salt, salt, sizeof salt);
    info_len = decode(v->info, info, sizeof info);
    prk_len = decode(v->prk, expected_prk, sizeof expected_prk);
    output_len = decode(v->okm, expected, sizeof expected);
    munit_assert_size(prk_len, ==, f->hash_len);
    const TC_bytes ikm_part = {ikm_len ? ikm : NULL, ikm_len};
    munit_assert_int(f->extract((TC_bytes){salt_len ? salt : NULL, salt_len}, &ikm_part, 1, prk),
                     ==, TC_OK);
    munit_assert_memory_equal(prk_len, prk, expected_prk);
    munit_assert_int(f->expand((TC_bytes){prk, prk_len},
                               (TC_bytes){info_len ? info : NULL, info_len},
                               (TC_buffer){output, output_len}),
                     ==, TC_OK);
    munit_assert_memory_equal(output_len, output, expected);
    memset(output, 0, sizeof output);
    munit_assert_int(f->derive((TC_bytes){salt_len ? salt : NULL, salt_len}, &ikm_part, 1,
                               (TC_bytes){info_len ? info : NULL, info_len},
                               (TC_buffer){output, output_len}),
                     ==, TC_OK);
    munit_assert_memory_equal(output_len, output, expected);
  }
  return MUNIT_OK;
}

static MunitResult test_hkdf_limits(const MunitParameter params[], void* data)
{
  static uint8_t output[16322];
  uint8_t prk[64];
  size_t i;
  (void)params;
  (void)data;
  memset(prk, 0x42, sizeof prk);
  for (i = 0; i < sizeof families / sizeof families[0]; ++i) {
    const struct hkdf_family* f = &families[i];
    size_t maximum = 255u * f->hash_len;
    memset(output, 0xa5, sizeof output);
    munit_assert_int(
        f->expand((TC_bytes){prk, f->hash_len}, (TC_bytes){NULL, 0}, (TC_buffer){output, maximum}),
        ==, TC_OK);
    munit_assert_uchar(output[maximum], ==, 0xa5);
    munit_assert_uchar(output[maximum - 1u], !=, 0xa5);
    memset(output, 0xa5, sizeof output);
    munit_assert_int(f->expand((TC_bytes){prk, f->hash_len}, (TC_bytes){NULL, 0},
                               (TC_buffer){output, maximum + 1u}),
                     ==, TC_ERROR);
    munit_assert_uchar(output[0], ==, 0xa5);
    munit_assert_uchar(output[maximum], ==, 0xa5);
    munit_assert_int(
        f->expand((TC_bytes){prk, f->hash_len}, (TC_bytes){NULL, 0}, (TC_buffer){output, SIZE_MAX}),
        ==, TC_ERROR);
    munit_assert_uchar(output[0], ==, 0xa5);
  }
  return MUNIT_OK;
}

static MunitResult test_hkdf_arguments(const MunitParameter params[], void* data)
{
  uint8_t input[128], output[128], prk[128];
  size_t i;
  (void)params;
  (void)data;
  memset(input, 0x11, sizeof input);
  memset(prk, 0x22, sizeof prk);
  const TC_bytes one = {input, 1}, missing = {NULL, 1}, empty = {NULL, 0};
  const TC_bytes aliases_output[] = {{output, 1}};
  for (i = 0; i < sizeof families / sizeof families[0]; ++i) {
    const struct hkdf_family* f = &families[i];
    memset(output, 0xa5, sizeof output);
    munit_assert_int(f->extract((TC_bytes){NULL, 1}, &one, 1, output), ==, TC_ERROR);
    munit_assert_uchar(output[0], ==, 0xa5);
    munit_assert_int(f->extract((TC_bytes){input, 1}, &missing, 1, output), ==, TC_ERROR);
    munit_assert_int(f->extract((TC_bytes){input, 1}, NULL, 1, output), ==, TC_ERROR);
    munit_assert_int(f->extract((TC_bytes){input, 1}, &one, 1, input), ==, TC_ERROR);
    munit_assert_int(f->extract((TC_bytes){NULL, 0}, aliases_output, 1, output), ==, TC_ERROR);
    munit_assert_uchar(output[0], ==, 0xa5);
    munit_assert_int(f->extract((TC_bytes){NULL, 0}, NULL, 0, output), ==, TC_OK);
    munit_assert_int(f->extract((TC_bytes){NULL, 0}, &empty, 1, output), ==, TC_OK);
    munit_assert_int(
        f->expand((TC_bytes){prk, f->hash_len - 1u}, (TC_bytes){NULL, 0}, (TC_buffer){output, 1}),
        ==, TC_ERROR);
    munit_assert_int(
        f->expand((TC_bytes){prk, f->hash_len}, (TC_bytes){NULL, 1}, (TC_buffer){output, 1}), ==,
        TC_ERROR);
    munit_assert_int(
        f->expand((TC_bytes){prk, f->hash_len}, (TC_bytes){NULL, 0}, (TC_buffer){output, 0}), ==,
        TC_ERROR);
    munit_assert_int(
        f->expand((TC_bytes){prk, f->hash_len}, (TC_bytes){input, 1}, (TC_buffer){input, 1}), ==,
        TC_ERROR);
    munit_assert_int(
        f->expand((TC_bytes){prk, f->hash_len}, (TC_bytes){NULL, 0}, (TC_buffer){prk, 1}), ==,
        TC_ERROR);
    memset(output, 0xa5, sizeof output);
    munit_assert_int(
        f->derive((TC_bytes){input, 1}, &one, 1, (TC_bytes){input, 1}, (TC_buffer){input, 1}), ==,
        TC_ERROR);
    munit_assert_int(f->derive((TC_bytes){NULL, 0}, aliases_output, 1, (TC_bytes){NULL, 0},
                               (TC_buffer){output, 1}),
                     ==, TC_ERROR);
    munit_assert_int(
        f->derive((TC_bytes){NULL, 0}, NULL, 0, (TC_bytes){NULL, 0}, (TC_buffer){output, 0}), ==,
        TC_ERROR);
    munit_assert_uchar(output[0], ==, 0xa5);
    munit_assert_int(f->derive((TC_bytes){NULL, 0}, NULL, 0, (TC_bytes){NULL, 0},
                               (TC_buffer){output, f->hash_len}),
                     ==, TC_OK);
    munit_assert_int(
        f->expand((TC_bytes){prk, f->hash_len + 1u}, (TC_bytes){NULL, 0}, (TC_buffer){output, 1}),
        ==, TC_OK);
  }
  return MUNIT_OK;
}

/* SP 800-56C revision 2 hybrid secrets: extracting Z || T from separate
 * parts equals extracting the concatenation, for every split point. */
static MunitResult test_hkdf_parts_and_multiple_expansions(const MunitParameter params[],
                                                           void* data)
{
  const uint8_t salt[] = {1, 2, 3, 4};
  const uint8_t combined[] = {5, 6, 7, 8, 9};
  const uint8_t first_info[] = {0x10};
  const uint8_t second_info[] = {0x20};
  size_t i;
  (void)params;
  (void)data;
  for (i = 0; i < sizeof families / sizeof families[0]; ++i) {
    const struct hkdf_family* f = &families[i];
    const TC_bytes whole = {combined, sizeof combined};
    uint8_t prk[64], ordinary_prk[64], first[77], second[77], expected[77];
    munit_assert_int(f->extract((TC_bytes){salt, sizeof salt}, &whole, 1, ordinary_prk), ==, TC_OK);
    for (size_t split = 0; split <= sizeof combined; ++split) {
      const TC_bytes three[] = {
          {combined, split}, {NULL, 0}, {combined + split, sizeof combined - split}};
      munit_assert_int(f->extract((TC_bytes){salt, sizeof salt}, three, 3, prk), ==, TC_OK);
      munit_assert_memory_equal(f->hash_len, prk, ordinary_prk);
    }
    munit_assert_int(f->expand((TC_bytes){prk, f->hash_len},
                               (TC_bytes){first_info, sizeof first_info},
                               (TC_buffer){first, sizeof first}),
                     ==, TC_OK);
    munit_assert_int(f->expand((TC_bytes){prk, f->hash_len},
                               (TC_bytes){second_info, sizeof second_info},
                               (TC_buffer){second, sizeof second}),
                     ==, TC_OK);
    munit_assert_memory_not_equal(sizeof first, first, second);
    const TC_bytes hybrid[] = {{combined, 3}, {combined + 3, 2}};
    munit_assert_int(f->derive((TC_bytes){salt, sizeof salt}, hybrid, 2,
                               (TC_bytes){first_info, sizeof first_info},
                               (TC_buffer){expected, sizeof expected}),
                     ==, TC_OK);
    munit_assert_memory_equal(sizeof first, first, expected);
    munit_assert_int(f->derive((TC_bytes){salt, sizeof salt}, hybrid, 2,
                               (TC_bytes){second_info, sizeof second_info},
                               (TC_buffer){expected, sizeof expected}),
                     ==, TC_OK);
    munit_assert_memory_equal(sizeof second, second, expected);
  }
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/vectors", test_hkdf_vectors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/limits", test_hkdf_limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/arguments", test_hkdf_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/parts-and-multiple-expansions", test_hkdf_parts_and_multiple_expansions, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite suite = {"/hkdf", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
