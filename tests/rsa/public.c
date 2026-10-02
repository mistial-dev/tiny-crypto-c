/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#include "munit.h"
#include "test_util.h"
#include <string.h>

static TC_RSA_result verify(const TC_RSA_public_key* key, TC_hash_algorithm hash, TC_bytes digest,
                            TC_bytes signature, const TC_RSA_workspace* workspace, uint32_t work)
{
  const TC_RSA_v15_options options = {hash};
  TC_work_budget budget = {work};
  return TC_RSA_verify_v15_digest(key, &options, digest, signature, workspace, &budget);
}

TC_TEST(arguments)
{
  uint8_t modulus[128], exponent[] = {3}, digest[32] = {0}, signature[128] = {0};
  TC_RSA_word scratch[9 * 1024 / TC_RSA_WORD_BITS + 2];
  TC_RSA_public_key key = {{modulus, sizeof modulus}, {exponent, sizeof exponent}};
  TC_RSA_workspace workspace = {scratch, sizeof scratch / sizeof *scratch};
  TC_bytes hashed = {digest, sizeof digest}, signed_bytes = {signature, sizeof signature};
  memset(modulus, 0xff, sizeof modulus);
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_VERIFY, 1024), ==, workspace.capacity);
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_VERIFY, 2048), ==,
                    9 * 2048 / TC_RSA_WORD_BITS + 2);
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_VERIFY, 3072), ==,
                    9 * 3072 / TC_RSA_WORD_BITS + 2);
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_VERIFY, 4096), ==,
                    9 * 4096 / TC_RSA_WORD_BITS + 2);
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_VERIFY, SIZE_MAX), ==, 0);
  const TC_RSA_v15_options options = {TC_HASH_SHA256};
  TC_work_budget work = {10000};
  munit_assert_int(
      TC_RSA_verify_v15_digest(&key, &options, hashed, signed_bytes, &workspace, &work), ==,
      TC_RSA_INVALID);
  munit_assert_uint(work.remaining, <, 10000);
  munit_assert_int(verify(&key, TC_HASH_SHA256, hashed, signed_bytes, &workspace, 0), ==,
                   TC_RSA_LIMIT);
  munit_assert_int(verify(NULL, TC_HASH_SHA256, hashed, signed_bytes, &workspace, 10000), ==,
                   TC_RSA_ARGUMENT);
  workspace.capacity = SIZE_MAX;
  munit_assert_int(verify(&key, TC_HASH_SHA256, hashed, signed_bytes, &workspace, 10000), ==,
                   TC_RSA_ARGUMENT);
  workspace.capacity = sizeof scratch / sizeof *scratch - 1;
  munit_assert_int(verify(&key, TC_HASH_SHA256, hashed, signed_bytes, &workspace, 10000), ==,
                   TC_RSA_LIMIT);
  workspace.capacity++;
  hashed.data = (const uint8_t*)scratch;
  memset(scratch, 0xa5, sizeof scratch);
  munit_assert_int(verify(&key, TC_HASH_SHA256, hashed, signed_bytes, &workspace, 10000), ==,
                   TC_RSA_ARGUMENT);
  for (size_t i = 0; i < sizeof scratch; ++i)
    munit_assert_uint(((uint8_t*)scratch)[i], ==, 0xa5);
  hashed.data = digest;
  TC_RSA_prepared_public_key prepared = {0};
  TC_RSA_word cache_words[128 / sizeof(TC_RSA_word)];
  TC_RSA_workspace cache = {cache_words, sizeof cache_words / sizeof *cache_words};
  TC_work_budget setup_work = {16 * sizeof modulus + 1};
  cache.capacity--;
  munit_assert_int(TC_RSA_prepare_public_key(&prepared, &key, &cache, &workspace, &setup_work), ==,
                   TC_RSA_LIMIT);
  munit_assert_uint(setup_work.remaining, ==, 16 * sizeof modulus + 1);
  cache.capacity++;
  cache.words = scratch;
  munit_assert_int(TC_RSA_prepare_public_key(&prepared, &key, &cache, &workspace, &setup_work), ==,
                   TC_RSA_ARGUMENT);
  cache.words = cache_words;
  munit_assert_int(TC_RSA_prepare_public_key(&prepared, &key, &cache, &workspace, &setup_work), ==,
                   TC_RSA_OK);
  munit_assert_uint(setup_work.remaining, ==, 0);
  TC_work_budget prepared_work = {10000};
  munit_assert_int(TC_RSA_verify_v15_prepared(&prepared, &options, hashed, signed_bytes, &workspace,
                                              &prepared_work),
                   ==, TC_RSA_INVALID);
  munit_assert_uint(prepared_work.remaining, ==, work.remaining + 16 * sizeof modulus);
  TC_RSA_word saved_cache[sizeof cache_words / sizeof *cache_words];
  memcpy(saved_cache, cache_words, sizeof saved_cache);
  TC_RSA_prepared_public_key_clear(&prepared);
  munit_assert_memory_equal(sizeof saved_cache, cache_words, saved_cache);
  munit_assert_int(TC_RSA_verify_v15_prepared(&prepared, &options, hashed, signed_bytes, &workspace,
                                              &prepared_work),
                   ==, TC_RSA_ARGUMENT);
  /* Clearing an uninitialized setup must not follow attacker-controlled
   * pointers. */
  memset(&prepared, 0xa5, sizeof prepared);
  TC_RSA_prepared_public_key_clear(&prepared);
  const TC_RSA_prepared_public_key zero_prepared = {0};
  munit_assert_memory_equal(sizeof prepared, &prepared, &zero_prepared);
  return MUNIT_OK;
}

/* A well-formed key of a size the library does not implement is
 * UNSUPPORTED, so X.509 reports it as unsupported rather than as a bad
 * signature. No work is charged. */
TC_TEST(unsupported_sizes)
{
  static uint8_t modulus[520], data[520], out[520];
  static TC_RSA_word scratch[9 * 4160 / TC_RSA_WORD_BITS + 2];
  const uint8_t exponent[] = {1, 0, 1};
  const size_t lengths[] = {96, 192, 520};
  uint8_t digest[32] = {0};
  memset(modulus, 0xff, sizeof modulus);
  for (size_t i = 0; i < sizeof lengths / sizeof *lengths; ++i) {
    const size_t length = lengths[i];
    const TC_RSA_public_key key = {{modulus, length}, {exponent, sizeof exponent}};
    const TC_RSA_workspace workspace = {scratch, sizeof scratch / sizeof *scratch};
    const TC_bytes signature = {data, length};
    const TC_RSA_v15_options v15 = {TC_HASH_SHA256};
    const TC_RSA_pss_options pss = {TC_HASH_SHA256, TC_HASH_SHA256, 32};
    TC_work_budget work = {100000};
    munit_assert_int(TC_RSA_verify_v15_digest(&key, &v15, (TC_bytes){digest, sizeof digest},
                                              signature, &workspace, &work),
                     ==, TC_RSA_UNSUPPORTED);
    munit_assert_int(TC_RSA_verify_pss_digest(&key, &pss, (TC_bytes){digest, sizeof digest},
                                              signature, &workspace, &work),
                     ==, TC_RSA_UNSUPPORTED);
    munit_assert_int(
        TC_RSA_raw_public(&key, signature, (TC_buffer){out, sizeof out}, &workspace, &work), ==,
        TC_RSA_UNSUPPORTED);
    munit_assert_uint32(work.remaining, ==, 100000);
  }
  return MUNIT_OK;
}

TC_TEST(ranges)
{
  enum { WORDS = 9 * 1024 / TC_RSA_WORD_BITS + 2 };
  union {
    TC_RSA_word words[WORDS];
    TC_RSA_public_key key;
    TC_RSA_workspace workspace;
  } shared;
  uint8_t modulus[128], exponent[] = {3}, digest[32] = {0}, signature[128] = {0};
  TC_RSA_public_key key = {{modulus, sizeof modulus}, {exponent, sizeof exponent}};
  TC_RSA_workspace workspace = {shared.words, WORDS};
  TC_bytes hashed = {digest, sizeof digest}, signed_bytes = {signature, sizeof signature};
  TC_bytes* inputs[] = {&key.modulus, &key.exponent, &hashed, &signed_bytes};
  uint8_t saved[sizeof shared];
  memset(modulus, 0xff, sizeof modulus);
  memset(&shared, 0xa5, sizeof shared);
  memcpy(saved, &shared, sizeof shared);
  for (size_t i = 0; i < sizeof inputs / sizeof *inputs; ++i) {
    TC_bytes original = *inputs[i];
    const TC_bytes invalid[] = {
        {NULL, 1}, {original.data, SIZE_MAX}, {(const uint8_t*)shared.words, 1}};
    for (size_t j = 0; j < sizeof invalid / sizeof *invalid; ++j) {
      *inputs[i] = invalid[j];
      munit_assert_int(verify(&key, TC_HASH_SHA256, hashed, signed_bytes, &workspace, 10000), ==,
                       TC_RSA_ARGUMENT);
      munit_assert_memory_equal(sizeof shared, &shared, saved);
    }
    *inputs[i] = original;
  }
  shared.key = key;
  memcpy(saved, &shared, sizeof shared);
  munit_assert_int(verify(&shared.key, TC_HASH_SHA256, hashed, signed_bytes, &workspace, 10000), ==,
                   TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof shared, &shared, saved);
  shared.workspace = workspace;
  memcpy(saved, &shared, sizeof shared);
  munit_assert_int(verify(&key, TC_HASH_SHA256, hashed, signed_bytes, &shared.workspace, 10000), ==,
                   TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof shared, &shared, saved);
#if TC_RSA_WORD_BITS == 32
  workspace.words = (TC_RSA_word*)((uint8_t*)shared.words + 1);
  munit_assert_int(verify(&key, TC_HASH_SHA256, hashed, signed_bytes, &workspace, 10000), ==,
                   TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof shared, &shared, saved);
#endif
  return MUNIT_OK;
}

/* One sizing function covers every operation and matches the static macros. */
TC_TEST(workspace_sizes)
{
  static const size_t sizes[] = {1024, 2048, 3072, 4096};
  for (size_t i = 0; i < sizeof sizes / sizeof *sizes; ++i) {
    const size_t bits = sizes[i];
    const size_t expected[] = {
        TC_RSA_VERIFY_WORKSPACE_WORDS(bits),     TC_RSA_ENCRYPT_WORKSPACE_WORDS(bits),
        TC_RSA_RAW_PUBLIC_WORKSPACE_WORDS(bits), TC_RSA_VALIDATE_WORKSPACE_WORDS(bits),
        TC_RSA_CRT_WORKSPACE_WORDS(bits),        TC_RSA_SIGN_WORKSPACE_WORDS(bits),
        TC_RSA_DECRYPT_WORKSPACE_WORDS(bits),    TC_RSA_RAW_PRIVATE_WORKSPACE_WORDS(bits),
        TC_RSA_KEYGEN_WORKSPACE_WORDS(bits)};
    for (unsigned op = TC_RSA_OPERATION_VERIFY; op <= TC_RSA_OPERATION_KEYGEN; ++op) {
      munit_assert_size(TC_RSA_workspace_words((TC_RSA_operation)op, bits), ==, expected[op]);
      munit_assert_size(TC_RSA_workspace_words((TC_RSA_operation)op, bits + 8), ==, 0);
    }
    munit_assert_size(TC_RSA_workspace_words((TC_RSA_operation)(TC_RSA_OPERATION_KEYGEN + 1), bits),
                      ==, 0);
  }
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_SIGN, 8192), ==, 0);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/arguments", arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/ranges", ranges, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/unsupported-sizes", unsupported_sizes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/workspace-sizes", workspace_sizes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/rsa/public", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
