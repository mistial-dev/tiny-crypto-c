/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#include "munit.h"
#include <string.h>

static TC_RSA_result verify(const TC_RSA_public_key* key, TC_hash_algorithm hash,
    TC_bytes digest, TC_bytes signature, const TC_RSA_workspace* workspace,
    uint32_t work)
{
  const TC_RSA_v15_options options = {hash};
  TC_work_budget budget = {work};
  return TC_RSA_verify_v15_digest(key,&options,digest,signature,workspace,&budget);
}

static MunitResult arguments(const MunitParameter params[], void* user)
{
  uint8_t modulus[128], exponent[] = {3}, digest[32] = {0}, signature[128] = {0};
  TC_RSA_word scratch[9 * 1024 / TC_RSA_WORD_BITS + 2];
  TC_RSA_public_key key = {{modulus,sizeof modulus},{exponent,sizeof exponent}};
  TC_RSA_workspace workspace = {scratch,sizeof scratch / sizeof *scratch};
  TC_bytes hashed = {digest,sizeof digest}, signed_bytes = {signature,sizeof signature};
  (void)params; (void)user;
  memset(modulus,0xff,sizeof modulus);
  munit_assert_size(TC_RSA_verify_workspace_words(1024), ==, workspace.capacity);
  munit_assert_size(TC_RSA_verify_workspace_words(2048), ==, 9 * 2048 / TC_RSA_WORD_BITS + 2);
  munit_assert_size(TC_RSA_verify_workspace_words(3072), ==, 9 * 3072 / TC_RSA_WORD_BITS + 2);
  munit_assert_size(TC_RSA_verify_workspace_words(SIZE_MAX), ==, 0);
  const TC_RSA_v15_options options = {TC_HASH_SHA256};
  TC_work_budget work = {10000};
  munit_assert_int(TC_RSA_verify_v15_digest(&key,&options,hashed,signed_bytes,
      &workspace,&work), ==, TC_RSA_INVALID);
  munit_assert_uint(work.remaining, <, 10000);
  munit_assert_int(verify(&key,TC_HASH_SHA256,hashed,signed_bytes,&workspace,0), ==, TC_RSA_LIMIT);
  munit_assert_int(verify(NULL,TC_HASH_SHA256,hashed,signed_bytes,&workspace,10000), ==, TC_RSA_ARGUMENT);
  workspace.capacity = SIZE_MAX;
  munit_assert_int(verify(&key,TC_HASH_SHA256,hashed,signed_bytes,&workspace,10000), ==, TC_RSA_ARGUMENT);
  workspace.capacity = sizeof scratch / sizeof *scratch - 1;
  munit_assert_int(verify(&key,TC_HASH_SHA256,hashed,signed_bytes,&workspace,10000), ==, TC_RSA_LIMIT);
  workspace.capacity++;
  hashed.data = (const uint8_t*)scratch;
  memset(scratch,0xa5,sizeof scratch);
  munit_assert_int(verify(&key,TC_HASH_SHA256,hashed,signed_bytes,&workspace,10000), ==, TC_RSA_ARGUMENT);
  for (size_t i = 0; i < sizeof scratch; ++i) munit_assert_uint(((uint8_t*)scratch)[i], ==, 0xa5);
  return MUNIT_OK;
}

static MunitResult ranges(const MunitParameter params[], void* user)
{
  enum { WORDS = 9 * 1024 / TC_RSA_WORD_BITS + 2 };
  union {
    TC_RSA_word words[WORDS];
    TC_RSA_public_key key;
    TC_RSA_workspace workspace;
  } shared;
  uint8_t modulus[128], exponent[] = {3}, digest[32] = {0}, signature[128] = {0};
  TC_RSA_public_key key = {{modulus,sizeof modulus},{exponent,sizeof exponent}};
  TC_RSA_workspace workspace = {shared.words,WORDS};
  TC_bytes hashed = {digest,sizeof digest}, signed_bytes = {signature,sizeof signature};
  TC_bytes* inputs[] = {&key.modulus,&key.exponent,&hashed,&signed_bytes};
  uint8_t saved[sizeof shared];
  (void)params; (void)user;
  memset(modulus,0xff,sizeof modulus); memset(&shared,0xa5,sizeof shared);
  memcpy(saved,&shared,sizeof shared);
  for (size_t i = 0; i < sizeof inputs / sizeof *inputs; ++i) {
    TC_bytes original = *inputs[i];
    const TC_bytes invalid[] = {
      {NULL,1}, {original.data,SIZE_MAX}, {(const uint8_t*)shared.words,1}
    };
    for (size_t j = 0; j < sizeof invalid / sizeof *invalid; ++j) {
      *inputs[i] = invalid[j];
      munit_assert_int(verify(&key,TC_HASH_SHA256,hashed,signed_bytes,&workspace,10000), ==, TC_RSA_ARGUMENT);
      munit_assert_memory_equal(sizeof shared,&shared,saved);
    }
    *inputs[i] = original;
  }
  shared.key = key;
  memcpy(saved,&shared,sizeof shared);
  munit_assert_int(verify(&shared.key,TC_HASH_SHA256,hashed,signed_bytes,&workspace,10000), ==, TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof shared,&shared,saved);
  shared.workspace = workspace;
  memcpy(saved,&shared,sizeof shared);
  munit_assert_int(verify(&key,TC_HASH_SHA256,hashed,signed_bytes,&shared.workspace,10000), ==, TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof shared,&shared,saved);
#if TC_RSA_WORD_BITS == 32
  workspace.words = (TC_RSA_word*)((uint8_t*)shared.words + 1);
  munit_assert_int(verify(&key,TC_HASH_SHA256,hashed,signed_bytes,&workspace,10000), ==, TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof shared,&shared,saved);
#endif
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/arguments",arguments,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/ranges",ranges,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/rsa/public",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
