/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/rsa_oaep_internal.h"
#include "munit.h"

enum { WIDTH = 256, MAX_DIGEST = 64, WORK_BUDGET = 100000 };

static MunitResult algorithms(const MunitParameter params[], void* user)
{
  uint8_t encoded[WIDTH], saved[WIDTH], seed[MAX_DIGEST] = {0}, block[MAX_DIGEST];
  tc_hash_workspace workspace;
  const TC_bytes empty = {NULL,0};
  (void)params; (void)user;
  for (unsigned h = TC_HASH_UNKNOWN; h <= TC_HASH_SHA512; ++h) {
    for (unsigned mgf = TC_HASH_UNKNOWN; mgf <= TC_HASH_SHA512; ++mgf) {
      const TC_hash_algorithm hash = (TC_hash_algorithm)h, mask = (TC_hash_algorithm)mgf;
      tc_hash_info info;
      const int available = tc_hash_available(hash) && tc_hash_available(mask);
      const size_t seed_length = tc_hash_info_get(hash,&info) ? info.digest_length : 0;
      size_t work = WORK_BUDGET;
      memset(encoded,0xa5,sizeof encoded); memcpy(saved,encoded,sizeof saved);
      munit_assert_int(tc_rsa_oaep_encode(encoded,sizeof encoded,hash,mask,empty,empty,
          (TC_bytes){seed,seed_length},block,&workspace,&work), ==,
          available ? TC_RSA_OK : TC_RSA_UNSUPPORTED);
      if (!available) {
        munit_assert_size(work, ==, WORK_BUDGET);
        munit_assert_memory_equal(sizeof encoded,encoded,saved);
      }
      TC_bytes message = {saved,sizeof saved};
      work = WORK_BUDGET;
      munit_assert_int(tc_rsa_oaep_decode(encoded,sizeof encoded,hash,mask,empty,
          block,&workspace,&work,&message), ==, available ? TC_RSA_OK : TC_RSA_UNSUPPORTED);
      if (!available) {
        munit_assert_size(work, ==, WORK_BUDGET);
        munit_assert_memory_equal(sizeof encoded,encoded,saved);
        munit_assert_ptr_equal(message.data,saved);
        munit_assert_size(message.length, ==, sizeof saved);
      } else munit_assert_size(message.length, ==, 0);
    }
  }
  return MUNIT_OK;
}

static MunitResult missing_storage(const MunitParameter params[], void* user)
{
  enum { ENCODED, LABEL, SEED, BLOCK, WORKSPACE, WORK, OUTPUT, MESSAGE, CASE_COUNT };
  uint8_t encoded[WIDTH], saved[WIDTH], seed[32] = {0}, block[MAX_DIGEST];
  tc_hash_workspace workspace;
  (void)params; (void)user;
  for (unsigned missing = 0; missing < CASE_COUNT; ++missing) {
    size_t work = WORK_BUDGET;
    TC_bytes message = {saved,sizeof saved};
    memset(encoded,0xa5,sizeof encoded); memcpy(saved,encoded,sizeof saved);
    const TC_bytes label = {NULL,missing == LABEL ? 1 : 0};
    if (missing != OUTPUT) {
      munit_assert_int(tc_rsa_oaep_encode(missing == ENCODED ? NULL : encoded,sizeof encoded,
          TC_HASH_SHA256,TC_HASH_SHA256,label,(TC_bytes){NULL,missing == MESSAGE ? 1 : 0},
          (TC_bytes){missing == SEED ? NULL : seed,sizeof seed},missing == BLOCK ? NULL : block,
          missing == WORKSPACE ? NULL : &workspace,missing == WORK ? NULL : &work), ==, TC_RSA_ARGUMENT);
    }
    if (missing != SEED && missing != MESSAGE) {
      munit_assert_int(tc_rsa_oaep_decode(missing == ENCODED ? NULL : encoded,sizeof encoded,
          TC_HASH_SHA256,TC_HASH_SHA256,label,missing == BLOCK ? NULL : block,
          missing == WORKSPACE ? NULL : &workspace,missing == WORK ? NULL : &work,
          missing == OUTPUT ? NULL : &message), ==, TC_RSA_ARGUMENT);
    }
    munit_assert_size(work, ==, WORK_BUDGET);
    munit_assert_memory_equal(sizeof encoded,encoded,saved);
    munit_assert_ptr_equal(message.data,saved);
    munit_assert_size(message.length, ==, sizeof saved);
  }
  return MUNIT_OK;
}

static MunitResult limits(const MunitParameter params[], void* user)
{
  uint8_t encoded[WIDTH], seed[32] = {0}, block[MAX_DIGEST];
  tc_hash_workspace workspace;
  const TC_bytes empty = {NULL,0};
  TC_bytes message = empty;
  (void)params; (void)user;
  if (!tc_hash_available(TC_HASH_SHA256)) return MUNIT_SKIP;
  size_t work = WORK_BUDGET;
  munit_assert_int(tc_rsa_oaep_encode(encoded,sizeof encoded,TC_HASH_SHA256,TC_HASH_SHA256,
      empty,empty,(TC_bytes){seed,sizeof seed - 1},block,&workspace,&work), ==, TC_RSA_ARGUMENT);
  work = SIZE_MAX;
  munit_assert_int(tc_rsa_oaep_decode(encoded,SIZE_MAX,TC_HASH_SHA256,TC_HASH_SHA256,
      empty,block,&workspace,&work,&message), ==, TC_RSA_LIMIT);
  munit_assert_size(work, ==, SIZE_MAX);
  work = WORK_BUDGET;
  munit_assert_int(tc_rsa_oaep_decode(encoded,2 * sizeof seed + 1,TC_HASH_SHA256,TC_HASH_SHA256,
      empty,block,&workspace,&work,&message), ==, TC_RSA_INVALID);
  if ((uint64_t)SIZE_MAX > (UINT64_MAX >> 3)) {
    /* The hash rejects an overflowing label length before reading its bytes. */
    const TC_bytes oversized = {seed,(size_t)((UINT64_MAX >> 3) + 1)};
    work = SIZE_MAX;
    munit_assert_int(tc_rsa_oaep_encode(encoded,sizeof encoded,TC_HASH_SHA256,TC_HASH_SHA256,
        oversized,empty,(TC_bytes){seed,sizeof seed},block,&workspace,&work), ==, TC_RSA_ARGUMENT);
  }
  munit_assert_null(message.data); munit_assert_size(message.length, ==, 0);
  return MUNIT_OK;
}

static TC_status unexpected_random(void* context, uint8_t* output, size_t length)
{
  (void)output; (void)length;
  ++*(size_t*)context;
  return TC_ERROR;
}

static MunitResult encryption_arguments(const MunitParameter params[], void* user)
{
  enum { NULL_KEY, NULL_WORKSPACE, NULL_WORDS, NULL_OUTPUT, NULL_RANDOM,
    NULL_MESSAGE, NULL_LABEL, NULL_MODULUS, NULL_EXPONENT, SCRATCH_MESSAGE,
    SCRATCH_OUTPUT, OUTPUT_KEY, OUTPUT_WORKSPACE, OUTPUT_MODULUS, OUTPUT_EXPONENT,
    OUTPUT_MESSAGE, OUTPUT_LABEL, OVERFLOW_WORKSPACE, OVERFLOW_LABEL, CASE_COUNT };
  uint8_t modulus[WIDTH], exponent[] = {3}, input[WIDTH], output[WIDTH];
  TC_RSA_word words[TC_RSA_ENCRYPT_WORKSPACE_WORDS(WIDTH * 8)];
  (void)params; (void)user;
  for (unsigned bad = 0; bad < CASE_COUNT; ++bad) {
    memset(modulus,0xff,sizeof modulus);
    memset(input,0xa5,sizeof input); memset(output,0xa5,sizeof output);
    memset(words,0xa5,sizeof words);
    TC_RSA_public_key key = {{modulus,sizeof modulus},{exponent,sizeof exponent}};
    TC_RSA_workspace workspace = {words,sizeof words / sizeof *words};
    TC_bytes message = {input,1}, label = {input + 8,1};
    uint8_t* ciphertext = output;
    size_t calls = 0;
    switch (bad) {
      case NULL_WORDS: workspace.words = NULL; break;
      case NULL_OUTPUT: ciphertext = NULL; break;
      case NULL_MESSAGE: message.data = NULL; break;
      case NULL_LABEL: label.data = NULL; break;
      case NULL_MODULUS: key.modulus.data = NULL; break;
      case NULL_EXPONENT: key.exponent.data = NULL; break;
      case SCRATCH_MESSAGE: message.data = (const uint8_t*)words; break;
      case SCRATCH_OUTPUT: ciphertext = (uint8_t*)words; break;
      case OUTPUT_KEY: ciphertext = (uint8_t*)&key; break;
      case OUTPUT_WORKSPACE: ciphertext = (uint8_t*)&workspace; break;
      case OUTPUT_MODULUS: ciphertext = modulus; break;
      case OUTPUT_EXPONENT: ciphertext = exponent; break;
      case OUTPUT_MESSAGE: ciphertext = input; break;
      case OUTPUT_LABEL: ciphertext = input + 8; break;
      case OVERFLOW_WORKSPACE: workspace.capacity = SIZE_MAX; break;
      case OVERFLOW_LABEL: label.length = SIZE_MAX; break;
      default: break;
    }
    const TC_RSA_public_key saved_key = key;
    const TC_RSA_workspace saved_workspace = workspace;
    const TC_RSA_oaep_options options = {TC_HASH_SHA256,TC_HASH_SHA256,label};
    TC_RSA_execution execution = {
      {bad == NULL_RANDOM ? NULL : unexpected_random,&calls},0,{WORK_BUDGET}
    };
    munit_assert_int(TC_RSA_encrypt_oaep(bad == NULL_KEY ? NULL : &key,
        &options,message,bad == NULL_WORKSPACE ? NULL : &workspace,
        (TC_buffer){ciphertext,WIDTH},&execution), ==, TC_RSA_ARGUMENT);
    munit_assert_size(calls, ==, 0);
    munit_assert_memory_equal(sizeof key,&key,&saved_key);
    munit_assert_memory_equal(sizeof workspace,&workspace,&saved_workspace);
    munit_assert_uint(exponent[0], ==, 3);
    for (size_t i = 0; i < WIDTH; ++i) {
      munit_assert_uint(modulus[i], ==, 0xff);
      munit_assert_uint(input[i], ==, 0xa5);
      munit_assert_uint(output[i], ==, 0xa5);
    }
    const uint8_t* scratch = (const uint8_t*)words;
    for (size_t i = 0; i < sizeof words; ++i) munit_assert_uint(scratch[i], ==, 0xa5);
  }
  return MUNIT_OK;
}

static MunitResult encryption_algorithms(const MunitParameter params[], void* user)
{
  uint8_t modulus[WIDTH], exponent[] = {3}, output[WIDTH];
  TC_RSA_word words[TC_RSA_ENCRYPT_WORKSPACE_WORDS(WIDTH * 8)];
  const TC_RSA_public_key key = {{modulus,sizeof modulus},{exponent,sizeof exponent}};
  const TC_RSA_workspace workspace = {words,sizeof words / sizeof *words};
  (void)params; (void)user;
  memset(modulus,0xff,sizeof modulus);
  for (unsigned h = TC_HASH_UNKNOWN; h <= TC_HASH_SHA512; ++h) {
    for (unsigned mgf = TC_HASH_UNKNOWN; mgf <= TC_HASH_SHA512; ++mgf) {
      const TC_hash_algorithm hash = (TC_hash_algorithm)h, mask = (TC_hash_algorithm)mgf;
      const int available = tc_hash_available(hash) && tc_hash_available(mask);
      size_t calls = 0;
      const TC_RSA_oaep_options options = {hash,mask,{NULL,0}};
      TC_RSA_execution execution = {{unexpected_random,&calls},0,{WORK_BUDGET}};
      memset(output,0xa5,sizeof output); memset(words,0xa5,sizeof words);
      munit_assert_int(TC_RSA_encrypt_oaep(&key,&options,(TC_bytes){NULL,0},
          &workspace,(TC_buffer){output,sizeof output},&execution), ==,
          available ? TC_RSA_ERROR : TC_RSA_UNSUPPORTED);
      munit_assert_size(calls, ==, available ? 1 : 0);
      for (size_t i = 0; i < sizeof output; ++i) munit_assert_uint(output[i], ==, 0xa5);
      const uint8_t* scratch = (const uint8_t*)words;
      for (size_t i = 0; i < sizeof words; ++i)
        munit_assert_uint(scratch[i], ==, available ? 0 : 0xa5);
    }
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/algorithms",algorithms,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/missing-storage",missing_storage,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/limits",limits,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/encryption-arguments",encryption_arguments,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/encryption-algorithms",encryption_algorithms,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/rsa/oaep",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
