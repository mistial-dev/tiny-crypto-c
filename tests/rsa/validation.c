/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#include "munit.h"
#include <string.h>

static TC_status random_bytes(void* context, uint8_t* output, size_t length)
{
  ++*(unsigned*)context;
  memset(output, 0, length);
  return TC_ERROR;
}

static TC_status deterministic_random(void* context, uint8_t* output, size_t length)
{
  uint32_t* state = context;
  for (size_t i = 0; i < length; ++i) {
    uint32_t value = *state;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    *state = value;
    output[i] = (uint8_t)value;
  }
  return TC_OK;
}

static int cancel_now(void* context)
{
  return *(const int*)context;
}

static TC_status repeated_random(void* context, uint8_t* output, size_t length)
{
  memset(output, *(const uint8_t*)context, length);
  return TC_OK;
}

static TC_RSA_result keygen_step(TC_RSA_keygen_state* state, TC_random_fn random, void* context,
                                 TC_RSA_cancel_fn cancel, void* cancel_context, uint32_t work)
{
  TC_work_budget budget = {work};
  return TC_RSA_keygen_step(state, (TC_random_source){random, context}, cancel, cancel_context,
                            &budget);
}

static TC_RSA_result validate_private_key(const TC_RSA_private_key* key, TC_random_fn random,
                                          void* context, size_t attempts,
                                          const TC_RSA_workspace* workspace, uint32_t work)
{
  TC_RSA_execution execution = {{random, context}, attempts, {work}};
  return TC_RSA_validate_private_key(key, TC_RSA_EXPONENT_FIPS, workspace, &execution);
}

static TC_RSA_result sign_v15(const TC_RSA_private_key* key, TC_hash_algorithm hash,
                              TC_bytes digest, TC_buffer output, const TC_RSA_workspace* workspace,
                              TC_RSA_execution execution)
{
  const TC_RSA_v15_options options = {hash};
  return TC_RSA_sign_v15_digest(key, &options, digest, workspace, output, &execution);
}

static TC_RSA_result sign_pss(const TC_RSA_private_key* key, TC_RSA_pss_options options,
                              TC_bytes digest, TC_buffer output, const TC_RSA_workspace* workspace,
                              TC_RSA_execution execution)
{
  return TC_RSA_sign_pss_digest(key, &options, digest, workspace, output, &execution);
}

static TC_RSA_result decrypt_oaep(const TC_RSA_private_key* key, TC_RSA_oaep_options options,
                                  TC_bytes ciphertext, TC_buffer output, size_t* length,
                                  const TC_RSA_workspace* workspace, TC_RSA_execution execution)
{
  return TC_RSA_decrypt_oaep(key, &options, ciphertext, workspace, output, length, &execution);
}

static MunitResult key_generation(const MunitParameter params[], void* user)
{
  enum {
    BITS = 1024,
    BYTES = BITS / 8,
    PRIME_BYTES = BYTES / 2,
    WORDS = TC_RSA_KEYGEN_WORKSPACE_WORDS(BITS),
    VALIDATE_WORDS = TC_RSA_VALIDATE_WORKSPACE_WORDS(BITS)
  };
  TC_RSA_word words[WORDS], validation_words[VALIDATE_WORDS];
  uint8_t modulus[BYTES], exponent[3], d[BYTES], p[PRIME_BYTES], q[PRIME_BYTES];
  TC_RSA_keygen_output output = {{modulus, sizeof modulus},
                                 {exponent, sizeof exponent},
                                 {d, sizeof d},
                                 {p, sizeof p},
                                 {q, sizeof q}};
  TC_RSA_workspace workspace = {words, WORDS};
  TC_RSA_keygen_state generation = {0};
  uint32_t rng = UINT32_C(0x6d2b79f5);
  (void)params;
  (void)user;
  memset(modulus, 0xa5, sizeof modulus);
  memset(exponent, 0xa5, sizeof exponent);
  memset(d, 0xa5, sizeof d);
  memset(p, 0xa5, sizeof p);
  memset(q, 0xa5, sizeof q);
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_KEYGEN, BITS), ==, WORDS);
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_KEYGEN, 2048), ==,
                    TC_RSA_KEYGEN_WORKSPACE_WORDS(2048));
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_KEYGEN, 3072), ==,
                    TC_RSA_KEYGEN_WORKSPACE_WORDS(3072));
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_KEYGEN, 4096), ==,
                    TC_RSA_KEYGEN_WORKSPACE_WORDS(4096));
  munit_assert_int(TC_RSA_keygen_init(&generation, BITS, &output,
                                      (TC_RSA_keygen_limits){4096, 16384}, &workspace),
                   ==, TC_RSA_OK);
  munit_assert_int(keygen_step(&generation, deterministic_random, &rng, NULL, NULL, 0), ==,
                   TC_RSA_IN_PROGRESS);
  for (size_t i = 0; i < sizeof modulus; ++i)
    munit_assert_uint(modulus[i], ==, 0xa5);
  TC_RSA_result status;
  do {
    status = keygen_step(&generation, deterministic_random, &rng, NULL, NULL, 50000);
  } while (status == TC_RSA_IN_PROGRESS);
  munit_assert_int(status, ==, TC_RSA_OK);
  const uint8_t expected_exponent[] = {1, 0, 1};
  munit_assert_memory_equal(3, exponent, expected_exponent);
  TC_RSA_private_key key = {{{modulus, sizeof modulus}, {exponent, sizeof exponent}},
                            {d, sizeof d},
                            {p, sizeof p},
                            {q, sizeof q},
                            NULL};
  TC_RSA_workspace validation = {validation_words, VALIDATE_WORDS};
  munit_assert_int(
      validate_private_key(&key, deterministic_random, &rng, 256, &validation, UINT32_MAX), ==,
      TC_RSA_OK);
  int cancelled = 1;
  memset(&generation, 0, sizeof generation);
  memset(words, 0xa5, sizeof words);
  munit_assert_int(
      TC_RSA_keygen_init(&generation, BITS, &output, (TC_RSA_keygen_limits){1, 1}, &workspace), ==,
      TC_RSA_OK);
  munit_assert_int(
      keygen_step(&generation, deterministic_random, &rng, cancel_now, &cancelled, UINT32_MAX), ==,
      TC_RSA_CANCELLED);
  for (size_t i = 0; i < sizeof words; ++i)
    munit_assert_uint(((uint8_t*)words)[i], ==, 0);
  uint8_t saved_modulus[sizeof modulus];
  memcpy(saved_modulus, modulus, sizeof modulus);
  memset(&generation, 0, sizeof generation);
  munit_assert_int(
      TC_RSA_keygen_init(&generation, BITS, &output, (TC_RSA_keygen_limits){1, 1}, &workspace), ==,
      TC_RSA_OK);
  unsigned failed_calls = 0;
  munit_assert_int(keygen_step(&generation, random_bytes, &failed_calls, NULL, NULL, UINT32_MAX),
                   ==, TC_RSA_ERROR);
  munit_assert_uint(failed_calls, ==, 1);
  munit_assert_memory_equal(sizeof modulus, modulus, saved_modulus);
  uint8_t repeated = 0xff;
  memset(&generation, 0, sizeof generation);
  munit_assert_int(
      TC_RSA_keygen_init(&generation, BITS, &output, (TC_RSA_keygen_limits){1, 2}, &workspace), ==,
      TC_RSA_OK);
  munit_assert_int(keygen_step(&generation, repeated_random, &repeated, NULL, NULL, UINT32_MAX), ==,
                   TC_RSA_LIMIT);
  munit_assert_memory_equal(sizeof modulus, modulus, saved_modulus);
  return MUNIT_OK;
}

/* Output buffers and scratch are sized by the caller. One byte or limb short
 * of the documented size is LIMIT, and a missing buffer is ARGUMENT. Both
 * leave the state, outputs and scratch unchanged. The exact sizes succeed. */
static MunitResult keygen_capacity(const MunitParameter params[], void* user)
{
  enum {
    BITS = 1024,
    BYTES = BITS / 8,
    PRIME_BYTES = BYTES / 2,
    WORDS = TC_RSA_KEYGEN_WORKSPACE_WORDS(BITS)
  };
  static TC_RSA_word words[WORDS];
  static uint8_t modulus[BYTES], exponent[3], d[BYTES], p[PRIME_BYTES], q[PRIME_BYTES];
  const TC_RSA_keygen_output exact = {{modulus, sizeof modulus},
                                      {exponent, sizeof exponent},
                                      {d, sizeof d},
                                      {p, sizeof p},
                                      {q, sizeof q}};
  const TC_RSA_workspace workspace = {words, WORDS};
  const TC_RSA_keygen_limits limits = {1, 1};
  TC_RSA_keygen_state state, state_before;
  (void)params;
  (void)user;
  memset(modulus, 0xa5, sizeof modulus);
  memset(exponent, 0xa5, sizeof exponent);
  memset(d, 0xa5, sizeof d);
  memset(p, 0xa5, sizeof p);
  memset(q, 0xa5, sizeof q);
  memset(words, 0xa5, sizeof words);
  memset(&state, 0, sizeof state);
  memcpy(&state_before, &state, sizeof state);
  for (size_t field = 0; field < 5; ++field) {
    for (int missing = 0; missing < 2; ++missing) {
      TC_RSA_keygen_output output = exact;
      TC_buffer* const buffers[] = {&output.modulus, &output.exponent, &output.d, &output.p,
                                    &output.q};
      if (missing)
        buffers[field]->data = NULL;
      else
        --buffers[field]->capacity;
      munit_assert_int(TC_RSA_keygen_init(&state, BITS, &output, limits, &workspace), ==,
                       missing ? TC_RSA_ARGUMENT : TC_RSA_LIMIT);
      /* A missing buffer is ARGUMENT whatever its capacity. */
      if (missing) {
        buffers[field]->capacity = 0;
        munit_assert_int(TC_RSA_keygen_init(&state, BITS, &output, limits, &workspace), ==,
                         TC_RSA_ARGUMENT);
      }
      munit_assert_memory_equal(sizeof state, &state, &state_before);
    }
  }
  const TC_RSA_workspace short_workspace = {words, WORDS - 1};
  munit_assert_int(TC_RSA_keygen_init(&state, BITS, &exact, limits, &short_workspace), ==,
                   TC_RSA_LIMIT);
  const TC_RSA_workspace no_words = {NULL, 0};
  munit_assert_int(TC_RSA_keygen_init(&state, BITS, &exact, limits, &no_words), ==,
                   TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof state, &state, &state_before);
  const uint8_t* const untouched[] = {modulus, exponent, d, p, q};
  const size_t untouched_size[] = {sizeof modulus, sizeof exponent, sizeof d, sizeof p, sizeof q};
  for (size_t buffer = 0; buffer < 5; ++buffer)
    for (size_t i = 0; i < untouched_size[buffer]; ++i)
      munit_assert_uint(untouched[buffer][i], ==, 0xa5);
  for (size_t i = 0; i < sizeof words; ++i)
    munit_assert_uint(((const uint8_t*)words)[i], ==, 0xa5);
  munit_assert_int(TC_RSA_keygen_init(&state, BITS, &exact, limits, &workspace), ==, TC_RSA_OK);
  TC_RSA_keygen_clear(&state);
  return MUNIT_OK;
}

/* The output metadata, the workspace descriptor and the state are disjoint
 * from the scratch limbs and from each other. Metadata inside scratch or the
 * state is ARGUMENT, and the scratch bytes stay unchanged. */
static MunitResult keygen_metadata_overlap(const MunitParameter params[], void* user)
{
  enum {
    BITS = 1024,
    BYTES = BITS / 8,
    PRIME_BYTES = BYTES / 2,
    WORDS = TC_RSA_KEYGEN_WORKSPACE_WORDS(BITS)
  };
  static union {
    TC_RSA_word words[WORDS];
    TC_RSA_keygen_output output;
    TC_RSA_workspace workspace;
  } scratch;
  static union {
    TC_RSA_keygen_state state;
    TC_RSA_keygen_output output;
  } shared;
  static uint8_t modulus[BYTES], exponent[3], d[BYTES], p[PRIME_BYTES], q[PRIME_BYTES];
  static uint8_t before[sizeof scratch];
  const TC_RSA_keygen_output exact = {{modulus, sizeof modulus},
                                      {exponent, sizeof exponent},
                                      {d, sizeof d},
                                      {p, sizeof p},
                                      {q, sizeof q}};
  const TC_RSA_workspace workspace = {scratch.words, WORDS};
  const TC_RSA_keygen_limits limits = {1, 1};
  TC_RSA_keygen_state state;
  (void)params;
  (void)user;
  memset(&state, 0, sizeof state);

  /* Output metadata stored in the scratch limbs. */
  memset(&scratch, 0xa5, sizeof scratch);
  scratch.output = exact;
  memcpy(before, &scratch, sizeof scratch);
  munit_assert_int(TC_RSA_keygen_init(&state, BITS, &scratch.output, limits, &workspace), ==,
                   TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof scratch, &scratch, before);
  munit_assert_uint32(state.marker, ==, 0);

  /* Workspace descriptor stored in the scratch limbs. */
  memset(&scratch, 0xa5, sizeof scratch);
  scratch.workspace = workspace;
  memcpy(before, &scratch, sizeof scratch);
  munit_assert_int(TC_RSA_keygen_init(&state, BITS, &exact, limits, &scratch.workspace), ==,
                   TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof scratch, &scratch, before);
  munit_assert_uint32(state.marker, ==, 0);

  /* Output metadata stored in the state. */
  memset(&scratch, 0xa5, sizeof scratch);
  memset(&shared, 0, sizeof shared);
  shared.output = exact;
  munit_assert_int(TC_RSA_keygen_init(&shared.state, BITS, &shared.output, limits, &workspace), ==,
                   TC_RSA_ARGUMENT);
  munit_assert_ptr_equal(shared.output.modulus.data, modulus);
  for (size_t i = 0; i < sizeof scratch; ++i)
    munit_assert_uint(((const uint8_t*)&scratch)[i], ==, 0xa5);

  munit_assert_int(TC_RSA_keygen_init(&state, BITS, &exact, limits, &workspace), ==, TC_RSA_OK);
  TC_RSA_keygen_clear(&state);
  return MUNIT_OK;
}

static MunitResult ranges(const MunitParameter params[], void* user)
{
  enum { BYTES = 128, WORDS = TC_RSA_VALIDATE_WORKSPACE_WORDS(BYTES * 8) };
  union {
    TC_RSA_word words[WORDS];
    TC_RSA_private_key key;
    TC_RSA_workspace workspace;
  } shared;
  uint8_t modulus[BYTES], exponent[] = {3}, d[BYTES] = {0}, p[BYTES] = {0}, q[BYTES] = {0};
  TC_RSA_private_key key = {{{modulus, sizeof modulus}, {exponent, sizeof exponent}},
                            {d, sizeof d},
                            {p, sizeof p},
                            {q, sizeof q},
                            NULL};
  TC_RSA_workspace workspace = {shared.words, WORDS};
  TC_bytes* components[] = {&key.public_key.modulus, &key.public_key.exponent, &key.d, &key.p,
                            &key.q};
  uint8_t saved[sizeof shared];
  unsigned calls = 0;
  (void)params;
  (void)user;
  memset(modulus, 0xff, sizeof modulus);
  memset(&shared, 0xa5, sizeof shared);
  memcpy(saved, &shared, sizeof shared);
  for (size_t i = 0; i < sizeof components / sizeof *components; ++i) {
    TC_bytes original = *components[i];
    const TC_bytes invalid[] = {
        {NULL, original.length},
        {original.data, SIZE_MAX},
        {(const uint8_t*)shared.words, original.length},
        {(const uint8_t*)shared.words + sizeof shared.words - 1, original.length}};
    for (size_t j = 0; j < sizeof invalid / sizeof *invalid; ++j) {
      *components[i] = invalid[j];
      munit_assert_int(validate_private_key(&key, random_bytes, &calls, TC_RSA_VALIDATION_ROUNDS,
                                            &workspace, UINT32_MAX),
                       ==, TC_RSA_ARGUMENT);
      munit_assert_memory_equal(sizeof shared, &shared, saved);
    }
    *components[i] = original;
  }
  uint8_t oversized[BYTES + 1] = {0}, digest[32] = {0}, output[BYTES];
  TC_bytes* private_components[] = {&key.d, &key.p, &key.q};
  for (size_t i = 0; i < sizeof private_components / sizeof *private_components; ++i) {
    const TC_bytes original = *private_components[i];
    const TC_bytes invalid[] = {{original.data, 0}, {oversized, sizeof oversized}};
    for (size_t j = 0; j < sizeof invalid / sizeof *invalid; ++j) {
      *private_components[i] = invalid[j];
      size_t recovered = SIZE_MAX;
      memset(output, 0xa5, sizeof output);
      munit_assert_int(validate_private_key(&key, random_bytes, &calls, TC_RSA_VALIDATION_ROUNDS,
                                            &workspace, UINT32_MAX),
                       ==, TC_RSA_INVALID);
      munit_assert_int(sign_v15(&key, TC_HASH_SHA256, (TC_bytes){digest, sizeof digest},
                                (TC_buffer){output, sizeof output}, &workspace,
                                (TC_RSA_execution){{random_bytes, &calls}, 1, {UINT32_MAX}}),
                       ==, TC_RSA_INVALID);
      munit_assert_int(
          sign_pss(&key, (TC_RSA_pss_options){TC_HASH_SHA256, TC_HASH_SHA256, sizeof digest},
                   (TC_bytes){digest, sizeof digest}, (TC_buffer){output, sizeof output},
                   &workspace, (TC_RSA_execution){{random_bytes, &calls}, 1, {UINT32_MAX}}),
          ==, TC_RSA_INVALID);
      munit_assert_int(
          decrypt_oaep(
              &key, (TC_RSA_oaep_options){TC_HASH_SHA256, TC_HASH_SHA256, (TC_bytes){NULL, 0}},
              (TC_bytes){modulus, sizeof modulus}, (TC_buffer){output, sizeof output}, &recovered,
              &workspace, (TC_RSA_execution){{random_bytes, &calls}, 1, {UINT32_MAX}}),
          ==, TC_RSA_INVALID);
      munit_assert_size(recovered, ==, SIZE_MAX);
      munit_assert_memory_equal(sizeof shared, &shared, saved);
      for (size_t k = 0; k < sizeof output; ++k)
        munit_assert_uint(output[k], ==, 0xa5);
    }
    *private_components[i] = original;
  }
  shared.key = key;
  memcpy(saved, &shared, sizeof shared);
  munit_assert_int(validate_private_key(&shared.key, random_bytes, &calls, TC_RSA_VALIDATION_ROUNDS,
                                        &workspace, UINT32_MAX),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof shared, &shared, saved);
  shared.workspace = workspace;
  memcpy(saved, &shared, sizeof shared);
  munit_assert_int(validate_private_key(&key, random_bytes, &calls, TC_RSA_VALIDATION_ROUNDS,
                                        &shared.workspace, UINT32_MAX),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof shared, &shared, saved);
  for (unsigned scenario = 0; scenario < 6; ++scenario) {
    TC_RSA_workspace storage = workspace;
    if (scenario == 3)
      storage.words = NULL;
    if (scenario == 4)
      storage.capacity = SIZE_MAX;
    if (scenario == 5)
      --storage.capacity;
    munit_assert_int(validate_private_key(
                         scenario == 0 ? NULL : &key, scenario == 1 ? NULL : random_bytes, &calls,
                         TC_RSA_VALIDATION_ROUNDS, scenario == 2 ? NULL : &storage, UINT32_MAX),
                     ==, scenario == 5 ? TC_RSA_LIMIT : TC_RSA_ARGUMENT);
    munit_assert_memory_equal(sizeof shared, &shared, saved);
  }
#if TC_RSA_WORD_BITS == 32
  workspace.words = (TC_RSA_word*)((uint8_t*)shared.words + 1);
  munit_assert_int(validate_private_key(&key, random_bytes, &calls, TC_RSA_VALIDATION_ROUNDS,
                                        &workspace, UINT32_MAX),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof shared, &shared, saved);
#endif
  munit_assert_uint(calls, ==, 0);
  return MUNIT_OK;
}

static MunitResult operation_ranges(const MunitParameter params[], void* user)
{
  enum { BYTES = 128, WORDS = TC_RSA_SIGN_WORKSPACE_WORDS(BYTES * 8) };
  struct {
    TC_RSA_word scratch[WORDS];
    uint8_t modulus[BYTES], exponent[1], d[BYTES], p[BYTES], q[BYTES];
    uint8_t digest[32], signature[BYTES];
    TC_RSA_private_key key;
    TC_RSA_workspace workspace;
  } fixture;
  memset(&fixture, 0, sizeof fixture);
  memset(fixture.modulus, 0xff, sizeof fixture.modulus);
  fixture.exponent[0] = 3;
  fixture.d[BYTES - 1] = 3;
  fixture.key =
      (TC_RSA_private_key){{{fixture.modulus, BYTES}, {fixture.exponent, sizeof fixture.exponent}},
                           {fixture.d, BYTES},
                           {fixture.p, BYTES},
                           {fixture.q, BYTES},
                           NULL};
  fixture.workspace = (TC_RSA_workspace){fixture.scratch, WORDS};
  uint8_t saved[sizeof fixture];
  memcpy(saved, &fixture, sizeof fixture);
  unsigned calls = 0;
  uint8_t* aliases[] = {fixture.modulus,
                        fixture.exponent,
                        fixture.d,
                        fixture.p,
                        fixture.q,
                        fixture.digest,
                        (uint8_t*)fixture.scratch,
                        (uint8_t*)&fixture.key,
                        (uint8_t*)&fixture.workspace};
  (void)params;
  (void)user;
  for (size_t i = 0; i < sizeof aliases / sizeof *aliases; ++i) {
    munit_assert_int(sign_v15(&fixture.key, TC_HASH_SHA256,
                              (TC_bytes){fixture.digest, sizeof fixture.digest},
                              (TC_buffer){aliases[i], BYTES}, &fixture.workspace,
                              (TC_RSA_execution){{random_bytes, &calls}, 1, {10000}}),
                     ==, TC_RSA_ARGUMENT);
    munit_assert_memory_equal(sizeof fixture, &fixture, saved);
  }
  const struct {
    TC_hash_algorithm hash;
    TC_bytes digest;
    size_t length, attempts, work;
    TC_RSA_result result;
  } invalid[] = {{TC_HASH_UNKNOWN, {fixture.digest, 32}, BYTES, 1, 10000, TC_RSA_UNSUPPORTED},
                 {TC_HASH_SHA256, {NULL, 32}, BYTES, 1, 10000, TC_RSA_ARGUMENT},
                 {TC_HASH_SHA256, {fixture.digest, 31}, BYTES, 1, 10000, TC_RSA_ARGUMENT},
                 {TC_HASH_SHA256, {fixture.digest, SIZE_MAX}, BYTES, 1, 10000, TC_RSA_ARGUMENT},
                 {TC_HASH_SHA256, {fixture.digest, 32}, BYTES - 1, 1, 10000, TC_RSA_LIMIT},
                 {TC_HASH_SHA256, {fixture.digest, 32}, SIZE_MAX, 1, 10000, TC_RSA_ARGUMENT},
                 {TC_HASH_SHA256, {fixture.digest, 32}, BYTES, 0, 10000, TC_RSA_LIMIT},
                 {TC_HASH_SHA256, {fixture.digest, 32}, BYTES, 1, 0, TC_RSA_LIMIT}};
  for (size_t i = 0; i < sizeof invalid / sizeof *invalid; ++i) {
    munit_assert_int(sign_v15(&fixture.key, invalid[i].hash, invalid[i].digest,
                              (TC_buffer){fixture.signature, invalid[i].length}, &fixture.workspace,
                              (TC_RSA_execution){
                                  {random_bytes, &calls}, invalid[i].attempts, {invalid[i].work}}),
                     ==, invalid[i].result);
    munit_assert_memory_equal(sizeof fixture, &fixture, saved);
  }
  munit_assert_int(sign_v15(&fixture.key, TC_HASH_SHA256,
                            (TC_bytes){fixture.digest, sizeof fixture.digest},
                            (TC_buffer){NULL, BYTES}, &fixture.workspace,
                            (TC_RSA_execution){{random_bytes, &calls}, 1, {10000}}),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof fixture, &fixture, saved);
  size_t recovered = SIZE_MAX;
  const TC_bytes label = {fixture.digest, sizeof fixture.digest};
  const TC_bytes ciphertext = {fixture.modulus, sizeof fixture.modulus};
  for (size_t i = 0; i < sizeof aliases / sizeof *aliases; ++i) {
    munit_assert_int(
        decrypt_oaep(&fixture.key, (TC_RSA_oaep_options){TC_HASH_SHA256, TC_HASH_SHA256, label},
                     ciphertext, (TC_buffer){aliases[i], BYTES}, &recovered, &fixture.workspace,
                     (TC_RSA_execution){{random_bytes, &calls}, 1, {10000}}),
        ==, TC_RSA_ARGUMENT);
    munit_assert_size(recovered, ==, SIZE_MAX);
    munit_assert_memory_equal(sizeof fixture, &fixture, saved);
    /* Select an aligned address so the overlap check is exercised directly. */
    if (aliases[i] != fixture.exponent) {
      uintptr_t address = (uintptr_t)aliases[i];
      address += (sizeof(size_t) - address % sizeof(size_t)) % sizeof(size_t);
      munit_assert_int(
          decrypt_oaep(&fixture.key, (TC_RSA_oaep_options){TC_HASH_SHA256, TC_HASH_SHA256, label},
                       ciphertext, (TC_buffer){fixture.signature, BYTES}, (size_t*)address,
                       &fixture.workspace, (TC_RSA_execution){{random_bytes, &calls}, 1, {10000}}),
          ==, TC_RSA_ARGUMENT);
      munit_assert_memory_equal(sizeof fixture, &fixture, saved);
    }
  }
  uintptr_t output_address = (uintptr_t)fixture.signature;
  output_address += (sizeof(size_t) - output_address % sizeof(size_t)) % sizeof(size_t);
  size_t* invalid_lengths[] = {NULL, (size_t*)output_address, (size_t*)((uint8_t*)&recovered + 1)};
  for (size_t i = 0; i < sizeof invalid_lengths / sizeof *invalid_lengths; ++i) {
    munit_assert_int(
        decrypt_oaep(&fixture.key, (TC_RSA_oaep_options){TC_HASH_SHA256, TC_HASH_SHA256, label},
                     ciphertext, (TC_buffer){fixture.signature, BYTES}, invalid_lengths[i],
                     &fixture.workspace, (TC_RSA_execution){{random_bytes, &calls}, 1, {10000}}),
        ==, TC_RSA_ARGUMENT);
    munit_assert_size(recovered, ==, SIZE_MAX);
    munit_assert_memory_equal(sizeof fixture, &fixture, saved);
  }
  munit_assert_uint(calls, ==, 0);
  return MUNIT_OK;
}

/* FIPS 186-5 A.1.1: e is odd and 2^16 < e < 2^256. */
static MunitResult exponent_range(const MunitParameter params[], void* user)
{
  static const uint8_t e3[] = {3}, e65535[] = {0xff, 0xff}, e65536[] = {1, 0, 0};
  static const uint8_t e65537[] = {1, 0, 1}, padded[] = {0, 0, 1, 0, 1}, even[] = {1, 0, 2};
  uint8_t top[32], over[33] = {1};
  (void)params;
  (void)user;
  memset(top, 0xff, sizeof top);
  over[32] = 1;
  munit_assert_int(TC_RSA_exponent_in_fips_range((TC_bytes){e3, sizeof e3}), ==, 0);
  munit_assert_int(TC_RSA_exponent_in_fips_range((TC_bytes){e65535, sizeof e65535}), ==, 0);
  munit_assert_int(TC_RSA_exponent_in_fips_range((TC_bytes){e65536, sizeof e65536}), ==, 0);
  munit_assert_int(TC_RSA_exponent_in_fips_range((TC_bytes){e65537, sizeof e65537}), ==, 1);
  munit_assert_int(TC_RSA_exponent_in_fips_range((TC_bytes){padded, sizeof padded}), ==, 1);
  munit_assert_int(TC_RSA_exponent_in_fips_range((TC_bytes){even, sizeof even}), ==, 0);
  munit_assert_int(TC_RSA_exponent_in_fips_range((TC_bytes){top, sizeof top}), ==, 1);
  munit_assert_int(TC_RSA_exponent_in_fips_range((TC_bytes){over, sizeof over}), ==, 0);
  munit_assert_int(TC_RSA_exponent_in_fips_range((TC_bytes){NULL, 0}), ==, 0);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/key-generation", key_generation, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/keygen-capacity", keygen_capacity, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/keygen-metadata-overlap", keygen_metadata_overlap, NULL, NULL, MUNIT_TEST_OPTION_NONE,
       NULL},
      {"/exponent-range", exponent_range, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/ranges", ranges, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/operation-ranges", operation_ranges, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/rsa/validation", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
