/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Work contracts, output-capacity statuses and argument ordering for the
 * public RSA operations. Each published cost is exact: the cost succeeds with
 * nothing left over and one unit less returns TC_RSA_LIMIT. */
#include <tiny_crypto/rsa.h>
#include "munit.h"
#include "test_util.h"
#include <string.h>

enum {
  BITS = 1024,
  BYTES = BITS / 8,
  PRIME_BYTES = BYTES / 2,
  WORDS = TC_RSA_SIGN_WORKSPACE_WORDS(BITS),
  KEYGEN_WORDS = TC_RSA_KEYGEN_WORKSPACE_WORDS(BITS),
  SHA256_BYTES = 32
};

typedef struct {
  uint8_t modulus[BYTES], exponent[3], d[BYTES], p[PRIME_BYTES], q[PRIME_BYTES];
  uint8_t dp[PRIME_BYTES], dq[PRIME_BYTES], q_inverse[PRIME_BYTES];
  TC_RSA_crt crt;
  TC_RSA_private_key key;
} test_key;

static TC_status xorshift_random(void* context, uint8_t* output, size_t length)
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

/* Every request returns the value 2, a blinding factor accepted on the first
 * attempt, and counts the call. */
static TC_status two_random(void* context, uint8_t* output, size_t length)
{
  ++*(unsigned*)context;
  memset(output, 0, length);
  if (length)
    output[length - 1] = 2;
  return TC_OK;
}

/* A deterministic RSA-1024 key with CRT values. */
static const test_key* key_fixture(void)
{
  static test_key fixture;
  static int ready;
  if (ready)
    return &fixture;
  static TC_RSA_word words[KEYGEN_WORDS];
  TC_RSA_keygen_output output = {{fixture.modulus, sizeof fixture.modulus},
                                 {fixture.exponent, sizeof fixture.exponent},
                                 {fixture.d, sizeof fixture.d},
                                 {fixture.p, sizeof fixture.p},
                                 {fixture.q, sizeof fixture.q}};
  TC_RSA_workspace workspace = {words, KEYGEN_WORDS};
  TC_RSA_keygen_state state = {0};
  uint32_t rng = UINT32_C(0x2545f491);
  munit_assert_int(
      TC_RSA_keygen_init(&state, BITS, &output, (TC_RSA_keygen_limits){4096, 16384}, &workspace),
      ==, TC_RSA_OK);
  TC_RSA_result status;
  do {
    TC_work_budget budget = {50000};
    status =
        TC_RSA_keygen_step(&state, (TC_random_source){xorshift_random, &rng}, NULL, NULL, &budget);
  } while (status == TC_RSA_IN_PROGRESS);
  munit_assert_int(status, ==, TC_RSA_OK);
  TC_RSA_keygen_clear(&state);
  fixture.key = (TC_RSA_private_key){{{fixture.modulus, BYTES}, {fixture.exponent, 3}},
                                     {fixture.d, BYTES},
                                     {fixture.p, PRIME_BYTES},
                                     {fixture.q, PRIME_BYTES},
                                     NULL};
  static TC_RSA_word crt_words[TC_RSA_CRT_WORKSPACE_WORDS(BITS)];
  const TC_RSA_crt_output crt_output = {
      {fixture.dp, PRIME_BYTES}, {fixture.dq, PRIME_BYTES}, {fixture.q_inverse, PRIME_BYTES}};
  TC_work_budget work = {UINT32_MAX};
  munit_assert_int(
      TC_RSA_derive_crt(&fixture.key, &crt_output,
                        &(TC_RSA_workspace){crt_words, TC_RSA_CRT_WORKSPACE_WORDS(BITS)}, &work),
      ==, TC_RSA_OK);
  fixture.crt = (TC_RSA_crt){
      {fixture.dp, PRIME_BYTES}, {fixture.dq, PRIME_BYTES}, {fixture.q_inverse, PRIME_BYTES}};
  ready = 1;
  return &fixture;
}

static int all_bytes(const uint8_t* data, size_t length, uint8_t value)
{
  for (size_t i = 0; i < length; ++i)
    if (data[i] != value)
      return 0;
  return 1;
}

TC_TEST(modulus_supported)
{
  static const size_t supported[] = {1024, 2048, 3072, 4096};
  static const size_t unsupported[] = {0, 8, 1016, 1023, 1025, 1536, 4104, 8192, SIZE_MAX};
  for (size_t i = 0; i < sizeof supported / sizeof *supported; ++i)
    munit_assert_int(TC_RSA_modulus_supported(supported[i]), ==, 1);
  for (size_t i = 0; i < sizeof unsupported / sizeof *unsupported; ++i)
    munit_assert_int(TC_RSA_modulus_supported(unsupported[i]), ==, 0);
  return MUNIT_OK;
}

/* TC_RSA_encode_*_work is the exact cost of a successful encoding. */
TC_TEST(encode_work)
{
  static const TC_hash_algorithm hashes[] = {TC_HASH_SHA1, TC_HASH_SHA224, TC_HASH_SHA256,
                                             TC_HASH_SHA384, TC_HASH_SHA512};
  static const size_t digest_lengths[] = {20, 28, 32, 48, 64};
  static const size_t sizes[] = {128, 256, 384, 512};
  uint8_t digest[64] = {0}, salt[64] = {0}, encoded[512], saved[512];
  for (size_t h = 0; h < sizeof hashes / sizeof *hashes; ++h) {
    const TC_bytes hashed = {digest, digest_lengths[h]};
    for (size_t s = 0; s < sizeof sizes / sizeof *sizes; ++s) {
      const size_t length = sizes[s];
      const TC_RSA_v15_options v15 = {hashes[h]};
      const uint32_t v15_cost = TC_RSA_encode_v15_work(&v15, length);
      munit_assert_size(v15_cost, ==, length);
      TC_work_budget work = {v15_cost};
      munit_assert_int(TC_RSA_encode_v15_digest(&v15, hashed, (TC_buffer){encoded, length}, &work),
                       ==, TC_RSA_OK);
      munit_assert_uint32(work.remaining, ==, 0);
      memset(encoded, 0xa5, sizeof encoded);
      memcpy(saved, encoded, sizeof saved);
      work.remaining = v15_cost - 1;
      munit_assert_int(TC_RSA_encode_v15_digest(&v15, hashed, (TC_buffer){encoded, length}, &work),
                       ==, TC_RSA_LIMIT);
      munit_assert_uint32(work.remaining, ==, v15_cost - 1);
      munit_assert_memory_equal(sizeof encoded, encoded, saved);

      /* The salt is one digest long, or the largest salt the modulus allows. */
      const size_t largest_salt = length - digest_lengths[h] - 2;
      const size_t salt_length =
          digest_lengths[h] < largest_salt ? digest_lengths[h] : largest_salt;
      const TC_RSA_pss_options pss = {hashes[h], TC_HASH_SHA256, salt_length};
      const uint32_t pss_cost = TC_RSA_encode_pss_work(&pss, length);
      munit_assert_size(pss_cost, >, length);
      const TC_bytes salted = {salt, salt_length};
      work.remaining = pss_cost;
      munit_assert_int(
          TC_RSA_encode_pss_digest(&pss, hashed, salted, (TC_buffer){encoded, length}, &work), ==,
          TC_RSA_OK);
      munit_assert_uint32(work.remaining, ==, 0);
      memset(encoded, 0xa5, sizeof encoded);
      work.remaining = pss_cost - 1;
      munit_assert_int(
          TC_RSA_encode_pss_digest(&pss, hashed, salted, (TC_buffer){encoded, length}, &work), ==,
          TC_RSA_LIMIT);
      munit_assert_uint32(work.remaining, ==, pss_cost - 1);
      munit_assert_memory_equal(sizeof encoded, encoded, saved);
    }
  }
  /* Unknown hashes, unsupported sizes and oversized salts have no cost. */
  const TC_RSA_v15_options unknown_v15 = {TC_HASH_UNKNOWN};
  const TC_RSA_v15_options sha256_v15 = {TC_HASH_SHA256};
  munit_assert_uint32(TC_RSA_encode_v15_work(NULL, 128), ==, 0);
  munit_assert_uint32(TC_RSA_encode_v15_work(&unknown_v15, 128), ==, 0);
  munit_assert_uint32(TC_RSA_encode_v15_work(&sha256_v15, 127), ==, 0);
  munit_assert_uint32(TC_RSA_encode_v15_work(&sha256_v15, 192), ==, 0);
  const TC_RSA_pss_options unknown_pss = {TC_HASH_UNKNOWN, TC_HASH_SHA256, 32};
  const TC_RSA_pss_options unknown_mgf = {TC_HASH_SHA256, TC_HASH_UNKNOWN, 32};
  const TC_RSA_pss_options largest_salt = {TC_HASH_SHA512, TC_HASH_SHA256, 128 - 64 - 2};
  const TC_RSA_pss_options oversized_salt = {TC_HASH_SHA512, TC_HASH_SHA256, 128 - 64 - 1};
  munit_assert_uint32(TC_RSA_encode_pss_work(NULL, 128), ==, 0);
  munit_assert_uint32(TC_RSA_encode_pss_work(&unknown_pss, 128), ==, 0);
  munit_assert_uint32(TC_RSA_encode_pss_work(&unknown_mgf, 128), ==, 0);
  munit_assert_uint32(TC_RSA_encode_pss_work(&largest_salt, 128), >, 0);
  munit_assert_uint32(TC_RSA_encode_pss_work(&oversized_salt, 128), ==, 0);
  munit_assert_uint32(TC_RSA_encode_pss_work(&largest_salt, 100), ==, 0);

  /* The work budget is written, so it must not overlap the digest or options. */
  union {
    TC_work_budget work;
    uint8_t bytes[SHA256_BYTES];
  } shared = {{UINT32_MAX}};
  const TC_RSA_v15_options overlapping_options[] = {{TC_HASH_SHA256}};
  memset(encoded, 0xa5, sizeof encoded);
  munit_assert_int(TC_RSA_encode_v15_digest(&sha256_v15, (TC_bytes){shared.bytes, SHA256_BYTES},
                                            (TC_buffer){encoded, 128}, &shared.work),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_uint32(shared.work.remaining, ==, UINT32_MAX);
  munit_assert_int(TC_RSA_encode_v15_digest(overlapping_options, (TC_bytes){digest, SHA256_BYTES},
                                            (TC_buffer){encoded, 128},
                                            (TC_work_budget*)(void*)overlapping_options),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_true(all_bytes(encoded, sizeof encoded, 0xa5));
  /* An output range that wraps the address space is a caller error. */
  TC_work_budget wrap_work = {UINT32_MAX};
  uint8_t* const wrapping = (uint8_t*)(UINTPTR_MAX - 63u);
  munit_assert_int(TC_RSA_encode_v15_digest(&sha256_v15, (TC_bytes){digest, SHA256_BYTES},
                                            (TC_buffer){wrapping, 128}, &wrap_work),
                   ==, TC_RSA_ARGUMENT);
  const TC_RSA_pss_options sha256_pss = {TC_HASH_SHA256, TC_HASH_SHA256, 0};
  munit_assert_int(TC_RSA_encode_pss_digest(&sha256_pss, (TC_bytes){digest, SHA256_BYTES},
                                            (TC_bytes){NULL, 0}, (TC_buffer){wrapping, 128},
                                            &wrap_work),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_uint32(wrap_work.remaining, ==, UINT32_MAX);
  return MUNIT_OK;
}

/* Public-key costs: raw, one-shot and prepared verification, and OAEP
 * encryption. */
TC_TEST(public_work)
{
  const test_key* fixture = key_fixture();
  const TC_RSA_public_key* key = &fixture->key.public_key;
  static TC_RSA_word scratch[WORDS];
  const TC_RSA_workspace workspace = {scratch, WORDS};
  uint8_t input[BYTES] = {0}, output[BYTES], saved[BYTES], digest[SHA256_BYTES] = {0};
  uint8_t signature[BYTES];
  input[BYTES - 1] = 7;
  const uint32_t public_cost = TC_RSA_public_work(key);
  munit_assert_uint32(public_cost, ==, 16 * BYTES + 16 * 3 + 4);
  for (unsigned short_work = 0; short_work < 2; ++short_work) {
    TC_work_budget work = {public_cost - short_work};
    memset(output, 0xa5, sizeof output);
    memcpy(saved, output, sizeof saved);
    munit_assert_int(TC_RSA_raw_public(key, (TC_bytes){input, BYTES}, (TC_buffer){output, BYTES},
                                       &workspace, &work),
                     ==, short_work ? TC_RSA_LIMIT : TC_RSA_OK);
    munit_assert_uint32(work.remaining, ==, short_work ? public_cost - 1 : 0);
    if (short_work)
      munit_assert_memory_equal(sizeof output, output, saved);
  }

  /* Sign a digest to verify below. */
  unsigned calls = 0;
  TC_RSA_execution signing = {{two_random, &calls}, 1, {UINT32_MAX}};
  const TC_RSA_v15_options v15 = {TC_HASH_SHA256};
  munit_assert_int(TC_RSA_sign_v15_digest(&fixture->key, &v15, (TC_bytes){digest, sizeof digest},
                                          (TC_buffer){signature, BYTES}, &workspace, &signing),
                   ==, TC_RSA_OK);
  const uint32_t verify_cost = public_cost + TC_RSA_encode_v15_work(&v15, BYTES);
  for (unsigned short_work = 0; short_work < 2; ++short_work) {
    TC_work_budget work = {verify_cost - short_work};
    munit_assert_int(TC_RSA_verify_v15_digest(key, &v15, (TC_bytes){digest, sizeof digest},
                                              (TC_bytes){signature, BYTES}, &workspace, &work),
                     ==, short_work ? TC_RSA_LIMIT : TC_RSA_OK);
    munit_assert_uint32(work.remaining, ==, short_work ? verify_cost - 1 : 0);
  }

  TC_RSA_word cache_words[BYTES / sizeof(TC_RSA_word)];
  TC_RSA_prepared_public_key setup = {0};
  munit_assert_uint32(TC_RSA_prepared_public_work(&setup), ==, 0);
  munit_assert_uint32(TC_RSA_prepared_public_work(NULL), ==, 0);
  TC_work_budget setup_work = {16 * BYTES + 1};
  munit_assert_int(TC_RSA_prepare_public_key(
                       &setup, key, &(TC_RSA_workspace){cache_words, BYTES / sizeof(TC_RSA_word)},
                       &workspace, &setup_work),
                   ==, TC_RSA_OK);
  const uint32_t prepared_cost = TC_RSA_prepared_public_work(&setup);
  munit_assert_uint32(prepared_cost, ==, public_cost - 16 * BYTES);
  for (unsigned short_work = 0; short_work < 2; ++short_work) {
    TC_work_budget work = {prepared_cost + BYTES - short_work};
    munit_assert_int(TC_RSA_verify_v15_prepared(&setup, &v15, (TC_bytes){digest, sizeof digest},
                                                (TC_bytes){signature, BYTES}, &workspace, &work),
                     ==, short_work ? TC_RSA_LIMIT : TC_RSA_OK);
    munit_assert_uint32(work.remaining, ==, short_work ? prepared_cost + BYTES - 1 : 0);
  }
  TC_RSA_prepared_public_key_clear(&setup);

  /* PSS verification costs the public operation plus the PSS encoding. */
  const TC_RSA_pss_options pss = {TC_HASH_SHA256, TC_HASH_SHA256, SHA256_BYTES};
  munit_assert_int(TC_RSA_sign_pss_digest(&fixture->key, &pss, (TC_bytes){digest, sizeof digest},
                                          (TC_buffer){signature, BYTES}, &workspace, &signing),
                   ==, TC_RSA_OK);
  const uint32_t pss_cost = public_cost + TC_RSA_encode_pss_work(&pss, BYTES);
  for (unsigned short_work = 0; short_work < 2; ++short_work) {
    TC_work_budget work = {pss_cost - short_work};
    munit_assert_int(TC_RSA_verify_pss_digest(key, &pss, (TC_bytes){digest, sizeof digest},
                                              (TC_bytes){signature, BYTES}, &workspace, &work),
                     ==, short_work ? TC_RSA_LIMIT : TC_RSA_OK);
    munit_assert_uint32(work.remaining, ==, short_work ? pss_cost - 1 : 0);
  }

  /* OAEP encryption: one RNG request, the padding and the public operation.
   * A short budget fails before the seed request. */
  const uint8_t label[] = {'l', 'a', 'b', 'e', 'l'};
  const TC_RSA_oaep_options oaep = {TC_HASH_SHA256, TC_HASH_SHA256, {label, sizeof label}};
  const uint32_t encrypt_cost = 1 + TC_RSA_oaep_work(&oaep, BYTES) + public_cost;
  for (unsigned short_work = 0; short_work < 2; ++short_work) {
    calls = 0;
    TC_RSA_execution execution = {{two_random, &calls}, 0, {encrypt_cost - short_work}};
    memset(output, 0xa5, sizeof output);
    munit_assert_int(TC_RSA_encrypt_oaep(key, &oaep, (TC_bytes){input, 16},
                                         (TC_buffer){output, BYTES}, &workspace, &execution),
                     ==, short_work ? TC_RSA_LIMIT : TC_RSA_OK);
    munit_assert_uint32(execution.work.remaining, ==, short_work ? encrypt_cost - 1 : 0);
    munit_assert_uint(calls, ==, short_work ? 0 : 1);
    if (short_work)
      munit_assert_memory_equal(sizeof output, output, saved);
  }

  /* Keys the operations reject have no cost. */
  uint8_t even[BYTES];
  memcpy(even, fixture->modulus, BYTES);
  even[BYTES - 1] &= 0xfe;
  munit_assert_uint32(TC_RSA_public_work(NULL), ==, 0);
  munit_assert_uint32(TC_RSA_public_work(&(TC_RSA_public_key){{even, BYTES}, key->exponent}), ==,
                      0);
  munit_assert_uint32(
      TC_RSA_public_work(&(TC_RSA_public_key){{fixture->modulus, 96}, key->exponent}), ==, 0);
  return MUNIT_OK;
}

/* OAEP padding covers both masks and has the same cost for encoding and
 * decoding. */
TC_TEST(oaep_work)
{
  const TC_RSA_oaep_options sha256 = {TC_HASH_SHA256, TC_HASH_SHA256, {NULL, 0}};
  const TC_RSA_oaep_options sha1_mgf = {TC_HASH_SHA256, TC_HASH_SHA1, {NULL, 0}};
  /* D = L - H - 1 = 95, ceil(D/G) = 3 and ceil(H/G) = 1 for SHA-256. */
  munit_assert_uint32(TC_RSA_oaep_work(&sha256, 128), ==,
                      (128 + 0 + 1) + (95 + 3 * (32 + 5)) + (32 + 1 * (95 + 5)));
  /* G = 20 gives ceil(95/20) = 5 and ceil(32/20) = 2. */
  munit_assert_uint32(TC_RSA_oaep_work(&sha1_mgf, 128), ==,
                      (128 + 0 + 1) + (95 + 5 * (32 + 5)) + (32 + 2 * (95 + 5)));
  const TC_RSA_oaep_options unknown = {TC_HASH_UNKNOWN, TC_HASH_SHA256, {NULL, 0}};
  const TC_RSA_oaep_options sha512 = {TC_HASH_SHA512, TC_HASH_SHA512, {NULL, 0}};
  munit_assert_uint32(TC_RSA_oaep_work(NULL, 128), ==, 0);
  munit_assert_uint32(TC_RSA_oaep_work(&unknown, 128), ==, 0);
  munit_assert_uint32(TC_RSA_oaep_work(&sha256, 100), ==, 0);
  munit_assert_uint32(TC_RSA_oaep_work(&sha512, 128), ==, 0);
  munit_assert_uint32(TC_RSA_oaep_work(&sha512, 256), >, 0);
  const TC_RSA_oaep_options huge_label = {
      TC_HASH_SHA256, TC_HASH_SHA256, {(const uint8_t*)"", UINT32_MAX}};
  munit_assert_uint32(TC_RSA_oaep_work(&huge_label, 128), ==, 0);
  return MUNIT_OK;
}

/* The first request returns 0, a rejected blinding factor, and later
 * requests return 2. */
static TC_status reject_once_random(void* context, uint8_t* output, size_t length)
{
  unsigned* calls = context;
  if (!*calls) {
    ++*calls;
    memset(output, 0, length);
    return TC_OK;
  }
  return two_random(context, output, length);
}

/* TC_RSA_private_work(key, A) covers every allowed blinding attempt. A budget
 * one unit short fails before the first request or private operation. */
TC_TEST(rejected_blinding)
{
  const test_key* fixture = key_fixture();
  static TC_RSA_word scratch[WORDS];
  const TC_RSA_workspace workspace = {scratch, WORDS};
  uint8_t digest[SHA256_BYTES] = {0}, signature[BYTES];
  const TC_RSA_v15_options v15 = {TC_HASH_SHA256};
  for (unsigned use_crt = 0; use_crt < 2; ++use_crt) {
    TC_RSA_private_key key = fixture->key;
    key.crt = use_crt ? &fixture->crt : NULL;
    const uint32_t cost = TC_RSA_private_work(&key, 2) + TC_RSA_encode_v15_work(&v15, BYTES);
    for (unsigned short_work = 0; short_work < 2; ++short_work) {
      unsigned calls = 0;
      TC_RSA_execution execution = {{reject_once_random, &calls}, 2, {cost - short_work}};
      memset(signature, 0xa5, sizeof signature);
      munit_assert_int(TC_RSA_sign_v15_digest(&key, &v15, (TC_bytes){digest, sizeof digest},
                                              (TC_buffer){signature, BYTES}, &workspace,
                                              &execution),
                       ==, short_work ? TC_RSA_LIMIT : TC_RSA_OK);
      munit_assert_uint(calls, ==, short_work ? 0 : 2);
      if (short_work) {
        munit_assert_true(all_bytes(signature, sizeof signature, 0xa5));
        munit_assert_true(all_bytes((const uint8_t*)scratch, sizeof scratch, 0));
      } else
        munit_assert_uint32(execution.work.remaining, ==, 0);
    }
    /* One attempt allowed: the rejected factor exhausts it. */
    unsigned calls = 0;
    TC_RSA_execution execution = {{reject_once_random, &calls}, 1, {cost}};
    munit_assert_int(TC_RSA_sign_v15_digest(&key, &v15, (TC_bytes){digest, sizeof digest},
                                            (TC_buffer){signature, BYTES}, &workspace, &execution),
                     ==, TC_RSA_LIMIT);
    munit_assert_uint(calls, ==, 1);
  }
  return MUNIT_OK;
}

/* Private-key costs for full-width and CRT keys: signing, raw private
 * operations and OAEP decryption. A short budget fails before any RNG
 * request. */
TC_TEST(private_work)
{
  const test_key* fixture = key_fixture();
  static TC_RSA_word scratch[WORDS];
  const TC_RSA_workspace workspace = {scratch, WORDS};
  uint8_t digest[SHA256_BYTES] = {0}, signature[BYTES], saved[BYTES], input[BYTES] = {0};
  input[BYTES - 1] = 9;
  for (unsigned use_crt = 0; use_crt < 2; ++use_crt) {
    TC_RSA_private_key key = fixture->key;
    key.crt = use_crt ? &fixture->crt : NULL;
    const uint32_t per_attempt = 16 * BYTES + 1;
    const uint32_t base = use_crt ? 48 * BYTES + 32 * 3 + 12 : 32 * BYTES + 32 * 3 + 8;
    munit_assert_uint32(TC_RSA_private_work(&key, 1), ==, base + per_attempt);
    munit_assert_uint32(TC_RSA_private_work(&key, 4), ==, base + 4 * per_attempt);
    munit_assert_uint32(TC_RSA_private_work(&key, 0), ==, 0);
    munit_assert_uint32(TC_RSA_private_work(&key, SIZE_MAX), ==, 0);
    const uint32_t private_cost = TC_RSA_private_work(&key, 4);

    const TC_RSA_v15_options v15 = {TC_HASH_SHA256};
    const TC_RSA_pss_options pss = {TC_HASH_SHA256, TC_HASH_SHA256, SHA256_BYTES};
    const uint32_t costs[] = {private_cost + TC_RSA_encode_v15_work(&v15, BYTES),
                              private_cost + TC_RSA_encode_pss_work(&pss, BYTES) + 1};
    for (unsigned scheme = 0; scheme < 2; ++scheme) {
      for (unsigned short_work = 0; short_work < 2; ++short_work) {
        unsigned calls = 0;
        TC_RSA_execution execution = {{two_random, &calls}, 4, {costs[scheme] - short_work}};
        memset(signature, 0xa5, sizeof signature);
        memcpy(saved, signature, sizeof saved);
        const TC_RSA_result result =
            scheme ? TC_RSA_sign_pss_digest(&key, &pss, (TC_bytes){digest, sizeof digest},
                                            (TC_buffer){signature, BYTES}, &workspace, &execution)
                   : TC_RSA_sign_v15_digest(&key, &v15, (TC_bytes){digest, sizeof digest},
                                            (TC_buffer){signature, BYTES}, &workspace, &execution);
        munit_assert_int(result, ==, short_work ? TC_RSA_LIMIT : TC_RSA_OK);
        munit_assert_uint32(execution.work.remaining, ==,
                            short_work ? costs[scheme] - 1 : 3 * per_attempt);
        munit_assert_uint(calls, ==, short_work ? 0 : 1 + scheme);
        if (short_work)
          munit_assert_memory_equal(sizeof signature, signature, saved);
      }
    }

    /* OAEP decryption: the private operation plus the padding. */
    const TC_RSA_oaep_options oaep = {TC_HASH_SHA256, TC_HASH_SHA256, {NULL, 0}};
    uint8_t ciphertext[BYTES], plaintext[BYTES], message[16] = {1, 2, 3};
    unsigned calls = 0;
    TC_RSA_execution encryption = {{two_random, &calls}, 0, {UINT32_MAX}};
    munit_assert_int(TC_RSA_encrypt_oaep(&key.public_key, &oaep,
                                         (TC_bytes){message, sizeof message},
                                         (TC_buffer){ciphertext, BYTES}, &workspace, &encryption),
                     ==, TC_RSA_OK);
    const uint32_t decrypt_cost = private_cost + TC_RSA_oaep_work(&oaep, BYTES);
    for (unsigned short_work = 0; short_work < 2; ++short_work) {
      calls = 0;
      size_t length = SIZE_MAX;
      TC_RSA_execution execution = {{two_random, &calls}, 4, {decrypt_cost - short_work}};
      munit_assert_int(TC_RSA_decrypt_oaep(&key, &oaep, (TC_bytes){ciphertext, BYTES},
                                           (TC_buffer){plaintext, sizeof plaintext}, &length,
                                           &workspace, &execution),
                       ==, short_work ? TC_RSA_LIMIT : TC_RSA_OK);
      munit_assert_uint32(execution.work.remaining, ==,
                          short_work ? decrypt_cost - 1 : 3 * per_attempt);
      munit_assert_uint(calls, ==, short_work ? 0 : 1);
      munit_assert_size(length, ==, short_work ? SIZE_MAX : sizeof message);
      if (!short_work)
        munit_assert_memory_equal(sizeof message, plaintext, message);
    }
  }

  /* A raw private operation costs TC_RSA_private_work for a key without CRT
   * values. */
  const TC_RSA_private_key public_only = {
      fixture->key.public_key, {NULL, 0}, {NULL, 0}, {NULL, 0}, NULL};
  const uint32_t raw_cost = TC_RSA_private_work(&public_only, 1);
  munit_assert_uint32(raw_cost, ==, TC_RSA_private_work(&fixture->key, 1));
  for (unsigned short_work = 0; short_work < 2; ++short_work) {
    unsigned calls = 0;
    TC_RSA_execution execution = {{two_random, &calls}, 1, {raw_cost - short_work}};
    munit_assert_int(TC_RSA_raw_private(&fixture->key.public_key, fixture->key.d,
                                        (TC_bytes){input, BYTES}, (TC_buffer){signature, BYTES},
                                        &workspace, &execution),
                     ==, short_work ? TC_RSA_LIMIT : TC_RSA_OK);
    munit_assert_uint32(execution.work.remaining, ==, short_work ? raw_cost - 1 : 0);
  }
  munit_assert_uint32(TC_RSA_private_work(NULL, 1), ==, 0);
  return MUNIT_OK;
}

/* A short caller output buffer returns TC_RSA_LIMIT before any work or RNG
 * use. A larger buffer is accepted and receives exactly modulus_bytes. */
TC_TEST(output_capacity)
{
  const test_key* fixture = key_fixture();
  static TC_RSA_word scratch[WORDS];
  const TC_RSA_workspace workspace = {scratch, WORDS};
  uint8_t digest[SHA256_BYTES] = {0}, output[BYTES + 1], input[BYTES] = {0};
  const TC_RSA_v15_options v15 = {TC_HASH_SHA256};
  const TC_RSA_pss_options pss = {TC_HASH_SHA256, TC_HASH_SHA256, SHA256_BYTES};
  const TC_RSA_oaep_options oaep = {TC_HASH_SHA256, TC_HASH_SHA256, {NULL, 0}};
  input[BYTES - 1] = 5;
  enum { SIGN_V15, SIGN_PSS, ENCRYPT, RAW_PUBLIC, RAW_PRIVATE, OPERATION_COUNT };
  for (unsigned operation = 0; operation < OPERATION_COUNT; ++operation) {
    for (unsigned larger = 0; larger < 2; ++larger) {
      const size_t capacity = larger ? BYTES + 1 : BYTES - 1;
      unsigned calls = 0;
      TC_RSA_execution execution = {{two_random, &calls}, 1, {UINT32_MAX}};
      memset(output, 0xa5, sizeof output);
      const TC_buffer buffer = {output, capacity};
      TC_RSA_result result = TC_RSA_ERROR;
      switch (operation) {
      case SIGN_V15:
        result = TC_RSA_sign_v15_digest(&fixture->key, &v15, (TC_bytes){digest, sizeof digest},
                                        buffer, &workspace, &execution);
        break;
      case SIGN_PSS:
        result = TC_RSA_sign_pss_digest(&fixture->key, &pss, (TC_bytes){digest, sizeof digest},
                                        buffer, &workspace, &execution);
        break;
      case ENCRYPT:
        result = TC_RSA_encrypt_oaep(&fixture->key.public_key, &oaep, (TC_bytes){input, 8}, buffer,
                                     &workspace, &execution);
        break;
      case RAW_PUBLIC:
        result = TC_RSA_raw_public(&fixture->key.public_key, (TC_bytes){input, BYTES}, buffer,
                                   &workspace, &execution.work);
        break;
      default:
        result = TC_RSA_raw_private(&fixture->key.public_key, fixture->key.d,
                                    (TC_bytes){input, BYTES}, buffer, &workspace, &execution);
        break;
      }
      munit_assert_int(result, ==, larger ? TC_RSA_OK : TC_RSA_LIMIT);
      if (larger) {
        munit_assert_false(all_bytes(output, BYTES, 0xa5));
        munit_assert_uint(output[BYTES], ==, 0xa5);
      } else {
        munit_assert_true(all_bytes(output, sizeof output, 0xa5));
        munit_assert_uint32(execution.work.remaining, ==, UINT32_MAX);
        munit_assert_uint(calls, ==, 0);
      }
    }
  }
  return MUNIT_OK;
}

/* NULL and overlapping storage outrank every data check. Key and parameter
 * problems outrank received-data checks, and all of them outrank limits. */
TC_TEST(argument_order)
{
  const test_key* fixture = key_fixture();
  static TC_RSA_word scratch[WORDS];
  const TC_RSA_workspace workspace = {scratch, WORDS};
  uint8_t digest[SHA256_BYTES] = {0}, signature[BYTES + 1] = {0}, output[BYTES];
  const TC_RSA_public_key* key = &fixture->key.public_key;
  const TC_RSA_v15_options v15 = {TC_HASH_SHA256};
  const TC_RSA_pss_options pss = {TC_HASH_SHA256, TC_HASH_SHA256, SHA256_BYTES};
  const TC_RSA_oaep_options oaep = {TC_HASH_SHA256, TC_HASH_SHA256, {NULL, 0}};
  uint8_t even[BYTES];
  memcpy(even, fixture->modulus, BYTES);
  even[BYTES - 1] &= 0xfe;
  const TC_RSA_public_key invalid_key = {{even, BYTES}, key->exponent};
  unsigned calls = 0;

  /* A NULL digest with a wrong signature length. */
  TC_work_budget work = {UINT32_MAX};
  const TC_bytes no_digest = {NULL, sizeof digest};
  const TC_bytes long_signature = {signature, BYTES + 1};
  munit_assert_int(
      TC_RSA_verify_pss_digest(key, &pss, no_digest, long_signature, &workspace, &work), ==,
      TC_RSA_ARGUMENT);
  munit_assert_int(
      TC_RSA_verify_v15_digest(key, &v15, no_digest, long_signature, &workspace, &work), ==,
      TC_RSA_ARGUMENT);
  /* A NULL signature with an invalid key. */
  munit_assert_int(TC_RSA_verify_pss_digest(&invalid_key, &pss, (TC_bytes){digest, sizeof digest},
                                            (TC_bytes){NULL, BYTES}, &workspace, &work),
                   ==, TC_RSA_ARGUMENT);
  /* A digest of the wrong length with an invalid key or a wrong signature
   * length. */
  const TC_bytes short_digest = {digest, sizeof digest - 1};
  munit_assert_int(TC_RSA_verify_pss_digest(&invalid_key, &pss, short_digest,
                                            (TC_bytes){signature, BYTES}, &workspace, &work),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_int(
      TC_RSA_verify_v15_digest(key, &v15, short_digest, long_signature, &workspace, &work), ==,
      TC_RSA_ARGUMENT);
  /* An invalid key outranks a wrong signature length. */
  munit_assert_int(TC_RSA_verify_v15_digest(&invalid_key, &v15, (TC_bytes){digest, sizeof digest},
                                            long_signature, &workspace, &work),
                   ==, TC_RSA_INVALID);
  /* Public exponents below 3 and even exponents are invalid keys. */
  for (uint8_t value = 0; value < 5; ++value) {
    if (value == 3)
      continue;
    const TC_RSA_public_key small_exponent = {key->modulus, {&value, 1}};
    munit_assert_int(TC_RSA_raw_public(&small_exponent, (TC_bytes){signature, BYTES},
                                       (TC_buffer){output, sizeof output}, &workspace, &work),
                     ==, TC_RSA_INVALID);
    munit_assert_uint32(TC_RSA_public_work(&small_exponent), ==, 0);
  }
  /* A wrong signature length outranks an exhausted budget. */
  TC_work_budget empty = {0};
  munit_assert_int(TC_RSA_verify_pss_digest(key, &pss, (TC_bytes){digest, sizeof digest},
                                            long_signature, &workspace, &empty),
                   ==, TC_RSA_INVALID);
  munit_assert_uint32(work.remaining, ==, UINT32_MAX);

  /* Signing: a NULL digest with a short signature buffer, and a NULL output
   * with an invalid key. */
  TC_RSA_execution execution = {{two_random, &calls}, 1, {UINT32_MAX}};
  memset(output, 0xa5, sizeof output);
  munit_assert_int(TC_RSA_sign_pss_digest(&fixture->key, &pss, no_digest,
                                          (TC_buffer){output, BYTES - 1}, &workspace, &execution),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_int(TC_RSA_sign_v15_digest(&fixture->key, &v15, no_digest,
                                          (TC_buffer){output, BYTES - 1}, &workspace, &execution),
                   ==, TC_RSA_ARGUMENT);
  TC_RSA_private_key broken = fixture->key;
  broken.public_key = invalid_key;
  munit_assert_int(TC_RSA_sign_v15_digest(&broken, &v15, (TC_bytes){digest, sizeof digest},
                                          (TC_buffer){NULL, BYTES}, &workspace, &execution),
                   ==, TC_RSA_ARGUMENT);
  /* A wrong digest length outranks an invalid key, which outranks a short
   * buffer. */
  munit_assert_int(TC_RSA_sign_v15_digest(&broken, &v15, short_digest,
                                          (TC_buffer){output, BYTES - 1}, &workspace, &execution),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_int(TC_RSA_sign_v15_digest(&broken, &v15, (TC_bytes){digest, sizeof digest},
                                          (TC_buffer){output, BYTES - 1}, &workspace, &execution),
                   ==, TC_RSA_INVALID);

  /* Decryption: a NULL ciphertext with a wrong length, and a wrong
   * ciphertext length before a short plaintext buffer. */
  size_t length = SIZE_MAX;
  munit_assert_int(TC_RSA_decrypt_oaep(&fixture->key, &oaep, (TC_bytes){NULL, BYTES + 1},
                                       (TC_buffer){output, sizeof output}, &length, &workspace,
                                       &execution),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_int(TC_RSA_decrypt_oaep(&fixture->key, &oaep, long_signature, (TC_buffer){output, 1},
                                       &length, &workspace, &execution),
                   ==, TC_RSA_INVALID);
  /* A missing RNG callback is an argument error. */
  TC_RSA_execution no_random = {{NULL, &calls}, 1, {UINT32_MAX}};
  munit_assert_int(TC_RSA_raw_private(key, fixture->key.d, (TC_bytes){signature, BYTES},
                                      (TC_buffer){output, sizeof output}, &workspace, &no_random),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_int(TC_RSA_sign_v15_digest(&fixture->key, &v15, (TC_bytes){digest, sizeof digest},
                                          (TC_buffer){output, sizeof output}, &workspace,
                                          &no_random),
                   ==, TC_RSA_ARGUMENT);
  TC_RSA_private_key unchecked = fixture->key;
  uint8_t zero_factor[BYTES / 2] = {0};
  TC_RSA_private_key all_zero_factor = fixture->key;
  all_zero_factor.p = (TC_bytes){zero_factor, sizeof zero_factor};
  TC_RSA_execution validation = {{two_random, &calls}, TC_RSA_VALIDATION_ROUNDS, {UINT32_MAX}};
  munit_assert_int(
      TC_RSA_validate_private_key(&all_zero_factor, TC_RSA_EXPONENT_FIPS, &workspace, &validation),
      ==, TC_RSA_INVALID);
  munit_assert_int(TC_RSA_sign_pss_digest(&fixture->key, &pss, (TC_bytes){digest, sizeof digest},
                                          (TC_buffer){output, sizeof output}, &workspace,
                                          &no_random),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_int(TC_RSA_encrypt_oaep(key, &oaep, (TC_bytes){digest, 8},
                                       (TC_buffer){output, sizeof output}, &workspace, &no_random),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_int(TC_RSA_decrypt_oaep(&fixture->key, &oaep, (TC_bytes){signature, BYTES},
                                       (TC_buffer){output, sizeof output}, &length, &workspace,
                                       &no_random),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_int(
      TC_RSA_validate_private_key(&unchecked, TC_RSA_EXPONENT_FIPS, &workspace, &no_random), ==,
      TC_RSA_ARGUMENT);
  munit_assert_uint32(no_random.work.remaining, ==, UINT32_MAX);
  /* Raw operations: a NULL input with a wrong length. */
  munit_assert_int(TC_RSA_raw_public(key, (TC_bytes){NULL, BYTES + 1},
                                     (TC_buffer){output, sizeof output}, &workspace, &work),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_int(TC_RSA_raw_private(key, fixture->key.d, (TC_bytes){NULL, BYTES + 1},
                                      (TC_buffer){output, sizeof output}, &workspace, &execution),
                   ==, TC_RSA_ARGUMENT);
  munit_assert_size(length, ==, SIZE_MAX);
  munit_assert_true(all_bytes(output, sizeof output, 0xa5));
  munit_assert_uint32(execution.work.remaining, ==, UINT32_MAX);
  munit_assert_uint32(work.remaining, ==, UINT32_MAX);
  munit_assert_uint(calls, ==, 0);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/modulus-supported", modulus_supported, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/encode-work", encode_work, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/oaep-work", oaep_work, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/public-work", public_work, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/private-work", private_work, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/rejected-blinding", rejected_blinding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/output-capacity", output_capacity, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/argument-order", argument_order, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/rsa/work", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
