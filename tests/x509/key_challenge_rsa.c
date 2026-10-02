/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/key_challenge.h>
#include <tiny_crypto/rsa.h>
#include <string.h>

#include "munit.h"
#include "test_util.h"

/* A workspace followed by a canary detects writes past the challenge buffer
 * without relying on a sanitizer. */
typedef struct {
  TC_key_challenge_workspace workspace;
  uint8_t canary[256];
} guarded_workspace;

static TC_status fixed_random(void* context, uint8_t* output, size_t length)
{
  (void)context;
  memset(output, 0x5a, length);
  return TC_OK;
}

static const uint8_t exponent[] = {1, 0, 1};
static uint8_t modulus[1024];

static TC_X509_public_key rsa_key(size_t bits, size_t modulus_length)
{
  TC_X509_public_key key;
  memset(&key, 0, sizeof key);
  memset(modulus, 0xff, sizeof modulus);
  key.type = TC_KEY_RSA;
  key.bits = (unsigned)bits;
  key.modulus = (TC_bytes){modulus, modulus_length};
  key.exponent = (TC_bytes){exponent, sizeof exponent};
  return key;
}

static TC_key_challenge_options v15_options(void)
{
  TC_key_challenge_options options;
  memset(&options, 0, sizeof options);
  options.signature.scheme = TC_SIGNATURE_RSA_V15;
  options.signature.hash = TC_HASH_SHA256;
  options.signature.mgf_hash = TC_HASH_UNKNOWN;
  return options;
}

static TC_key_challenge_options pss_options(size_t salt_length)
{
  TC_key_challenge_options options = v15_options();
  options.signature.scheme = TC_SIGNATURE_RSA_PSS;
  options.signature.mgf_hash = TC_HASH_SHA256;
  options.signature.salt_length = (uint32_t)salt_length;
  return options;
}

static void assert_canary(const guarded_workspace* guarded)
{
  for (size_t i = 0; i < sizeof guarded->canary; ++i)
    munit_assert_uint8(guarded->canary[i], ==, 0xc3);
}

static TC_key_challenge_result prepare(const TC_X509_public_key* key,
                                       const TC_key_challenge_options* options,
                                       guarded_workspace* guarded, uint32_t budget,
                                       uint32_t* remaining, TC_bytes* out)
{
  TC_work_budget work = {budget};
  const TC_key_challenge_result result = TC_key_challenge_prepare(
      key, options, (TC_random_source){fixed_random, NULL}, &guarded->workspace, &work, out);
  if (remaining)
    *remaining = work.remaining;
  return result;
}

/* Every supported modulus size, including the largest, fits the workspace. */
TC_TEST(largest_modulus)
{
  const TC_key_challenge_options schemes[] = {v15_options(), pss_options(32)};
  const TC_X509_public_key key = rsa_key(4096, 512);
  for (size_t i = 0; i < sizeof schemes / sizeof *schemes; ++i) {
    guarded_workspace guarded;
    TC_bytes out = {NULL, 0};
    memset(guarded.canary, 0xc3, sizeof guarded.canary);
    munit_assert_int(prepare(&key, &schemes[i], &guarded, 100000, NULL, &out), ==,
                     TC_KEY_CHALLENGE_OK);
    munit_assert_size(out.length, ==, 512);
    munit_assert_ptr_equal(out.data, guarded.workspace.challenge);
    assert_canary(&guarded);
    TC_key_challenge_clear(&guarded.workspace);
  }
  return MUNIT_OK;
}

TC_TEST(unsupported_shapes)
{
  const TC_key_challenge_options v15 = v15_options();
  const TC_key_challenge_options salt_too_long = pss_options(TC_KEY_CHALLENGE_MAX_SALT_BYTES + 1);
  const TC_X509_public_key oversized = rsa_key(8192, 1024);
  const TC_X509_public_key mismatched = rsa_key(4096, 511);
  const TC_X509_public_key supported = rsa_key(4096, 512);
  const struct {
    const TC_X509_public_key* key;
    const TC_key_challenge_options* options;
  } cases[] = {{&oversized, &v15}, {&mismatched, &v15}, {&supported, &salt_too_long}};
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    guarded_workspace guarded, saved;
    TC_bytes out = {NULL, 7}, unchanged = out;
    memset(&guarded, 0xa5, sizeof guarded);
    saved = guarded;
    munit_assert_int(prepare(cases[i].key, cases[i].options, &guarded, 100000, NULL, &out), ==,
                     TC_KEY_CHALLENGE_UNSUPPORTED);
    munit_assert_memory_equal(sizeof guarded, &guarded, &saved);
    munit_assert_memory_equal(sizeof out, &out, &unchanged);
  }
  return MUNIT_OK;
}

/* The documented cost is exact: one unit less fails before any RNG use and
 * leaves the workspace unchanged. */
TC_TEST(exact_work)
{
  const TC_key_challenge_options schemes[] = {v15_options(), pss_options(32)};
  const TC_X509_public_key key = rsa_key(4096, 512);
  for (size_t i = 0; i < sizeof schemes / sizeof *schemes; ++i) {
    guarded_workspace guarded, saved;
    TC_bytes out;
    uint32_t remaining;
    memset(guarded.canary, 0xc3, sizeof guarded.canary);
    munit_assert_int(prepare(&key, &schemes[i], &guarded, 100000, &remaining, &out), ==,
                     TC_KEY_CHALLENGE_OK);
    const uint32_t cost = 100000 - remaining;
    munit_assert_uint32(cost, >, 0);
    TC_key_challenge_clear(&guarded.workspace);

    munit_assert_int(prepare(&key, &schemes[i], &guarded, cost, &remaining, &out), ==,
                     TC_KEY_CHALLENGE_OK);
    munit_assert_uint32(remaining, ==, 0);
    TC_key_challenge_clear(&guarded.workspace);

    memset(&guarded.workspace, 0xa5, sizeof guarded.workspace);
    saved = guarded;
    munit_assert_int(prepare(&key, &schemes[i], &guarded, cost - 1, &remaining, &out), ==,
                     TC_KEY_CHALLENGE_LIMIT);
    munit_assert_uint32(remaining, ==, cost - 1);
    munit_assert_memory_equal(sizeof guarded, &guarded, &saved);
  }
  return MUNIT_OK;
}

/* Output or work storage inside the workspace returns ARGUMENT before RNG
 * use and leaves the workspace unchanged. */
TC_TEST(overlapping_storage)
{
  const TC_key_challenge_options v15 = v15_options();
  const TC_X509_public_key key = rsa_key(2048, 256);
  guarded_workspace guarded, saved;
  memset(&guarded, 0xa5, sizeof guarded);
  saved = guarded;
  TC_bytes* inner_out = (TC_bytes*)(void*)guarded.workspace.challenge;
  TC_work_budget* inner_work = (TC_work_budget*)(void*)(guarded.workspace.challenge + 64);
  TC_work_budget work = {100000};
  TC_bytes out = {NULL, 7};
  munit_assert_int(TC_key_challenge_prepare(&key, &v15, (TC_random_source){fixed_random, NULL},
                                            &guarded.workspace, &work, inner_out),
                   ==, TC_KEY_CHALLENGE_ARGUMENT);
  munit_assert_int(TC_key_challenge_prepare(&key, &v15, (TC_random_source){fixed_random, NULL},
                                            &guarded.workspace, inner_work, &out),
                   ==, TC_KEY_CHALLENGE_ARGUMENT);
  munit_assert_memory_equal(sizeof guarded, &guarded, &saved);
  munit_assert_uint32(work.remaining, ==, 100000);
  munit_assert_ptr_null(out.data);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/largest-modulus", largest_modulus, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/unsupported-shapes", unsupported_shapes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/exact-work", exact_work, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/overlapping-storage", overlapping_storage, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/key-challenge-rsa", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
