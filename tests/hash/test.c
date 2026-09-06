/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Unit tests for tiny-crypto-c using µunit (munit)
 * https://nemequ.github.io/munit/
 */

#include <stdio.h>
#include <string.h>
#include "munit.h"
#include <tiny_crypto/hash.h>
#include "test_util.h"
#include "test_vectors.h"

/* Provided by hmac_test.c (returns MUNIT_SKIP when HMAC is disabled). */
MunitResult test_hmac_rfc(const MunitParameter params[], void* data);
MunitResult test_hmac_key_lengths(const MunitParameter params[], void* data);
MunitResult test_hmac_truncation(const MunitParameter params[], void* data);
MunitResult test_hmac_verify(const MunitParameter params[], void* data);
MunitResult test_hmac_streaming(const MunitParameter params[], void* data);
MunitResult test_hmac_zeroize(const MunitParameter params[], void* data);
MunitResult test_hmac_wycheproof(const MunitParameter params[], void* data);

/* Provided by cavp.c (returns MUNIT_SKIP when TC_HASH_CAVP is 0). */
MunitResult test_cavp_sha(const MunitParameter params[], void* data);
MunitResult test_cavp_hmac(const MunitParameter params[], void* data);

/* The five SHA APIs share one behavioral matrix. */
#if TC_ZEROIZE
#define TC_SHA_ASSERT_CLEARED(ctx) munit_assert_true(tc_test_all_zero(&(ctx), sizeof(ctx)))
#else
#define TC_SHA_ASSERT_CLEARED(ctx) ((void)0)
#endif

#if TC_STRICT
#define TC_SHA_STRICT_CHECKS(N, ctx, out) \
  do { \
    TC_SHA##N##_init(&(ctx)); \
    munit_assert_int(TC_SHA##N##_update(NULL, fips_abc_msg, 1), ==, TC_ERROR); \
    munit_assert_int(TC_SHA##N##_update(&(ctx), NULL, 1), ==, TC_ERROR); \
    munit_assert_int(TC_SHA##N##_final(NULL, (out)), ==, TC_ERROR); \
    munit_assert_int(TC_SHA##N##_final(&(ctx), NULL), ==, TC_ERROR); \
  } while (0)
#else
#define TC_SHA_STRICT_CHECKS(N, ctx, out) ((void)0)
#endif

#define TC_SHA_TEST_MATRIX(N, digest_bytes, block_bytes, count_limit) \
  static MunitResult test_sha##N##_fips(const MunitParameter params[], void* data) \
  { \
    uint8_t out[TC_SHA##N##_DIGESTLEN]; \
    (void)params; \
    (void)data; \
    munit_assert_int(TC_SHA##N##_digest(fips_empty_msg, 0, out), ==, TC_OK); \
    munit_assert_memory_equal(TC_SHA##N##_DIGESTLEN, out, fips_empty_sha##N); \
    munit_assert_int(TC_SHA##N##_digest(fips_abc_msg, FIPS_ABC_LEN, out), ==, TC_OK); \
    munit_assert_memory_equal(TC_SHA##N##_DIGESTLEN, out, fips_abc_sha##N); \
    munit_assert_int(TC_SHA##N##_digest(fips_two_block_msg, FIPS_TWO_BLOCK_LEN, out), ==, TC_OK); \
    munit_assert_memory_equal(TC_SHA##N##_DIGESTLEN, out, fips_two_block_sha##N); \
    munit_assert_int(TC_SHA##N##_digest(fips_four_block_msg, FIPS_FOUR_BLOCK_LEN, out), ==, TC_OK); \
    munit_assert_memory_equal(TC_SHA##N##_DIGESTLEN, out, fips_four_block_sha##N); \
    return MUNIT_OK; \
  } \
  static MunitResult test_sha##N##_million(const MunitParameter params[], void* data) \
  { \
    struct TC_SHA##N##_ctx ctx; \
    uint8_t chunk[1000]; \
    uint8_t out[TC_SHA##N##_DIGESTLEN]; \
    size_t i; \
    (void)params; \
    (void)data; \
    memset(chunk, 'a', sizeof(chunk)); \
    TC_SHA##N##_init(&ctx); \
    for (i = 0; i < 1000; ++i) \
      munit_assert_int(TC_SHA##N##_update(&ctx, chunk, sizeof(chunk)), ==, TC_OK); \
    munit_assert_int(TC_SHA##N##_final(&ctx, out), ==, TC_OK); \
    munit_assert_memory_equal(TC_SHA##N##_DIGESTLEN, out, million_a_sha##N); \
    TC_SHA##N##_init(&ctx); \
    for (i = 0; i < 100; ++i) \
      munit_assert_int(TC_SHA##N##_update(&ctx, chunk, 7), ==, TC_OK); \
    i = 700; \
    while (i < 1000000) \
    { \
      const size_t take = (1000000 - i < 999) ? (1000000 - i) : 999; \
      munit_assert_int(TC_SHA##N##_update(&ctx, chunk, take), ==, TC_OK); \
      i += take; \
    } \
    munit_assert_int(TC_SHA##N##_final(&ctx, out), ==, TC_OK); \
    munit_assert_memory_equal(TC_SHA##N##_DIGESTLEN, out, million_a_sha##N); \
    return MUNIT_OK; \
  } \
  static MunitResult test_sha##N##_boundaries(const MunitParameter params[], void* data) \
  { \
    uint8_t msg[256]; \
    uint8_t out[TC_SHA##N##_DIGESTLEN]; \
    size_t i; \
    (void)params; \
    (void)data; \
    tc_test_fill_incrementing(msg, sizeof(msg)); \
    for (i = 0; i < BOUNDARY_COUNT; ++i) \
    { \
      munit_assert_size(boundary_lengths[i], <=, sizeof(msg)); \
      munit_assert_int(TC_SHA##N##_digest(msg, boundary_lengths[i], out), ==, TC_OK); \
      munit_assert_memory_equal(TC_SHA##N##_DIGESTLEN, out, boundary_sha##N[i]); \
    } \
    return MUNIT_OK; \
  } \
  static MunitResult test_sha##N##_incremental(const MunitParameter params[], void* data) \
  { \
    uint8_t msg[130]; \
    uint8_t expected[TC_SHA##N##_DIGESTLEN]; \
    uint8_t out[TC_SHA##N##_DIGESTLEN]; \
    struct TC_SHA##N##_ctx ctx; \
    size_t split; \
    size_t i; \
    (void)params; \
    (void)data; \
    tc_test_fill_incrementing(msg, sizeof(msg)); \
    munit_assert_int(TC_SHA##N##_digest(msg, sizeof(msg), expected), ==, TC_OK); \
    for (split = 0; split <= sizeof(msg); ++split) \
    { \
      TC_SHA##N##_init(&ctx); \
      munit_assert_int(TC_SHA##N##_update(&ctx, msg, split), ==, TC_OK); \
      munit_assert_int(TC_SHA##N##_update(&ctx, msg + split, sizeof(msg) - split), ==, TC_OK); \
      munit_assert_int(TC_SHA##N##_final(&ctx, out), ==, TC_OK); \
      munit_assert_memory_equal(TC_SHA##N##_DIGESTLEN, out, expected); \
    } \
    TC_SHA##N##_init(&ctx); \
    munit_assert_int(TC_SHA##N##_update(&ctx, msg, 1), ==, TC_OK); \
    munit_assert_int(TC_SHA##N##_update(&ctx, msg + 1, 63), ==, TC_OK); \
    munit_assert_int(TC_SHA##N##_update(&ctx, msg + 64, 66), ==, TC_OK); \
    munit_assert_int(TC_SHA##N##_final(&ctx, out), ==, TC_OK); \
    munit_assert_memory_equal(TC_SHA##N##_DIGESTLEN, out, expected); \
    TC_SHA##N##_init(&ctx); \
    for (i = 0; i < sizeof(msg); ++i) \
      munit_assert_int(TC_SHA##N##_update(&ctx, msg + i, 1), ==, TC_OK); \
    munit_assert_int(TC_SHA##N##_final(&ctx, out), ==, TC_OK); \
    munit_assert_memory_equal(TC_SHA##N##_DIGESTLEN, out, expected); \
    TC_SHA##N##_init(&ctx); \
    munit_assert_int(TC_SHA##N##_update(&ctx, NULL, 0), ==, TC_OK); \
    munit_assert_int(TC_SHA##N##_update(&ctx, msg, 0), ==, TC_OK); \
    munit_assert_int(TC_SHA##N##_final(&ctx, out), ==, TC_OK); \
    munit_assert_memory_equal(TC_SHA##N##_DIGESTLEN, out, fips_empty_sha##N); \
    munit_assert_int(TC_SHA##N##_digest(NULL, 0, out), ==, TC_OK); \
    munit_assert_memory_equal(TC_SHA##N##_DIGESTLEN, out, fips_empty_sha##N); \
    return MUNIT_OK; \
  } \
  static MunitResult test_sha##N##_api(const MunitParameter params[], void* data) \
  { \
    struct TC_SHA##N##_ctx ctx; \
    uint8_t out[TC_SHA##N##_DIGESTLEN]; \
    (void)params; \
    (void)data; \
    memset(ctx.Buf, 0xA5, sizeof(ctx.Buf)); \
    TC_SHA##N##_init(&ctx); \
    munit_assert_true(tc_test_all_zero(ctx.Buf, sizeof(ctx.Buf))); \
    munit_assert_int(TC_SHA##N##_update(&ctx, fips_abc_msg, FIPS_ABC_LEN), ==, TC_OK); \
    munit_assert_false(tc_test_all_zero(&ctx, sizeof(ctx))); \
    munit_assert_int(TC_SHA##N##_final(&ctx, out), ==, TC_OK); \
    munit_assert_memory_equal(TC_SHA##N##_DIGESTLEN, out, fips_abc_sha##N); \
    TC_SHA_ASSERT_CLEARED(ctx); \
    TC_SHA##N##_init(&ctx); \
    munit_assert_int(TC_SHA##N##_update(&ctx, fips_abc_msg, FIPS_ABC_LEN), ==, TC_OK); \
    TC_SHA##N##_ctx_clear(&ctx); \
    munit_assert_true(tc_test_all_zero(&ctx, sizeof(ctx))); \
    TC_SHA##N##_ctx_clear(NULL); \
    munit_assert_int(TC_SHA##N##_digest(NULL, 1, out), ==, TC_ERROR); \
    munit_assert_int(TC_SHA##N##_digest(fips_abc_msg, 1, NULL), ==, TC_ERROR); \
    TC_SHA##N##_init(&ctx); \
    ctx.Count = (count_limit); \
    munit_assert_int(TC_SHA##N##_update(&ctx, fips_abc_msg, 1), ==, TC_ERROR); \
    ctx.Count = (count_limit) - 1; \
    munit_assert_int(TC_SHA##N##_update(&ctx, fips_abc_msg, 1), ==, TC_OK); \
    TC_SHA_STRICT_CHECKS(N, ctx, out); \
    munit_assert_int(TC_SHA##N##_DIGESTLEN, ==, digest_bytes); \
    munit_assert_int(TC_SHA##N##_BLOCKLEN, ==, block_bytes); \
    return MUNIT_OK; \
  }

#if TC_ENABLE_SHA1
TC_SHA_TEST_MATRIX(1, 20, 64, (UINT64_MAX >> 3))
#endif
#if TC_ENABLE_SHA224
TC_SHA_TEST_MATRIX(224, 28, 64, (UINT64_MAX >> 3))
#endif
#if TC_ENABLE_SHA256
TC_SHA_TEST_MATRIX(256, 32, 64, (UINT64_MAX >> 3))
#endif
#if TC_ENABLE_SHA384
TC_SHA_TEST_MATRIX(384, 48, 128, UINT64_MAX)
#endif
#if TC_ENABLE_SHA512
TC_SHA_TEST_MATRIX(512, 64, 128, UINT64_MAX)
#endif

#undef TC_SHA_TEST_MATRIX
#undef TC_SHA_STRICT_CHECKS
#undef TC_SHA_ASSERT_CLEARED

/* Secure wipe test and status codes */
static MunitResult test_secure_zero(const MunitParameter params[], void* data)
{
  uint8_t buf[16];
  size_t i;
  (void) params;
  (void) data;

  for (i = 0; i < sizeof(buf); ++i)
    buf[i] = (uint8_t)(0xA5U + (uint8_t)i);

  TC_secure_zero(buf, sizeof(buf));
  for (i = 0; i < sizeof(buf); ++i)
    munit_assert_uint8(buf[i], ==, 0);

  TC_secure_zero(buf, 0); /* zero length is a no-op */

  munit_assert_int(TC_OK, ==, 0);
  munit_assert_int(TC_ERROR, ==, -1);
  munit_assert_int(TC_MISMATCH, ==, 1);

  return MUNIT_OK;
}

static MunitResult test_ct_eq(const MunitParameter params[], void* data)
{
  const uint8_t a[] = { 0x00, 0x11, 0x22, 0x33, 0x44 };
  uint8_t b[5];
  (void) params;
  (void) data;

  memcpy(b, a, sizeof(a));
  munit_assert_int(TC_ct_equal(a, b, sizeof(a)), ==, TC_OK);
  munit_assert_int(TC_ct_equal(NULL, NULL, 0), ==, TC_OK);
  munit_assert_int(TC_ct_equal(a, b, 0), ==, TC_OK);

  b[0] ^= 0x01U;
  munit_assert_int(TC_ct_equal(a, b, sizeof(a)), ==, TC_MISMATCH);
  b[0] ^= 0x01U;
  b[sizeof(b) - 1] ^= 0x80U;
  munit_assert_int(TC_ct_equal(a, b, sizeof(a)), ==, TC_MISMATCH);

  munit_assert_int(TC_ct_equal(NULL, b, 1), ==, TC_ERROR);
  munit_assert_int(TC_ct_equal(a, NULL, 1), ==, TC_ERROR);

  return MUNIT_OK;
}

/* --- Test Suite Setup --- */

static MunitTest test_suite_tests[] = {
#if TC_ENABLE_SHA256
  { "/sha256/fips",        test_sha256_fips,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha256/million_a",   test_sha256_million,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha256/boundaries",  test_sha256_boundaries,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha256/incremental", test_sha256_incremental, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha256/api",         test_sha256_api,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_ENABLE_SHA1
  { "/sha1/fips",          test_sha1_fips,          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha1/million_a",     test_sha1_million,       NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha1/boundaries",    test_sha1_boundaries,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha1/incremental",   test_sha1_incremental,   NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha1/api",           test_sha1_api,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_ENABLE_SHA224
  { "/sha224/fips",        test_sha224_fips,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha224/million_a",   test_sha224_million,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha224/boundaries",  test_sha224_boundaries,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha224/incremental", test_sha224_incremental, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha224/api",         test_sha224_api,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_ENABLE_SHA384
  { "/sha384/fips",        test_sha384_fips,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha384/million_a",   test_sha384_million,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha384/boundaries",  test_sha384_boundaries,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha384/incremental", test_sha384_incremental, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha384/api",         test_sha384_api,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_ENABLE_SHA512
  { "/sha512/fips",        test_sha512_fips,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha512/million_a",   test_sha512_million,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha512/boundaries",  test_sha512_boundaries,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha512/incremental", test_sha512_incremental, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/sha512/api",         test_sha512_api,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
  { "/hmac/rfc",           test_hmac_rfc,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/hmac/key_lengths",   test_hmac_key_lengths,   NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/hmac/truncation",    test_hmac_truncation,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/hmac/verify",        test_hmac_verify,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/hmac/streaming",     test_hmac_streaming,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/hmac/zeroize",       test_hmac_zeroize,       NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/hmac/wycheproof",    test_hmac_wycheproof,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/cavp/sha",           test_cavp_sha,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/cavp/hmac",          test_cavp_hmac,          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/secure_zero",        test_secure_zero,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/ct_eq",              test_ct_eq,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static const MunitSuite test_suite = {
  "/tiny-crypto-c",
  test_suite_tests,
  NULL,
  1,
  MUNIT_SUITE_OPTION_NONE
};

int main(int argc, char* argv[])
{
  return munit_suite_main(&test_suite, NULL, argc, argv);
}
