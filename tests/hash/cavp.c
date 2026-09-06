/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Opt-in NIST CAVP response-file validation for the SHA-1 / SHA-2 family
 * (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512) and HMAC.
 *
 * Runs the byte-oriented SHAVS corpora checked in under tests/vectors/hash/cavp/:
 *   sha/SHA{1,224,256,384,512}ShortMsg.rsp - short message KATs (Len in bits)
 *   sha/SHA{1,224,256,384,512}LongMsg.rsp  - long message KATs
 *   sha/SHA{1,224,256,384,512}Monte.rsp    - SHAVS Monte Carlo (standard mode)
 *   hmac/HMAC.rsp                          - HMACVS groups [L=20/28/32/48/64]
 * Digest dispatch uses the digest length in bytes (20/28/32/48/64).
 *
 * This translation unit is part of the test executable only; it is never
 * linked into the library. Enable with TC_HASH_CAVP=1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tiny_crypto/hash.h>
#include "cavp.h"
#include "munit.h"
#include "test_io.h"

#ifndef CAVP_VECTOR_DIR
#define CAVP_VECTOR_DIR "tests/vectors/hash/cavp"
#endif

#if defined(TC_HASH_CAVP) && (TC_HASH_CAVP == 1)

/* SHA-384/512 LongMsg lines carry up to 12800 message bytes (25600 hex
   characters plus the "Msg = " prefix and CRLF). */
#define CAVP_MAX_LINE 32768
#define CAVP_MAX_MSG  16384

static char cavp_line[CAVP_MAX_LINE];
static uint8_t cavp_msg[CAVP_MAX_MSG];

/* Digest dispatch on the digest length in bytes. */
static size_t cavp_digest(int alg, const uint8_t* msg, size_t len, uint8_t* out)
{
  switch (alg)
  {
#if TC_ENABLE_SHA1
  case TC_SHA1_DIGESTLEN:
    munit_assert_int(TC_SHA1_digest(msg, len, out), ==, TC_OK);
    return TC_SHA1_DIGESTLEN;
#endif
#if TC_ENABLE_SHA224
  case TC_SHA224_DIGESTLEN:
    munit_assert_int(TC_SHA224_digest(msg, len, out), ==, TC_OK);
    return TC_SHA224_DIGESTLEN;
#endif
#if TC_ENABLE_SHA256
  case TC_SHA256_DIGESTLEN:
    munit_assert_int(TC_SHA256_digest(msg, len, out), ==, TC_OK);
    return TC_SHA256_DIGESTLEN;
#endif
#if TC_ENABLE_SHA384
  case TC_SHA384_DIGESTLEN:
    munit_assert_int(TC_SHA384_digest(msg, len, out), ==, TC_OK);
    return TC_SHA384_DIGESTLEN;
#endif
#if TC_ENABLE_SHA512
  case TC_SHA512_DIGESTLEN:
    munit_assert_int(TC_SHA512_digest(msg, len, out), ==, TC_OK);
    return TC_SHA512_DIGESTLEN;
#endif
  default:
    munit_errorf("digest length %d not compiled in", alg);
  }
  return 0;
}

static FILE* cavp_open(const char* relative)
{
  char path[512];
  FILE* file;
  snprintf(path, sizeof(path), "%s/%s", CAVP_VECTOR_DIR, relative);
  file = tc_test_fopen(path, "r");
  if (file == NULL)
    munit_errorf("cannot open CAVP file %s", path);
  return file;
}

/* ------------------------------------------------------------------------- */
/* ShortMsg / LongMsg                                                        */
/* ------------------------------------------------------------------------- */

static long cavp_run_msg_file(int alg, const char* relative)
{
  FILE* file = cavp_open(relative);
  long len_bits = -1;
  long msg_len = -1;
  uint8_t expected[TC_SHA512_DIGESTLEN];
  long expected_len = -1;
  long cases = 0;

  while (fgets(cavp_line, sizeof(cavp_line), file) != NULL)
  {
    const char* v;
    if ((v = tc_cavp_field_value(cavp_line, "Len")) != NULL)
    {
      len_bits = strtol(v, NULL, 10);
      munit_assert_long(len_bits % 8, ==, 0);
      msg_len = -1;
      expected_len = -1;
    }
    else if ((v = tc_cavp_field_value(cavp_line, "Msg")) != NULL)
    {
      msg_len = tc_cavp_parse_hex(v, cavp_msg, sizeof(cavp_msg));
      munit_assert_long(msg_len, >=, 0);
      /* Len = 0 records carry a placeholder "Msg = 00". */
      if (len_bits == 0)
        msg_len = 0;
      munit_assert_long(msg_len, ==, len_bits / 8);
    }
    else if ((v = tc_cavp_field_value(cavp_line, "MD")) != NULL)
    {
      uint8_t actual[TC_SHA512_DIGESTLEN];
      size_t actual_len;
      expected_len = tc_cavp_parse_hex(v, expected, sizeof(expected));
      munit_assert_long(expected_len, >, 0);
      munit_assert_long(msg_len, >=, 0);

      actual_len = cavp_digest(alg, cavp_msg, (size_t)msg_len, actual);
      munit_assert_size(actual_len, ==, (size_t)expected_len);
      if (memcmp(actual, expected, actual_len) != 0)
      {
        fprintf(stderr, "CAVP mismatch in %s (Len = %ld)\n", relative, len_bits);
        tc_cavp_print_bytes("expected", expected, actual_len);
        tc_cavp_print_bytes("actual  ", actual, actual_len);
        munit_error("CAVP message test failed");
      }
      cases++;
    }
  }
  fclose(file);
  return cases;
}

/* ------------------------------------------------------------------------- */
/* Monte Carlo (SHAVS section 6.4, standard mode)                            */
/*                                                                           */
/* for j in 0..99:                                                           */
/*   MD0 = MD1 = MD2 = Seed                                                  */
/*   for i in 3..1002: M = MD[i-3] || MD[i-2] || MD[i-1]; MD[i] = SHA(M)     */
/*   emit MD[1002] as COUNT = j; Seed = MD[1002]                             */
/* ------------------------------------------------------------------------- */

static long cavp_run_monte_file(int alg, const char* relative)
{
  FILE* file = cavp_open(relative);
  const size_t n = (size_t)alg;
  uint8_t seed[TC_SHA512_DIGESTLEN];
  uint8_t md[3][TC_SHA512_DIGESTLEN];
  uint8_t m[3 * TC_SHA512_DIGESTLEN];
  uint8_t out[TC_SHA512_DIGESTLEN];
  int have_seed = 0;
  long count = -1;
  long cases = 0;

  while (fgets(cavp_line, sizeof(cavp_line), file) != NULL)
  {
    const char* v;
    if ((v = tc_cavp_field_value(cavp_line, "Seed")) != NULL)
    {
      munit_assert_long(tc_cavp_parse_hex(v, seed, sizeof(seed)), ==, (long)n);
      have_seed = 1;
    }
    else if ((v = tc_cavp_field_value(cavp_line, "COUNT")) != NULL)
    {
      count = strtol(v, NULL, 10);
    }
    else if ((v = tc_cavp_field_value(cavp_line, "MD")) != NULL)
    {
      uint8_t expected[TC_SHA512_DIGESTLEN];
      int i;

      munit_assert_true(have_seed);
      munit_assert_long(count, ==, cases);
      munit_assert_long(tc_cavp_parse_hex(v, expected, sizeof(expected)), ==, (long)n);

      memcpy(md[0], seed, n);
      memcpy(md[1], seed, n);
      memcpy(md[2], seed, n);
      for (i = 3; i < 1003; ++i)
      {
        memcpy(m, md[0], n);
        memcpy(m + n, md[1], n);
        memcpy(m + 2 * n, md[2], n);
        cavp_digest(alg, m, 3 * n, out);
        memcpy(md[0], md[1], n);
        memcpy(md[1], md[2], n);
        memcpy(md[2], out, n);
      }

      if (memcmp(out, expected, n) != 0)
      {
        fprintf(stderr, "CAVP Monte mismatch in %s (COUNT = %ld)\n", relative, count);
        tc_cavp_print_bytes("expected", expected, n);
        tc_cavp_print_bytes("actual  ", out, n);
        munit_error("CAVP Monte Carlo test failed");
      }
      memcpy(seed, out, n);
      cases++;
    }
  }
  fclose(file);
  munit_assert_long(cases, ==, 100);
  return cases;
}

/* Case counts are fixed by the vendored CAVS 11.x files: ShortMsg has one
   record per byte length from 0 to the block size (65 for 64-byte blocks,
   129 for 128-byte blocks), LongMsg 64 or 128 records, Monte 100. */
static void cavp_run_sha_set(int alg, const char* short_file, long short_cases,
                             const char* long_file, long long_cases,
                             const char* monte_file)
{
  munit_assert_long(cavp_run_msg_file(alg, short_file), ==, short_cases);
  munit_assert_long(cavp_run_msg_file(alg, long_file), ==, long_cases);
  munit_assert_long(cavp_run_monte_file(alg, monte_file), ==, 100);
}

MunitResult test_cavp_sha(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

#if TC_ENABLE_SHA1
  cavp_run_sha_set(TC_SHA1_DIGESTLEN, "sha/SHA1ShortMsg.rsp", 65,
                   "sha/SHA1LongMsg.rsp", 64, "sha/SHA1Monte.rsp");
#endif
#if TC_ENABLE_SHA224
  cavp_run_sha_set(TC_SHA224_DIGESTLEN, "sha/SHA224ShortMsg.rsp", 65,
                   "sha/SHA224LongMsg.rsp", 64, "sha/SHA224Monte.rsp");
#endif
#if TC_ENABLE_SHA256
  cavp_run_sha_set(TC_SHA256_DIGESTLEN, "sha/SHA256ShortMsg.rsp", 65,
                   "sha/SHA256LongMsg.rsp", 64, "sha/SHA256Monte.rsp");
#endif
#if TC_ENABLE_SHA384
  cavp_run_sha_set(TC_SHA384_DIGESTLEN, "sha/SHA384ShortMsg.rsp", 129,
                   "sha/SHA384LongMsg.rsp", 128, "sha/SHA384Monte.rsp");
#endif
#if TC_ENABLE_SHA512
  cavp_run_sha_set(TC_SHA512_DIGESTLEN, "sha/SHA512ShortMsg.rsp", 129,
                   "sha/SHA512LongMsg.rsp", 128, "sha/SHA512Monte.rsp");
#endif
  return MUNIT_OK;
}

/* ------------------------------------------------------------------------- */
/* HMACVS: HMAC.rsp                                                          */
/* ------------------------------------------------------------------------- */

#if TC_ENABLE_HMAC

#define CAVP_HMAC_FULL_CASE(N) \
  { \
    struct TC_HMAC_SHA##N##_ctx ctx; \
    munit_assert_int(TC_HMAC_SHA##N##_init(&ctx, key, klen), ==, TC_OK); \
    munit_assert_int(TC_HMAC_SHA##N##_update(&ctx, msg, mlen), ==, TC_OK); \
    munit_assert_int(TC_HMAC_SHA##N##_final(&ctx, tag), ==, TC_OK); \
  }

static void cavp_hmac_full(int alg, const uint8_t* key, size_t klen,
                           const uint8_t* msg, size_t mlen, uint8_t* tag)
{
  switch (alg)
  {
#if TC_ENABLE_SHA1
  case TC_SHA1_DIGESTLEN: CAVP_HMAC_FULL_CASE(1) break;
#endif
#if TC_ENABLE_SHA224
  case TC_SHA224_DIGESTLEN: CAVP_HMAC_FULL_CASE(224) break;
#endif
#if TC_ENABLE_SHA256
  case TC_SHA256_DIGESTLEN: CAVP_HMAC_FULL_CASE(256) break;
#endif
#if TC_ENABLE_SHA384
  case TC_SHA384_DIGESTLEN: CAVP_HMAC_FULL_CASE(384) break;
#endif
#if TC_ENABLE_SHA512
  case TC_SHA512_DIGESTLEN: CAVP_HMAC_FULL_CASE(512) break;
#endif
  default:
    munit_errorf("digest length %d not compiled in", alg);
  }
}

static TC_status cavp_hmac_verify(int alg, const uint8_t* key, size_t klen,
                                  const uint8_t* msg, size_t mlen,
                                  const uint8_t* tag, size_t tlen)
{
  switch (alg)
  {
#if TC_ENABLE_SHA1
  case TC_SHA1_DIGESTLEN: return TC_HMAC_SHA1_verify(key, klen, msg, mlen, tag, tlen);
#endif
#if TC_ENABLE_SHA224
  case TC_SHA224_DIGESTLEN: return TC_HMAC_SHA224_verify(key, klen, msg, mlen, tag, tlen);
#endif
#if TC_ENABLE_SHA256
  case TC_SHA256_DIGESTLEN: return TC_HMAC_SHA256_verify(key, klen, msg, mlen, tag, tlen);
#endif
#if TC_ENABLE_SHA384
  case TC_SHA384_DIGESTLEN: return TC_HMAC_SHA384_verify(key, klen, msg, mlen, tag, tlen);
#endif
#if TC_ENABLE_SHA512
  case TC_SHA512_DIGESTLEN: return TC_HMAC_SHA512_verify(key, klen, msg, mlen, tag, tlen);
#endif
  default:
    return TC_ERROR;
  }
}

/* HMACVS record counts per [L=] group in the vendored CAVS 11.0 file. */
#define CAVP_HMAC_CASES \
  (TC_ENABLE_SHA1 * 300 + TC_ENABLE_SHA224 * 375 + TC_ENABLE_SHA256 * 225 + \
   TC_ENABLE_SHA384 * 300 + TC_ENABLE_SHA512 * 375)

MunitResult test_cavp_hmac(const MunitParameter params[], void* data)
{
  FILE* file = cavp_open("hmac/HMAC.rsp");
  long group_len = -1;   /* [L=20] / [L=28] / [L=32] / [L=48] / [L=64] */
  int active = 0;
  long count = -1, klen = -1, tlen = -1;
  static uint8_t key[512];
  static uint8_t msg[512];
  long key_len = -1, msg_len = -1;
  long cases = 0;
  (void) params;
  (void) data;

  while (fgets(cavp_line, sizeof(cavp_line), file) != NULL)
  {
    const char* v;
    if (cavp_line[0] == '[')
    {
      const char* p = cavp_line + 1;
      while (*p == ' ' || *p == 'L' || *p == '=')
        p++;
      group_len = strtol(p, NULL, 10);
      active = 0;
#if TC_ENABLE_SHA1
      if (group_len == TC_SHA1_DIGESTLEN)
        active = 1;
#endif
#if TC_ENABLE_SHA224
      if (group_len == TC_SHA224_DIGESTLEN)
        active = 1;
#endif
#if TC_ENABLE_SHA256
      if (group_len == TC_SHA256_DIGESTLEN)
        active = 1;
#endif
#if TC_ENABLE_SHA384
      if (group_len == TC_SHA384_DIGESTLEN)
        active = 1;
#endif
#if TC_ENABLE_SHA512
      if (group_len == TC_SHA512_DIGESTLEN)
        active = 1;
#endif
      continue;
    }
    if (!active)
      continue;

    if ((v = tc_cavp_field_value(cavp_line, "Count")) != NULL)
    {
      count = strtol(v, NULL, 10);
      key_len = msg_len = -1;
    }
    else if ((v = tc_cavp_field_value(cavp_line, "Klen")) != NULL)
      klen = strtol(v, NULL, 10);
    else if ((v = tc_cavp_field_value(cavp_line, "Tlen")) != NULL)
      tlen = strtol(v, NULL, 10);
    else if ((v = tc_cavp_field_value(cavp_line, "Key")) != NULL)
    {
      key_len = tc_cavp_parse_hex(v, key, sizeof(key));
      munit_assert_long(key_len, ==, klen);
    }
    else if ((v = tc_cavp_field_value(cavp_line, "Msg")) != NULL)
    {
      msg_len = tc_cavp_parse_hex(v, msg, sizeof(msg));
      munit_assert_long(msg_len, >=, 0);
    }
    else if ((v = tc_cavp_field_value(cavp_line, "Mac")) != NULL)
    {
      uint8_t expected[TC_SHA512_DIGESTLEN];
      uint8_t actual[TC_SHA512_DIGESTLEN];
      long expected_len = tc_cavp_parse_hex(v, expected, sizeof(expected));
      int alg = (int)group_len;

      munit_assert_long(expected_len, ==, tlen);
      munit_assert_long(key_len, >=, 0);
      munit_assert_long(msg_len, >=, 0);

      cavp_hmac_full(alg, key, (size_t)key_len, msg, (size_t)msg_len, actual);
      if (memcmp(actual, expected, (size_t)tlen) != 0)
      {
        fprintf(stderr, "HMAC CAVP mismatch [L=%ld] Count = %ld\n", group_len, count);
        tc_cavp_print_bytes("expected", expected, (size_t)tlen);
        tc_cavp_print_bytes("actual  ", actual, (size_t)tlen);
        munit_error("HMAC CAVP test failed");
      }

      /* The one-shot and verify APIs agree whenever Tlen is in range. */
      if (tlen >= TC_HMAC_MIN_TAG_LEN)
      {
        int rc = cavp_hmac_verify(alg, key, (size_t)key_len, msg, (size_t)msg_len,
                                  expected, (size_t)tlen);
        munit_assert_int(rc, ==, TC_OK);
      }
      cases++;
    }
  }
  fclose(file);
  munit_assert_long(cases, ==, CAVP_HMAC_CASES);
  return MUNIT_OK;
}

#else /* !TC_ENABLE_HMAC */

MunitResult test_cavp_hmac(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;
  return MUNIT_SKIP;
}

#endif /* TC_ENABLE_HMAC */

#else /* !TC_HASH_CAVP */

MunitResult test_cavp_sha(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;
  return MUNIT_SKIP;
}

MunitResult test_cavp_hmac(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;
  return MUNIT_SKIP;
}

#endif /* TC_HASH_CAVP */
