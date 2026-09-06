/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Mistial Dev
 *
 * HMAC tests for SHA-1/224/256/384/512: RFC 2202 / RFC 4231 KATs, API edge
 * cases, Wycheproof. Digest dispatch uses the digest length (20/28/32/48/64).
 * Test-only translation unit; never linked into the library.
 */

#include <tiny_crypto/hash.h>
#include "munit.h"
#include "test_io.h"
#include "test_util.h"
#include "test_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef HMAC_WYCHEPROOF_DIR
#define HMAC_WYCHEPROOF_DIR "tests/vectors/hash/wycheproof"
#endif

#if TC_ENABLE_HMAC

/* Full-tag streaming MAC; alg is the digest length in bytes (20/28/32/48/64). */
#define HMAC_FULL_TAG_CASE(N) \
  { \
    struct TC_HMAC_SHA##N##_ctx ctx; \
    munit_assert_int(TC_HMAC_SHA##N##_init(&ctx, key, key_len), ==, TC_OK); \
    munit_assert_int(TC_HMAC_SHA##N##_update(&ctx, msg, msg_len), ==, TC_OK); \
    munit_assert_int(TC_HMAC_SHA##N##_final(&ctx, tag), ==, TC_OK); \
  }

static void full_tag(int alg, const uint8_t* key, size_t key_len,
                     const uint8_t* msg, size_t msg_len, uint8_t* tag)
{
  switch (alg)
  {
#if TC_ENABLE_SHA1
  case TC_SHA1_DIGESTLEN: HMAC_FULL_TAG_CASE(1) break;
#endif
#if TC_ENABLE_SHA224
  case TC_SHA224_DIGESTLEN: HMAC_FULL_TAG_CASE(224) break;
#endif
#if TC_ENABLE_SHA256
  case TC_SHA256_DIGESTLEN: HMAC_FULL_TAG_CASE(256) break;
#endif
#if TC_ENABLE_SHA384
  case TC_SHA384_DIGESTLEN: HMAC_FULL_TAG_CASE(384) break;
#endif
#if TC_ENABLE_SHA512
  case TC_SHA512_DIGESTLEN: HMAC_FULL_TAG_CASE(512) break;
#endif
  default:
    munit_errorf("digest length %d not compiled in", alg);
  }
}

/* Public verify API for the same dispatch; TC_ERROR when alg is compiled out. */
static TC_status hmac_verify(int alg, const uint8_t* key, size_t key_len,
                             const uint8_t* msg, size_t msg_len,
                             const uint8_t* tag, size_t tag_len)
{
  switch (alg)
  {
#if TC_ENABLE_SHA1
  case TC_SHA1_DIGESTLEN: return TC_HMAC_SHA1_verify(key, key_len, msg, msg_len, tag, tag_len);
#endif
#if TC_ENABLE_SHA224
  case TC_SHA224_DIGESTLEN: return TC_HMAC_SHA224_verify(key, key_len, msg, msg_len, tag, tag_len);
#endif
#if TC_ENABLE_SHA256
  case TC_SHA256_DIGESTLEN: return TC_HMAC_SHA256_verify(key, key_len, msg, msg_len, tag, tag_len);
#endif
#if TC_ENABLE_SHA384
  case TC_SHA384_DIGESTLEN: return TC_HMAC_SHA384_verify(key, key_len, msg, msg_len, tag, tag_len);
#endif
#if TC_ENABLE_SHA512
  case TC_SHA512_DIGESTLEN: return TC_HMAC_SHA512_verify(key, key_len, msg, msg_len, tag, tag_len);
#endif
  default:
    return TC_ERROR;
  }
}

/* ------------------------------------------------------------------------- */
/* RFC 2202 / RFC 4231                                                       */
/* ------------------------------------------------------------------------- */

MunitResult test_hmac_rfc(const MunitParameter params[], void* data)
{
  uint8_t tag[TC_SHA512_DIGESTLEN];
  size_t i;
  (void) params;
  (void) data;

#if TC_ENABLE_SHA1
  for (i = 0; i < RFC2202_COUNT; ++i)
  {
    const struct hmac_vector* v = &rfc2202[i];
    full_tag(TC_SHA1_DIGESTLEN, v->key, v->key_len, v->msg, v->msg_len, tag);
    munit_assert_memory_equal(TC_SHA1_DIGESTLEN, tag, v->tag);
    /* Case 5 is the RFC's 96-bit truncation example; its full tag is above. */
    munit_assert_int(TC_HMAC_SHA1_digest(v->key, v->key_len, v->msg, v->msg_len, tag, TC_SHA1_DIGESTLEN), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA1_DIGESTLEN, tag, v->tag);
    munit_assert_int(TC_HMAC_SHA1_verify(v->key, v->key_len, v->msg, v->msg_len, v->tag, TC_SHA1_DIGESTLEN), ==, TC_OK);
  }
#endif
#if TC_ENABLE_SHA256
  for (i = 0; i < RFC4231_COUNT; ++i)
  {
    const struct hmac_vector* v = &rfc4231[i];
    full_tag(TC_SHA256_DIGESTLEN, v->key, v->key_len, v->msg, v->msg_len, tag);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, tag, v->tag);
    munit_assert_int(TC_HMAC_SHA256_digest(v->key, v->key_len, v->msg, v->msg_len, tag, TC_SHA256_DIGESTLEN), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, tag, v->tag);
    munit_assert_int(TC_HMAC_SHA256_verify(v->key, v->key_len, v->msg, v->msg_len, v->tag, TC_SHA256_DIGESTLEN), ==, TC_OK);
  }
#endif
#if TC_ENABLE_SHA224
  for (i = 0; i < RFC4231_COUNT; ++i)
  {
    const struct hmac_vector* v = &rfc4231_sha224[i];
    full_tag(TC_SHA224_DIGESTLEN, v->key, v->key_len, v->msg, v->msg_len, tag);
    munit_assert_memory_equal(TC_SHA224_DIGESTLEN, tag, v->tag);
    munit_assert_int(TC_HMAC_SHA224_digest(v->key, v->key_len, v->msg, v->msg_len, tag, TC_SHA224_DIGESTLEN), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA224_DIGESTLEN, tag, v->tag);
    munit_assert_int(TC_HMAC_SHA224_verify(v->key, v->key_len, v->msg, v->msg_len, v->tag, TC_SHA224_DIGESTLEN), ==, TC_OK);
  }
#endif
#if TC_ENABLE_SHA384
  for (i = 0; i < RFC4231_COUNT; ++i)
  {
    const struct hmac_vector* v = &rfc4231_sha384[i];
    full_tag(TC_SHA384_DIGESTLEN, v->key, v->key_len, v->msg, v->msg_len, tag);
    munit_assert_memory_equal(TC_SHA384_DIGESTLEN, tag, v->tag);
    munit_assert_int(TC_HMAC_SHA384_digest(v->key, v->key_len, v->msg, v->msg_len, tag, TC_SHA384_DIGESTLEN), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA384_DIGESTLEN, tag, v->tag);
    munit_assert_int(TC_HMAC_SHA384_verify(v->key, v->key_len, v->msg, v->msg_len, v->tag, TC_SHA384_DIGESTLEN), ==, TC_OK);
  }
#endif
#if TC_ENABLE_SHA512
  for (i = 0; i < RFC4231_COUNT; ++i)
  {
    const struct hmac_vector* v = &rfc4231_sha512[i];
    full_tag(TC_SHA512_DIGESTLEN, v->key, v->key_len, v->msg, v->msg_len, tag);
    munit_assert_memory_equal(TC_SHA512_DIGESTLEN, tag, v->tag);
    munit_assert_int(TC_HMAC_SHA512_digest(v->key, v->key_len, v->msg, v->msg_len, tag, TC_SHA512_DIGESTLEN), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA512_DIGESTLEN, tag, v->tag);
    munit_assert_int(TC_HMAC_SHA512_verify(v->key, v->key_len, v->msg, v->msg_len, v->tag, TC_SHA512_DIGESTLEN), ==, TC_OK);
  }
#endif
  return MUNIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Key lengths: 0, 1, 63, 64, 65, 131; long keys equal HMAC(H(K)).           */
/* ------------------------------------------------------------------------- */

MunitResult test_hmac_key_lengths(const MunitParameter params[], void* data)
{
  uint8_t key[256];
  uint8_t tag[TC_SHA512_DIGESTLEN];
  uint8_t tag2[TC_SHA512_DIGESTLEN];
  uint8_t hashed[TC_SHA512_DIGESTLEN];
  size_t i;
  (void) params;
  (void) data;

  tc_test_fill_incrementing(key, sizeof(key));

  for (i = 0; i < HMAC_KEYLEN_COUNT; ++i)
  {
    size_t klen = hmac_key_lengths[i];
    const uint8_t* kp = (klen == 0) ? NULL : key;
#if TC_ENABLE_SHA1
    full_tag(TC_SHA1_DIGESTLEN, kp, klen, hmac_keylen_msg, sizeof(hmac_keylen_msg), tag);
    munit_assert_memory_equal(TC_SHA1_DIGESTLEN, tag, hmac_keylen_sha1[i]);
    if (klen > TC_SHA1_BLOCKLEN)
    {
      TC_SHA1_digest(key, klen, hashed);
      full_tag(TC_SHA1_DIGESTLEN, hashed, TC_SHA1_DIGESTLEN, hmac_keylen_msg, sizeof(hmac_keylen_msg), tag2);
      munit_assert_memory_equal(TC_SHA1_DIGESTLEN, tag, tag2);
    }
#endif
#if TC_ENABLE_SHA256
    full_tag(TC_SHA256_DIGESTLEN, kp, klen, hmac_keylen_msg, sizeof(hmac_keylen_msg), tag);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, tag, hmac_keylen_sha256[i]);
    if (klen > TC_SHA256_BLOCKLEN)
    {
      TC_SHA256_digest(key, klen, hashed);
      full_tag(TC_SHA256_DIGESTLEN, hashed, TC_SHA256_DIGESTLEN, hmac_keylen_msg, sizeof(hmac_keylen_msg), tag2);
      munit_assert_memory_equal(TC_SHA256_DIGESTLEN, tag, tag2);
    }
#endif
#if TC_ENABLE_SHA224
    full_tag(TC_SHA224_DIGESTLEN, kp, klen, hmac_keylen_msg, sizeof(hmac_keylen_msg), tag);
    munit_assert_memory_equal(TC_SHA224_DIGESTLEN, tag, hmac_keylen_sha224[i]);
    if (klen > TC_SHA224_BLOCKLEN)
    {
      TC_SHA224_digest(key, klen, hashed);
      full_tag(TC_SHA224_DIGESTLEN, hashed, TC_SHA224_DIGESTLEN, hmac_keylen_msg, sizeof(hmac_keylen_msg), tag2);
      munit_assert_memory_equal(TC_SHA224_DIGESTLEN, tag, tag2);
    }
#endif
#if TC_ENABLE_SHA384
    full_tag(TC_SHA384_DIGESTLEN, kp, klen, hmac_keylen_msg, sizeof(hmac_keylen_msg), tag);
    munit_assert_memory_equal(TC_SHA384_DIGESTLEN, tag, hmac_keylen_sha384[i]);
    if (klen > TC_SHA384_BLOCKLEN)
    {
      TC_SHA384_digest(key, klen, hashed);
      full_tag(TC_SHA384_DIGESTLEN, hashed, TC_SHA384_DIGESTLEN, hmac_keylen_msg, sizeof(hmac_keylen_msg), tag2);
      munit_assert_memory_equal(TC_SHA384_DIGESTLEN, tag, tag2);
    }
#endif
#if TC_ENABLE_SHA512
    full_tag(TC_SHA512_DIGESTLEN, kp, klen, hmac_keylen_msg, sizeof(hmac_keylen_msg), tag);
    munit_assert_memory_equal(TC_SHA512_DIGESTLEN, tag, hmac_keylen_sha512[i]);
    if (klen > TC_SHA512_BLOCKLEN)
    {
      TC_SHA512_digest(key, klen, hashed);
      full_tag(TC_SHA512_DIGESTLEN, hashed, TC_SHA512_DIGESTLEN, hmac_keylen_msg, sizeof(hmac_keylen_msg), tag2);
      munit_assert_memory_equal(TC_SHA512_DIGESTLEN, tag, tag2);
    }
#endif
  }

  /* NULL key with non-zero length is rejected by init */
#if TC_ENABLE_SHA256
  {
    struct TC_HMAC_SHA256_ctx ctx;
    munit_assert_int(TC_HMAC_SHA256_init(&ctx, NULL, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA256_init(NULL, key, 1), ==, TC_ERROR);
  }
#endif
#if TC_ENABLE_SHA224
  {
    struct TC_HMAC_SHA224_ctx ctx;
    munit_assert_int(TC_HMAC_SHA224_init(&ctx, NULL, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA224_init(NULL, key, 1), ==, TC_ERROR);
  }
#endif
#if TC_ENABLE_SHA384
  {
    struct TC_HMAC_SHA384_ctx ctx;
    munit_assert_int(TC_HMAC_SHA384_init(&ctx, NULL, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA384_init(NULL, key, 1), ==, TC_ERROR);
  }
#endif
#if TC_ENABLE_SHA512
  {
    struct TC_HMAC_SHA512_ctx ctx;
    munit_assert_int(TC_HMAC_SHA512_init(&ctx, NULL, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA512_init(NULL, key, 1), ==, TC_ERROR);
  }
#endif
#if TC_ENABLE_SHA1
  {
    struct TC_HMAC_SHA1_ctx ctx;
    munit_assert_int(TC_HMAC_SHA1_init(&ctx, NULL, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA1_init(NULL, key, 1), ==, TC_ERROR);
  }
#endif

#if SIZE_MAX > (UINT64_MAX >> 3)
  /* A length rejected by the digest must propagate through HMAC. The pointer
     is never read because the length check happens before compression. */
  {
    const size_t excessive = (size_t)(UINT64_MAX >> 3) + 1U;
#if TC_ENABLE_SHA256
    struct TC_HMAC_SHA256_ctx sha256_ctx;
    munit_assert_int(TC_HMAC_SHA256_init(&sha256_ctx, key, excessive), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA256_digest(key, 1, key, excessive,
                                tag, TC_SHA256_DIGESTLEN), ==, TC_ERROR);
#endif
#if TC_ENABLE_SHA224
    struct TC_HMAC_SHA224_ctx sha224_ctx;
    munit_assert_int(TC_HMAC_SHA224_init(&sha224_ctx, key, excessive), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA224_digest(key, 1, key, excessive,
                                tag, TC_SHA224_DIGESTLEN), ==, TC_ERROR);
#endif
#if TC_ENABLE_SHA1
    struct TC_HMAC_SHA1_ctx sha1_ctx;
    munit_assert_int(TC_HMAC_SHA1_init(&sha1_ctx, key, excessive), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA1_digest(key, 1, key, excessive,
                              tag, TC_SHA1_DIGESTLEN), ==, TC_ERROR);
#endif
  }
#endif
  return MUNIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Truncation bounds                                                         */
/* ------------------------------------------------------------------------- */

MunitResult test_hmac_truncation(const MunitParameter params[], void* data)
{
  uint8_t key[16];
  uint8_t msg[40];
  uint8_t full[TC_SHA512_DIGESTLEN];
  uint8_t tag[TC_SHA512_DIGESTLEN + 1];
  (void) params;
  (void) data;

  tc_test_fill_incrementing(key, sizeof(key));
  tc_test_fill_incrementing(msg, sizeof(msg));

#if TC_ENABLE_SHA256
  full_tag(TC_SHA256_DIGESTLEN, key, sizeof(key), msg, sizeof(msg), full);
  munit_assert_int(TC_HMAC_SHA256_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  munit_assert_memory_equal(TC_HMAC_MIN_TAG_LEN, tag, full);
  munit_assert_int(TC_HMAC_SHA256_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA256_DIGESTLEN - 1), ==, TC_OK);
  munit_assert_memory_equal(TC_SHA256_DIGESTLEN - 1, tag, full);
  munit_assert_int(TC_HMAC_SHA256_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA256_DIGESTLEN), ==, TC_OK);
  munit_assert_memory_equal(TC_SHA256_DIGESTLEN, tag, full);

  munit_assert_int(TC_HMAC_SHA256_digest(key, sizeof(key), msg, sizeof(msg), tag, 0), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA256_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN - 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA256_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA256_DIGESTLEN + 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA256_digest(key, sizeof(key), msg, sizeof(msg), NULL, TC_SHA256_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA256_digest(key, sizeof(key), NULL, 1, tag, TC_SHA256_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA256_digest(NULL, 1, msg, sizeof(msg), tag, TC_SHA256_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA256_verify(key, sizeof(key), msg, sizeof(msg), full, 0), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA256_verify(key, sizeof(key), msg, sizeof(msg), full, TC_HMAC_MIN_TAG_LEN - 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA256_verify(key, sizeof(key), msg, sizeof(msg), full, TC_SHA256_DIGESTLEN + 1), ==, TC_ERROR);
#endif
#if TC_ENABLE_SHA224
  full_tag(TC_SHA224_DIGESTLEN, key, sizeof(key), msg, sizeof(msg), full);
  munit_assert_int(TC_HMAC_SHA224_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  munit_assert_memory_equal(TC_HMAC_MIN_TAG_LEN, tag, full);
  munit_assert_int(TC_HMAC_SHA224_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA224_DIGESTLEN - 1), ==, TC_OK);
  munit_assert_memory_equal(TC_SHA224_DIGESTLEN - 1, tag, full);
  munit_assert_int(TC_HMAC_SHA224_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA224_DIGESTLEN), ==, TC_OK);
  munit_assert_memory_equal(TC_SHA224_DIGESTLEN, tag, full);

  munit_assert_int(TC_HMAC_SHA224_digest(key, sizeof(key), msg, sizeof(msg), tag, 0), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA224_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN - 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA224_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA224_DIGESTLEN + 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA224_digest(key, sizeof(key), msg, sizeof(msg), NULL, TC_SHA224_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA224_digest(key, sizeof(key), NULL, 1, tag, TC_SHA224_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA224_digest(NULL, 1, msg, sizeof(msg), tag, TC_SHA224_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA224_verify(key, sizeof(key), msg, sizeof(msg), full, 0), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA224_verify(key, sizeof(key), msg, sizeof(msg), full, TC_HMAC_MIN_TAG_LEN - 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA224_verify(key, sizeof(key), msg, sizeof(msg), full, TC_SHA224_DIGESTLEN + 1), ==, TC_ERROR);
#endif
#if TC_ENABLE_SHA384
  full_tag(TC_SHA384_DIGESTLEN, key, sizeof(key), msg, sizeof(msg), full);
  munit_assert_int(TC_HMAC_SHA384_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  munit_assert_memory_equal(TC_HMAC_MIN_TAG_LEN, tag, full);
  munit_assert_int(TC_HMAC_SHA384_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA384_DIGESTLEN - 1), ==, TC_OK);
  munit_assert_memory_equal(TC_SHA384_DIGESTLEN - 1, tag, full);
  munit_assert_int(TC_HMAC_SHA384_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA384_DIGESTLEN), ==, TC_OK);
  munit_assert_memory_equal(TC_SHA384_DIGESTLEN, tag, full);

  munit_assert_int(TC_HMAC_SHA384_digest(key, sizeof(key), msg, sizeof(msg), tag, 0), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA384_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN - 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA384_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA384_DIGESTLEN + 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA384_digest(key, sizeof(key), msg, sizeof(msg), NULL, TC_SHA384_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA384_digest(key, sizeof(key), NULL, 1, tag, TC_SHA384_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA384_digest(NULL, 1, msg, sizeof(msg), tag, TC_SHA384_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA384_verify(key, sizeof(key), msg, sizeof(msg), full, 0), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA384_verify(key, sizeof(key), msg, sizeof(msg), full, TC_HMAC_MIN_TAG_LEN - 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA384_verify(key, sizeof(key), msg, sizeof(msg), full, TC_SHA384_DIGESTLEN + 1), ==, TC_ERROR);
#endif
#if TC_ENABLE_SHA512
  full_tag(TC_SHA512_DIGESTLEN, key, sizeof(key), msg, sizeof(msg), full);
  munit_assert_int(TC_HMAC_SHA512_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  munit_assert_memory_equal(TC_HMAC_MIN_TAG_LEN, tag, full);
  munit_assert_int(TC_HMAC_SHA512_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA512_DIGESTLEN - 1), ==, TC_OK);
  munit_assert_memory_equal(TC_SHA512_DIGESTLEN - 1, tag, full);
  munit_assert_int(TC_HMAC_SHA512_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA512_DIGESTLEN), ==, TC_OK);
  munit_assert_memory_equal(TC_SHA512_DIGESTLEN, tag, full);

  munit_assert_int(TC_HMAC_SHA512_digest(key, sizeof(key), msg, sizeof(msg), tag, 0), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA512_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN - 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA512_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA512_DIGESTLEN + 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA512_digest(key, sizeof(key), msg, sizeof(msg), NULL, TC_SHA512_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA512_digest(key, sizeof(key), NULL, 1, tag, TC_SHA512_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA512_digest(NULL, 1, msg, sizeof(msg), tag, TC_SHA512_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA512_verify(key, sizeof(key), msg, sizeof(msg), full, 0), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA512_verify(key, sizeof(key), msg, sizeof(msg), full, TC_HMAC_MIN_TAG_LEN - 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA512_verify(key, sizeof(key), msg, sizeof(msg), full, TC_SHA512_DIGESTLEN + 1), ==, TC_ERROR);
#endif

#if TC_ENABLE_SHA1
  full_tag(TC_SHA1_DIGESTLEN, key, sizeof(key), msg, sizeof(msg), full);
  munit_assert_int(TC_HMAC_SHA1_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  munit_assert_memory_equal(TC_HMAC_MIN_TAG_LEN, tag, full);
  munit_assert_int(TC_HMAC_SHA1_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA1_DIGESTLEN - 1), ==, TC_OK);
  munit_assert_memory_equal(TC_SHA1_DIGESTLEN - 1, tag, full);
  munit_assert_int(TC_HMAC_SHA1_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA1_DIGESTLEN), ==, TC_OK);
  munit_assert_memory_equal(TC_SHA1_DIGESTLEN, tag, full);

  munit_assert_int(TC_HMAC_SHA1_digest(key, sizeof(key), msg, sizeof(msg), tag, 0), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA1_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN - 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA1_digest(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA1_DIGESTLEN + 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA1_digest(key, sizeof(key), msg, sizeof(msg), NULL, TC_SHA1_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA1_digest(key, sizeof(key), NULL, 1, tag, TC_SHA1_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA1_digest(NULL, 1, msg, sizeof(msg), tag, TC_SHA1_DIGESTLEN), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA1_verify(key, sizeof(key), msg, sizeof(msg), full, 0), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA1_verify(key, sizeof(key), msg, sizeof(msg), full, TC_HMAC_MIN_TAG_LEN - 1), ==, TC_ERROR);
  munit_assert_int(TC_HMAC_SHA1_verify(key, sizeof(key), msg, sizeof(msg), full, TC_SHA1_DIGESTLEN + 1), ==, TC_ERROR);
#endif
  return MUNIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Verify: correct tags pass, single-byte flips fail                         */
/* ------------------------------------------------------------------------- */

MunitResult test_hmac_verify(const MunitParameter params[], void* data)
{
  uint8_t key[20];
  uint8_t msg[70];
  uint8_t tag[TC_SHA512_DIGESTLEN];
  (void) params;
  (void) data;

  tc_test_fill_incrementing(key, sizeof(key));
  tc_test_fill_incrementing(msg, sizeof(msg));

#if TC_ENABLE_SHA256
  full_tag(TC_SHA256_DIGESTLEN, key, sizeof(key), msg, sizeof(msg), tag);
  munit_assert_int(TC_HMAC_SHA256_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA256_DIGESTLEN), ==, TC_OK);
  munit_assert_int(TC_HMAC_SHA256_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  tag[0] ^= 0x01U;
  munit_assert_int(TC_HMAC_SHA256_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA256_DIGESTLEN), ==, TC_MISMATCH);
  tag[0] ^= 0x01U;
  tag[TC_SHA256_DIGESTLEN - 1] ^= 0x80U;
  munit_assert_int(TC_HMAC_SHA256_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA256_DIGESTLEN), ==, TC_MISMATCH);
  /* The flipped byte is outside a MIN-length prefix, so that prefix still verifies */
  munit_assert_int(TC_HMAC_SHA256_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  tag[TC_SHA256_DIGESTLEN - 1] ^= 0x80U;
  tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 0x10U;
  munit_assert_int(TC_HMAC_SHA256_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_MISMATCH);
  tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 0x10U;
  munit_assert_int(TC_HMAC_SHA256_verify(key, sizeof(key), msg, sizeof(msg), NULL, TC_SHA256_DIGESTLEN), ==, TC_ERROR);
  /* Wrong key */
  key[0] ^= 0xFFU;
  munit_assert_int(TC_HMAC_SHA256_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA256_DIGESTLEN), ==, TC_MISMATCH);
  key[0] ^= 0xFFU;
#endif
#if TC_ENABLE_SHA224
  full_tag(TC_SHA224_DIGESTLEN, key, sizeof(key), msg, sizeof(msg), tag);
  munit_assert_int(TC_HMAC_SHA224_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA224_DIGESTLEN), ==, TC_OK);
  munit_assert_int(TC_HMAC_SHA224_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  tag[0] ^= 0x01U;
  munit_assert_int(TC_HMAC_SHA224_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA224_DIGESTLEN), ==, TC_MISMATCH);
  tag[0] ^= 0x01U;
  tag[TC_SHA224_DIGESTLEN - 1] ^= 0x80U;
  munit_assert_int(TC_HMAC_SHA224_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA224_DIGESTLEN), ==, TC_MISMATCH);
  /* The flipped byte is outside a MIN-length prefix, so that prefix still verifies */
  munit_assert_int(TC_HMAC_SHA224_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  tag[TC_SHA224_DIGESTLEN - 1] ^= 0x80U;
  tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 0x10U;
  munit_assert_int(TC_HMAC_SHA224_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_MISMATCH);
  tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 0x10U;
  munit_assert_int(TC_HMAC_SHA224_verify(key, sizeof(key), msg, sizeof(msg), NULL, TC_SHA224_DIGESTLEN), ==, TC_ERROR);
  /* Wrong key */
  key[0] ^= 0xFFU;
  munit_assert_int(TC_HMAC_SHA224_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA224_DIGESTLEN), ==, TC_MISMATCH);
  key[0] ^= 0xFFU;
#endif
#if TC_ENABLE_SHA384
  full_tag(TC_SHA384_DIGESTLEN, key, sizeof(key), msg, sizeof(msg), tag);
  munit_assert_int(TC_HMAC_SHA384_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA384_DIGESTLEN), ==, TC_OK);
  munit_assert_int(TC_HMAC_SHA384_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  tag[0] ^= 0x01U;
  munit_assert_int(TC_HMAC_SHA384_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA384_DIGESTLEN), ==, TC_MISMATCH);
  tag[0] ^= 0x01U;
  tag[TC_SHA384_DIGESTLEN - 1] ^= 0x80U;
  munit_assert_int(TC_HMAC_SHA384_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA384_DIGESTLEN), ==, TC_MISMATCH);
  /* The flipped byte is outside a MIN-length prefix, so that prefix still verifies */
  munit_assert_int(TC_HMAC_SHA384_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  tag[TC_SHA384_DIGESTLEN - 1] ^= 0x80U;
  tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 0x10U;
  munit_assert_int(TC_HMAC_SHA384_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_MISMATCH);
  tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 0x10U;
  munit_assert_int(TC_HMAC_SHA384_verify(key, sizeof(key), msg, sizeof(msg), NULL, TC_SHA384_DIGESTLEN), ==, TC_ERROR);
  /* Wrong key */
  key[0] ^= 0xFFU;
  munit_assert_int(TC_HMAC_SHA384_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA384_DIGESTLEN), ==, TC_MISMATCH);
  key[0] ^= 0xFFU;
#endif
#if TC_ENABLE_SHA512
  full_tag(TC_SHA512_DIGESTLEN, key, sizeof(key), msg, sizeof(msg), tag);
  munit_assert_int(TC_HMAC_SHA512_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA512_DIGESTLEN), ==, TC_OK);
  munit_assert_int(TC_HMAC_SHA512_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  tag[0] ^= 0x01U;
  munit_assert_int(TC_HMAC_SHA512_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA512_DIGESTLEN), ==, TC_MISMATCH);
  tag[0] ^= 0x01U;
  tag[TC_SHA512_DIGESTLEN - 1] ^= 0x80U;
  munit_assert_int(TC_HMAC_SHA512_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA512_DIGESTLEN), ==, TC_MISMATCH);
  /* The flipped byte is outside a MIN-length prefix, so that prefix still verifies */
  munit_assert_int(TC_HMAC_SHA512_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  tag[TC_SHA512_DIGESTLEN - 1] ^= 0x80U;
  tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 0x10U;
  munit_assert_int(TC_HMAC_SHA512_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_MISMATCH);
  tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 0x10U;
  munit_assert_int(TC_HMAC_SHA512_verify(key, sizeof(key), msg, sizeof(msg), NULL, TC_SHA512_DIGESTLEN), ==, TC_ERROR);
  /* Wrong key */
  key[0] ^= 0xFFU;
  munit_assert_int(TC_HMAC_SHA512_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA512_DIGESTLEN), ==, TC_MISMATCH);
  key[0] ^= 0xFFU;
#endif

#if TC_ENABLE_SHA1
  full_tag(TC_SHA1_DIGESTLEN, key, sizeof(key), msg, sizeof(msg), tag);
  munit_assert_int(TC_HMAC_SHA1_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA1_DIGESTLEN), ==, TC_OK);
  munit_assert_int(TC_HMAC_SHA1_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_OK);
  tag[0] ^= 0x01U;
  munit_assert_int(TC_HMAC_SHA1_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA1_DIGESTLEN), ==, TC_MISMATCH);
  tag[0] ^= 0x01U;
  tag[TC_SHA1_DIGESTLEN - 1] ^= 0x80U;
  munit_assert_int(TC_HMAC_SHA1_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_SHA1_DIGESTLEN), ==, TC_MISMATCH);
  tag[TC_SHA1_DIGESTLEN - 1] ^= 0x80U;
  tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 0x10U;
  munit_assert_int(TC_HMAC_SHA1_verify(key, sizeof(key), msg, sizeof(msg), tag, TC_HMAC_MIN_TAG_LEN), ==, TC_MISMATCH);
  tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 0x10U;
  munit_assert_int(TC_HMAC_SHA1_verify(key, sizeof(key), msg, sizeof(msg), NULL, TC_SHA1_DIGESTLEN), ==, TC_ERROR);
#endif
  return MUNIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Streaming equals one-shot; empty message with NULL pointer                */
/* ------------------------------------------------------------------------- */

MunitResult test_hmac_streaming(const MunitParameter params[], void* data)
{
  uint8_t key[33];
  uint8_t msg[150];
  uint8_t expected[TC_SHA512_DIGESTLEN];
  uint8_t tag[TC_SHA512_DIGESTLEN];
  size_t split;
  (void) params;
  (void) data;

  tc_test_fill_incrementing(key, sizeof(key));
  tc_test_fill_incrementing(msg, sizeof(msg));

#if TC_ENABLE_SHA256
  munit_assert_int(TC_HMAC_SHA256_digest(key, sizeof(key), msg, sizeof(msg), expected, TC_SHA256_DIGESTLEN), ==, TC_OK);
  for (split = 0; split <= sizeof(msg); split += 7)
  {
    struct TC_HMAC_SHA256_ctx ctx;
    munit_assert_int(TC_HMAC_SHA256_init(&ctx, key, sizeof(key)), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA256_update(&ctx, msg, split), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA256_update(&ctx, msg + split, sizeof(msg) - split), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA256_final(&ctx, tag), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, tag, expected);
  }
  {
    struct TC_HMAC_SHA256_ctx ctx;
    munit_assert_int(TC_HMAC_SHA256_digest(key, sizeof(key), NULL, 0, expected, TC_SHA256_DIGESTLEN), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA256_init(&ctx, key, sizeof(key)), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA256_update(&ctx, NULL, 0), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA256_final(&ctx, tag), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, tag, expected);
#if TC_STRICT
    munit_assert_int(TC_HMAC_SHA256_update(NULL, msg, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA256_update(&ctx, NULL, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA256_final(NULL, tag), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA256_final(&ctx, NULL), ==, TC_ERROR);
#endif
  }
#endif
#if TC_ENABLE_SHA224
  munit_assert_int(TC_HMAC_SHA224_digest(key, sizeof(key), msg, sizeof(msg), expected, TC_SHA224_DIGESTLEN), ==, TC_OK);
  for (split = 0; split <= sizeof(msg); split += 7)
  {
    struct TC_HMAC_SHA224_ctx ctx;
    munit_assert_int(TC_HMAC_SHA224_init(&ctx, key, sizeof(key)), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA224_update(&ctx, msg, split), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA224_update(&ctx, msg + split, sizeof(msg) - split), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA224_final(&ctx, tag), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA224_DIGESTLEN, tag, expected);
  }
  {
    struct TC_HMAC_SHA224_ctx ctx;
    munit_assert_int(TC_HMAC_SHA224_digest(key, sizeof(key), NULL, 0, expected, TC_SHA224_DIGESTLEN), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA224_init(&ctx, key, sizeof(key)), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA224_update(&ctx, NULL, 0), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA224_final(&ctx, tag), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA224_DIGESTLEN, tag, expected);
#if TC_STRICT
    munit_assert_int(TC_HMAC_SHA224_update(NULL, msg, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA224_update(&ctx, NULL, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA224_final(NULL, tag), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA224_final(&ctx, NULL), ==, TC_ERROR);
#endif
  }
#endif
#if TC_ENABLE_SHA384
  munit_assert_int(TC_HMAC_SHA384_digest(key, sizeof(key), msg, sizeof(msg), expected, TC_SHA384_DIGESTLEN), ==, TC_OK);
  for (split = 0; split <= sizeof(msg); split += 7)
  {
    struct TC_HMAC_SHA384_ctx ctx;
    munit_assert_int(TC_HMAC_SHA384_init(&ctx, key, sizeof(key)), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA384_update(&ctx, msg, split), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA384_update(&ctx, msg + split, sizeof(msg) - split), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA384_final(&ctx, tag), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA384_DIGESTLEN, tag, expected);
  }
  {
    struct TC_HMAC_SHA384_ctx ctx;
    munit_assert_int(TC_HMAC_SHA384_digest(key, sizeof(key), NULL, 0, expected, TC_SHA384_DIGESTLEN), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA384_init(&ctx, key, sizeof(key)), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA384_update(&ctx, NULL, 0), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA384_final(&ctx, tag), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA384_DIGESTLEN, tag, expected);
#if TC_STRICT
    munit_assert_int(TC_HMAC_SHA384_update(NULL, msg, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA384_update(&ctx, NULL, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA384_final(NULL, tag), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA384_final(&ctx, NULL), ==, TC_ERROR);
#endif
  }
#endif
#if TC_ENABLE_SHA512
  munit_assert_int(TC_HMAC_SHA512_digest(key, sizeof(key), msg, sizeof(msg), expected, TC_SHA512_DIGESTLEN), ==, TC_OK);
  for (split = 0; split <= sizeof(msg); split += 7)
  {
    struct TC_HMAC_SHA512_ctx ctx;
    munit_assert_int(TC_HMAC_SHA512_init(&ctx, key, sizeof(key)), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA512_update(&ctx, msg, split), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA512_update(&ctx, msg + split, sizeof(msg) - split), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA512_final(&ctx, tag), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA512_DIGESTLEN, tag, expected);
  }
  {
    struct TC_HMAC_SHA512_ctx ctx;
    munit_assert_int(TC_HMAC_SHA512_digest(key, sizeof(key), NULL, 0, expected, TC_SHA512_DIGESTLEN), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA512_init(&ctx, key, sizeof(key)), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA512_update(&ctx, NULL, 0), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA512_final(&ctx, tag), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA512_DIGESTLEN, tag, expected);
#if TC_STRICT
    munit_assert_int(TC_HMAC_SHA512_update(NULL, msg, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA512_update(&ctx, NULL, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA512_final(NULL, tag), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA512_final(&ctx, NULL), ==, TC_ERROR);
#endif
  }
#endif

#if TC_ENABLE_SHA1
  munit_assert_int(TC_HMAC_SHA1_digest(key, sizeof(key), msg, sizeof(msg), expected, TC_SHA1_DIGESTLEN), ==, TC_OK);
  for (split = 0; split <= sizeof(msg); split += 7)
  {
    struct TC_HMAC_SHA1_ctx ctx;
    munit_assert_int(TC_HMAC_SHA1_init(&ctx, key, sizeof(key)), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA1_update(&ctx, msg, split), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA1_update(&ctx, msg + split, sizeof(msg) - split), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA1_final(&ctx, tag), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA1_DIGESTLEN, tag, expected);
  }
  {
    struct TC_HMAC_SHA1_ctx ctx;
    munit_assert_int(TC_HMAC_SHA1_digest(key, sizeof(key), NULL, 0, expected, TC_SHA1_DIGESTLEN), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA1_init(&ctx, key, sizeof(key)), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA1_update(&ctx, NULL, 0), ==, TC_OK);
    munit_assert_int(TC_HMAC_SHA1_final(&ctx, tag), ==, TC_OK);
    munit_assert_memory_equal(TC_SHA1_DIGESTLEN, tag, expected);
#if TC_STRICT
    munit_assert_int(TC_HMAC_SHA1_update(NULL, msg, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA1_update(&ctx, NULL, 1), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA1_final(NULL, tag), ==, TC_ERROR);
    munit_assert_int(TC_HMAC_SHA1_final(&ctx, NULL), ==, TC_ERROR);
#endif
  }
#endif
  return MUNIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Zeroization                                                               */
/* ------------------------------------------------------------------------- */

MunitResult test_hmac_zeroize(const MunitParameter params[], void* data)
{
  uint8_t key[16];
  uint8_t tag[TC_SHA512_DIGESTLEN];
  (void) params;
  (void) data;

  tc_test_fill_incrementing(key, sizeof(key));

#if TC_ENABLE_SHA256
  {
    struct TC_HMAC_SHA256_ctx ctx;
    TC_HMAC_SHA256_init(&ctx, key, sizeof(key));
    munit_assert_false(tc_test_all_zero(&ctx, sizeof(ctx)));
    TC_HMAC_SHA256_final(&ctx, tag);
#if TC_ZEROIZE
    munit_assert_true(tc_test_all_zero(&ctx, sizeof(ctx)));
#endif
    TC_HMAC_SHA256_init(&ctx, key, sizeof(key));
    TC_HMAC_SHA256_ctx_clear(&ctx);
    munit_assert_true(tc_test_all_zero(&ctx, sizeof(ctx)));
    TC_HMAC_SHA256_ctx_clear(NULL);
  }
#endif
#if TC_ENABLE_SHA224
  {
    struct TC_HMAC_SHA224_ctx ctx;
    TC_HMAC_SHA224_init(&ctx, key, sizeof(key));
    munit_assert_false(tc_test_all_zero(&ctx, sizeof(ctx)));
    TC_HMAC_SHA224_final(&ctx, tag);
#if TC_ZEROIZE
    munit_assert_true(tc_test_all_zero(&ctx, sizeof(ctx)));
#endif
    TC_HMAC_SHA224_init(&ctx, key, sizeof(key));
    TC_HMAC_SHA224_ctx_clear(&ctx);
    munit_assert_true(tc_test_all_zero(&ctx, sizeof(ctx)));
    TC_HMAC_SHA224_ctx_clear(NULL);
  }
#endif
#if TC_ENABLE_SHA384
  {
    struct TC_HMAC_SHA384_ctx ctx;
    TC_HMAC_SHA384_init(&ctx, key, sizeof(key));
    munit_assert_false(tc_test_all_zero(&ctx, sizeof(ctx)));
    TC_HMAC_SHA384_final(&ctx, tag);
#if TC_ZEROIZE
    munit_assert_true(tc_test_all_zero(&ctx, sizeof(ctx)));
#endif
    TC_HMAC_SHA384_init(&ctx, key, sizeof(key));
    TC_HMAC_SHA384_ctx_clear(&ctx);
    munit_assert_true(tc_test_all_zero(&ctx, sizeof(ctx)));
    TC_HMAC_SHA384_ctx_clear(NULL);
  }
#endif
#if TC_ENABLE_SHA512
  {
    struct TC_HMAC_SHA512_ctx ctx;
    TC_HMAC_SHA512_init(&ctx, key, sizeof(key));
    munit_assert_false(tc_test_all_zero(&ctx, sizeof(ctx)));
    TC_HMAC_SHA512_final(&ctx, tag);
#if TC_ZEROIZE
    munit_assert_true(tc_test_all_zero(&ctx, sizeof(ctx)));
#endif
    TC_HMAC_SHA512_init(&ctx, key, sizeof(key));
    TC_HMAC_SHA512_ctx_clear(&ctx);
    munit_assert_true(tc_test_all_zero(&ctx, sizeof(ctx)));
    TC_HMAC_SHA512_ctx_clear(NULL);
  }
#endif
#if TC_ENABLE_SHA1
  {
    struct TC_HMAC_SHA1_ctx ctx;
    TC_HMAC_SHA1_init(&ctx, key, sizeof(key));
    munit_assert_false(tc_test_all_zero(&ctx, sizeof(ctx)));
    TC_HMAC_SHA1_final(&ctx, tag);
#if TC_ZEROIZE
    munit_assert_true(tc_test_all_zero(&ctx, sizeof(ctx)));
#endif
    TC_HMAC_SHA1_init(&ctx, key, sizeof(key));
    TC_HMAC_SHA1_ctx_clear(&ctx);
    munit_assert_true(tc_test_all_zero(&ctx, sizeof(ctx)));
    TC_HMAC_SHA1_ctx_clear(NULL);
  }
#endif
  return MUNIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Wycheproof (mac_test_schema_v1): line-oriented scan, no JSON library      */
/* ------------------------------------------------------------------------- */

/* Returns pointer just past `"name":` (whitespace skipped) or NULL. */
static const char* json_field(const char* line, const char* name)
{
  char pattern[64];
  const char* p;
  snprintf(pattern, sizeof(pattern), "\"%s\"", name);
  p = strstr(line, pattern);
  if (p == NULL)
    return NULL;
  p += strlen(pattern);
  while (*p == ' ' || *p == '\t')
    p++;
  if (*p != ':')
    return NULL;
  p++;
  while (*p == ' ' || *p == '\t')
    p++;
  return p;
}

static long json_number(const char* p)
{
  return strtol(p, NULL, 10);
}

/* Decodes the quoted hex string at p. */
static size_t json_hex(const char* p, uint8_t* out, size_t capacity)
{
  if (*p != '"')
    return SIZE_MAX;
  return tc_test_decode_hex(p + 1, out, capacity);
}

struct wycheproof_case
{
  long tc_id;
  long key_bits;
  long tag_bits;
  uint8_t key[256];
  size_t key_len;
  uint8_t msg[1024];
  size_t msg_len;
  uint8_t tag[TC_SHA512_DIGESTLEN];
  size_t tag_len;
  int have_key, have_msg, have_tag;
};

static void run_wycheproof_file(int alg, const char* path)
{
  FILE* file;
  static char line[4096];
  struct wycheproof_case tc;
  long expected_total = -1;
  long ran = 0;
  const size_t digest_len = (size_t)alg;

  file = tc_test_fopen(path, "r");
  if (file == NULL)
    munit_errorf("cannot open Wycheproof file %s", path);

  memset(&tc, 0, sizeof(tc));

  while (fgets(line, sizeof(line), file) != NULL)
  {
    const char* p;

    if (expected_total < 0 && (p = json_field(line, "numberOfTests")) != NULL)
      expected_total = json_number(p);
    else if ((p = json_field(line, "keySize")) != NULL)
      tc.key_bits = json_number(p);
    else if ((p = json_field(line, "tagSize")) != NULL)
      tc.tag_bits = json_number(p);
    else if ((p = json_field(line, "tcId")) != NULL)
    {
      tc.tc_id = json_number(p);
      tc.have_key = tc.have_msg = tc.have_tag = 0;
    }
    else if ((p = json_field(line, "key")) != NULL)
    {
      tc.key_len = json_hex(p, tc.key, sizeof(tc.key));
      munit_assert_size(tc.key_len, !=, SIZE_MAX);
      tc.have_key = 1;
    }
    else if ((p = json_field(line, "msg")) != NULL)
    {
      tc.msg_len = json_hex(p, tc.msg, sizeof(tc.msg));
      munit_assert_size(tc.msg_len, !=, SIZE_MAX);
      tc.have_msg = 1;
    }
    else if ((p = json_field(line, "tag")) != NULL)
    {
      tc.tag_len = json_hex(p, tc.tag, sizeof(tc.tag));
      munit_assert_size(tc.tag_len, !=, SIZE_MAX);
      tc.have_tag = 1;
    }
    else if ((p = json_field(line, "result")) != NULL)
    {
      uint8_t computed[TC_SHA512_DIGESTLEN];
      int valid;
      int matches;

      munit_assert_true(tc.have_key && tc.have_msg && tc.have_tag);
      munit_assert_size(tc.key_len, ==, (size_t)tc.key_bits / 8);
      munit_assert_size(tc.tag_len, ==, (size_t)tc.tag_bits / 8);
      munit_assert_size(tc.tag_len, <=, digest_len);

      valid = (strncmp(p, "\"valid\"", 7) == 0);
      if (!valid)
        munit_assert_true(strncmp(p, "\"invalid\"", 9) == 0);

      full_tag(alg, tc.key, tc.key_len, tc.msg, tc.msg_len, computed);
      matches = (memcmp(computed, tc.tag, tc.tag_len) == 0);
      if (matches != valid)
        munit_errorf("%s tcId %ld: expected %s", path, tc.tc_id, valid ? "match" : "mismatch");

      /* The public verify API agrees whenever the tag length is in range. */
      if (tc.tag_len >= TC_HMAC_MIN_TAG_LEN)
      {
        int rc = hmac_verify(alg, tc.key, tc.key_len, tc.msg, tc.msg_len, tc.tag, tc.tag_len);
        munit_assert_int(rc, ==, valid ? TC_OK : TC_MISMATCH);
      }
      ran++;
    }
  }
  fclose(file);

  munit_assert_long(expected_total, >, 0);
  munit_assert_long(ran, ==, expected_total);
}

MunitResult test_hmac_wycheproof(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;
#if TC_ENABLE_SHA1
  run_wycheproof_file(TC_SHA1_DIGESTLEN, HMAC_WYCHEPROOF_DIR "/hmac_sha1_test.json");
#endif
#if TC_ENABLE_SHA224
  run_wycheproof_file(TC_SHA224_DIGESTLEN, HMAC_WYCHEPROOF_DIR "/hmac_sha224_test.json");
#endif
#if TC_ENABLE_SHA256
  run_wycheproof_file(TC_SHA256_DIGESTLEN, HMAC_WYCHEPROOF_DIR "/hmac_sha256_test.json");
#endif
#if TC_ENABLE_SHA384
  run_wycheproof_file(TC_SHA384_DIGESTLEN, HMAC_WYCHEPROOF_DIR "/hmac_sha384_test.json");
#endif
#if TC_ENABLE_SHA512
  run_wycheproof_file(TC_SHA512_DIGESTLEN, HMAC_WYCHEPROOF_DIR "/hmac_sha512_test.json");
#endif
  return MUNIT_OK;
}

#else /* !TC_ENABLE_HMAC */

MunitResult test_hmac_rfc(const MunitParameter params[], void* data)
{ (void) params; (void) data; return MUNIT_SKIP; }
MunitResult test_hmac_key_lengths(const MunitParameter params[], void* data)
{ (void) params; (void) data; return MUNIT_SKIP; }
MunitResult test_hmac_truncation(const MunitParameter params[], void* data)
{ (void) params; (void) data; return MUNIT_SKIP; }
MunitResult test_hmac_verify(const MunitParameter params[], void* data)
{ (void) params; (void) data; return MUNIT_SKIP; }
MunitResult test_hmac_streaming(const MunitParameter params[], void* data)
{ (void) params; (void) data; return MUNIT_SKIP; }
MunitResult test_hmac_zeroize(const MunitParameter params[], void* data)
{ (void) params; (void) data; return MUNIT_SKIP; }
MunitResult test_hmac_wycheproof(const MunitParameter params[], void* data)
{ (void) params; (void) data; return MUNIT_SKIP; }

#endif /* TC_ENABLE_HMAC */
