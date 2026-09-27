/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * SHA-384 / SHA-512 and their HMACs for tiny-crypto-c (FIPS 180-4,
 * FIPS 198-1 / RFC 2104). This is the 64-bit Merkle-Damgard core: 128-byte
 * blocks, eight 64-bit state words, a 128-bit length field. The 32-bit
 * SHA-1 / SHA-224 / SHA-256 core in hash.c is untouched by this file so that
 * SHA-256-only firmware images do not change size.
 */

#include <string.h>
#include <tiny_crypto/common.h>
#if TC_ENABLE_SHA384 || TC_ENABLE_SHA512
#include <tiny_crypto/hash.h>
#endif
#include "internal.h"

/* SHA-384 reuses the SHA-512 compression function; either digest pulls in
 * the shared core, and each public API is gated on its own switch. */
#define TC_HASH_SHA512_CORE (TC_ENABLE_SHA384 || TC_ENABLE_SHA512)

#if TC_HASH_SHA512_CORE
#include "hash_validation_internal.h"
#include "hash_stream_internal.h"
#endif
#if TC_HASH_SHA512_CORE

#if defined(__AVR__) && TC_AVR_PROGMEM
  #include <avr/pgmspace.h>
  #define HASH_K512_STORAGE PROGMEM
  #ifdef pgm_read_qword
    #define HASH_K512_READ(i) pgm_read_qword(&K512[(i)])
  #else
    /* avr-libc < 2.0 has no 64-bit flash read; assemble two little-endian
       dwords the way the compiler laid the constant out. */
    #define HASH_K512_READ(i) \
      (((uint64_t)pgm_read_dword((const uint32_t*)&K512[(i)] + 1) << 32) | \
       (uint64_t)pgm_read_dword((const uint32_t*)&K512[(i)]))
  #endif
#else
  #define HASH_K512_STORAGE
  #define HASH_K512_READ(i) K512[(i)]
#endif

/*****************************************************************************/
/* Private Helpers                                                           */
/*****************************************************************************/

/* Rotation with compile-time constant counts in 1..63 only. */
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

/*****************************************************************************/
/* Shared 128-byte block streaming                                           */
/*****************************************************************************/

/* FIPS 180-4 encodes the SHA-512 message length as 128 bits, so any 64-bit
   byte count is representable: (count >> 61, count << 3). The only limit is
   the 64-bit Count field itself (2^64 - 1 bytes). */
typedef void (*tc_sha512_compress_fn)(uint64_t* state, const uint8_t* block);
typedef struct {
  uint64_t* state;
  tc_sha512_compress_fn compress;
} tc_sha512_operation;

static void tc_sha512_compress_block(void* context, const uint8_t* block)
{
  tc_sha512_operation* operation = (tc_sha512_operation*)context;
  operation->compress(operation->state, block);
}

static TC_status tc_sha512_stream_update(uint64_t* state, uint64_t* count,
                                         uint8_t* buf_len, uint8_t* buf,
                                         const uint8_t* data, size_t len,
                                         tc_sha512_compress_fn compress)
{
  tc_sha512_operation operation = { state, compress };
  if (len == 0)
    return TC_OK;
  if ((uint64_t)len > UINT64_MAX - *count)
    return TC_ERROR;

  *count += (uint64_t)len;
  tc_hash_stream_absorb(&operation, buf_len, buf, data, len,
                        TC_SHA512_BLOCKLEN, tc_sha512_compress_block);
  return TC_OK;
}

static void tc_sha512_stream_final(uint64_t* state, size_t state_words,
                                   uint64_t count, uint8_t* buf_len, uint8_t* buf,
                                   uint8_t* digest, tc_sha512_compress_fn compress)
{
  tc_sha512_operation operation = { state, compress };
  size_t i;

  tc_hash_stream_finish(&operation, count, buf_len, buf,
                        TC_SHA512_BLOCKLEN, 16u,
                        TC_HASH_LENGTH_BIG_ENDIAN, tc_sha512_compress_block);

  for (i = 0; i < state_words; ++i)
    tc_internal_store_be64(digest + (8u * i), state[i]);
}

/*****************************************************************************/
/* SHA-512 compression                                                       */
/*****************************************************************************/

/* Round constants (ROM/Flash, 640 bytes) */
static const uint64_t K512[80] HASH_K512_STORAGE = {
  0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
  0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
  0xD807AA98A3030242ULL, 0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
  0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
  0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
  0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
  0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL,
  0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL, 0x06CA6351E003826FULL, 0x142929670A0E6E70ULL,
  0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
  0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,
  0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL,
  0xD192E819D6EF5218ULL, 0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
  0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,
  0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL,
  0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
  0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,
  0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL, 0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL,
  0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
  0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL, 0x431D67C49C100D4CULL,
  0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL, 0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
};

#define TC_SHA512_CH(x, y, z)  ((z) ^ ((x) & ((y) ^ (z))))
#define TC_SHA512_MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) ^ (y))))
#define TC_SHA512_BSIG0(x)     (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define TC_SHA512_BSIG1(x)     (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define TC_SHA512_SSIG0(x)     (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define TC_SHA512_SSIG1(x)     (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

#define TC_SHA512_STEP(a, b, c, d, e, f, g, h, k, w) do { \
  uint64_t t1 = (h) + TC_SHA512_BSIG1(e) + TC_SHA512_CH((e), (f), (g)) + (k) + (w); \
  uint64_t t2 = TC_SHA512_BSIG0(a) + TC_SHA512_MAJ((a), (b), (c)); \
  h = g; \
  g = f; \
  f = e; \
  e = d + t1; \
  d = c; \
  c = b; \
  b = a; \
  a = t1 + t2; \
} while (0)

/* One 128-byte block. Rolling 16-word schedule keeps the stack small. */
static void tc_sha512_compress_impl(uint64_t state[8],
                                    const uint8_t block[TC_SHA512_BLOCKLEN],
                                    int wipe_schedule)
{
  uint64_t W[16];
  uint64_t a, b, c, d, e, f, g, h;
  unsigned t;

  for (t = 0; t < 16; ++t)
    W[t] = tc_internal_load_be64(block + 8U * t);

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];

  /* Rounds 0..15 */
  for (t = 0; t < 16; ++t)
  {
    TC_SHA512_STEP(a, b, c, d, e, f, g, h, HASH_K512_READ(t), W[t]);
  }

  /* Rounds 16..79 */
  for (t = 16; t < 80; ++t)
  {
    uint64_t w = TC_SHA512_SSIG1(W[(t - 2U) & 15U]) + W[(t - 7U) & 15U] +
                 TC_SHA512_SSIG0(W[(t - 15U) & 15U]) + W[t & 15U];
    W[t & 15U] = w;
    TC_SHA512_STEP(a, b, c, d, e, f, g, h, HASH_K512_READ(t), w);
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;

#if TC_ZEROIZE
  TC_secure_zero(W, sizeof(W));
#endif
  (void)wipe_schedule;
}

static void tc_sha512_compress(uint64_t state[8],
                               const uint8_t block[TC_SHA512_BLOCKLEN])
{
  tc_sha512_compress_impl(state, block, 0);
}

/* HMAC's pad blocks contain key-derived material. Wipe their expanded
 * schedules without paying that cost for ordinary, public-data hashing. */
#if TC_ENABLE_HMAC
static void tc_sha512_compress_secret(uint64_t state[8],
                                      const uint8_t block[TC_SHA512_BLOCKLEN])
{
  tc_sha512_compress_impl(state, block, 1);
}
#endif


/* AVR single-algorithm builds bind the shared body to compile-time
 * constants. Multi-algorithm builds keep descriptors in program memory. */
#if defined(__AVR__) && TC_AVR_PROGMEM
#define TC_HASH_DESC_STORAGE PROGMEM
#else
#define TC_HASH_DESC_STORAGE
#endif

#if defined(__AVR__) && TC_AVR_PROGMEM && \
    (TC_ENABLE_SHA384 + TC_ENABLE_SHA512 == 1)
#if TC_ENABLE_SHA384
#define TC_HASH64_TYPE TC_SHA384_ctx
#define TC_HMAC64_TYPE TC_HMAC_SHA384_ctx
#define TC_HASH64_WORDS 6
#define TC_HASH64_LENGTH TC_SHA384_DIGESTLEN
#define TC_HASH64_INIT tc_sha384_state_init
#else
#define TC_HASH64_TYPE TC_SHA512_ctx
#define TC_HMAC64_TYPE TC_HMAC_SHA512_ctx
#define TC_HASH64_WORDS 8
#define TC_HASH64_LENGTH TC_SHA512_DIGESTLEN
#define TC_HASH64_INIT tc_sha512_state_init
#endif
#define TC_HASH64_FIELD_context_size sizeof(struct TC_HASH64_TYPE)
#define TC_HASH64_FIELD_count_offset offsetof(struct TC_HASH64_TYPE, Count)
#define TC_HASH64_FIELD_state_offset offsetof(struct TC_HASH64_TYPE, State)
#define TC_HASH64_FIELD_buf_len_offset offsetof(struct TC_HASH64_TYPE, BufLen)
#define TC_HASH64_FIELD_active_offset offsetof(struct TC_HASH64_TYPE, active)
#define TC_HASH64_FIELD_buffer_offset offsetof(struct TC_HASH64_TYPE, Buf)
#define TC_HASH64_FIELD_state_words TC_HASH64_WORDS
#define TC_HASH64_FIELD_digest_len TC_HASH64_LENGTH
#define TC_HASH64_FIELD_state_init TC_HASH64_INIT
#define TC_HASH64_FIELD_compress tc_sha512_compress
#define TC_HASH64_FIELD_compress_secret tc_sha512_compress_secret
#define TC_HMAC64_FIELD_context_size sizeof(struct TC_HMAC64_TYPE)
#define TC_HMAC64_FIELD_outer_offset offsetof(struct TC_HMAC64_TYPE, OuterState)
#define TC_HMAC64_FIELD_hash ((const tc_hash64_info*)0)
#define TC_HASH64_READ(info, field) TC_HASH64_FIELD_##field
#define TC_HMAC64_READ(info, field) TC_HMAC64_FIELD_##field
#define TC_HASH_DESC_LOAD(type, source, local) (void)(source)
#elif defined(__AVR__) && TC_AVR_PROGMEM
#define TC_HASH64_READ(info, field) ((info)->field)
#define TC_HMAC64_READ(info, field) ((info)->field)
#define TC_HASH_DESC_LOAD(type, source, local) \
  type local; memcpy_P(&local, source, sizeof(local)); source = &local
#else
#define TC_HASH64_READ(info, field) ((info)->field)
#define TC_HMAC64_READ(info, field) ((info)->field)
#define TC_HASH_DESC_LOAD(type, source, local)
#endif

#if defined(__AVR__) && TC_AVR_PROGMEM && \
    (TC_ENABLE_SHA384 + TC_ENABLE_SHA512 == 1)
static void TC_HASH64_INIT(uint64_t*);
static void tc_sha512_compress(uint64_t*, const uint8_t*);
#if TC_ENABLE_HMAC
static void tc_sha512_compress_secret(uint64_t*, const uint8_t*);
#endif
#endif

/* SHA-384 and SHA-512 share these member offsets. The offset table names
 * typed members without casting one public context to another. */
typedef struct {
  size_t context_size, count_offset, state_offset, buf_len_offset;
  size_t active_offset, buffer_offset;
  uint8_t state_words, digest_len;
  void (*state_init)(uint64_t*);
  tc_sha512_compress_fn compress, compress_secret;
} tc_hash64_info;

#define TC_HASH64_MEMBER(ctx, info, member, type) \
  ((type*)((uint8_t*)(ctx) + TC_HASH64_READ(info, member##_offset)))

static TC_status tc_hash64_init(const tc_hash64_info* info, void* ctx)
{
  TC_HASH_DESC_LOAD(tc_hash64_info, info, local_info);
  if (ctx == NULL) return TC_ERROR;
  TC_secure_zero(ctx, TC_HASH64_READ(info, context_size));
  TC_HASH64_READ(info, state_init)(TC_HASH64_MEMBER(ctx, info, state, uint64_t));
  *TC_HASH64_MEMBER(ctx, info, active, uint8_t) = 1;
  return TC_OK;
}

static TC_status tc_hash64_update(const tc_hash64_info* info, void* ctx,
                                  const uint8_t* data, size_t len)
{
  TC_HASH_DESC_LOAD(tc_hash64_info, info, local_info);
  if (!tc_hash_update_args(ctx, TC_HASH64_READ(info, context_size), data, len) ||
      *TC_HASH64_MEMBER(ctx, info, active, uint8_t) != 1 ||
      *TC_HASH64_MEMBER(ctx, info, buf_len, uint8_t) >= 128)
    return TC_ERROR;
  return tc_sha512_stream_update(TC_HASH64_MEMBER(ctx, info, state, uint64_t),
      TC_HASH64_MEMBER(ctx, info, count, uint64_t),
      TC_HASH64_MEMBER(ctx, info, buf_len, uint8_t),
      TC_HASH64_MEMBER(ctx, info, buffer, uint8_t), data, len, TC_HASH64_READ(info, compress));
}

static TC_status tc_hash64_final(const tc_hash64_info* info, void* ctx,
                                 uint8_t* digest)
{
  TC_HASH_DESC_LOAD(tc_hash64_info, info, local_info);
  if (!tc_hash_final_args(ctx, TC_HASH64_READ(info, context_size), digest, TC_HASH64_READ(info, digest_len)) ||
      *TC_HASH64_MEMBER(ctx, info, active, uint8_t) != 1 ||
      *TC_HASH64_MEMBER(ctx, info, buf_len, uint8_t) >= 128)
    return TC_ERROR;
  tc_sha512_stream_final(TC_HASH64_MEMBER(ctx, info, state, uint64_t),
      TC_HASH64_READ(info, state_words), *TC_HASH64_MEMBER(ctx, info, count, uint64_t),
      TC_HASH64_MEMBER(ctx, info, buf_len, uint8_t),
      TC_HASH64_MEMBER(ctx, info, buffer, uint8_t), digest, TC_HASH64_READ(info, compress));
#if TC_ZEROIZE
  TC_secure_zero(ctx, TC_HASH64_READ(info, context_size));
#else
  *TC_HASH64_MEMBER(ctx, info, active, uint8_t) = 0;
#endif
  return TC_OK;
}

static void tc_hash64_clear(const tc_hash64_info* info, void* ctx)
{
  TC_HASH_DESC_LOAD(tc_hash64_info, info, local_info);
  if (ctx != NULL) TC_secure_zero(ctx, TC_HASH64_READ(info, context_size));
}

#define TC_HASH64_INFO(name, type, words, length, init_fn, compress_fn, secret_fn) \
  static const tc_hash64_info name TC_HASH_DESC_STORAGE = { sizeof(struct type), \
    offsetof(struct type, Count), offsetof(struct type, State), \
    offsetof(struct type, BufLen), offsetof(struct type, active), \
    offsetof(struct type, Buf), words, length, init_fn, compress_fn, secret_fn }


/* Callers provide their typed context so each digest uses its exact stack size. */
static TC_status tc_hash64_digest(const tc_hash64_info* info,
    void* workspace, const uint8_t* data, size_t len, uint8_t* digest)
{
  if (digest == NULL || (len != 0 && data == NULL)) return TC_ERROR;
  if (tc_hash64_init(info, workspace) != TC_OK ||
      tc_hash64_update(info, workspace, data, len) != TC_OK)
  {
    tc_hash64_clear(info, workspace);
    return TC_ERROR;
  }
  return tc_hash64_final(info, workspace, digest);
}

/*****************************************************************************/
/* SHA-512                                                                   */
/*****************************************************************************/

#if TC_ENABLE_SHA512

static void tc_sha512_state_init(uint64_t state[8])
{
  state[0] = 0x6A09E667F3BCC908ULL;
  state[1] = 0xBB67AE8584CAA73BULL;
  state[2] = 0x3C6EF372FE94F82BULL;
  state[3] = 0xA54FF53A5F1D36F1ULL;
  state[4] = 0x510E527FADE682D1ULL;
  state[5] = 0x9B05688C2B3E6C1FULL;
  state[6] = 0x1F83D9ABFB41BD6BULL;
  state[7] = 0x5BE0CD19137E2179ULL;
}

#if TC_ENABLE_HMAC
#define TC_SHA512_SECRET tc_sha512_compress_secret
#else
#define TC_SHA512_SECRET NULL
#endif
TC_HASH64_INFO(tc_sha512_info, TC_SHA512_ctx, 8, TC_SHA512_DIGESTLEN,
               tc_sha512_state_init, tc_sha512_compress, TC_SHA512_SECRET);
#undef TC_SHA512_SECRET

TC_status TC_SHA512_init(struct TC_SHA512_ctx* ctx)
{
  return tc_hash64_init(&tc_sha512_info, ctx);
}

TC_status TC_SHA512_update(struct TC_SHA512_ctx* ctx, const uint8_t* data, size_t len)
{
  return tc_hash64_update(&tc_sha512_info, ctx, data, len);
}

TC_status TC_SHA512_final(struct TC_SHA512_ctx* ctx, uint8_t* digest)
{
  return tc_hash64_final(&tc_sha512_info, ctx, digest);
}

void TC_SHA512_ctx_clear(struct TC_SHA512_ctx* ctx)
{
  tc_hash64_clear(&tc_sha512_info, ctx);
}

TC_status TC_SHA512_digest(const uint8_t* data, size_t len, uint8_t* digest)
{
  struct TC_SHA512_ctx ctx;
  return tc_hash64_digest(&tc_sha512_info, &ctx, data, len, digest);
}

#endif /* TC_ENABLE_SHA512 */

/*****************************************************************************/
/* SHA-384                                                                   */
/*****************************************************************************/

#if TC_ENABLE_SHA384

/* FIPS 180-4 section 5.3.4: fractional parts of the square roots of the
 * 9th through 16th primes. */
static void tc_sha384_state_init(uint64_t state[8])
{
  state[0] = 0xCBBB9D5DC1059ED8ULL;
  state[1] = 0x629A292A367CD507ULL;
  state[2] = 0x9159015A3070DD17ULL;
  state[3] = 0x152FECD8F70E5939ULL;
  state[4] = 0x67332667FFC00B31ULL;
  state[5] = 0x8EB44A8768581511ULL;
  state[6] = 0xDB0C2E0D64F98FA7ULL;
  state[7] = 0x47B5481DBEFA4FA4ULL;
}

#if TC_ENABLE_HMAC
#define TC_SHA384_SECRET tc_sha512_compress_secret
#else
#define TC_SHA384_SECRET NULL
#endif
TC_HASH64_INFO(tc_sha384_info, TC_SHA384_ctx, 6, TC_SHA384_DIGESTLEN,
               tc_sha384_state_init, tc_sha512_compress, TC_SHA384_SECRET);
#undef TC_SHA384_SECRET

TC_status TC_SHA384_init(struct TC_SHA384_ctx* ctx)
{
  return tc_hash64_init(&tc_sha384_info, ctx);
}

TC_status TC_SHA384_update(struct TC_SHA384_ctx* ctx, const uint8_t* data, size_t len)
{
  return tc_hash64_update(&tc_sha384_info, ctx, data, len);
}

TC_status TC_SHA384_final(struct TC_SHA384_ctx* ctx, uint8_t* digest)
{
  return tc_hash64_final(&tc_sha384_info, ctx, digest);
}

void TC_SHA384_ctx_clear(struct TC_SHA384_ctx* ctx)
{
  tc_hash64_clear(&tc_sha384_info, ctx);
}

TC_status TC_SHA384_digest(const uint8_t* data, size_t len, uint8_t* digest)
{
  struct TC_SHA384_ctx ctx;
  return tc_hash64_digest(&tc_sha384_info, &ctx, data, len, digest);
}

#endif /* TC_ENABLE_SHA384 */

/*****************************************************************************/
/* HMAC (FIPS 198-1 / RFC 2104) over the 128-byte block                     */
/*****************************************************************************/

#if TC_ENABLE_HMAC

#define HMAC_IPAD 0x36U
#define HMAC_OPAD 0x5CU

typedef void (*tc_sha512_state_init_fn)(uint64_t* state);

static TC_status tc_sha512_hmac_init_common(uint64_t* inner_state, uint64_t* inner_count,
                                            uint8_t* inner_buf_len, uint8_t* inner_buf,
                                            uint64_t* outer_state, size_t state_words,
                                            const uint8_t* key, size_t keylen,
                                            tc_sha512_state_init_fn state_init,
                                            tc_sha512_compress_fn compress_secret)
{
  uint8_t block[TC_SHA512_BLOCKLEN];
  size_t i;

  memset(block, 0, sizeof(block));
  if (keylen > sizeof(block))
  {
    /* Reuse the caller's inner state for H(K). This avoids stacking a second
     * full hash context when an HMAC key is longer than one block. */
    state_init(inner_state);
    *inner_count = 0;
    *inner_buf_len = 0;
    memset(inner_buf, 0, sizeof(block));
    if (tc_sha512_stream_update(inner_state, inner_count, inner_buf_len, inner_buf,
                                key, keylen, compress_secret) != TC_OK)
      return TC_ERROR;
    tc_sha512_stream_final(inner_state, state_words, *inner_count, inner_buf_len,
                           inner_buf, block, compress_secret);
  }
  else if (keylen != 0)
  {
    memcpy(block, key, keylen);
  }

  for (i = 0; i < sizeof(block); ++i)
    block[i] ^= HMAC_IPAD;
  state_init(inner_state);
  compress_secret(inner_state, block);
  *inner_count = sizeof(block);
  *inner_buf_len = 0;
  memset(inner_buf, 0, sizeof(block));

  /* ipad ^ opad converts K'^ipad into K'^opad in place. */
  for (i = 0; i < sizeof(block); ++i)
    block[i] ^= (uint8_t)(HMAC_IPAD ^ HMAC_OPAD);
  state_init(outer_state);
  compress_secret(outer_state, block);

#if TC_ZEROIZE
  TC_secure_zero(block, sizeof(block));
#endif
  return TC_OK;
}

/* Outer hash of (K' ^ opad) || inner: exactly one padded block since the
 * inner digest (<= 64 bytes) plus 0x80 and the 16-byte length fit in 128. */
static void tc_sha512_hmac_outer_final(uint64_t* state, size_t state_words,
                                       size_t digest_len, const uint8_t* inner,
                                       uint8_t* tag, tc_sha512_compress_fn compress_secret)
{
  uint8_t block[TC_SHA512_BLOCKLEN];
  size_t i;

  memcpy(block, inner, digest_len);
  block[digest_len] = 0x80U;
  memset(block + digest_len + 1, 0, sizeof(block) - digest_len - 1 - 16);
  tc_internal_store_be64(block + sizeof(block) - 16, 0);
  tc_internal_store_be64(block + sizeof(block) - 8,
                       ((uint64_t)sizeof(block) + digest_len) << 3);
  compress_secret(state, block);
  for (i = 0; i < state_words; ++i)
    tc_internal_store_be64(tag + 8U * i, state[i]);
#if TC_ZEROIZE
  TC_secure_zero(block, sizeof(block));
#endif
}

typedef struct {
  const tc_hash64_info* hash;
  size_t context_size, outer_offset;
} tc_hmac64_info;

static TC_status tc_hmac64_init(const tc_hmac64_info* info, void* ctx,
                                const uint8_t* key, size_t keylen)
{
  TC_HASH_DESC_LOAD(tc_hmac64_info, info, local_info);
  uint8_t* inner = ctx;
  const tc_hash64_info* hash = TC_HMAC64_READ(info, hash);
  TC_HASH_DESC_LOAD(tc_hash64_info, hash, local_hash);
  if (ctx == NULL) return TC_ERROR;
  TC_secure_zero(ctx, TC_HMAC64_READ(info, context_size));
  if (keylen != 0 && key == NULL) return TC_ERROR;
  if (tc_sha512_hmac_init_common(TC_HASH64_MEMBER(inner, hash, state, uint64_t),
          TC_HASH64_MEMBER(inner, hash, count, uint64_t),
          TC_HASH64_MEMBER(inner, hash, buf_len, uint8_t),
          TC_HASH64_MEMBER(inner, hash, buffer, uint8_t),
          (uint64_t*)((uint8_t*)ctx + TC_HMAC64_READ(info, outer_offset)), TC_HASH64_READ(hash, state_words),
          key, keylen, TC_HASH64_READ(hash, state_init), TC_HASH64_READ(hash, compress_secret)) != TC_OK)
  {
    TC_secure_zero(ctx, TC_HMAC64_READ(info, context_size));
    return TC_ERROR;
  }
  *TC_HASH64_MEMBER(inner, hash, active, uint8_t) = 1;
  return TC_OK;
}

static TC_status tc_hmac64_update(const tc_hmac64_info* info, void* ctx,
                                  const uint8_t* data, size_t len)
{
  TC_HASH_DESC_LOAD(tc_hmac64_info, info, local_info);
  if (!tc_hash_update_args(ctx, info->context_size, data, len)) return TC_ERROR;
  return tc_hash64_update(TC_HMAC64_READ(info, hash), ctx, data, len);
}

static TC_status tc_hmac64_final(const tc_hmac64_info* info, void* ctx,
                                 uint8_t* tag)
{
  TC_HASH_DESC_LOAD(tc_hmac64_info, info, local_info);
  uint8_t inner[TC_SHA512_DIGESTLEN];
  const tc_hash64_info* hash = TC_HMAC64_READ(info, hash);
  const tc_hash64_info* hash_flash = hash;
  TC_HASH_DESC_LOAD(tc_hash64_info, hash, local_hash);
  if (!tc_hash_final_args(ctx, TC_HMAC64_READ(info, context_size),
                          tag, TC_HASH64_READ(hash, digest_len))) return TC_ERROR;
  if (tc_hash64_final(hash_flash, ctx, inner) != TC_OK)
  {
    TC_secure_zero(ctx, TC_HMAC64_READ(info, context_size));
    return TC_ERROR;
  }
  tc_sha512_hmac_outer_final((uint64_t*)((uint8_t*)ctx + TC_HMAC64_READ(info, outer_offset)),
      TC_HASH64_READ(hash, state_words), TC_HASH64_READ(hash, digest_len), inner, tag, TC_HASH64_READ(hash, compress_secret));
#if TC_ZEROIZE
  TC_secure_zero(inner, sizeof(inner));
  TC_secure_zero(ctx, TC_HMAC64_READ(info, context_size));
#endif
  return TC_OK;
}

static void tc_hmac64_clear(const tc_hmac64_info* info, void* ctx)
{
  TC_HASH_DESC_LOAD(tc_hmac64_info, info, local_info);
  if (ctx != NULL) TC_secure_zero(ctx, TC_HMAC64_READ(info, context_size));
}

#define TC_HMAC64_INFO(name, type, hash_info) \
  static const tc_hmac64_info name TC_HASH_DESC_STORAGE = { &hash_info, sizeof(struct type), \
    offsetof(struct type, OuterState) }


static uint8_t tc_hmac64_digest_size(const tc_hmac64_info* info)
{
  const tc_hash64_info* hash;
  TC_HASH_DESC_LOAD(tc_hmac64_info, info, local_info);
  hash = TC_HMAC64_READ(info, hash);
  TC_HASH_DESC_LOAD(tc_hash64_info, hash, local_hash);
  return TC_HASH64_READ(hash, digest_len);
}

static TC_status tc_hmac64_digest(const tc_hmac64_info* info,
    void* workspace, const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msg_len,
    uint8_t* tag, size_t tag_len)
{
  uint8_t full[64];
  if (tag == NULL || tag_len < TC_HMAC_MIN_TAG_LEN ||
      tag_len > tc_hmac64_digest_size(info) || (msg_len != 0 && msg == NULL))
    return TC_ERROR;
  if (tc_hmac64_init(info, workspace, key, keylen) != TC_OK) return TC_ERROR;
  if (tc_hmac64_update(info, workspace, msg, msg_len) != TC_OK ||
      tc_hmac64_final(info, workspace, full) != TC_OK)
  {
    tc_hmac64_clear(info, workspace);
    TC_secure_zero(full, sizeof(full));
    return TC_ERROR;
  }
  memcpy(tag, full, tag_len);
#if TC_ZEROIZE
  TC_secure_zero(full, sizeof(full));
#endif
  return TC_OK;
}

static TC_status tc_hmac64_verify(const tc_hmac64_info* info,
    void* workspace, const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msg_len,
    const uint8_t* tag, size_t tag_len)
{
  uint8_t computed[64];
  int result;
  if (tag == NULL || tag_len < TC_HMAC_MIN_TAG_LEN ||
      tag_len > tc_hmac64_digest_size(info)) return TC_ERROR;
  if (tc_hmac64_digest(info, workspace, key, keylen, msg, msg_len, computed, tag_len) != TC_OK)
    return TC_ERROR;
  result = TC_ct_equal(computed, tag, tag_len);
#if TC_ZEROIZE
  TC_secure_zero(computed, sizeof(computed));
#endif
  return result;
}

#if TC_ENABLE_SHA384

TC_HMAC64_INFO(tc_hmac_sha384_info, TC_HMAC_SHA384_ctx, tc_sha384_info);

TC_status TC_HMAC_SHA384_init(struct TC_HMAC_SHA384_ctx* ctx, const uint8_t* key, size_t keylen)
{
  return tc_hmac64_init(&tc_hmac_sha384_info, ctx, key, keylen);
}

TC_status TC_HMAC_SHA384_update(struct TC_HMAC_SHA384_ctx* ctx, const uint8_t* data, size_t len)
{
  return tc_hmac64_update(&tc_hmac_sha384_info, ctx, data, len);
}

TC_status TC_HMAC_SHA384_final(struct TC_HMAC_SHA384_ctx* ctx, uint8_t* tag)
{
  return tc_hmac64_final(&tc_hmac_sha384_info, ctx, tag);
}

void TC_HMAC_SHA384_ctx_clear(struct TC_HMAC_SHA384_ctx* ctx)
{
  tc_hmac64_clear(&tc_hmac_sha384_info, ctx);
}

TC_status TC_HMAC_SHA384_digest(const uint8_t* key, size_t keylen,
    const uint8_t* msg, size_t msg_len, uint8_t* tag, size_t tag_len)
{
  struct TC_HMAC_SHA384_ctx ctx;
  return tc_hmac64_digest(&tc_hmac_sha384_info, &ctx, key, keylen, msg, msg_len, tag, tag_len);
}

TC_status TC_HMAC_SHA384_verify(const uint8_t* key, size_t keylen,
    const uint8_t* msg, size_t msg_len, const uint8_t* tag, size_t tag_len)
{
  struct TC_HMAC_SHA384_ctx ctx;
  return tc_hmac64_verify(&tc_hmac_sha384_info, &ctx, key, keylen, msg, msg_len, tag, tag_len);
}

#endif /* TC_ENABLE_SHA384 */

#if TC_ENABLE_SHA512

TC_HMAC64_INFO(tc_hmac_sha512_info, TC_HMAC_SHA512_ctx, tc_sha512_info);

TC_status TC_HMAC_SHA512_init(struct TC_HMAC_SHA512_ctx* ctx, const uint8_t* key, size_t keylen)
{
  return tc_hmac64_init(&tc_hmac_sha512_info, ctx, key, keylen);
}

TC_status TC_HMAC_SHA512_update(struct TC_HMAC_SHA512_ctx* ctx, const uint8_t* data, size_t len)
{
  return tc_hmac64_update(&tc_hmac_sha512_info, ctx, data, len);
}

TC_status TC_HMAC_SHA512_final(struct TC_HMAC_SHA512_ctx* ctx, uint8_t* tag)
{
  return tc_hmac64_final(&tc_hmac_sha512_info, ctx, tag);
}

void TC_HMAC_SHA512_ctx_clear(struct TC_HMAC_SHA512_ctx* ctx)
{
  tc_hmac64_clear(&tc_hmac_sha512_info, ctx);
}

TC_status TC_HMAC_SHA512_digest(const uint8_t* key, size_t keylen,
    const uint8_t* msg, size_t msg_len, uint8_t* tag, size_t tag_len)
{
  struct TC_HMAC_SHA512_ctx ctx;
  return tc_hmac64_digest(&tc_hmac_sha512_info, &ctx, key, keylen, msg, msg_len, tag, tag_len);
}

TC_status TC_HMAC_SHA512_verify(const uint8_t* key, size_t keylen,
    const uint8_t* msg, size_t msg_len, const uint8_t* tag, size_t tag_len)
{
  struct TC_HMAC_SHA512_ctx ctx;
  return tc_hmac64_verify(&tc_hmac_sha512_info, &ctx, key, keylen, msg, msg_len, tag, tag_len);
}

#endif /* TC_ENABLE_SHA512 */

#endif /* TC_ENABLE_HMAC */

#endif /* TC_HASH_SHA512_CORE */
