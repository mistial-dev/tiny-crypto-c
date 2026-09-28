/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * NIST SP 800-108 KBKDF for tiny-crypto-c: counter, feedback and
 * double-pipeline mode over the HMAC and CMAC PRFs compiled into the profile.
 *
 * One generic core drives every mode. A PRF is a tagged, typed descriptor:
 * HMAC PRFs name a hash-core descriptor, and CMAC PRFs name their cipher's
 * CMAC functions. Per-PRF wrappers provide typed context storage with no heap
 * allocation. The MAC reads each block as an ordered list of borrowed segments
 * (counter, chaining value, fixed input), which bounds the stack to two
 * contexts of the selected MAC plus two h-byte blocks.
 */

#include <string.h>
#include <tiny_crypto/kdf.h>
#include "internal.h"

#if TC_ENABLE_KDF
#include "kdf_prf_internal.h"

/*****************************************************************************/
/* PRF descriptors                                                           */
/*****************************************************************************/

#if TC_KBKDF_HAVE_AES_CMAC
/* The AES key size is fixed per build, so the KDK must match it exactly. */
static int tc_kdf_aes_key_ok(size_t key_len)
{
  return key_len == TC_AES_KEYLEN;
}
static TC_status tc_kdf_aes_cmac_init(void* ctx, const uint8_t* key, size_t key_len)
{
  (void)key_len;
  return TC_AES_CMAC_init((struct TC_AES_CMAC_ctx*)ctx, key);
}
static TC_status tc_kdf_aes_cmac_update(void* ctx, const uint8_t* data, size_t len)
{
  return TC_AES_CMAC_update((struct TC_AES_CMAC_ctx*)ctx, data, len);
}
static TC_status tc_kdf_aes_cmac_final(void* ctx, uint8_t* out)
{
  return TC_AES_CMAC_final((struct TC_AES_CMAC_ctx*)ctx, out);
}
static void tc_kdf_aes_cmac_clear(void* ctx)
{
  TC_AES_CMAC_ctx_clear((struct TC_AES_CMAC_ctx*)ctx);
}
static const struct tc_kdf_cmac tc_kdf_aes_cmac = {tc_kdf_aes_key_ok, tc_kdf_aes_cmac_init,
                                                   tc_kdf_aes_cmac_update, tc_kdf_aes_cmac_final,
                                                   tc_kdf_aes_cmac_clear};
static const struct tc_kdf_prf tc_kdf_prf_aes_cmac = {TC_KDF_PRF_CMAC,
                                                      TC_AES_CMAC_TAG_MAX,
                                                      sizeof(struct TC_AES_CMAC_ctx),
                                                      {.cmac = &tc_kdf_aes_cmac}};
#endif /* TC_KBKDF_HAVE_AES_CMAC */

#if TC_KBKDF_HAVE_DES_CMAC
static int tc_kdf_des_key_ok(size_t key_len)
{
  return key_len == 8 || key_len == 16 || key_len == 24;
}
static TC_status tc_kdf_des_cmac_init(void* ctx, const uint8_t* key, size_t key_len)
{
  return TC_DES_CMAC_init((struct TC_DES_CMAC_ctx*)ctx, key, key_len);
}
static TC_status tc_kdf_des_cmac_update(void* ctx, const uint8_t* data, size_t len)
{
  return TC_DES_CMAC_update((struct TC_DES_CMAC_ctx*)ctx, data, len);
}
static TC_status tc_kdf_des_cmac_final(void* ctx, uint8_t* out)
{
  return TC_DES_CMAC_final((struct TC_DES_CMAC_ctx*)ctx, out);
}
static void tc_kdf_des_cmac_clear(void* ctx)
{
  TC_DES_CMAC_ctx_clear((struct TC_DES_CMAC_ctx*)ctx);
}
static const struct tc_kdf_cmac tc_kdf_des_cmac = {tc_kdf_des_key_ok, tc_kdf_des_cmac_init,
                                                   tc_kdf_des_cmac_update, tc_kdf_des_cmac_final,
                                                   tc_kdf_des_cmac_clear};
static const struct tc_kdf_prf tc_kdf_prf_des_cmac = {TC_KDF_PRF_CMAC,
                                                      TC_DES_CMAC_TAG_MAX,
                                                      sizeof(struct TC_DES_CMAC_ctx),
                                                      {.cmac = &tc_kdf_des_cmac}};
#endif /* TC_KBKDF_HAVE_DES_CMAC */

/*****************************************************************************/
/* Shared derivation core                                                    */
/*****************************************************************************/

#define TC_KDF_MODE_COUNTER 0
#define TC_KDF_MODE_FEEDBACK 1
#define TC_KDF_MODE_PIPELINE 2

static int tc_kdf_counter_bits_ok(unsigned bits)
{
  return bits == TC_KBKDF_COUNTER_8 || bits == TC_KBKDF_COUNTER_16 || bits == TC_KBKDF_COUNTER_24 ||
         bits == TC_KBKDF_COUNTER_32;
}

/*
 * in1 / in2 depend on the mode:
 *   counter   : in1 = data before the counter, in2 = data after the counter
 *   feedback  : in1 = IV (K(0)),               in2 = fixed input
 *   pipeline  : in1 unused,                     in2 = fixed input (= A(0))
 */
static TC_status tc_kdf_derive(const struct tc_kdf_prf* prf, int mode, const uint8_t* key,
                               size_t key_len, const struct TC_KBKDF_params* params,
                               const uint8_t* in1, size_t in1_len, const uint8_t* in2,
                               size_t in2_len, uint8_t* out, size_t out_len, void* initialized,
                               void* ctx, uint8_t* chain, uint8_t* block)
{
  uint8_t ctr[4];
  struct tc_kdf_segment seg[3];
  const uint8_t* chain_p = NULL;
  size_t chain_n = 0;
  size_t h, reps, pos;
  unsigned r = 0, ctr_len = 0;
  int use_ctr;
  uint32_t i;

  if (key == NULL || key_len == 0 || !tc_kdf_key_ok(prf, key_len) || params == NULL ||
      out == NULL || out_len == 0 || !tc_internal_span_valid(in1, in1_len) ||
      !tc_internal_span_valid(in2, in2_len))
    return TC_ERROR;
  if (!tc_kdf_output_disjoint(out, out_len, key, key_len) ||
      !tc_kdf_output_disjoint(out, out_len, in1, in1_len) ||
      !tc_kdf_output_disjoint(out, out_len, in2, in2_len))
    return TC_ERROR;

  use_ctr = (mode == TC_KDF_MODE_COUNTER) ? 1 : (params->use_counter != 0);
  if (use_ctr) {
    r = params->counter_bits;
    if (!tc_kdf_counter_bits_ok(r))
      return TC_ERROR;
    ctr_len = r / 8u;
    if (mode != TC_KDF_MODE_COUNTER && (params->counter_location < TC_KBKDF_CTR_BEFORE_ITER ||
                                        params->counter_location > TC_KBKDF_CTR_AFTER_FIXED))
      return TC_ERROR;
  }

  /* n = ceil(L / h) must fit the counter and the 32-bit loop index. Keep the
     shift explicitly 32-bit: unsigned int is only 16 bits on AVR. */
  h = prf->out_len;
  reps = out_len / h + (out_len % h != 0);
#if SIZE_MAX > UINT32_MAX
  if (reps > UINT32_MAX)
    return TC_ERROR;
#endif
  if (use_ctr && r < 32 && reps > (((uint32_t)1u << r) - 1u))
    return TC_ERROR;

  /* Cache the keyed PRF state once. Each block starts from a small context
     copy, avoiding repeated HMAC key hashing and CMAC key expansion. */
  if (tc_kdf_mac_init(prf, initialized, key, key_len) != TC_OK)
    return TC_ERROR;

  if (mode == TC_KDF_MODE_FEEDBACK) {
    chain_p = in1;
    chain_n = in1_len;
  } else if (mode == TC_KDF_MODE_PIPELINE) {
    chain_p = in2;
    chain_n = in2_len;
  }

  pos = 0;
  for (i = 1; pos < out_len; ++i) {
    unsigned count;
    size_t take;

    if (use_ctr) {
      unsigned k;
      for (k = 0; k < ctr_len; ++k)
        ctr[k] = (uint8_t)(i >> (8u * (ctr_len - 1u - k)));
    }

    if (mode == TC_KDF_MODE_PIPELINE) {
      /* A(i) = PRF(KDK, A(i-1)). A(0) is the fixed input itself. */
      seg[0].data = chain_p;
      seg[0].len = chain_n;
      if (tc_kdf_prf_run(prf, initialized, ctx, seg, 1, chain) != TC_OK)
        goto fail;
      chain_p = chain;
      chain_n = h;
    }

    if (mode == TC_KDF_MODE_COUNTER) {
      seg[0].data = in1;
      seg[0].len = in1_len;
      seg[1].data = ctr;
      seg[1].len = ctr_len;
      seg[2].data = in2;
      seg[2].len = in2_len;
      count = 3;
    } else if (!use_ctr) {
      seg[0].data = chain_p;
      seg[0].len = chain_n;
      seg[1].data = in2;
      seg[1].len = in2_len;
      count = 2;
    } else if (params->counter_location == TC_KBKDF_CTR_BEFORE_ITER) {
      seg[0].data = ctr;
      seg[0].len = ctr_len;
      seg[1].data = chain_p;
      seg[1].len = chain_n;
      seg[2].data = in2;
      seg[2].len = in2_len;
      count = 3;
    } else if (params->counter_location == TC_KBKDF_CTR_AFTER_ITER) {
      seg[0].data = chain_p;
      seg[0].len = chain_n;
      seg[1].data = ctr;
      seg[1].len = ctr_len;
      seg[2].data = in2;
      seg[2].len = in2_len;
      count = 3;
    } else /* TC_KBKDF_CTR_AFTER_FIXED */
    {
      seg[0].data = chain_p;
      seg[0].len = chain_n;
      seg[1].data = in2;
      seg[1].len = in2_len;
      seg[2].data = ctr;
      seg[2].len = ctr_len;
      count = 3;
    }

    if (tc_kdf_prf_run(prf, initialized, ctx, seg, count, block) != TC_OK)
      goto fail;

    if (mode == TC_KDF_MODE_FEEDBACK) {
      memcpy(chain, block, h);
      chain_p = chain;
      chain_n = h;
    }

    take = out_len - pos;
    if (take > h)
      take = h;
    memcpy(out + pos, block, take);
    pos += take;
  }

#if TC_ZEROIZE
  tc_kdf_mac_clear(prf, initialized);
  tc_kdf_mac_clear(prf, ctx);
  if (chain != NULL)
    TC_secure_zero(chain, h);
  TC_secure_zero(block, h);
#endif
  return TC_OK;

fail:
  tc_kdf_mac_clear(prf, initialized);
  tc_kdf_mac_clear(prf, ctx);
  TC_secure_zero(out, out_len);
  if (chain != NULL)
    TC_secure_zero(chain, h);
  TC_secure_zero(block, h);
  return TC_ERROR;
}

/*****************************************************************************/
/* Fixed-input helper                                                        */
/*****************************************************************************/

TC_status TC_KBKDF_fixed_input(const uint8_t* label, size_t label_len, const uint8_t* context,
                               size_t context_len, size_t out_len, uint8_t* buf, size_t buf_len)
{
  size_t needed;

  if (buf == NULL || !tc_internal_span_valid(label, label_len) ||
      !tc_internal_span_valid(context, context_len))
    return TC_ERROR;
  /* [L]_32 is a bit count, so out_len must stay below 2^29 bytes. */
  if (out_len == 0 || out_len > 0x1FFFFFFFu)
    return TC_ERROR;
  if (label_len > SIZE_MAX - 5u || context_len > SIZE_MAX - 5u - label_len)
    return TC_ERROR;
  needed = TC_KBKDF_FIXED_INPUT_LEN(label_len, context_len);
  if (buf_len < needed)
    return TC_ERROR;
  if (!tc_kdf_output_disjoint(buf, needed, label, label_len) ||
      !tc_kdf_output_disjoint(buf, needed, context, context_len))
    return TC_ERROR;
  if (label_len != 0 && memchr(label, 0, label_len) != NULL)
    return TC_ERROR;

  if (label_len != 0)
    memcpy(buf, label, label_len);
  buf[label_len] = 0x00;
  if (context_len != 0)
    memcpy(buf + label_len + 1u, context, context_len);
  tc_internal_store_be32(buf + label_len + 1u + context_len, (uint32_t)out_len << 3);
  return TC_OK;
}

/*****************************************************************************/
/* Public per-PRF entry points                                               */
/*****************************************************************************/

/* Typed storage keeps unrelated enabled PRFs out of this call's stack budget. */
#define TC_KDF_DEFINE_FAMILY(NAME, PRF, CTX, DIGESTLEN)                                            \
  static TC_status tc_kdf_##NAME(int mode, const uint8_t* key, size_t key_len,                     \
                                 const struct TC_KBKDF_params* params, const uint8_t* in1,         \
                                 size_t in1_len, const uint8_t* in2, size_t in2_len, uint8_t* out, \
                                 size_t out_len)                                                   \
  {                                                                                                \
    CTX initialized, ctx;                                                                          \
    const struct tc_kdf_prf prf = PRF;                                                             \
    uint8_t chain[DIGESTLEN], block[DIGESTLEN];                                                    \
    return tc_kdf_derive(&prf, mode, key, key_len, params, in1, in1_len, in2, in2_len, out,        \
                         out_len, &initialized, &ctx, chain, block);                               \
  }                                                                                                \
  TC_status TC_KBKDF_##NAME##_counter(const uint8_t* key, size_t key_len,                          \
                                      const struct TC_KBKDF_params* params, const uint8_t* before, \
                                      size_t before_len, const uint8_t* after, size_t after_len,   \
                                      uint8_t* out, size_t out_len)                                \
  {                                                                                                \
    CTX initialized, ctx;                                                                          \
    const struct tc_kdf_prf prf = PRF;                                                             \
    uint8_t block[DIGESTLEN];                                                                      \
    return tc_kdf_derive(&prf, TC_KDF_MODE_COUNTER, key, key_len, params, before, before_len,      \
                         after, after_len, out, out_len, &initialized, &ctx, NULL, block);         \
  }                                                                                                \
  TC_status TC_KBKDF_##NAME##_feedback(                                                            \
      const uint8_t* key, size_t key_len, const struct TC_KBKDF_params* params, const uint8_t* iv, \
      size_t iv_len, const uint8_t* fixed, size_t fixed_len, uint8_t* out, size_t out_len)         \
  {                                                                                                \
    return tc_kdf_##NAME(TC_KDF_MODE_FEEDBACK, key, key_len, params, iv, iv_len, fixed, fixed_len, \
                         out, out_len);                                                            \
  }                                                                                                \
  TC_status TC_KBKDF_##NAME##_pipeline(const uint8_t* key, size_t key_len,                         \
                                       const struct TC_KBKDF_params* params, const uint8_t* fixed, \
                                       size_t fixed_len, uint8_t* out, size_t out_len)             \
  {                                                                                                \
    return tc_kdf_##NAME(TC_KDF_MODE_PIPELINE, key, key_len, params, NULL, 0, fixed, fixed_len,    \
                         out, out_len);                                                            \
  }

#if TC_KBKDF_HAVE_HMAC_SHA1
TC_KDF_DEFINE_FAMILY(HMAC_SHA1,
                     tc_kdf_hmac_prf(&tc_sha1_info, sizeof(struct TC_HMAC_SHA1_ctx),
                                     TC_SHA1_DIGESTLEN),
                     struct TC_HMAC_SHA1_ctx, TC_SHA1_DIGESTLEN)
#endif
#if TC_KBKDF_HAVE_HMAC_SHA224
TC_KDF_DEFINE_FAMILY(HMAC_SHA224,
                     tc_kdf_hmac_prf(&tc_sha224_info, sizeof(struct TC_HMAC_SHA224_ctx),
                                     TC_SHA224_DIGESTLEN),
                     struct TC_HMAC_SHA224_ctx, TC_SHA224_DIGESTLEN)
#endif
#if TC_KBKDF_HAVE_HMAC_SHA256
TC_KDF_DEFINE_FAMILY(HMAC_SHA256,
                     tc_kdf_hmac_prf(&tc_sha256_info, sizeof(struct TC_HMAC_SHA256_ctx),
                                     TC_SHA256_DIGESTLEN),
                     struct TC_HMAC_SHA256_ctx, TC_SHA256_DIGESTLEN)
#endif
#if TC_KBKDF_HAVE_HMAC_SHA384
TC_KDF_DEFINE_FAMILY(HMAC_SHA384,
                     tc_kdf_hmac_prf(&tc_sha384_info, sizeof(struct TC_HMAC_SHA384_ctx),
                                     TC_SHA384_DIGESTLEN),
                     struct TC_HMAC_SHA384_ctx, TC_SHA384_DIGESTLEN)
#endif
#if TC_KBKDF_HAVE_HMAC_SHA512
TC_KDF_DEFINE_FAMILY(HMAC_SHA512,
                     tc_kdf_hmac_prf(&tc_sha512_info, sizeof(struct TC_HMAC_SHA512_ctx),
                                     TC_SHA512_DIGESTLEN),
                     struct TC_HMAC_SHA512_ctx, TC_SHA512_DIGESTLEN)
#endif
#if TC_KBKDF_HAVE_AES_CMAC
TC_KDF_DEFINE_FAMILY(AES_CMAC, tc_kdf_prf_aes_cmac, struct TC_AES_CMAC_ctx, TC_AES_CMAC_TAG_MAX)
#endif
#if TC_KBKDF_HAVE_DES_CMAC
TC_KDF_DEFINE_FAMILY(DES_CMAC, tc_kdf_prf_des_cmac, struct TC_DES_CMAC_ctx, TC_DES_CMAC_TAG_MAX)
#endif

#endif /* TC_ENABLE_KDF */
