/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * DES message authentication: CMAC (NIST SP 800-38B) and ISO/IEC 9797-1
 * MAC algorithms 1 and 3. Algorithm 3 also takes a three-key retail-MAC
 * extension.
 */

#include <string.h>
#include <tiny_crypto/des.h>
#include "internal.h"
#include "des_internal.h"
#include "mac_core_internal.h"

/*****************************************************************************/
/* Public Functions: DES / 3DES CMAC (NIST SP 800-38B)                      */
/*****************************************************************************/
#if TC_DES_ENABLE_CMAC

/* CMAC needs only the raw block cipher, so the context schedules keys and
   chains blocks itself. CMAC must keep working with the optional ECB/CBC/TDES
   mode gates compiled out. */
static tc_block_cipher tc_des_cmac_cipher(const struct TC_DES_CMAC_ctx* ctx, tc_des_block_key* key)
{
  key->schedule = ctx->keys.schedule;
  key->triple = ctx->triple;
  return tc_des_block_cipher(key);
}

TC_status TC_DES_CMAC_init(struct TC_DES_CMAC_ctx* ctx, const uint8_t* key, size_t keylen)
{
  if (ctx == NULL)
    return TC_ERROR;
  if (key == NULL ||
      (keylen != TC_DES_KEYLEN && keylen != TC_DES_KEYLEN_2KEY && keylen != TC_DES_KEYLEN_3KEY) ||
      !tc_internal_ranges_disjoint(ctx, sizeof *ctx, key, keylen)) {
    TC_DES_CMAC_ctx_clear(ctx);
    return TC_ERROR;
  }
  TC_DES_CMAC_ctx_clear(ctx);
#if TC_DES_REJECT_WEAK_KEYS
  if (tc_des_bundle_is_rejected(key, keylen))
    return TC_ERROR;
#endif

  ctx->triple = (uint8_t)(keylen != TC_DES_KEYLEN);
  tc_des_schedule_key(ctx->keys.schedule, key, keylen);
  tc_des_block_key mac_key;
  const tc_block_cipher cipher = tc_des_cmac_cipher(ctx, &mac_key);
  if (tc_mac_derive_subkeys(&cipher, 0x1b, 0, ctx->k1, ctx->k2) != TC_OK) {
    TC_DES_CMAC_ctx_clear(ctx);
    return TC_ERROR;
  }
  ctx->active = 1;
  return TC_OK;
}

TC_status TC_DES_CMAC_update(struct TC_DES_CMAC_ctx* ctx, const uint8_t* data, size_t len)
{
  tc_des_block_key key;
  if (!tc_block_mode_args(ctx, sizeof *ctx, data, len, 1) || ctx->active != 1 ||
      ctx->buf_len > TC_DES_BLOCKLEN)
    return TC_ERROR;
  const tc_block_cipher cipher = tc_des_cmac_cipher(ctx, &key);
  if (tc_mac_cbc_update(&cipher, ctx->mac, ctx->buf, &ctx->buf_len, data, len, 1) != TC_OK) {
    TC_DES_CMAC_ctx_clear(ctx);
    return TC_ERROR;
  }
  return TC_OK;
}

TC_status TC_DES_CMAC_final(struct TC_DES_CMAC_ctx* ctx, uint8_t tag[TC_DES_CMAC_TAG_MAX])
{
  tc_des_block_key key;
  if (!tc_block_mode_args(ctx, sizeof *ctx, tag, TC_DES_CMAC_TAG_MAX, 1) || ctx->active != 1 ||
      ctx->buf_len > TC_DES_BLOCKLEN)
    return TC_ERROR;
  const tc_block_cipher cipher = tc_des_cmac_cipher(ctx, &key);
  const TC_status status =
      tc_mac_cmac_final(&cipher, ctx->mac, ctx->buf, ctx->buf_len, ctx->k1, ctx->k2, tag);
  /* The context is one-shot: it is cleared after success and failure. */
  TC_DES_CMAC_ctx_clear(ctx);
  return status;
}

void TC_DES_CMAC_ctx_clear(struct TC_DES_CMAC_ctx* ctx)
{
  if (ctx == NULL)
    return;
  TC_secure_zero(ctx, sizeof(*ctx));
}

/* One-shot CMAC over the streaming context. The tag is the leading tag_len
 * bytes of T (SP 800-38B section 6.2 step 7). short_tag selects the lengths
 * below TC_MIN_TAG_LEN (Appendix A.2). */
static TC_status tc_des_cmac_oneshot(const uint8_t* key, size_t keylen, TC_bytes msg, uint8_t* tag,
                                     size_t tag_len, int short_tag)
{
  struct TC_DES_CMAC_ctx ctx;
  uint8_t full[TC_DES_CMAC_TAG_MAX];
  TC_status status;

  if (key == NULL || tag == NULL ||
      !tc_internal_tag_length_allowed(tag_len, TC_DES_CMAC_TAG_MAX, short_tag) ||
      !tc_internal_span_valid(msg.data, msg.length))
    return TC_ERROR;
  status = TC_DES_CMAC_init(&ctx, key, keylen);
  /* Empty message: msg may be NULL. update reads msg only when its length is
   * nonzero. */
  if (status == TC_OK)
    status = TC_DES_CMAC_update(&ctx, msg.data, msg.length);
  if (status == TC_OK)
    status = TC_DES_CMAC_final(&ctx, full);
  if (status == TC_OK)
    memcpy(tag, full, tag_len);
  TC_secure_zero(full, sizeof(full));
  TC_DES_CMAC_ctx_clear(&ctx);
  return status;
}

static TC_status tc_des_cmac_verify_oneshot(const uint8_t* key, size_t keylen, TC_bytes msg,
                                            const uint8_t* tag, size_t tag_len, int short_tag)
{
  uint8_t computed[TC_DES_CMAC_TAG_MAX];
  if (tag == NULL || !tc_internal_tag_length_allowed(tag_len, TC_DES_CMAC_TAG_MAX, short_tag))
    return TC_ERROR;
  return tc_internal_verify_tag(tc_des_cmac_oneshot(key, keylen, msg, computed, tag_len, short_tag),
                                computed, sizeof computed, tag, tag_len);
}

TC_status TC_DES_CMAC(const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msg_len,
                      uint8_t* tag, size_t tag_len)
{
  return tc_des_cmac_oneshot(key, keylen, (TC_bytes){msg, msg_len}, tag, tag_len, 0);
}

TC_status TC_DES_CMAC_verify(const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msg_len,
                             const uint8_t* tag, size_t tag_len)
{
  return tc_des_cmac_verify_oneshot(key, keylen, (TC_bytes){msg, msg_len}, tag, tag_len, 0);
}

TC_status TC_DES_CMAC_short_tag(const uint8_t* key, size_t keylen, const uint8_t* msg,
                                size_t msg_len, uint8_t* tag, size_t tag_len)
{
  return tc_des_cmac_oneshot(key, keylen, (TC_bytes){msg, msg_len}, tag, tag_len, 1);
}

TC_status TC_DES_CMAC_verify_short_tag(const uint8_t* key, size_t keylen, const uint8_t* msg,
                                       size_t msg_len, const uint8_t* tag, size_t tag_len)
{
  return tc_des_cmac_verify_oneshot(key, keylen, (TC_bytes){msg, msg_len}, tag, tag_len, 1);
}

#endif /* TC_DES_ENABLE_CMAC */

#if TC_DES_ENABLE_ISO9797
/* ISO/IEC 9797-1:2011 clause 6.7.4 Output Transformation 3: G = e_K(d_K'(H_q))
 * with K' = K2. The schedule holds K1 again at K3 for a two-key bundle, so a
 * 24-byte bundle applies the three-key extension e_K3(d_K2(H_q)). */
static void tc_des_iso9797_output_transformation3(const struct TC_DES_ISO9797_ctx* ctx,
                                                  uint8_t block[TC_DES_BLOCKLEN])
{
  tc_des_cipher_block(&ctx->keys.schedule[16], block, 1);
  tc_des_cipher_block(&ctx->keys.schedule[32], block, 0);
}

static int tc_des_iso9797_padding_known(TC_DES_ISO9797_padding padding)
{
  return padding == TC_DES_ISO9797_PAD_NONE || padding == TC_DES_ISO9797_PAD1 ||
         padding == TC_DES_ISO9797_PAD2;
}

TC_status TC_DES_ISO9797_init(struct TC_DES_ISO9797_ctx* ctx, TC_DES_ISO9797_algorithm algorithm,
                              TC_DES_ISO9797_padding padding, const uint8_t* key, size_t keylen)
{
  if (ctx == NULL)
    return TC_ERROR;
  TC_DES_ISO9797_ctx_clear(ctx);
  if (key == NULL ||
      (algorithm != TC_DES_ISO9797_ALG1 && algorithm != TC_DES_ISO9797_ALG3 &&
       algorithm != TC_DES_ISO9797_ALG3_3KEY_EXTENSION) ||
      !tc_des_iso9797_padding_known(padding) ||
      (algorithm == TC_DES_ISO9797_ALG3 && keylen != TC_DES_KEYLEN_2KEY) ||
      (algorithm == TC_DES_ISO9797_ALG3_3KEY_EXTENSION && keylen != TC_DES_KEYLEN_3KEY) ||
      (algorithm == TC_DES_ISO9797_ALG1 && keylen != TC_DES_KEYLEN_2KEY &&
       keylen != TC_DES_KEYLEN_3KEY) ||
      !tc_internal_ranges_disjoint(ctx, sizeof(*ctx), key, keylen))
    return TC_ERROR;
  if (tc_des_keys_equal(key, key + TC_DES_KEYLEN) ||
      (keylen == TC_DES_KEYLEN_3KEY &&
       tc_des_keys_equal(key + TC_DES_KEYLEN, key + TC_DES_KEYLEN_2KEY)))
    return TC_ERROR;
#if TC_DES_REJECT_WEAK_KEYS
  /* Clause 7.4 requires independent K and K'. K1 = K2 or K2 = K3 cancels a
   * DES stage, and weak component keys are rejected as for the modes. */
  if (tc_des_bundle_is_rejected(key, keylen))
    return TC_ERROR;
#endif
  tc_des_schedule_key(ctx->keys.schedule, key, keylen);
  ctx->algorithm = (uint16_t)algorithm;
  ctx->padding = (uint8_t)padding;
  ctx->active = 1;
  return TC_OK;
}

TC_status TC_DES_ISO9797_update(struct TC_DES_ISO9797_ctx* ctx, const uint8_t* msg, size_t msg_len)
{
  tc_des_block_key key;
  if (!tc_block_mode_args(ctx, sizeof *ctx, msg, msg_len, 1) || ctx->active != 1 ||
      ctx->used >= TC_DES_BLOCKLEN)
    return TC_ERROR;
  if (msg_len)
    ctx->nonempty = 1;
  key.schedule = ctx->keys.schedule;
  key.triple = ctx->algorithm == TC_DES_ISO9797_ALG1;
  const tc_block_cipher cipher = tc_des_block_cipher(&key);
  if (tc_mac_cbc_update(&cipher, ctx->mac, ctx->buf, &ctx->used, msg, msg_len, 0) != TC_OK) {
    TC_DES_ISO9797_ctx_clear(ctx);
    return TC_ERROR;
  }
  return TC_OK;
}

TC_status TC_DES_ISO9797_final(struct TC_DES_ISO9797_ctx* ctx, uint8_t tag[TC_DES_BLOCKLEN])
{
  tc_des_block_key key;
  tc_block_cipher cipher;
  if (!tc_block_mode_args(ctx, sizeof *ctx, tag, TC_DES_BLOCKLEN, 1) || ctx->active != 1 ||
      ctx->used >= TC_DES_BLOCKLEN)
    return TC_ERROR;
  if ((ctx->padding == TC_DES_ISO9797_PAD_NONE && ctx->used != 0) ||
      (ctx->padding == TC_DES_ISO9797_PAD_NONE && !ctx->nonempty)) {
    TC_DES_ISO9797_ctx_clear(ctx);
    return TC_ERROR;
  }
  key.schedule = ctx->keys.schedule;
  key.triple = ctx->algorithm == TC_DES_ISO9797_ALG1;
  cipher = tc_des_block_cipher(&key);
  TC_status status = TC_OK;
  if (ctx->padding == TC_DES_ISO9797_PAD1 && (ctx->used || !ctx->nonempty)) {
    memset(ctx->buf + ctx->used, 0, TC_DES_BLOCKLEN - ctx->used);
    status = tc_mac_cbc_block(&cipher, ctx->mac, ctx->buf);
  }
  if (ctx->padding == TC_DES_ISO9797_PAD2) {
    ctx->buf[ctx->used] = 0x80;
    memset(ctx->buf + ctx->used + 1, 0, TC_DES_BLOCKLEN - ctx->used - 1);
    status = tc_mac_cbc_block(&cipher, ctx->mac, ctx->buf);
  }
  if (status != TC_OK) {
    TC_DES_ISO9797_ctx_clear(ctx);
    return TC_ERROR;
  }
  if (ctx->algorithm == TC_DES_ISO9797_ALG3 ||
      ctx->algorithm == TC_DES_ISO9797_ALG3_3KEY_EXTENSION)
    tc_des_iso9797_output_transformation3(ctx, ctx->mac);
  memcpy(tag, ctx->mac, TC_DES_BLOCKLEN);
  TC_DES_ISO9797_ctx_clear(ctx);
  return TC_OK;
}

void TC_DES_ISO9797_ctx_clear(struct TC_DES_ISO9797_ctx* ctx)
{
  if (ctx != NULL)
    TC_secure_zero(ctx, sizeof(*ctx));
}

/* One-shot arguments. A short tag has 4..7 bytes, a full tag one block. */
static int tc_des_iso9797_mac_args(const uint8_t* msg, size_t msg_len, const uint8_t* tag,
                                   size_t tag_len, int short_tag)
{
  return tag != NULL && (msg_len == 0 || msg != NULL) &&
         (short_tag ? tag_len >= 4 && tag_len < TC_DES_BLOCKLEN : tag_len == TC_DES_BLOCKLEN);
}

/* MAC msg with a context whose initialization returned init, then write the
 * leading tag_len bytes. The context is consumed or cleared on every path. */
static TC_status tc_des_iso9797_mac_run(struct TC_DES_ISO9797_ctx* ctx, TC_status init,
                                        const uint8_t* msg, size_t msg_len, uint8_t* tag,
                                        size_t tag_len)
{
  uint8_t full[TC_DES_BLOCKLEN];
  TC_status status;
  if (init != TC_OK)
    return TC_ERROR;
  status = TC_DES_ISO9797_update(ctx, msg, msg_len);
  if (status == TC_OK)
    status = TC_DES_ISO9797_final(ctx, full);
  else
    TC_DES_ISO9797_ctx_clear(ctx);
  if (status == TC_OK)
    memcpy(tag, full, tag_len);
  TC_secure_zero(full, sizeof(full));
  return status;
}

TC_status TC_DES_ISO9797_MAC(TC_DES_ISO9797_algorithm algorithm, TC_DES_ISO9797_padding padding,
                             const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msg_len,
                             uint8_t* tag, size_t tag_len)
{
  struct TC_DES_ISO9797_ctx ctx;
  if (!tc_des_iso9797_mac_args(msg, msg_len, tag, tag_len, 0))
    return TC_ERROR;
  return tc_des_iso9797_mac_run(&ctx, TC_DES_ISO9797_init(&ctx, algorithm, padding, key, keylen),
                                msg, msg_len, tag, tag_len);
}

TC_status TC_DES_ISO9797_MAC_short_tag(TC_DES_ISO9797_algorithm algorithm,
                                       TC_DES_ISO9797_padding padding, const uint8_t* key,
                                       size_t keylen, const uint8_t* msg, size_t msg_len,
                                       uint8_t* tag, size_t tag_len)
{
  struct TC_DES_ISO9797_ctx ctx;
  if (!tc_des_iso9797_mac_args(msg, msg_len, tag, tag_len, 1))
    return TC_ERROR;
  return tc_des_iso9797_mac_run(&ctx, TC_DES_ISO9797_init(&ctx, algorithm, padding, key, keylen),
                                msg, msg_len, tag, tag_len);
}

TC_status TC_DES_ISO9797_verify(TC_DES_ISO9797_algorithm algorithm, TC_DES_ISO9797_padding padding,
                                const uint8_t* key, size_t keylen, const uint8_t* msg,
                                size_t msg_len, const uint8_t* tag, size_t tag_len)
{
  uint8_t full[TC_DES_BLOCKLEN];
  if (tag == NULL || tag_len != TC_DES_BLOCKLEN)
    return TC_ERROR;
  return tc_internal_verify_tag(
      TC_DES_ISO9797_MAC(algorithm, padding, key, keylen, msg, msg_len, full, tag_len), full,
      sizeof full, tag, tag_len);
}

TC_status TC_DES_ISO9797_verify_short_tag(TC_DES_ISO9797_algorithm algorithm,
                                          TC_DES_ISO9797_padding padding, const uint8_t* key,
                                          size_t keylen, const uint8_t* msg, size_t msg_len,
                                          const uint8_t* tag, size_t tag_len)
{
  uint8_t full[TC_DES_BLOCKLEN];
  if (tag == NULL || tag_len < 4 || tag_len >= TC_DES_BLOCKLEN)
    return TC_ERROR;
  return tc_internal_verify_tag(
      TC_DES_ISO9797_MAC_short_tag(algorithm, padding, key, keylen, msg, msg_len, full, tag_len),
      full, sizeof full, tag, tag_len);
}

#endif /* TC_DES_ENABLE_ISO9797 */
