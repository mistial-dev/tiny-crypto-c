/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * DES message authentication: CMAC (NIST SP 800-38B) and ISO/IEC 9797-1
 * MAC algorithms 1 and 3, with the three-key retail-MAC extension.
 */

#include <string.h>
#include <tiny_crypto/des.h>
#include "internal.h"
#include "des_internal.h"
#include "mac_core_internal.h"

#if TC_DES_ENABLE_CMAC || TC_DES_ENABLE_ISO9797
typedef struct {
  const void* schedule;
  int triple;
} tc_des_mac_key;

static TC_status tc_des_mac_encrypt(const void* cipher, uint8_t* block)
{
  const tc_des_mac_key* key = (const tc_des_mac_key*)cipher;
  tc_des_encrypt_scheduled(key->schedule, block, key->triple);
  return TC_OK;
}

static tc_mac_cipher tc_des_mac_cipher(const tc_des_mac_key* key)
{
  tc_mac_cipher cipher = {TC_DES_BLOCKLEN, key, tc_des_mac_encrypt};
  return cipher;
}
#endif

/*****************************************************************************/
/* Public Functions: DES / 3DES CMAC (NIST SP 800-38B)                      */
/*****************************************************************************/
#if TC_DES_ENABLE_CMAC

/* CMAC needs only the raw block cipher, so the context schedules keys and
   chains blocks itself. CMAC must keep working with the optional ECB/CBC/TDES
   mode gates compiled out. */
static tc_mac_cipher tc_des_cmac_cipher(const struct TC_DES_CMAC_ctx* ctx, tc_des_mac_key* key)
{
  key->schedule = ctx->keys.schedule;
  key->triple = ctx->triple;
  return tc_des_mac_cipher(key);
}

TC_status TC_DES_CMAC_init(struct TC_DES_CMAC_ctx* ctx, const uint8_t* key, size_t keylen)
{
  if (ctx == NULL)
    return TC_ERROR;
  if (key == NULL || (keylen != 8 && keylen != 16 && keylen != 24) ||
      !tc_internal_ranges_disjoint(ctx, sizeof *ctx, key, keylen)) {
    TC_DES_CMAC_ctx_clear(ctx);
    return TC_ERROR;
  }
  TC_DES_CMAC_ctx_clear(ctx);
#if TC_DES_REJECT_WEAK_KEYS
  if (tc_des_bundle_is_rejected(key, keylen))
    return TC_ERROR;
#endif

  ctx->triple = (uint8_t)(keylen != 8);
  if (keylen == 8)
    tc_des_key_schedule(&ctx->keys.schedule[0], key);
  else
    tc_des_bundle_schedule(ctx->keys.schedule, key, keylen);
  tc_des_mac_key mac_key;
  const tc_mac_cipher cipher = tc_des_cmac_cipher(ctx, &mac_key);
  if (tc_mac_derive_subkeys(&cipher, 0x1b, 0, ctx->k1, ctx->k2) != TC_OK) {
    TC_DES_CMAC_ctx_clear(ctx);
    return TC_ERROR;
  }
  ctx->active = 1;
  return TC_OK;
}

TC_status TC_DES_CMAC_update(struct TC_DES_CMAC_ctx* ctx, const uint8_t* data, size_t len)
{
  tc_des_mac_key key;
  if (ctx == NULL || ctx->active != 1 || ctx->buf_len > TC_DES_BLOCKLEN ||
      !tc_internal_span_valid(data, len))
    return TC_ERROR;
  const tc_mac_cipher cipher = tc_des_cmac_cipher(ctx, &key);
  if (tc_mac_cbc_update(&cipher, ctx->mac, ctx->buf, &ctx->buf_len, data, len, 1) != TC_OK) {
    TC_DES_CMAC_ctx_clear(ctx);
    return TC_ERROR;
  }
  return TC_OK;
}

TC_status TC_DES_CMAC_final(struct TC_DES_CMAC_ctx* ctx, uint8_t tag[TC_DES_CMAC_TAG_MAX])
{
  tc_des_mac_key key;
  if (ctx == NULL || ctx->active != 1 || tag == NULL || ctx->buf_len > TC_DES_BLOCKLEN)
    return TC_ERROR;
  const tc_mac_cipher cipher = tc_des_cmac_cipher(ctx, &key);
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

TC_status TC_DES_CMAC(const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msg_len,
                      uint8_t* tag, size_t tag_len)
{
  struct TC_DES_CMAC_ctx ctx;
  uint8_t full[TC_DES_CMAC_TAG_MAX];

  if (key == NULL || tag == NULL || tag_len < TC_DES_CMAC_MIN_TAG_LEN ||
      tag_len > TC_DES_CMAC_TAG_MAX || (msg_len != 0 && msg == NULL)) {
    return TC_ERROR;
  }
  if (TC_DES_CMAC_init(&ctx, key, keylen) != TC_OK)
    return TC_ERROR;
  /* Empty message: msg may be NULL. update reads msg only when msg_len > 0. */
  if (TC_DES_CMAC_update(&ctx, msg, msg_len) != TC_OK || TC_DES_CMAC_final(&ctx, full) != TC_OK) {
    TC_DES_CMAC_ctx_clear(&ctx);
    return TC_ERROR;
  }
  memcpy(tag, full, tag_len);

#if TC_ZEROIZE
  TC_secure_zero(full, sizeof(full));
#endif
  return TC_OK;
}

TC_status TC_DES_CMAC_verify(const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msg_len,
                             const uint8_t* tag, size_t tag_len)
{
  uint8_t computed[TC_DES_CMAC_TAG_MAX];
  if (tag == NULL || tag_len < TC_DES_CMAC_MIN_TAG_LEN || tag_len > TC_DES_CMAC_TAG_MAX)
    return TC_ERROR;
  return tc_internal_verify_tag(TC_DES_CMAC(key, keylen, msg, msg_len, computed, tag_len), computed,
                                sizeof computed, tag, tag_len);
}

#endif /* TC_DES_ENABLE_CMAC */

#if TC_DES_ENABLE_ISO9797
static void tc_des_iso9797_finish_alg3(const struct TC_DES_ISO9797_ctx* ctx,
                                       uint8_t block[TC_DES_BLOCKLEN])
{
  tc_des_cipher_block(&ctx->keys.schedule[16], block, 1);
  tc_des_cipher_block(&ctx->keys.schedule[ctx->algorithm == 4 ? 32 : 0], block, 0);
}

TC_status TC_DES_ISO9797_init(struct TC_DES_ISO9797_ctx* ctx, TC_DES_ISO9797_algorithm algorithm,
                              TC_DES_ISO9797_padding padding, const uint8_t* key, size_t keylen)
{
  if (ctx == NULL)
    return TC_ERROR;
  if (key != NULL && keylen <= 24 && !tc_internal_ranges_disjoint(ctx, sizeof(*ctx), key, keylen)) {
    TC_DES_ISO9797_clear(ctx);
    return TC_ERROR;
  }
  if (key == NULL || (algorithm != TC_DES_ISO9797_ALG1 && algorithm != TC_DES_ISO9797_ALG3) ||
      (padding != TC_DES_ISO9797_PAD_NONE && padding != TC_DES_ISO9797_PAD1 &&
       padding != TC_DES_ISO9797_PAD2) ||
      (algorithm == TC_DES_ISO9797_ALG1 && keylen != 16 && keylen != 24) ||
      (algorithm == TC_DES_ISO9797_ALG3 && keylen != 16)) {
    TC_DES_ISO9797_clear(ctx);
    return TC_ERROR;
  }
#if TC_DES_REJECT_WEAK_KEYS
  if (tc_des_bundle_is_rejected(key, keylen)) {
    TC_DES_ISO9797_clear(ctx);
    return TC_ERROR;
  }
#endif
  ctx->active = 0;
  tc_des_bundle_schedule(ctx->keys.schedule, key, keylen);
  memset(ctx->mac, 0, sizeof ctx->mac);
  memset(ctx->buf, 0, sizeof ctx->buf);
  ctx->used = 0;
  ctx->nonempty = 0;
  ctx->keylen = (uint8_t)keylen;
  ctx->algorithm = (uint8_t)algorithm;
  ctx->padding = (uint8_t)padding;
  ctx->active = 1;
  return TC_OK;
}

TC_status TC_DES_ISO9797_update(struct TC_DES_ISO9797_ctx* ctx, const uint8_t* msg, size_t msg_len)
{
  tc_des_mac_key key;
  if (ctx == NULL || ctx->active != 1 || ctx->used >= TC_DES_BLOCKLEN ||
      !tc_internal_span_valid(msg, msg_len))
    return TC_ERROR;
  if (msg_len)
    ctx->nonempty = 1;
  key.schedule = ctx->keys.schedule;
  key.triple = ctx->algorithm == TC_DES_ISO9797_ALG1;
  const tc_mac_cipher cipher = tc_des_mac_cipher(&key);
  if (tc_mac_cbc_update(&cipher, ctx->mac, ctx->buf, &ctx->used, msg, msg_len, 0) != TC_OK) {
    TC_DES_ISO9797_clear(ctx);
    return TC_ERROR;
  }
  return TC_OK;
}

#define TC_DES_ISO9797_ALG_RETAIL3 4u

TC_status TC_DES_ISO9797_final(struct TC_DES_ISO9797_ctx* ctx, uint8_t tag[TC_DES_BLOCKLEN])
{
  tc_des_mac_key key;
  tc_mac_cipher cipher;
  if (ctx == NULL || tag == NULL || ctx->active != 1 || ctx->used >= TC_DES_BLOCKLEN)
    return TC_ERROR;
  if ((ctx->padding == TC_DES_ISO9797_PAD_NONE && ctx->used != 0) ||
      (ctx->padding == TC_DES_ISO9797_PAD_NONE && !ctx->nonempty)) {
    TC_DES_ISO9797_clear(ctx);
    return TC_ERROR;
  }
  key.schedule = ctx->keys.schedule;
  key.triple = ctx->algorithm == TC_DES_ISO9797_ALG1;
  cipher = tc_des_mac_cipher(&key);
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
    TC_DES_ISO9797_clear(ctx);
    return TC_ERROR;
  }
  if (ctx->algorithm == TC_DES_ISO9797_ALG3 || ctx->algorithm == TC_DES_ISO9797_ALG_RETAIL3)
    tc_des_iso9797_finish_alg3(ctx, ctx->mac);
  memcpy(tag, ctx->mac, TC_DES_BLOCKLEN);
  TC_DES_ISO9797_clear(ctx);
  return TC_OK;
}

void TC_DES_ISO9797_clear(struct TC_DES_ISO9797_ctx* ctx)
{
  if (ctx != NULL)
    TC_secure_zero(ctx, sizeof(*ctx));
}

TC_status TC_DES_RETAIL3_init(struct TC_DES_ISO9797_ctx* ctx, TC_DES_ISO9797_padding padding,
                              const uint8_t key[24])
{
  TC_status status = TC_DES_ISO9797_init(ctx, TC_DES_ISO9797_ALG1, padding, key, 24);
  if (status == TC_OK)
    ctx->algorithm = TC_DES_ISO9797_ALG_RETAIL3;
  return status;
}

static TC_status tc_des_iso9797_mac_common(TC_DES_ISO9797_algorithm algorithm,
                                           TC_DES_ISO9797_padding padding, const uint8_t* key,
                                           size_t keylen, const uint8_t* msg, size_t msg_len,
                                           uint8_t* tag, size_t tag_len, int retail3, int short_tag)
{
  struct TC_DES_ISO9797_ctx ctx;
  uint8_t full[TC_DES_BLOCKLEN];
  TC_status status;
  if (tag == NULL ||
      (short_tag ? (tag_len < 4 || tag_len >= TC_DES_BLOCKLEN) : tag_len != TC_DES_BLOCKLEN) ||
      (msg_len && msg == NULL))
    return TC_ERROR;
  if ((retail3 ? TC_DES_RETAIL3_init(&ctx, padding, key)
               : TC_DES_ISO9797_init(&ctx, algorithm, padding, key, keylen)) != TC_OK)
    return TC_ERROR;
  status = TC_DES_ISO9797_update(&ctx, msg, msg_len);
  if (status == TC_OK)
    status = TC_DES_ISO9797_final(&ctx, full);
  else
    TC_DES_ISO9797_clear(&ctx);
  if (status == TC_OK)
    memcpy(tag, full, tag_len);
  TC_secure_zero(full, sizeof(full));
  return status;
}

TC_status TC_DES_ISO9797_MAC(TC_DES_ISO9797_algorithm algorithm, TC_DES_ISO9797_padding padding,
                             const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msg_len,
                             uint8_t* tag, size_t tag_len)
{
  return tc_des_iso9797_mac_common(algorithm, padding, key, keylen, msg, msg_len, tag, tag_len, 0,
                                   0);
}

TC_status TC_DES_ISO9797_MAC_short_tag(TC_DES_ISO9797_algorithm algorithm,
                                       TC_DES_ISO9797_padding padding, const uint8_t* key,
                                       size_t keylen, const uint8_t* msg, size_t msg_len,
                                       uint8_t* tag, size_t tag_len)
{
  return tc_des_iso9797_mac_common(algorithm, padding, key, keylen, msg, msg_len, tag, tag_len, 0,
                                   1);
}

TC_status TC_DES_RETAIL3_MAC(TC_DES_ISO9797_padding padding, const uint8_t key[24],
                             const uint8_t* msg, size_t msg_len, uint8_t* tag, size_t tag_len)
{
  return tc_des_iso9797_mac_common(TC_DES_ISO9797_ALG3, padding, key, 24, msg, msg_len, tag,
                                   tag_len, 1, 0);
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

TC_status TC_DES_RETAIL3_verify(TC_DES_ISO9797_padding padding, const uint8_t key[24],
                                const uint8_t* msg, size_t msg_len, const uint8_t* tag,
                                size_t tag_len)
{
  uint8_t full[TC_DES_BLOCKLEN];
  if (tag == NULL || tag_len != TC_DES_BLOCKLEN)
    return TC_ERROR;
  return tc_internal_verify_tag(TC_DES_RETAIL3_MAC(padding, key, msg, msg_len, full, tag_len), full,
                                sizeof full, tag, tag_len);
}
#endif /* TC_DES_ENABLE_ISO9797 */
