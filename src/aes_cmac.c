/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * AES-CMAC (NIST SP 800-38B): one-shot, streaming and dynamic-key forms. */
#include "aes_mac_core_internal.h"

#if TC_AES_ENABLE_CMAC || TC_AES_ENABLE_DYNAMIC
static TC_status tc_aes_cmac_update(const uint8_t* key, uint8_t rounds, uint8_t mac[16],
    uint8_t buffer[16], uint8_t* used, const uint8_t* data, size_t length)
{
  const tc_aes_mac_key mac_key = {key,rounds};
  const tc_mac_cipher cipher = tc_aes_mac_cipher(&mac_key);
  size_t count = *used;
  const TC_status status = tc_mac_cbc_update(&cipher,mac,buffer,&count,data,length,1);
  *used = (uint8_t)count;
  return status;
}

static TC_status tc_aes_cmac_final(const uint8_t* key, uint8_t rounds, uint8_t mac[16],
    uint8_t buffer[16], uint8_t used, const uint8_t k1[16], const uint8_t k2[16], uint8_t tag[16])
{
  const tc_aes_mac_key mac_key = {key,rounds};
  const tc_mac_cipher cipher = tc_aes_mac_cipher(&mac_key);
  return tc_mac_cmac_final(&cipher,mac,buffer,used,k1,k2,tag);
}
#endif

#if TC_AES_ENABLE_DYNAMIC
TC_status TC_AES_dynamic_CMAC_init(TC_AES_dynamic_CMAC* ctx, const uint8_t* key, size_t length)
{
  if (!ctx || !tc_internal_ranges_disjoint(ctx, sizeof *ctx, key, length) ||
      TC_AES_dynamic_key_init(&ctx->key, key, length) != TC_OK) return TC_ERROR;
  if (tc_aes_cmac_generate_subkeys(ctx->key.round_key, ctx->key.rounds, ctx->k1, ctx->k2) != TC_OK) {
    TC_AES_dynamic_CMAC_clear(ctx);
    return TC_ERROR;
  }
  memset(ctx->mac, 0, 16); memset(ctx->buffer, 0, 16); ctx->used = 0;
  return TC_OK;
}

static int tc_aes_dynamic_cmac_valid(const TC_AES_dynamic_CMAC* ctx)
{
  return ctx && ctx->used <= 16 &&
    (ctx->key.rounds == 10 || ctx->key.rounds == 12 || ctx->key.rounds == 14);
}

TC_status TC_AES_dynamic_CMAC_update(TC_AES_dynamic_CMAC* ctx, const uint8_t* data, size_t length)
{
  if (!tc_aes_dynamic_cmac_valid(ctx) || (!data && length) ||
      !tc_internal_ranges_disjoint(ctx, sizeof *ctx, data, length)) return TC_ERROR;
  if (tc_aes_cmac_update(ctx->key.round_key, ctx->key.rounds, ctx->mac,
                        ctx->buffer, &ctx->used, data, length) != TC_OK) {
    TC_AES_dynamic_CMAC_clear(ctx);
    return TC_ERROR;
  }
  return TC_OK;
}

TC_status TC_AES_dynamic_CMAC_final(TC_AES_dynamic_CMAC* ctx, uint8_t tag[16])
{
  TC_status status;
  if (!tc_aes_dynamic_cmac_valid(ctx) || !tag ||
      !tc_internal_ranges_disjoint(ctx, sizeof *ctx, tag, 16)) return TC_ERROR;
  status = tc_aes_cmac_final(ctx->key.round_key, ctx->key.rounds, ctx->mac,
                           ctx->buffer, ctx->used, ctx->k1, ctx->k2, tag);
  TC_AES_dynamic_CMAC_clear(ctx);
  return status;
}

void TC_AES_dynamic_CMAC_clear(TC_AES_dynamic_CMAC* ctx)
{ if (ctx) TC_secure_zero(ctx, sizeof *ctx); }
#endif

#if defined(TC_AES_ENABLE_CMAC) && (TC_AES_ENABLE_CMAC == 1)
static void tc_aes_cmac_invalidate(struct TC_AES_CMAC_ctx* ctx)
{
  TC_AES_CMAC_ctx_clear(ctx);
}

TC_status TC_AES_CMAC(const uint8_t* key, const uint8_t* msg, size_t msg_len,
             uint8_t* tag, size_t tag_len)
{
  struct TC_AES_CMAC_ctx ctx;
  uint8_t full[TC_AES_BLOCKLEN];
  TC_status status;

  if (key == NULL || tag == NULL ||
      tag_len < TC_AES_CMAC_MIN_TAG_LEN || tag_len > TC_AES_CMAC_TAG_MAX ||
      (msg_len != 0 && msg == NULL))
    return TC_ERROR;

  if (TC_AES_CMAC_init(&ctx, key) != TC_OK)
    return TC_ERROR;
  status = TC_AES_CMAC_update(&ctx, msg, msg_len);
  if (status == TC_OK)
    status = TC_AES_CMAC_final(&ctx, full);
  if (status == TC_OK)
    tc_aes_copy_bytes(tag, full, tag_len);

#if TC_ZEROIZE
  TC_secure_zero(full, sizeof(full));
  TC_AES_CMAC_ctx_clear(&ctx);
#endif
  return status;
}

TC_status TC_AES_CMAC_verify(const uint8_t* key, const uint8_t* msg, size_t msg_len,
                    const uint8_t* tag, size_t tag_len)
{
  uint8_t computed[TC_AES_CMAC_TAG_MAX];
  TC_status status;

  if (tag == NULL ||
      tag_len < TC_AES_CMAC_MIN_TAG_LEN || tag_len > TC_AES_CMAC_TAG_MAX)
    return TC_ERROR;
  if (TC_AES_CMAC(key, msg, msg_len, computed, tag_len) != TC_OK)
    return TC_ERROR;

  /* A mismatch is data, not malformed input. Report it distinctly. */
  status = TC_ct_equal(computed, tag, tag_len);

#if TC_ZEROIZE
  TC_secure_zero(computed, sizeof(computed));
#endif
  return status;
}

/* Absorb one full block from ctx->buf into the CBC-MAC chain. */
TC_status TC_AES_CMAC_init(struct TC_AES_CMAC_ctx* ctx, const uint8_t* key)
{
  if (!ctx) return TC_ERROR;
  TC_AES_CMAC_ctx_clear(ctx);
  if (TC_AES_key_init(&ctx->key, key) != TC_OK) return TC_ERROR;
  if (tc_aes_cmac_generate_subkeys(ctx->key.round_key, TC_AES_FIXED_ROUNDS, ctx->k1, ctx->k2) != TC_OK) {
    tc_aes_cmac_invalidate(ctx);
    return TC_ERROR;
  }
  memset(ctx->mac, 0, 16); memset(ctx->buf, 0, 16); ctx->buf_len = 0;
  ctx->active = 1;
  return TC_OK;
}

TC_status TC_AES_CMAC_update(struct TC_AES_CMAC_ctx* ctx, const uint8_t* data, size_t length)
{
  if (!ctx || ctx->active != 1 || (!data && length) || ctx->buf_len > 16)
    return TC_ERROR;
  if (tc_aes_cmac_update(ctx->key.round_key, TC_AES_FIXED_ROUNDS, ctx->mac, ctx->buf,
                       &ctx->buf_len, data, length) != TC_OK) {
    tc_aes_cmac_invalidate(ctx);
    return TC_ERROR;
  }
  return TC_OK;
}

TC_status TC_AES_CMAC_final(struct TC_AES_CMAC_ctx* ctx, uint8_t tag[16])
{
  TC_status status;
  if (!ctx || ctx->active != 1 || !tag || ctx->buf_len > 16) return TC_ERROR;
  status = tc_aes_cmac_final(ctx->key.round_key, TC_AES_FIXED_ROUNDS, ctx->mac, ctx->buf,
                           ctx->buf_len, ctx->k1, ctx->k2, tag);
  if (status != TC_OK) {
    tc_aes_cmac_invalidate(ctx);
    return status;
  }
#if TC_ZEROIZE
  TC_secure_zero(ctx, sizeof *ctx);
#else
  ctx->active = 0;
#endif
  return TC_OK;
}

void TC_AES_CMAC_ctx_clear(struct TC_AES_CMAC_ctx* ctx)
{
  if (ctx == NULL)
    return;
  TC_secure_zero(ctx, sizeof(*ctx));
}

#endif /* CMAC */
