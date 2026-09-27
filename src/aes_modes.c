/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * AES confidentiality modes (NIST SP 800-38A): ECB, CBC, CTR and OFB, plus
 * CBC over dynamic-length keys. */
#include <tiny_crypto/aes.h>
#include "aes_internal.h"

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined(TC_AES_ENABLE_ECB) && (TC_AES_ENABLE_ECB == 1)

TC_status TC_AES_ECB_encrypt(const struct TC_AES_key_ctx* ctx, uint8_t* buf)
{
  if (ctx == NULL || ctx->active != 1 || buf == NULL)
    return TC_ERROR;
  return tc_aes_cipher((state_t*)buf, ctx->round_key);
}

TC_status TC_AES_ECB_decrypt(const struct TC_AES_key_ctx* ctx, uint8_t* buf)
{
  if (ctx == NULL || ctx->active != 1 || buf == NULL)
    return TC_ERROR;
  return tc_aes_inverse_rounds((state_t*)buf, ctx->round_key, TC_AES_FIXED_ROUNDS);
}

#endif

#if TC_AES_ENABLE_CBC || TC_AES_ENABLE_DYNAMIC
static TC_status tc_aes_cbc_encrypt(const uint8_t* key, uint8_t rounds, uint8_t iv[16],
                               uint8_t* buffer, size_t length)
{
  size_t offset;
  for (offset = 0; offset < length; offset += 16) {
    tc_internal_xor(buffer + offset, iv, 16);
    if (tc_aes_cipher_rounds((state_t*)(buffer + offset), key, rounds) != TC_OK)
      return TC_ERROR;
    memcpy(iv, buffer + offset, 16);
  }
  return TC_OK;
}

static TC_status tc_aes_cbc_decrypt(const uint8_t* key, uint8_t rounds, uint8_t iv[16],
                               uint8_t* buffer, size_t length)
{
  uint8_t previous[16];
  size_t offset;
  TC_status status = TC_OK;
  for (offset = 0; offset < length; offset += 16) {
    memcpy(previous, buffer + offset, 16);
    status = tc_aes_inverse_rounds((state_t*)(buffer + offset), key, rounds);
    if (status != TC_OK) break;
    tc_internal_xor(buffer + offset, iv, 16);
    memcpy(iv, previous, 16);
  }
#if TC_ZEROIZE
  TC_secure_zero(previous, sizeof previous);
#endif
  return status;
}
#endif

#if TC_AES_ENABLE_CBC
TC_status TC_AES_CBC_encrypt(struct TC_AES_ctx* ctx, uint8_t* buffer, size_t length)
{
  if (!ctx || ctx->key.active != 1 || (!buffer && length)) return TC_ERROR;
  if (length % 16) return TC_ERROR;
  return tc_aes_cbc_encrypt(ctx->key.round_key, TC_AES_FIXED_ROUNDS, ctx->iv, buffer, length);
}

TC_status TC_AES_CBC_decrypt(struct TC_AES_ctx* ctx, uint8_t* buffer, size_t length)
{
  if (!ctx || ctx->key.active != 1 || (!buffer && length)) return TC_ERROR;
  if (length % 16) return TC_ERROR;
  return tc_aes_cbc_decrypt(ctx->key.round_key, TC_AES_FIXED_ROUNDS, ctx->iv, buffer, length);
}
#endif /* CBC */

#if defined(TC_AES_ENABLE_CTR) && (TC_AES_ENABLE_CTR == 1)

TC_status TC_AES_CTR_crypt(struct TC_AES_ctx* ctx, uint8_t* buf, size_t length)
{
  size_t offset = 0;
  size_t blocks_needed;

  if (ctx == NULL || ctx->key.active != 1 || ctx->ctr_pos > TC_AES_BLOCKLEN ||
      (length != 0 && buf == NULL))
    return TC_ERROR;
  if (length == 0)
    return TC_OK;

  blocks_needed = tc_internal_counter_blocks_needed(length, TC_AES_BLOCKLEN,
                                                      ctx->ctr_pos);
  if (!tc_internal_counter_has_blocks(ctx->iv, TC_AES_BLOCKLEN,
                                      blocks_needed))
    return TC_ERROR;

  while (offset < length && ctx->ctr_pos < TC_AES_BLOCKLEN)
    buf[offset++] ^= ctx->ctr_stream[ctx->ctr_pos++];

  while (length - offset >= TC_AES_BLOCKLEN)
  {
    tc_aes_copy_bytes(ctx->ctr_stream, ctx->iv, TC_AES_BLOCKLEN);
    if (tc_aes_cipher((state_t*)ctx->ctr_stream, ctx->key.round_key) != TC_OK)
      return TC_ERROR;
    tc_internal_increment_be(ctx->iv, TC_AES_BLOCKLEN);
    tc_internal_xor(buf + offset, ctx->ctr_stream, TC_AES_BLOCKLEN);
    offset += TC_AES_BLOCKLEN;
    ctx->ctr_pos = TC_AES_BLOCKLEN;
  }

  if (offset < length)
  {
    tc_aes_copy_bytes(ctx->ctr_stream, ctx->iv, TC_AES_BLOCKLEN);
    if (tc_aes_cipher((state_t*)ctx->ctr_stream, ctx->key.round_key) != TC_OK)
      return TC_ERROR;
    tc_internal_increment_be(ctx->iv, TC_AES_BLOCKLEN);
    ctx->ctr_pos = 0;
    while (offset < length)
      buf[offset++] ^= ctx->ctr_stream[ctx->ctr_pos++];
  }
  return TC_OK;
}

#endif /* CTR */

#if defined(TC_AES_ENABLE_OFB) && (TC_AES_ENABLE_OFB == 1)

TC_status TC_AES_OFB_crypt(struct TC_AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t pos;

  if (ctx == NULL || ctx->key.active != 1 || ctx->ofb_pos > TC_AES_BLOCKLEN ||
      (length != 0 && buf == NULL))
    return TC_ERROR;

  pos = ctx->ofb_pos;
  while (length-- != 0)
  {
    if (pos == TC_AES_BLOCKLEN)
    {
      if (tc_aes_cipher((state_t*)ctx->iv, ctx->key.round_key) != TC_OK) {
        ctx->ofb_pos = pos;
        return TC_ERROR;
      }
      pos = 0;
    }
    *buf++ ^= ctx->iv[pos++];
  }
  ctx->ofb_pos = pos;
  return TC_OK;
}

#endif /* OFB */

#if TC_AES_ENABLE_DYNAMIC
static int tc_aes_dynamic_cbc_valid(const TC_AES_dynamic_key* ctx,
    const uint8_t* iv, const uint8_t* buffer, size_t length)
{
  return tc_aes_dynamic_key_valid(ctx) && iv && (buffer || !length) && !(length % 16) &&
    tc_internal_ranges_disjoint(ctx, sizeof *ctx, iv, 16) &&
    tc_internal_ranges_disjoint(ctx, sizeof *ctx, buffer, length) &&
    tc_internal_ranges_disjoint(iv, 16, buffer, length);
}

TC_status TC_AES_dynamic_CBC_encrypt(const TC_AES_dynamic_key* ctx, uint8_t iv[16],
    uint8_t* buffer, size_t length)
{
  if (!tc_aes_dynamic_cbc_valid(ctx, iv, buffer, length)) return TC_ERROR;
  return tc_aes_cbc_encrypt(ctx->round_key, ctx->rounds, iv, buffer, length);
}

TC_status TC_AES_dynamic_CBC_decrypt(const TC_AES_dynamic_key* ctx, uint8_t iv[16],
    uint8_t* buffer, size_t length)
{
  if (!tc_aes_dynamic_cbc_valid(ctx, iv, buffer, length)) return TC_ERROR;
  return tc_aes_cbc_decrypt(ctx->round_key, ctx->rounds, iv, buffer, length);
}
#endif
