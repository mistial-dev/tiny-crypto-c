/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * DES and Triple-DES confidentiality modes (NIST SP 800-38A): ECB, CBC, CTR,
 * CFB1, CFB8, CFB64 and OFB over the block cipher in des.c.
 */

#include <string.h>
#include <tiny_crypto/des.h>
#include "internal.h"
#include "des_internal.h"

typedef void (*tc_des_mode_block_fn)(const void* cipher, uint8_t* block);

/* Public wrappers must check before taking addresses of context members. */
#define DES_MODE_REQUIRE_CTX(ctx)                                                                  \
  do {                                                                                             \
    if ((ctx) == NULL || (ctx)->active != 1)                                                       \
      return TC_ERROR;                                                                             \
  } while (0)

#if TC_DES_ENABLE_CBC
static TC_status tc_des_mode_cbc(const void* cipher, uint8_t iv[TC_DES_BLOCKLEN], uint8_t* buf,
                                 size_t length, tc_des_mode_block_fn crypt_block, int decrypt)
{
  uint8_t saved[TC_DES_BLOCKLEN];
  size_t i;
  uint8_t j;

#if TC_STRICT
  if (cipher == NULL || (length != 0 && buf == NULL))
    return TC_ERROR;
#endif
  if ((length % TC_DES_BLOCKLEN) != 0)
    return TC_ERROR;

  for (i = 0; i < length; i += TC_DES_BLOCKLEN) {
    if (decrypt)
      memcpy(saved, buf + i, TC_DES_BLOCKLEN);
    else
      for (j = 0; j < TC_DES_BLOCKLEN; ++j)
        buf[i + j] ^= iv[j];

    crypt_block(cipher, buf + i);

    if (decrypt) {
      for (j = 0; j < TC_DES_BLOCKLEN; ++j)
        buf[i + j] ^= iv[j];
      memcpy(iv, saved, TC_DES_BLOCKLEN);
    } else {
      memcpy(iv, buf + i, TC_DES_BLOCKLEN);
    }
  }
  return TC_OK;
}
#endif

#if TC_DES_ENABLE_CTR
static TC_status tc_des_mode_ctr(const void* cipher, uint8_t iv[TC_DES_BLOCKLEN],
                                 uint8_t stream[TC_DES_BLOCKLEN], uint8_t* pos, uint8_t* exhausted,
                                 uint8_t* buf, size_t length, tc_des_mode_block_fn encrypt_block)
{
  size_t blocks_needed;
  size_t i;

#if TC_STRICT
  if (cipher == NULL || (length != 0 && buf == NULL))
    return TC_ERROR;
#endif
  if (*pos > TC_DES_BLOCKLEN)
    return TC_ERROR;
  if (length == 0)
    return TC_OK;

  blocks_needed = tc_internal_counter_blocks_needed(length, TC_DES_BLOCKLEN, *pos);
  if (!tc_internal_counter_has_blocks(iv, TC_DES_BLOCKLEN, blocks_needed, *exhausted))
    return TC_ERROR;

  for (i = 0; i < length; ++i) {
    if (*pos == TC_DES_BLOCKLEN) {
      memcpy(stream, iv, TC_DES_BLOCKLEN);
      encrypt_block(cipher, stream);
      *exhausted |= tc_internal_increment_be(iv, TC_DES_BLOCKLEN);
      *pos = 0;
    }
    buf[i] ^= stream[(*pos)++];
  }
  return TC_OK;
}
#endif

#if TC_DES_ENABLE_CFB64
/* A short final CFB-64 segment shifts only its ciphertext bytes into the
 * feedback register, as specified by SP 800-38A. */
static void tc_des_cfb64_shift_iv(uint8_t* iv, const uint8_t* ct, size_t length)
{
  if (length >= TC_DES_BLOCKLEN) {
    memcpy(iv, ct, TC_DES_BLOCKLEN);
    return;
  }
  memmove(iv, iv + length, TC_DES_BLOCKLEN - length);
  memcpy(iv + TC_DES_BLOCKLEN - length, ct, length);
}

static TC_status tc_des_mode_cfb64(const void* cipher, uint8_t iv[TC_DES_BLOCKLEN], uint8_t* buf,
                                   size_t length, tc_des_mode_block_fn encrypt_block, int decrypt)
{
  uint8_t keystream[TC_DES_BLOCKLEN];
  uint8_t saved[TC_DES_BLOCKLEN];
  size_t offset = 0;

#if TC_STRICT
  if (cipher == NULL || (length != 0 && buf == NULL))
    return TC_ERROR;
#endif
  while (offset < length) {
    const size_t segment = length - offset < TC_DES_BLOCKLEN ? length - offset : TC_DES_BLOCKLEN;
    size_t j;

    if (decrypt)
      memcpy(saved, buf + offset, segment);
    memcpy(keystream, iv, TC_DES_BLOCKLEN);
    encrypt_block(cipher, keystream);
    for (j = 0; j < segment; ++j)
      buf[offset + j] ^= keystream[j];
    tc_des_cfb64_shift_iv(iv, decrypt ? saved : buf + offset, segment);
    offset += segment;
  }
#if TC_ZEROIZE
  TC_secure_zero(keystream, sizeof(keystream));
  TC_secure_zero(saved, sizeof(saved));
#endif
  return TC_OK;
}
#endif

#if TC_DES_ENABLE_CFB8
static TC_status tc_des_mode_cfb8(const void* cipher, uint8_t iv[TC_DES_BLOCKLEN], uint8_t* buf,
                                  size_t length, tc_des_mode_block_fn encrypt_block, int decrypt)
{
  uint8_t keystream[TC_DES_BLOCKLEN];
  size_t i;

#if TC_STRICT
  if (cipher == NULL || (length != 0 && buf == NULL))
    return TC_ERROR;
#endif
  for (i = 0; i < length; ++i) {
    const uint8_t ciphertext = buf[i];
    memcpy(keystream, iv, TC_DES_BLOCKLEN);
    encrypt_block(cipher, keystream);
    buf[i] ^= keystream[0];
    memmove(iv, iv + 1, TC_DES_BLOCKLEN - 1);
    iv[TC_DES_BLOCKLEN - 1] = decrypt ? ciphertext : buf[i];
  }
#if TC_ZEROIZE
  TC_secure_zero(keystream, sizeof(keystream));
#endif
  return TC_OK;
}
#endif

#if TC_DES_ENABLE_CFB1
static void tc_des_cfb1_shift_iv(uint8_t* iv, uint8_t ciphertext_bit)
{
  uint8_t j;
  for (j = 0; j < TC_DES_BLOCKLEN - 1; ++j)
    iv[j] = (uint8_t)((iv[j] << 1) | (iv[j + 1] >> 7));
  iv[TC_DES_BLOCKLEN - 1] = (uint8_t)((iv[TC_DES_BLOCKLEN - 1] << 1) | ciphertext_bit);
}

static TC_status tc_des_mode_cfb1(const void* cipher, uint8_t iv[TC_DES_BLOCKLEN], uint8_t* buf,
                                  size_t bit_length, tc_des_mode_block_fn encrypt_block,
                                  int decrypt)
{
  uint8_t keystream[TC_DES_BLOCKLEN];
  size_t i;

#if TC_STRICT
  if (cipher == NULL || (bit_length != 0 && buf == NULL))
    return TC_ERROR;
#endif
  for (i = 0; i < bit_length; ++i) {
    const size_t byte_index = i / 8;
    const uint8_t shift = (uint8_t)(7 - (i % 8));
    const uint8_t input_bit = (uint8_t)((buf[byte_index] >> shift) & 1u);
    uint8_t output_bit;
    uint8_t ciphertext_bit;

    memcpy(keystream, iv, TC_DES_BLOCKLEN);
    encrypt_block(cipher, keystream);
    output_bit = (uint8_t)((input_bit ^ (keystream[0] >> 7)) & 1u);
    ciphertext_bit = decrypt ? input_bit : output_bit;
    buf[byte_index] =
        (uint8_t)((buf[byte_index] & ~(1u << shift)) | ((unsigned)output_bit << shift));
    tc_des_cfb1_shift_iv(iv, ciphertext_bit);
  }
#if TC_ZEROIZE
  TC_secure_zero(keystream, sizeof(keystream));
#endif
  return TC_OK;
}
#endif

#if TC_DES_ENABLE_OFB
static TC_status tc_des_mode_ofb(const void* cipher, uint8_t iv[TC_DES_BLOCKLEN], uint8_t* pos,
                                 uint8_t* buf, size_t length, tc_des_mode_block_fn encrypt_block)
{
  size_t i;
#if TC_STRICT
  if (cipher == NULL || (length != 0 && buf == NULL))
    return TC_ERROR;
#endif
  if (*pos > TC_DES_BLOCKLEN)
    return TC_ERROR;
  for (i = 0; i < length; ++i) {
    if (*pos == TC_DES_BLOCKLEN) {
      encrypt_block(cipher, iv);
      *pos = 0;
    }
    buf[i] ^= iv[(*pos)++];
  }
  return TC_OK;
}
#endif

/*****************************************************************************/
/* Public Functions: secure wipe                                             */
/*****************************************************************************/

void TC_DES_ctx_clear(struct TC_DES_ctx* ctx)
{
  if (ctx == NULL)
    return;
  TC_secure_zero(ctx, sizeof(*ctx));
}

#if TC_DES_ENABLE_TDES
void TC_DES3_ctx_clear(struct TC_DES3_ctx* ctx)
{
  if (ctx == NULL)
    return;
  TC_secure_zero(ctx, sizeof(*ctx));
}
#endif

/*****************************************************************************/
/* Public Functions: Single DES                                              */
/*****************************************************************************/

#if TC_DES_ENABLE_CBC || TC_DES_ENABLE_CTR || TC_DES_ENABLE_OFB || TC_DES_ENABLE_CFB1 ||           \
    TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB64
static void tc_des_encrypt_mode_block(const void* cipher, uint8_t* block)
{
  const struct TC_DES_ctx* ctx = (const struct TC_DES_ctx*)cipher;
  tc_des_cipher_block(ctx->Sk, block, 0);
}
#endif

#if TC_DES_ENABLE_CBC
static void tc_des_decrypt_mode_block(const void* cipher, uint8_t* block)
{
  const struct TC_DES_ctx* ctx = (const struct TC_DES_ctx*)cipher;
  tc_des_cipher_block(ctx->Sk, block, 1);
}
#endif

TC_status TC_DES_init_ctx(struct TC_DES_ctx* ctx, const uint8_t* key)
{
  if (ctx == NULL)
    return TC_ERROR;
  if (key == NULL || !tc_internal_ranges_disjoint(ctx, sizeof *ctx, key, TC_DES_KEYLEN)) {
    TC_DES_ctx_clear(ctx);
    return TC_ERROR;
  }
  TC_DES_ctx_clear(ctx);
#if TC_DES_REJECT_WEAK_KEYS
  if (tc_des_bundle_is_rejected(key, TC_DES_KEYLEN))
    return TC_ERROR;
#endif
  tc_des_key_schedule(ctx->Sk, key);
#if TC_DES_NEEDS_IV
  memset(ctx->Iv, 0, TC_DES_BLOCKLEN);
#endif
#if TC_DES_ENABLE_CTR
  memset(ctx->ctr_stream, 0, TC_DES_BLOCKLEN);
  ctx->ctr_pos = TC_DES_BLOCKLEN;
  ctx->ctr_exhausted = 0;
#endif
#if TC_DES_ENABLE_OFB
  ctx->ofb_pos = TC_DES_BLOCKLEN;
#endif
  ctx->active = 1;
  return TC_OK;
}

#if TC_DES_NEEDS_IV
TC_status TC_DES_init_ctx_iv(struct TC_DES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  if (ctx == NULL)
    return TC_ERROR;
  if (iv == NULL || !tc_internal_ranges_disjoint(ctx, sizeof *ctx, iv, TC_DES_BLOCKLEN)) {
    TC_DES_ctx_clear(ctx);
    return TC_ERROR;
  }
  if (TC_DES_init_ctx(ctx, key) != TC_OK)
    return TC_ERROR;
  memcpy(ctx->Iv, iv, TC_DES_BLOCKLEN);
#if TC_DES_ENABLE_CTR
  ctx->ctr_pos = TC_DES_BLOCKLEN;
  ctx->ctr_exhausted = 0;
#endif
#if TC_DES_ENABLE_OFB
  ctx->ofb_pos = TC_DES_BLOCKLEN;
#endif
  return TC_OK;
}

TC_status TC_DES_ctx_set_iv(struct TC_DES_ctx* ctx, const uint8_t* iv)
{
  if (ctx == NULL || ctx->active != 1 || iv == NULL)
    return TC_ERROR;
  memcpy(ctx->Iv, iv, TC_DES_BLOCKLEN);
#if TC_DES_ENABLE_CTR
  ctx->ctr_pos = TC_DES_BLOCKLEN;
  ctx->ctr_exhausted = 0;
#endif
#if TC_DES_ENABLE_OFB
  ctx->ofb_pos = TC_DES_BLOCKLEN;
#endif
  return TC_OK;
}
#endif

#if TC_DES_ENABLE_ECB
TC_status TC_DES_ECB_encrypt(const struct TC_DES_ctx* ctx, uint8_t* buf)
{
  if (ctx == NULL || ctx->active != 1 || buf == NULL)
    return TC_ERROR;
  tc_des_cipher_block(ctx->Sk, buf, 0);
  return TC_OK;
}

TC_status TC_DES_ECB_decrypt(const struct TC_DES_ctx* ctx, uint8_t* buf)
{
  if (ctx == NULL || ctx->active != 1 || buf == NULL)
    return TC_ERROR;
  tc_des_cipher_block(ctx->Sk, buf, 1);
  return TC_OK;
}
#endif

#if TC_DES_ENABLE_CBC
TC_status TC_DES_CBC_encrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cbc(ctx, ctx->Iv, buf, length, tc_des_encrypt_mode_block, 0);
}

TC_status TC_DES_CBC_decrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cbc(ctx, ctx->Iv, buf, length, tc_des_decrypt_mode_block, 1);
}
#endif

#if TC_DES_ENABLE_CTR
TC_status TC_DES_CTR_crypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_ctr(ctx, ctx->Iv, ctx->ctr_stream, &ctx->ctr_pos, &ctx->ctr_exhausted, buf,
                         length, tc_des_encrypt_mode_block);
}
#endif

#if TC_DES_ENABLE_CFB64
TC_status TC_DES_CFB64_encrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cfb64(ctx, ctx->Iv, buf, length, tc_des_encrypt_mode_block, 0);
}

TC_status TC_DES_CFB64_decrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  /* CFB decryption uses the cipher's forward direction. */
  return tc_des_mode_cfb64(ctx, ctx->Iv, buf, length, tc_des_encrypt_mode_block, 1);
}
#endif

#if TC_DES_ENABLE_CFB8
TC_status TC_DES_CFB8_encrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cfb8(ctx, ctx->Iv, buf, length, tc_des_encrypt_mode_block, 0);
}

TC_status TC_DES_CFB8_decrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cfb8(ctx, ctx->Iv, buf, length, tc_des_encrypt_mode_block, 1);
}
#endif

#if TC_DES_ENABLE_CFB1
TC_status TC_DES_CFB1_encrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t bit_length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cfb1(ctx, ctx->Iv, buf, bit_length, tc_des_encrypt_mode_block, 0);
}

TC_status TC_DES_CFB1_decrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t bit_length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cfb1(ctx, ctx->Iv, buf, bit_length, tc_des_encrypt_mode_block, 1);
}
#endif

#if TC_DES_ENABLE_OFB
TC_status TC_DES_OFB_crypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_ofb(ctx, ctx->Iv, &ctx->ofb_pos, buf, length, tc_des_encrypt_mode_block);
}
#endif

/*****************************************************************************/
/* Public Functions: Triple DES (3DES / TDES)                                */
/*****************************************************************************/

#if TC_DES_ENABLE_TDES

TC_status TC_DES3_init_ctx(struct TC_DES3_ctx* ctx, const uint8_t* key, size_t keylen)
{
  if (ctx == NULL)
    return TC_ERROR;
  if (key == NULL || (keylen != 16 && keylen != 24) ||
      !tc_internal_ranges_disjoint(ctx, sizeof *ctx, key, keylen)) {
    TC_DES3_ctx_clear(ctx);
    return TC_ERROR;
  }
  TC_DES3_ctx_clear(ctx);
#if TC_DES_REJECT_WEAK_KEYS
  if (tc_des_bundle_is_rejected(key, keylen))
    return TC_ERROR;
#endif

  tc_des_bundle_schedule(ctx->keys.schedule, key, keylen);
#if TC_DES_NEEDS_IV
  memset(ctx->Iv, 0, TC_DES_BLOCKLEN);
#endif
#if TC_DES_ENABLE_CTR
  memset(ctx->ctr_stream, 0, TC_DES_BLOCKLEN);
  ctx->ctr_pos = TC_DES_BLOCKLEN;
  ctx->ctr_exhausted = 0;
#endif
#if TC_DES_ENABLE_OFB
  ctx->ofb_pos = TC_DES_BLOCKLEN;
#endif
  ctx->active = 1;
  return TC_OK;
}

#if TC_DES_NEEDS_IV
TC_status TC_DES3_init_ctx_iv(struct TC_DES3_ctx* ctx, const uint8_t* key, size_t keylen,
                              const uint8_t* iv)
{
  if (ctx == NULL)
    return TC_ERROR;
  if (iv == NULL || !tc_internal_ranges_disjoint(ctx, sizeof *ctx, iv, TC_DES_BLOCKLEN)) {
    TC_DES3_ctx_clear(ctx);
    return TC_ERROR;
  }
  if (TC_DES3_init_ctx(ctx, key, keylen) != TC_OK)
    return TC_ERROR;
  memcpy(ctx->Iv, iv, TC_DES_BLOCKLEN);
#if TC_DES_ENABLE_CTR
  ctx->ctr_pos = TC_DES_BLOCKLEN;
  ctx->ctr_exhausted = 0;
#endif
#if TC_DES_ENABLE_OFB
  ctx->ofb_pos = TC_DES_BLOCKLEN;
#endif
  return TC_OK;
}

TC_status TC_DES3_ctx_set_iv(struct TC_DES3_ctx* ctx, const uint8_t* iv)
{
  if (ctx == NULL || ctx->active != 1 || iv == NULL)
    return TC_ERROR;
  memcpy(ctx->Iv, iv, TC_DES_BLOCKLEN);
#if TC_DES_ENABLE_CTR
  ctx->ctr_pos = TC_DES_BLOCKLEN;
  ctx->ctr_exhausted = 0;
#endif
#if TC_DES_ENABLE_OFB
  ctx->ofb_pos = TC_DES_BLOCKLEN;
#endif
  return TC_OK;
}
#endif

/* 3DES Core Encryption: E(K1) -> D(K2) -> E(K3) */
#if TC_DES_ENABLE_ECB || TC_DES_ENABLE_CBC || TC_DES_ENABLE_CTR || TC_DES_ENABLE_OFB ||            \
    TC_DES_ENABLE_CFB1 || TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB64
static void tc_des3_encrypt_block(const struct TC_DES3_ctx* ctx, uint8_t* buf)
{
  tc_des_encrypt_scheduled(ctx->keys.schedule, buf, 1);
}
#endif

#if (TC_DES_ENABLE_ECB == 1) || (TC_DES_ENABLE_CBC == 1)
/* 3DES Core Decryption: D(K1) -> E(K2) -> D(K3) */
static void tc_des3_decrypt_block(const struct TC_DES3_ctx* ctx, uint8_t* buf)
{
  tc_des_cipher_block(&ctx->keys.schedule[32], buf, 1); /* Decrypt K3 */
  tc_des_cipher_block(&ctx->keys.schedule[16], buf, 0); /* Encrypt K2 */
  tc_des_cipher_block(&ctx->keys.schedule[0], buf, 1);  /* Decrypt K1 */
}
#endif

#if TC_DES_ENABLE_CBC || TC_DES_ENABLE_CTR || TC_DES_ENABLE_OFB || TC_DES_ENABLE_CFB1 ||           \
    TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB64
static void tc_des3_encrypt_mode_block(const void* cipher, uint8_t* block)
{
  tc_des3_encrypt_block((const struct TC_DES3_ctx*)cipher, block);
}
#endif

#if TC_DES_ENABLE_CBC
static void tc_des3_decrypt_mode_block(const void* cipher, uint8_t* block)
{
  tc_des3_decrypt_block((const struct TC_DES3_ctx*)cipher, block);
}
#endif

#if TC_DES_ENABLE_ECB
TC_status TC_DES3_ECB_encrypt(const struct TC_DES3_ctx* ctx, uint8_t* buf)
{
  if (ctx == NULL || ctx->active != 1 || buf == NULL)
    return TC_ERROR;
  tc_des3_encrypt_block(ctx, buf);
  return TC_OK;
}

TC_status TC_DES3_ECB_decrypt(const struct TC_DES3_ctx* ctx, uint8_t* buf)
{
  if (ctx == NULL || ctx->active != 1 || buf == NULL)
    return TC_ERROR;
  tc_des3_decrypt_block(ctx, buf);
  return TC_OK;
}
#endif

#if TC_DES_ENABLE_CBC
TC_status TC_DES3_CBC_encrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cbc(ctx, ctx->Iv, buf, length, tc_des3_encrypt_mode_block, 0);
}

TC_status TC_DES3_CBC_decrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cbc(ctx, ctx->Iv, buf, length, tc_des3_decrypt_mode_block, 1);
}
#endif

#if TC_DES_ENABLE_CTR
TC_status TC_DES3_CTR_crypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_ctr(ctx, ctx->Iv, ctx->ctr_stream, &ctx->ctr_pos, &ctx->ctr_exhausted, buf,
                         length, tc_des3_encrypt_mode_block);
}
#endif

#if TC_DES_ENABLE_CFB64
TC_status TC_DES3_CFB64_encrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cfb64(ctx, ctx->Iv, buf, length, tc_des3_encrypt_mode_block, 0);
}

TC_status TC_DES3_CFB64_decrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cfb64(ctx, ctx->Iv, buf, length, tc_des3_encrypt_mode_block, 1);
}
#endif

#if TC_DES_ENABLE_CFB8
TC_status TC_DES3_CFB8_encrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cfb8(ctx, ctx->Iv, buf, length, tc_des3_encrypt_mode_block, 0);
}

TC_status TC_DES3_CFB8_decrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cfb8(ctx, ctx->Iv, buf, length, tc_des3_encrypt_mode_block, 1);
}
#endif

#if TC_DES_ENABLE_CFB1
TC_status TC_DES3_CFB1_encrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t bit_length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cfb1(ctx, ctx->Iv, buf, bit_length, tc_des3_encrypt_mode_block, 0);
}

TC_status TC_DES3_CFB1_decrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t bit_length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_cfb1(ctx, ctx->Iv, buf, bit_length, tc_des3_encrypt_mode_block, 1);
}
#endif

#if TC_DES_ENABLE_OFB
TC_status TC_DES3_OFB_crypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length)
{
  DES_MODE_REQUIRE_CTX(ctx);
  return tc_des_mode_ofb(ctx, ctx->Iv, &ctx->ofb_pos, buf, length, tc_des3_encrypt_mode_block);
}
#endif

#endif /* #if TC_DES_ENABLE_TDES */
