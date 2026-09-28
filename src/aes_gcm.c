/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * AES-GCM authenticated encryption (NIST SP 800-38D): streaming and one-shot
 * encryption and decryption, short-tag packet limits (appendix C) and the
 * decrypt-side recheck that keeps ciphertext unchanged on a bad tag.
 * GHASH lives in aes_ghash.c. */
#include "aes_internal.h"
#include "aes_ghash_internal.h"

#if defined(TC_AES_ENABLE_GCM) && (TC_AES_ENABLE_GCM == 1)

#define TC_AES_GCM_PHASE_UNINIT 0u
#define TC_AES_GCM_PHASE_AAD 1u
#define TC_AES_GCM_PHASE_TEXT 2u
#define TC_AES_GCM_PHASE_FINAL 3u
#define TC_AES_GCM_DIRECTION_NONE 0u
#define TC_AES_GCM_DIRECTION_ENCRYPT 1u
#define TC_AES_GCM_DIRECTION_DECRYPT 2u

static void tc_aes_gcm_make_j0(struct TC_AES_GCM_ctx* ctx, const uint8_t* iv, size_t iv_len)
{
  uint8_t length_block[TC_AES_BLOCKLEN] = {0};

  memset(ctx->S, 0, TC_AES_BLOCKLEN);
  memset(ctx->ghash, 0, TC_AES_BLOCKLEN);
  if (iv_len == 12) {
    memset(ctx->J0, 0, TC_AES_BLOCKLEN);
    tc_aes_copy_bytes(ctx->J0, iv, iv_len);
    ctx->J0[15] = 1;
  } else {
    tc_aes_gcm_hash_bytes(ctx, iv, iv_len);
    tc_internal_store_be64(length_block + 8, (uint64_t)iv_len * 8u);
    tc_aes_gcm_ghash_block(ctx, length_block);
    tc_aes_copy_bytes(ctx->J0, ctx->S, TC_AES_BLOCKLEN);
  }
  memset(ctx->S, 0, TC_AES_BLOCKLEN);
  memset(ctx->ghash, 0, TC_AES_BLOCKLEN);
}

static int tc_aes_gcm_length_is_valid(uint64_t current, size_t additional, uint64_t limit)
{
  return (uint64_t)additional <= (limit - current);
}

static void tc_aes_gcm_pad_ghash(struct TC_AES_GCM_ctx* ctx)
{
  if (ctx->ghash_len != 0) {
    memset(ctx->ghash + ctx->ghash_len, 0, TC_AES_BLOCKLEN - ctx->ghash_len);
    tc_aes_gcm_ghash_block(ctx, ctx->ghash);
    ctx->ghash_len = 0;
    memset(ctx->ghash, 0, TC_AES_BLOCKLEN);
  }
}

static void tc_aes_gcm_start_text(struct TC_AES_GCM_ctx* ctx, int decrypt)
{
  if (ctx->phase != TC_AES_GCM_PHASE_AAD)
    return;
  tc_aes_gcm_pad_ghash(ctx);
  if (decrypt)
    tc_aes_copy_bytes(ctx->aad_state, ctx->S, TC_AES_BLOCKLEN);
  ctx->phase = TC_AES_GCM_PHASE_TEXT;
}

static void tc_aes_gcm_absorb(struct TC_AES_GCM_ctx* ctx, const uint8_t* data, size_t length)
{
  while (length != 0) {
    if (ctx->ghash_len == 0 && length >= TC_AES_BLOCKLEN) {
      tc_aes_gcm_ghash_block(ctx, data);
      data += TC_AES_BLOCKLEN;
      length -= TC_AES_BLOCKLEN;
      continue;
    }
    const size_t available = TC_AES_BLOCKLEN - ctx->ghash_len;
    const size_t count = length < available ? length : available;
    tc_aes_copy_bytes(ctx->ghash + ctx->ghash_len, data, count);
    ctx->ghash_len = (uint8_t)(ctx->ghash_len + count);
    data += count;
    length -= count;
    if (ctx->ghash_len == TC_AES_BLOCKLEN) {
      tc_aes_gcm_ghash_block(ctx, ctx->ghash);
      ctx->ghash_len = 0;
      memset(ctx->ghash, 0, TC_AES_BLOCKLEN);
    }
  }
}

static void tc_aes_gcm_increment_counter(uint8_t* counter)
{
  unsigned i;
  for (i = 0; i < 4; ++i) {
    const unsigned offset = 15u - i;
    if (counter[offset] != 0xffu) {
      ++counter[offset];
      break;
    }
    counter[offset] = 0;
  }
}

static void tc_aes_gcm_finish_ghash(struct TC_AES_GCM_ctx* ctx)
{
  uint8_t length_block[TC_AES_BLOCKLEN] = {0};

  tc_aes_gcm_pad_ghash(ctx);
  tc_internal_store_be64(length_block, ctx->aad_len * 8u);
  tc_internal_store_be64(length_block + 8, ctx->text_len * 8u);
  tc_aes_gcm_ghash_block(ctx, length_block);
}

/* SP 800-38D §5.2.1.2 permits these lengths. Short tags need explicit use. */
static int tc_aes_gcm_tag_length_is_allowed(size_t tag_len, int short_tag)
{
  return short_tag ? (tag_len == 4 || tag_len == 8) : (tag_len >= 12 && tag_len <= 16);
}

/*
 * Appendix C packet bound for short tags only (most permissive table row).
 * 96–128 bit tags have no Appendix C size cap. Overflow-safe for MCU math.
 * The application tracks lifetime decryption-invocation limits and rotates
 * keys per Appendix C. The library has no NVRAM or key store.
 */
static int tc_aes_gcm_packet_lengths_ok(size_t tag_len, uint64_t aad_len, uint64_t text_len,
                                        uint64_t extra_text)
{
  uint64_t limit;

  if (tag_len != 4 && tag_len != 8)
    return 1;

  limit = (tag_len == 4) ? TC_AES_GCM_SHORT_TAG4_MAX_PACKET : TC_AES_GCM_SHORT_TAG8_MAX_PACKET;
  if (aad_len > limit || text_len > limit - aad_len)
    return 0;
  return extra_text <= limit - aad_len - text_len;
}

static int tc_aes_gcm_packet_length_ok(const struct TC_AES_GCM_ctx* ctx, uint64_t extra_text)
{
  return tc_aes_gcm_packet_lengths_ok(ctx->tag_len, ctx->aad_len, ctx->text_len, extra_text);
}

static void tc_aes_gcm_invalidate(struct TC_AES_GCM_ctx* ctx)
{
  TC_AES_GCM_clear(ctx);
  ctx->phase = TC_AES_GCM_PHASE_FINAL;
}

static TC_status tc_aes_gcm_make_tag(const struct TC_AES_GCM_ctx* ctx, uint8_t* tag)
{
  uint8_t mask[TC_AES_BLOCKLEN];
  uint8_t hash[TC_AES_BLOCKLEN];
  uint8_t i;
  TC_status status;

  tc_aes_copy_bytes(mask, ctx->J0, TC_AES_BLOCKLEN);
  status = tc_aes_cipher((state_t*)mask, ctx->key.round_key);
  if (status != TC_OK)
    goto done;
  tc_aes_copy_bytes(hash, ctx->S, TC_AES_BLOCKLEN);
  /* MSBt truncation: leading tag_len bytes of the 128-bit block. */
  for (i = 0; i < ctx->tag_len; ++i)
    tag[i] = (uint8_t)(mask[i] ^ hash[i]);
done:
#if TC_ZEROIZE
  TC_secure_zero(mask, sizeof(mask));
  TC_secure_zero(hash, sizeof(hash));
#endif
  return status;
}

static TC_status tc_aes_gcm_init_impl(struct TC_AES_GCM_ctx* ctx, const uint8_t* key,
                                      const uint8_t* iv, size_t iv_len, size_t tag_len,
                                      int short_tag)
{
  uint8_t zero[TC_AES_BLOCKLEN] = {0};

  if (ctx == NULL)
    return TC_ERROR;
  if ((key != NULL && !tc_internal_ranges_disjoint(ctx, sizeof(*ctx), key, TC_AES_KEYLEN)) ||
      (iv != NULL && iv_len <= TC_AES_GCM_MAX_IV_BYTES &&
       !tc_internal_ranges_disjoint(ctx, sizeof(*ctx), iv, iv_len))) {
    TC_AES_GCM_clear(ctx);
    return TC_ERROR;
  }
  TC_AES_GCM_clear(ctx);
  if (key == NULL || iv == NULL || iv_len == 0 || (uint64_t)iv_len > TC_AES_GCM_MAX_IV_BYTES ||
      !tc_aes_gcm_tag_length_is_allowed(tag_len, short_tag))
    return TC_ERROR;

  if (TC_AES_key_init(&ctx->key, key) != TC_OK)
    return TC_ERROR;
  tc_aes_copy_bytes(ctx->H, zero, TC_AES_BLOCKLEN);
  if (tc_aes_cipher((state_t*)ctx->H, ctx->key.round_key) != TC_OK) {
    tc_aes_gcm_invalidate(ctx);
    return TC_ERROR;
  }
#if TC_AES_GCM_GHASH_MODE == TC_AES_GCM_GHASH_MODE_FAST_TABLE
  tc_aes_gcm_init_table(ctx);
#endif
  tc_aes_gcm_make_j0(ctx, iv, iv_len);
  tc_aes_copy_bytes(ctx->counter, ctx->J0, TC_AES_BLOCKLEN);
  tc_aes_copy_bytes(ctx->S, zero, TC_AES_BLOCKLEN);
  tc_aes_copy_bytes(ctx->ghash, zero, TC_AES_BLOCKLEN);
  ctx->aad_len = 0;
  ctx->text_len = 0;
  ctx->stream_pos = TC_AES_BLOCKLEN;
  ctx->ghash_len = 0;
  ctx->tag_len = (uint8_t)tag_len;
  ctx->phase = TC_AES_GCM_PHASE_AAD;
  ctx->direction = TC_AES_GCM_DIRECTION_NONE;
  ctx->decrypt_buffer = NULL;
  ctx->decrypt_length = 0;
  return TC_OK;
}

TC_status TC_AES_GCM_init(struct TC_AES_GCM_ctx* ctx, const uint8_t* key, const uint8_t* iv,
                          size_t iv_len, size_t tag_len)
{
  return tc_aes_gcm_init_impl(ctx, key, iv, iv_len, tag_len, 0);
}

TC_status TC_AES_GCM_init_short_tag(struct TC_AES_GCM_ctx* ctx, const uint8_t* key,
                                    const uint8_t* iv, size_t iv_len, size_t tag_len)
{
  return tc_aes_gcm_init_impl(ctx, key, iv, iv_len, tag_len, 1);
}

TC_status TC_AES_GCM_aad_update(struct TC_AES_GCM_ctx* ctx, const uint8_t* aad, size_t length)
{
  if (ctx == NULL || ctx->phase != TC_AES_GCM_PHASE_AAD || (length != 0 && aad == NULL) ||
      !tc_internal_ranges_disjoint(ctx, sizeof(*ctx), aad, length) ||
      !tc_aes_gcm_length_is_valid(ctx->aad_len, length, TC_AES_GCM_MAX_AAD_BYTES))
    return TC_ERROR;

  if (!tc_aes_gcm_packet_length_ok(ctx, (uint64_t)length))
    return TC_ERROR;

  tc_aes_gcm_absorb(ctx, aad, length);
  ctx->aad_len += (uint64_t)length;
  return TC_OK;
}

static int tc_aes_gcm_encrypt_update_impl(struct TC_AES_GCM_ctx* ctx, uint8_t* buf, size_t length)
{
  size_t i;
  const size_t total_length = length;
  uint8_t* const output = buf;

  if (ctx == NULL || ctx->phase == TC_AES_GCM_PHASE_UNINIT ||
      ctx->phase == TC_AES_GCM_PHASE_FINAL || (length != 0 && buf == NULL) ||
      !tc_internal_ranges_disjoint(ctx, sizeof(*ctx), buf, length) ||
      !tc_aes_gcm_length_is_valid(ctx->text_len, length, TC_AES_GCM_MAX_PLAINTEXT_BYTES) ||
      !tc_aes_gcm_packet_length_ok(ctx, (uint64_t)length))
    return TC_ERROR;
  if (ctx->direction == TC_AES_GCM_DIRECTION_DECRYPT)
    return TC_ERROR;
  ctx->direction = TC_AES_GCM_DIRECTION_ENCRYPT;

  tc_aes_gcm_start_text(ctx, 0);

  while (length >= TC_AES_BLOCKLEN && ctx->stream_pos == TC_AES_BLOCKLEN && ctx->ghash_len == 0) {
    uint8_t j;

    tc_aes_gcm_increment_counter(ctx->counter);
    tc_aes_copy_bytes(ctx->stream, ctx->counter, TC_AES_BLOCKLEN);
    if (tc_aes_cipher((state_t*)ctx->stream, ctx->key.round_key) != TC_OK)
      goto failed;
    for (j = 0; j < TC_AES_BLOCKLEN; ++j)
      buf[j] ^= ctx->stream[j];
    tc_aes_gcm_absorb(ctx, buf, TC_AES_BLOCKLEN);
    buf += TC_AES_BLOCKLEN;
    length -= TC_AES_BLOCKLEN;
  }

  while (length != 0) {
    size_t available;
    size_t count;

    if (ctx->stream_pos == TC_AES_BLOCKLEN) {
      tc_aes_gcm_increment_counter(ctx->counter);
      tc_aes_copy_bytes(ctx->stream, ctx->counter, TC_AES_BLOCKLEN);
      if (tc_aes_cipher((state_t*)ctx->stream, ctx->key.round_key) != TC_OK)
        goto failed;
      ctx->stream_pos = 0;
    }

    available = TC_AES_BLOCKLEN - ctx->stream_pos;
    count = length < available ? length : available;
    for (i = 0; i < count; ++i)
      buf[i] ^= ctx->stream[ctx->stream_pos + i];
    tc_aes_gcm_absorb(ctx, buf, count);
    buf += count;
    length -= count;
    ctx->stream_pos = (uint8_t)(ctx->stream_pos + count);
  }
  ctx->text_len += (uint64_t)total_length;
  return TC_OK;
failed:
  TC_secure_zero(output, total_length);
  tc_aes_gcm_invalidate(ctx);
  return TC_ERROR;
}

TC_status TC_AES_GCM_encrypt_update(struct TC_AES_GCM_ctx* ctx, uint8_t* buf, size_t length)
{
  return tc_aes_gcm_encrypt_update_impl(ctx, buf, length);
}

static TC_status tc_aes_gcm_decrypt_absorb(struct TC_AES_GCM_ctx* ctx, const uint8_t* ciphertext,
                                           size_t length)
{
  if (ctx->direction == TC_AES_GCM_DIRECTION_ENCRYPT ||
      !tc_aes_gcm_length_is_valid(ctx->text_len, length, TC_AES_GCM_MAX_PLAINTEXT_BYTES) ||
      !tc_aes_gcm_packet_length_ok(ctx, (uint64_t)length))
    return TC_ERROR;
  tc_aes_gcm_start_text(ctx, 1);
  ctx->direction = TC_AES_GCM_DIRECTION_DECRYPT;
  tc_aes_gcm_absorb(ctx, ciphertext, length);
  ctx->text_len += (uint64_t)length;
  return TC_OK;
}

TC_status TC_AES_GCM_decrypt_update(struct TC_AES_GCM_ctx* ctx, uint8_t* buf, size_t length)
{
  if (ctx == NULL || ctx->phase == TC_AES_GCM_PHASE_UNINIT ||
      ctx->phase == TC_AES_GCM_PHASE_FINAL || (length != 0 && buf == NULL) ||
      !tc_internal_ranges_disjoint(ctx, sizeof(*ctx), buf, length) ||
      length > SIZE_MAX - ctx->decrypt_length)
    return TC_ERROR;
  if (length != 0 && ctx->decrypt_buffer != NULL &&
      ((uintptr_t)ctx->decrypt_buffer > UINTPTR_MAX - ctx->decrypt_length ||
       (uintptr_t)buf != (uintptr_t)ctx->decrypt_buffer + ctx->decrypt_length))
    return TC_ERROR;
  if (tc_aes_gcm_decrypt_absorb(ctx, buf, length) != TC_OK)
    return TC_ERROR;
  if (length != 0 && ctx->decrypt_buffer == NULL)
    ctx->decrypt_buffer = buf;
  ctx->decrypt_length += length;
  return TC_OK;
}

/* Rehash the same local ciphertext blocks used for decryption. A caller may
 * change the receive buffer after update or while finish is running. */
static TC_status tc_aes_gcm_decrypt_recheck(struct TC_AES_GCM_ctx* ctx, const uint8_t* ciphertext,
                                            uint8_t* plaintext, size_t length, const uint8_t* tag)
{
  uint8_t counter[TC_AES_BLOCKLEN];
  uint8_t block[TC_AES_BLOCKLEN];
  uint8_t stream[TC_AES_BLOCKLEN];
  uint8_t expected[TC_AES_BLOCKLEN];
  size_t offset = 0;
  TC_status status = TC_OK;

  tc_aes_copy_bytes(ctx->S, ctx->aad_state, TC_AES_BLOCKLEN);
  ctx->ghash_len = 0;
  tc_aes_copy_bytes(counter, ctx->J0, TC_AES_BLOCKLEN);
  while (offset < length) {
    const size_t remaining = length - offset;
    const size_t count = remaining < TC_AES_BLOCKLEN ? remaining : TC_AES_BLOCKLEN;
    size_t i;
    tc_aes_copy_bytes(block, ciphertext + offset, count);
    tc_aes_gcm_absorb(ctx, block, count);
    tc_aes_gcm_increment_counter(counter);
    tc_aes_copy_bytes(stream, counter, TC_AES_BLOCKLEN);
    if (tc_aes_cipher((state_t*)stream, ctx->key.round_key) != TC_OK) {
      status = TC_ERROR;
      break;
    }
    for (i = 0; i < count; ++i)
      plaintext[offset + i] = (uint8_t)(block[i] ^ stream[i]);
    offset += count;
  }
  if (status == TC_OK) {
    tc_aes_gcm_finish_ghash(ctx);
    status = tc_aes_gcm_make_tag(ctx, expected);
    if (status == TC_OK)
      status = TC_ct_equal(expected, tag, ctx->tag_len);
  }
  if (status != TC_OK)
    TC_secure_zero(plaintext, length);
#if TC_ZEROIZE
  TC_secure_zero(counter, sizeof counter);
  TC_secure_zero(block, sizeof block);
  TC_secure_zero(stream, sizeof stream);
  TC_secure_zero(expected, sizeof expected);
#endif
  return status;
}

TC_status TC_AES_GCM_encrypt_finish(struct TC_AES_GCM_ctx* ctx, uint8_t* tag)
{
  if (ctx == NULL || tag == NULL || ctx->phase == TC_AES_GCM_PHASE_UNINIT ||
      ctx->phase == TC_AES_GCM_PHASE_FINAL ||
      !tc_internal_ranges_disjoint(ctx, sizeof(*ctx), tag, ctx->tag_len) ||
      !tc_aes_gcm_packet_length_ok(ctx, 0))
    return TC_ERROR;
  if (ctx->direction == TC_AES_GCM_DIRECTION_DECRYPT)
    return TC_ERROR;
  tc_aes_gcm_start_text(ctx, 0);
  tc_aes_gcm_finish_ghash(ctx);
  if (tc_aes_gcm_make_tag(ctx, tag) != TC_OK) {
    tc_aes_gcm_invalidate(ctx);
    return TC_ERROR;
  }
  ctx->phase = TC_AES_GCM_PHASE_FINAL;
#if TC_ZEROIZE
  tc_aes_gcm_invalidate(ctx);
#endif
  return TC_OK;
}

TC_status TC_AES_GCM_decrypt_finish(struct TC_AES_GCM_ctx* ctx, const uint8_t* tag)
{
  uint8_t expected[TC_AES_BLOCKLEN];
  TC_status status;

  if (ctx == NULL || tag == NULL || ctx->phase == TC_AES_GCM_PHASE_UNINIT ||
      ctx->phase == TC_AES_GCM_PHASE_FINAL ||
      !tc_internal_ranges_disjoint(ctx, sizeof(*ctx), tag, ctx->tag_len) ||
      !tc_aes_buffers_disjoint(ctx->decrypt_buffer, ctx->decrypt_length, tag, ctx->tag_len) ||
      !tc_aes_gcm_packet_length_ok(ctx, 0))
    return TC_ERROR;
  if (ctx->direction == TC_AES_GCM_DIRECTION_ENCRYPT)
    return TC_ERROR;
  tc_aes_gcm_start_text(ctx, 1);
  tc_aes_gcm_finish_ghash(ctx);
  status = tc_aes_gcm_make_tag(ctx, expected);
  /* Authentication tags contain secrets, so comparison time must not reveal
   * the first byte that differs. */
  if (status == TC_OK)
    status = TC_ct_equal(expected, tag, ctx->tag_len);
  if (status == TC_OK && ctx->decrypt_length != 0)
    status = tc_aes_gcm_decrypt_recheck(ctx, ctx->decrypt_buffer, ctx->decrypt_buffer,
                                        ctx->decrypt_length, tag);
  if (status != TC_OK || TC_ZEROIZE)
    tc_aes_gcm_invalidate(ctx);
  else {
    ctx->phase = TC_AES_GCM_PHASE_FINAL;
    ctx->decrypt_buffer = NULL;
    ctx->decrypt_length = 0;
  }
#if TC_ZEROIZE
  TC_secure_zero(expected, sizeof(expected));
#endif
  return status;
}

void TC_AES_GCM_clear(struct TC_AES_GCM_ctx* ctx)
{
  if (ctx == NULL)
    return;
  TC_secure_zero(ctx, sizeof(*ctx));
}

static int tc_aes_gcm_oneshot_args_ok(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                                      const uint8_t* aad, size_t aad_len, const uint8_t* input,
                                      size_t input_len, uint8_t* output, const uint8_t* tag,
                                      size_t tag_len, int short_tag)
{
  return key != NULL && iv != NULL && iv_len != 0 && (aad_len == 0 || aad != NULL) &&
         (input_len == 0 || (input != NULL && output != NULL)) && tag != NULL &&
         tc_aes_gcm_tag_length_is_allowed(tag_len, short_tag) &&
         (uint64_t)iv_len <= TC_AES_GCM_MAX_IV_BYTES &&
         (uint64_t)aad_len <= TC_AES_GCM_MAX_AAD_BYTES &&
         (uint64_t)input_len <= TC_AES_GCM_MAX_PLAINTEXT_BYTES &&
         tc_aes_buffers_ok(input, input_len, output, input_len) &&
         tc_aes_buffers_disjoint(output, input_len, tag, tag_len) &&
         tc_aes_gcm_packet_lengths_ok(tag_len, (uint64_t)aad_len, (uint64_t)input_len, 0);
}

static TC_status tc_aes_gcm_encrypt_impl(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                                         const uint8_t* aad, size_t aad_len,
                                         const uint8_t* plaintext, size_t plaintext_len,
                                         uint8_t* ciphertext, uint8_t* tag, size_t tag_len,
                                         int short_tag)
{
  struct TC_AES_GCM_ctx ctx;
  int status;

  if (!tc_aes_gcm_oneshot_args_ok(key, iv, iv_len, aad, aad_len, plaintext, plaintext_len,
                                  ciphertext, tag, tag_len, short_tag))
    return TC_ERROR;

  if (tc_aes_gcm_init_impl(&ctx, key, iv, iv_len, tag_len, short_tag) != TC_OK)
    return TC_ERROR;
  if (TC_AES_GCM_aad_update(&ctx, aad, aad_len) != TC_OK) {
#if TC_ZEROIZE
    TC_AES_GCM_clear(&ctx);
#endif
    return TC_ERROR;
  }

  /* Copy only after all length/overlap checks and AAD accept. */
  if (plaintext != ciphertext && plaintext_len != 0)
    tc_aes_copy_bytes(ciphertext, plaintext, plaintext_len);

  status = TC_AES_GCM_encrypt_update(&ctx, ciphertext, plaintext_len);
  if (status == TC_OK)
    status = TC_AES_GCM_encrypt_finish(&ctx, tag);
  if (status != TC_OK && plaintext_len != 0)
    TC_secure_zero(ciphertext, plaintext_len);

#if TC_ZEROIZE
  TC_AES_GCM_clear(&ctx);
#endif
  return status;
}

static TC_status tc_aes_gcm_decrypt_impl(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                                         const uint8_t* aad, size_t aad_len,
                                         const uint8_t* ciphertext, size_t ciphertext_len,
                                         const uint8_t* tag, size_t tag_len, uint8_t* plaintext,
                                         int short_tag)
{
  struct TC_AES_GCM_ctx ctx;
  uint8_t expected[TC_AES_BLOCKLEN] = {0};
  TC_status status = TC_ERROR;

  if (!tc_aes_gcm_oneshot_args_ok(key, iv, iv_len, aad, aad_len, ciphertext, ciphertext_len,
                                  plaintext, tag, tag_len, short_tag))
    return TC_ERROR;

  if (tc_aes_gcm_init_impl(&ctx, key, iv, iv_len, tag_len, short_tag) != TC_OK)
    return TC_ERROR;
  if (TC_AES_GCM_aad_update(&ctx, aad, aad_len) != TC_OK)
    goto done;

  /* Absorb ciphertext into GHASH before releasing plaintext. */
  if (tc_aes_gcm_decrypt_absorb(&ctx, ciphertext, ciphertext_len) != TC_OK)
    goto done;

  tc_aes_gcm_finish_ghash(&ctx);
  if (tc_aes_gcm_make_tag(&ctx, expected) != TC_OK)
    goto done;
  status = TC_ct_equal(expected, tag, ctx.tag_len);
  ctx.phase = TC_AES_GCM_PHASE_FINAL;

  if (status != TC_OK) {
    /* In-place callers supplied ciphertext in this buffer. Wipe it so an
     * authentication failure cannot leave unauthenticated data behind. */
    if (plaintext != NULL && plaintext == ciphertext && ciphertext_len != 0)
      TC_secure_zero(plaintext, ciphertext_len);
    goto done;
  }

  if (ciphertext_len != 0)
    status = tc_aes_gcm_decrypt_recheck(&ctx, ciphertext, plaintext, ciphertext_len, tag);

done:
#if TC_ZEROIZE
  TC_AES_GCM_clear(&ctx);
  TC_secure_zero(expected, sizeof(expected));
#endif
  return status;
}

TC_status TC_AES_GCM_encrypt(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                             const uint8_t* aad, size_t aad_len, const uint8_t* plaintext,
                             size_t plaintext_len, uint8_t* ciphertext, uint8_t* tag,
                             size_t tag_len)
{
  return tc_aes_gcm_encrypt_impl(key, iv, iv_len, aad, aad_len, plaintext, plaintext_len,
                                 ciphertext, tag, tag_len, 0);
}

TC_status TC_AES_GCM_encrypt_short_tag(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                                       const uint8_t* aad, size_t aad_len, const uint8_t* plaintext,
                                       size_t plaintext_len, uint8_t* ciphertext, uint8_t* tag,
                                       size_t tag_len)
{
  return tc_aes_gcm_encrypt_impl(key, iv, iv_len, aad, aad_len, plaintext, plaintext_len,
                                 ciphertext, tag, tag_len, 1);
}

TC_status TC_AES_GCM_decrypt(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                             const uint8_t* aad, size_t aad_len, const uint8_t* ciphertext,
                             size_t ciphertext_len, const uint8_t* tag, size_t tag_len,
                             uint8_t* plaintext)
{
  return tc_aes_gcm_decrypt_impl(key, iv, iv_len, aad, aad_len, ciphertext, ciphertext_len, tag,
                                 tag_len, plaintext, 0);
}

TC_status TC_AES_GCM_decrypt_short_tag(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                                       const uint8_t* aad, size_t aad_len,
                                       const uint8_t* ciphertext, size_t ciphertext_len,
                                       const uint8_t* tag, size_t tag_len, uint8_t* plaintext)
{
  return tc_aes_gcm_decrypt_impl(key, iv, iv_len, aad, aad_len, ciphertext, ciphertext_len, tag,
                                 tag_len, plaintext, 1);
}

#endif
