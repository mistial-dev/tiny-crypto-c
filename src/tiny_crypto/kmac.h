/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_KMAC_H_
#define TINY_CRYPTO_KMAC_H_

#include <tiny_crypto/common.h>

#if TC_ENABLE_KMAC256
/* KMAC256 state (SP 800-185). Initialize through TC_KMAC256_init.
 * Members are private to the implementation. */
struct TC_KMAC256_ctx {
  uint64_t State[25];
  uint8_t Position;
  uint8_t Active;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Key and customization lengths are in bytes, at most UINT64_MAX / 8.
 * Either may be empty (NULL with length 0). Use a strong key in real protocols.
 * Neither input may overlap ctx. Returns TC_ERROR for a NULL ctx, a NULL span
 * with a nonzero length, an oversized length or an overlap, and leaves ctx
 * unchanged in each case. */
TC_status TC_KMAC256_init(struct TC_KMAC256_ctx* ctx, const uint8_t* key, size_t key_len,
                          const uint8_t* custom, size_t custom_len);
/* Absorb len bytes into an active context. data may be NULL when len is zero.
 * Input must be separate from ctx. Rejected calls leave ctx unchanged. */
TC_status TC_KMAC256_update(struct TC_KMAC256_ctx* ctx, const uint8_t* data, size_t len);
/* Produce out_len bytes. The requested length is part of the KMAC computation.
 * Changing it changes the output, including the common prefix.
 * A successful final wipes the context. Call init again before reuse.
 * Output must be nonempty and separate from ctx. On error, neither changes. */
TC_status TC_KMAC256_final(struct TC_KMAC256_ctx* ctx, uint8_t* out, size_t out_len);
/* Wipe the context, including its key-dependent state. NULL is accepted. */
void TC_KMAC256_ctx_clear(struct TC_KMAC256_ctx* ctx);
/* One-shot KMAC256. Returns TC_ERROR for a NULL span with a nonzero length,
 * an empty output or an oversized length. Output may overlap inputs because
 * all input is read before any output is written. The internal context is
 * wiped before return. */
TC_status TC_KMAC256_digest(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len,
                            const uint8_t* custom, size_t custom_len, uint8_t* out, size_t out_len);

#ifdef __cplusplus
}
#endif
#endif
#endif
