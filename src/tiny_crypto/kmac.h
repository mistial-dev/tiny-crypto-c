/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* KMAC256 with a caller-chosen output length and customization string.
 * Standards: SP 800-185 section 4.
 * Configuration: TC_ENABLE_KMAC256.
 * Limitations: fixed-output KMAC256 only.
 * Contracts: docs/api.md. */
#ifndef TINY_CRYPTO_KMAC_H_
#define TINY_CRYPTO_KMAC_H_

#include <tiny_crypto/common.h>

#if TC_ENABLE_KMAC256
/* KMAC256 state (SP 800-185 section 4). Initialize through TC_KMAC256_init.
 * Members are private to the implementation: state is the Keccak-f[1600]
 * lane array, position is the next byte within the 136-byte rate, and active
 * is 1 between a successful init and final or clear. */
struct TC_KMAC256_ctx {
  uint64_t state[25];
  uint8_t position;
  uint8_t active;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Inputs are borrowed TC_bytes spans. A span may have NULL data only when it
 * is empty. Key and customization lengths are in bytes, at most UINT64_MAX / 8.
 * Either may be empty. Use a strong key in real protocols.
 *
 * init returns TC_ERROR for a NULL ctx, an invalid span, an oversized length
 * or a span that overlaps ctx, and leaves ctx unchanged in each case. */
TC_status TC_KMAC256_init(struct TC_KMAC256_ctx* ctx, TC_bytes key, TC_bytes custom);
/* Absorb data into an active context. data must be disjoint from ctx.
 * Returns TC_ERROR for a NULL or inactive ctx, an invalid span or an overlap.
 * Rejected calls leave ctx unchanged. */
TC_status TC_KMAC256_update(struct TC_KMAC256_ctx* ctx, TC_bytes data);
/* Write out.capacity bytes of output. The requested length L is part of the
 * KMAC computation (SP 800-185 section 4.3), so changing it changes every
 * output byte. A successful final wipes the context. Call init again before
 * reuse. Returns TC_ERROR for a NULL or inactive ctx, NULL out.data, a zero
 * or oversized capacity, or output that overlaps ctx. On error, neither ctx
 * nor out changes. */
TC_status TC_KMAC256_final(struct TC_KMAC256_ctx* ctx, TC_buffer out);
/* Wipe the context, including its key-dependent state. NULL is accepted. */
void TC_KMAC256_ctx_clear(struct TC_KMAC256_ctx* ctx);
/* One-shot KMAC256(key, data, out.capacity * 8, custom). Returns TC_ERROR for
 * an invalid span, an empty output or an oversized length, and leaves out
 * unchanged. Output may overlap inputs because all input is read before any
 * output is written. The internal context is wiped before return. */
TC_status TC_KMAC256_digest(TC_bytes key, TC_bytes data, TC_bytes custom, TC_buffer out);

#ifdef __cplusplus
}
#endif
#endif
#endif
