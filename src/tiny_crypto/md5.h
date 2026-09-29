/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* MD5 for legacy download checksums.
 * Standards: RFC 1321.
 * Configuration: TC_ENABLE_MD5.
 * Limitations: MD5 has broken collision resistance. Establish authenticity
 * through trusted transport or provisioning.
 * Contracts: docs/api.md. Guide: docs/md5.md. */
#ifndef TINY_CRYPTO_MD5_H_
#define TINY_CRYPTO_MD5_H_
#include <tiny_crypto/common.h>

#if TC_ENABLE_MD5
#ifdef __cplusplus
extern "C" {
#endif

#define TC_MD5_DIGESTLEN 16
#define TC_MD5_BLOCKLEN 64

/* Legacy download checksums (RFC 1321). MD5 has broken collision resistance.
 * Establish download authenticity through trusted transport or provisioning.
 * count is the number of bytes absorbed, buf holds the partial block and
 * buf_len is its fill level. */
struct TC_MD5_ctx {
  uint64_t count;
  uint32_t state[4];
  uint8_t buf_len;
  uint8_t active;
  uint8_t buf[TC_MD5_BLOCKLEN];
};

/* MD5 follows the SHA status contract in hash.h. Initialize before use and
 * before reusing a finalized context. update takes a span whose data may be
 * NULL only when it is empty. Context storage must be disjoint from input and
 * digest buffers. One-shot input and digest may overlap. Failed argument
 * checks preserve context and output. final and ctx_clear wipe the context. */
TC_status TC_MD5_init(struct TC_MD5_ctx* ctx);
TC_status TC_MD5_update(struct TC_MD5_ctx* ctx, TC_bytes data);
TC_status TC_MD5_final(struct TC_MD5_ctx* ctx, uint8_t digest[TC_MD5_DIGESTLEN]);
TC_status TC_MD5_digest(TC_bytes data, uint8_t digest[TC_MD5_DIGESTLEN]);
void TC_MD5_ctx_clear(struct TC_MD5_ctx* ctx);

#ifdef __cplusplus
}
#endif
#endif /* TC_ENABLE_MD5 */
#endif
