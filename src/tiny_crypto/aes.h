/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TINY_CRYPTO_AES_H_
#define TINY_CRYPTO_AES_H_

#include <tiny_crypto/common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Mode selection (define to 1/0 before including this header, or via -D).
 * Default build enables CTR only. CBC, ECB, OFB, CCM, EAX, EAX_PRIME, GCM,
 * SIV, and CMAC are opt-in so a build contains code and context fields only for
 * the modes it enables.
 */

#if TC_AES_GCM_GHASH_MODE == TC_AES_GCM_GHASH_MODE_HARDWARE
/* Platform hook required by the hardware GHASH profile. */
void TC_AES_GCM_hardware_multiply(uint8_t result[16], const uint8_t left[16],
                                  const uint8_t right[16]);
#endif

/* Modes that keep an IV in TC_AES_ctx. */
#define TC_AES_HAVE_IV (TC_AES_ENABLE_CBC || TC_AES_ENABLE_CTR || TC_AES_ENABLE_OFB)

#define TC_AES_BLOCKLEN 16 /* AES block length in bytes (128-bit block only). */

#if TC_AES_KEY_BITS == 256
#define TC_AES_KEYLEN 32
#define TC_AES_KEY_EXP_SIZE 240
#elif TC_AES_KEY_BITS == 192
#define TC_AES_KEYLEN 24
#define TC_AES_KEY_EXP_SIZE 208
#else
#define TC_AES_KEYLEN 16
#define TC_AES_KEY_EXP_SIZE 176
#endif

struct TC_AES_key_ctx {
  uint8_t round_key[TC_AES_KEY_EXP_SIZE];
  uint8_t active;
};

struct TC_AES_ctx {
  struct TC_AES_key_ctx key;
#if TC_AES_HAVE_IV
  uint8_t iv[TC_AES_BLOCKLEN];
#if TC_AES_ENABLE_CTR
  uint8_t ctr_stream[TC_AES_BLOCKLEN];
  uint8_t ctr_pos;
  uint8_t ctr_exhausted; /* The counter wrapped; set a new IV to continue. */
#endif
#if TC_AES_ENABLE_OFB
  uint8_t ofb_pos;
#endif
#endif
};

TC_status TC_AES_key_init(struct TC_AES_key_ctx* ctx, const uint8_t* key);
void TC_AES_key_ctx_clear(struct TC_AES_key_ctx* ctx);

/* Wipe an AES context, including mode-specific streaming state. */
void TC_AES_ctx_clear(struct TC_AES_ctx* ctx);

/* Initialize an expanded key schedule. Both pointers must be non-NULL. */
TC_status TC_AES_init_ctx(struct TC_AES_ctx* ctx, const uint8_t* key);
#if TC_AES_CAVP
/* Test-only single-block hooks used by the AESAVS harness. They return
 * TC_ERROR, leaving block unchanged, when the key cannot be scheduled. */
TC_status TC_AES_CAVP_encrypt_block(const uint8_t* key, uint8_t block[TC_AES_BLOCKLEN]);
TC_status TC_AES_CAVP_decrypt_block(const uint8_t* key, uint8_t block[TC_AES_BLOCKLEN]);
#endif
#if TC_AES_SBOX_MODE == TC_AES_SBOX_MODE_RUNTIME
/* Must be called once before TC_AES_init_ctx(), TC_AES_init_ctx_iv(), or encryption. */
void TC_AES_init_sbox(void);
#endif
#if TC_AES_HAVE_IV
TC_status TC_AES_init_ctx_iv(struct TC_AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
/* Load a new 16-byte IV and reset the CTR and OFB stream state. Returns
 * TC_ERROR, leaving ctx unchanged, for a NULL argument, an uninitialized
 * context or an IV that overlaps ctx. */
TC_status TC_AES_ctx_set_iv(struct TC_AES_ctx* ctx, const uint8_t* iv);
#endif

/*
 * The CBC, CTR, OFB and ECB functions below transform buf in place and share
 * one failure rule. They return TC_ERROR, leaving buf and ctx unchanged, for
 * an uninitialized context, a NULL buf with a nonzero length, or a buf that
 * overlaps ctx. A block cipher failure part way through wipes buf and clears
 * ctx, so neither partial output nor a broken chaining value survives. ECB
 * takes a const key schedule, so its failure wipes buf only.
 */

#if TC_AES_ENABLE_ECB
/* buf is exactly TC_AES_BLOCKLEN bytes. ECB is insecure for most uses. */
TC_status TC_AES_ECB_encrypt(const struct TC_AES_key_ctx* ctx, uint8_t* buf);
TC_status TC_AES_ECB_decrypt(const struct TC_AES_key_ctx* ctx, uint8_t* buf);
#endif

#if TC_AES_ENABLE_CBC
/*
 * length must be a multiple of TC_AES_BLOCKLEN. The caller applies padding.
 * An unaligned length is an argument error. Set the IV via TC_AES_init_ctx_iv()
 * or TC_AES_ctx_set_iv(). Never reuse an IV with the same key.
 */
TC_status TC_AES_CBC_encrypt(struct TC_AES_ctx* ctx, uint8_t* buf, size_t length);
TC_status TC_AES_CBC_decrypt(struct TC_AES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_AES_ENABLE_CTR
/*
 * Encrypt and decrypt are the same operation (SP 800-38A section 6.5). The IV
 * is incremented for every block, and one IV covers at most 2^128 blocks
 * across all calls. Returns TC_ERROR, leaving buf and IV unchanged, when the
 * request would need a block beyond that space. Once the counter wraps,
 * further calls fail until TC_AES_ctx_set_iv or TC_AES_init_ctx_iv supplies a
 * new IV. Never reuse an IV with the same key.
 */
TC_status TC_AES_CTR_crypt(struct TC_AES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_AES_ENABLE_OFB
/*
 * Encrypt and decrypt are the same operation. Never reuse an IV with the same
 * key. OFB provides confidentiality only.
 */
TC_status TC_AES_OFB_crypt(struct TC_AES_ctx* ctx, uint8_t* buf, size_t length);
#endif

/*
 * One-shot AEAD contract (GCM, CCM, EAX, EAX', SIV). docs/api.md has the
 * full description.
 * - Encrypt writes plaintext.length bytes to ciphertext and tag.capacity tag
 *   bytes to tag. Decrypt writes ciphertext.length bytes to plaintext and
 *   checks tag.length tag bytes. The tag length is fixed for the key.
 *   EAX' and SIV take fixed-size tag arrays.
 * - CCM and EAX default entry points take tags of at least TC_MIN_TAG_LEN
 *   bytes (config.h, default 8). Their _short_tag forms take only the
 *   shorter lengths, for protocols that bound failed verifications
 *   (SP 800-38B Appendix A.2). GCM short tags follow SP 800-38D Appendix C.
 * - The text output capacity must be at least the text input length.
 * - Text input and output are exact aliases or fully disjoint. The tag is
 *   disjoint from the text output. SIV associated data is disjoint from the
 *   text output. A violation returns TC_ERROR before a write.
 * - The key, and the nonce and AAD of GCM, CCM, EAX and EAX', may share
 *   storage with the text output. Each is read in full before the first
 *   output write.
 * - The caller keeps the key, nonce, AAD, text input and received tag stable
 *   for the duration of the call. GCM, CCM, EAX and EAX' decrypt read the
 *   ciphertext twice, once to authenticate it and once to decrypt it.
 * - TC_ERROR before any write: NULL key, NULL tag, NULL text or AAD with a
 *   nonzero length, short text output, a forbidden overlap, a nonce or tag
 *   length outside the mode's range, or a length above the mode's limit.
 * - GCM, CCM, EAX and EAX' decrypt authenticate before writing plaintext.
 *   SIV decrypt writes candidate plaintext and then recomputes the synthetic
 *   IV over the AD and that plaintext (RFC 5297 section 2.7).
 * - After the argument checks, every failure wipes input.length bytes of the
 *   text output: TC_MISMATCH for a tag that fails to verify and TC_ERROR for
 *   a cipher backend failure. In-place callers lose the input. The tag output
 *   is written only on success.
 */

#if TC_AES_ENABLE_GCM

/*
 * NIST SP 800-38D length limits (bit lengths converted to bytes):
 *   1 <= len(IV) <= 2^64-1 bits
 *   len(P) <= 2^39-256 bits  =>  TC_AES_GCM_MAX_PLAINTEXT_BYTES
 *   len(A) <= 2^64-1 bits
 * Tag length t (bits) is one of 128,120,112,104,96,64,32 and is fixed for the
 * key for the life of this context (passed at init).
 *
 * Appendix C short-tag packet limits (most permissive table row):
 *   t=32: |C|+|A| <= 2^10 bytes per packet
 *   t=64: |C|+|A| <= 2^25 bytes per packet
 * Key lifetime / max decryption invocations remain the application's duty.
 */
#define TC_AES_GCM_MAX_PLAINTEXT_BYTES ((((uint64_t)1) << 36) - 32u)
#define TC_AES_GCM_MAX_AAD_BYTES (UINT64_MAX / 8u)
#define TC_AES_GCM_MAX_IV_BYTES (UINT64_MAX / 8u)
#define TC_AES_GCM_SHORT_TAG4_MAX_PACKET ((uint64_t)1 << 10) /* 1024 */
#define TC_AES_GCM_SHORT_TAG8_MAX_PACKET ((uint64_t)1 << 25) /* 33554432 */

struct TC_AES_GCM_ctx {
  struct TC_AES_key_ctx key;
  uint8_t H[TC_AES_BLOCKLEN];
  uint8_t J0[TC_AES_BLOCKLEN];
  uint8_t counter[TC_AES_BLOCKLEN];
  uint8_t stream[TC_AES_BLOCKLEN];
  uint8_t S[TC_AES_BLOCKLEN];
  uint8_t ghash[TC_AES_BLOCKLEN];
#if TC_AES_GCM_GHASH_MODE == TC_AES_GCM_GHASH_MODE_FAST_TABLE
  uint8_t ghash_table[16][TC_AES_BLOCKLEN];
#endif

  uint64_t aad_len;
  uint64_t text_len;
  uint8_t stream_pos;
  uint8_t ghash_len;
  uint8_t tag_len; /* fixed for this key/context (SP 800-38D §5.2.1.2) */
  uint8_t phase;
};

/*
 * Streaming GCM encryption. Decryption is one-shot only (TC_AES_GCM_decrypt)
 * so the tag is verified before any plaintext is released.
 *
 * Initialize GCM with a 12–16-byte tag. The explicit short-tag initializer
 * accepts 4 or 8 bytes under the SP 800-38D Appendix C packet limits.
 * Tag length is fixed for this context. IV may be any supported
 * non-zero byte length. 12 bytes (96 bits) is the recommended fast path.
 */
TC_status TC_AES_GCM_init(struct TC_AES_GCM_ctx* ctx, const uint8_t* key, TC_bytes iv,
                          size_t tag_len);
TC_status TC_AES_GCM_init_short_tag(struct TC_AES_GCM_ctx* ctx, const uint8_t* key, TC_bytes iv,
                                    size_t tag_len);

/* AAD must be supplied before the first encrypt update. Check every return
 * value. encrypt_update encrypts buf in place. Buffers must be disjoint from
 * the context. Argument errors and exceeded length limits return TC_ERROR and
 * leave buf and the context unchanged. A cipher backend failure wipes buf,
 * clears the context and returns TC_ERROR. */
TC_status TC_AES_GCM_aad_update(struct TC_AES_GCM_ctx* ctx, const uint8_t* aad, size_t length);
TC_status TC_AES_GCM_encrypt_update(struct TC_AES_GCM_ctx* ctx, uint8_t* buf, size_t length);

/* Tag buffer must hold ctx->tag_len bytes (set at init). Finish consumes the
 * context and wipes it on success and on failure. Argument errors leave it
 * unchanged. */
TC_status TC_AES_GCM_encrypt_finish(struct TC_AES_GCM_ctx* ctx, uint8_t* tag);

/* One-shot GCM (SP 800-38D). Follows the one-shot AEAD contract above. */
TC_status TC_AES_GCM_encrypt(const uint8_t* key, TC_bytes iv, TC_bytes aad, TC_bytes plaintext,
                             TC_buffer ciphertext, TC_buffer tag);
TC_status TC_AES_GCM_decrypt(const uint8_t* key, TC_bytes iv, TC_bytes aad, TC_bytes ciphertext,
                             TC_bytes tag, TC_buffer plaintext);
TC_status TC_AES_GCM_encrypt_short_tag(const uint8_t* key, TC_bytes iv, TC_bytes aad,
                                       TC_bytes plaintext, TC_buffer ciphertext, TC_buffer tag);
TC_status TC_AES_GCM_decrypt_short_tag(const uint8_t* key, TC_bytes iv, TC_bytes aad,
                                       TC_bytes ciphertext, TC_bytes tag, TC_buffer plaintext);

/* Clear expanded key material and intermediate authentication state. */
void TC_AES_GCM_clear(struct TC_AES_GCM_ctx* ctx);

#endif /* TC_AES_ENABLE_GCM */

#if TC_AES_ENABLE_CCM

/* CCM (SP 800-38C) is a packet mode. Payload and AAD lengths are known at
 * entry. Follows the one-shot AEAD contract above. The nonce is 7..13 bytes.
 * CCM tags have an even length of 4..16 bytes. The default entry points take
 * those of at least TC_MIN_TAG_LEN (8, 10, 12, 14 or 16 by default). The
 * _short_tag forms take those below it (4 or 6 by default). Any other tag
 * length returns TC_ERROR. The payload length must fit the 15 - nonce length
 * byte length field. */
TC_status TC_AES_CCM_encrypt(const uint8_t* key, TC_bytes nonce, TC_bytes aad, TC_bytes plaintext,
                             TC_buffer ciphertext, TC_buffer tag);
TC_status TC_AES_CCM_decrypt(const uint8_t* key, TC_bytes nonce, TC_bytes aad, TC_bytes ciphertext,
                             TC_bytes tag, TC_buffer plaintext);
TC_status TC_AES_CCM_encrypt_short_tag(const uint8_t* key, TC_bytes nonce, TC_bytes aad,
                                       TC_bytes plaintext, TC_buffer ciphertext, TC_buffer tag);
TC_status TC_AES_CCM_decrypt_short_tag(const uint8_t* key, TC_bytes nonce, TC_bytes aad,
                                       TC_bytes ciphertext, TC_bytes tag, TC_buffer plaintext);

#endif

#if TC_AES_ENABLE_EAX

/* EAX one-shot AEAD. Follows the one-shot AEAD contract above. The tag is
 * the leading bytes of the 16-byte EAX tag. The default entry points take
 * TC_MIN_TAG_LEN..16 bytes. The _short_tag forms take 1..TC_MIN_TAG_LEN - 1
 * bytes. Other tag lengths, including 0, return TC_ERROR. The nonce may have
 * any length. */
TC_status TC_AES_EAX_encrypt(const uint8_t* key, TC_bytes nonce, TC_bytes aad, TC_bytes plaintext,
                             TC_buffer ciphertext, TC_buffer tag);
TC_status TC_AES_EAX_decrypt(const uint8_t* key, TC_bytes nonce, TC_bytes aad, TC_bytes ciphertext,
                             TC_bytes tag, TC_buffer plaintext);
TC_status TC_AES_EAX_encrypt_short_tag(const uint8_t* key, TC_bytes nonce, TC_bytes aad,
                                       TC_bytes plaintext, TC_buffer ciphertext, TC_buffer tag);
TC_status TC_AES_EAX_decrypt_short_tag(const uint8_t* key, TC_bytes nonce, TC_bytes aad,
                                       TC_bytes ciphertext, TC_bytes tag, TC_buffer plaintext);

#endif

#if TC_AES_ENABLE_EAX_PRIME

#define TC_AES_EAX_PRIME_TAG_LEN 4

/* ANSI C12.22 EAX'. Follows the one-shot AEAD contract above. The protocol
 * fixes the tag at four bytes, so EAX' is exempt from TC_MIN_TAG_LEN and has
 * no _short_tag form. The cleartext header is authenticated and serves as
 * the nonce. */
TC_status TC_AES_EAX_PRIME_encrypt(const uint8_t* key, TC_bytes cleartext, TC_bytes plaintext,
                                   TC_buffer ciphertext, uint8_t tag[TC_AES_EAX_PRIME_TAG_LEN]);
TC_status TC_AES_EAX_PRIME_decrypt(const uint8_t* key, TC_bytes cleartext, TC_bytes ciphertext,
                                   const uint8_t tag[TC_AES_EAX_PRIME_TAG_LEN],
                                   TC_buffer plaintext);

#endif

#if TC_AES_ENABLE_CMAC

/* Full CMAC tag is one AES block. Shorter tags are the leading tag_len bytes. */
#define TC_AES_CMAC_TAG_MAX TC_AES_BLOCKLEN

/*
 * AES-CMAC (NIST SP 800-38B). One-shot.
 * tag_len must be in TC_MIN_TAG_LEN..TC_AES_CMAC_TAG_MAX. Truncation keeps the
 * most significant octets of the full T (SP 800-38B section 6.2).
 * msg may be NULL when msg_len is 0. The context and full tag on the stack
 * are wiped before return.
 * @return TC_OK, or TC_ERROR for a NULL key or tag, a NULL msg with a nonzero
 *         length, a tag length outside the range, or a cipher failure. An
 *         argument error leaves tag unchanged.
 */
TC_status TC_AES_CMAC(const uint8_t* key, const uint8_t* msg, size_t msg_len, uint8_t* tag,
                      size_t tag_len);

/* Constant-time verify of a (possibly truncated) tag of tag_len bytes, with
 * the same length range as TC_AES_CMAC.
 * @return TC_OK when the tag matches, TC_MISMATCH when it differs, or
 *         TC_ERROR as for TC_AES_CMAC. */
TC_status TC_AES_CMAC_verify(const uint8_t* key, const uint8_t* msg, size_t msg_len,
                             const uint8_t* tag, size_t tag_len);

/* Short-tag AES-CMAC and verify. tag_len must be in 1..TC_MIN_TAG_LEN - 1.
 * Use them only when the protocol fixes the short tag and limits failed
 * verifications for the key (SP 800-38B Appendix A.2). Status values follow
 * TC_AES_CMAC and TC_AES_CMAC_verify. */
TC_status TC_AES_CMAC_short_tag(const uint8_t* key, const uint8_t* msg, size_t msg_len,
                                uint8_t* tag, size_t tag_len);
TC_status TC_AES_CMAC_verify_short_tag(const uint8_t* key, const uint8_t* msg, size_t msg_len,
                                       const uint8_t* tag, size_t tag_len);

/*
 * Streaming AES-CMAC. The most recent block is held back in buf so that
 * *_final can apply K1 (complete) or K2 (padded) to the true last block.
 * *_final always emits the full TC_AES_CMAC_TAG_MAX bytes. Callers may truncate
 * the tag. Argument errors leave the context unchanged. Otherwise *_final
 * wipes it, on success and on failure.
 * Call *_init again before reuse.
 */
struct TC_AES_CMAC_ctx {
  struct TC_AES_key_ctx key;
  uint8_t k1[TC_AES_BLOCKLEN];
  uint8_t k2[TC_AES_BLOCKLEN];
  uint8_t mac[TC_AES_BLOCKLEN];
  uint8_t buf[TC_AES_BLOCKLEN];
  uint8_t buf_len;
  uint8_t active;
};

/* The key must be disjoint from the whole context. Overlap returns TC_ERROR
 * and leaves the context cleared. Update data and the final tag must also be
 * disjoint from it. Overlap there is an argument error. */
TC_status TC_AES_CMAC_init(struct TC_AES_CMAC_ctx* ctx, const uint8_t* key);
TC_status TC_AES_CMAC_update(struct TC_AES_CMAC_ctx* ctx, const uint8_t* data, size_t len);
TC_status TC_AES_CMAC_final(struct TC_AES_CMAC_ctx* ctx, uint8_t tag[TC_AES_CMAC_TAG_MAX]);
void TC_AES_CMAC_ctx_clear(struct TC_AES_CMAC_ctx* ctx);

#endif

#if TC_AES_ENABLE_SIV

/* RFC 5297 SIV-AES: key is two equal AES keys concatenated (CMAC || CTR). */
#define TC_AES_SIV_KEYLEN (TC_AES_KEYLEN * 2)
#define TC_AES_SIV_V_LEN TC_AES_BLOCKLEN
/* RFC §7: at most 126 associated-data components (plaintext is the last S2V input). */
#define TC_AES_SIV_MAX_AD 126u

/*
 * One-shot SIV (RFC 5297). Follows the one-shot AEAD contract above.
 * Associated data is a vector of 0..TC_AES_SIV_MAX_AD spans (empty components
 * are valid). Every AD span must be disjoint from the text output, because
 * decrypt runs S2V over the AD after writing candidate plaintext. Ciphertext
 * length equals plaintext length. v may alias plaintext when ciphertext is
 * distinct. Any overlap between v and the text output returns TC_ERROR.
 * Decrypt writes candidate plaintext, then verifies. A mismatch returns
 * TC_MISMATCH and wipes the output.
 */
TC_status TC_AES_SIV_encrypt(const uint8_t* key, const TC_bytes* ad, size_t ad_count,
                             TC_bytes plaintext, uint8_t v[TC_AES_SIV_V_LEN], TC_buffer ciphertext);
TC_status TC_AES_SIV_decrypt(const uint8_t* key, const TC_bytes* ad, size_t ad_count,
                             const uint8_t v[TC_AES_SIV_V_LEN], TC_bytes ciphertext,
                             TC_buffer plaintext);

#endif

#ifdef __cplusplus
}
#endif

#endif /* TINY_CRYPTO_AES_H_ */
