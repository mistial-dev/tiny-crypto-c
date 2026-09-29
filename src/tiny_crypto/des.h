/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TINY_CRYPTO_DES_H_
#define TINY_CRYPTO_DES_H_

#include <tiny_crypto/common.h>

/**
 * @file des.h
 * @brief Portable C implementation of DES and Triple-DES (3DES / TDEA).
 */

/*
 * Mode selection (define to 1/0 before including this header, or via -D).
 * Default build enables CTR and Triple-DES only. ECB, CBC, CFB*, OFB, and
 * CMAC are opt-in so a build contains code and context fields only for the
 * modes it enables.
 * Only TC_DES_ENABLE_* names are used so this header can co-exist with aes.h.
 */

/* Modes that keep chaining state in ctx->Iv */
#if (TC_DES_ENABLE_CBC == 1) || (TC_DES_ENABLE_CTR == 1) || (TC_DES_ENABLE_CFB1 == 1) ||           \
    (TC_DES_ENABLE_CFB8 == 1) || (TC_DES_ENABLE_CFB64 == 1) || (TC_DES_ENABLE_OFB == 1)
#define TC_DES_NEEDS_IV 1
#else
#define TC_DES_NEEDS_IV 0
#endif

#define TC_DES_BLOCKLEN 8 /**< Block length in bytes - DES is a 64-bit (8 bytes) block cipher */
#define TC_DES_KEYLEN 8   /**< Single DES key length in bytes (64 bits total, 56 bits effective) */
/** Two-key TDEA bundle K1 || K2 in bytes. K3 is K1 (112 bits effective). */
#define TC_DES_KEYLEN_2KEY 16
/** Three-key TDEA bundle K1 || K2 || K3 in bytes (168 bits effective). */
#define TC_DES_KEYLEN_3KEY 24

/* Three DES schedules in encrypt, decrypt, encrypt order. */
typedef struct TC_DES_key_bundle {
  uint8_t schedule[48][6];
} TC_DES_key_bundle;

/* Round subkeys held by TC_DES_ctx: one schedule for single DES, three for
 * TDEA when TC_DES_ENABLE_TDES is set. */
#if TC_DES_ENABLE_TDES
#define TC_DES_CTX_SUBKEYS 48
#else
#define TC_DES_CTX_SUBKEYS 16
#endif

/**
 * @brief DES and TDEA context.
 *
 * TC_DES_init_ctx selects the cipher from the key length: 8 bytes for single
 * DES, or 16 and 24 bytes for two- and three-key TDEA when TC_DES_ENABLE_TDES
 * is set. TDEA encrypts as E(K1), D(K2), E(K3). The context is caller-owned.
 * Fields are private. Clear it with TC_DES_ctx_clear when its lifetime ends.
 */
struct TC_DES_ctx {
  uint8_t schedule[TC_DES_CTX_SUBKEYS][6];
  uint8_t triple; /* 1 when schedule holds a K1, K2, K3 TDEA bundle. */
  uint8_t active;
#if TC_DES_NEEDS_IV
  uint8_t Iv[TC_DES_BLOCKLEN];
#endif
#if TC_DES_ENABLE_CTR
  uint8_t ctr_stream[TC_DES_BLOCKLEN];
  uint8_t ctr_pos;
  uint8_t ctr_exhausted; /* The counter wrapped; set a new IV to continue. */
#endif
#if TC_DES_ENABLE_OFB
  uint8_t ofb_pos;
#endif
#if TC_DES_ENABLE_CFB64
  uint8_t cfb64_finished; /* A short segment ended the message; set a new IV. */
#endif
};

#ifdef __cplusplus
extern "C" {
#endif

/* Wipe a DES context (subkeys and IV when present). NULL is a no-op. */
void TC_DES_ctx_clear(struct TC_DES_ctx* ctx);

/*
 * The CBC, CTR, CFB and OFB entry points share one argument contract. They
 * return TC_ERROR for a NULL or uninitialized context, or a NULL buffer with
 * a nonzero length, and leave the context and buffer unchanged. A NULL buffer
 * with length 0 returns TC_OK. Every mode transforms buf in place, and buf
 * must not overlap the context.
 */

/**
 * @brief Initialize a DES or TDEA context with a key.
 * @param ctx Caller-owned context.
 * @param key Key bytes. They must not overlap ctx.
 * @param keylen TC_DES_KEYLEN, or TC_DES_KEYLEN_2KEY or TC_DES_KEYLEN_3KEY
 *        when TC_DES_ENABLE_TDES is set.
 * @return TC_OK, or TC_ERROR. A NULL ctx is left alone. Every other failure
 *         wipes ctx, so a previous key is unusable after a failed re-init.
 * @note Key parity is ignored. With TC_DES_REJECT_WEAK_KEYS=1 (default 0 for
 *       legacy vectors) weak and semi-weak component keys and TDEA bundles
 *       with K1 = K2 or K2 = K3 are rejected, because those collapse to single
 *       DES. K1 = K3 remains valid two-key TDEA.
 */
TC_status TC_DES_init_ctx(struct TC_DES_ctx* ctx, const uint8_t* key, size_t keylen);

#if TC_DES_NEEDS_IV
/**
 * @brief Initialize a DES or TDEA context with a key and IV.
 * @param ctx Caller-owned context.
 * @param key Key bytes, as for TC_DES_init_ctx.
 * @param keylen Key length, as for TC_DES_init_ctx.
 * @param iv 8-byte initialization vector. It must not overlap ctx.
 * @return TC_OK, or TC_ERROR with the failure behavior of TC_DES_init_ctx.
 */
TC_status TC_DES_init_ctx_iv(struct TC_DES_ctx* ctx, const uint8_t* key, size_t keylen,
                             const uint8_t* iv);

/**
 * @brief Start a new message under the same key.
 *
 * Resets the CTR and OFB stream positions, the CTR exhaustion flag and the
 * CFB64 finished flag.
 *
 * @param ctx Initialized context.
 * @param iv 8-byte initialization vector.
 * @return TC_OK, or TC_ERROR for a NULL argument or an inactive context.
 */
TC_status TC_DES_ctx_set_iv(struct TC_DES_ctx* ctx, const uint8_t* iv);
#endif

#if TC_DES_ENABLE_ECB
/**
 * @brief Encrypt one 8-byte block in ECB mode.
 * @param ctx Initialized context.
 * @param buf 8-byte block, encrypted in place.
 * @return TC_OK, or TC_ERROR for a NULL argument or an inactive context.
 */
TC_status TC_DES_ECB_encrypt(const struct TC_DES_ctx* ctx, uint8_t* buf);

/**
 * @brief Decrypt one 8-byte block in ECB mode.
 * @param ctx Initialized context.
 * @param buf 8-byte block, decrypted in place.
 * @return TC_OK, or TC_ERROR for a NULL argument or an inactive context.
 */
TC_status TC_DES_ECB_decrypt(const struct TC_DES_ctx* ctx, uint8_t* buf);
#endif

#if TC_DES_ENABLE_CBC
/**
 * @brief Encrypt a buffer in CBC mode. The IV carries the chaining value.
 * @param ctx Initialized context.
 * @param buf Data encrypted in place.
 * @param length Data length in bytes, a multiple of 8.
 * @return TC_OK, or TC_ERROR if length is not block-aligned (context and
 *         buffer unchanged).
 */
TC_status TC_DES_CBC_encrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt a buffer in CBC mode. The IV carries the chaining value.
 * @param ctx Initialized context.
 * @param buf Data decrypted in place.
 * @param length Data length in bytes, a multiple of 8.
 * @return TC_OK, or TC_ERROR if length is not block-aligned (context and
 *         buffer unchanged).
 */
TC_status TC_DES_CBC_decrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_DES_ENABLE_CTR
/**
 * @brief Encrypt or decrypt a buffer in CTR mode.
 * @param ctx Initialized context. The IV is the big-endian counter block.
 * @param buf Data of any length, transformed in place.
 * @param length Data length in bytes.
 * @return TC_OK, or TC_ERROR if the request would need a block beyond the
 *         2^64-block space of one IV (buffer and IV left unchanged). After the
 *         counter wraps, calls fail until a new IV is set.
 */
TC_status TC_DES_CTR_crypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_DES_ENABLE_CFB64
/*
 * CFB64 (NIST SP 800-38A section 6.3, s = 64) processes whole 8-byte
 * segments, as section 5.2 requires. As an extension, a call may end with one
 * short segment of 1..7 bytes. That segment shifts only its ciphertext bytes
 * into the feedback register and finishes the message. Later CFB64 calls
 * return TC_ERROR until TC_DES_ctx_set_iv or an init starts a new message.
 * Split a message at multiples of 8 bytes to get the same output as one call.
 */

/**
 * @brief Encrypt a buffer in CFB64 mode.
 * @param ctx Initialized context (IV holds the feedback register).
 * @param buf Data encrypted in place.
 * @param length Data length in bytes.
 * @return TC_OK, or TC_ERROR for an argument error or a finished message.
 *         The context and buffer are unchanged on error.
 */
TC_status TC_DES_CFB64_encrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt a buffer in CFB64 mode.
 * @param ctx Initialized context (IV holds the feedback register).
 * @param buf Data decrypted in place.
 * @param length Data length in bytes.
 * @return TC_OK, or TC_ERROR for an argument error or a finished message.
 *         The context and buffer are unchanged on error.
 */
TC_status TC_DES_CFB64_decrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_DES_ENABLE_CFB8
/**
 * @brief Encrypt a buffer in CFB8 mode.
 * @param ctx Initialized context (IV holds the feedback register).
 * @param buf Data of any length, encrypted in place.
 * @param length Data length in bytes.
 * @return TC_OK, or TC_ERROR for an argument error.
 */
TC_status TC_DES_CFB8_encrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt a buffer in CFB8 mode.
 * @param ctx Initialized context (IV holds the feedback register).
 * @param buf Data of any length, decrypted in place.
 * @param length Data length in bytes.
 * @return TC_OK, or TC_ERROR for an argument error.
 */
TC_status TC_DES_CFB8_decrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_DES_ENABLE_CFB1
/**
 * @brief Encrypt bits in CFB1 mode.
 *
 * Bits are packed MSB-first: bit i of the stream is (buf[i/8] >> (7 - i%8)) & 1.
 * Trailing pad bits of the final byte are left unchanged.
 *
 * @param ctx Initialized context (IV holds the feedback register).
 * @param buf Packed bit buffer of at least ceil(bit_length / 8) bytes.
 * @param bit_length Data length in bits.
 * @return TC_OK, or TC_ERROR for an argument error.
 */
TC_status TC_DES_CFB1_encrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t bit_length);

/**
 * @brief Decrypt bits in CFB1 mode, packed as for TC_DES_CFB1_encrypt.
 * @param ctx Initialized context (IV holds the feedback register).
 * @param buf Packed bit buffer of at least ceil(bit_length / 8) bytes.
 * @param bit_length Data length in bits.
 * @return TC_OK, or TC_ERROR for an argument error.
 */
TC_status TC_DES_CFB1_decrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t bit_length);
#endif

#if TC_DES_ENABLE_OFB
/**
 * @brief Encrypt or decrypt a buffer in OFB mode.
 * @param ctx Initialized context (IV holds the output feedback block).
 * @param buf Data of any length, transformed in place.
 * @param length Data length in bytes.
 * @return TC_OK, or TC_ERROR for an argument error.
 */
TC_status TC_DES_OFB_crypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

/* --- DES / 3DES CMAC (NIST SP 800-38B) --- */
#if TC_DES_ENABLE_CMAC

/* Full CMAC tag is one DES block. Shorter tags are the leading tag_len bytes. */
#define TC_DES_CMAC_TAG_MAX TC_DES_BLOCKLEN

/*
 * DES/3DES-CMAC (NIST SP 800-38B). One-shot.
 * keylen must be 8 (single DES), 16 (2-key TDEA), or 24 (3-key TDEA).
 * tag_len must be in TC_DES_CMAC_MIN_TAG_LEN..TC_DES_CMAC_TAG_MAX.
 * Empty message: msg may be NULL when msg_len is 0.
 * The key schedules and the full tag on the stack are wiped before return.
 */
TC_status TC_DES_CMAC(const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msg_len,
                      uint8_t* tag, size_t tag_len);

/* Constant-time verify of a (possibly truncated) tag. */
TC_status TC_DES_CMAC_verify(const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msg_len,
                             const uint8_t* tag, size_t tag_len);

/*
 * Streaming DES/3DES-CMAC. Holds its own key schedules so it works with the
 * ECB/CBC/TDES mode gates compiled out. The most recent block is held back in
 * buf so *_final can apply K1 (complete) or K2 (padded) to the true last
 * block. *_final always emits the full TC_DES_CMAC_TAG_MAX bytes. Argument
 * errors leave the context unchanged. Otherwise *_final wipes it, on success
 * and on failure. Call *_init again before reuse.
 */
struct TC_DES_CMAC_ctx {
  TC_DES_key_bundle keys;
  uint8_t k1[TC_DES_BLOCKLEN];
  uint8_t k2[TC_DES_BLOCKLEN];
  uint8_t mac[TC_DES_BLOCKLEN];
  uint8_t buf[TC_DES_BLOCKLEN];
  uint8_t buf_len;
  uint8_t triple;
  uint8_t active;
};

/* keylen must be TC_DES_KEYLEN, TC_DES_KEYLEN_2KEY (K1, K2, K1) or
 * TC_DES_KEYLEN_3KEY. */
TC_status TC_DES_CMAC_init(struct TC_DES_CMAC_ctx* ctx, const uint8_t* key, size_t keylen);
TC_status TC_DES_CMAC_update(struct TC_DES_CMAC_ctx* ctx, const uint8_t* data, size_t len);
TC_status TC_DES_CMAC_final(struct TC_DES_CMAC_ctx* ctx, uint8_t tag[TC_DES_CMAC_TAG_MAX]);
void TC_DES_CMAC_ctx_clear(struct TC_DES_CMAC_ctx* ctx);

#endif /* TC_DES_ENABLE_CMAC */

#if TC_DES_ENABLE_ISO9797
/*
 * ISO/IEC 9797-1:2011 MAC algorithm 1 (CBC-MAC) or 3 (retail MAC) over DES.
 *
 * Algorithm 1 runs CBC under a 16- or 24-byte TDEA bundle. ISO/IEC
 * 9797-1:2011 clause 5 restricts single DES to Algorithms 3 and 4.
 * Algorithm 3 (clause 7.4) runs CBC under single-DES K1 and applies Output
 * Transformation 3 (clause 6.7.4) as D(K2) then E(K1). A 24-byte key K1 || K2
 * || K3 selects the three-key retail extension, whose final encryption uses
 * K3. That extension is outside ISO/IEC 9797-1.
 *
 * Padding 1 adds zero bytes only to a partial block. Padding 2 always adds
 * 0x80 followed by zeroes. NONE requires block alignment and a nonempty
 * message. Padding 1 on an empty message processes one zero block. The caller
 * must authenticate a fixed or separately authenticated length when using
 * NONE or padding 1.
 *
 * With TC_DES_REJECT_WEAK_KEYS=1, init rejects weak and semi-weak component
 * keys and K1 = K2 or K2 = K3. Clause 7.4 requires independent K and K'.
 *
 * The context is caller-owned and final consumes it. Input, key, and tag
 * buffers must not overlap the context. A failed init wipes the context. A
 * failed final leaves the tag untouched and wipes the context. An update with
 * invalid arguments leaves the context unchanged. An update that fails while
 * processing wipes it.
 */
typedef enum TC_DES_ISO9797_algorithm {
  TC_DES_ISO9797_ALG1 = 1,
  TC_DES_ISO9797_ALG3 = 3
} TC_DES_ISO9797_algorithm;

typedef enum TC_DES_ISO9797_padding {
  TC_DES_ISO9797_PAD_NONE = 0,
  TC_DES_ISO9797_PAD1 = 1,
  TC_DES_ISO9797_PAD2 = 2
} TC_DES_ISO9797_padding;

struct TC_DES_ISO9797_ctx {
  TC_DES_key_bundle keys;
  uint8_t mac[TC_DES_BLOCKLEN];
  uint8_t buf[TC_DES_BLOCKLEN];
  uint8_t used;
  uint8_t algorithm;
  uint8_t padding;
  uint8_t active;
  uint8_t nonempty;
};

/* keylen is TC_DES_KEYLEN_2KEY or TC_DES_KEYLEN_3KEY for both algorithms.
 * Returns TC_ERROR for a NULL argument, an unknown algorithm or padding, or
 * another key length. */
TC_status TC_DES_ISO9797_init(struct TC_DES_ISO9797_ctx* ctx, TC_DES_ISO9797_algorithm algorithm,
                              TC_DES_ISO9797_padding padding, const uint8_t* key, size_t keylen);
/* msg may be NULL when msg_len is 0. */
TC_status TC_DES_ISO9797_update(struct TC_DES_ISO9797_ctx* ctx, const uint8_t* msg, size_t msg_len);
/* Writes the full MAC. Returns TC_ERROR for a NONE-padded message that is
 * empty or not block-aligned. */
TC_status TC_DES_ISO9797_final(struct TC_DES_ISO9797_ctx* ctx, uint8_t tag[TC_DES_BLOCKLEN]);
void TC_DES_ISO9797_clear(struct TC_DES_ISO9797_ctx* ctx);
/* The default one-shot API requires the full 8-byte MAC. MAC leaves tag
 * untouched on error. Verify returns TC_MISMATCH for a bad tag and TC_ERROR
 * for every argument or key error. */
TC_status TC_DES_ISO9797_MAC(TC_DES_ISO9797_algorithm algorithm, TC_DES_ISO9797_padding padding,
                             const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msg_len,
                             uint8_t* tag, size_t tag_len);
TC_status TC_DES_ISO9797_verify(TC_DES_ISO9797_algorithm algorithm, TC_DES_ISO9797_padding padding,
                                const uint8_t* key, size_t keylen, const uint8_t* msg,
                                size_t msg_len, const uint8_t* tag, size_t tag_len);
/* Explicit truncated-MAC API. Accepts the leading 4..7 bytes. */
TC_status TC_DES_ISO9797_MAC_short_tag(TC_DES_ISO9797_algorithm algorithm,
                                       TC_DES_ISO9797_padding padding, const uint8_t* key,
                                       size_t keylen, const uint8_t* msg, size_t msg_len,
                                       uint8_t* tag, size_t tag_len);
TC_status TC_DES_ISO9797_verify_short_tag(TC_DES_ISO9797_algorithm algorithm,
                                          TC_DES_ISO9797_padding padding, const uint8_t* key,
                                          size_t keylen, const uint8_t* msg, size_t msg_len,
                                          const uint8_t* tag, size_t tag_len);
#endif /* TC_DES_ENABLE_ISO9797 */

#ifdef __cplusplus
}
#endif

#endif /* TINY_CRYPTO_DES_H_ */
