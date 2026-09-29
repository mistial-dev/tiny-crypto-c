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

#define TC_DES3_KEYLEN_2KEY                                                                        \
  16 /**< 2-Key Triple DES key length in bytes (128 bits total, 112 bits effective) */
#define TC_DES3_KEYLEN_3KEY                                                                        \
  24 /**< 3-Key Triple DES key length in bytes (192 bits total, 168 bits effective) */

/* Three DES schedules in encrypt, decrypt, encrypt order. */
typedef struct TC_DES_key_bundle {
  uint8_t schedule[48][6];
} TC_DES_key_bundle;

/**
 * @brief Single DES Context Structure
 */
struct TC_DES_ctx {
  uint8_t Sk[16][6];
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
};

#if TC_DES_ENABLE_TDES
/**
 * @brief Triple DES (3DES / TDES) Context Structure
 */
struct TC_DES3_ctx {
  TC_DES_key_bundle keys;
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
};
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Wipe a DES context (subkeys and IV when present). */
void TC_DES_ctx_clear(struct TC_DES_ctx* ctx);

#if TC_DES_ENABLE_TDES
/* Wipe a Triple DES context (subkeys and IV when present). */
void TC_DES3_ctx_clear(struct TC_DES3_ctx* ctx);
#endif

/*
 * The CBC, CTR, CFB and OFB entry points share one argument contract. They
 * return TC_ERROR for a NULL or uninitialized context, or a NULL buffer with
 * a nonzero length, and leave the context and buffer unchanged. A NULL buffer
 * with length 0 returns TC_OK.
 */

/* --- Single DES API --- */

/**
 * @brief Initialize a Single DES context with key.
 * @param ctx Pointer to Single DES context structure.
 * @param key Pointer to 8-byte key buffer.
 * @note Key parity is ignored. Weak and semi-weak keys are rejected when
 *       TC_DES_REJECT_WEAK_KEYS=1 (default: 0 for compatibility).
 */
TC_status TC_DES_init_ctx(struct TC_DES_ctx* ctx, const uint8_t* key);

#if TC_DES_NEEDS_IV
/**
 * @brief Initialize a Single DES context with key and IV.
 * @param ctx Pointer to Single DES context structure.
 * @param key Pointer to 8-byte key buffer.
 * @param iv Pointer to 8-byte Initialization Vector.
 */
TC_status TC_DES_init_ctx_iv(struct TC_DES_ctx* ctx, const uint8_t* key, const uint8_t* iv);

/**
 * @brief Set or update the Initialization Vector (IV) in Single DES context.
 * @param ctx Pointer to Single DES context structure.
 * @param iv Pointer to 8-byte Initialization Vector.
 */
TC_status TC_DES_ctx_set_iv(struct TC_DES_ctx* ctx, const uint8_t* iv);
#endif

#if TC_DES_ENABLE_ECB
/**
 * @brief Encrypt an 8-byte block in ECB mode using Single DES.
 * @param ctx Pointer to initialized Single DES context.
 * @param buf Pointer to 8-byte data block (encrypted in-place).
 */
TC_status TC_DES_ECB_encrypt(const struct TC_DES_ctx* ctx, uint8_t* buf);

/**
 * @brief Decrypt an 8-byte block in ECB mode using Single DES.
 * @param ctx Pointer to initialized Single DES context.
 * @param buf Pointer to 8-byte data block (decrypted in-place).
 */
TC_status TC_DES_ECB_decrypt(const struct TC_DES_ctx* ctx, uint8_t* buf);
#endif

#if TC_DES_ENABLE_CBC
/**
 * @brief Encrypt buffer in CBC mode using Single DES.
 * @param ctx Pointer to initialized Single DES context.
 * @param buf Data buffer (length must be a multiple of 8 bytes). Encrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 * @return TC_OK, or TC_ERROR if length is not block-aligned.
 */
TC_status TC_DES_CBC_encrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt buffer in CBC mode using Single DES.
 * @param ctx Pointer to initialized Single DES context.
 * @param buf Data buffer (length must be a multiple of 8 bytes). Decrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 * @return TC_OK, or TC_ERROR if length is not block-aligned.
 */
TC_status TC_DES_CBC_decrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_DES_ENABLE_CTR
/**
 * @brief Encrypt/Decrypt buffer in Counter (CTR) stream mode using Single DES.
 * @param ctx Pointer to initialized Single DES context.
 * @param buf Data buffer (arbitrary length). Transformed in-place.
 * @param length Data length in bytes.
 * @return TC_OK, or TC_ERROR if the request would need a block beyond the
 *         2^64-block space of one IV (buffer and IV left unchanged). After the
 *         counter wraps, calls fail until a new IV is set.
 */
TC_status TC_DES_CTR_crypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_DES_ENABLE_CFB64
/**
 * @brief Encrypt buffer in 64-bit Cipher Feedback (CFB64) mode using Single DES.
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Data buffer (arbitrary length, final segment may be shorter than 8).
 * @param length Data length in bytes.
 * @return TC_OK, or TC_ERROR for an inactive context or a NULL buffer with
 *         nonzero length. The context is unchanged on error.
 */
TC_status TC_DES_CFB64_encrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt buffer in 64-bit Cipher Feedback (CFB64) mode using Single DES.
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Data buffer (arbitrary length, final segment may be shorter than 8).
 * @param length Data length in bytes.
 * @return TC_OK, or TC_ERROR for an inactive context or a NULL buffer with
 *         nonzero length. The context is unchanged on error.
 */
TC_status TC_DES_CFB64_decrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_DES_ENABLE_CFB8
/**
 * @brief Encrypt buffer in 8-bit Cipher Feedback (CFB8) mode using Single DES.
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Data buffer (arbitrary length). Encrypted in-place.
 * @param length Data length in bytes.
 */
TC_status TC_DES_CFB8_encrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt buffer in 8-bit Cipher Feedback (CFB8) mode using Single DES.
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Data buffer (arbitrary length). Decrypted in-place.
 * @param length Data length in bytes.
 */
TC_status TC_DES_CFB8_decrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_DES_ENABLE_CFB1
/**
 * @brief Encrypt bits in 1-bit Cipher Feedback (CFB1) mode using Single DES.
 *
 * Bits are packed MSB-first: bit i of the stream is (buf[i/8] >> (7 - i%8)) & 1.
 * Trailing pad bits of the final byte are left unchanged.
 *
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Packed bit buffer. Encrypted in-place.
 * @param bit_length Data length in bits.
 */
TC_status TC_DES_CFB1_encrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t bit_length);

/**
 * @brief Decrypt bits in 1-bit Cipher Feedback (CFB1) mode using Single DES.
 *
 * Bits are packed MSB-first: bit i of the stream is (buf[i/8] >> (7 - i%8)) & 1.
 * Trailing pad bits of the final byte are left unchanged.
 *
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Packed bit buffer. Decrypted in-place.
 * @param bit_length Data length in bits.
 */
TC_status TC_DES_CFB1_decrypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t bit_length);
#endif

#if TC_DES_ENABLE_OFB
/**
 * @brief Encrypt/Decrypt buffer in Output Feedback (OFB) stream mode using Single DES.
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Data buffer (arbitrary length). Transformed in-place.
 * @param length Data length in bytes.
 */
TC_status TC_DES_OFB_crypt(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

/* --- Triple DES (3DES / TDES) API --- */
#if TC_DES_ENABLE_TDES

/**
 * @brief Initialize a Triple DES (3DES) context with key.
 * @param ctx Pointer to 3DES context structure.
 * @param key Pointer to key buffer (16 bytes for 2-Key 3DES, 24 bytes for 3-Key 3DES).
 * @param keylen Key length in bytes (16 or 24).
 * @note Weak component keys and bundles that collapse to single DES are
 *       rejected when TC_DES_REJECT_WEAK_KEYS=1. K1=K3 remains valid 2-key
 *       TDEA. The default is 0 for compatibility with legacy vectors.
 * @return TC_OK on success, TC_ERROR if keylen is not 16 or 24.
 */
TC_status TC_DES3_init_ctx(struct TC_DES3_ctx* ctx, const uint8_t* key, size_t keylen);

#if TC_DES_NEEDS_IV
/**
 * @brief Initialize a Triple DES (3DES) context with key and IV.
 * @param ctx Pointer to 3DES context structure.
 * @param key Pointer to key buffer (16 or 24 bytes).
 * @param keylen Key length in bytes (16 or 24).
 * @param iv Pointer to 8-byte Initialization Vector.
 * @return TC_OK on success, TC_ERROR if keylen is not 16 or 24.
 */
TC_status TC_DES3_init_ctx_iv(struct TC_DES3_ctx* ctx, const uint8_t* key, size_t keylen,
                              const uint8_t* iv);

/**
 * @brief Set or update the Initialization Vector (IV) in 3DES context.
 * @param ctx Pointer to 3DES context structure.
 * @param iv Pointer to 8-byte Initialization Vector.
 * @return TC_OK on success, or TC_ERROR for a NULL argument.
 */
TC_status TC_DES3_ctx_set_iv(struct TC_DES3_ctx* ctx, const uint8_t* iv);
#endif

#if TC_DES_ENABLE_ECB
/**
 * @brief Encrypt an 8-byte block in ECB mode using 3DES.
 * @param ctx Pointer to initialized 3DES context.
 * @param buf Pointer to 8-byte data block (encrypted in-place).
 */
TC_status TC_DES3_ECB_encrypt(const struct TC_DES3_ctx* ctx, uint8_t* buf);

/**
 * @brief Decrypt an 8-byte block in ECB mode using 3DES.
 * @param ctx Pointer to initialized 3DES context.
 * @param buf Pointer to 8-byte data block (decrypted in-place).
 */
TC_status TC_DES3_ECB_decrypt(const struct TC_DES3_ctx* ctx, uint8_t* buf);
#endif

#if TC_DES_ENABLE_CBC
/**
 * @brief Encrypt buffer in CBC mode using 3DES.
 * @param ctx Pointer to initialized 3DES context.
 * @param buf Data buffer (length must be a multiple of 8 bytes). Encrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
TC_status TC_DES3_CBC_encrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt buffer in CBC mode using 3DES.
 * @param ctx Pointer to initialized 3DES context.
 * @param buf Data buffer (length must be a multiple of 8 bytes). Decrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
TC_status TC_DES3_CBC_decrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_DES_ENABLE_CTR
/**
 * @brief Encrypt/Decrypt buffer in Counter (CTR) stream mode using 3DES.
 * @param ctx Pointer to initialized 3DES context.
 * @param buf Data buffer (arbitrary length). Transformed in-place.
 * @param length Data length in bytes.
 * @return TC_OK, or TC_ERROR if the request would need a block beyond the
 *         2^64-block space of one IV (buffer and IV left unchanged). After the
 *         counter wraps, calls fail until a new IV is set.
 */
TC_status TC_DES3_CTR_crypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_DES_ENABLE_CFB64
/**
 * @brief Encrypt buffer in 64-bit Cipher Feedback (CFB64) mode using 3DES.
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Data buffer (length must be a multiple of 8 bytes). Encrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
TC_status TC_DES3_CFB64_encrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt buffer in 64-bit Cipher Feedback (CFB64) mode using 3DES.
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Data buffer (length must be a multiple of 8 bytes). Decrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
TC_status TC_DES3_CFB64_decrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_DES_ENABLE_CFB8
/**
 * @brief Encrypt buffer in 8-bit Cipher Feedback (CFB8) mode using 3DES.
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Data buffer (arbitrary length). Encrypted in-place.
 * @param length Data length in bytes.
 */
TC_status TC_DES3_CFB8_encrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt buffer in 8-bit Cipher Feedback (CFB8) mode using 3DES.
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Data buffer (arbitrary length). Decrypted in-place.
 * @param length Data length in bytes.
 */
TC_status TC_DES3_CFB8_decrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if TC_DES_ENABLE_CFB1
/**
 * @brief Encrypt bits in 1-bit Cipher Feedback (CFB1) mode using 3DES.
 *
 * Bits are packed MSB-first: bit i of the stream is (buf[i/8] >> (7 - i%8)) & 1.
 * Trailing pad bits of the final byte are left unchanged.
 *
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Packed bit buffer. Encrypted in-place.
 * @param bit_length Data length in bits.
 */
TC_status TC_DES3_CFB1_encrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t bit_length);

/**
 * @brief Decrypt bits in 1-bit Cipher Feedback (CFB1) mode using 3DES.
 *
 * Bits are packed MSB-first: bit i of the stream is (buf[i/8] >> (7 - i%8)) & 1.
 * Trailing pad bits of the final byte are left unchanged.
 *
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Packed bit buffer. Decrypted in-place.
 * @param bit_length Data length in bits.
 */
TC_status TC_DES3_CFB1_decrypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t bit_length);
#endif

#if TC_DES_ENABLE_OFB
/**
 * @brief Encrypt/Decrypt buffer in Output Feedback (OFB) stream mode using 3DES.
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Data buffer (arbitrary length). Transformed in-place.
 * @param length Data length in bytes.
 */
TC_status TC_DES3_OFB_crypt(struct TC_DES3_ctx* ctx, uint8_t* buf, size_t length);
#endif

#endif /* #if TC_DES_ENABLE_TDES */

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

/* keylen must be 8, 16 (K1,K2,K1) or 24. */
TC_status TC_DES_CMAC_init(struct TC_DES_CMAC_ctx* ctx, const uint8_t* key, size_t keylen);
TC_status TC_DES_CMAC_update(struct TC_DES_CMAC_ctx* ctx, const uint8_t* data, size_t len);
TC_status TC_DES_CMAC_final(struct TC_DES_CMAC_ctx* ctx, uint8_t tag[TC_DES_CMAC_TAG_MAX]);
void TC_DES_CMAC_ctx_clear(struct TC_DES_CMAC_ctx* ctx);

#endif /* TC_DES_ENABLE_CMAC */

#if TC_DES_ENABLE_ISO9797
/* ISO/IEC 9797-1 MAC algorithm 1 (CBC-MAC) or 3 (retail MAC).
 * Algorithm 1 uses 2/3-key TDEA. Algorithm 3 uses two DES keys.
 * CBC iteration uses K1 and the output transform uses D(K2), E(K1).
 * Padding 1 adds zero bytes only to a partial block. Padding 2 always adds
 * 0x80 followed by zeroes. NONE requires block alignment and a nonempty
 * message. Padding 1 on an empty message processes one zero block.
 * The caller must authenticate a fixed or separately authenticated length
 * when using NONE or padding 1. Context is caller-owned and final consumes it.
 * Input, key, and tag buffers must not overlap the context. A failed final
 * leaves the tag untouched. An update with invalid arguments leaves the
 * context unchanged. An update that fails while processing wipes it.
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
  uint8_t keylen;
  uint8_t algorithm;
  uint8_t padding;
  uint8_t active;
  uint8_t nonempty;
};

TC_status TC_DES_ISO9797_init(struct TC_DES_ISO9797_ctx* ctx, TC_DES_ISO9797_algorithm algorithm,
                              TC_DES_ISO9797_padding padding, const uint8_t* key, size_t keylen);
TC_status TC_DES_ISO9797_update(struct TC_DES_ISO9797_ctx* ctx, const uint8_t* msg, size_t msg_len);
TC_status TC_DES_ISO9797_final(struct TC_DES_ISO9797_ctx* ctx, uint8_t tag[TC_DES_BLOCKLEN]);
void TC_DES_ISO9797_clear(struct TC_DES_ISO9797_ctx* ctx);
TC_status TC_DES_ISO9797_MAC(TC_DES_ISO9797_algorithm algorithm, TC_DES_ISO9797_padding padding,
                             const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msg_len,
                             uint8_t* tag, size_t tag_len);
/* The default one-shot API requires the full 8-byte MAC. MAC leaves tag
 * untouched on error. Verify returns TC_MISMATCH for a bad tag. */
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

/* Explicit three-key retail-MAC extension: DES-CBC under K1, then
 * D(K2) and E(K3). Use the standard Algorithm 3 API for two-key MACs. */
TC_status TC_DES_RETAIL3_init(struct TC_DES_ISO9797_ctx* ctx, TC_DES_ISO9797_padding padding,
                              const uint8_t key[24]);
TC_status TC_DES_RETAIL3_MAC(TC_DES_ISO9797_padding padding, const uint8_t key[24],
                             const uint8_t* msg, size_t msg_len, uint8_t* tag, size_t tag_len);
TC_status TC_DES_RETAIL3_verify(TC_DES_ISO9797_padding padding, const uint8_t key[24],
                                const uint8_t* msg, size_t msg_len, const uint8_t* tag,
                                size_t tag_len);
#endif /* TC_DES_ENABLE_ISO9797 */

#ifdef __cplusplus
}
#endif

#endif /* TINY_CRYPTO_DES_H_ */
