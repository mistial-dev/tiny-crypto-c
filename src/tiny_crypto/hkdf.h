/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_HKDF_H_
#define TINY_CRYPTO_HKDF_H_

#include <tiny_crypto/common.h>

#if TC_ENABLE_HKDF
#include <tiny_crypto/hash.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 5869 HKDF over each enabled HMAC-SHA family. Extract writes exactly
 * TC_SHA*_DIGESTLEN bytes to prk. Expand accepts a PRK at least that long.
 * output_len must be 1..255*HashLen. Derive performs both steps and clears
 * its intermediate PRK. A NULL salt, IKM or info is valid when its length is
 * zero. Hybrid functions process Z followed by T without copying either.
 * Output must be disjoint from every input. Invalid arguments leave output
 * unchanged. A processing failure clears it. All lengths are bytes. */
#define TC_HKDF_DECLARE(N)                                                                         \
  TC_status TC_HKDF_SHA##N##_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm,     \
                                     size_t ikm_len, uint8_t* prk);                                \
  TC_status TC_HKDF_SHA##N##_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info,       \
                                    size_t info_len, uint8_t* output, size_t output_len);          \
  TC_status TC_HKDF_SHA##N##_derive(const uint8_t* salt, size_t salt_len, const uint8_t* ikm,      \
                                    size_t ikm_len, const uint8_t* info, size_t info_len,          \
                                    uint8_t* output, size_t output_len);                           \
  TC_status TC_HKDF_SHA##N##_extract_hybrid(const uint8_t* salt, size_t salt_len,                  \
                                            const uint8_t* z, size_t z_len, const uint8_t* t,      \
                                            size_t t_len, uint8_t* prk);                           \
  TC_status TC_HKDF_SHA##N##_derive_hybrid(                                                        \
      const uint8_t* salt, size_t salt_len, const uint8_t* z, size_t z_len, const uint8_t* t,      \
      size_t t_len, const uint8_t* info, size_t info_len, uint8_t* output, size_t output_len)

#if TC_ENABLE_SHA1
TC_HKDF_DECLARE(1);
#endif
#if TC_ENABLE_SHA224
TC_HKDF_DECLARE(224);
#endif
#if TC_ENABLE_SHA256
TC_HKDF_DECLARE(256);
#endif
#if TC_ENABLE_SHA384
TC_HKDF_DECLARE(384);
#endif
#if TC_ENABLE_SHA512
TC_HKDF_DECLARE(512);
#endif

#undef TC_HKDF_DECLARE

#ifdef __cplusplus
}
#endif
#endif /* TC_ENABLE_HKDF */
#endif /* TINY_CRYPTO_HKDF_H_ */
