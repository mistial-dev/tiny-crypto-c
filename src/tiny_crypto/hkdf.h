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

/* RFC 5869 HKDF over each enabled HMAC-SHA family.
 *
 * extract computes PRK = HMAC(salt, IKM) and writes exactly
 * TC_SHA*_DIGESTLEN bytes to prk. The input keying material is the
 * concatenation of ikm_count spans, read in order without copying; pass one
 * span for an ordinary secret, or Z and T for an SP 800-56C revision 2 hybrid
 * secret Z || T. An empty salt is the RFC's all-zero salt.
 *
 * expand accepts a PRK at least one digest long and writes exactly
 * output.capacity bytes, 1..255*HashLen. derive runs extract then expand and
 * wipes its PRK.
 *
 * A span may have NULL data only when it is empty. Output must be disjoint
 * from every input. Argument errors return TC_ERROR and leave output
 * unchanged. A failure after processing begins wipes output. */
#define TC_HKDF_DECLARE(N)                                                                         \
  TC_status TC_HKDF_SHA##N##_extract(TC_bytes salt, const TC_bytes* ikm, size_t ikm_count,         \
                                     uint8_t prk[TC_SHA##N##_DIGESTLEN]);                          \
  TC_status TC_HKDF_SHA##N##_expand(TC_bytes prk, TC_bytes info, TC_buffer output);                \
  TC_status TC_HKDF_SHA##N##_derive(TC_bytes salt, const TC_bytes* ikm, size_t ikm_count,          \
                                    TC_bytes info, TC_buffer output)

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
