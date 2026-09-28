/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_HKDF_HPP_
#define TINY_CRYPTO_HKDF_HPP_

#ifndef __cplusplus
#error Do not include hkdf.hpp in a C project, include hkdf.h instead
#endif

#include <tiny_crypto/hkdf.h>

namespace tiny_crypto {

#if TC_ENABLE_HKDF
#define TINY_CRYPTO_HKDF_FAMILY(N)                                                                 \
  inline TC_status hkdf_sha##N##_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, \
                                         size_t ikm_len, uint8_t* prk)                             \
  {                                                                                                \
    return TC_HKDF_SHA##N##_extract(salt, salt_len, ikm, ikm_len, prk);                            \
  }                                                                                                \
  inline TC_status hkdf_sha##N##_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info,   \
                                        size_t info_len, uint8_t* output, size_t output_len)       \
  {                                                                                                \
    return TC_HKDF_SHA##N##_expand(prk, prk_len, info, info_len, output, output_len);              \
  }                                                                                                \
  inline TC_status hkdf_sha##N##_derive(const uint8_t* salt, size_t salt_len, const uint8_t* ikm,  \
                                        size_t ikm_len, const uint8_t* info, size_t info_len,      \
                                        uint8_t* output, size_t output_len)                        \
  {                                                                                                \
    return TC_HKDF_SHA##N##_derive(salt, salt_len, ikm, ikm_len, info, info_len, output,           \
                                   output_len);                                                    \
  }                                                                                                \
  inline TC_status hkdf_sha##N##_extract_hybrid(const uint8_t* salt, size_t salt_len,              \
                                                const uint8_t* z, size_t z_len, const uint8_t* t,  \
                                                size_t t_len, uint8_t* prk)                        \
  {                                                                                                \
    return TC_HKDF_SHA##N##_extract_hybrid(salt, salt_len, z, z_len, t, t_len, prk);               \
  }                                                                                                \
  inline TC_status hkdf_sha##N##_derive_hybrid(                                                    \
      const uint8_t* salt, size_t salt_len, const uint8_t* z, size_t z_len, const uint8_t* t,      \
      size_t t_len, const uint8_t* info, size_t info_len, uint8_t* output, size_t output_len)      \
  {                                                                                                \
    return TC_HKDF_SHA##N##_derive_hybrid(salt, salt_len, z, z_len, t, t_len, info, info_len,      \
                                          output, output_len);                                     \
  }

#if TC_ENABLE_SHA1
TINY_CRYPTO_HKDF_FAMILY(1)
#endif
#if TC_ENABLE_SHA224
TINY_CRYPTO_HKDF_FAMILY(224)
#endif
#if TC_ENABLE_SHA256
TINY_CRYPTO_HKDF_FAMILY(256)
#endif
#if TC_ENABLE_SHA384
TINY_CRYPTO_HKDF_FAMILY(384)
#endif
#if TC_ENABLE_SHA512
TINY_CRYPTO_HKDF_FAMILY(512)
#endif

#undef TINY_CRYPTO_HKDF_FAMILY
#endif /* TC_ENABLE_HKDF */

} // namespace tiny_crypto

#endif /* TINY_CRYPTO_HKDF_HPP_ */
