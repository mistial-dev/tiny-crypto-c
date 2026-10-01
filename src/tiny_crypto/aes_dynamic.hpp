/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* AES_dynamic and AES_dynamic_CMAC classes for aes_dynamic.h.
 * Contracts, statuses and lifetimes follow the C header. Conventions:
 * docs/cpp.md. Library-wide contracts: docs/api.md. */
#ifndef TINY_CRYPTO_AES_DYNAMIC_HPP_
#define TINY_CRYPTO_AES_DYNAMIC_HPP_

#ifndef __cplusplus
#error Do not include aes_dynamic.hpp in a C project, include aes_dynamic.h instead
#endif

#include <tiny_crypto/common.hpp>
#include <tiny_crypto/aes_dynamic.h>
#if TC_ENABLE_AES && TC_AES_ENABLE_DYNAMIC

namespace tiny_crypto {

/* AES with a key length chosen at init: 16, 24 or 32 bytes. The key is a
 * borrowed span disjoint from the object. A failed init leaves the object
 * unkeyed. The destructor clears the key schedule. */
class AES_dynamic {
  TC_AES_dynamic_key ctx_;

public:
  AES_dynamic() noexcept : ctx_{}
  {}
  ~AES_dynamic() noexcept
  {
    clear();
  }
  AES_dynamic(const AES_dynamic&) = delete;
  AES_dynamic& operator=(const AES_dynamic&) = delete;
  TC_CPP_NODISCARD TC_status init(bytes key) noexcept
  {
    return ::TC_AES_dynamic_key_init(&ctx_, key.data, key.length);
  }
  template <size_t N> TC_CPP_NODISCARD TC_status init(const uint8_t (&key)[N]) noexcept
  {
    return init(bytes{key, N});
  }
  void clear() noexcept
  {
    ::TC_AES_dynamic_key_clear(&ctx_);
  }
  TC_CPP_NODISCARD TC_status encrypt(uint8_t (&block)[16]) const noexcept
  {
    return ::TC_AES_dynamic_encrypt(&ctx_, block);
  }
  TC_CPP_NODISCARD TC_status decrypt(uint8_t (&block)[16]) const noexcept
  {
    return ::TC_AES_dynamic_decrypt(&ctx_, block);
  }
  TC_CPP_NODISCARD TC_status cbc_encrypt(uint8_t (&iv)[16], uint8_t* buffer,
                                         size_t length) const noexcept
  {
    return ::TC_AES_dynamic_CBC_encrypt(&ctx_, iv, buffer, length);
  }
  TC_CPP_NODISCARD TC_status cbc_decrypt(uint8_t (&iv)[16], uint8_t* buffer,
                                         size_t length) const noexcept
  {
    return ::TC_AES_dynamic_CBC_decrypt(&ctx_, iv, buffer, length);
  }
};

/* Streaming AES-CMAC with a key length chosen at init. final writes the full
 * 16-byte tag and consumes the key. A failed init, a final and clear leave the
 * object unkeyed. The destructor clears the context. */
class AES_dynamic_CMAC {
  TC_AES_dynamic_CMAC ctx_;

public:
  AES_dynamic_CMAC() noexcept : ctx_{}
  {}
  ~AES_dynamic_CMAC() noexcept
  {
    clear();
  }
  AES_dynamic_CMAC(const AES_dynamic_CMAC&) = delete;
  AES_dynamic_CMAC& operator=(const AES_dynamic_CMAC&) = delete;
  TC_CPP_NODISCARD TC_status init(bytes key) noexcept
  {
    return ::TC_AES_dynamic_CMAC_init(&ctx_, key.data, key.length);
  }
  template <size_t N> TC_CPP_NODISCARD TC_status init(const uint8_t (&key)[N]) noexcept
  {
    return init(bytes{key, N});
  }
  TC_CPP_NODISCARD TC_status update(bytes data) noexcept
  {
    return ::TC_AES_dynamic_CMAC_update(&ctx_, data.data, data.length);
  }
  template <size_t N> TC_CPP_NODISCARD TC_status update(const uint8_t (&data)[N]) noexcept
  {
    return update(bytes{data, N});
  }
  TC_CPP_NODISCARD TC_status final(uint8_t (&tag)[16]) noexcept
  {
    return ::TC_AES_dynamic_CMAC_final(&ctx_, tag);
  }
  void clear() noexcept
  {
    ::TC_AES_dynamic_CMAC_clear(&ctx_);
  }
};
} // namespace tiny_crypto
#endif
#endif
