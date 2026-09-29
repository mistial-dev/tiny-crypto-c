/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_DES_HPP_
#define TINY_CRYPTO_DES_HPP_

#ifndef __cplusplus
#error Do not include des.hpp in a C project, include des.h instead
#endif

#include <tiny_crypto/common.hpp>
#include <tiny_crypto/des.h>

namespace tiny_crypto {

/* DES or TDEA cipher. init selects single DES for an 8-byte key and TDEA for a
 * 16- or 24-byte bundle when TC_DES_ENABLE_TDES is set. A failed init leaves
 * the object unkeyed, and later cipher calls return TC_ERROR. */
class DES {
public:
  DES() noexcept = default;
  ~DES() noexcept
  {
    TC_DES_ctx_clear(&ctx_);
  }
  DES(const DES&) = delete;
  DES& operator=(const DES&) = delete;

  TC_CPP_NODISCARD TC_status init(const uint8_t* key, size_t key_len) noexcept
  {
    return TC_DES_init_ctx(&ctx_, key, key_len);
  }
  template <size_t N> TC_CPP_NODISCARD TC_status init(const uint8_t (&key)[N]) noexcept
  {
    return init(key, N);
  }
#if TC_DES_NEEDS_IV
  TC_CPP_NODISCARD TC_status init(const uint8_t* key, size_t key_len, const uint8_t* iv,
                                  size_t iv_len) noexcept
  {
    if (iv_len != TC_DES_BLOCKLEN) {
      TC_DES_ctx_clear(&ctx_);
      return TC_ERROR;
    }
    return TC_DES_init_ctx_iv(&ctx_, key, key_len, iv);
  }
  TC_CPP_NODISCARD TC_status set_iv(const uint8_t* iv, size_t iv_len) noexcept
  {
    return iv_len == TC_DES_BLOCKLEN ? TC_DES_ctx_set_iv(&ctx_, iv) : TC_ERROR;
  }
#endif
#if TC_DES_ENABLE_ECB
  TC_CPP_NODISCARD TC_status encrypt_ecb(uint8_t* block) const noexcept
  {
    return TC_DES_ECB_encrypt(&ctx_, block);
  }
  TC_CPP_NODISCARD TC_status decrypt_ecb(uint8_t* block) const noexcept
  {
    return TC_DES_ECB_decrypt(&ctx_, block);
  }
#endif
#if TC_DES_ENABLE_CBC
  TC_CPP_NODISCARD TC_status encrypt_cbc(uint8_t* data, size_t n) noexcept
  {
    return TC_DES_CBC_encrypt(&ctx_, data, n);
  }
  TC_CPP_NODISCARD TC_status decrypt_cbc(uint8_t* data, size_t n) noexcept
  {
    return TC_DES_CBC_decrypt(&ctx_, data, n);
  }
#endif
#if TC_DES_ENABLE_CTR
  TC_CPP_NODISCARD TC_status xcrypt_ctr(uint8_t* data, size_t n) noexcept
  {
    return TC_DES_CTR_crypt(&ctx_, data, n);
  }
#endif
#if TC_DES_ENABLE_CFB64
  /* A call whose length is not a multiple of 8 ends the message. See des.h. */
  TC_CPP_NODISCARD TC_status encrypt_cfb64(uint8_t* data, size_t n) noexcept
  {
    return TC_DES_CFB64_encrypt(&ctx_, data, n);
  }
  TC_CPP_NODISCARD TC_status decrypt_cfb64(uint8_t* data, size_t n) noexcept
  {
    return TC_DES_CFB64_decrypt(&ctx_, data, n);
  }
#endif
#if TC_DES_ENABLE_CFB8
  TC_CPP_NODISCARD TC_status encrypt_cfb8(uint8_t* data, size_t n) noexcept
  {
    return TC_DES_CFB8_encrypt(&ctx_, data, n);
  }
  TC_CPP_NODISCARD TC_status decrypt_cfb8(uint8_t* data, size_t n) noexcept
  {
    return TC_DES_CFB8_decrypt(&ctx_, data, n);
  }
#endif
#if TC_DES_ENABLE_CFB1
  TC_CPP_NODISCARD TC_status encrypt_cfb1(uint8_t* data, size_t data_len, size_t bits) noexcept
  {
    return cfb1_fits(data_len, bits) ? TC_DES_CFB1_encrypt(&ctx_, data, bits) : TC_ERROR;
  }
  TC_CPP_NODISCARD TC_status decrypt_cfb1(uint8_t* data, size_t data_len, size_t bits) noexcept
  {
    return cfb1_fits(data_len, bits) ? TC_DES_CFB1_decrypt(&ctx_, data, bits) : TC_ERROR;
  }
  template <size_t N>
  TC_CPP_NODISCARD TC_status encrypt_cfb1(uint8_t (&data)[N], size_t bits) noexcept
  {
    return encrypt_cfb1(data, N, bits);
  }
  template <size_t N>
  TC_CPP_NODISCARD TC_status decrypt_cfb1(uint8_t (&data)[N], size_t bits) noexcept
  {
    return decrypt_cfb1(data, N, bits);
  }
#endif
#if TC_DES_ENABLE_OFB
  TC_CPP_NODISCARD TC_status xcrypt_ofb(uint8_t* data, size_t n) noexcept
  {
    return TC_DES_OFB_crypt(&ctx_, data, n);
  }
#endif
  void clear() noexcept
  {
    TC_DES_ctx_clear(&ctx_);
  }
  const TC_DES_ctx& get_c_ctx() const noexcept
  {
    return ctx_;
  }

private:
#if TC_DES_ENABLE_CFB1
  /* bits must fit in data_len bytes. */
  static bool cfb1_fits(size_t data_len, size_t bits) noexcept
  {
    return bits / 8u < data_len || (bits / 8u == data_len && bits % 8u == 0);
  }
#endif
  TC_DES_ctx ctx_{};
};

#if TC_DES_ENABLE_CMAC
TC_CPP_NODISCARD inline TC_status des_cmac(const uint8_t* key, size_t key_len,
                                           const uint8_t* message, size_t message_len, uint8_t* tag,
                                           size_t tag_len) noexcept
{
  return TC_DES_CMAC(key, key_len, message, message_len, tag, tag_len);
}
#endif

} /* namespace tiny_crypto */

#endif /* TINY_CRYPTO_DES_HPP_ */
