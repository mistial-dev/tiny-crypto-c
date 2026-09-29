/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_AES_HPP_
#define TINY_CRYPTO_AES_HPP_

#ifndef __cplusplus
#error Do not include aes.hpp in a C project, include aes.h instead
#endif

#include <tiny_crypto/aes.h>
#include <tiny_crypto/common.hpp>

namespace tiny_crypto {

class AES {
public:
  AES() noexcept = default;
  ~AES() noexcept
  {
    TC_AES_ctx_clear(&ctx_);
  }
  AES(const AES&) = delete;
  AES& operator=(const AES&) = delete;

  TC_CPP_NODISCARD TC_status init(const uint8_t* key, size_t key_len) noexcept
  {
    if (key_len != TC_AES_KEYLEN) {
      TC_AES_ctx_clear(&ctx_);
      return TC_ERROR;
    }
    return TC_AES_init_ctx(&ctx_, key);
  }
  template <size_t N> TC_CPP_NODISCARD TC_status init(const uint8_t (&key)[N]) noexcept
  {
    return init(key, N);
  }

#if TC_AES_ENABLE_CBC || TC_AES_ENABLE_CTR || TC_AES_ENABLE_OFB
  TC_CPP_NODISCARD TC_status init(const uint8_t* key, size_t key_len, const uint8_t* iv,
                                  size_t iv_len) noexcept
  {
    if (key_len != TC_AES_KEYLEN || iv_len != TC_AES_BLOCKLEN) {
      TC_AES_ctx_clear(&ctx_);
      return TC_ERROR;
    }
    return TC_AES_init_ctx_iv(&ctx_, key, iv);
  }
  TC_CPP_NODISCARD TC_status set_iv(const uint8_t* iv, size_t iv_len) noexcept
  {
    return iv_len == TC_AES_BLOCKLEN ? TC_AES_ctx_set_iv(&ctx_, iv) : TC_ERROR;
  }
  template <size_t N> TC_CPP_NODISCARD TC_status set_iv(const uint8_t (&iv)[N]) noexcept
  {
    return set_iv(iv, N);
  }
#endif

#if TC_AES_ENABLE_ECB
  TC_CPP_NODISCARD TC_status encrypt_ecb(uint8_t* block) const noexcept
  {
    return TC_AES_ECB_encrypt(&ctx_.key, block);
  }
  TC_CPP_NODISCARD TC_status decrypt_ecb(uint8_t* block) const noexcept
  {
    return TC_AES_ECB_decrypt(&ctx_.key, block);
  }
#endif
#if TC_AES_ENABLE_CBC
  TC_CPP_NODISCARD TC_status encrypt_cbc(uint8_t* data, size_t length) noexcept
  {
    return TC_AES_CBC_encrypt(&ctx_, data, length);
  }
  TC_CPP_NODISCARD TC_status decrypt_cbc(uint8_t* data, size_t length) noexcept
  {
    return TC_AES_CBC_decrypt(&ctx_, data, length);
  }
  template <size_t N> TC_CPP_NODISCARD TC_status encrypt_cbc(uint8_t (&data)[N]) noexcept
  {
    return encrypt_cbc(data, N);
  }
  template <size_t N> TC_CPP_NODISCARD TC_status decrypt_cbc(uint8_t (&data)[N]) noexcept
  {
    return decrypt_cbc(data, N);
  }
#endif
#if TC_AES_ENABLE_CTR
  TC_CPP_NODISCARD TC_status xcrypt_ctr(uint8_t* data, size_t length) noexcept
  {
    return TC_AES_CTR_crypt(&ctx_, data, length);
  }
  template <size_t N> TC_CPP_NODISCARD TC_status xcrypt_ctr(uint8_t (&data)[N]) noexcept
  {
    return xcrypt_ctr(data, N);
  }
#endif
#if TC_AES_ENABLE_OFB
  TC_CPP_NODISCARD TC_status xcrypt_ofb(uint8_t* data, size_t length) noexcept
  {
    return TC_AES_OFB_crypt(&ctx_, data, length);
  }
  template <size_t N> TC_CPP_NODISCARD TC_status xcrypt_ofb(uint8_t (&data)[N]) noexcept
  {
    return xcrypt_ofb(data, N);
  }
#endif

  void clear() noexcept
  {
    TC_AES_ctx_clear(&ctx_);
  }
  const TC_AES_ctx& get_c_ctx() const noexcept
  {
    return ctx_;
  }

private:
  TC_AES_ctx ctx_{};
};

#if TC_AES_ENABLE_GCM
class GCM {
public:
  GCM() noexcept = default;
  ~GCM() noexcept
  {
    TC_AES_GCM_clear(&ctx_);
  }
  GCM(const GCM&) = delete;
  GCM& operator=(const GCM&) = delete;

  TC_CPP_NODISCARD TC_status init(const uint8_t* key, size_t key_len, bytes iv,
                                  size_t tag_len = TC_AES_BLOCKLEN) noexcept
  {
    if (key_len != TC_AES_KEYLEN) {
      TC_AES_GCM_clear(&ctx_);
      return TC_ERROR;
    }
    return TC_AES_GCM_init(&ctx_, key, iv, tag_len);
  }
  TC_CPP_NODISCARD TC_status init_short_tag(const uint8_t* key, size_t key_len, bytes iv,
                                            size_t tag_len) noexcept
  {
    if (key_len != TC_AES_KEYLEN) {
      TC_AES_GCM_clear(&ctx_);
      return TC_ERROR;
    }
    return TC_AES_GCM_init_short_tag(&ctx_, key, iv, tag_len);
  }
  TC_CPP_NODISCARD TC_status aad_update(const uint8_t* aad, size_t length) noexcept
  {
    return TC_AES_GCM_aad_update(&ctx_, aad, length);
  }
  TC_CPP_NODISCARD TC_status encrypt_update(uint8_t* data, size_t length) noexcept
  {
    return TC_AES_GCM_encrypt_update(&ctx_, data, length);
  }
  TC_CPP_NODISCARD TC_status decrypt_update(uint8_t* data, size_t length) noexcept
  {
    return TC_AES_GCM_decrypt_update(&ctx_, data, length);
  }
  TC_CPP_NODISCARD TC_status encrypt_finish(uint8_t* tag, size_t tag_len) noexcept
  {
    return tag_len == ctx_.tag_len ? TC_AES_GCM_encrypt_finish(&ctx_, tag) : TC_ERROR;
  }
  TC_CPP_NODISCARD TC_status decrypt_finish(const uint8_t* tag, size_t tag_len) noexcept
  {
    return tag_len == ctx_.tag_len ? TC_AES_GCM_decrypt_finish(&ctx_, tag) : TC_ERROR;
  }
  size_t tag_length() const noexcept
  {
    return ctx_.tag_len;
  }
  const TC_AES_GCM_ctx& get_c_ctx() const noexcept
  {
    return ctx_;
  }

private:
  TC_AES_GCM_ctx ctx_{};
};
#endif

#if TC_AES_ENABLE_CMAC
TC_CPP_NODISCARD inline TC_status aes_cmac(const uint8_t* key, size_t key_len,
                                           const uint8_t* message, size_t message_len, uint8_t* tag,
                                           size_t tag_len) noexcept
{
  return key_len == TC_AES_KEYLEN ? TC_AES_CMAC(key, message, message_len, tag, tag_len) : TC_ERROR;
}
#endif

/* The one-shot AEAD wrappers take a sized key and check its length before the
 * C call. A wrong length returns TC_ERROR and leaves every output unchanged.
 * CCM, EAX and EAX' take TC_AES_KEYLEN bytes. SIV takes TC_AES_SIV_KEYLEN. */
#if TC_AES_ENABLE_CCM
TC_CPP_NODISCARD inline TC_status ccm_encrypt(bytes key, bytes nonce, bytes aad, bytes plaintext,
                                              buffer ciphertext, buffer tag) noexcept
{
  if (key.length != TC_AES_KEYLEN)
    return TC_ERROR;
  return TC_AES_CCM_encrypt(key.data, nonce, aad, plaintext, ciphertext, tag);
}
TC_CPP_NODISCARD inline TC_status ccm_decrypt(bytes key, bytes nonce, bytes aad, bytes ciphertext,
                                              bytes tag, buffer plaintext) noexcept
{
  if (key.length != TC_AES_KEYLEN)
    return TC_ERROR;
  return TC_AES_CCM_decrypt(key.data, nonce, aad, ciphertext, tag, plaintext);
}
#endif

#if TC_AES_ENABLE_EAX
TC_CPP_NODISCARD inline TC_status eax_encrypt(bytes key, bytes nonce, bytes aad, bytes plaintext,
                                              buffer ciphertext, buffer tag) noexcept
{
  if (key.length != TC_AES_KEYLEN)
    return TC_ERROR;
  return TC_AES_EAX_encrypt(key.data, nonce, aad, plaintext, ciphertext, tag);
}
TC_CPP_NODISCARD inline TC_status eax_decrypt(bytes key, bytes nonce, bytes aad, bytes ciphertext,
                                              bytes tag, buffer plaintext) noexcept
{
  if (key.length != TC_AES_KEYLEN)
    return TC_ERROR;
  return TC_AES_EAX_decrypt(key.data, nonce, aad, ciphertext, tag, plaintext);
}
#endif

#if TC_AES_ENABLE_EAX_PRIME
TC_CPP_NODISCARD inline TC_status
eax_prime_encrypt(bytes key, bytes cleartext, bytes plaintext, buffer ciphertext,
                  uint8_t (&tag)[TC_AES_EAX_PRIME_TAG_LEN]) noexcept
{
  if (key.length != TC_AES_KEYLEN)
    return TC_ERROR;
  return TC_AES_EAX_PRIME_encrypt(key.data, cleartext, plaintext, ciphertext, tag);
}
TC_CPP_NODISCARD inline TC_status eax_prime_decrypt(bytes key, bytes cleartext, bytes ciphertext,
                                                    const uint8_t (&tag)[TC_AES_EAX_PRIME_TAG_LEN],
                                                    buffer plaintext) noexcept
{
  if (key.length != TC_AES_KEYLEN)
    return TC_ERROR;
  return TC_AES_EAX_PRIME_decrypt(key.data, cleartext, ciphertext, tag, plaintext);
}
#endif

#if TC_AES_ENABLE_SIV
TC_CPP_NODISCARD inline TC_status siv_encrypt(bytes key, const bytes* ad, size_t ad_count,
                                              bytes plaintext,
                                              uint8_t (&synthetic_iv)[TC_AES_SIV_V_LEN],
                                              buffer ciphertext) noexcept
{
  if (key.length != TC_AES_SIV_KEYLEN)
    return TC_ERROR;
  return TC_AES_SIV_encrypt(key.data, ad, ad_count, plaintext, synthetic_iv, ciphertext);
}
TC_CPP_NODISCARD inline TC_status siv_decrypt(bytes key, const bytes* ad, size_t ad_count,
                                              const uint8_t (&synthetic_iv)[TC_AES_SIV_V_LEN],
                                              bytes ciphertext, buffer plaintext) noexcept
{
  if (key.length != TC_AES_SIV_KEYLEN)
    return TC_ERROR;
  return TC_AES_SIV_decrypt(key.data, ad, ad_count, synthetic_iv, ciphertext, plaintext);
}
#endif

} /* namespace tiny_crypto */

#endif /* TINY_CRYPTO_AES_HPP_ */
