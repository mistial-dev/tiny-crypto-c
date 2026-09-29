/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_KMAC_HPP_
#define TINY_CRYPTO_KMAC_HPP_
#ifndef __cplusplus
#error "Use kmac.h in C projects"
#endif
#include <tiny_crypto/kmac.h>
#include <tiny_crypto/common.hpp>
#if TC_ENABLE_KMAC256
namespace tiny_crypto {
class KMAC256 {
  TC_KMAC256_ctx ctx_{};

public:
  KMAC256() noexcept = default;
  KMAC256(const KMAC256&) = delete;
  KMAC256& operator=(const KMAC256&) = delete;
  ~KMAC256() noexcept
  {
    clear();
  }
  /* The C functions in kmac.h document the span, length and failure rules. */
  TC_CPP_NODISCARD TC_status init(bytes key, bytes custom = bytes{nullptr, 0}) noexcept
  {
    return TC_KMAC256_init(&ctx_, key, custom);
  }
  TC_CPP_NODISCARD TC_status update(bytes data) noexcept
  {
    return TC_KMAC256_update(&ctx_, data);
  }
  TC_CPP_NODISCARD TC_status final(buffer out) noexcept
  {
    return TC_KMAC256_final(&ctx_, out);
  }
  void clear() noexcept
  {
    TC_KMAC256_ctx_clear(&ctx_);
  }
  TC_CPP_NODISCARD static TC_status digest(bytes key, bytes data, bytes custom, buffer out) noexcept
  {
    return TC_KMAC256_digest(key, data, custom, out);
  }
};
} // namespace tiny_crypto
#endif
#endif
