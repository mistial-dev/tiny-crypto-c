/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* GZIPDecoder for gzip.h.
 * Contracts, statuses and lifetimes follow the C header. Conventions:
 * docs/cpp.md. Library-wide contracts: docs/api.md. */
#ifndef TINY_CRYPTO_GZIP_HPP_
#define TINY_CRYPTO_GZIP_HPP_

#ifndef __cplusplus
#error Do not include gzip.hpp in a C project, include gzip.h instead
#endif

#include <tiny_crypto/common.hpp>
#include <tiny_crypto/gzip.h>

namespace tiny_crypto {
/* Owns reusable scratch. Input and output remain caller-owned. */
class GZIPDecoder {
public:
  GZIPDecoder() noexcept : workspace_()
  {}
  GZIPDecoder(const GZIPDecoder&) = delete;
  GZIPDecoder& operator=(const GZIPDecoder&) = delete;

  TC_CPP_NODISCARD TC_GZIP_result decode(TC_bytes input, size_t& work, TC_buffer output,
                                         size_t& output_length) noexcept
  {
    return TC_GZIP_decode(input, &workspace_, &work, output, &output_length);
  }

  template <size_t InputSize, size_t OutputSize>
  TC_CPP_NODISCARD TC_GZIP_result decode(const uint8_t (&input)[InputSize], size_t& work,
                                         uint8_t (&output)[OutputSize],
                                         size_t& output_length) noexcept
  {
    return decode(TC_bytes{input, InputSize}, work, TC_buffer{output, OutputSize}, output_length);
  }

private:
  TC_GZIP_workspace workspace_;
};
} // namespace tiny_crypto
#endif
