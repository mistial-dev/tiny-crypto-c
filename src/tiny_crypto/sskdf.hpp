/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_SSKDF_HPP_
#define TINY_CRYPTO_SSKDF_HPP_
#include <tiny_crypto/common.hpp>
#include <tiny_crypto/sskdf.h>

namespace tiny_crypto {
#if TC_ENABLE_SHA256
TC_CPP_NODISCARD inline TC_status sskdf_sha256(bytes z, const bytes* info, size_t count,
                                               buffer output) noexcept
{
  return ::TC_SSKDF_SHA256(z, info, count, output);
}
#endif
#if TC_ENABLE_SHA384
TC_CPP_NODISCARD inline TC_status sskdf_sha384(bytes z, const bytes* info, size_t count,
                                               buffer output) noexcept
{
  return ::TC_SSKDF_SHA384(z, info, count, output);
}
#endif
} // namespace tiny_crypto
#endif
