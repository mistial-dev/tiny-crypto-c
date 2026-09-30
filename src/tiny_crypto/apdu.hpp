/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* APDU encoding and response reading for apdu.h.
 * Contracts, statuses and lifetimes follow the C header. Conventions:
 * docs/cpp.md. Library-wide contracts: docs/api.md. */
#ifndef TINY_CRYPTO_APDU_HPP_
#define TINY_CRYPTO_APDU_HPP_

#ifndef __cplusplus
#error Do not include apdu.hpp in a C project, include apdu.h instead
#endif

#include <tiny_crypto/apdu.h>
#include <tiny_crypto/common.hpp>

namespace tiny_crypto {

typedef ::TC_APDU_result apdu_result;
typedef ::TC_APDU_length_format apdu_length_format;
typedef ::TC_APDU_status_class apdu_status_class;
typedef ::TC_APDU_command apdu_command;
typedef ::TC_APDU_response apdu_response;
typedef ::TC_APDU_transport apdu_transport;
typedef ::TC_APDU_channel_options apdu_channel_options;

/* TC_APDU_command_size. */
TC_CPP_NODISCARD inline apdu_result
apdu_command_size(const apdu_command& command, apdu_length_format format, size_t& size) noexcept
{
  return ::TC_APDU_command_size(&command, format, &size);
}

/* TC_APDU_command_encode into a buffer span. */
TC_CPP_NODISCARD inline apdu_result apdu_command_encode(const apdu_command& command,
                                                        apdu_length_format format, buffer out,
                                                        size_t& written) noexcept
{
  return ::TC_APDU_command_encode(&command, format, out, &written);
}

/* TC_APDU_command_encode into a whole array. */
template <size_t Size>
TC_CPP_NODISCARD inline apdu_result
apdu_command_encode(const apdu_command& command, apdu_length_format format, uint8_t (&out)[Size],
                    size_t& written) noexcept
{
  return apdu_command_encode(command, format, buffer{out, Size}, written);
}

/* TC_APDU_response_read. out borrows encoded. */
TC_CPP_NODISCARD inline apdu_result apdu_response_read(bytes encoded, apdu_response& out) noexcept
{
  return ::TC_APDU_response_read(encoded, &out);
}

/* TC_APDU_status_classify. */
TC_CPP_NODISCARD inline apdu_status_class apdu_status_classify(uint16_t sw) noexcept
{
  return ::TC_APDU_status_classify(sw);
}

} // namespace tiny_crypto
#endif
