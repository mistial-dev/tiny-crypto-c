/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.hpp>
#include <doctest.h>
#include <cstring>

namespace {
typedef TC_status (*cpp_derive)(tiny_crypto::bytes, const tiny_crypto::bytes*, size_t,
                                tiny_crypto::buffer);
typedef TC_status (*c_derive)(TC_bytes, const TC_bytes*, size_t, TC_buffer);

/* Each wrapper must match its C function and forward argument errors. */
void check_family(cpp_derive wrapper, c_derive function)
{
  uint8_t z[48] = {}, output[128], expected[128];
  const uint8_t text[] = {'i', 'n', 'f', 'o'};
  const tiny_crypto::bytes info[] = {{text, sizeof text}};
  REQUIRE(wrapper({z, sizeof z}, info, 1, {output, sizeof output}) == TC_OK);
  REQUIRE(function({z, sizeof z}, info, 1, {expected, sizeof expected}) == TC_OK);
  CHECK(std::memcmp(output, expected, sizeof output) == 0);
  CHECK(wrapper({nullptr, 0}, nullptr, 0, {output, sizeof output}) == TC_ERROR);
}
} // namespace

TEST_CASE("Single-step KDF wrappers")
{
#if TC_ENABLE_SHA1
  check_family(tiny_crypto::sskdf_sha1, TC_SSKDF_SHA1);
#endif
#if TC_ENABLE_SHA224
  check_family(tiny_crypto::sskdf_sha224, TC_SSKDF_SHA224);
#endif
#if TC_ENABLE_SHA256
  check_family(tiny_crypto::sskdf_sha256, TC_SSKDF_SHA256);
#endif
#if TC_ENABLE_SHA384
  check_family(tiny_crypto::sskdf_sha384, TC_SSKDF_SHA384);
#endif
#if TC_ENABLE_SHA512
  check_family(tiny_crypto::sskdf_sha512, TC_SSKDF_SHA512);
#endif
}
