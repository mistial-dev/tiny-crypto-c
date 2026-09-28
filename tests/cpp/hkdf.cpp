/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <cstring>
#include <tiny_crypto/hkdf.hpp>
#include "doctest.h"

using tiny_crypto::bytes;

#if TC_ENABLE_SHA256
TEST_CASE("HKDF-SHA256 C++ wrappers match the C API and reject invalid requests")
{
  const uint8_t ikm[] = {0x0b, 0x0b, 0x0b};
  const uint8_t salt[] = {0x00, 0x01, 0x02};
  const uint8_t info[] = {0xf0, 0xf1};
  const uint8_t t[] = {0x42};
  const bytes salt_span = {salt, sizeof salt}, info_span = {info, sizeof info};
  const bytes secret = {ikm, sizeof ikm};
  uint8_t prk[TC_SHA256_DIGESTLEN], from_stages[72], from_cpp[72], from_c[72];
  CHECK(tiny_crypto::hkdf_sha256_extract(salt_span, &secret, 1, prk) == TC_OK);
  CHECK(tiny_crypto::hkdf_sha256_expand(bytes{prk, sizeof prk}, info_span, from_stages,
                                        sizeof from_stages) == TC_OK);
  CHECK(tiny_crypto::hkdf_sha256_derive(salt_span, secret, info_span, from_cpp, sizeof from_cpp) ==
        TC_OK);
  CHECK(TC_HKDF_SHA256_derive(salt, sizeof salt, &secret, 1, info, sizeof info, from_c,
                              sizeof from_c) == TC_OK);
  CHECK(std::memcmp(from_stages, from_cpp, sizeof from_cpp) == 0);
  CHECK(std::memcmp(from_c, from_cpp, sizeof from_cpp) == 0);
  CHECK(tiny_crypto::hkdf_sha256_expand(bytes{prk, sizeof prk - 1}, info_span, from_cpp, 1) ==
        TC_ERROR);
  CHECK(tiny_crypto::hkdf_sha256_derive(salt_span, secret, info_span, from_cpp, 0) == TC_ERROR);
  /* A hybrid Z || T secret passes as two parts. */
  const bytes hybrid[] = {secret, {t, sizeof t}};
  CHECK(tiny_crypto::hkdf_sha256_derive(salt_span, hybrid, 2, info_span, from_cpp,
                                        sizeof from_cpp) == TC_OK);
  CHECK(TC_HKDF_SHA256_derive(salt, sizeof salt, hybrid, 2, info, sizeof info, from_c,
                              sizeof from_c) == TC_OK);
  CHECK(std::memcmp(from_cpp, from_c, sizeof from_c) == 0);
}
#endif
