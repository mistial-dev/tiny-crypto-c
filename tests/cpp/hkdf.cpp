/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <cstring>
#include <tiny_crypto/hkdf.hpp>
#include "doctest.h"

namespace {
struct family {
  size_t hash_len;
  TC_status (*cpp_extract)(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*);
  TC_status (*cpp_expand)(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t);
  TC_status (*cpp_derive)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t,
                          uint8_t*, size_t);
  TC_status (*c_derive)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t,
                        uint8_t*, size_t);
  TC_status (*cpp_hybrid)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t,
                          const uint8_t*, size_t, uint8_t*, size_t);
  TC_status (*c_hybrid)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t,
                        const uint8_t*, size_t, uint8_t*, size_t);
};

const family families[] = {
#if TC_ENABLE_SHA1
    {TC_SHA1_DIGESTLEN, tiny_crypto::hkdf_sha1_extract, tiny_crypto::hkdf_sha1_expand,
     tiny_crypto::hkdf_sha1_derive, TC_HKDF_SHA1_derive, tiny_crypto::hkdf_sha1_derive_hybrid,
     TC_HKDF_SHA1_derive_hybrid},
#endif
#if TC_ENABLE_SHA224
    {TC_SHA224_DIGESTLEN, tiny_crypto::hkdf_sha224_extract, tiny_crypto::hkdf_sha224_expand,
     tiny_crypto::hkdf_sha224_derive, TC_HKDF_SHA224_derive, tiny_crypto::hkdf_sha224_derive_hybrid,
     TC_HKDF_SHA224_derive_hybrid},
#endif
#if TC_ENABLE_SHA256
    {TC_SHA256_DIGESTLEN, tiny_crypto::hkdf_sha256_extract, tiny_crypto::hkdf_sha256_expand,
     tiny_crypto::hkdf_sha256_derive, TC_HKDF_SHA256_derive, tiny_crypto::hkdf_sha256_derive_hybrid,
     TC_HKDF_SHA256_derive_hybrid},
#endif
#if TC_ENABLE_SHA384
    {TC_SHA384_DIGESTLEN, tiny_crypto::hkdf_sha384_extract, tiny_crypto::hkdf_sha384_expand,
     tiny_crypto::hkdf_sha384_derive, TC_HKDF_SHA384_derive, tiny_crypto::hkdf_sha384_derive_hybrid,
     TC_HKDF_SHA384_derive_hybrid},
#endif
#if TC_ENABLE_SHA512
    {TC_SHA512_DIGESTLEN, tiny_crypto::hkdf_sha512_extract, tiny_crypto::hkdf_sha512_expand,
     tiny_crypto::hkdf_sha512_derive, TC_HKDF_SHA512_derive, tiny_crypto::hkdf_sha512_derive_hybrid,
     TC_HKDF_SHA512_derive_hybrid},
#endif
};
} // namespace

TEST_CASE("HKDF C++ wrappers match the C API and reject invalid requests")
{
  const uint8_t ikm[] = {0x0b, 0x0b, 0x0b};
  const uint8_t salt[] = {0x00, 0x01, 0x02};
  const uint8_t info[] = {0xf0, 0xf1};
  const uint8_t t[] = {0x42};
  for (const family& f : families) {
    uint8_t prk[64], from_stages[72], from_cpp[72], from_c[72];
    CHECK(f.cpp_extract(salt, sizeof salt, ikm, sizeof ikm, prk) == TC_OK);
    CHECK(f.cpp_expand(prk, f.hash_len, info, sizeof info, from_stages, sizeof from_stages) ==
          TC_OK);
    CHECK(f.cpp_derive(salt, sizeof salt, ikm, sizeof ikm, info, sizeof info, from_cpp,
                       sizeof from_cpp) == TC_OK);
    CHECK(f.c_derive(salt, sizeof salt, ikm, sizeof ikm, info, sizeof info, from_c,
                     sizeof from_c) == TC_OK);
    CHECK(std::memcmp(from_stages, from_cpp, sizeof from_cpp) == 0);
    CHECK(std::memcmp(from_c, from_cpp, sizeof from_cpp) == 0);
    CHECK(f.cpp_expand(prk, f.hash_len - 1u, info, sizeof info, from_cpp, 1) == TC_ERROR);
    CHECK(f.cpp_derive(salt, sizeof salt, ikm, sizeof ikm, info, sizeof info, from_cpp, 0) ==
          TC_ERROR);
    CHECK(f.cpp_hybrid(salt, sizeof salt, ikm, sizeof ikm, t, sizeof t, info, sizeof info, from_cpp,
                       sizeof from_cpp) == TC_OK);
    CHECK(f.c_hybrid(salt, sizeof salt, ikm, sizeof ikm, t, sizeof t, info, sizeof info, from_c,
                     sizeof from_c) == TC_OK);
    CHECK(std::memcmp(from_cpp, from_c, sizeof from_c) == 0);
  }
}
