/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

#include <cstring>

#include "doctest.h"
#include <tiny_crypto/hash.hpp>
#include "test_vectors.h"

namespace {

using tiny_crypto::buffer;
using tiny_crypto::bytes;

template <class Hash, size_t N>
void check_hash(const uint8_t (&expected)[N], const uint8_t (&boundary)[BOUNDARY_COUNT][N])
{
  uint8_t one_shot[N];
  uint8_t streamed[N];
  const bytes abc = {fips_abc_msg, FIPS_ABC_LEN};
  CHECK(Hash::digest(abc, buffer{one_shot, N}) == TC_OK);
  CHECK(std::memcmp(one_shot, expected, N) == 0);
  CHECK(Hash::digest(bytes{nullptr, 1}, buffer{one_shot, N}) == TC_ERROR);
  CHECK(Hash::digest(bytes{nullptr, 0}, buffer{one_shot, N - 1}) == TC_ERROR);
  CHECK(Hash::digest(bytes{nullptr, 0}, buffer{nullptr, N}) == TC_ERROR);
  CHECK(std::memcmp(one_shot, expected, N) == 0);

  Hash hash;
  CHECK(hash.update(bytes{fips_abc_msg, 1}) == TC_OK);
  CHECK(hash.update(bytes{fips_abc_msg + 1, FIPS_ABC_LEN - 1}) == TC_OK);
  CHECK(hash.finish(buffer{streamed, N + 1}) == TC_ERROR);
  CHECK(hash.finish(streamed) == TC_OK);
  CHECK(std::memcmp(streamed, expected, N) == 0);
  CHECK(hash.update(bytes{nullptr, 1}) == TC_ERROR);

  uint8_t message[256];
  for (size_t i = 0; i < sizeof(message); ++i)
    message[i] = static_cast<uint8_t>(i);
  for (size_t i = 0; i < BOUNDARY_COUNT; ++i) {
    CAPTURE(boundary_lengths[i]);
    CHECK(Hash::digest(bytes{message, boundary_lengths[i]}, buffer{one_shot, N}) == TC_OK);
    CHECK(std::memcmp(one_shot, boundary[i], N) == 0);
  }

  REQUIRE(Hash::digest(bytes{message, 130}, buffer{one_shot, N}) == TC_OK);
  for (size_t split = 0; split <= 130; ++split) {
    REQUIRE(hash.reset() == TC_OK);
    CHECK(hash.update(bytes{message, split}) == TC_OK);
    CHECK(hash.update(bytes{message + split, 130 - split}) == TC_OK);
    CHECK(hash.finish(buffer{streamed, N}) == TC_OK);
    CHECK(std::memcmp(streamed, one_shot, N) == 0);
  }

  CHECK(hash.update(abc) == TC_OK);
  CHECK(hash.finish(streamed) == TC_OK);
  CHECK(std::memcmp(streamed, expected, N) == 0);

  CHECK(noexcept(Hash()));
  CHECK(noexcept(hash.reset()));
  CHECK(noexcept(hash.update(abc)));
  CHECK(noexcept(hash.finish(streamed)));
  CHECK(noexcept(Hash::digest(abc, buffer{one_shot, N})));
}

template <class Hmac, size_t N> void check_hmac(const hmac_vector* vectors, size_t count)
{
  uint8_t tag[N];
  uint8_t streamed[N];
  for (size_t i = 0; i < count; ++i) {
    const hmac_vector& v = vectors[i];
    const bytes key = {v.key, v.key_len};
    const bytes msg = {v.msg, v.msg_len};
    CAPTURE(i);
    CHECK(Hmac::mac(key, msg, buffer{tag, N}) == TC_OK);
    CHECK(std::memcmp(tag, v.tag, N) == 0);
    uint8_t full[N];
    CHECK(Hmac::mac(key, msg, full) == TC_OK);
    CHECK(std::memcmp(full, v.tag, N) == 0);
    CHECK(Hmac::verify(key, msg, bytes{tag, N}) == TC_OK);
    CHECK(Hmac::verify(key, msg, bytes{tag, TC_HMAC_MIN_TAG_LEN}) == TC_OK);
    tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 1;
    CHECK(Hmac::verify(key, msg, bytes{tag, TC_HMAC_MIN_TAG_LEN}) == TC_MISMATCH);
    tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 1;

    /* A truncated mac is the leading bytes of the full tag and verifies. */
    uint8_t truncated[N];
    std::memset(truncated, 0xA5, sizeof truncated);
    CHECK(Hmac::mac(key, msg, buffer{truncated, TC_HMAC_MIN_TAG_LEN}) == TC_OK);
    CHECK(std::memcmp(truncated, v.tag, TC_HMAC_MIN_TAG_LEN) == 0);
    CHECK(truncated[TC_HMAC_MIN_TAG_LEN] == 0xA5);
    CHECK(Hmac::verify(key, msg, bytes{truncated, TC_HMAC_MIN_TAG_LEN}) == TC_OK);

    Hmac hmac;
    CHECK(hmac.init(key) == TC_OK);
    const size_t split = v.msg_len / 2;
    CHECK(hmac.update(bytes{v.msg, split}) == TC_OK);
    CHECK(hmac.update(bytes{v.msg + split, v.msg_len - split}) == TC_OK);
    CHECK(hmac.finish(buffer{streamed, N - 1}) == TC_ERROR);
    CHECK(hmac.finish(streamed) == TC_OK);
    CHECK(std::memcmp(streamed, v.tag, N) == 0);
    CHECK(hmac.finish(streamed) == TC_ERROR);
    CHECK(hmac.update(msg) == TC_ERROR);
  }

  const bytes key0 = {vectors[0].key, vectors[0].key_len};
  const bytes msg0 = {vectors[0].msg, vectors[0].msg_len};

  /* A default-constructed object holds no key. */
  Hmac unkeyed;
  CHECK(unkeyed.update(msg0) == TC_ERROR);
  CHECK(unkeyed.finish(streamed) == TC_ERROR);

  /* A failed re-init leaves the object unkeyed. */
  Hmac rekeyed(key0);
  CHECK(rekeyed.update(msg0) == TC_OK);
  CHECK(rekeyed.init(bytes{nullptr, 1}) == TC_ERROR);
  CHECK(rekeyed.update(msg0) == TC_ERROR);
  CHECK(rekeyed.finish(streamed) == TC_ERROR);

  const bytes empty = {nullptr, 0};
  CHECK(noexcept(unkeyed.update(msg0)));
  CHECK(noexcept(unkeyed.finish(streamed)));
  CHECK(noexcept(Hmac::verify(empty, empty, empty)));
  CHECK(noexcept(Hmac::mac(empty, empty, buffer{tag, N})));
  CHECK(noexcept(Hmac(key0)));
  CHECK(Hmac::mac(key0, bytes{nullptr, 1}, buffer{tag, N}) == TC_ERROR);
  CHECK(Hmac::mac(key0, msg0, buffer{tag, N + 1}) == TC_ERROR);
  CHECK(Hmac::mac(key0, msg0, buffer{tag, TC_HMAC_MIN_TAG_LEN - 1}) == TC_ERROR);
  CHECK(Hmac::verify(key0, msg0, bytes{tag, TC_HMAC_MIN_TAG_LEN - 1}) == TC_ERROR);
}

} /* namespace */

TEST_CASE("ct_equal compares byte spans")
{
  using tiny_crypto::bytes;
  const uint8_t a[] = {1, 2};
  const uint8_t b[] = {1, 3};
  const uint8_t longer[] = {1, 2, 0};
  CHECK(tiny_crypto::ct_equal(bytes{a, 2}, bytes{a, 2}) == TC_OK);
  CHECK(tiny_crypto::ct_equal(bytes{a, 2}, bytes{b, 2}) == TC_MISMATCH);
  CHECK(tiny_crypto::ct_equal(bytes{nullptr, 0}, bytes{nullptr, 0}) == TC_OK);
  /* Unequal lengths never match, including a matching prefix or an empty span. */
  CHECK(tiny_crypto::ct_equal(bytes{a, 2}, bytes{longer, 3}) == TC_MISMATCH);
  CHECK(tiny_crypto::ct_equal(bytes{longer, 3}, bytes{a, 2}) == TC_MISMATCH);
  CHECK(tiny_crypto::ct_equal(bytes{nullptr, 0}, bytes{a, 2}) == TC_MISMATCH);
  /* A NULL span with a nonzero length is an argument error, whatever the other length. */
  CHECK(tiny_crypto::ct_equal(bytes{nullptr, 1}, bytes{b, 1}) == TC_ERROR);
  CHECK(tiny_crypto::ct_equal(bytes{b, 1}, bytes{nullptr, 1}) == TC_ERROR);
  CHECK(tiny_crypto::ct_equal(bytes{nullptr, 2}, bytes{b, 1}) == TC_ERROR);
  CHECK(tiny_crypto::ct_equal(bytes{b, 0}, bytes{nullptr, 3}) == TC_ERROR);
  CHECK(noexcept(tiny_crypto::ct_equal(bytes{a, 2}, bytes{b, 2})));
}

#if TC_ENABLE_SHA1
TEST_CASE("SHA-1 status wrapper")
{
  check_hash<tiny_crypto::SHA1>(fips_abc_sha1, boundary_sha1);
}
#endif
#if TC_ENABLE_SHA224
TEST_CASE("SHA-224 status wrapper")
{
  check_hash<tiny_crypto::SHA224>(fips_abc_sha224, boundary_sha224);
}
#endif
#if TC_ENABLE_SHA256
TEST_CASE("SHA-256 status wrapper")
{
  check_hash<tiny_crypto::SHA256>(fips_abc_sha256, boundary_sha256);
}
#endif
#if TC_ENABLE_SHA384
TEST_CASE("SHA-384 status wrapper")
{
  check_hash<tiny_crypto::SHA384>(fips_abc_sha384, boundary_sha384);
}
#endif
#if TC_ENABLE_SHA512
TEST_CASE("SHA-512 status wrapper")
{
  check_hash<tiny_crypto::SHA512>(fips_abc_sha512, boundary_sha512);
}
#endif

#if TC_ENABLE_HMAC && TC_ENABLE_SHA1
TEST_CASE("HMAC-SHA-1 status wrapper")
{
  check_hmac<tiny_crypto::HMAC_SHA1, TC_SHA1_DIGESTLEN>(rfc2202, RFC2202_COUNT);
}
#endif
#if TC_ENABLE_HMAC && TC_ENABLE_SHA224
TEST_CASE("HMAC-SHA-224 status wrapper")
{
  check_hmac<tiny_crypto::HMAC_SHA224, TC_SHA224_DIGESTLEN>(rfc4231_sha224, RFC4231_COUNT);
}
#endif
#if TC_ENABLE_HMAC && TC_ENABLE_SHA256
TEST_CASE("HMAC-SHA-256 status wrapper")
{
  check_hmac<tiny_crypto::HMAC_SHA256, TC_SHA256_DIGESTLEN>(rfc4231, RFC4231_COUNT);
}
#endif
#if TC_ENABLE_HMAC && TC_ENABLE_SHA384
TEST_CASE("HMAC-SHA-384 status wrapper")
{
  check_hmac<tiny_crypto::HMAC_SHA384, TC_SHA384_DIGESTLEN>(rfc4231_sha384, RFC4231_COUNT);
}
#endif
#if TC_ENABLE_HMAC && TC_ENABLE_SHA512
TEST_CASE("HMAC-SHA-512 status wrapper")
{
  check_hmac<tiny_crypto::HMAC_SHA512, TC_SHA512_DIGESTLEN>(rfc4231_sha512, RFC4231_COUNT);
}
#endif
