/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

#include <cstring>

#include "doctest.h"
#include <tiny_crypto/hash.hpp>
#include "test_vectors.h"

namespace {

template <class Hash, size_t N>
void check_hash(const uint8_t (&expected)[N],
                const uint8_t (&boundary)[BOUNDARY_COUNT][N]) {
    uint8_t one_shot[N];
    uint8_t streamed[N];
    CHECK(Hash::digest(fips_abc_msg, FIPS_ABC_LEN, one_shot, sizeof(one_shot)) == TC_OK);
    CHECK(std::memcmp(one_shot, expected, N) == 0);
    CHECK(Hash::digest(nullptr, 1, one_shot, sizeof(one_shot)) == TC_ERROR);
    CHECK(Hash::digest(nullptr, 0, one_shot, sizeof(one_shot) - 1) == TC_ERROR);

    Hash hash;
    CHECK(hash.update(fips_abc_msg, 1) == TC_OK);
    CHECK(hash.update(fips_abc_msg + 1, FIPS_ABC_LEN - 1) == TC_OK);
    CHECK(hash.finish(streamed) == TC_OK);
    CHECK(std::memcmp(streamed, expected, N) == 0);
    CHECK(hash.update(nullptr, 1) == TC_ERROR);

    uint8_t message[256];
    for (size_t i = 0; i < sizeof(message); ++i)
        message[i] = static_cast<uint8_t>(i);
    for (size_t i = 0; i < BOUNDARY_COUNT; ++i) {
        CAPTURE(boundary_lengths[i]);
        CHECK(Hash::digest(message, boundary_lengths[i], one_shot,
                           sizeof(one_shot)) == TC_OK);
        CHECK(std::memcmp(one_shot, boundary[i], N) == 0);
    }

    REQUIRE(Hash::digest(message, 130, one_shot, sizeof(one_shot)) == TC_OK);
    for (size_t split = 0; split <= 130; ++split) {
        REQUIRE(hash.reset() == TC_OK);
        CHECK(hash.update(message, split) == TC_OK);
        CHECK(hash.update(message + split, 130 - split) == TC_OK);
        CHECK(hash.finish(streamed) == TC_OK);
        CHECK(std::memcmp(streamed, one_shot, N) == 0);
    }

    CHECK(hash.update(fips_abc_msg, FIPS_ABC_LEN) == TC_OK);
    CHECK(hash.finish(streamed) == TC_OK);
    CHECK(std::memcmp(streamed, expected, N) == 0);
}

template <class Hmac, size_t N>
void check_hmac(const hmac_vector* vectors, size_t count) {
    uint8_t tag[N];
    uint8_t streamed[N];
    for (size_t i = 0; i < count; ++i) {
        const hmac_vector& v = vectors[i];
        CAPTURE(i);
        CHECK(Hmac::mac(v.key, v.key_len, v.msg, v.msg_len,
                        tag, sizeof(tag)) == TC_OK);
        CHECK(std::memcmp(tag, v.tag, N) == 0);
        CHECK(Hmac::verify(v.key, v.key_len, v.msg, v.msg_len,
                           tag, N) == TC_OK);
        CHECK(Hmac::verify(v.key, v.key_len, v.msg, v.msg_len,
                           tag, TC_HMAC_MIN_TAG_LEN) == TC_OK);
        tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 1;
        CHECK(Hmac::verify(v.key, v.key_len, v.msg, v.msg_len,
                           tag, TC_HMAC_MIN_TAG_LEN) == TC_MISMATCH);
        tag[TC_HMAC_MIN_TAG_LEN - 1] ^= 1;

        Hmac hmac;
        CHECK(hmac.init(v.key, v.key_len) == TC_OK);
        const size_t split = v.msg_len / 2;
        CHECK(hmac.update(v.msg, split) == TC_OK);
        CHECK(hmac.update(v.msg + split, v.msg_len - split) == TC_OK);
        CHECK(hmac.finish(streamed) == TC_OK);
        CHECK(std::memcmp(streamed, v.tag, N) == 0);
        CHECK(hmac.finish(streamed) == TC_ERROR);
    }
    CHECK(Hmac::mac(vectors[0].key, vectors[0].key_len, nullptr, 1,
                    tag, sizeof(tag)) == TC_ERROR);
    CHECK(Hmac::verify(vectors[0].key, vectors[0].key_len,
                       vectors[0].msg, vectors[0].msg_len,
                       tag, TC_HMAC_MIN_TAG_LEN - 1) == TC_ERROR);
}

} /* namespace */

TEST_CASE("ct_equal preserves C status values") {
    const uint8_t a[] = {1, 2};
    const uint8_t b[] = {1, 3};
    CHECK(tiny_crypto::ct_equal(a, a, 2) == TC_OK);
    CHECK(tiny_crypto::ct_equal(a, b, 2) == TC_MISMATCH);
    CHECK(tiny_crypto::ct_equal(nullptr, b, 1) == TC_ERROR);
}

#if TC_ENABLE_SHA1
TEST_CASE("SHA-1 status wrapper") { check_hash<tiny_crypto::SHA1>(fips_abc_sha1, boundary_sha1); }
#endif
#if TC_ENABLE_SHA224
TEST_CASE("SHA-224 status wrapper") { check_hash<tiny_crypto::SHA224>(fips_abc_sha224, boundary_sha224); }
#endif
#if TC_ENABLE_SHA256
TEST_CASE("SHA-256 status wrapper") { check_hash<tiny_crypto::SHA256>(fips_abc_sha256, boundary_sha256); }
#endif
#if TC_ENABLE_SHA384
TEST_CASE("SHA-384 status wrapper") { check_hash<tiny_crypto::SHA384>(fips_abc_sha384, boundary_sha384); }
#endif
#if TC_ENABLE_SHA512
TEST_CASE("SHA-512 status wrapper") { check_hash<tiny_crypto::SHA512>(fips_abc_sha512, boundary_sha512); }
#endif

#if TC_ENABLE_HMAC && TC_ENABLE_SHA1
TEST_CASE("HMAC-SHA-1 status wrapper") { check_hmac<tiny_crypto::HMAC_SHA1, TC_SHA1_DIGESTLEN>(rfc2202, RFC2202_COUNT); }
#endif
#if TC_ENABLE_HMAC && TC_ENABLE_SHA224
TEST_CASE("HMAC-SHA-224 status wrapper") { check_hmac<tiny_crypto::HMAC_SHA224, TC_SHA224_DIGESTLEN>(rfc4231_sha224, RFC4231_COUNT); }
#endif
#if TC_ENABLE_HMAC && TC_ENABLE_SHA256
TEST_CASE("HMAC-SHA-256 status wrapper") { check_hmac<tiny_crypto::HMAC_SHA256, TC_SHA256_DIGESTLEN>(rfc4231, RFC4231_COUNT); }
#endif
#if TC_ENABLE_HMAC && TC_ENABLE_SHA384
TEST_CASE("HMAC-SHA-384 status wrapper") { check_hmac<tiny_crypto::HMAC_SHA384, TC_SHA384_DIGESTLEN>(rfc4231_sha384, RFC4231_COUNT); }
#endif
#if TC_ENABLE_HMAC && TC_ENABLE_SHA512
TEST_CASE("HMAC-SHA-512 status wrapper") { check_hmac<tiny_crypto::HMAC_SHA512, TC_SHA512_DIGESTLEN>(rfc4231_sha512, RFC4231_COUNT); }
#endif
