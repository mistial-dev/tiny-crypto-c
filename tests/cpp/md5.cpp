/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

#include "doctest.h"
#include <tiny_crypto/tiny_crypto.hpp>
#include <cstring>
#include <type_traits>

static_assert(!std::is_copy_constructible<tiny_crypto::MD5>::value,
              "Hash contexts require explicit ownership");
static_assert(sizeof(tiny_crypto::MD5) == sizeof(TC_MD5_ctx),
              "The wrapper retains one C context");

TEST_CASE("MD5 streaming, reuse and argument errors") {
    const uint8_t message[] = {'a', 'b', 'c'};
    const uint8_t expected[] = {
        0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,
        0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72
    };
    uint8_t digest[tiny_crypto::MD5::digest_size];
    REQUIRE(tiny_crypto::MD5::digest(message, digest) == TC_OK);
    CHECK(std::memcmp(digest, expected, sizeof digest) == 0);

    tiny_crypto::MD5 hash;
    REQUIRE(hash.update(message, 1) == TC_OK);
    CHECK(hash.update(nullptr, 1) == TC_ERROR);
    REQUIRE(hash.update(message + 1, 2) == TC_OK);
    CHECK(hash.finish(digest, sizeof digest - 1) == TC_ERROR);
    CHECK(hash.finish(nullptr, sizeof digest) == TC_ERROR);
    REQUIRE(hash.finish(digest) == TC_OK);
    CHECK(std::memcmp(digest, expected, sizeof digest) == 0);

    REQUIRE(hash.update(message) == TC_OK);
    REQUIRE(hash.finish(digest) == TC_OK);
    CHECK(std::memcmp(digest, expected, sizeof digest) == 0);
    REQUIRE(hash.update(message) == TC_OK);
    REQUIRE(hash.reset() == TC_OK);
    REQUIRE(hash.update(message) == TC_OK);
    REQUIRE(hash.finish(digest) == TC_OK);
    CHECK(std::memcmp(digest, expected, sizeof digest) == 0);

    CHECK(tiny_crypto::MD5::digest(nullptr, 1, digest, sizeof digest) == TC_ERROR);
    CHECK(tiny_crypto::MD5::digest(message, sizeof message, digest,
                                 sizeof digest - 1) == TC_ERROR);
    CHECK(std::memcmp(digest, expected, sizeof digest) == 0);
}
