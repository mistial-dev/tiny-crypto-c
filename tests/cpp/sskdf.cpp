/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.hpp>
#include <doctest.h>
#include <cstring>

TEST_CASE("Single-step KDF wrappers") {
    uint8_t z[48] = {}, output[128], expected[128];
    tiny_crypto::bytes input = {z, sizeof z};
    REQUIRE(tiny_crypto::sskdf_sha256(input, nullptr, 0, output, sizeof output) == TC_OK);
    REQUIRE(TC_SSKDF_SHA256(z, sizeof z, nullptr, 0, expected, sizeof expected) == TC_OK);
    CHECK(std::memcmp(output, expected, sizeof output) == 0);
    REQUIRE(tiny_crypto::sskdf_sha384(input, nullptr, 0, output, sizeof output) == TC_OK);
    REQUIRE(TC_SSKDF_SHA384(z, sizeof z, nullptr, 0, expected, sizeof expected) == TC_OK);
    CHECK(std::memcmp(output, expected, sizeof output) == 0);
    CHECK(tiny_crypto::sskdf_sha384({nullptr, 0}, nullptr, 0, output, sizeof output) == TC_ERROR);
}
