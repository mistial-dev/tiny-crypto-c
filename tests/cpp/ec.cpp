/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.hpp>
#include <doctest.h>
#include <cstring>

TEST_CASE("EC wrappers") {
    tiny_crypto::ec_workspace workspace;
    uint8_t scalar[32] = {}, public_key[65], shared[32];
    scalar[31] = 1;
    REQUIRE(tiny_crypto::ec_public_key(TC_EC_P256, {scalar, sizeof scalar},
                                       public_key, sizeof public_key, workspace) == TC_OK);
    REQUIRE(tiny_crypto::ec_validate_public_key(TC_EC_P256, {public_key, sizeof public_key},
                                                workspace) == TC_OK);
    REQUIRE(tiny_crypto::ecdh(TC_EC_P256, {scalar, sizeof scalar},
                              {public_key, sizeof public_key}, shared, sizeof shared, workspace) == TC_OK);
    CHECK(std::memcmp(shared, public_key + 1, sizeof shared) == 0);
    tiny_crypto::ecdsa_workspace signature_workspace;
    uint8_t digest[32] = {}, signature[64];
    // With d = k = 1 and a zero digest, r = s = Gx.
    std::memcpy(signature, public_key + 1, 32);
    std::memcpy(signature + 32, public_key + 1, 32);
    CHECK(tiny_crypto::ecdsa_verify_digest(TC_EC_P256, {public_key, sizeof public_key},
        {digest, sizeof digest}, {signature, sizeof signature}, signature_workspace) == TC_OK);
    digest[0] = 1;
    CHECK(tiny_crypto::ecdsa_verify_digest(TC_EC_P256, {public_key, sizeof public_key},
        {digest, sizeof digest}, {signature, sizeof signature}, signature_workspace) == TC_MISMATCH);
    CHECK(tiny_crypto::ecdsa_verify_digest(TC_EC_P256, {public_key, sizeof public_key},
        {nullptr, 0}, {signature, sizeof signature}, signature_workspace) == TC_ERROR);
    CHECK(tiny_crypto::ec_public_key(TC_EC_P256, {nullptr, 0},
                                     public_key, sizeof public_key, workspace) == TC_ERROR);
}
