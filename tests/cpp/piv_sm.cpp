/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.hpp>
#include "../../examples/piv_sm_wire.h"
#include "doctest.h"
#include <type_traits>
#include <cstring>
#if TC_TEST_SM_FIXTURES
#include "sm_fixtures.h"
#endif

static TC_status scalar_one(void*, uint8_t* output, size_t length) {
    std::memset(output, 0, length);
    output[length - 1] = 1;
    return TC_OK;
}

static_assert(!std::is_copy_constructible<tiny_crypto::piv_sm>::value, "Session must not copy");
static_assert(!std::is_move_constructible<tiny_crypto::piv_sm>::value, "Session must not move");

#if TC_TEST_SM_FIXTURES
TEST_CASE("PIV SM authenticated exchange") {
    for (const auto& fixture : sm_fixtures) {
        tiny_crypto::piv_sm session;
        tiny_crypto::piv_sm_workspace workspace{};
        uint8_t host[8] = {}, output[256];
        tiny_crypto::piv_sm_handshake handshake{};
        const bool enabled = fixture.suite == TC_PIV_SM_CS2 ?
            TC_PIV_SM_ENABLE_CS2 : TC_PIV_SM_ENABLE_CS7;
        if (!enabled) {
            CHECK(session.begin(fixture.suite,host,scalar_one,nullptr,
                                handshake,workspace) == TC_ERROR);
            CHECK(session.state() == TC_PIV_SM_IDLE);
            continue;
        }
        REQUIRE(session.begin(fixture.suite,host,scalar_one,nullptr,
                              handshake,workspace) == TC_OK);
        CHECK(handshake.suite == fixture.suite);
        CHECK(handshake.host_identifier.length == sizeof host);
        CHECK(handshake.public_key.length == fixture.public_key.length);
        CHECK(std::memcmp(handshake.public_key.data,fixture.request.data + 18,
                          handshake.public_key.length) == 0);
        ExamplePIVSMResponse parsed{};
        REQUIRE(example_piv_sm_response_read(fixture.suite,fixture.response,&parsed) == TC_OK);
        REQUIRE(session.finish(parsed.peer,fixture.public_key,workspace) == TC_OK);
        CHECK(session.state() == TC_PIV_SM_READY);
        uint8_t header[16] = {0x0c,0x20,0,0x80,0x80};
        const TC_bytes command_mac[] = {{header,sizeof header},{nullptr,0}};
        tiny_crypto::piv_sm_protect_request command = {
            {nullptr,0},nullptr,0,command_mac,2
        };
        uint8_t tag[8];
        size_t ciphertext_length = 99;
        REQUIRE(session.protect(command,ciphertext_length,tag,workspace) == TC_OK);
        REQUIRE(ciphertext_length == 0);
        REQUIRE(fixture.command.length == 10);
        CHECK(std::memcmp(tag,fixture.command.data + 2,sizeof tag) == 0);
        CHECK(session.state() == TC_PIV_SM_PENDING);
        const TC_bytes response_mac = {fixture.reply.data,4};
        tiny_crypto::piv_sm_unprotect_request response = {
            {nullptr,0},{fixture.reply.data + 6,8},&response_mac,1
        };
        size_t plaintext_length = 99;
        REQUIRE(session.unprotect(response,output,sizeof output,plaintext_length,workspace) == TC_OK);
        CHECK(plaintext_length == 0);
        CHECK(session.state() == TC_PIV_SM_READY);
    }
}
#endif

TEST_CASE("PIV SM session lifecycle") {
    const TC_PIV_SM_suite suites[] = {TC_PIV_SM_CS2, TC_PIV_SM_CS7};
    for (auto suite : suites) {
        tiny_crypto::piv_sm session;
        tiny_crypto::piv_sm_workspace workspace{};
        uint8_t host[8] = {}, output[118] = {};
        tiny_crypto::piv_sm_handshake handshake{};
        CHECK(session.state() == TC_PIV_SM_IDLE);
        const bool enabled = suite == TC_PIV_SM_CS2 ? TC_PIV_SM_ENABLE_CS2 : TC_PIV_SM_ENABLE_CS7;
        if (!enabled) {
            CHECK(session.begin(suite,host,scalar_one,nullptr,handshake,workspace) == TC_ERROR);
            CHECK(session.state() == TC_PIV_SM_IDLE);
            continue;
        }
        REQUIRE(session.begin(suite,host,scalar_one,nullptr,handshake,workspace) == TC_OK);
        CHECK(handshake.public_key.length == (suite == TC_PIV_SM_CS2 ? 65u : 97u));
        CHECK(session.state() == TC_PIV_SM_ESTABLISHING);
        tiny_crypto::piv_sm_peer peer{};
        CHECK(session.finish(peer,{nullptr,0},workspace) == TC_ERROR);
        session.clear();
        CHECK(session.state() == TC_PIV_SM_IDLE);
        tiny_crypto::piv_sm_protect_request command{};
        uint8_t tag[8] = {};
        size_t length = 456;
        CHECK(session.protect(command,length,tag,workspace) == TC_ERROR);
        tiny_crypto::piv_sm_unprotect_request response{};
        CHECK(session.unprotect(response,output,sizeof output,length,workspace) == TC_ERROR);
        CHECK(length == 456);
    }
}
