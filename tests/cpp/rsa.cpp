/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.hpp>
#include <doctest.h>
#include <cstring>

TEST_CASE("RSA signature representative encoding") {
    uint8_t digest[32] = {}, encoded[256], expected[256];
    tiny_crypto::rsa_v15_options options = {TC_HASH_SHA256};
    TC_work_budget work = {sizeof encoded};
    CHECK(tiny_crypto::rsa_encode_v15_digest(options,
        {digest, sizeof digest}, encoded, work) == TC_RSA_OK);
    work.remaining = sizeof expected;
    CHECK(TC_RSA_encode_v15_digest(&options,{digest, sizeof digest},
        {expected, sizeof expected}, &work) == TC_RSA_OK);
    CHECK(std::memcmp(encoded, expected, sizeof encoded) == 0);
    work.remaining = sizeof encoded - 1;
    CHECK(tiny_crypto::rsa_encode_v15_digest(options,
        {digest, sizeof digest}, encoded, work) == TC_RSA_LIMIT);
    CHECK(std::memcmp(encoded, expected, sizeof encoded) == 0);
    work.remaining = sizeof encoded;
    CHECK(tiny_crypto::rsa_encode_v15_digest(options,
        {encoded, sizeof digest}, encoded, work) == TC_RSA_ARGUMENT);
    CHECK(std::memcmp(encoded, expected, sizeof encoded) == 0);
}

TEST_CASE("RSA PSS representative wrappers preserve C results") {
    uint8_t digest[32] = {}, salt[32] = {}, encoded[256], expected[256];
    std::memset(encoded, 0x5a, sizeof encoded);
    std::memset(expected, 0x5a, sizeof expected);
    tiny_crypto::rsa_pss_options options = {TC_HASH_SHA256, TC_HASH_SHA256, sizeof salt};
    TC_work_budget work = {100000}, reference_work = work;
    const TC_RSA_result reference = TC_RSA_encode_pss_digest(&options,
        {digest, sizeof digest}, {salt, sizeof salt},
        {expected, sizeof expected}, &reference_work);
    CHECK(tiny_crypto::rsa_encode_pss_digest(options, {digest, sizeof digest},
        {salt, sizeof salt}, encoded, work) == reference);
    CHECK(work.remaining == reference_work.remaining);
    CHECK(std::memcmp(encoded, expected, sizeof encoded) == 0);
    work.remaining = 100000;
    tiny_crypto::buffer output = {encoded, sizeof encoded};
    CHECK(tiny_crypto::rsa_encode_pss_digest(options, {digest, sizeof digest},
        {salt, sizeof salt}, output, work) == reference);
    CHECK(std::memcmp(encoded, expected, sizeof encoded) == 0);
    CHECK(tiny_crypto::rsa_encode_pss_digest(options, {digest, sizeof digest},
        {salt, sizeof salt - 1}, output, work) == TC_RSA_ARGUMENT);
    CHECK(std::memcmp(encoded, expected, sizeof encoded) == 0);
}

TEST_CASE("RSA key generation state wrappers") {
    TC_RSA_word words[TC_RSA_KEYGEN_WORKSPACE_WORDS(1024)] = {};
    uint8_t modulus[128], exponent[3], d[128], p[64], q[64];
    tiny_crypto::rsa_keygen_output output = {
        {modulus, sizeof modulus}, {exponent, sizeof exponent}, {d, sizeof d},
        {p, sizeof p}, {q, sizeof q}
    };
    tiny_crypto::rsa_keygen_state state = {};
    auto workspace = tiny_crypto::rsa_workspace_for(words);
    CHECK(tiny_crypto::rsa_keygen_init(state, 1024, output, {1, 1}, workspace)
        == TC_RSA_OK);
    tiny_crypto::rsa_keygen_clear(state);
    CHECK(state.marker == 0);
}

TEST_CASE("RSA workspace view and verification") {
    TC_RSA_word words[9 * 1024 / TC_RSA_WORD_BITS + 2];
    auto workspace = tiny_crypto::rsa_workspace_for(words);
    CHECK(workspace.words == words);
    CHECK(workspace.capacity == TC_RSA_verify_workspace_words(1024));
    uint8_t modulus[128], exponent[] = {3}, digest[32] = {}, signature[128] = {};
    std::memset(modulus, 0xff, sizeof modulus);
    tiny_crypto::rsa_public_key key = {{modulus, sizeof modulus}, {exponent, sizeof exponent}};
    tiny_crypto::rsa_v15_options v15 = {TC_HASH_SHA256};
    tiny_crypto::rsa_pss_options pss = {TC_HASH_SHA256,TC_HASH_SHA256,sizeof digest};
    TC_work_budget work = {10000};
    CHECK(tiny_crypto::rsa_verify_v15_digest(key,v15,{digest, sizeof digest},
        {signature, sizeof signature},workspace,work) == TC_RSA_INVALID);
    work.remaining = 0;
    CHECK(tiny_crypto::rsa_verify_v15_digest(key,v15,{digest, sizeof digest},
        {signature, sizeof signature},workspace,work) == TC_RSA_LIMIT);
    work.remaining = 10000;
    CHECK(tiny_crypto::rsa_verify_v15_digest(key,v15,{nullptr, sizeof digest},
        {signature, sizeof signature},workspace,work) == TC_RSA_ARGUMENT);
    CHECK(tiny_crypto::rsa_verify_pss_digest(key,pss,{nullptr, sizeof digest},
        {signature, sizeof signature},workspace,work) == TC_RSA_ARGUMENT);
}

static TC_status unavailable_random(void* context, uint8_t*, size_t) {
    ++*static_cast<unsigned*>(context);
    return TC_ERROR;
}

TEST_CASE("RSA CRT wrapper argument checks") {
    TC_RSA_word words[TC_RSA_CRT_WORKSPACE_WORDS(1024)];
    auto workspace = tiny_crypto::rsa_workspace_for(words);
    tiny_crypto::rsa_private_key key = {};
    tiny_crypto::rsa_crt crt = {};
    tiny_crypto::rsa_crt_output output = {};
    CHECK(workspace.capacity == TC_RSA_crt_workspace_words(1024));
    TC_work_budget work = {0};
    CHECK(tiny_crypto::rsa_validate_crt(key, crt, workspace, work) == TC_RSA_INVALID);
    CHECK(tiny_crypto::rsa_derive_crt(key, output, workspace, work) == TC_RSA_INVALID);
    workspace.words = nullptr;
    CHECK(tiny_crypto::rsa_validate_crt(key, crt, workspace, work) == TC_RSA_ARGUMENT);
}

TEST_CASE("RSA encryption wrapper argument checks") {
    TC_RSA_word words[TC_RSA_ENCRYPT_WORKSPACE_WORDS(1024)];
    auto workspace = tiny_crypto::rsa_workspace_for(words);
    tiny_crypto::rsa_public_key key = {};
    uint8_t ciphertext[128] = {};
    unsigned calls = 0;
    CHECK(workspace.capacity == TC_RSA_encrypt_workspace_words(1024));
    CHECK(TC_RSA_encrypt_workspace_words(1536) == 0);
    tiny_crypto::rsa_oaep_options options = {TC_HASH_SHA256,TC_HASH_SHA256,{nullptr,0}};
    tiny_crypto::rsa_execution execution = {{nullptr,&calls},0,{10000}};
    CHECK(tiny_crypto::rsa_encrypt_oaep(key,options,{nullptr,0},workspace,
        {ciphertext,sizeof ciphertext},execution) == TC_RSA_ARGUMENT);
    execution = {{unavailable_random,&calls},0,{10000}};
    CHECK(tiny_crypto::rsa_encrypt_oaep(key,options,{nullptr,0},workspace,
        {ciphertext,sizeof ciphertext},execution) == TC_RSA_ARGUMENT);
    CHECK(calls == 0);
}

TEST_CASE("RSA private validation wrapper") {
    TC_RSA_word words[TC_RSA_VALIDATE_WORKSPACE_WORDS(1024)];
    auto workspace = tiny_crypto::rsa_workspace_for(words);
    CHECK(workspace.capacity == TC_RSA_validate_workspace_words(1024));
    uint8_t modulus[128], exponent[] = {3}, d[128] = {}, p[128] = {}, q[128] = {};
    std::memset(modulus, 0xff, sizeof modulus);
    d[sizeof d - 1] = 3;
    tiny_crypto::rsa_private_key key = {
        {{modulus, sizeof modulus}, {exponent, sizeof exponent}},
        {d, sizeof d}, {p, sizeof p}, {q, sizeof q}, nullptr
    };
    unsigned calls = 0;
    tiny_crypto::rsa_execution execution = {
        {unavailable_random,&calls},TC_RSA_VALIDATION_ROUNDS,{0}
    };
    CHECK(tiny_crypto::rsa_validate_private_key(key,workspace,execution) == TC_RSA_LIMIT);
    execution = {{nullptr,&calls},TC_RSA_VALIDATION_ROUNDS,{10000}};
    CHECK(tiny_crypto::rsa_validate_private_key(key,workspace,execution) == TC_RSA_ARGUMENT);
    std::memset(words, 0xa5, sizeof words);
    execution = {{unavailable_random,&calls},TC_RSA_VALIDATION_ROUNDS,{10000}};
    CHECK(tiny_crypto::rsa_validate_private_key(key,workspace,execution) == TC_RSA_INVALID);
    CHECK(calls == 0);
    for (auto word : words) CHECK(word == 0);
    uint8_t digest[32] = {}, signature[128];
    std::memset(signature, 0xa5, sizeof signature);
    CHECK(TC_RSA_sign_workspace_words(1024) == TC_RSA_SIGN_WORKSPACE_WORDS(1024));
    tiny_crypto::rsa_v15_options v15 = {TC_HASH_SHA256};
    execution = {{unavailable_random,&calls},1,{10000}};
    CHECK(tiny_crypto::rsa_sign_v15_digest(key,v15,{digest,sizeof digest},workspace,
        {signature,sizeof signature},execution) == TC_RSA_LIMIT);
    execution.work.remaining = 10000;
    CHECK(tiny_crypto::rsa_sign_v15_digest(key,v15,{digest,sizeof digest},workspace,
        {modulus,sizeof modulus},execution) == TC_RSA_ARGUMENT);
    CHECK(calls == 0);
    for (auto byte : signature) CHECK(byte == 0xa5);
    tiny_crypto::rsa_pss_options pss = {TC_HASH_SHA256,TC_HASH_SHA256,sizeof digest};
    execution.work.remaining = 10000;
    CHECK(tiny_crypto::rsa_sign_pss_digest(key,pss,{digest,sizeof digest},workspace,
        {modulus,sizeof modulus},execution) == TC_RSA_ARGUMENT);
    size_t plaintext_length = SIZE_MAX;
    tiny_crypto::rsa_oaep_options oaep = {TC_HASH_SHA256,TC_HASH_SHA256,{nullptr,0}};
    execution = {{nullptr,&calls},1,{10000}};
    CHECK(tiny_crypto::rsa_decrypt_oaep(key,oaep,{modulus,sizeof modulus},workspace,
        {signature,sizeof signature},plaintext_length,execution) == TC_RSA_ARGUMENT);
    execution = {{unavailable_random,&calls},1,{10000}};
    CHECK(tiny_crypto::rsa_decrypt_oaep(key,oaep,{modulus,sizeof modulus},workspace,
        {modulus,sizeof modulus},plaintext_length,execution) == TC_RSA_ARGUMENT);
    CHECK(plaintext_length == SIZE_MAX);
    CHECK(calls == 0);
    for (auto byte : signature) CHECK(byte == 0xa5);
}
