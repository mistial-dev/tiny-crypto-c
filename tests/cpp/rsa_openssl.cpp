/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.hpp>
#include <doctest.h>
#include "../rsa/openssl_key.h"
#include <openssl/rsa.h>
#include <memory>
#include <cstring>

static TC_status blinding_bytes(void*, uint8_t* output, size_t length) {
    std::memset(output, 0, length);
    output[length - 1] = 2;
    return TC_OK;
}

TEST_CASE("RSA C++ PSS and OAEP operations") {
    const size_t width = 128;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> generated(
        EVP_RSA_gen(width * 8), EVP_PKEY_free);
    REQUIRE(generated != nullptr);
    uint8_t components[5][TC_TEST_RSA_MAX_BYTES];
    const size_t exponent_length = tc_test_rsa_export(generated.get(), components, width);
    REQUIRE(exponent_length > 0);
    tiny_crypto::rsa_private_key key = {
        {{components[0], width}, {components[1], exponent_length}},
        {components[2], width}, {components[3], width}, {components[4], width}, nullptr
    };
    TC_bytes* magnitudes[] = {&key.d, &key.p, &key.q};
    for (auto magnitude : magnitudes)
        while (magnitude->length > 1 && magnitude->data[0] == 0) {
            ++magnitude->data;
            --magnitude->length;
        }
    TC_RSA_word words[TC_RSA_SIGN_WORKSPACE_WORDS(1024)];
    auto workspace = tiny_crypto::rsa_workspace_for(words);
    uint8_t dp[width / 2], dq[width / 2], inverse[width / 2];
    tiny_crypto::rsa_crt_output crt_output = {
        {dp, sizeof dp}, {dq, sizeof dq}, {inverse, sizeof inverse}
    };
    TC_work_budget work = {static_cast<uint32_t>(48 * width + 3)};
    REQUIRE(tiny_crypto::rsa_derive_crt(key,crt_output,workspace,work) == TC_RSA_OK);
    tiny_crypto::rsa_crt crt = {
        {dp, sizeof dp}, {dq, sizeof dq}, {inverse, sizeof inverse}
    };
    work.remaining = static_cast<uint32_t>(32 * width + 1);
    REQUIRE(tiny_crypto::rsa_validate_crt(key,crt,workspace,work) == TC_RSA_OK);
    key.crt = &crt;
    uint8_t digest[32] = {1}, signature[width];
    tiny_crypto::rsa_pss_options pss = {TC_HASH_SHA256,TC_HASH_SHA256,sizeof digest};
    tiny_crypto::rsa_execution execution = {{blinding_bytes,nullptr},1,{UINT32_MAX}};
    REQUIRE(tiny_crypto::rsa_sign_pss_digest(key,pss,{digest,sizeof digest},workspace,
        {signature,sizeof signature},execution) == TC_RSA_OK);
    work.remaining = UINT32_MAX;
    REQUIRE(tiny_crypto::rsa_verify_pss_digest(key.public_key,pss,
        {digest,sizeof digest},{signature,sizeof signature},workspace,work) == TC_RSA_OK);
    digest[0] ^= 1;
    work.remaining = UINT32_MAX;
    CHECK(tiny_crypto::rsa_verify_pss_digest(key.public_key,pss,
        {digest,sizeof digest},{signature,sizeof signature},workspace,work) == TC_RSA_INVALID);

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> encrypt(
        EVP_PKEY_CTX_new(generated.get(), nullptr), EVP_PKEY_CTX_free);
    REQUIRE(encrypt != nullptr);
    REQUIRE(EVP_PKEY_encrypt_init(encrypt.get()) == 1);
    REQUIRE(EVP_PKEY_CTX_set_rsa_padding(encrypt.get(), RSA_PKCS1_OAEP_PADDING) == 1);
    REQUIRE(EVP_PKEY_CTX_set_rsa_oaep_md(encrypt.get(), EVP_sha256()) == 1);
    REQUIRE(EVP_PKEY_CTX_set_rsa_mgf1_md(encrypt.get(), EVP_sha256()) == 1);
    uint8_t message[] = {0, 1, 0xff}, ciphertext[width], plaintext[sizeof message];
    size_t ciphertext_length = sizeof ciphertext, plaintext_length = SIZE_MAX;
    REQUIRE(EVP_PKEY_encrypt(encrypt.get(), ciphertext, &ciphertext_length,
        message, sizeof message) == 1);
    tiny_crypto::rsa_oaep_options oaep = {
        TC_HASH_SHA256,TC_HASH_SHA256,{nullptr,0}
    };
    execution.work.remaining = UINT32_MAX;
    REQUIRE(tiny_crypto::rsa_decrypt_oaep(key,oaep,{ciphertext,ciphertext_length},
        workspace,{plaintext,sizeof plaintext},plaintext_length,execution) == TC_RSA_OK);
    CHECK(plaintext_length == sizeof message);
    CHECK(std::memcmp(plaintext, message, sizeof message) == 0);
    for (auto word : words) CHECK(word == 0);
}
