/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

#include <array>
#include <cstring>
#include <vector>

#include "doctest.h"
#include <tiny_crypto/aes.hpp>
#include "test_vectors.h"
#include "gcm_test_vectors.h"

namespace {
template <size_t N>
std::array<uint8_t, N> bytes(const uint8_t* source) {
    std::array<uint8_t, N> result{};
    std::memcpy(result.data(), source, N);
    return result;
}

#if TC_AES_KEY_BITS == 128
const uint8_t* const kat_key = aes128_key;
const uint8_t* const kat_ecb = aes128_ecb_ciphertext;
const uint8_t* const kat_cbc = aes128_cbc_ciphertext;
const uint8_t* const kat_ctr = aes128_ctr_ciphertext;
const uint8_t* const kat_ofb = aes128_ofb_ciphertext;
#elif TC_AES_KEY_BITS == 192
const uint8_t* const kat_key = aes192_key;
const uint8_t* const kat_ecb = aes192_ecb_ciphertext;
const uint8_t* const kat_cbc = aes192_cbc_ciphertext;
const uint8_t* const kat_ctr = aes192_ctr_ciphertext;
const uint8_t* const kat_ofb = aes192_ofb_ciphertext;
#else
const uint8_t* const kat_key = aes256_key;
const uint8_t* const kat_ecb = aes256_ecb_ciphertext;
const uint8_t* const kat_cbc = aes256_cbc_ciphertext;
const uint8_t* const kat_ctr = aes256_ctr_ciphertext;
const uint8_t* const kat_ofb = aes256_ofb_ciphertext;
#endif
} /* namespace */

TEST_CASE("AES initialization returns status") {
    tiny_crypto::AES aes;
    CHECK(aes.init(kat_key, TC_AES_KEYLEN) == TC_OK);
    CHECK(aes.init(kat_key, TC_AES_KEYLEN - 1) == TC_ERROR);
    CHECK(aes.init(nullptr, TC_AES_KEYLEN) == TC_ERROR);
#if TC_AES_ENABLE_CBC || TC_AES_ENABLE_CTR || TC_AES_ENABLE_OFB
    CHECK(aes.init(kat_key, TC_AES_KEYLEN, nist_iv, sizeof(nist_iv)) == TC_OK);
    CHECK(aes.set_iv(nist_iv, sizeof(nist_iv) - 1) == TC_ERROR);
#endif
}

#if TC_AES_ENABLE_ECB
TEST_CASE("AES ECB wrapper") {
    tiny_crypto::AES aes;
    uint8_t block[TC_AES_BLOCKLEN];
    REQUIRE(aes.init(kat_key, TC_AES_KEYLEN) == TC_OK);
    std::memcpy(block, nist_plaintext, sizeof(block));
    CHECK(aes.encrypt_ecb(block) == TC_OK);
    CHECK(std::memcmp(block, kat_ecb, sizeof(block)) == 0);
    CHECK(aes.decrypt_ecb(block) == TC_OK);
    CHECK(std::memcmp(block, nist_plaintext, sizeof(block)) == 0);
}
#endif

#if TC_AES_ENABLE_CBC
TEST_CASE("AES CBC wrapper") {
    tiny_crypto::AES aes;
    uint8_t data[64];
    REQUIRE(aes.init(kat_key, TC_AES_KEYLEN, nist_iv, sizeof(nist_iv)) == TC_OK);
    std::memcpy(data, nist_plaintext, sizeof(data));
    CHECK(aes.encrypt_cbc(data) == TC_OK);
    CHECK(std::memcmp(data, kat_cbc, sizeof(data)) == 0);
    CHECK(aes.set_iv(nist_iv, sizeof(nist_iv)) == TC_OK);
    CHECK(aes.decrypt_cbc(data) == TC_OK);
    CHECK(std::memcmp(data, nist_plaintext, sizeof(data)) == 0);
    CHECK(aes.encrypt_cbc(data, 15) == TC_ERROR);
}
#endif

#if TC_AES_ENABLE_CTR
TEST_CASE("AES CTR wrapper") {
    tiny_crypto::AES aes;
    uint8_t data[64];
    REQUIRE(aes.init(kat_key, TC_AES_KEYLEN, nist_ctr_iv, sizeof(nist_ctr_iv)) == TC_OK);
    std::memcpy(data, nist_plaintext, sizeof(data));
    CHECK(aes.xcrypt_ctr(data) == TC_OK);
    CHECK(std::memcmp(data, kat_ctr, sizeof(data)) == 0);

    std::memcpy(data, nist_plaintext, sizeof(data));
    REQUIRE(aes.set_iv(nist_ctr_iv, sizeof(nist_ctr_iv)) == TC_OK);
    CHECK(aes.xcrypt_ctr(data, 5) == TC_OK);
    CHECK(aes.xcrypt_ctr(data + 5, 27) == TC_OK);
    CHECK(aes.xcrypt_ctr(data + 32, 32) == TC_OK);
    CHECK(std::memcmp(data, kat_ctr, sizeof(data)) == 0);

    uint8_t top[TC_AES_BLOCKLEN];
    uint8_t two_blocks[2 * TC_AES_BLOCKLEN] = { 0 };
    std::memset(top, 0xff, sizeof(top));
    REQUIRE(aes.set_iv(top, sizeof(top)) == TC_OK);
    CHECK(aes.xcrypt_ctr(two_blocks, sizeof(two_blocks)) == TC_ERROR);
}
#endif

#if TC_AES_ENABLE_OFB
TEST_CASE("AES OFB wrapper") {
    tiny_crypto::AES aes;
    uint8_t data[64];
    REQUIRE(aes.init(kat_key, TC_AES_KEYLEN, nist_iv, sizeof(nist_iv)) == TC_OK);
    std::memcpy(data, nist_plaintext, sizeof(data));
    CHECK(aes.xcrypt_ofb(data) == TC_OK);
    CHECK(std::memcmp(data, kat_ofb, sizeof(data)) == 0);
    REQUIRE(aes.set_iv(nist_iv, sizeof(nist_iv)) == TC_OK);
    CHECK(aes.xcrypt_ofb(data, 7) == TC_OK);
    CHECK(aes.xcrypt_ofb(data + 7, sizeof(data) - 7) == TC_OK);
    CHECK(std::memcmp(data, nist_plaintext, sizeof(data)) == 0);
}
#endif

#if TC_AES_ENABLE_GCM
static void check_gcm_vector(const gcm_test_vector& v) {
    std::vector<uint8_t> data(v.plaintext, v.plaintext + v.length);
    std::vector<uint8_t> tag(v.tag_len);
    tiny_crypto::GCM gcm;

    REQUIRE(gcm.init(v.key, v.key_len, v.iv, v.iv_len, v.tag_len) == TC_OK);
    CHECK(gcm.tag_length() == v.tag_len);
    CHECK(gcm.aad_update(v.aad, v.aad_len) == TC_OK);
    const size_t split = v.length < 5 ? v.length : 5;
    CHECK(gcm.encrypt_update(data.data(), split) == TC_OK);
    CHECK(gcm.encrypt_update(data.data() + split, v.length - split) == TC_OK);
    CHECK(gcm.encrypt_finish(tag.data(), tag.size()) == TC_OK);
    CHECK(std::memcmp(data.data(), v.ciphertext, v.length) == 0);
    CHECK(std::memcmp(tag.data(), v.tag, v.tag_len) == 0);

    REQUIRE(gcm.init(v.key, v.key_len, v.iv, v.iv_len, v.tag_len) == TC_OK);
    CHECK(gcm.aad_update(v.aad, v.aad_len) == TC_OK);
    CHECK(gcm.decrypt_update(data.data(), v.length) == TC_OK);
    CHECK(gcm.decrypt_finish(tag.data(), tag.size()) == TC_OK);
    CHECK(std::memcmp(data.data(), v.plaintext, v.length) == 0);
}

TEST_CASE("AES GCM known answers and state errors") {
    size_t matched = 0;
    for (size_t i = 0; i < sizeof(gcm_test_vectors) / sizeof(gcm_test_vectors[0]); ++i) {
        if (gcm_test_vectors[i].key_len == TC_AES_KEYLEN) {
            check_gcm_vector(gcm_test_vectors[i]);
            ++matched;
        }
    }
    if (gcm_non96_test_vector.key_len == TC_AES_KEYLEN) {
        check_gcm_vector(gcm_non96_test_vector);
        ++matched;
    }
    CHECK(matched > 0);

    const gcm_test_vector* v = nullptr;
    for (size_t i = 0; i < sizeof(gcm_test_vectors) / sizeof(gcm_test_vectors[0]); ++i)
        if (gcm_test_vectors[i].key_len == TC_AES_KEYLEN) { v = &gcm_test_vectors[i]; break; }
    REQUIRE(v != nullptr);
    std::vector<uint8_t> data(v->ciphertext, v->ciphertext + v->length);
    std::vector<uint8_t> tag(v->tag, v->tag + v->tag_len);
    tiny_crypto::GCM gcm;
    REQUIRE(gcm.init(v->key, v->key_len, v->iv, v->iv_len, v->tag_len) == TC_OK);
    CHECK(gcm.aad_update(v->aad, v->aad_len) == TC_OK);
    CHECK(gcm.decrypt_update(data.data(), data.size()) == TC_OK);
    tag[0] ^= 1;
    CHECK(gcm.decrypt_finish(tag.data(), tag.size()) == TC_MISMATCH);
    CHECK(gcm.decrypt_finish(tag.data(), tag.size()) == TC_ERROR);

    REQUIRE(gcm.init(v->key, v->key_len, v->iv, v->iv_len, v->tag_len) == TC_OK);
    CHECK(gcm.encrypt_update(data.data(), data.size()) == TC_OK);
    CHECK(gcm.aad_update(v->aad, v->aad_len) == TC_ERROR);
    CHECK(gcm.decrypt_update(data.data(), data.size()) == TC_ERROR);
    CHECK(gcm.encrypt_finish(tag.data(), tag.size() - 1) == TC_ERROR);
    CHECK(gcm.init(v->key, v->key_len - 1, v->iv, v->iv_len, v->tag_len) == TC_ERROR);
}
#endif

#if TC_AES_ENABLE_CMAC
TEST_CASE("AES CMAC wrapper returns status") {
    uint8_t tag[TC_AES_BLOCKLEN];
    uint8_t expected[TC_AES_BLOCKLEN];
    CHECK(tiny_crypto::aes_cmac(kat_key, TC_AES_KEYLEN, nullptr, 0,
                                tag, sizeof(tag)) == TC_OK);
    REQUIRE(TC_AES_CMAC(kat_key, nullptr, 0, expected, sizeof(expected)) == TC_OK);
    CHECK(std::memcmp(tag, expected, sizeof(tag)) == 0);
    CHECK(tiny_crypto::aes_cmac(kat_key, TC_AES_KEYLEN - 1, nullptr, 0,
                                tag, sizeof(tag)) == TC_ERROR);
    CHECK(tiny_crypto::aes_cmac(kat_key, TC_AES_KEYLEN, nullptr, 1,
                                tag, sizeof(tag)) == TC_ERROR);
}
#endif

#if TC_AES_ENABLE_CCM
TEST_CASE("AES CCM authentication status") {
    const uint8_t* const key =
#if TC_AES_KEY_BITS == 128
        ccm_rfc_key;
#else
        kat_key;
#endif
    uint8_t ciphertext[sizeof(ccm_rfc_plaintext)];
    uint8_t recovered[sizeof(ccm_rfc_plaintext)];
    uint8_t tag[sizeof(ccm_rfc_tag)];
    REQUIRE(tiny_crypto::ccm_encrypt(key, ccm_rfc_nonce, sizeof(ccm_rfc_nonce),
              ccm_rfc_aad, sizeof(ccm_rfc_aad), ccm_rfc_plaintext,
              sizeof(ccm_rfc_plaintext), ciphertext, tag, sizeof(tag)) == TC_OK);
#if TC_AES_KEY_BITS == 128
    CHECK(std::memcmp(ciphertext, ccm_rfc_ciphertext, sizeof(ciphertext)) == 0);
    CHECK(std::memcmp(tag, ccm_rfc_tag, sizeof(tag)) == 0);
#endif
    CHECK(tiny_crypto::ccm_decrypt(key, ccm_rfc_nonce, sizeof(ccm_rfc_nonce),
              ccm_rfc_aad, sizeof(ccm_rfc_aad), ciphertext, sizeof(ciphertext),
              tag, sizeof(tag), recovered) == TC_OK);
    CHECK(std::memcmp(recovered, ccm_rfc_plaintext, sizeof(recovered)) == 0);
    tag[0] ^= 1;
    CHECK(tiny_crypto::ccm_decrypt(key, ccm_rfc_nonce, sizeof(ccm_rfc_nonce),
              ccm_rfc_aad, sizeof(ccm_rfc_aad), ciphertext, sizeof(ciphertext),
              tag, sizeof(tag), recovered) == TC_MISMATCH);
}
#endif

#if TC_AES_ENABLE_EAX
TEST_CASE("AES EAX wrappers round trip and preserve mismatch") {
    uint8_t nonce[16] = { 0 };
    const uint8_t aad[] = { 1, 2, 3 };
    const uint8_t plaintext[] = { 4, 5, 6, 7, 8, 9, 10 };
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t recovered[sizeof(plaintext)];
    uint8_t tag[16];
    REQUIRE(tiny_crypto::eax_encrypt(kat_key, nonce, sizeof(nonce), aad, sizeof(aad),
              plaintext, sizeof(plaintext), ciphertext, tag, sizeof(tag)) == TC_OK);
    CHECK(tiny_crypto::eax_decrypt(kat_key, nonce, sizeof(nonce), aad, sizeof(aad),
              ciphertext, sizeof(ciphertext), tag, sizeof(tag), recovered) == TC_OK);
    CHECK(std::memcmp(recovered, plaintext, sizeof(plaintext)) == 0);
    tag[0] ^= 1;
    CHECK(tiny_crypto::eax_decrypt(kat_key, nonce, sizeof(nonce), aad, sizeof(aad),
              ciphertext, sizeof(ciphertext), tag, sizeof(tag), recovered) == TC_MISMATCH);
    CHECK(tiny_crypto::eax_encrypt(kat_key, nonce, sizeof(nonce), aad, sizeof(aad),
              plaintext, sizeof(plaintext), ciphertext, tag,
              TC_AES_EAX_MIN_TAG_LEN - 1) == TC_ERROR);
}
#endif

#if TC_AES_ENABLE_EAX_PRIME
TEST_CASE("AES EAX-prime wrappers round trip and preserve mismatch") {
    const uint8_t cleartext[] = { 1, 2, 3 };
    const uint8_t plaintext[] = { 4, 5, 6, 7, 8 };
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t recovered[sizeof(plaintext)];
    uint8_t tag[TC_AES_EAX_PRIME_TAG_LEN];
    REQUIRE(tiny_crypto::eax_prime_encrypt(kat_key, cleartext, sizeof(cleartext),
              plaintext, sizeof(plaintext), ciphertext, tag) == TC_OK);
    CHECK(tiny_crypto::eax_prime_decrypt(kat_key, cleartext, sizeof(cleartext),
              ciphertext, sizeof(ciphertext), tag, recovered) == TC_OK);
    CHECK(std::memcmp(recovered, plaintext, sizeof(plaintext)) == 0);
    tag[0] ^= 1;
    CHECK(tiny_crypto::eax_prime_decrypt(kat_key, cleartext, sizeof(cleartext),
              ciphertext, sizeof(ciphertext), tag, recovered) == TC_MISMATCH);
}
#endif

#if TC_AES_ENABLE_SIV
TEST_CASE("AES SIV wrappers bind associated data") {
    std::array<uint8_t, TC_AES_SIV_KEYLEN> key{};
    const uint8_t ad0[] = { 1, 2, 3 };
    const uint8_t ad1[] = { 4, 5 };
    const uint8_t* ad[] = { ad0, ad1 };
    const size_t ad_lens[] = { sizeof(ad0), sizeof(ad1) };
    const uint8_t plaintext[] = { 6, 7, 8, 9, 10, 11, 12 };
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t recovered[sizeof(plaintext)];
    uint8_t synthetic_iv[TC_AES_SIV_V_LEN];
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(0x20u + i);
    REQUIRE(tiny_crypto::siv_encrypt(key.data(), ad, ad_lens, 2, plaintext,
              sizeof(plaintext), synthetic_iv, ciphertext) == TC_OK);
    CHECK(tiny_crypto::siv_decrypt(key.data(), ad, ad_lens, 2, synthetic_iv,
              ciphertext, sizeof(ciphertext), recovered) == TC_OK);
    CHECK(std::memcmp(recovered, plaintext, sizeof(plaintext)) == 0);
    CHECK(tiny_crypto::siv_decrypt(key.data(), ad, ad_lens, 1, synthetic_iv,
              ciphertext, sizeof(ciphertext), recovered) == TC_MISMATCH);
    for (size_t i = 0; i < sizeof(recovered); ++i)
        CHECK(recovered[i] == 0);
}
#endif
