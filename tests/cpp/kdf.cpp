/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

#include <cstring>
#include <string>
#include <vector>

#include "doctest.h"
#include <tiny_crypto/kdf.hpp>
#include "test_vectors.h"

namespace {

struct family {
    const char* name;
    int prf_id;
    size_t output_size;
    size_t key_len;
    TC_status (*counter)(const uint8_t*, size_t,
                         const tiny_crypto::kbkdf_params&,
                         const uint8_t*, size_t, const uint8_t*, size_t,
                         uint8_t*, size_t);
    TC_status (*feedback)(const uint8_t*, size_t,
                          const tiny_crypto::kbkdf_params&,
                          const uint8_t*, size_t, const uint8_t*, size_t,
                          uint8_t*, size_t);
    TC_status (*pipeline)(const uint8_t*, size_t,
                          const tiny_crypto::kbkdf_params&,
                          const uint8_t*, size_t, uint8_t*, size_t);
};

#if TC_AES_KEY_BITS == 128
#define KDF_AES_PRF_ID KBKDF_PRF_CMAC_AES128
#elif TC_AES_KEY_BITS == 192
#define KDF_AES_PRF_ID KBKDF_PRF_CMAC_AES192
#else
#define KDF_AES_PRF_ID KBKDF_PRF_CMAC_AES256
#endif

const family families[] = {
#if TC_KBKDF_HAVE_HMAC_SHA1
    {"HMAC-SHA-1", KBKDF_PRF_HMAC_SHA1, TC_SHA1_DIGESTLEN, 32,
     tiny_crypto::kbkdf_hmac_sha1_counter, tiny_crypto::kbkdf_hmac_sha1_feedback,
     tiny_crypto::kbkdf_hmac_sha1_pipeline},
#endif
#if TC_KBKDF_HAVE_HMAC_SHA224
    {"HMAC-SHA-224", KBKDF_PRF_HMAC_SHA224, TC_SHA224_DIGESTLEN, 32,
     tiny_crypto::kbkdf_hmac_sha224_counter, tiny_crypto::kbkdf_hmac_sha224_feedback,
     tiny_crypto::kbkdf_hmac_sha224_pipeline},
#endif
#if TC_KBKDF_HAVE_HMAC_SHA256
    {"HMAC-SHA-256", KBKDF_PRF_HMAC_SHA256, TC_SHA256_DIGESTLEN, 32,
     tiny_crypto::kbkdf_hmac_sha256_counter, tiny_crypto::kbkdf_hmac_sha256_feedback,
     tiny_crypto::kbkdf_hmac_sha256_pipeline},
#endif
#if TC_KBKDF_HAVE_HMAC_SHA384
    {"HMAC-SHA-384", KBKDF_PRF_HMAC_SHA384, TC_SHA384_DIGESTLEN, 32,
     tiny_crypto::kbkdf_hmac_sha384_counter, tiny_crypto::kbkdf_hmac_sha384_feedback,
     tiny_crypto::kbkdf_hmac_sha384_pipeline},
#endif
#if TC_KBKDF_HAVE_HMAC_SHA512
    {"HMAC-SHA-512", KBKDF_PRF_HMAC_SHA512, TC_SHA512_DIGESTLEN, 32,
     tiny_crypto::kbkdf_hmac_sha512_counter, tiny_crypto::kbkdf_hmac_sha512_feedback,
     tiny_crypto::kbkdf_hmac_sha512_pipeline},
#endif
#if TC_KBKDF_HAVE_AES_CMAC
    {"AES-CMAC", KDF_AES_PRF_ID, TC_AES_CMAC_TAG_MAX, TC_AES_KEYLEN,
     tiny_crypto::kbkdf_aes_cmac_counter, tiny_crypto::kbkdf_aes_cmac_feedback,
     tiny_crypto::kbkdf_aes_cmac_pipeline},
#endif
#if TC_KBKDF_HAVE_DES_CMAC
    {"TDEA-CMAC", KBKDF_PRF_CMAC_TDES3, TC_DES_CMAC_TAG_MAX, 24,
     tiny_crypto::kbkdf_des_cmac_counter, tiny_crypto::kbkdf_des_cmac_feedback,
     tiny_crypto::kbkdf_des_cmac_pipeline},
#endif
};

const family* find_family(int prf_id) {
    for (const family& item : families) {
        if (item.prf_id == prf_id)
            return &item;
#if TC_KBKDF_HAVE_DES_CMAC
        if (prf_id == KBKDF_PRF_CMAC_TDES2 &&
            item.prf_id == KBKDF_PRF_CMAC_TDES3)
            return &item;
#endif
    }
    return nullptr;
}

} /* namespace */

TEST_CASE("KBKDF fixed input returns C status") {
    uint8_t fixed[sizeof(kbkdf_known_fixed)];
    CHECK(tiny_crypto::kbkdf_fixed_input(kbkdf_known_label,
                                         sizeof(kbkdf_known_label),
                                         kbkdf_known_context,
                                         sizeof(kbkdf_known_context), 32,
                                         fixed, sizeof(fixed)) == TC_OK);
    CHECK(std::memcmp(fixed, kbkdf_known_fixed, sizeof(fixed)) == 0);
    CHECK(tiny_crypto::kbkdf_fixed_input(nullptr, 1, nullptr, 0, 32,
                                         fixed, sizeof(fixed)) == TC_ERROR);
}

#if TC_KBKDF_HAVE_HMAC_SHA256
TEST_CASE("KBKDF HMAC-SHA-256 status wrapper") {
    const tiny_crypto::kbkdf_params params = {
        TC_KBKDF_COUNTER_32, TC_KBKDF_CTR_BEFORE_ITER, 1
    };
    uint8_t out[32];
    CHECK(tiny_crypto::kbkdf_hmac_sha256_counter(
              kbkdf_known_key, sizeof(kbkdf_known_key), params,
              nullptr, 0, kbkdf_known_fixed, sizeof(kbkdf_known_fixed),
              out, sizeof(out)) == TC_OK);
    CHECK(std::memcmp(out, kbkdf_known_out, sizeof(out)) == 0);
    CHECK(tiny_crypto::kbkdf_hmac_sha256_counter(
              nullptr, sizeof(kbkdf_known_key), params,
              nullptr, 0, kbkdf_known_fixed, sizeof(kbkdf_known_fixed),
              out, sizeof(out)) == TC_ERROR);
}
#endif

TEST_CASE("KBKDF generated vectors exercise every available C++ family") {
    unsigned ran = 0;
    for (size_t i = 0; i < KBKDF_VECTOR_COUNT; ++i) {
        const kbkdf_vector& v = kbkdf_vectors[i];
        const family* f = find_family(v.prf);
        if (f == nullptr)
            continue;
        CAPTURE(std::string(v.source));
        const tiny_crypto::kbkdf_params params = {
            v.counter_bits, v.location, v.use_counter
        };
        std::vector<uint8_t> out(v.out_len);
        TC_status status;
        if (v.mode == KBKDF_MODE_COUNTER)
            status = f->counter(v.key, v.key_len, params, v.in1, v.in1_len,
                                v.in2, v.in2_len, out.data(), out.size());
        else if (v.mode == KBKDF_MODE_FEEDBACK)
            status = f->feedback(v.key, v.key_len, params, v.iv, v.iv_len,
                                 v.in2, v.in2_len, out.data(), out.size());
        else
            status = f->pipeline(v.key, v.key_len, params, v.in2, v.in2_len,
                                 out.data(), out.size());
        CHECK(status == TC_OK);
        CHECK(std::memcmp(out.data(), v.out, v.out_len) == 0);
        ++ran;
    }
    CHECK(ran > 0);
}

TEST_CASE("KBKDF families enforce bounds, truncation and aliases") {
    uint8_t key[32];
    uint8_t fixed[20];
    uint8_t iv[6];
    for (size_t i = 0; i < sizeof(key); ++i)
        key[i] = static_cast<uint8_t>(0x50u + i);
    for (size_t i = 0; i < sizeof(fixed); ++i)
        fixed[i] = static_cast<uint8_t>(0x90u + i);
    for (size_t i = 0; i < sizeof(iv); ++i)
        iv[i] = static_cast<uint8_t>(0xe0u + i);

    for (const family& f : families) {
        CAPTURE(std::string(f.name));
        const tiny_crypto::kbkdf_params params = {
            TC_KBKDF_COUNTER_16, TC_KBKDF_CTR_AFTER_ITER, 1
        };
        std::vector<uint8_t> full(3 * f.output_size);
        std::vector<uint8_t> part(f.output_size + 1);

        REQUIRE(f.counter(key, f.key_len, params, nullptr, 0, fixed,
                          sizeof(fixed), full.data(), full.size()) == TC_OK);
        CHECK(f.counter(key, f.key_len, params, nullptr, 0, fixed,
                        sizeof(fixed), part.data(), part.size()) == TC_OK);
        CHECK(std::memcmp(full.data(), part.data(), part.size()) == 0);

        REQUIRE(f.feedback(key, f.key_len, params, iv, sizeof(iv), fixed,
                           sizeof(fixed), full.data(), full.size()) == TC_OK);
        CHECK(f.feedback(key, f.key_len, params, iv, sizeof(iv), fixed,
                         sizeof(fixed), part.data(), part.size()) == TC_OK);
        CHECK(std::memcmp(full.data(), part.data(), part.size()) == 0);

        REQUIRE(f.pipeline(key, f.key_len, params, fixed, sizeof(fixed),
                           full.data(), full.size()) == TC_OK);
        CHECK(f.pipeline(key, f.key_len, params, fixed, sizeof(fixed),
                         part.data(), part.size()) == TC_OK);
        CHECK(std::memcmp(full.data(), part.data(), part.size()) == 0);

        CHECK(f.feedback(key, f.key_len, params, nullptr, 0, fixed,
                         sizeof(fixed), part.data(), part.size()) == TC_OK);
        CHECK(f.feedback(key, f.key_len, params, nullptr, 1, fixed,
                         sizeof(fixed), part.data(), part.size()) == TC_ERROR);
        CHECK(f.counter(nullptr, f.key_len, params, nullptr, 0, fixed,
                        sizeof(fixed), part.data(), part.size()) == TC_ERROR);

        const tiny_crypto::kbkdf_params bad_bits = {
            12, TC_KBKDF_CTR_AFTER_ITER, 1
        };
        CHECK(f.counter(key, f.key_len, bad_bits, nullptr, 0, fixed,
                        sizeof(fixed), part.data(), part.size()) == TC_ERROR);

        const tiny_crypto::kbkdf_params r8 = {
            TC_KBKDF_COUNTER_8, TC_KBKDF_CTR_BEFORE_ITER, 1
        };
        std::vector<uint8_t> big(256 * f.output_size);
        CHECK(f.counter(key, f.key_len, r8, nullptr, 0, fixed, sizeof(fixed),
                        big.data(), 255 * f.output_size) == TC_OK);
        CHECK(f.counter(key, f.key_len, r8, nullptr, 0, fixed, sizeof(fixed),
                        big.data(), big.size()) == TC_ERROR);

        uint8_t shared[64] = { 0 };
        CHECK(f.counter(key, f.key_len, params, nullptr, 0, shared, 8,
                        shared, 8) == TC_ERROR);
    }
}

#if TC_KBKDF_HAVE_AES_CMAC
TEST_CASE("KBKDF AES-CMAC rejects the wrong key size") {
    const tiny_crypto::kbkdf_params params = {
        TC_KBKDF_COUNTER_32, TC_KBKDF_CTR_BEFORE_ITER, 1
    };
    uint8_t key[TC_AES_KEYLEN] = {0};
    uint8_t fixed[4] = {1, 2, 3, 4};
    uint8_t out[16];
    CHECK(tiny_crypto::kbkdf_aes_cmac_counter(
              key, sizeof(key), params, nullptr, 0, fixed, sizeof(fixed),
              out, sizeof(out)) == TC_OK);
    CHECK(tiny_crypto::kbkdf_aes_cmac_counter(
              key, sizeof(key) - 1, params, nullptr, 0, fixed, sizeof(fixed),
              out, sizeof(out)) == TC_ERROR);
}
#endif
