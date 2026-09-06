/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

#include <cstring>

#include "doctest.h"
#include <tiny_crypto/des.hpp>
#include "test_vectors.h"

TEST_CASE("DES initialization returns status") {
    tiny_crypto::DES des;
    CHECK(des.init(des_test_key, sizeof(des_test_key)) == TC_OK);
    CHECK(des.init(des_test_key, sizeof(des_test_key) - 1) == TC_ERROR);
    CHECK(des.init(nullptr, sizeof(des_test_key)) == TC_ERROR);
#if TC_DES_ENABLE_TDES
    tiny_crypto::DES3 des3;
    CHECK(des3.init(tdes2_key, sizeof(tdes2_key)) == TC_OK);
    CHECK(des3.init(tdes3_key, sizeof(tdes3_key)) == TC_OK);
    CHECK(des3.init(tdes3_key, 12) == TC_ERROR);
#endif
}

#if TC_DES_ENABLE_ECB
TEST_CASE("DES ECB wrapper") {
    tiny_crypto::DES des;
    uint8_t block[TC_DES_BLOCKLEN];
    REQUIRE(des.init(des_test_key, sizeof(des_test_key)) == TC_OK);
    std::memcpy(block, des_test_pt, sizeof(block));
    CHECK(des.encrypt_ecb(block) == TC_OK);
    CHECK(std::memcmp(block, des_test_ct, sizeof(block)) == 0);
    CHECK(des.decrypt_ecb(block) == TC_OK);
    CHECK(std::memcmp(block, des_test_pt, sizeof(block)) == 0);
}
#endif

#if TC_DES_ENABLE_CBC
TEST_CASE("DES CBC wrapper") {
    tiny_crypto::DES des;
    uint8_t block[TC_DES_BLOCKLEN];
    REQUIRE(des.init(des_test_key, sizeof(des_test_key), des_cbc_iv,
                     sizeof(des_cbc_iv)) == TC_OK);
    std::memcpy(block, des_test_pt, sizeof(block));
    CHECK(des.encrypt_cbc(block, sizeof(block)) == TC_OK);
    CHECK(std::memcmp(block, des_cbc_ct, sizeof(block)) == 0);
    CHECK(des.set_iv(des_cbc_iv, sizeof(des_cbc_iv)) == TC_OK);
    CHECK(des.decrypt_cbc(block, sizeof(block)) == TC_OK);
    CHECK(std::memcmp(block, des_test_pt, sizeof(block)) == 0);
    CHECK(des.encrypt_cbc(block, sizeof(block) - 1) == TC_ERROR);
}
#endif

#if TC_DES_ENABLE_CTR
TEST_CASE("DES CTR round trip") {
    tiny_crypto::DES des;
    uint8_t data[13];
    uint8_t original[13];
    for (size_t i = 0; i < sizeof(data); ++i)
        data[i] = original[i] = static_cast<uint8_t>(i);
    REQUIRE(des.init(des_test_key, sizeof(des_test_key), des_ctr_iv,
                     sizeof(des_ctr_iv)) == TC_OK);
    CHECK(des.xcrypt_ctr(data, sizeof(data)) == TC_OK);
    CHECK(des.set_iv(des_ctr_iv, sizeof(des_ctr_iv)) == TC_OK);
    CHECK(des.xcrypt_ctr(data, sizeof(data)) == TC_OK);
    CHECK(std::memcmp(data, original, sizeof(data)) == 0);

    uint8_t known[sizeof(des_ctr_pt)];
    std::memcpy(known, des_ctr_pt, sizeof(known));
    REQUIRE(des.set_iv(des_ctr_iv, sizeof(des_ctr_iv)) == TC_OK);
    CHECK(des.xcrypt_ctr(known, 5) == TC_OK);
    CHECK(des.xcrypt_ctr(known + 5, sizeof(known) - 5) == TC_OK);
    CHECK(std::memcmp(known, des_ctr_ct, sizeof(known)) == 0);
}
#endif

#if TC_DES_ENABLE_CFB64
TEST_CASE("DES CFB64 wrapper known answer") {
    tiny_crypto::DES des;
    uint8_t data[sizeof(des_test_pt)];
    REQUIRE(des.init(des_test_key, sizeof(des_test_key), des_cbc_iv,
                     sizeof(des_cbc_iv)) == TC_OK);
    std::memcpy(data, des_test_pt, sizeof(data));
    CHECK(des.encrypt_cfb64(data, sizeof(data)) == TC_OK);
    CHECK(std::memcmp(data, des_cfb64_ct, sizeof(data)) == 0);
    REQUIRE(des.set_iv(des_cbc_iv, sizeof(des_cbc_iv)) == TC_OK);
    CHECK(des.decrypt_cfb64(data, sizeof(data)) == TC_OK);
    CHECK(std::memcmp(data, des_test_pt, sizeof(data)) == 0);
}
#endif

#if TC_DES_ENABLE_CFB8
TEST_CASE("DES CFB8 wrapper known answer") {
    tiny_crypto::DES des;
    uint8_t data[sizeof(des_test_pt)];
    REQUIRE(des.init(des_test_key, sizeof(des_test_key), des_cbc_iv,
                     sizeof(des_cbc_iv)) == TC_OK);
    std::memcpy(data, des_test_pt, sizeof(data));
    CHECK(des.encrypt_cfb8(data, sizeof(data)) == TC_OK);
    CHECK(std::memcmp(data, des_cfb8_ct, sizeof(data)) == 0);
    REQUIRE(des.set_iv(des_cbc_iv, sizeof(des_cbc_iv)) == TC_OK);
    CHECK(des.decrypt_cfb8(data, sizeof(data)) == TC_OK);
    CHECK(std::memcmp(data, des_test_pt, sizeof(data)) == 0);
}
#endif

#if TC_DES_ENABLE_OFB
TEST_CASE("DES OFB wrapper known answer") {
    tiny_crypto::DES des;
    uint8_t data[sizeof(des_test_pt)];
    REQUIRE(des.init(des_test_key, sizeof(des_test_key), des_cbc_iv,
                     sizeof(des_cbc_iv)) == TC_OK);
    std::memcpy(data, des_test_pt, sizeof(data));
    CHECK(des.xcrypt_ofb(data, sizeof(data)) == TC_OK);
    CHECK(std::memcmp(data, des_ofb_ct, sizeof(data)) == 0);
}
#endif

#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB
TEST_CASE("TDEA ECB wrapper known answer") {
    tiny_crypto::DES3 des;
    uint8_t data[sizeof(tdes3_pt)];
    REQUIRE(des.init(tdes3_key, sizeof(tdes3_key)) == TC_OK);
    std::memcpy(data, tdes3_pt, sizeof(data));
    CHECK(des.encrypt_ecb(data) == TC_OK);
    CHECK(std::memcmp(data, tdes3_ecb_ct, TC_DES_BLOCKLEN) == 0);
    CHECK(des.decrypt_ecb(data) == TC_OK);
    CHECK(std::memcmp(data, tdes3_pt, TC_DES_BLOCKLEN) == 0);
}
#endif

#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CTR
TEST_CASE("TDEA CTR wrapper known answer") {
    tiny_crypto::DES3 des;
    uint8_t data[sizeof(des_ctr_pt)];
    REQUIRE(des.init(tdes3_key, sizeof(tdes3_key), des_ctr_iv,
                     sizeof(des_ctr_iv)) == TC_OK);
    std::memcpy(data, des_ctr_pt, sizeof(data));
    CHECK(des.xcrypt_ctr(data, sizeof(data)) == TC_OK);
    CHECK(std::memcmp(data, tdes3_ctr_ct, sizeof(data)) == 0);
}
#endif

#if TC_DES_ENABLE_CFB1
TEST_CASE("DES CFB1 array overload checks bit capacity") {
    tiny_crypto::DES des;
    uint8_t data[2] = {0};
    REQUIRE(des.init(des_test_key, sizeof(des_test_key), des_cbc_iv,
                     sizeof(des_cbc_iv)) == TC_OK);
    CHECK(des.encrypt_cfb1(data, 16) == TC_OK);
    CHECK(des.encrypt_cfb1(data, 17) == TC_ERROR);
}
#endif

#if TC_DES_ENABLE_CMAC
TEST_CASE("TDEA-CMAC wrapper returns status") {
    uint8_t tag[TC_DES_BLOCKLEN];
    CHECK(tiny_crypto::des_cmac(tdes3_key, sizeof(tdes3_key), nullptr, 0,
                                tag, sizeof(tag)) == TC_OK);
    CHECK(tiny_crypto::des_cmac(tdes3_key, 12, nullptr, 0,
                                tag, sizeof(tag)) == TC_ERROR);
}
#endif
