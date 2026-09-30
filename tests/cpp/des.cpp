/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

#include <cstring>

#include "doctest.h"
#include <tiny_crypto/des.hpp>
#include "test_vectors.h"

TEST_CASE("DES initialization returns status")
{
  tiny_crypto::DES des;
  CHECK(des.init({des_test_key, sizeof(des_test_key)}) == TC_OK);
  CHECK(des.init({des_test_key, sizeof(des_test_key) - 1}) == TC_ERROR);
  CHECK(des.init({nullptr, sizeof(des_test_key)}) == TC_ERROR);
#if TC_DES_ENABLE_TDES
  CHECK(des.init({tdes2_key, sizeof(tdes2_key)}) == TC_OK);
  CHECK(des.get_c_ctx().triple == 1);
  CHECK(des.init({tdes3_key, sizeof(tdes3_key)}) == TC_OK);
  CHECK(des.init({tdes3_key, 12}) == TC_ERROR);
  CHECK(des.get_c_ctx().active == 0);
  CHECK(des.init(des_test_key) == TC_OK);
  CHECK(des.get_c_ctx().triple == 0);
#else
  CHECK(des.init({tdes2_key, sizeof(tdes2_key)}) == TC_ERROR);
#endif
}

#if TC_DES_ENABLE_ECB
TEST_CASE("DES re-init with a wrong key length clears the previous key")
{
  tiny_crypto::DES des;
  uint8_t block[TC_DES_BLOCKLEN];
  std::memcpy(block, des_test_pt, sizeof(block));
  REQUIRE(des.init({des_test_key, sizeof(des_test_key)}) == TC_OK);
  CHECK(des.init({des_test_key, sizeof(des_test_key) - 1}) == TC_ERROR);
  CHECK(des.encrypt_ecb(block) == TC_ERROR);
  CHECK(std::memcmp(block, des_test_pt, sizeof(block)) == 0);
}
#endif

#if TC_DES_ENABLE_CTR
TEST_CASE("DES IV re-init with a wrong key length clears the previous key")
{
  tiny_crypto::DES des;
  uint8_t data[TC_DES_BLOCKLEN];
  std::memcpy(data, des_test_pt, sizeof(data));
  REQUIRE(des.init({des_test_key, sizeof(des_test_key)}, {des_ctr_iv, sizeof(des_ctr_iv)}) ==
          TC_OK);
  CHECK(des.init({des_test_key, sizeof(des_test_key) + 1}, {des_ctr_iv, sizeof(des_ctr_iv)}) ==
        TC_ERROR);
  CHECK(des.xcrypt_ctr(data, sizeof(data)) == TC_ERROR);
  CHECK(std::memcmp(data, des_test_pt, sizeof(data)) == 0);
}
#endif

#if TC_DES_ENABLE_CTR
TEST_CASE("DES IV re-init with a NULL IV clears the previous key")
{
  tiny_crypto::DES des;
  uint8_t data[TC_DES_BLOCKLEN];
  std::memcpy(data, des_test_pt, sizeof(data));
  REQUIRE(des.init({des_test_key, sizeof(des_test_key)}, {des_ctr_iv, sizeof(des_ctr_iv)}) ==
          TC_OK);
  CHECK(des.init({des_test_key, sizeof(des_test_key)}, {nullptr, TC_DES_BLOCKLEN}) == TC_ERROR);
  CHECK(des.xcrypt_ctr(data, sizeof(data)) == TC_ERROR);
  CHECK(std::memcmp(data, des_test_pt, sizeof(data)) == 0);
}
#endif

#if TC_DES_NEEDS_IV
/* A key alone loads no IV. Each IV mode returns TC_ERROR with the buffer
 * unchanged until set_iv starts a message. */
TEST_CASE("DES IV modes fail after a key-only init until set_iv")
{
  tiny_crypto::DES des;
  uint8_t data[TC_DES_BLOCKLEN];
  const auto expect_iv_required = [&](TC_status (*run)(tiny_crypto::DES&, uint8_t*),
                                      const uint8_t* ciphertext) {
    std::memcpy(data, des_test_pt, sizeof data);
    REQUIRE(des.init(des_test_key) == TC_OK);
    CHECK(run(des, data) == TC_ERROR);
    CHECK(std::memcmp(data, des_test_pt, sizeof data) == 0);
    REQUIRE(des.set_iv(des_cbc_iv) == TC_OK);
    CHECK(run(des, data) == TC_OK);
    CHECK(std::memcmp(data, ciphertext, sizeof data) == 0);
  };
  (void)expect_iv_required;
#if TC_DES_ENABLE_CBC
  expect_iv_required([](tiny_crypto::DES& d, uint8_t* p) { return d.encrypt_cbc(p, 8); },
                     des_cbc_ct);
  std::memcpy(data, des_test_pt, sizeof data);
  REQUIRE(des.init(des_test_key) == TC_OK);
  CHECK(des.decrypt_cbc(data, sizeof data) == TC_ERROR);
  CHECK(std::memcmp(data, des_test_pt, sizeof data) == 0);
#endif
#if TC_DES_ENABLE_OFB
  expect_iv_required([](tiny_crypto::DES& d, uint8_t* p) { return d.xcrypt_ofb(p, 8); },
                     des_ofb_ct);
#endif
#if TC_DES_ENABLE_CFB64
  expect_iv_required([](tiny_crypto::DES& d, uint8_t* p) { return d.encrypt_cfb64(p, 8); },
                     des_cfb64_ct);
#endif
#if TC_DES_ENABLE_CFB8
  expect_iv_required([](tiny_crypto::DES& d, uint8_t* p) { return d.encrypt_cfb8(p, 8); },
                     des_cfb8_ct);
#endif
#if TC_DES_ENABLE_CFB1
  std::memcpy(data, des_test_pt, sizeof data);
  REQUIRE(des.init(des_test_key) == TC_OK);
  CHECK(des.encrypt_cfb1(data, 8 * sizeof data) == TC_ERROR);
  CHECK(std::memcmp(data, des_test_pt, sizeof data) == 0);
  REQUIRE(des.set_iv(des_cbc_iv) == TC_OK);
  CHECK(des.encrypt_cfb1(data, 8 * sizeof data) == TC_OK);
#endif
#if TC_DES_ENABLE_CTR
  uint8_t counter_data[sizeof des_ctr_pt];
  std::memcpy(counter_data, des_ctr_pt, sizeof counter_data);
  REQUIRE(des.init(des_test_key) == TC_OK);
  CHECK(des.xcrypt_ctr(counter_data, sizeof counter_data) == TC_ERROR);
  CHECK(std::memcmp(counter_data, des_ctr_pt, sizeof counter_data) == 0);
  REQUIRE(des.set_iv(des_ctr_iv) == TC_OK);
  CHECK(des.xcrypt_ctr(counter_data, sizeof counter_data) == TC_OK);
  CHECK(std::memcmp(counter_data, des_ctr_ct, sizeof counter_data) == 0);
#endif
}
#endif

#if TC_DES_ENABLE_ECB
TEST_CASE("DES ECB wrapper")
{
  tiny_crypto::DES des;
  uint8_t block[TC_DES_BLOCKLEN];
  REQUIRE(des.init({des_test_key, sizeof(des_test_key)}) == TC_OK);
  std::memcpy(block, des_test_pt, sizeof(block));
  CHECK(des.encrypt_ecb(block) == TC_OK);
  CHECK(std::memcmp(block, des_test_ct, sizeof(block)) == 0);
  CHECK(des.decrypt_ecb(block) == TC_OK);
  CHECK(std::memcmp(block, des_test_pt, sizeof(block)) == 0);
}
#endif

#if TC_DES_ENABLE_CBC
TEST_CASE("DES CBC wrapper")
{
  tiny_crypto::DES des;
  uint8_t block[TC_DES_BLOCKLEN];
  REQUIRE(des.init({des_test_key, sizeof(des_test_key)}, {des_cbc_iv, sizeof(des_cbc_iv)}) ==
          TC_OK);
  std::memcpy(block, des_test_pt, sizeof(block));
  CHECK(des.encrypt_cbc(block, sizeof(block)) == TC_OK);
  CHECK(std::memcmp(block, des_cbc_ct, sizeof(block)) == 0);
  CHECK(des.set_iv(des_cbc_iv) == TC_OK);
  CHECK(des.decrypt_cbc(block, sizeof(block)) == TC_OK);
  CHECK(std::memcmp(block, des_test_pt, sizeof(block)) == 0);
  CHECK(des.encrypt_cbc(block, sizeof(block) - 1) == TC_ERROR);
}
#endif

#if TC_DES_ENABLE_CTR
TEST_CASE("DES CTR round trip")
{
  tiny_crypto::DES des;
  uint8_t data[13];
  uint8_t original[13];
  for (size_t i = 0; i < sizeof(data); ++i)
    data[i] = original[i] = static_cast<uint8_t>(i);
  REQUIRE(des.init({des_test_key, sizeof(des_test_key)}, {des_ctr_iv, sizeof(des_ctr_iv)}) ==
          TC_OK);
  CHECK(des.xcrypt_ctr(data, sizeof(data)) == TC_OK);
  CHECK(des.set_iv({des_ctr_iv, sizeof(des_ctr_iv)}) == TC_OK);
  CHECK(des.xcrypt_ctr(data, sizeof(data)) == TC_OK);
  CHECK(std::memcmp(data, original, sizeof(data)) == 0);

  uint8_t known[sizeof(des_ctr_pt)];
  std::memcpy(known, des_ctr_pt, sizeof(known));
  REQUIRE(des.set_iv({des_ctr_iv, sizeof(des_ctr_iv)}) == TC_OK);
  CHECK(des.xcrypt_ctr(known, 5) == TC_OK);
  CHECK(des.xcrypt_ctr(known + 5, sizeof(known) - 5) == TC_OK);
  CHECK(std::memcmp(known, des_ctr_ct, sizeof(known)) == 0);

  /* Key and IV arrays deduce their lengths. A wrong key size clears the key. */
  std::memcpy(known, des_ctr_pt, sizeof(known));
  REQUIRE(des.init(des_test_key, des_ctr_iv) == TC_OK);
  CHECK(des.xcrypt_ctr(known, sizeof(known)) == TC_OK);
  CHECK(std::memcmp(known, des_ctr_ct, sizeof(known)) == 0);
  const uint8_t short_key[TC_DES_KEYLEN - 1] = {0};
  CHECK(des.init(short_key, des_ctr_iv) == TC_ERROR);
  CHECK(des.xcrypt_ctr(known, sizeof(known)) == TC_ERROR);
  CHECK(noexcept(des.init(des_test_key, des_ctr_iv)));
}
#endif

#if TC_DES_ENABLE_CFB64
TEST_CASE("DES CFB64 wrapper known answer")
{
  tiny_crypto::DES des;
  uint8_t data[sizeof(des_test_pt)];
  REQUIRE(des.init({des_test_key, sizeof(des_test_key)}, {des_cbc_iv, sizeof(des_cbc_iv)}) ==
          TC_OK);
  std::memcpy(data, des_test_pt, sizeof(data));
  CHECK(des.encrypt_cfb64(data, sizeof(data)) == TC_OK);
  CHECK(std::memcmp(data, des_cfb64_ct, sizeof(data)) == 0);
  REQUIRE(des.set_iv({des_cbc_iv, sizeof(des_cbc_iv)}) == TC_OK);
  CHECK(des.decrypt_cfb64(data, sizeof(data)) == TC_OK);
  CHECK(std::memcmp(data, des_test_pt, sizeof(data)) == 0);
}
#endif

#if TC_DES_ENABLE_CFB8
TEST_CASE("DES CFB8 wrapper known answer")
{
  tiny_crypto::DES des;
  uint8_t data[sizeof(des_test_pt)];
  REQUIRE(des.init({des_test_key, sizeof(des_test_key)}, {des_cbc_iv, sizeof(des_cbc_iv)}) ==
          TC_OK);
  std::memcpy(data, des_test_pt, sizeof(data));
  CHECK(des.encrypt_cfb8(data, sizeof(data)) == TC_OK);
  CHECK(std::memcmp(data, des_cfb8_ct, sizeof(data)) == 0);
  REQUIRE(des.set_iv({des_cbc_iv, sizeof(des_cbc_iv)}) == TC_OK);
  CHECK(des.decrypt_cfb8(data, sizeof(data)) == TC_OK);
  CHECK(std::memcmp(data, des_test_pt, sizeof(data)) == 0);
}
#endif

#if TC_DES_ENABLE_OFB
TEST_CASE("DES OFB wrapper known answer")
{
  tiny_crypto::DES des;
  uint8_t data[sizeof(des_test_pt)];
  REQUIRE(des.init({des_test_key, sizeof(des_test_key)}, {des_cbc_iv, sizeof(des_cbc_iv)}) ==
          TC_OK);
  std::memcpy(data, des_test_pt, sizeof(data));
  CHECK(des.xcrypt_ofb(data, sizeof(data)) == TC_OK);
  CHECK(std::memcmp(data, des_ofb_ct, sizeof(data)) == 0);
}
#endif

#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB
TEST_CASE("TDEA ECB wrapper known answer")
{
  tiny_crypto::DES des;
  uint8_t data[sizeof(tdes3_pt)];
  REQUIRE(des.init({tdes3_key, sizeof(tdes3_key)}) == TC_OK);
  std::memcpy(data, tdes3_pt, sizeof(data));
  CHECK(des.encrypt_ecb(data) == TC_OK);
  CHECK(std::memcmp(data, tdes3_ecb_ct, TC_DES_BLOCKLEN) == 0);
  CHECK(des.decrypt_ecb(data) == TC_OK);
  CHECK(std::memcmp(data, tdes3_pt, TC_DES_BLOCKLEN) == 0);
}
#endif

#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CTR
TEST_CASE("TDEA CTR wrapper known answer")
{
  tiny_crypto::DES des;
  uint8_t data[sizeof(des_ctr_pt)];
  REQUIRE(des.init({tdes3_key, sizeof(tdes3_key)}, {des_ctr_iv, sizeof(des_ctr_iv)}) == TC_OK);
  std::memcpy(data, des_ctr_pt, sizeof(data));
  CHECK(des.xcrypt_ctr(data, sizeof(data)) == TC_OK);
  CHECK(std::memcmp(data, tdes3_ctr_ct, sizeof(data)) == 0);
}
#endif

#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB
TEST_CASE("DES re-init switches between TDEA and single DES")
{
  tiny_crypto::DES des;
  uint8_t block[TC_DES_BLOCKLEN];
  REQUIRE(des.init(tdes3_key) == TC_OK);
  REQUIRE(des.init(des_test_key) == TC_OK);
  std::memcpy(block, des_test_pt, sizeof(block));
  CHECK(des.encrypt_ecb(block) == TC_OK);
  CHECK(std::memcmp(block, des_test_ct, sizeof(block)) == 0);
}
#endif

#if TC_DES_ENABLE_CFB64
TEST_CASE("DES CFB64 short segment ends the message")
{
  tiny_crypto::DES des;
  uint8_t data[TC_DES_BLOCKLEN] = {0};
  REQUIRE(des.init({des_test_key, sizeof(des_test_key)}, {des_cbc_iv, sizeof(des_cbc_iv)}) ==
          TC_OK);
  CHECK(des.encrypt_cfb64(data, 3) == TC_OK);
  CHECK(des.encrypt_cfb64(data + 3, 5) == TC_ERROR);
  REQUIRE(des.set_iv({des_cbc_iv, sizeof(des_cbc_iv)}) == TC_OK);
  CHECK(des.encrypt_cfb64(data, sizeof(data)) == TC_OK);
}
#endif

#if TC_DES_ENABLE_CFB1
TEST_CASE("DES CFB1 array overload checks bit capacity")
{
  tiny_crypto::DES des;
  uint8_t data[2] = {0};
  REQUIRE(des.init({des_test_key, sizeof(des_test_key)}, {des_cbc_iv, sizeof(des_cbc_iv)}) ==
          TC_OK);
  CHECK(des.encrypt_cfb1(data, 16) == TC_OK);
  CHECK(des.encrypt_cfb1(data, 17) == TC_ERROR);
}
#endif

#if TC_DES_ENABLE_CMAC
TEST_CASE("TDEA-CMAC wrapper returns status")
{
  uint8_t tag[TC_DES_BLOCKLEN];
  CHECK(tiny_crypto::des_cmac({tdes3_key, sizeof(tdes3_key)}, {nullptr, 0}, {tag, sizeof(tag)}) ==
        TC_OK);
  CHECK(tiny_crypto::des_cmac({tdes3_key, 12}, {nullptr, 0}, {tag, sizeof(tag)}) == TC_ERROR);
}

TEST_CASE("TDEA-CMAC tag length boundary at TC_MIN_TAG_LEN")
{
  const size_t below = TC_MIN_TAG_LEN - 1;
  uint8_t full[TC_DES_BLOCKLEN];
  uint8_t tag[TC_DES_BLOCKLEN];
  REQUIRE(tiny_crypto::des_cmac({tdes3_key, sizeof(tdes3_key)}, {nullptr, 0},
                                {full, sizeof(full)}) == TC_OK);
  CHECK(tiny_crypto::des_cmac({tdes3_key, sizeof(tdes3_key)}, {nullptr, 0}, {tag, below}) ==
        TC_ERROR);
  CHECK(tiny_crypto::des_cmac({tdes3_key, sizeof(tdes3_key)}, {nullptr, 0},
                              {tag, TC_MIN_TAG_LEN}) == TC_OK);
  CHECK(tiny_crypto::des_cmac_short_tag({tdes3_key, sizeof(tdes3_key)}, {nullptr, 0},
                                        {tag, TC_MIN_TAG_LEN}) == TC_ERROR);
  CHECK(tiny_crypto::des_cmac_short_tag({tdes3_key, 12}, {nullptr, 0}, {tag, below}) == TC_ERROR);
  REQUIRE(tiny_crypto::des_cmac_short_tag({tdes3_key, sizeof(tdes3_key)}, {nullptr, 0},
                                          {tag, below}) == TC_OK);
  CHECK(std::memcmp(tag, full, below) == 0);
}
#endif

#if TC_DES_ENABLE_CMAC
namespace {
/* OpenSSL-cross-checked DES, two-key and three-key TDEA CMAC tags, shared
 * with tests/des/test.c. */
const uint8_t des_cmac_message[] = "tiny-DES-c CMAC Test!";
const size_t des_cmac_message_length = sizeof des_cmac_message - 1;
const uint8_t des_cmac_tag_des[8] = {0x0a, 0xa5, 0xf5, 0xff, 0x35, 0xe8, 0x9f, 0x6a};
const uint8_t des_cmac_tag_tdes2[8] = {0x3c, 0xc1, 0x01, 0x09, 0xae, 0x58, 0xa5, 0xa6};
const uint8_t des_cmac_tag_tdes3[8] = {0xea, 0x5e, 0x07, 0x9a, 0xac, 0x25, 0x18, 0xe9};
} // namespace

TEST_CASE("DES-CMAC one-shot and verify wrappers")
{
  using tiny_crypto::bytes;
  const bytes message = {des_cmac_message, des_cmac_message_length};
  const bytes key = {tdes2_key, sizeof tdes2_key};
  uint8_t tag[TC_DES_CMAC_TAG_MAX];
  CHECK(tiny_crypto::des_cmac({des_test_key, sizeof des_test_key}, message, {tag, sizeof tag}) ==
        TC_OK);
  CHECK(std::memcmp(tag, des_cmac_tag_des, sizeof tag) == 0);
  CHECK(tiny_crypto::des_cmac(key, message, {tag, sizeof tag}) == TC_OK);
  CHECK(std::memcmp(tag, des_cmac_tag_tdes2, sizeof tag) == 0);

  CHECK(tiny_crypto::des_cmac_verify(key, message, {des_cmac_tag_tdes2, 8}) == TC_OK);
  CHECK(tiny_crypto::des_cmac_verify(key, message, {des_cmac_tag_tdes2, TC_MIN_TAG_LEN}) == TC_OK);
  tag[TC_MIN_TAG_LEN - 1] ^= 1;
  CHECK(tiny_crypto::des_cmac_verify(key, message, {tag, TC_MIN_TAG_LEN}) == TC_MISMATCH);
  CHECK(tiny_crypto::des_cmac_verify(key, message, {tag, TC_MIN_TAG_LEN - 1}) == TC_ERROR);
  CHECK(tiny_crypto::des_cmac_verify({tdes2_key, 12}, message, {des_cmac_tag_tdes2, 8}) ==
        TC_ERROR);
  CHECK(tiny_crypto::des_cmac_verify(key, {nullptr, 1}, {des_cmac_tag_tdes2, 8}) == TC_ERROR);
  CHECK(tiny_crypto::des_cmac_verify_short_tag(key, message, {des_cmac_tag_tdes2, 4}) == TC_OK);
  CHECK(tiny_crypto::des_cmac_verify_short_tag(key, message, {des_cmac_tag_tdes2, 8}) == TC_ERROR);

  /* A bad key length leaves the tag unchanged. */
  std::memset(tag, 0x5a, sizeof tag);
  CHECK(tiny_crypto::des_cmac({tdes2_key, 15}, message, {tag, sizeof tag}) == TC_ERROR);
  for (uint8_t byte : tag)
    CHECK(byte == 0x5a);

  CHECK(noexcept(tiny_crypto::des_cmac(key, message, {tag, sizeof tag})));
  CHECK(noexcept(tiny_crypto::des_cmac_verify(key, message, {tag, sizeof tag})));
}

TEST_CASE("DES-CMAC streaming class")
{
  using tiny_crypto::bytes;
  static_assert(tiny_crypto::DES_CMAC::tag_size == TC_DES_CMAC_TAG_MAX, "full tag size");
  uint8_t tag[TC_DES_CMAC_TAG_MAX];

  tiny_crypto::DES_CMAC unkeyed;
  CHECK(unkeyed.update({des_cmac_message, 1}) == TC_ERROR);
  CHECK(unkeyed.finish(tag) == TC_ERROR);

#if TC_DES_ENABLE_TDES
  const struct {
    const uint8_t* key;
    size_t key_length;
    const uint8_t* tag;
  } cases[] = {{des_test_key, sizeof des_test_key, des_cmac_tag_des},
               {tdes2_key, sizeof tdes2_key, des_cmac_tag_tdes2},
               {tdes3_key, sizeof tdes3_key, des_cmac_tag_tdes3}};
#else
  const struct {
    const uint8_t* key;
    size_t key_length;
    const uint8_t* tag;
  } cases[] = {{des_test_key, sizeof des_test_key, des_cmac_tag_des}};
#endif
  for (const auto& c : cases) {
    CAPTURE(c.key_length);
    for (size_t split = 0; split <= des_cmac_message_length; ++split) {
      tiny_crypto::DES_CMAC mac;
      REQUIRE(mac.init({c.key, c.key_length}) == TC_OK);
      CHECK(mac.update({des_cmac_message, split}) == TC_OK);
      CHECK(mac.update({des_cmac_message + split, des_cmac_message_length - split}) == TC_OK);
      CHECK(mac.finish(tag) == TC_OK);
      CHECK(std::memcmp(tag, c.tag, sizeof tag) == 0);
      /* finish consumes the key. */
      CHECK(mac.update({des_cmac_message, 1}) == TC_ERROR);
      CHECK(mac.finish(tag) == TC_ERROR);
    }
  }

  /* A failed re-init leaves the object unkeyed. */
  tiny_crypto::DES_CMAC mac;
  REQUIRE(mac.init(des_test_key) == TC_OK);
  CHECK(mac.init({des_test_key, 7}) == TC_ERROR);
  CHECK(mac.update({des_cmac_message, 1}) == TC_ERROR);
  CHECK(mac.finish(tag) == TC_ERROR);

  /* clear abandons the message. */
  REQUIRE(mac.init(des_test_key) == TC_OK);
  CHECK(mac.update({des_cmac_message, 1}) == TC_OK);
  mac.clear();
  CHECK(mac.finish(tag) == TC_ERROR);

  CHECK(noexcept(mac.init(des_test_key)));
  CHECK(noexcept(mac.update({des_cmac_message, 1})));
  CHECK(noexcept(mac.finish(tag)));
}
#endif

#if TC_DES_ENABLE_ISO9797
namespace {
/* ISO/IEC 9797-1:2011 Annex B.4 Algorithm 3 examples with K = 0123456789abcdef
 * and K' = fedcba9876543210. */
const uint8_t iso9797_key2[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
const uint8_t iso9797_message1[] = "Now is the time for all ";
const uint8_t iso9797_message2[] = "Now is the time for it";
const uint8_t iso9797_alg3_message1_none[8] = {0xa1, 0xc7, 0x2e, 0x74, 0xea, 0x3f, 0xa9, 0xb6};
const uint8_t iso9797_alg3_message1_pad2[8] = {0xe9, 0x08, 0x62, 0x30, 0xca, 0x3b, 0xe7, 0x96};
const uint8_t iso9797_alg3_message2_pad1[8] = {0x2e, 0x2b, 0x14, 0x28, 0xcc, 0x78, 0x25, 0x4f};
const uint8_t iso9797_alg3_message2_pad2[8] = {0x5a, 0x69, 0x2c, 0xe6, 0x4f, 0x40, 0x41, 0x45};
/* Three-key tags rederived from DES-CBC and DES-ECB in tests/des/test.c. */
const uint8_t iso9797_key3[24] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                                  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
const uint8_t iso9797_alg1_3key_pad1[8] = {0x44, 0x07, 0xa0, 0x1f, 0xa8, 0x7c, 0x18, 0xe2};
const uint8_t iso9797_alg3_3key_pad2[8] = {0x5c, 0xcd, 0x8f, 0x7a, 0x05, 0xc8, 0x05, 0x22};

struct iso9797_case {
  TC_DES_ISO9797_algorithm algorithm;
  TC_DES_ISO9797_padding padding;
  tiny_crypto::bytes key;
  tiny_crypto::bytes message;
  const uint8_t* tag;
};

const iso9797_case iso9797_cases[] = {
    {TC_DES_ISO9797_ALG3,
     TC_DES_ISO9797_PAD_NONE,
     {iso9797_key2, 16},
     {iso9797_message1, 24},
     iso9797_alg3_message1_none},
    {TC_DES_ISO9797_ALG3,
     TC_DES_ISO9797_PAD2,
     {iso9797_key2, 16},
     {iso9797_message1, 24},
     iso9797_alg3_message1_pad2},
    {TC_DES_ISO9797_ALG3,
     TC_DES_ISO9797_PAD1,
     {iso9797_key2, 16},
     {iso9797_message2, 22},
     iso9797_alg3_message2_pad1},
    {TC_DES_ISO9797_ALG3,
     TC_DES_ISO9797_PAD2,
     {iso9797_key2, 16},
     {iso9797_message2, 22},
     iso9797_alg3_message2_pad2},
    {TC_DES_ISO9797_ALG1,
     TC_DES_ISO9797_PAD1,
     {iso9797_key3, 24},
     {iso9797_message1, 23},
     iso9797_alg1_3key_pad1},
    {TC_DES_ISO9797_ALG3,
     TC_DES_ISO9797_PAD2,
     {iso9797_key3, 24},
     {iso9797_message1, 23},
     iso9797_alg3_3key_pad2},
};
} // namespace

TEST_CASE("ISO 9797-1 one-shot wrappers match Annex B")
{
  uint8_t tag[TC_DES_BLOCKLEN];
  for (const iso9797_case& c : iso9797_cases) {
    CAPTURE(c.algorithm);
    CAPTURE(c.padding);
    CAPTURE(c.key.length);
    CHECK(tiny_crypto::des_iso9797_mac(c.algorithm, c.padding, c.key, c.message,
                                       {tag, sizeof tag}) == TC_OK);
    CHECK(std::memcmp(tag, c.tag, sizeof tag) == 0);
    CHECK(tiny_crypto::des_iso9797_verify(c.algorithm, c.padding, c.key, c.message,
                                          {c.tag, TC_DES_BLOCKLEN}) == TC_OK);
    tag[0] ^= 1;
    CHECK(tiny_crypto::des_iso9797_verify(c.algorithm, c.padding, c.key, c.message,
                                          {tag, sizeof tag}) == TC_MISMATCH);

    /* Truncated MACs keep the leading bytes and need the _short_tag forms. */
    uint8_t short_tag[TC_DES_BLOCKLEN];
    std::memset(short_tag, 0x5a, sizeof short_tag);
    CHECK(tiny_crypto::des_iso9797_mac(c.algorithm, c.padding, c.key, c.message, {short_tag, 4}) ==
          TC_ERROR);
    CHECK(tiny_crypto::des_iso9797_mac_short_tag(c.algorithm, c.padding, c.key, c.message,
                                                 {short_tag, 4}) == TC_OK);
    CHECK(std::memcmp(short_tag, c.tag, 4) == 0);
    CHECK(short_tag[4] == 0x5a);
    CHECK(tiny_crypto::des_iso9797_verify_short_tag(c.algorithm, c.padding, c.key, c.message,
                                                    {c.tag, 7}) == TC_OK);
    CHECK(tiny_crypto::des_iso9797_verify_short_tag(c.algorithm, c.padding, c.key, c.message,
                                                    {c.tag, 3}) == TC_ERROR);
    CHECK(tiny_crypto::des_iso9797_verify(c.algorithm, c.padding, c.key, c.message, {c.tag, 7}) ==
          TC_ERROR);
  }

  const tiny_crypto::bytes key = {iso9797_key2, sizeof iso9797_key2};
  const tiny_crypto::bytes message = {iso9797_message1, 24};
  std::memset(tag, 0x5a, sizeof tag);
  /* Single-DES keys, unknown paddings, a misaligned unpadded message and a
   * wrong tag capacity are errors that leave the tag unchanged. */
  CHECK(tiny_crypto::des_iso9797_mac(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2,
                                     {iso9797_key2, TC_DES_KEYLEN}, message,
                                     {tag, sizeof tag}) == TC_ERROR);
  CHECK(tiny_crypto::des_iso9797_mac(TC_DES_ISO9797_ALG3, static_cast<TC_DES_ISO9797_padding>(3),
                                     key, message, {tag, sizeof tag}) == TC_ERROR);
  CHECK(tiny_crypto::des_iso9797_mac(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD_NONE, key,
                                     {iso9797_message1, 23}, {tag, sizeof tag}) == TC_ERROR);
  CHECK(tiny_crypto::des_iso9797_mac(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, key, message,
                                     {tag, sizeof tag + 1}) == TC_ERROR);
  for (uint8_t byte : tag)
    CHECK(byte == 0x5a);
  CHECK(tiny_crypto::des_iso9797_verify(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, {iso9797_key2, 8},
                                        message, {iso9797_alg3_message1_pad2, 8}) == TC_ERROR);
  CHECK(noexcept(tiny_crypto::des_iso9797_mac(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, key,
                                              message, {tag, sizeof tag})));
}

TEST_CASE("ISO 9797-1 streaming class")
{
  static_assert(tiny_crypto::DES_ISO9797::tag_size == TC_DES_BLOCKLEN, "full tag size");
  uint8_t tag[TC_DES_BLOCKLEN];

  tiny_crypto::DES_ISO9797 unkeyed;
  CHECK(unkeyed.update({iso9797_message1, 1}) == TC_ERROR);
  CHECK(unkeyed.finish(tag) == TC_ERROR);

  for (const iso9797_case& c : iso9797_cases) {
    CAPTURE(c.algorithm);
    CAPTURE(c.padding);
    for (size_t split = 0; split <= c.message.length; ++split) {
      tiny_crypto::DES_ISO9797 mac;
      REQUIRE(mac.init(c.algorithm, c.padding, c.key) == TC_OK);
      CHECK(mac.update({c.message.data, split}) == TC_OK);
      CHECK(mac.update({c.message.data + split, c.message.length - split}) == TC_OK);
      CHECK(mac.finish(tag) == TC_OK);
      CHECK(std::memcmp(tag, c.tag, sizeof tag) == 0);
      /* finish consumes the key. */
      CHECK(mac.update({c.message.data, 1}) == TC_ERROR);
      CHECK(mac.finish(tag) == TC_ERROR);
    }
  }

  tiny_crypto::DES_ISO9797 mac;
  /* Array keys deduce their length. */
  REQUIRE(mac.init(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key2) == TC_OK);
  CHECK(mac.update({iso9797_message1, 24}) == TC_OK);
  CHECK(mac.finish(tag) == TC_OK);
  CHECK(std::memcmp(tag, iso9797_alg3_message1_pad2, sizeof tag) == 0);

  /* A failed re-init leaves the object unkeyed. */
  REQUIRE(mac.init(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key2) == TC_OK);
  CHECK(mac.init(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, {iso9797_key2, 8}) == TC_ERROR);
  CHECK(mac.update({iso9797_message1, 1}) == TC_ERROR);
  REQUIRE(mac.init(TC_DES_ISO9797_ALG1, TC_DES_ISO9797_PAD1, iso9797_key3) == TC_OK);
  CHECK(mac.init(static_cast<TC_DES_ISO9797_algorithm>(2), TC_DES_ISO9797_PAD1, iso9797_key3) ==
        TC_ERROR);
  CHECK(mac.finish(tag) == TC_ERROR);

  /* An unpadded message that ends mid-block fails at finish and consumes the
   * key. */
  REQUIRE(mac.init(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD_NONE, iso9797_key2) == TC_OK);
  CHECK(mac.update({iso9797_message1, 23}) == TC_OK);
  std::memset(tag, 0x5a, sizeof tag);
  CHECK(mac.finish(tag) == TC_ERROR);
  for (uint8_t byte : tag)
    CHECK(byte == 0x5a);
  CHECK(mac.update({iso9797_message1, 1}) == TC_ERROR);

  /* An update with a NULL span keeps the message state. */
  REQUIRE(mac.init(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key2) == TC_OK);
  CHECK(mac.update({iso9797_message1, 10}) == TC_OK);
  CHECK(mac.update({nullptr, 1}) == TC_ERROR);
  CHECK(mac.update({iso9797_message1 + 10, 14}) == TC_OK);
  CHECK(mac.finish(tag) == TC_OK);
  CHECK(std::memcmp(tag, iso9797_alg3_message1_pad2, sizeof tag) == 0);

  /* clear abandons the message. */
  REQUIRE(mac.init(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key2) == TC_OK);
  mac.clear();
  CHECK(mac.finish(tag) == TC_ERROR);

  CHECK(noexcept(mac.init(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key2)));
  CHECK(noexcept(mac.update({iso9797_message1, 1})));
  CHECK(noexcept(mac.finish(tag)));
}
#endif
