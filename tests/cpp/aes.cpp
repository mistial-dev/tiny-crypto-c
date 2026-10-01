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
template <size_t N> std::array<uint8_t, N> bytes(const uint8_t* source)
{
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

TEST_CASE("AES initialization returns status")
{
  tiny_crypto::AES aes;
  CHECK(aes.init({kat_key, TC_AES_KEYLEN}) == TC_OK);
  CHECK(aes.init({kat_key, TC_AES_KEYLEN - 1}) == TC_ERROR);
  CHECK(aes.init({nullptr, TC_AES_KEYLEN}) == TC_ERROR);
#if TC_AES_ENABLE_CBC || TC_AES_ENABLE_CTR || TC_AES_ENABLE_OFB
  CHECK(aes.init({kat_key, TC_AES_KEYLEN}, {nist_iv, sizeof(nist_iv)}) == TC_OK);
  CHECK(aes.set_iv({nist_iv, sizeof(nist_iv) - 1}) == TC_ERROR);
#endif
}

#if TC_AES_ENABLE_CTR
TEST_CASE("AES IV re-init with a NULL IV clears the previous key")
{
  tiny_crypto::AES aes;
  uint8_t data[TC_AES_BLOCKLEN];
  std::memcpy(data, nist_plaintext, sizeof(data));
  REQUIRE(aes.init({kat_key, TC_AES_KEYLEN}, {nist_ctr_iv, sizeof(nist_ctr_iv)}) == TC_OK);
  CHECK(aes.init({kat_key, TC_AES_KEYLEN}, {nullptr, TC_AES_BLOCKLEN}) == TC_ERROR);
  CHECK(aes.xcrypt_ctr(data) == TC_ERROR);
  CHECK(std::memcmp(data, nist_plaintext, sizeof(data)) == 0);
}
#endif

#if TC_AES_ENABLE_CBC || TC_AES_ENABLE_CTR || TC_AES_ENABLE_OFB
/* A key alone loads no IV. Each IV mode returns TC_ERROR with the buffer
 * unchanged until set_iv starts a message. */
TEST_CASE("AES IV modes fail after a key-only init until set_iv")
{
  tiny_crypto::AES aes;
  uint8_t data[2 * TC_AES_BLOCKLEN];
  std::memcpy(data, nist_plaintext, sizeof data);
#if TC_AES_ENABLE_CBC
  REQUIRE(aes.init({kat_key, TC_AES_KEYLEN}) == TC_OK);
  CHECK(aes.encrypt_cbc(data) == TC_ERROR);
  CHECK(aes.decrypt_cbc(data) == TC_ERROR);
  CHECK(std::memcmp(data, nist_plaintext, sizeof data) == 0);
  REQUIRE(aes.set_iv(nist_iv) == TC_OK);
  CHECK(aes.encrypt_cbc(data) == TC_OK);
  CHECK(std::memcmp(data, kat_cbc, sizeof data) == 0);
  std::memcpy(data, nist_plaintext, sizeof data);
#endif
#if TC_AES_ENABLE_CTR
  REQUIRE(aes.init({kat_key, TC_AES_KEYLEN}) == TC_OK);
  CHECK(aes.xcrypt_ctr(data) == TC_ERROR);
  CHECK(std::memcmp(data, nist_plaintext, sizeof data) == 0);
  REQUIRE(aes.set_iv(nist_ctr_iv) == TC_OK);
  CHECK(aes.xcrypt_ctr(data) == TC_OK);
  CHECK(std::memcmp(data, kat_ctr, sizeof data) == 0);
  std::memcpy(data, nist_plaintext, sizeof data);
#endif
#if TC_AES_ENABLE_OFB
  REQUIRE(aes.init({kat_key, TC_AES_KEYLEN}) == TC_OK);
  CHECK(aes.xcrypt_ofb(data) == TC_ERROR);
  CHECK(std::memcmp(data, nist_plaintext, sizeof data) == 0);
  REQUIRE(aes.set_iv(nist_iv) == TC_OK);
  CHECK(aes.xcrypt_ofb(data) == TC_OK);
  CHECK(std::memcmp(data, kat_ofb, sizeof data) == 0);
#endif
}
#endif

#if TC_AES_ENABLE_ECB
TEST_CASE("AES ECB wrapper")
{
  tiny_crypto::AES aes;
  uint8_t block[TC_AES_BLOCKLEN];
  REQUIRE(aes.init({kat_key, TC_AES_KEYLEN}) == TC_OK);
  std::memcpy(block, nist_plaintext, sizeof(block));
  CHECK(aes.encrypt_ecb(block) == TC_OK);
  CHECK(std::memcmp(block, kat_ecb, sizeof(block)) == 0);
  CHECK(aes.decrypt_ecb(block) == TC_OK);
  CHECK(std::memcmp(block, nist_plaintext, sizeof(block)) == 0);
}
#endif

#if TC_AES_ENABLE_CBC
TEST_CASE("AES CBC wrapper")
{
  tiny_crypto::AES aes;
  uint8_t data[64];
  REQUIRE(aes.init({kat_key, TC_AES_KEYLEN}, {nist_iv, sizeof(nist_iv)}) == TC_OK);
  std::memcpy(data, nist_plaintext, sizeof(data));
  CHECK(aes.encrypt_cbc(data) == TC_OK);
  CHECK(std::memcmp(data, kat_cbc, sizeof(data)) == 0);
  CHECK(aes.set_iv({nist_iv, sizeof(nist_iv)}) == TC_OK);
  CHECK(aes.decrypt_cbc(data) == TC_OK);
  CHECK(std::memcmp(data, nist_plaintext, sizeof(data)) == 0);
  CHECK(aes.encrypt_cbc(data, 15) == TC_ERROR);
}
#endif

#if TC_AES_ENABLE_CTR
TEST_CASE("AES CTR wrapper")
{
  tiny_crypto::AES aes;
  uint8_t data[64];
  REQUIRE(aes.init({kat_key, TC_AES_KEYLEN}, {nist_ctr_iv, sizeof(nist_ctr_iv)}) == TC_OK);
  std::memcpy(data, nist_plaintext, sizeof(data));
  CHECK(aes.xcrypt_ctr(data) == TC_OK);
  CHECK(std::memcmp(data, kat_ctr, sizeof(data)) == 0);

  std::memcpy(data, nist_plaintext, sizeof(data));
  REQUIRE(aes.set_iv({nist_ctr_iv, sizeof(nist_ctr_iv)}) == TC_OK);
  CHECK(aes.xcrypt_ctr(data, 5) == TC_OK);
  CHECK(aes.xcrypt_ctr(data + 5, 27) == TC_OK);
  CHECK(aes.xcrypt_ctr(data + 32, 32) == TC_OK);
  CHECK(std::memcmp(data, kat_ctr, sizeof(data)) == 0);

  uint8_t top[TC_AES_BLOCKLEN];
  uint8_t two_blocks[2 * TC_AES_BLOCKLEN] = {0};
  std::memset(top, 0xff, sizeof(top));
  REQUIRE(aes.set_iv({top, sizeof(top)}) == TC_OK);
  CHECK(aes.xcrypt_ctr(two_blocks, sizeof(two_blocks)) == TC_ERROR);

  /* Key and IV arrays deduce their lengths. A wrong key size clears the key. */
  uint8_t key[TC_AES_KEYLEN];
  std::memcpy(key, kat_key, sizeof key);
  std::memcpy(data, nist_plaintext, sizeof(data));
  REQUIRE(aes.init(key, nist_ctr_iv) == TC_OK);
  CHECK(aes.xcrypt_ctr(data) == TC_OK);
  CHECK(std::memcmp(data, kat_ctr, sizeof(data)) == 0);
  const uint8_t short_key[TC_AES_KEYLEN - 1] = {0};
  CHECK(aes.init(short_key, nist_ctr_iv) == TC_ERROR);
  CHECK(aes.xcrypt_ctr(data) == TC_ERROR);
  CHECK(noexcept(aes.init(key, nist_ctr_iv)));
}
#endif

#if TC_AES_ENABLE_OFB
TEST_CASE("AES OFB wrapper")
{
  tiny_crypto::AES aes;
  uint8_t data[64];
  REQUIRE(aes.init({kat_key, TC_AES_KEYLEN}, {nist_iv, sizeof(nist_iv)}) == TC_OK);
  std::memcpy(data, nist_plaintext, sizeof(data));
  CHECK(aes.xcrypt_ofb(data) == TC_OK);
  CHECK(std::memcmp(data, kat_ofb, sizeof(data)) == 0);
  REQUIRE(aes.set_iv({nist_iv, sizeof(nist_iv)}) == TC_OK);
  CHECK(aes.xcrypt_ofb(data, 7) == TC_OK);
  CHECK(aes.xcrypt_ofb(data + 7, sizeof(data) - 7) == TC_OK);
  CHECK(std::memcmp(data, nist_plaintext, sizeof(data)) == 0);
}
#endif

#if TC_AES_ENABLE_GCM
static void check_gcm_vector(const gcm_test_vector& v)
{
  std::vector<uint8_t> data(v.plaintext, v.plaintext + v.length);
  std::vector<uint8_t> tag(v.tag_len);
  tiny_crypto::GCM gcm;

  REQUIRE(gcm.init({v.key, v.key_len}, {v.iv, v.iv_len}, v.tag_len) == TC_OK);
  CHECK(gcm.tag_length() == v.tag_len);
  CHECK(gcm.aad_update({v.aad, v.aad_len}) == TC_OK);
  const size_t split = v.length < 5 ? v.length : 5;
  CHECK(gcm.encrypt_update(data.data(), split) == TC_OK);
  CHECK(gcm.encrypt_update(data.data() + split, v.length - split) == TC_OK);
  CHECK(gcm.encrypt_finish({tag.data(), tag.size()}) == TC_OK);
  CHECK(std::memcmp(data.data(), v.ciphertext, v.length) == 0);
  CHECK(std::memcmp(tag.data(), v.tag, v.tag_len) == 0);

  const tiny_crypto::bytes key = {v.key, v.key_len};
  CHECK(tiny_crypto::gcm_decrypt(key, {v.iv, v.iv_len}, {v.aad, v.aad_len}, {data.data(), v.length},
                                 {tag.data(), tag.size()}, {data.data(), v.length}) == TC_OK);
  CHECK(std::memcmp(data.data(), v.plaintext, v.length) == 0);

  std::vector<uint8_t> ciphertext(v.length + 1);
  std::vector<uint8_t> one_shot_tag(v.tag_len);
  CHECK(tiny_crypto::gcm_encrypt(key, {v.iv, v.iv_len}, {v.aad, v.aad_len}, {v.plaintext, v.length},
                                 {ciphertext.data(), v.length},
                                 {one_shot_tag.data(), one_shot_tag.size()}) == TC_OK);
  CHECK(std::memcmp(ciphertext.data(), v.ciphertext, v.length) == 0);
  CHECK(std::memcmp(one_shot_tag.data(), v.tag, v.tag_len) == 0);
}

TEST_CASE("AES GCM known answers and state errors")
{
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
    if (gcm_test_vectors[i].key_len == TC_AES_KEYLEN) {
      v = &gcm_test_vectors[i];
      break;
    }
  REQUIRE(v != nullptr);
  std::vector<uint8_t> data(v->ciphertext, v->ciphertext + v->length);
  std::vector<uint8_t> tag(v->tag, v->tag + v->tag_len);
  std::vector<uint8_t> output(data.size(), 0x5a);
  const tiny_crypto::bytes key = {v->key, v->key_len};

  /* A wrong key length is rejected before any write. */
  CHECK(tiny_crypto::gcm_decrypt({v->key, v->key_len - 1}, {v->iv, v->iv_len}, {v->aad, v->aad_len},
                                 {data.data(), data.size()}, {tag.data(), tag.size()},
                                 {output.data(), output.size()}) == TC_ERROR);
  CHECK(output == std::vector<uint8_t>(data.size(), 0x5a));

  /* A tag mismatch wipes the plaintext output. */
  tag[0] ^= 1;
  CHECK(tiny_crypto::gcm_decrypt(key, {v->iv, v->iv_len}, {v->aad, v->aad_len},
                                 {data.data(), data.size()}, {tag.data(), tag.size()},
                                 {output.data(), output.size()}) == TC_MISMATCH);
  CHECK(output == std::vector<uint8_t>(data.size(), 0));
  tag[0] ^= 1;

  /* Four-byte tags need the explicit short-tag form (SP 800-38D appendix C). */
  uint8_t short_tag[4];
  CHECK(tiny_crypto::gcm_encrypt(key, {v->iv, v->iv_len}, {v->aad, v->aad_len},
                                 {v->plaintext, v->length}, {output.data(), output.size()},
                                 {short_tag, sizeof(short_tag)}) == TC_ERROR);
  REQUIRE(tiny_crypto::gcm_encrypt_short_tag(
              key, {v->iv, v->iv_len}, {v->aad, v->aad_len}, {v->plaintext, v->length},
              {output.data(), output.size()}, {short_tag, sizeof(short_tag)}) == TC_OK);
  CHECK(tiny_crypto::gcm_decrypt_short_tag(
            key, {v->iv, v->iv_len}, {v->aad, v->aad_len}, {output.data(), output.size()},
            {short_tag, sizeof(short_tag)}, {output.data(), output.size()}) == TC_OK);
  CHECK(std::memcmp(output.data(), v->plaintext, v->length) == 0);

  tiny_crypto::GCM gcm;
  REQUIRE(gcm.init({v->key, v->key_len}, {v->iv, v->iv_len}, v->tag_len) == TC_OK);
  CHECK(gcm.encrypt_update(data.data(), data.size()) == TC_OK);
  CHECK(gcm.aad_update({v->aad, v->aad_len}) == TC_ERROR);
  CHECK(gcm.encrypt_finish({tag.data(), tag.size() - 1}) == TC_ERROR);
  CHECK(gcm.init({v->key, v->key_len - 1}, {v->iv, v->iv_len}, v->tag_len) == TC_ERROR);
}
#endif

#if TC_AES_ENABLE_CMAC
TEST_CASE("AES CMAC wrapper returns status")
{
  uint8_t tag[TC_AES_BLOCKLEN];
  uint8_t expected[TC_AES_BLOCKLEN];
  CHECK(tiny_crypto::aes_cmac({kat_key, TC_AES_KEYLEN}, {nullptr, 0}, {tag, sizeof(tag)}) == TC_OK);
  REQUIRE(TC_AES_CMAC(TC_bytes{kat_key, TC_AES_KEYLEN}, TC_bytes{nullptr, 0},
                      TC_buffer{expected, sizeof(expected)}) == TC_OK);
  CHECK(std::memcmp(tag, expected, sizeof(tag)) == 0);
  CHECK(tiny_crypto::aes_cmac({kat_key, TC_AES_KEYLEN - 1}, {nullptr, 0}, {tag, sizeof(tag)}) ==
        TC_ERROR);
  CHECK(tiny_crypto::aes_cmac({kat_key, TC_AES_KEYLEN}, {nullptr, 1}, {tag, sizeof(tag)}) ==
        TC_ERROR);
}

TEST_CASE("AES CMAC tag length boundary at TC_MIN_TAG_LEN")
{
  const size_t below = TC_MIN_TAG_LEN - 1;
  uint8_t full[TC_AES_BLOCKLEN];
  uint8_t tag[TC_AES_BLOCKLEN];
  REQUIRE(tiny_crypto::aes_cmac({kat_key, TC_AES_KEYLEN}, {nullptr, 0}, {full, sizeof(full)}) ==
          TC_OK);
  CHECK(tiny_crypto::aes_cmac({kat_key, TC_AES_KEYLEN}, {nullptr, 0}, {tag, below}) == TC_ERROR);
  CHECK(tiny_crypto::aes_cmac({kat_key, TC_AES_KEYLEN}, {nullptr, 0}, {tag, TC_MIN_TAG_LEN}) ==
        TC_OK);
  CHECK(std::memcmp(tag, full, TC_MIN_TAG_LEN) == 0);
  CHECK(tiny_crypto::aes_cmac_short_tag({kat_key, TC_AES_KEYLEN}, {nullptr, 0},
                                        {tag, TC_MIN_TAG_LEN}) == TC_ERROR);
  CHECK(tiny_crypto::aes_cmac_short_tag({kat_key, TC_AES_KEYLEN - 1}, {nullptr, 0}, {tag, below}) ==
        TC_ERROR);
  CHECK(tiny_crypto::aes_cmac_short_tag({kat_key, TC_AES_KEYLEN}, {nullptr, 0}, {tag, 0}) ==
        TC_ERROR);
  REQUIRE(tiny_crypto::aes_cmac_short_tag({kat_key, TC_AES_KEYLEN}, {nullptr, 0}, {tag, below}) ==
          TC_OK);
  CHECK(std::memcmp(tag, full, below) == 0);
}
#endif

#if TC_AES_ENABLE_CMAC
namespace {
/* SP 800-38B Appendix D examples 3, 7 and 11: the first 40 bytes of the
 * sample plaintext under the sample key of the configured size. */
#if TC_AES_KEY_BITS == 128
const uint8_t cmac_40_tag[16] = {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
                                 0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};
#elif TC_AES_KEY_BITS == 192
const uint8_t cmac_40_tag[16] = {0x8a, 0x1d, 0xe5, 0xbe, 0x2e, 0xb3, 0x1a, 0xad,
                                 0x08, 0x9a, 0x82, 0xe6, 0xee, 0x90, 0x8b, 0x0e};
#else
const uint8_t cmac_40_tag[16] = {0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2,
                                 0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6};
#endif
const size_t cmac_40_length = 40;
} // namespace

TEST_CASE("AES CMAC known answer and verify wrappers")
{
  const tiny_crypto::bytes key = {kat_key, TC_AES_KEYLEN};
  const tiny_crypto::bytes message = {nist_plaintext, cmac_40_length};
  uint8_t tag[TC_AES_CMAC_TAG_MAX];
  CHECK(tiny_crypto::aes_cmac(key, message, {tag, sizeof tag}) == TC_OK);
  CHECK(std::memcmp(tag, cmac_40_tag, sizeof tag) == 0);
  CHECK(tiny_crypto::aes_cmac_verify(key, message, {cmac_40_tag, sizeof cmac_40_tag}) == TC_OK);
  CHECK(tiny_crypto::aes_cmac_verify(key, message, {cmac_40_tag, TC_MIN_TAG_LEN}) == TC_OK);
  tag[TC_MIN_TAG_LEN - 1] ^= 1;
  CHECK(tiny_crypto::aes_cmac_verify(key, message, {tag, TC_MIN_TAG_LEN}) == TC_MISMATCH);
  CHECK(tiny_crypto::aes_cmac_verify(key, message, {tag, TC_MIN_TAG_LEN - 1}) == TC_ERROR);
  CHECK(tiny_crypto::aes_cmac_verify({kat_key, TC_AES_KEYLEN - 1}, message,
                                     {cmac_40_tag, sizeof cmac_40_tag}) == TC_ERROR);
  CHECK(tiny_crypto::aes_cmac_verify(key, {nullptr, 1}, {cmac_40_tag, sizeof cmac_40_tag}) ==
        TC_ERROR);
  CHECK(tiny_crypto::aes_cmac_verify_short_tag(key, message, {cmac_40_tag, 4}) == TC_OK);
  CHECK(tiny_crypto::aes_cmac_verify_short_tag(key, message, {cmac_40_tag, TC_MIN_TAG_LEN}) ==
        TC_ERROR);
  CHECK(tiny_crypto::aes_cmac_verify_short_tag({kat_key, TC_AES_KEYLEN + 1}, message,
                                               {cmac_40_tag, 4}) == TC_ERROR);

  /* A wrong key length leaves the tag unchanged. */
  std::memset(tag, 0x5a, sizeof tag);
  CHECK(tiny_crypto::aes_cmac({kat_key, TC_AES_KEYLEN + 1}, message, {tag, sizeof tag}) ==
        TC_ERROR);
  for (uint8_t byte : tag)
    CHECK(byte == 0x5a);
  CHECK(noexcept(tiny_crypto::aes_cmac_verify(key, message, {tag, sizeof tag})));
}

TEST_CASE("AES CMAC streaming class")
{
  static_assert(tiny_crypto::AES_CMAC::tag_size == TC_AES_CMAC_TAG_MAX, "full tag size");
  uint8_t tag[TC_AES_CMAC_TAG_MAX];

  tiny_crypto::AES_CMAC unkeyed;
  CHECK(unkeyed.update({nist_plaintext, 1}) == TC_ERROR);
  CHECK(unkeyed.finish(tag) == TC_ERROR);

  for (size_t split = 0; split <= cmac_40_length; ++split) {
    CAPTURE(split);
    tiny_crypto::AES_CMAC mac;
    REQUIRE(mac.init({kat_key, TC_AES_KEYLEN}) == TC_OK);
    CHECK(mac.update({nist_plaintext, split}) == TC_OK);
    CHECK(mac.update({nist_plaintext + split, cmac_40_length - split}) == TC_OK);
    CHECK(mac.finish(tag) == TC_OK);
    CHECK(std::memcmp(tag, cmac_40_tag, sizeof tag) == 0);
    /* finish consumes the key. */
    CHECK(mac.update({nist_plaintext, 1}) == TC_ERROR);
    CHECK(mac.finish(tag) == TC_ERROR);
  }

  /* A wrong key length on re-init leaves the object unkeyed. */
  tiny_crypto::AES_CMAC mac;
  REQUIRE(mac.init({kat_key, TC_AES_KEYLEN}) == TC_OK);
  CHECK(mac.init({kat_key, TC_AES_KEYLEN - 1}) == TC_ERROR);
  CHECK(mac.update({nist_plaintext, 1}) == TC_ERROR);
  CHECK(mac.finish(tag) == TC_ERROR);
  REQUIRE(mac.init({kat_key, TC_AES_KEYLEN}) == TC_OK);
  CHECK(mac.init({nullptr, TC_AES_KEYLEN}) == TC_ERROR);
  CHECK(mac.finish(tag) == TC_ERROR);

  /* clear abandons the message. */
  REQUIRE(mac.init({kat_key, TC_AES_KEYLEN}) == TC_OK);
  CHECK(mac.update({nist_plaintext, 16}) == TC_OK);
  mac.clear();
  CHECK(mac.finish(tag) == TC_ERROR);

  CHECK(noexcept(mac.init({kat_key, TC_AES_KEYLEN})));
  CHECK(noexcept(mac.update({nist_plaintext, 1})));
  CHECK(noexcept(mac.finish(tag)));
}
#endif

#if TC_AES_ENABLE_ECB
TEST_CASE("AES re-init with a wrong key length clears the previous key")
{
  tiny_crypto::AES aes;
  uint8_t block[TC_AES_BLOCKLEN];
  std::memcpy(block, nist_plaintext, sizeof block);
  REQUIRE(aes.init({kat_key, TC_AES_KEYLEN}) == TC_OK);
  CHECK(aes.init({kat_key, TC_AES_KEYLEN - 1}) == TC_ERROR);
  CHECK(aes.encrypt_ecb(block) == TC_ERROR);
  CHECK(std::memcmp(block, nist_plaintext, sizeof block) == 0);
}
#endif

#if TC_AES_ENABLE_GCM
TEST_CASE("AES GCM clear and failed re-init leave the object unkeyed")
{
  const gcm_test_vector* v = nullptr;
  for (size_t i = 0; i < sizeof(gcm_test_vectors) / sizeof(gcm_test_vectors[0]); ++i)
    if (gcm_test_vectors[i].key_len == TC_AES_KEYLEN) {
      v = &gcm_test_vectors[i];
      break;
    }
  REQUIRE(v != nullptr);
  uint8_t block[TC_AES_BLOCKLEN] = {0};
  uint8_t tag[TC_AES_BLOCKLEN];
  const tiny_crypto::bytes key = {v->key, v->key_len};
  const tiny_crypto::bytes iv = {v->iv, v->iv_len};

  tiny_crypto::GCM gcm;
  REQUIRE(gcm.init(key, iv) == TC_OK);
  CHECK(gcm.encrypt_update(block) == TC_OK);
  gcm.clear();
  CHECK(gcm.encrypt_update(block) == TC_ERROR);
  CHECK(gcm.encrypt_finish(tag) == TC_ERROR);
  CHECK(gcm.get_c_ctx().phase == 0);

  REQUIRE(gcm.init(key, iv) == TC_OK);
  CHECK(gcm.init({v->key, v->key_len + 1}, iv) == TC_ERROR);
  CHECK(gcm.encrypt_update(block) == TC_ERROR);
  REQUIRE(gcm.init(key, iv) == TC_OK);
  CHECK(gcm.init_short_tag({v->key, v->key_len - 1}, iv, 8) == TC_ERROR);
  CHECK(gcm.aad_update({block, 1}) == TC_ERROR);

  /* The array overload of encrypt_finish needs exactly tag_length() bytes. */
  REQUIRE(gcm.init(key, iv) == TC_OK);
  uint8_t long_tag[TC_AES_BLOCKLEN + 1];
  CHECK(gcm.encrypt_finish(long_tag) == TC_ERROR);
  CHECK(gcm.encrypt_finish(tag) == TC_OK);
  CHECK(gcm.encrypt_finish(tag) == TC_ERROR);
  CHECK(noexcept(gcm.clear()));
}

TEST_CASE("AES GCM array key overloads deduce the key length")
{
  const gcm_test_vector* v = nullptr;
  for (size_t i = 0; i < sizeof(gcm_test_vectors) / sizeof(gcm_test_vectors[0]); ++i)
    if (gcm_test_vectors[i].key_len == TC_AES_KEYLEN && gcm_test_vectors[i].tag_len == 16) {
      v = &gcm_test_vectors[i];
      break;
    }
  REQUIRE(v != nullptr);
  uint8_t key[TC_AES_KEYLEN];
  std::memcpy(key, v->key, sizeof key);
  const tiny_crypto::bytes iv = {v->iv, v->iv_len};
  std::vector<uint8_t> data(v->plaintext, v->plaintext + v->length);
  uint8_t tag[TC_AES_BLOCKLEN];

  /* The array key matches the span form, including the default tag length. */
  tiny_crypto::GCM gcm;
  REQUIRE(gcm.init(key, iv) == TC_OK);
  CHECK(gcm.tag_length() == TC_AES_BLOCKLEN);
  CHECK(gcm.aad_update({v->aad, v->aad_len}) == TC_OK);
  CHECK(gcm.encrypt_update(data.data(), data.size()) == TC_OK);
  CHECK(gcm.encrypt_finish(tag) == TC_OK);
  CHECK(std::memcmp(data.data(), v->ciphertext, v->length) == 0);
  CHECK(std::memcmp(tag, v->tag, sizeof tag) == 0);

  /* A wrong array size returns TC_ERROR and leaves the object unkeyed. */
  const uint8_t short_key[TC_AES_KEYLEN - 1] = {0};
  const uint8_t long_key[TC_AES_KEYLEN + 1] = {0};
  uint8_t block[TC_AES_BLOCKLEN] = {0};
  REQUIRE(gcm.init(key, iv) == TC_OK);
  CHECK(gcm.init(short_key, iv) == TC_ERROR);
  CHECK(gcm.encrypt_update(block) == TC_ERROR);
  CHECK(gcm.get_c_ctx().phase == 0);
  REQUIRE(gcm.init(key, iv, 12) == TC_OK);
  CHECK(gcm.tag_length() == 12);
  CHECK(gcm.init(long_key, iv) == TC_ERROR);
  CHECK(gcm.aad_update({block, 1}) == TC_ERROR);

  REQUIRE(gcm.init_short_tag(key, iv, 8) == TC_OK);
  CHECK(gcm.tag_length() == 8);
  CHECK(gcm.init_short_tag(short_key, iv, 8) == TC_ERROR);
  CHECK(gcm.encrypt_update(block) == TC_ERROR);
  CHECK(noexcept(gcm.init(key, iv)));
  CHECK(noexcept(gcm.init_short_tag(key, iv, 8)));
}
#endif

#if TC_AES_ENABLE_CCM
TEST_CASE("AES CCM authentication status")
{
  const tiny_crypto::bytes key = {
#if TC_AES_KEY_BITS == 128
      ccm_rfc_key,
#else
      kat_key,
#endif
      TC_AES_KEYLEN};
  uint8_t ciphertext[sizeof(ccm_rfc_plaintext)];
  uint8_t recovered[sizeof(ccm_rfc_plaintext)];
  /* The AES-256 test profile raises TC_MIN_TAG_LEN above the 8-byte RFC 3610
   * tag, so the other key sizes use a full tag. */
#if TC_AES_KEY_BITS == 128
  const size_t tag_length = sizeof(ccm_rfc_tag);
#else
  const size_t tag_length = TC_AES_BLOCKLEN;
#endif
  uint8_t tag[TC_AES_BLOCKLEN];
  REQUIRE(tiny_crypto::ccm_encrypt(
              key, {ccm_rfc_nonce, sizeof(ccm_rfc_nonce)}, {ccm_rfc_aad, sizeof(ccm_rfc_aad)},
              {ccm_rfc_plaintext, sizeof(ccm_rfc_plaintext)},
              {ciphertext, sizeof(ccm_rfc_plaintext)}, {tag, tag_length}) == TC_OK);
#if TC_AES_KEY_BITS == 128
  CHECK(std::memcmp(ciphertext, ccm_rfc_ciphertext, sizeof(ciphertext)) == 0);
  CHECK(std::memcmp(tag, ccm_rfc_tag, tag_length) == 0);
#endif
  CHECK(tiny_crypto::ccm_decrypt(key, {ccm_rfc_nonce, sizeof(ccm_rfc_nonce)},
                                 {ccm_rfc_aad, sizeof(ccm_rfc_aad)},
                                 {ciphertext, sizeof(ciphertext)}, {tag, tag_length},
                                 {recovered, sizeof(ciphertext)}) == TC_OK);
  CHECK(std::memcmp(recovered, ccm_rfc_plaintext, sizeof(recovered)) == 0);
  tag[0] ^= 1;
  CHECK(tiny_crypto::ccm_decrypt(key, {ccm_rfc_nonce, sizeof(ccm_rfc_nonce)},
                                 {ccm_rfc_aad, sizeof(ccm_rfc_aad)},
                                 {ciphertext, sizeof(ciphertext)}, {tag, tag_length},
                                 {recovered, sizeof(ciphertext)}) == TC_MISMATCH);

  uint8_t untouched[sizeof(ccm_rfc_plaintext)];
  uint8_t untouched_tag[TC_AES_BLOCKLEN];
  std::memset(untouched, 0xa5, sizeof(untouched));
  std::memset(untouched_tag, 0xa5, sizeof(untouched_tag));
  const tiny_crypto::bytes short_key = {key.data, TC_AES_KEYLEN - 1};
  CHECK(tiny_crypto::ccm_encrypt(
            short_key, {ccm_rfc_nonce, sizeof(ccm_rfc_nonce)}, {ccm_rfc_aad, sizeof(ccm_rfc_aad)},
            {ccm_rfc_plaintext, sizeof(ccm_rfc_plaintext)}, {untouched, sizeof(untouched)},
            {untouched_tag, tag_length}) == TC_ERROR);
  CHECK(tiny_crypto::ccm_decrypt(short_key, {ccm_rfc_nonce, sizeof(ccm_rfc_nonce)},
                                 {ccm_rfc_aad, sizeof(ccm_rfc_aad)},
                                 {ciphertext, sizeof(ciphertext)}, {tag, tag_length},
                                 {untouched, sizeof(untouched)}) == TC_ERROR);
  for (size_t i = 0; i < sizeof(untouched); ++i)
    CHECK(untouched[i] == 0xa5);
  for (size_t i = 0; i < sizeof(untouched_tag); ++i)
    CHECK(untouched_tag[i] == 0xa5);
}
#endif

#if TC_AES_ENABLE_CCM
TEST_CASE("AES CCM tag length boundary at TC_MIN_TAG_LEN")
{
  const tiny_crypto::bytes key = {kat_key, TC_AES_KEYLEN};
  const uint8_t nonce[12] = {0};
  const uint8_t plaintext[] = {1, 2, 3, 4, 5};
  const size_t short_max = (TC_MIN_TAG_LEN - 1) & ~static_cast<size_t>(1);
  const size_t default_min = (TC_MIN_TAG_LEN + 1) & ~static_cast<size_t>(1);
  uint8_t ciphertext[sizeof(plaintext)];
  uint8_t recovered[sizeof(plaintext)];
  uint8_t tag[16];
  CHECK(tiny_crypto::ccm_encrypt(key, {nonce, sizeof(nonce)}, {nullptr, 0},
                                 {plaintext, sizeof(plaintext)}, {ciphertext, sizeof(ciphertext)},
                                 {tag, short_max}) == TC_ERROR);
  CHECK(tiny_crypto::ccm_encrypt(key, {nonce, sizeof(nonce)}, {nullptr, 0},
                                 {plaintext, sizeof(plaintext)}, {ciphertext, sizeof(ciphertext)},
                                 {tag, default_min}) == TC_OK);
  CHECK(tiny_crypto::ccm_encrypt_short_tag(
            key, {nonce, sizeof(nonce)}, {nullptr, 0}, {plaintext, sizeof(plaintext)},
            {ciphertext, sizeof(ciphertext)}, {tag, default_min}) == TC_ERROR);
  REQUIRE(tiny_crypto::ccm_encrypt_short_tag(
              key, {nonce, sizeof(nonce)}, {nullptr, 0}, {plaintext, sizeof(plaintext)},
              {ciphertext, sizeof(ciphertext)}, {tag, short_max}) == TC_OK);
  CHECK(tiny_crypto::ccm_decrypt(key, {nonce, sizeof(nonce)}, {nullptr, 0},
                                 {ciphertext, sizeof(ciphertext)}, {tag, short_max},
                                 {recovered, sizeof(recovered)}) == TC_ERROR);
  CHECK(tiny_crypto::ccm_decrypt_short_tag(key, {nonce, sizeof(nonce)}, {nullptr, 0},
                                           {ciphertext, sizeof(ciphertext)}, {tag, short_max},
                                           {recovered, sizeof(recovered)}) == TC_OK);
  CHECK(std::memcmp(recovered, plaintext, sizeof(plaintext)) == 0);
  CHECK(tiny_crypto::ccm_decrypt_short_tag({kat_key, TC_AES_KEYLEN - 1}, {nonce, sizeof(nonce)},
                                           {nullptr, 0}, {ciphertext, sizeof(ciphertext)},
                                           {tag, short_max},
                                           {recovered, sizeof(recovered)}) == TC_ERROR);
}
#endif

#if TC_AES_ENABLE_EAX
TEST_CASE("AES EAX wrappers round trip and preserve mismatch")
{
  uint8_t nonce[16] = {0};
  const uint8_t aad[] = {1, 2, 3};
  const uint8_t plaintext[] = {4, 5, 6, 7, 8, 9, 10};
  uint8_t ciphertext[sizeof(plaintext)];
  uint8_t recovered[sizeof(plaintext)];
  uint8_t tag[16];
  const tiny_crypto::bytes key = {kat_key, TC_AES_KEYLEN};
  REQUIRE(tiny_crypto::eax_encrypt(key, {nonce, sizeof(nonce)}, {aad, sizeof(aad)},
                                   {plaintext, sizeof(plaintext)}, {ciphertext, sizeof(plaintext)},
                                   {tag, sizeof(tag)}) == TC_OK);
  CHECK(tiny_crypto::eax_decrypt(key, {nonce, sizeof(nonce)}, {aad, sizeof(aad)},
                                 {ciphertext, sizeof(ciphertext)}, {tag, sizeof(tag)},
                                 {recovered, sizeof(ciphertext)}) == TC_OK);
  CHECK(std::memcmp(recovered, plaintext, sizeof(plaintext)) == 0);
  tag[0] ^= 1;
  CHECK(tiny_crypto::eax_decrypt(key, {nonce, sizeof(nonce)}, {aad, sizeof(aad)},
                                 {ciphertext, sizeof(ciphertext)}, {tag, sizeof(tag)},
                                 {recovered, sizeof(ciphertext)}) == TC_MISMATCH);
  CHECK(tiny_crypto::eax_encrypt(key, {nonce, sizeof(nonce)}, {aad, sizeof(aad)},
                                 {plaintext, sizeof(plaintext)}, {ciphertext, sizeof(plaintext)},
                                 {tag, TC_MIN_TAG_LEN - 1}) == TC_ERROR);
  CHECK(tiny_crypto::eax_encrypt(key, {nonce, sizeof(nonce)}, {aad, sizeof(aad)},
                                 {plaintext, sizeof(plaintext)}, {ciphertext, sizeof(plaintext)},
                                 {tag, TC_MIN_TAG_LEN}) == TC_OK);
  CHECK(tiny_crypto::eax_encrypt_short_tag(
            key, {nonce, sizeof(nonce)}, {aad, sizeof(aad)}, {plaintext, sizeof(plaintext)},
            {ciphertext, sizeof(plaintext)}, {tag, TC_MIN_TAG_LEN}) == TC_ERROR);
  REQUIRE(tiny_crypto::eax_encrypt_short_tag(
              key, {nonce, sizeof(nonce)}, {aad, sizeof(aad)}, {plaintext, sizeof(plaintext)},
              {ciphertext, sizeof(plaintext)}, {tag, TC_MIN_TAG_LEN - 1}) == TC_OK);
  CHECK(tiny_crypto::eax_decrypt(key, {nonce, sizeof(nonce)}, {aad, sizeof(aad)},
                                 {ciphertext, sizeof(ciphertext)}, {tag, TC_MIN_TAG_LEN - 1},
                                 {recovered, sizeof(ciphertext)}) == TC_ERROR);
  CHECK(tiny_crypto::eax_decrypt_short_tag(
            key, {nonce, sizeof(nonce)}, {aad, sizeof(aad)}, {ciphertext, sizeof(ciphertext)},
            {tag, TC_MIN_TAG_LEN - 1}, {recovered, sizeof(ciphertext)}) == TC_OK);
  CHECK(std::memcmp(recovered, plaintext, sizeof(plaintext)) == 0);

  uint8_t untouched[sizeof(plaintext)];
  std::memset(untouched, 0xa5, sizeof(untouched));
  uint8_t long_key_bytes[TC_AES_KEYLEN + 1];
  std::memcpy(long_key_bytes, kat_key, TC_AES_KEYLEN);
  long_key_bytes[TC_AES_KEYLEN] = 0;
  const tiny_crypto::bytes long_key = {long_key_bytes, sizeof(long_key_bytes)};
  CHECK(tiny_crypto::eax_encrypt(long_key, {nonce, sizeof(nonce)}, {aad, sizeof(aad)},
                                 {plaintext, sizeof(plaintext)}, {untouched, sizeof(untouched)},
                                 {tag, sizeof(tag)}) == TC_ERROR);
  CHECK(tiny_crypto::eax_decrypt(long_key, {nonce, sizeof(nonce)}, {aad, sizeof(aad)},
                                 {ciphertext, sizeof(ciphertext)}, {tag, sizeof(tag)},
                                 {untouched, sizeof(untouched)}) == TC_ERROR);
  for (size_t i = 0; i < sizeof(untouched); ++i)
    CHECK(untouched[i] == 0xa5);
}
#endif

#if TC_AES_ENABLE_EAX_PRIME
TEST_CASE("AES EAX-prime wrappers round trip and preserve mismatch")
{
  const uint8_t cleartext[] = {1, 2, 3};
  const uint8_t plaintext[] = {4, 5, 6, 7, 8};
  uint8_t ciphertext[sizeof(plaintext)];
  uint8_t recovered[sizeof(plaintext)];
  uint8_t tag[TC_AES_EAX_PRIME_TAG_LEN];
  const tiny_crypto::bytes key = {kat_key, TC_AES_KEYLEN};
  REQUIRE(tiny_crypto::eax_prime_encrypt(key, {cleartext, sizeof(cleartext)},
                                         {plaintext, sizeof(plaintext)},
                                         {ciphertext, sizeof(plaintext)}, tag) == TC_OK);
  CHECK(tiny_crypto::eax_prime_decrypt(key, {cleartext, sizeof(cleartext)},
                                       {ciphertext, sizeof(ciphertext)}, tag,
                                       {recovered, sizeof(ciphertext)}) == TC_OK);
  CHECK(std::memcmp(recovered, plaintext, sizeof(plaintext)) == 0);
  tag[0] ^= 1;
  CHECK(tiny_crypto::eax_prime_decrypt(key, {cleartext, sizeof(cleartext)},
                                       {ciphertext, sizeof(ciphertext)}, tag,
                                       {recovered, sizeof(ciphertext)}) == TC_MISMATCH);

  uint8_t untouched[sizeof(plaintext)];
  uint8_t untouched_tag[TC_AES_EAX_PRIME_TAG_LEN];
  std::memset(untouched, 0xa5, sizeof(untouched));
  std::memset(untouched_tag, 0xa5, sizeof(untouched_tag));
  const tiny_crypto::bytes short_key = {kat_key, TC_AES_KEYLEN - 1};
  CHECK(tiny_crypto::eax_prime_encrypt(short_key, {cleartext, sizeof(cleartext)},
                                       {plaintext, sizeof(plaintext)},
                                       {untouched, sizeof(untouched)}, untouched_tag) == TC_ERROR);
  CHECK(tiny_crypto::eax_prime_decrypt(short_key, {cleartext, sizeof(cleartext)},
                                       {ciphertext, sizeof(ciphertext)}, tag,
                                       {untouched, sizeof(untouched)}) == TC_ERROR);
  for (size_t i = 0; i < sizeof(untouched); ++i)
    CHECK(untouched[i] == 0xa5);
  for (size_t i = 0; i < sizeof(untouched_tag); ++i)
    CHECK(untouched_tag[i] == 0xa5);
}
#endif

#if TC_AES_ENABLE_SIV
TEST_CASE("AES SIV wrappers bind associated data")
{
  std::array<uint8_t, TC_AES_SIV_KEYLEN> key{};
  const uint8_t ad0[] = {1, 2, 3};
  const uint8_t ad1[] = {4, 5};
  const tiny_crypto::bytes ad[] = {{ad0, sizeof(ad0)}, {ad1, sizeof(ad1)}};
  const uint8_t plaintext[] = {6, 7, 8, 9, 10, 11, 12};
  uint8_t ciphertext[sizeof(plaintext)];
  uint8_t recovered[sizeof(plaintext)];
  uint8_t synthetic_iv[TC_AES_SIV_V_LEN];
  for (size_t i = 0; i < key.size(); ++i)
    key[i] = static_cast<uint8_t>(0x20u + i);
  REQUIRE(tiny_crypto::siv_encrypt({key.data(), key.size()}, ad, 2, {plaintext, sizeof(plaintext)},
                                   synthetic_iv, {ciphertext, sizeof(plaintext)}) == TC_OK);
  CHECK(tiny_crypto::siv_decrypt({key.data(), key.size()}, ad, 2, synthetic_iv,
                                 {ciphertext, sizeof(ciphertext)},
                                 {recovered, sizeof(ciphertext)}) == TC_OK);
  CHECK(std::memcmp(recovered, plaintext, sizeof(plaintext)) == 0);
  CHECK(tiny_crypto::siv_decrypt({key.data(), key.size()}, ad, 1, synthetic_iv,
                                 {ciphertext, sizeof(ciphertext)},
                                 {recovered, sizeof(ciphertext)}) == TC_MISMATCH);
  for (size_t i = 0; i < sizeof(recovered); ++i)
    CHECK(recovered[i] == 0);

  /* SIV takes two AES keys. One AES key is the wrong length. */
  uint8_t untouched[sizeof(plaintext)];
  uint8_t untouched_iv[TC_AES_SIV_V_LEN];
  std::memset(untouched, 0xa5, sizeof(untouched));
  std::memset(untouched_iv, 0xa5, sizeof(untouched_iv));
  const tiny_crypto::bytes single_key = {key.data(), TC_AES_KEYLEN};
  CHECK(tiny_crypto::siv_encrypt(single_key, ad, 2, {plaintext, sizeof(plaintext)}, untouched_iv,
                                 {untouched, sizeof(untouched)}) == TC_ERROR);
  CHECK(tiny_crypto::siv_decrypt(single_key, ad, 2, synthetic_iv, {ciphertext, sizeof(ciphertext)},
                                 {untouched, sizeof(untouched)}) == TC_ERROR);
  for (size_t i = 0; i < sizeof(untouched); ++i)
    CHECK(untouched[i] == 0xa5);
  for (size_t i = 0; i < sizeof(untouched_iv); ++i)
    CHECK(untouched_iv[i] == 0xa5);
}
#endif
