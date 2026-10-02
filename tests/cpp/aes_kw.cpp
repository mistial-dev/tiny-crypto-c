/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.hpp>
#include <doctest.h>
#include <cstring>

TEST_CASE("AES key wrap wrappers")
{
  /* RFC 3394 section 4.1 under the AES-128 test library. */
  const uint8_t kek[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  const uint8_t key_data[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  const uint8_t expected[24] = {0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47,
                                0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82,
                                0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5};
  static_assert(TC_AES_KW_KEK_LENGTH_SUPPORTED(sizeof kek), "AES-128 KEK");
  uint8_t wrapped[TC_AES_KW_WRAPPED_BYTES(16)] = {};
  uint8_t unwrapped[TC_AES_KW_UNWRAPPED_BYTES(sizeof wrapped)] = {};
  const tiny_crypto::bytes k = {kek, sizeof kek};

  REQUIRE(tiny_crypto::aes_kw_wrap(k, {key_data, sizeof key_data}, {wrapped, sizeof wrapped}) ==
          TC_OK);
  CHECK(std::memcmp(wrapped, expected, sizeof wrapped) == 0);
  REQUIRE(tiny_crypto::aes_kw_unwrap(k, {wrapped, sizeof wrapped}, {unwrapped, sizeof unwrapped}) ==
          TC_OK);
  CHECK(std::memcmp(unwrapped, key_data, sizeof key_data) == 0);

  /* A modified wrapped key fails the integrity check and wipes the output. */
  wrapped[3] ^= 1;
  CHECK(tiny_crypto::aes_kw_unwrap(k, {wrapped, sizeof wrapped}, {unwrapped, sizeof unwrapped}) ==
        TC_MISMATCH);
  const uint8_t zero[16] = {};
  CHECK(std::memcmp(unwrapped, zero, sizeof unwrapped) == 0);

  /* KWP returns the key data length through a reference. */
  uint8_t padded[TC_AES_KWP_WRAPPED_BYTES(13)] = {};
  uint8_t recovered[TC_AES_KW_UNWRAPPED_BYTES(sizeof padded)] = {};
  size_t length = 0;
  REQUIRE(tiny_crypto::aes_kwp_wrap(k, {key_data, 13}, {padded, sizeof padded}) == TC_OK);
  REQUIRE(tiny_crypto::aes_kwp_unwrap(k, {padded, sizeof padded}, {recovered, sizeof recovered},
                                      length) == TC_OK);
  CHECK(length == 13);
  CHECK(std::memcmp(recovered, key_data, 13) == 0);
  padded[sizeof padded - 1] ^= 0x80;
  length = 99;
  CHECK(tiny_crypto::aes_kwp_unwrap(k, {padded, sizeof padded}, {recovered, sizeof recovered},
                                    length) == TC_MISMATCH);
  CHECK(length == 99);

  /* A KEK length outside the build policy is an argument error. */
  std::memset(wrapped, 0x5a, sizeof wrapped);
  CHECK(tiny_crypto::aes_kw_wrap({kek, 15}, {key_data, sizeof key_data},
                                 {wrapped, sizeof wrapped}) == TC_ERROR);
  CHECK(wrapped[0] == 0x5a);
}
