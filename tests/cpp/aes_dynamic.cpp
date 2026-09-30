/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.hpp>
#include <doctest.h>
#include <cstring>

TEST_CASE("Dynamic AES wrappers and lifecycle")
{
  tiny_crypto::AES_dynamic cipher;
  tiny_crypto::AES_dynamic_CMAC mac;
  uint8_t key[32] = {}, block[16] = {}, original[16] = {}, iv[16] = {};
  CHECK(cipher.encrypt(block) == TC_ERROR);
  CHECK(mac.final(block) == TC_ERROR);
  for (size_t length = 16; length <= 32; length += 8) {
    REQUIRE(cipher.init({key, length}) == TC_OK);
    REQUIRE(cipher.encrypt(block) == TC_OK);
    REQUIRE(cipher.decrypt(block) == TC_OK);
    CHECK(std::memcmp(block, original, 16) == 0);
    std::memset(iv, 0, sizeof iv);
    REQUIRE(cipher.cbc_encrypt(iv, block, 16) == TC_OK);
    std::memset(iv, 0, sizeof iv);
    REQUIRE(cipher.cbc_decrypt(iv, block, 16) == TC_OK);
    CHECK(std::memcmp(block, original, 16) == 0);
    REQUIRE(mac.init({key, length}) == TC_OK);
    REQUIRE(mac.update({block, 16}) == TC_OK);
    REQUIRE(mac.final(block) == TC_OK);
    CHECK(mac.final(block) == TC_ERROR);
    std::memset(block, 0, sizeof block);
  }
  cipher.clear();
  CHECK(cipher.decrypt(block) == TC_ERROR);

  /* Array keys deduce their length, and a bad length leaves the object
   * unkeyed. */
  REQUIRE(cipher.init(key) == TC_OK);
  CHECK(cipher.init({key, 20}) == TC_ERROR);
  CHECK(cipher.encrypt(block) == TC_ERROR);
  const uint8_t message[16] = {};
  REQUIRE(mac.init(key) == TC_OK);
  CHECK(mac.update(message) == TC_OK);
  CHECK(mac.init({key, 20}) == TC_ERROR);
  CHECK(mac.update(message) == TC_ERROR);
  CHECK(mac.final(block) == TC_ERROR);
}
