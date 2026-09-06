/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.hpp>
#include <doctest.h>
#include <cstring>
#include <type_traits>

TEST_CASE("KMAC256 streaming and lifecycle") {
  tiny_crypto::KMAC256 ctx;
  uint8_t key[32] = {}, out[48], expected[48];
  CHECK_FALSE(std::is_copy_constructible<tiny_crypto::KMAC256>::value);
  CHECK(ctx.update(nullptr, 0) == TC_ERROR);
  REQUIRE(ctx.init(key, sizeof(key)) == TC_OK);
  REQUIRE(ctx.update(key, 13) == TC_OK);
  REQUIRE(ctx.final(out, sizeof(out)) == TC_OK);
  REQUIRE(tiny_crypto::KMAC256::digest(key, sizeof(key), key, 13,
      nullptr, 0, expected, sizeof(expected)) == TC_OK);
  CHECK(std::memcmp(out, expected, sizeof(out)) == 0);
  CHECK(ctx.final(out, sizeof(out)) == TC_ERROR);
  REQUIRE(ctx.init(key, sizeof(key)) == TC_OK);
  ctx.clear();
  CHECK(ctx.update(nullptr, 0) == TC_ERROR);
}
