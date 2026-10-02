/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.hpp>
#include <doctest.h>
#include <cstring>

using tiny_crypto::buffer;
using tiny_crypto::bytes;

TEST_CASE("KMAC256 streaming and lifecycle")
{
  tiny_crypto::KMAC256 ctx;
  uint8_t key[32] = {}, out[48], expected[48];
  const bytes empty = {nullptr, 0};
  CHECK(ctx.update(empty) == TC_ERROR);
  REQUIRE(ctx.init(bytes{key, sizeof(key)}) == TC_OK);
  REQUIRE(ctx.update(bytes{key, 13}) == TC_OK);
  REQUIRE(ctx.finish(buffer{out, sizeof(out)}) == TC_OK);
  REQUIRE(tiny_crypto::KMAC256::digest(bytes{key, sizeof(key)}, bytes{key, 13}, empty,
                                       buffer{expected, sizeof(expected)}) == TC_OK);
  CHECK(std::memcmp(out, expected, sizeof(out)) == 0);
  CHECK(ctx.finish(buffer{out, sizeof(out)}) == TC_ERROR);
  REQUIRE(ctx.init(bytes{key, sizeof(key)}) == TC_OK);
  ctx.clear();
  CHECK(ctx.update(empty) == TC_ERROR);

  /* The customization string changes the output. */
  const uint8_t custom[] = {'c'};
  REQUIRE(ctx.init(bytes{key, sizeof(key)}, bytes{custom, 1}) == TC_OK);
  REQUIRE(ctx.update(bytes{key, 13}) == TC_OK);
  REQUIRE(ctx.finish(buffer{out, sizeof(out)}) == TC_OK);
  CHECK(std::memcmp(out, expected, sizeof(out)) != 0);
  CHECK(tiny_crypto::KMAC256::digest(bytes{key, sizeof(key)}, bytes{nullptr, 1}, empty,
                                     buffer{out, sizeof(out)}) == TC_ERROR);
}

TEST_CASE("KMAC256 members do not throw")
{
  tiny_crypto::KMAC256 ctx;
  uint8_t out[32];
  const bytes data = {out, sizeof(out)};
  CHECK(noexcept(tiny_crypto::KMAC256()));
  CHECK(noexcept(ctx.init(data)));
  CHECK(noexcept(ctx.update(data)));
  CHECK(noexcept(ctx.finish(buffer{out, sizeof(out)})));
  CHECK(noexcept(ctx.clear()));
  CHECK(noexcept(tiny_crypto::KMAC256::digest(data, data, data, buffer{out, sizeof(out)})));
}
