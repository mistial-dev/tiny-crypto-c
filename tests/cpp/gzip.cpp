/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "doctest.h"
#include <tiny_crypto/tiny_crypto.hpp>
#include <cstring>
#include <type_traits>

static_assert(sizeof(tiny_crypto::GZIPDecoder) == sizeof(TC_GZIP_workspace),
              "The decoder retains one workspace");
static_assert(!std::is_copy_constructible<tiny_crypto::GZIPDecoder>::value,
              "Decoder scratch has one owner");

TEST_CASE("GZIP decoder reuse, limits and arguments") {
  const uint8_t compressed[] = {
    0x1f,0x8b,8,0,0,0,0,0,2,0xff,0x4b,0x4c,0x4a,0x4e,0x44,0x45,0,
    4,0xc0,0x26,0xdc,0x12,0,0,0
  };
  const char expected[] = "abcabcabcabcabcabc";
  uint8_t output[sizeof expected - 1];
  tiny_crypto::GZIPDecoder decoder;
  size_t work = 4096, length = SIZE_MAX;
  REQUIRE(decoder.decode(compressed,output,work,length) == TC_GZIP_OK);
  CHECK(length == sizeof output);
  CHECK(std::memcmp(output,expected,sizeof output) == 0);
  CHECK(work < 4096);

  length = SIZE_MAX; work = 0;
  CHECK(decoder.decode(compressed,output,work,length) == TC_GZIP_LIMIT);
  CHECK(length == SIZE_MAX);
  for (uint8_t byte : output) CHECK(byte == 0);

  std::memset(output,0x5a,sizeof output); work = 4096;
  CHECK(decoder.decode(nullptr,1,output,sizeof output,work,length) == TC_GZIP_ARGUMENT);
  CHECK(work == 4096);
  CHECK(length == SIZE_MAX);
  for (uint8_t byte : output) CHECK(byte == 0x5a);

  REQUIRE(decoder.decode(compressed,sizeof compressed,output,sizeof output,work,length) == TC_GZIP_OK);
  CHECK(std::memcmp(output,expected,sizeof output) == 0);
}
