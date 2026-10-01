/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "doctest.h"
#include <tiny_crypto/apdu.hpp>
#include <cstring>

namespace {
/* Answers every command with one data byte and 9000. */
TC_status answer(void* context, TC_bytes command, TC_buffer response, size_t* length)
{
  size_t& calls = *static_cast<size_t*>(context);
  ++calls;
  if (command.length < TC_APDU_HEADER_BYTES || response.capacity < 3)
    return TC_ERROR;
  response.data[0] = command.data[1];
  response.data[1] = 0x90;
  response.data[2] = 0x00;
  *length = 3;
  return TC_OK;
}
} // namespace

TEST_CASE("APDU encoding and response reading")
{
  static const uint8_t tag[] = {0x5c, 1, 0x7e};
  const tiny_crypto::apdu_command command = {{tag, sizeof tag}, 256, 0x00, 0xcb, 0x3f, 0xff};
  size_t size = 0;
  REQUIRE(tiny_crypto::apdu_command_size(command, TC_APDU_SHORT, size) == TC_APDU_OK);
  CHECK(size == 9);
  uint8_t encoded[9];
  size_t written = 0;
  REQUIRE(tiny_crypto::apdu_command_encode(command, TC_APDU_SHORT, encoded, written) == TC_APDU_OK);
  static const uint8_t expected[] = {0x00, 0xcb, 0x3f, 0xff, 0x03, 0x5c, 0x01, 0x7e, 0x00};
  CHECK(written == sizeof expected);
  CHECK(std::memcmp(encoded, expected, sizeof expected) == 0);

  uint8_t small[8];
  std::memset(small, 0xcc, sizeof small);
  written = 77;
  CHECK(tiny_crypto::apdu_command_encode(command, TC_APDU_SHORT, small, written) == TC_APDU_LIMIT);
  CHECK(written == 77);

  static const uint8_t answer_bytes[] = {0x53, 0x00, 0x90, 0x00};
  tiny_crypto::apdu_response response = {};
  REQUIRE(tiny_crypto::apdu_response_read({answer_bytes, sizeof answer_bytes}, response) ==
          TC_APDU_OK);
  CHECK(response.data.length == 2);
  CHECK(response.sw == 0x9000);
  CHECK(tiny_crypto::apdu_response_read({answer_bytes, 1}, response) == TC_APDU_INVALID);
  CHECK(tiny_crypto::apdu_status_classify(0x6c10) == TC_APDU_SW_WRONG_LE);
}

TEST_CASE("APDU channel owns and clears its state")
{
  size_t calls = 0;
  uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
  uint8_t response_bytes[16];
  const tiny_crypto::apdu_transport transport = {answer, &calls};
  const tiny_crypto::apdu_channel_options options = {TC_APDU_SHORT, 0, 2, 0, 0};
  {
    tiny_crypto::apdu_channel channel;
    REQUIRE(channel.init(transport, options, {scratch, sizeof scratch}) == TC_APDU_OK);
    CHECK(channel.exchanges_left() == 2);
    REQUIRE(channel.restrict(32, 16, TC_APDU_GET_RESPONSE_PLAIN_CLA) == TC_APDU_OK);
    const tiny_crypto::apdu_command select = {{nullptr, 0}, 14, 0x00, 0xa4, 0x04, 0x00};
    tiny_crypto::apdu_response out = {};
    REQUIRE(channel.transceive(select, response_bytes, out) == TC_APDU_OK);
    CHECK(out.data.length == 1);
    CHECK(out.data.data[0] == 0xa4);
    CHECK(out.sw == 0x9000);
    CHECK(channel.exchanges_left() == 1);
    CHECK(channel.native() != nullptr);
    CHECK(calls == 1);
  }
  for (uint8_t byte : scratch)
    CHECK(byte == 0);
}
