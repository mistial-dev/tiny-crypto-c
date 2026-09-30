/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "doctest.h"
#include <tiny_crypto/piv_command.hpp>
#include <cstring>

namespace {
/* A PIV card that answers SELECT with a minimal template, GET DATA with an
 * empty container and VERIFY with 63C5. */
struct card {
  size_t calls;
};

TC_status answer(void* context, TC_bytes command, TC_buffer response, size_t* length)
{
  static const uint8_t selected[] = {0x61, 0x15, 0x4f, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08,
                                     0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x06, 0x4f,
                                     0x04, 0xa0, 0x00, 0x00, 0x03, 0x90, 0x00};
  static const uint8_t empty[] = {0x53, 0x00, 0x90, 0x00};
  static const uint8_t retries[] = {0x63, 0xc5};
  ++static_cast<card*>(context)->calls;
  const uint8_t* bytes = retries;
  size_t size = sizeof retries;
  if (command.data[1] == 0xa4) {
    bytes = selected;
    size = sizeof selected;
  } else if (command.data[1] == 0xcb) {
    bytes = empty;
    size = sizeof empty;
  }
  if (size > response.capacity)
    return TC_ERROR;
  std::memcpy(response.data, bytes, size);
  *length = size;
  return TC_OK;
}
} // namespace

TEST_CASE("PIV link session")
{
  card state = {0};
  uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
  uint8_t response[64];
  const tiny_crypto::piv_link_options options = {{TC_APDU_SHORT, 0, 8, 0, 0}, TC_PIV_CONTACT, 0};
  {
    tiny_crypto::piv_link link;
    REQUIRE(link.init({answer, &state}, options, {scratch, sizeof scratch}) == TC_PIV_OK);
    tiny_crypto::piv_application application = {};
    REQUIRE(link.select(TC_PIV_APPLICATION_PIV, 0, {response, sizeof response}, application) ==
            TC_PIV_OK);
    CHECK(application.profile == TC_PIV_CARD);
    CHECK(link.info().application == TC_PIV_APPLICATION_PIV);
    static const uint8_t tag[] = {0x5f, 0xc1, 0x02};
    tiny_crypto::piv_data_object object = {};
    REQUIRE(link.get_data({tag, sizeof tag}, {response, sizeof response}, object) == TC_PIV_OK);
    CHECK(object.form == TC_PIV_FORM_CONTAINER);
    CHECK(object.value.length == 0);
    tiny_crypto::piv_reference_status status = {};
    REQUIRE(link.verify_status(0x80, status) == TC_PIV_OK);
    CHECK(status.retries_known == 1);
    CHECK(status.retries == 5);
    CHECK(link.status() == 0x63c5);
    unsigned retries = 0;
    CHECK(tiny_crypto::piv_status_classify(link.status(), TC_PIV_COMMAND_VERIFY,
                                           TC_PIV_APPLICATION_PIV,
                                           &retries) == TC_PIV_SW_VERIFY_FAILED);
    CHECK(retries == 5);
    static const uint8_t pin[] = {'1', '2', '3'};
    CHECK(link.pin_verify(0x80, {pin, sizeof pin}, 3, status) == TC_PIV_ARGUMENT);
    CHECK(TC_PIV_link_status(link.native()) == 0x63c5);
    CHECK(state.calls == 3);
  }
  /* The destructor wiped the scratch buffer. */
  for (uint8_t byte : scratch)
    CHECK(byte == 0);
}

TEST_CASE("PIV application template reader")
{
  static const uint8_t apt[] = {0x61, 0x15, 0x4f, 0x0b, 0xa0, 0x00, 0x00, 0x03,
                                0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79,
                                0x06, 0x4f, 0x04, 0xa0, 0x00, 0x00, 0x03};
  tiny_crypto::piv_application out = {};
  CHECK(tiny_crypto::piv_application_read({apt, sizeof apt}, TC_PIV_APPLICATION_PIV, 0, out) ==
        TC_TLV_OK);
  CHECK(out.aid.length == 11);
  CHECK(tiny_crypto::piv_application_read({apt, sizeof apt}, TC_PIV_APPLICATION_TWIC, 0, out) ==
        TC_TLV_INVALID);
}
