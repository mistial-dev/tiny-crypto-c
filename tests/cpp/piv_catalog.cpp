/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "doctest.h"
#include <tiny_crypto/piv_catalog.hpp>
#include <cstring>

namespace {
/* A PIV card that answers SELECT with a minimal template, GET DATA of a
 * 3-byte tag with an empty container (SP 800-73-5 Part 1 4.1.1) and the
 * Discovery Object and BIT group with 6A82. */
TC_status answer(void* context, TC_bytes command, TC_buffer response, size_t* length)
{
  static const uint8_t selected[] = {0x61, 0x15, 0x4f, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08,
                                     0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x06, 0x4f,
                                     0x04, 0xa0, 0x00, 0x00, 0x03, 0x90, 0x00};
  static const uint8_t empty[] = {0x53, 0x00, 0x90, 0x00};
  static const uint8_t absent[] = {0x6a, 0x82};
  ++*static_cast<size_t*>(context);
  const uint8_t* bytes = empty;
  size_t size = sizeof empty;
  if (command.data[1] == 0xa4) {
    bytes = selected;
    size = sizeof selected;
  } else if (command.data[6] != 3) {
    bytes = absent;
    size = sizeof absent;
  }
  if (size > response.capacity)
    return TC_ERROR;
  std::memcpy(response.data, bytes, size);
  *length = size;
  return TC_OK;
}
} // namespace

TEST_CASE("PIV catalog lookup")
{
  CHECK(tiny_crypto::piv_catalog_count(TC_PIV_APPLICATION_PIV, TC_PIV_CARD) ==
        TC_PIV_CATALOG_PIV_OBJECTS);
  static const uint8_t tag[] = {0xdf, 0xc1, 0x01};
  const tiny_crypto::piv_object_info* privacy_key = tiny_crypto::piv_catalog_find(
      TC_PIV_APPLICATION_TWIC, TC_TWIC_LEGACY_CARD, {tag, sizeof tag});
  REQUIRE(privacy_key != nullptr);
  CHECK(privacy_key->contactless == TC_PIV_ACCESS_NEVER);
  CHECK(tiny_crypto::piv_catalog_at(TC_PIV_APPLICATION_TWIC, TC_TWIC_LEGACY_CARD, 2) ==
        privacy_key);
}

TEST_CASE("PIV inventory lifecycle")
{
  size_t calls = 0;
  uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
  uint8_t response[64];
  static uint8_t pool[1024];
  tiny_crypto::piv_object objects[TC_PIV_CATALOG_PIV_OBJECTS];
  const tiny_crypto::piv_link_options options = {{TC_APDU_SHORT, 0, 64, 0, 0}, TC_PIV_CONTACT, 0};
  tiny_crypto::piv_link link;
  REQUIRE(link.init({answer, &calls}, options, {scratch, sizeof scratch}) == TC_PIV_OK);
  tiny_crypto::piv_application application = {};
  REQUIRE(link.select(TC_PIV_APPLICATION_PIV, 0, {response, sizeof response}, application) ==
          TC_PIV_OK);
  {
    tiny_crypto::piv_inventory inventory(objects);
    size_t work = 10000;
    REQUIRE(inventory.read(link, nullptr, {pool, sizeof pool}, work) == TC_PIV_OK);
    CHECK(inventory.size() == TC_PIV_CATALOG_PIV_OBJECTS);
    CHECK(inventory[0].state == TC_PIV_OBJECT_EMPTY);
    CHECK(inventory.find(0x6010)->state == TC_PIV_OBJECT_RESTRICTED);
    CHECK(inventory.find(0x1018)->state == TC_PIV_OBJECT_SKIPPED);
    CHECK(inventory.find(0x6050)->state == TC_PIV_OBJECT_ABSENT);
    /* Four PIN objects are restricted and the pairing code is skipped. */
    CHECK(calls == 1 + TC_PIV_CATALOG_PIV_OBJECTS - 5);
    CHECK(inventory.pool_used() == 2 * (TC_PIV_CATALOG_PIV_OBJECTS - 7));
    CHECK(inventory.native()->link.application == TC_PIV_APPLICATION_PIV);
  }
  /* The destructor wiped the pool bytes and the objects. */
  for (uint8_t byte : pool)
    CHECK(byte == 0);
  CHECK(objects[0].info == nullptr);
}
