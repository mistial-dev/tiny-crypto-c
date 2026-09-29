/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tlv.hpp>
#include "doctest.h"
TEST_CASE("TLV reader borrows input and reports incomplete values")
{
  const uint8_t bytes[] = {4, 1, 42};
  const TC_TLV_limits limits = {32, 16, 4, 2};
  tiny_crypto::TLVReader reader;
  TC_TLV_element element;
  CHECK(reader.next(element) == TC_TLV_ARGUMENT);
  CHECK(reader.init(bytes, sizeof bytes, TC_TLV_DER, limits) == TC_TLV_OK);
  CHECK(reader.next(element) == TC_TLV_OK);
  CHECK(element.value.data == bytes + 2);
  CHECK(reader.next(element) == TC_TLV_END);
  CHECK(reader.init(bytes, 2, TC_TLV_DER, limits) == TC_TLV_OK);
  CHECK(reader.next(element) == TC_TLV_MORE);
}

TEST_CASE("A failed re-init leaves the TLV reader unusable")
{
  const uint8_t bytes[] = {4, 1, 42, 4, 1, 43};
  const TC_TLV_limits limits = {32, 16, 4, 2};
  tiny_crypto::TLVReader reader;
  TC_TLV_element element;
  CHECK(reader.init(bytes, sizeof bytes, TC_TLV_DER, limits) == TC_TLV_OK);
  CHECK(reader.next(element) == TC_TLV_OK);
  CHECK(reader.init(NULL, 3, TC_TLV_DER, limits) != TC_TLV_OK);
  CHECK(reader.next(element) == TC_TLV_ARGUMENT);
}

TEST_CASE("A child TLV reader rejects padding inside a template")
{
  const uint8_t bytes[] = {0, 0x70, 2, 4, 0, 0xff, 0x70, 3, 0, 4, 0};
  const TC_TLV_limits limits = {32, 16, 8, 2};
  tiny_crypto::TLVReader root, child, unready;
  TC_TLV_element element = TC_TLV_element(), inner = TC_TLV_element();
  CHECK(child.init_child(unready, element) == TC_TLV_ARGUMENT);
  CHECK(root.init(bytes, sizeof bytes, TC_TLV_ISO7816_PAD_ZERO_FF, limits) == TC_TLV_OK);
  REQUIRE(root.next(element) == TC_TLV_OK);
  CHECK(child.init_child(root, element) == TC_TLV_OK);
  CHECK(child.next(inner) == TC_TLV_OK);
  CHECK(inner.encoded.data == bytes + 3);
  CHECK(child.next(inner) == TC_TLV_END);
  REQUIRE(root.next(element) == TC_TLV_OK);
  CHECK(child.init_child(root, element) == TC_TLV_OK);
  CHECK(child.next(inner) == TC_TLV_INVALID);
  CHECK(root.next(element) == TC_TLV_END);
}

TEST_CASE("A TLV reader can descend into its own element")
{
  const uint8_t bytes[] = {0x30, 3, 4, 1, 42};
  const TC_TLV_limits limits = {32, 16, 8, 2};
  tiny_crypto::TLVReader reader;
  TC_TLV_element element = TC_TLV_element();
  REQUIRE(reader.init(bytes, sizeof bytes, TC_TLV_DER, limits) == TC_TLV_OK);
  REQUIRE(reader.next(element) == TC_TLV_OK);
  CHECK(reader.init_child(reader, element) == TC_TLV_OK);
  REQUIRE(reader.next(element) == TC_TLV_OK);
  CHECK(element.value.data == bytes + 4);
  CHECK(reader.next(element) == TC_TLV_END);
}
