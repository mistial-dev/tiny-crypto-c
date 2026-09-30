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
  CHECK(reader.init(bytes, TC_TLV_DER, limits) == TC_TLV_OK);
  CHECK(reader.next(element) == TC_TLV_OK);
  CHECK(element.value.data == bytes + 2);
  CHECK(reader.next(element) == TC_TLV_END);
  CHECK(reader.init(TC_bytes{bytes, 2}, TC_TLV_DER, limits) == TC_TLV_OK);
  CHECK(reader.next(element) == TC_TLV_MORE);
}

TEST_CASE("A failed re-init leaves the TLV reader unusable")
{
  const uint8_t bytes[] = {4, 1, 42, 4, 1, 43};
  const TC_TLV_limits limits = {32, 16, 4, 2};
  tiny_crypto::TLVReader reader;
  TC_TLV_element element;
  CHECK(reader.init(bytes, TC_TLV_DER, limits) == TC_TLV_OK);
  CHECK(reader.next(element) == TC_TLV_OK);
  CHECK(reader.init(TC_bytes{NULL, 3}, TC_TLV_DER, limits) != TC_TLV_OK);
  CHECK(reader.next(element) == TC_TLV_ARGUMENT);
}

TEST_CASE("A child TLV reader rejects padding inside a template")
{
  const uint8_t bytes[] = {0, 0x70, 2, 4, 0, 0xff, 0x70, 3, 0, 4, 0};
  const TC_TLV_limits limits = {32, 16, 8, 2};
  tiny_crypto::TLVReader root, child, unready;
  TC_TLV_element element = TC_TLV_element(), inner = TC_TLV_element();
  CHECK(child.init_child(unready, element) == TC_TLV_ARGUMENT);
  CHECK(root.init(TC_bytes{bytes, sizeof bytes}, TC_TLV_ISO7816_PAD_ZERO_FF, limits) == TC_TLV_OK);
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
  REQUIRE(reader.init(bytes, TC_TLV_DER, limits) == TC_TLV_OK);
  REQUIRE(reader.next(element) == TC_TLV_OK);
  CHECK(reader.init_child(reader, element) == TC_TLV_OK);
  REQUIRE(reader.next(element) == TC_TLV_OK);
  CHECK(element.value.data == bytes + 4);
  CHECK(reader.next(element) == TC_TLV_END);
}

TEST_CASE("A failed init_child leaves a populated TLV reader unusable")
{
  const uint8_t bytes[] = {0x30, 6, 4, 1, 42, 4, 1, 43, 0x30, 3, 4, 1, 44};
  const uint8_t foreign[] = {0x30, 3, 4, 1, 45};
  const TC_TLV_limits limits = {32, 16, 8, 2};
  tiny_crypto::TLVReader root, other, child;
  TC_TLV_element first = TC_TLV_element(), second = TC_TLV_element();
  TC_TLV_element outside = TC_TLV_element(), inner = TC_TLV_element();
  REQUIRE(root.init(bytes, TC_TLV_DER, limits) == TC_TLV_OK);
  REQUIRE(root.next(first) == TC_TLV_OK);
  REQUIRE(root.next(second) == TC_TLV_OK);
  REQUIRE(other.init(foreign, TC_TLV_DER, limits) == TC_TLV_OK);
  REQUIRE(other.next(outside) == TC_TLV_OK);
  REQUIRE(child.init_child(root, first) == TC_TLV_OK);
  REQUIRE(child.next(inner) == TC_TLV_OK);
  CHECK(inner.value.data == bytes + 4);
  /* The child still has an unread sibling. An element outside the parent
   * fails, and the child must not resume at its old position. */
  CHECK(child.init_child(root, outside) == TC_TLV_ARGUMENT);
  CHECK(child.next(inner) == TC_TLV_ARGUMENT);
  CHECK(inner.value.data == bytes + 4);
  REQUIRE(child.init_child(root, second) == TC_TLV_OK);
  REQUIRE(child.next(inner) == TC_TLV_OK);
  CHECK(inner.value.data == bytes + 12);
  CHECK(child.next(inner) == TC_TLV_END);
}

TEST_CASE("A copied TLV reader continues from the saved position")
{
  const uint8_t bytes[] = {4, 1, 42, 4, 1, 43, 4, 1, 44};
  const TC_TLV_limits limits = {32, 16, 8, 2};
  tiny_crypto::TLVReader reader;
  TC_TLV_element element = TC_TLV_element();
  REQUIRE(reader.init(bytes, TC_TLV_DER, limits) == TC_TLV_OK);
  REQUIRE(reader.next(element) == TC_TLV_OK);
  tiny_crypto::TLVReader saved(reader);
  REQUIRE(reader.next(element) == TC_TLV_OK);
  REQUIRE(reader.next(element) == TC_TLV_OK);
  CHECK(element.value.data == bytes + 8);
  CHECK(reader.next(element) == TC_TLV_END);
  /* The copy kept its own cursor at the second element. */
  REQUIRE(saved.next(element) == TC_TLV_OK);
  CHECK(element.value.data == bytes + 5);
  /* Assignment restores a saved position over a finished reader. */
  reader = saved;
  REQUIRE(reader.next(element) == TC_TLV_OK);
  CHECK(element.value.data == bytes + 8);
  REQUIRE(saved.next(element) == TC_TLV_OK);
  CHECK(element.value.data == bytes + 8);
  CHECK(saved.next(element) == TC_TLV_END);
}
