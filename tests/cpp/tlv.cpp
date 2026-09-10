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
