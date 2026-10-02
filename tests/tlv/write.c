/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Shared BER-TLV header writer: minimal definite lengths (X.690 8.1.3,
 * ISO/IEC 7816-4 6.3) that the DER and ISO 7816 readers accept. */
#include <tiny_crypto/tlv.h>
#include "tlv_internal.h"
#include "munit.h"
#include "test_util.h"
#include <string.h>

static void check_header(const uint8_t* tag, size_t tag_length, size_t value_length,
                         const uint8_t* expected, size_t expected_length)
{
  uint8_t out[TC_TLV_TAG_BYTES + 4 + 1];
  memset(out, 0xee, sizeof out);
  munit_assert_size(tc_tlv_header_size(tag_length, value_length), ==, expected_length);
  const uint8_t* end = tc_tlv_header_write(out, tag, tag_length, value_length);
  munit_assert_ptr_equal(end, out + expected_length);
  munit_assert_memory_equal(expected_length, out, expected);
  munit_assert_uint8(out[expected_length], ==, 0xee);
}

TC_TEST(lengths)
{
  static const uint8_t sequence = 0x30;
  static const uint8_t short_form[] = {0x30, 0x7f};
  static const uint8_t one_octet[] = {0x30, 0x81, 0x80};
  static const uint8_t one_octet_max[] = {0x30, 0x81, 0xff};
  static const uint8_t two_octets[] = {0x30, 0x82, 0x01, 0x00};
  static const uint8_t two_octets_max[] = {0x30, 0x82, 0xff, 0xff};
  static const uint8_t empty[] = {0x30, 0x00};
  check_header(&sequence, 1, 0, empty, sizeof empty);
  check_header(&sequence, 1, 0x7f, short_form, sizeof short_form);
  check_header(&sequence, 1, 0x80, one_octet, sizeof one_octet);
  check_header(&sequence, 1, 0xff, one_octet_max, sizeof one_octet_max);
  check_header(&sequence, 1, 0x100, two_octets, sizeof two_octets);
  check_header(&sequence, 1, 0xffff, two_octets_max, sizeof two_octets_max);
#if SIZE_MAX > 0xffffu
  static const uint8_t three_octets[] = {0x30, 0x83, 0x01, 0x00, 0x00};
  static const uint8_t three_octets_max[] = {0x30, 0x83, 0xff, 0xff, 0xff};
  check_header(&sequence, 1, 0x10000, three_octets, sizeof three_octets);
  check_header(&sequence, 1, 0xffffff, three_octets_max, sizeof three_octets_max);
  /* Values above FFFFFF exceed the four-octet length field. */
  munit_assert_size(tc_tlv_header_size(1, 0x1000000), ==, 0);
#endif
  return MUNIT_OK;
}

TC_TEST(tags)
{
  static const uint8_t chuid[] = {0x5f, 0xc1, 0x02};
  static const uint8_t chuid_header[] = {0x5f, 0xc1, 0x02, 0x82, 0x0b, 0xc6};
  static const uint8_t long_tag[TC_TLV_TAG_BYTES] = {0xdf, 0x81, 0x82, 0x83, 0x84, 0x05};
  check_header(chuid, sizeof chuid, 0x0bc6, chuid_header, sizeof chuid_header);
  munit_assert_size(tc_tlv_header_size(TC_TLV_TAG_BYTES, 1), ==, TC_TLV_TAG_BYTES + 1);
  munit_assert_size(tc_tlv_header_size(0, 1), ==, 0);
  munit_assert_size(tc_tlv_header_size(TC_TLV_TAG_BYTES + 1, 1), ==, 0);
  uint8_t out[TC_TLV_TAG_BYTES + 1];
  tc_tlv_header_write(out, long_tag, sizeof long_tag, 5);
  munit_assert_memory_equal(sizeof long_tag, out, long_tag);
  munit_assert_uint8(out[TC_TLV_TAG_BYTES], ==, 5);
  return MUNIT_OK;
}

/* Every written header reads back under DER and ISO 7816. */
TC_TEST(round_trip)
{
  static uint8_t buffer[0x10000 + 16];
  static const size_t lengths[] = {0, 1, 0x7f, 0x80, 0xff, 0x100, 0x1234, 0x10000};
  static const uint8_t tag[] = {0x7f, 0x21};
  const TC_TLV_limits limits = {sizeof buffer, sizeof buffer, 16, 4};
  for (size_t i = 0; i < sizeof lengths / sizeof *lengths; ++i) {
    const size_t header = tc_tlv_header_size(sizeof tag, lengths[i]);
    if (!header)
      continue;
    memset(buffer, 0, sizeof buffer);
    tc_tlv_header_write(buffer, tag, sizeof tag, lengths[i]);
    TC_TLV_element element;
    munit_assert_int(
        TC_TLV_read((TC_bytes){buffer, header + lengths[i]}, TC_TLV_DER, &limits, &element), ==,
        TC_TLV_OK);
    munit_assert_size(element.value.length, ==, lengths[i]);
    munit_assert_size(element.header.header_length, ==, header);
    munit_assert_int(
        TC_TLV_read((TC_bytes){buffer, header + lengths[i]}, TC_TLV_ISO7816, &limits, &element), ==,
        TC_TLV_OK);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  static MunitTest tests[] = {{"/lengths", lengths, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                              {"/tags", tags, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                              {"/round-trip", round_trip, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                              {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  static const MunitSuite suite = {"/tlv/write", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
