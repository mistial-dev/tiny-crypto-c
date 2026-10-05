/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_chuid.h>
#include <stdio.h>
#include <string.h>

#include "munit.h"
#include "test_util.h"

/* Set the RFC 4122 variant (section 4.1.1) and version (section 4.1.3) of a
 * 16-byte UUID. */
static void uuid_mark(uint8_t* uuid, unsigned version)
{
  uuid[6] = (uint8_t)((version << 4) | (uuid[6] & 15));
  uuid[8] = (uint8_t)(0x80 | (uuid[8] & 63));
}

TC_TEST(test_profiles)
{
  static const char* invalid_dates[] = {"19000229", "20240230", "20241301",
                                        "20240431", "00000101", "2024x101"};
  uint8_t data[81] = {0x53, 79, 0x30, 25};
  TC_PIV_CHUID chuid, saved;
  size_t i;
  for (i = 0; i < 25; ++i)
    data[4 + i] = (uint8_t)i;
  data[29] = 0x34;
  data[30] = 16;
  for (i = 0; i < 16; ++i)
    data[31 + i] = (uint8_t)(i + 32);
  data[47] = 0x35;
  data[48] = 8;
  memcpy(data + 49, "20240229", 8);
  data[57] = 0x36;
  data[58] = 16;
  for (i = 0; i < 16; ++i)
    data[59 + i] = (uint8_t)(i + 64);
  uuid_mark(data + 31, 4);
  uuid_mark(data + 59, 4);
  /* Nonempty signature placeholder. CMS decoding is outside this test. */
  data[75] = 0x3e;
  data[76] = 2;
  data[77] = 0x30;
  data[78] = 0;
  data[79] = 0xfe;
  data[80] = 0;
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                 TC_CHUID_PROFILE_PIV, &chuid) == TC_TLV_OK);
  munit_assert(chuid.card_uuid.data == data + 31 && chuid.card_uuid.length == 16);
  munit_assert(chuid.cardholder_uuid.data == data + 59 && chuid.cardholder_uuid.length == 16);
  munit_assert(chuid.fascn.length == 25 && chuid.expiration.length == 8 &&
               chuid.signature.length == 2);
  munit_assert_ptr_equal(chuid.signed_content[0].data, data + 2);
  munit_assert_size(chuid.signed_content[0].length, ==, 73);
  munit_assert_ptr_equal(chuid.signed_content[1].data, data + 79);
  munit_assert_size(chuid.signed_content[1].length, ==, 2);
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data + 2, sizeof data - 2}, TC_PIV_CHUID_CONTENTS,
                                 TC_CHUID_PROFILE_PIV, &chuid) == TC_TLV_OK);
  saved = chuid;
  /* SP 800-73-5 Part 1 3.4.1 and 3.4.2: the GUID is an RFC 4122 UUID of
   * version 1, 4 or 5 and the Cardholder UUID one of version 4. The other
   * profiles keep their own rules, such as the zero GUID of Legacy TWIC. */
  for (unsigned version = 0; version < 16; ++version) {
    uuid_mark(data + 31, version);
    munit_assert_int(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                       TC_CHUID_PROFILE_PIV, &chuid),
                     ==, version == 1 || version == 4 || version == 5 ? TC_TLV_OK : TC_TLV_INVALID);
    munit_assert_int(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                       TC_CHUID_PROFILE_PIV_SP800_73_4, &chuid),
                     ==, TC_TLV_OK);
    uuid_mark(data + 31, 4);
    uuid_mark(data + 59, version);
    munit_assert_int(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                       TC_CHUID_PROFILE_PIV, &chuid),
                     ==, version == 4 ? TC_TLV_OK : TC_TLV_INVALID);
    uuid_mark(data + 59, 4);
  }
  /* Variants other than 10xx: NCS (0xxx), Microsoft (110x) and reserved. */
  static const uint8_t variants[] = {0x00, 0x40, 0xc0, 0xe0};
  for (i = 0; i < sizeof variants; ++i) {
    data[31 + 8] = variants[i];
    munit_assert(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                   TC_CHUID_PROFILE_PIV, &chuid) == TC_TLV_INVALID);
    data[31 + 8] = 0x80;
    data[59 + 8] = variants[i];
    munit_assert(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                   TC_CHUID_PROFILE_PIV, &chuid) == TC_TLV_INVALID);
    data[59 + 8] = 0x80;
  }
  memset(data + 31, 0, 16);
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                 TC_CHUID_PROFILE_PIV, &chuid) == TC_TLV_INVALID);
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                 TC_CHUID_PROFILE_PIV_SP800_73_4, &chuid) == TC_TLV_OK);
  for (i = 0; i < 16; ++i)
    data[31 + i] = (uint8_t)(i + 32);
  uuid_mark(data + 31, 4);
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                 TC_CHUID_PROFILE_PIV, &chuid) == TC_TLV_OK);
  for (i = 0; i < sizeof data; ++i) {
    munit_assert(TC_PIV_CHUID_read((TC_bytes){data, i}, TC_PIV_CHUID_CONTAINER,
                                   TC_CHUID_PROFILE_PIV, &chuid) != TC_TLV_OK);
    munit_assert(memcmp(&chuid, &saved, sizeof chuid) == 0);
  }
  for (i = 0; i < sizeof invalid_dates / sizeof invalid_dates[0]; ++i) {
    memcpy(data + 49, invalid_dates[i], 8);
    munit_assert(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                   TC_CHUID_PROFILE_PIV, &chuid) == TC_TLV_INVALID);
  }
  memcpy(data + 49, "20240229", 8);
  data[57] = 0x34;
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                 TC_CHUID_PROFILE_PIV, &chuid) == TC_TLV_INVALID);
  munit_assert(memcmp(&chuid, &saved, sizeof chuid) == 0);
  data[57] = 0x36;
  data[30] = 15;
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                 TC_CHUID_PROFILE_PIV, &chuid) == TC_TLV_INVALID);
  data[30] = 16;
  memmove(data + 57, data + 75, 6);
  data[1] = 61;
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data, 63}, TC_PIV_CHUID_CONTAINER, TC_CHUID_PROFILE_PIV,
                                 &chuid) == TC_TLV_OK);
  munit_assert(!chuid.cardholder_uuid.data && !chuid.cardholder_uuid.length);
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data, 63}, TC_PIV_CHUID_CONTAINER,
                                 TC_CHUID_PROFILE_TWIC_SIGNED, &chuid) == TC_TLV_OK);
  memset(data + 31, 0, 16);
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data, 63}, TC_PIV_CHUID_CONTAINER,
                                 TC_CHUID_PROFILE_TWIC_SIGNED, &chuid) == TC_TLV_OK);
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data, 63}, TC_PIV_CHUID_CONTAINER,
                                 TC_CHUID_PROFILE_TWIC_UNSIGNED, &chuid) == TC_TLV_INVALID);
  data[57] = 0xfe;
  data[58] = 0;
  data[1] = 57;
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data, 59}, TC_PIV_CHUID_CONTAINER,
                                 TC_CHUID_PROFILE_TWIC_UNSIGNED, &chuid) == TC_TLV_OK);
  munit_assert(!chuid.signature.data && !chuid.signature.length);
  {
    union {
      TC_PIV_CHUID result;
      uint8_t bytes[256];
    } overlapping;
    uint8_t original[sizeof overlapping];
    for (int encoding = TC_PIV_CHUID_CONTENTS; encoding <= TC_PIV_CHUID_CONTAINER; ++encoding) {
      memset(&overlapping, 0x5a, sizeof overlapping);
      memcpy(overlapping.bytes, data, 59);
      memcpy(original, &overlapping, sizeof original);
      size_t offset = encoding == TC_PIV_CHUID_CONTENTS ? 2 : 0;
      munit_assert_int(TC_PIV_CHUID_read((TC_bytes){overlapping.bytes + offset, 59 - offset},
                                         (TC_PIV_CHUID_encoding)encoding,
                                         TC_CHUID_PROFILE_TWIC_UNSIGNED, &overlapping.result),
                       ==, TC_TLV_ARGUMENT);
      munit_assert_memory_equal(sizeof original, original, &overlapping);
    }
  }
  for (i = 0; i < 2; ++i) {
    munit_assert_null(chuid.signed_content[i].data);
    munit_assert_size(chuid.signed_content[i].length, ==, 0);
  }
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data, 59}, TC_PIV_CHUID_CONTAINER, TC_CHUID_PROFILE_PIV,
                                 &chuid) == TC_TLV_INVALID);
  saved = chuid;
  {
    static const uint8_t extras[] = {0x3d, 0xee, 0x32, 0x33, 0x40, 0x36, 0x3e};
    for (i = 0; i < sizeof extras; ++i) {
      data[57] = extras[i];
      data[58] = 0;
      data[59] = 0xfe;
      data[60] = 0;
      data[1] = 59;
      munit_assert(TC_PIV_CHUID_read((TC_bytes){data, 61}, TC_PIV_CHUID_CONTAINER,
                                     TC_CHUID_PROFILE_TWIC_UNSIGNED, &chuid) == TC_TLV_INVALID);
      munit_assert(TC_PIV_CHUID_read((TC_bytes){data, 61}, TC_PIV_CHUID_CONTAINER,
                                     TC_CHUID_PROFILE_PIV, &chuid) == TC_TLV_INVALID);
      munit_assert(memcmp(&chuid, &saved, sizeof chuid) == 0);
    }
  }
  munit_assert(TC_PIV_CHUID_read((TC_bytes){NULL, 1}, TC_PIV_CHUID_CONTENTS, TC_CHUID_PROFILE_PIV,
                                 &chuid) == TC_TLV_ARGUMENT);
  munit_assert(TC_PIV_CHUID_read((TC_bytes){data, 61}, TC_PIV_CHUID_CONTAINER, TC_CHUID_PROFILE_PIV,
                                 NULL) == TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

TC_TEST(test_boundaries)
{
  uint8_t data[66] = {0x53, 0, 0x30, 25};
  TC_PIV_CHUID chuid, saved;
  unsigned profile;
  size_t length, cut;
  data[29] = 0x34;
  data[30] = 16;
  uuid_mark(data + 31, 4);
  data[47] = 0x35;
  data[48] = 8;
  memcpy(data + 49, "20301231", 8);
  for (profile = TC_CHUID_PROFILE_PIV; profile <= TC_CHUID_PROFILE_TWIC_UNSIGNED; ++profile) {
    length = profile == TC_CHUID_PROFILE_TWIC_UNSIGNED ? 59 : 63;
    data[57] = 0x3e;
    data[58] = 2;
    data[59] = 0x30;
    data[60] = 0;
    data[length - 2] = 0xfe;
    data[length - 1] = 0;
    data[1] = (uint8_t)(length - 2);
    munit_assert_int(TC_PIV_CHUID_read((TC_bytes){data, length}, TC_PIV_CHUID_CONTAINER,
                                       (TC_PIV_CHUID_profile)profile, &chuid),
                     ==, TC_TLV_OK);
    saved = chuid;
    /* Make the outer length agree with a truncated field inside it. */
    for (cut = 2; cut < length; ++cut) {
      data[1] = (uint8_t)(cut - 2);
      munit_assert_int(TC_PIV_CHUID_read((TC_bytes){data, cut}, TC_PIV_CHUID_CONTAINER,
                                         (TC_PIV_CHUID_profile)profile, &chuid),
                       !=, TC_TLV_OK);
      munit_assert_memory_equal(sizeof chuid, &chuid, &saved);
    }
    data[1] = (uint8_t)(length - 2);
    data[0] = 0x54;
    munit_assert_int(TC_PIV_CHUID_read((TC_bytes){data, length}, TC_PIV_CHUID_CONTAINER,
                                       (TC_PIV_CHUID_profile)profile, &chuid),
                     ==, TC_TLV_INVALID);
    data[0] = 0x53;
    data[length] = 0;
    munit_assert_int(TC_PIV_CHUID_read((TC_bytes){data, length + 1}, TC_PIV_CHUID_CONTAINER,
                                       (TC_PIV_CHUID_profile)profile, &chuid),
                     ==, TC_TLV_INVALID);
    data[length - 1] = 1;
    data[1] = (uint8_t)(length - 1);
    munit_assert_int(TC_PIV_CHUID_read((TC_bytes){data, length + 1}, TC_PIV_CHUID_CONTAINER,
                                       (TC_PIV_CHUID_profile)profile, &chuid),
                     ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof chuid, &chuid, &saved);
  }
  return MUNIT_OK;
}

TC_TEST(test_signed_content)
{
  enum { FIELD_BYTES = 61, SIGNATURE_OFFSET = 55, FOOTER_OFFSET = 59, WRAPPER_BYTES = 3 };
  uint8_t fields[FIELD_BYTES] = {0x30, 25}, wrapped[80];
  TC_PIV_CHUID chuid;
  fields[27] = 0x34;
  fields[28] = 16;
  uuid_mark(fields + 29, 5);
  fields[45] = 0x35;
  fields[46] = 8;
  memcpy(fields + 47, "20301231", 8);
  fields[SIGNATURE_OFFSET] = 0x3e;
  fields[SIGNATURE_OFFSET + 1] = 2;
  fields[SIGNATURE_OFFSET + 2] = 0x30;
  fields[FOOTER_OFFSET] = 0xfe;
  for (unsigned mask = 0; mask < 8; ++mask) {
    size_t length = WRAPPER_BYTES, signature = 0, footer = 0;
    for (size_t i = 0; i < sizeof fields; ++i) {
      if (i == SIGNATURE_OFFSET)
        signature = length;
      if (i == FOOTER_OFFSET)
        footer = length;
      /* Preserve nonminimal definite lengths in fields on both sides of CMS. */
      if ((i == 1 && (mask & 1)) || (i == SIGNATURE_OFFSET + 1 && (mask & 2)) ||
          (i == FOOTER_OFFSET + 1 && (mask & 4)))
        wrapped[length++] = 0x81;
      wrapped[length++] = fields[i];
    }
    wrapped[0] = 0x53;
    wrapped[1] = 0x81;
    wrapped[2] = (uint8_t)(length - WRAPPER_BYTES);
    for (unsigned mode = 0; mode < 2; ++mode) {
      for (unsigned profile = TC_CHUID_PROFILE_PIV; profile <= TC_CHUID_PROFILE_TWIC_SIGNED;
           ++profile) {
        const size_t skip = mode == TC_PIV_CHUID_CONTENTS ? WRAPPER_BYTES : 0;
        munit_assert_int(TC_PIV_CHUID_read((TC_bytes){wrapped + skip, length - skip},
                                           (TC_PIV_CHUID_encoding)mode,
                                           (TC_PIV_CHUID_profile)profile, &chuid),
                         ==, TC_TLV_OK);
        munit_assert_ptr_equal(chuid.signed_content[0].data, wrapped + WRAPPER_BYTES);
        munit_assert_size(chuid.signed_content[0].length, ==, signature - WRAPPER_BYTES);
        munit_assert_ptr_equal(chuid.signed_content[1].data, wrapped + footer);
        munit_assert_size(chuid.signed_content[1].length, ==, length - footer);
        munit_assert_size(chuid.signature.length, ==, 2);
      }
    }
  }
  return MUNIT_OK;
}

TC_TEST(test_sp800_73_4_key_map)
{
  enum { PREFIX_BYTES = 55, MAP_HEADER_BYTES = 4, MAX_MAP_BYTES = 512 };
  uint8_t fields[PREFIX_BYTES + MAP_HEADER_BYTES + MAX_MAP_BYTES + 1 + 8] = {0x30, 25};
  fields[27] = 0x34;
  fields[28] = 16;
  fields[45] = 0x35;
  fields[46] = 8;
  memcpy(fields + 47, "20301231", 8);
  static const size_t sizes[] = {0, 1, MAX_MAP_BYTES, MAX_MAP_BYTES + 1};
  for (size_t i = 0; i < sizeof sizes / sizeof *sizes; ++i) {
    const size_t size = sizes[i], map = PREFIX_BYTES;
    fields[map] = 0x3d;
    fields[map + 1] = 0x82;
    fields[map + 2] = (uint8_t)(size >> 8);
    fields[map + 3] = (uint8_t)size;
    memset(fields + map + MAP_HEADER_BYTES, 0xa5, size);
    const size_t signature = map + MAP_HEADER_BYTES + size;
    fields[signature] = 0x3e;
    fields[signature + 1] = 2;
    fields[signature + 2] = 0x30;
    fields[signature + 3] = 0;
    fields[signature + 4] = 0xfe;
    fields[signature + 5] = 0;
    TC_PIV_CHUID parsed, preserved;
    memset(&parsed, 0xa5, sizeof parsed);
    preserved = parsed;
    const TC_TLV_result result =
        TC_PIV_CHUID_read((TC_bytes){fields, signature + 6}, TC_PIV_CHUID_CONTENTS,
                          TC_CHUID_PROFILE_PIV_SP800_73_4, &parsed);
    munit_assert_int(result, ==, size <= MAX_MAP_BYTES ? TC_TLV_OK : TC_TLV_INVALID);
    if (result == TC_TLV_OK) {
      munit_assert_ptr_equal(parsed.authentication_key_map.data, fields + map + MAP_HEADER_BYTES);
      munit_assert_size(parsed.authentication_key_map.length, ==, size);
      munit_assert_ptr_equal(parsed.signed_content[0].data, fields);
      munit_assert_size(parsed.signed_content[0].length, ==, signature);
      munit_assert_ptr_equal(parsed.signed_content[1].data, fields + signature + 4);
      munit_assert_size(parsed.signed_content[1].length, ==, 2);
    } else
      munit_assert_memory_equal(sizeof parsed, &parsed, &preserved);
    for (unsigned profile = TC_CHUID_PROFILE_PIV; profile <= TC_CHUID_PROFILE_TWIC_UNSIGNED;
         ++profile)
      munit_assert_int(TC_PIV_CHUID_read((TC_bytes){fields, signature + 6}, TC_PIV_CHUID_CONTENTS,
                                         (TC_PIV_CHUID_profile)profile, &parsed),
                       ==, TC_TLV_INVALID);
    /* A second map cannot occupy the signature field. */
    fields[signature] = 0x3d;
    munit_assert_int(TC_PIV_CHUID_read((TC_bytes){fields, signature + 6}, TC_PIV_CHUID_CONTENTS,
                                       TC_CHUID_PROFILE_PIV_SP800_73_4, &parsed),
                     ==, TC_TLV_INVALID);
  }
  return MUNIT_OK;
}

/* Append one TLV with a single-byte length and a fill value. */
static size_t field_append(uint8_t* out, size_t offset, uint8_t tag, size_t length, uint8_t fill)
{
  out[offset] = tag;
  out[offset + 1] = (uint8_t)length;
  memset(out + offset + 2, fill, length);
  return offset + 2 + length;
}

/* Append a 16-byte UUID field of the given RFC 4122 version. */
static size_t uuid_append(uint8_t* out, size_t offset, uint8_t tag, unsigned version)
{
  const size_t end = field_append(out, offset, tag, 16, 0x55);
  uuid_mark(out + offset + 2, version);
  return end;
}

/* SP 800-73-4 Part 1 Table 9 optional fields: EE (2), 32 (4) and 33 (9).
 * SP 800-73-5 Part 1 Table 10 eliminated them, so only the SP 800-73-4
 * profile accepts them. */
TC_TEST(test_deprecated_fields)
{
  enum { BUFFER_LENGTH = 1, ORGANIZATION = 2, DUNS = 4, CARDHOLDER = 8 };
  uint8_t fields[128];
  TC_PIV_CHUID chuid, preserved;
  for (unsigned mask = 0; mask < 16; ++mask) {
    size_t length = 0, signed_start, signature;
    if (mask & BUFFER_LENGTH)
      length = field_append(fields, length, 0xee, 2, 0x11);
    signed_start = length;
    length = field_append(fields, length, 0x30, 25, 0x22);
    if (mask & ORGANIZATION)
      length = field_append(fields, length, 0x32, 4, 0x33);
    if (mask & DUNS)
      length = field_append(fields, length, 0x33, 9, 0x44);
    length = uuid_append(fields, length, 0x34, 1);
    fields[length] = 0x35;
    fields[length + 1] = 8;
    memcpy(fields + length + 2, "20301231", 8);
    length += 10;
    if (mask & CARDHOLDER)
      length = uuid_append(fields, length, 0x36, 4);
    signature = length;
    length = field_append(fields, length, 0x3e, 2, 0x30);
    length = field_append(fields, length, 0xfe, 0, 0);
    for (unsigned profile = TC_CHUID_PROFILE_PIV; profile <= TC_CHUID_PROFILE_PIV_SP800_73_4;
         ++profile) {
      memset(&chuid, 0xa5, sizeof chuid);
      preserved = chuid;
      const int deprecated = (mask & (BUFFER_LENGTH | ORGANIZATION | DUNS)) != 0;
      const int expect_ok = profile == TC_CHUID_PROFILE_PIV_SP800_73_4 ||
                            (profile == TC_CHUID_PROFILE_PIV && !deprecated) ||
                            (profile == TC_CHUID_PROFILE_TWIC_SIGNED && !mask);
      const TC_TLV_result result = TC_PIV_CHUID_read(
          (TC_bytes){fields, length}, TC_PIV_CHUID_CONTENTS, (TC_PIV_CHUID_profile)profile, &chuid);
      munit_assert_int(result, ==, expect_ok ? TC_TLV_OK : TC_TLV_INVALID);
      if (!expect_ok) {
        munit_assert_memory_equal(sizeof chuid, &chuid, &preserved);
        continue;
      }
      /* The signature excludes Buffer Length (SP 800-73-4 Part 1 section 3.1.2). */
      munit_assert_ptr_equal(chuid.signed_content[0].data, fields + signed_start);
      munit_assert_size(chuid.signed_content[0].length, ==, signature - signed_start);
      munit_assert_ptr_equal(chuid.signed_content[1].data, fields + length - 2);
      munit_assert_size(chuid.signed_content[1].length, ==, 2);
      munit_assert_ptr_equal(chuid.fascn.data, fields + signed_start + 2);
      munit_assert_size(chuid.card_uuid.length, ==, 16);
      munit_assert_int(chuid.card_uuid.data[0], ==, 0x55);
      munit_assert_size(chuid.cardholder_uuid.length, ==, mask & CARDHOLDER ? 16 : 0);
      munit_assert_null(chuid.authentication_key_map.data);
    }
  }
  /* Unsigned TWIC (TWIC Part 2 section 4.6.1) rejects each deprecated field. */
  for (unsigned mask = 0; mask < 8; ++mask) {
    size_t length = 0;
    if (mask & BUFFER_LENGTH)
      length = field_append(fields, length, 0xee, 2, 0);
    length = field_append(fields, length, 0x30, 25, 0);
    if (mask & ORGANIZATION)
      length = field_append(fields, length, 0x32, 4, 0);
    if (mask & DUNS)
      length = field_append(fields, length, 0x33, 9, 0);
    length = field_append(fields, length, 0x34, 16, 0);
    fields[length] = 0x35;
    fields[length + 1] = 8;
    memcpy(fields + length + 2, "20301231", 8);
    length += 10;
    length = field_append(fields, length, 0xfe, 0, 0);
    memset(&chuid, 0xa5, sizeof chuid);
    preserved = chuid;
    munit_assert_int(TC_PIV_CHUID_read((TC_bytes){fields, length}, TC_PIV_CHUID_CONTENTS,
                                       TC_CHUID_PROFILE_TWIC_UNSIGNED, &chuid),
                     ==, mask ? TC_TLV_INVALID : TC_TLV_OK);
    if (mask)
      munit_assert_memory_equal(sizeof chuid, &chuid, &preserved);
  }
  /* Each deprecated field has a fixed length in the SP 800-73-4 profile. */
  static const struct {
    uint8_t tag;
    size_t length;
  } sizes[] = {{0xee, 2}, {0x32, 4}, {0x33, 9}};
  for (size_t i = 0; i < sizeof sizes / sizeof *sizes; ++i)
    for (size_t delta = 0; delta < 3; ++delta) {
      const size_t value_length = sizes[i].length + delta - 1;
      size_t length = 0;
      if (sizes[i].tag == 0xee)
        length = field_append(fields, length, 0xee, value_length, 0);
      length = field_append(fields, length, 0x30, 25, 0);
      if (sizes[i].tag != 0xee)
        length = field_append(fields, length, sizes[i].tag, value_length, 0);
      length = field_append(fields, length, 0x34, 16, 0);
      fields[length] = 0x35;
      fields[length + 1] = 8;
      memcpy(fields + length + 2, "20301231", 8);
      length += 10;
      length = field_append(fields, length, 0x3e, 2, 0x30);
      length = field_append(fields, length, 0xfe, 0, 0);
      munit_assert_int(TC_PIV_CHUID_read((TC_bytes){fields, length}, TC_PIV_CHUID_CONTENTS,
                                         TC_CHUID_PROFILE_PIV_SP800_73_4, &chuid),
                       ==, delta == 1 ? TC_TLV_OK : TC_TLV_INVALID);
    }
  /* Table 9 order is fixed. Each sequence moves or repeats one deprecated field. */
  static const uint8_t orders[][9] = {
      {0x30, 0xee, 0x34, 0x35, 0x3e, 0xfe},       {0x32, 0x30, 0x34, 0x35, 0x3e, 0xfe},
      {0x30, 0x33, 0x32, 0x34, 0x35, 0x3e, 0xfe}, {0x30, 0x34, 0x32, 0x35, 0x3e, 0xfe},
      {0x30, 0x34, 0x35, 0x33, 0x3e, 0xfe},       {0xee, 0xee, 0x30, 0x34, 0x35, 0x3e, 0xfe},
      {0x30, 0x32, 0x32, 0x34, 0x35, 0x3e, 0xfe}, {0x30, 0x33, 0x33, 0x34, 0x35, 0x3e, 0xfe}};
  for (size_t i = 0; i < sizeof orders / sizeof *orders; ++i) {
    size_t length = 0;
    for (size_t j = 0; j < sizeof orders[i] && orders[i][j]; ++j) {
      const uint8_t tag = orders[i][j];
      if (tag == 0x35) {
        fields[length] = 0x35;
        fields[length + 1] = 8;
        memcpy(fields + length + 2, "20301231", 8);
        length += 10;
        continue;
      }
      const size_t value_length = tag == 0xee   ? 2
                                  : tag == 0x30 ? 25
                                  : tag == 0x32 ? 4
                                  : tag == 0x33 ? 9
                                  : tag == 0x34 ? 16
                                  : tag == 0x3e ? 2
                                                : 0;
      length = field_append(fields, length, tag, value_length, 0x30);
    }
    for (unsigned profile = TC_CHUID_PROFILE_PIV; profile <= TC_CHUID_PROFILE_PIV_SP800_73_4;
         ++profile)
      munit_assert_int(TC_PIV_CHUID_read((TC_bytes){fields, length}, TC_PIV_CHUID_CONTENTS,
                                         (TC_PIV_CHUID_profile)profile, &chuid),
                       ==, TC_TLV_INVALID);
  }
  return MUNIT_OK;
}

TC_TEST(test_arguments)
{
  static const uint8_t data[] = {0x53, 0};
  TC_PIV_CHUID chuid, preserved;
  memset(&chuid, 0xa5, sizeof chuid);
  preserved = chuid;
  munit_assert_int(
      TC_PIV_CHUID_read((TC_bytes){NULL, 1}, TC_PIV_CHUID_CONTENTS, TC_CHUID_PROFILE_PIV, &chuid),
      ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                     TC_CHUID_PROFILE_PIV, NULL),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, (TC_PIV_CHUID_encoding)2,
                                     TC_CHUID_PROFILE_PIV, &chuid),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_CHUID_read((TC_bytes){data, sizeof data}, TC_PIV_CHUID_CONTAINER,
                                     (TC_PIV_CHUID_profile)4, &chuid),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof chuid, &chuid, &preserved);
  munit_assert_int(
      TC_PIV_CHUID_read((TC_bytes){NULL, 0}, TC_PIV_CHUID_CONTAINER, TC_CHUID_PROFILE_PIV, &chuid),
      ==, TC_TLV_MORE);
  munit_assert_int(
      TC_PIV_CHUID_read((TC_bytes){NULL, 0}, TC_PIV_CHUID_CONTENTS, TC_CHUID_PROFILE_PIV, &chuid),
      ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof chuid, &chuid, &preserved);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/boundaries", test_boundaries, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/profiles", test_profiles, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/signed-content", test_signed_content, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/sp800-73-4-key-map", test_sp800_73_4_key_map, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/deprecated-fields", test_deprecated_fields, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/arguments", test_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/chuid", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
