/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "munit.h"
#include <string.h>
#include <tiny_crypto/piv_printed.h>

enum { BUFFER_BYTES = 256, DATE_BYTES = 9 };

typedef struct {
  uint8_t bytes[BUFFER_BYTES];
  size_t length;
} fixture;

static void append(fixture *value, uint8_t tag, const void *bytes,
                   size_t length) {
  munit_assert_size(length, <, 128);
  munit_assert_size(value->length + length + 2, <=, sizeof value->bytes);
  value->bytes[value->length++] = tag;
  value->bytes[value->length++] = (uint8_t)length;
  if (length)
    memcpy(value->bytes + value->length, bytes, length);
  value->length += length;
}

static size_t find(const fixture *value, uint8_t tag) {
  for (size_t offset = 0; offset + 2 <= value->length;
       offset += 2 + value->bytes[offset + 1])
    if (value->bytes[offset] == tag)
      return offset;
  munit_error("fixture tag is missing");
}

static fixture printed(TC_PIV_printed_profile profile) {
  static const uint8_t name[] = "TEST PERSON";
  static const uint8_t employee[] = "PORT WORKER";
  static const uint8_t piv_date[] = "2026SEP10";
  static const uint8_t twic_date[] = "10SEP2026";
  static const uint8_t serial[] = "12345678";
  static const uint8_t piv_issuer[] = "123456789012345";
  static const uint8_t twic_issuer[] = "70991234";
  static const uint8_t organization[] = "EXAMPLE";
  fixture value = {{0}, 0};
  append(&value, 0x01, name, sizeof name - 1);
  append(&value, 0x02, employee, sizeof employee - 1);
  append(&value, 0x04,
         profile == TC_PIV_PRINTED_PROFILE_PIV ? piv_date : twic_date,
         DATE_BYTES);
  append(&value, 0x05, serial, sizeof serial - 1);
  append(&value, 0x06,
         profile == TC_PIV_PRINTED_PROFILE_PIV ? piv_issuer : twic_issuer,
         profile == TC_PIV_PRINTED_PROFILE_PIV ? sizeof piv_issuer - 1
                                               : sizeof twic_issuer - 1);
  append(&value, 0x07, organization, sizeof organization - 1);
  append(&value, 0x08, NULL, 0);
  if (profile == TC_PIV_PRINTED_PROFILE_PIV)
    append(&value, 0xfe, NULL, 0);
  return value;
}

static MunitResult profiles(const MunitParameter params[], void *user) {
  (void)params;
  (void)user;
  for (unsigned profile = TC_PIV_PRINTED_PROFILE_PIV;
       profile <= TC_PIV_PRINTED_PROFILE_TWIC; ++profile) {
    fixture value = printed((TC_PIV_printed_profile)profile);
    TC_PIV_printed parsed;
    memset(&parsed, 0xa5, sizeof parsed);
    munit_assert_int(TC_PIV_printed_read((TC_bytes){value.bytes, value.length},
                                         TC_PIV_PRINTED_CONTENTS,
                                         (TC_PIV_printed_profile)profile,
                                         &parsed),
                     ==, TC_TLV_OK);
    munit_assert_size(parsed.name.length, ==, 11);
    munit_assert_memory_equal(parsed.name.length, parsed.name.data,
                              "TEST PERSON");
    munit_assert_uint(parsed.expiration.year, ==, 2026);
    munit_assert_uint8(parsed.expiration.month, ==, 9);
    munit_assert_uint8(parsed.expiration.day, ==, 10);
    munit_assert_size(parsed.organization_1.length, ==, 7);

    fixture container = {{0}, 0};
    append(&container, 0x53, value.bytes, value.length);
    munit_assert_int(
        TC_PIV_printed_read((TC_bytes){container.bytes, container.length},
                            TC_PIV_PRINTED_CONTAINER,
                            (TC_PIV_printed_profile)profile, &parsed),
        ==, TC_TLV_OK);
    munit_assert_ptr_equal(parsed.name.data, container.bytes + 4);
  }
  return MUNIT_OK;
}

static MunitResult failures(const MunitParameter params[], void *user) {
  (void)params;
  (void)user;
  fixture piv = printed(TC_PIV_PRINTED_PROFILE_PIV);
  TC_PIV_printed unchanged, out;
  memset(&unchanged, 0xa5, sizeof unchanged);
  static const uint8_t tags[] = {0x01, 0x02, 0x04, 0x05,
                                 0x06, 0x07, 0x08, 0xfe};
  for (size_t i = 0; i < sizeof tags; ++i) {
    fixture changed = piv;
    changed.bytes[find(&changed, tags[i])] ^= 0x10;
    out = unchanged;
    munit_assert_int(
        TC_PIV_printed_read((TC_bytes){changed.bytes, changed.length},
                            TC_PIV_PRINTED_CONTENTS, TC_PIV_PRINTED_PROFILE_PIV,
                            &out),
        ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof out, &out, &unchanged);
  }
  for (size_t length = 0; length < piv.length; ++length) {
    out = unchanged;
    munit_assert_int(TC_PIV_printed_read((TC_bytes){piv.bytes, length},
                                         TC_PIV_PRINTED_CONTENTS,
                                         TC_PIV_PRINTED_PROFILE_PIV, &out),
                     !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof out, &out, &unchanged);
  }
  fixture twic = printed(TC_PIV_PRINTED_PROFILE_TWIC);
  twic.bytes[find(&twic, 0x05) + 2] = 'X';
  munit_assert_int(TC_PIV_printed_read((TC_bytes){twic.bytes, twic.length},
                                       TC_PIV_PRINTED_CONTENTS,
                                       TC_PIV_PRINTED_PROFILE_TWIC, &out),
                   ==, TC_TLV_INVALID);
  twic = printed(TC_PIV_PRINTED_PROFILE_TWIC);
  twic.bytes[find(&twic, 0x06) + 2] = '8';
  munit_assert_int(TC_PIV_printed_read((TC_bytes){twic.bytes, twic.length},
                                       TC_PIV_PRINTED_CONTENTS,
                                       TC_PIV_PRINTED_PROFILE_TWIC, &out),
                   ==, TC_TLV_INVALID);
  munit_assert_int(TC_PIV_printed_read((TC_bytes){piv.bytes, piv.length},
                                       TC_PIV_PRINTED_CONTENTS,
                                       (TC_PIV_printed_profile)99, &out),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_printed_read((TC_bytes){piv.bytes, piv.length},
                                       TC_PIV_PRINTED_CONTENTS,
                                       TC_PIV_PRINTED_PROFILE_PIV,
                                       (TC_PIV_printed *)piv.bytes),
                   ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult expiration(const MunitParameter params[], void *user) {
  (void)params;
  (void)user;
  fixture value = printed(TC_PIV_PRINTED_PROFILE_PIV);
  TC_PIV_printed parsed;
  munit_assert_int(TC_PIV_printed_read((TC_bytes){value.bytes, value.length},
                                       TC_PIV_PRINTED_CONTENTS,
                                       TC_PIV_PRINTED_PROFILE_PIV, &parsed),
                   ==, TC_TLV_OK);
  const uint8_t matching[] = "20260910";
  const uint8_t different[] = "20260911";
  const uint8_t malformed[] = "20261310";
  TC_X509_time at = {2026, 9, 10, 23, 59, 59};
  int valid = -1;
  munit_assert_int(
      TC_PIV_printed_expiration_check(
          &parsed, (TC_bytes){matching, sizeof matching - 1}, &at, &valid),
      ==, TC_TLV_OK);
  munit_assert_int(valid, ==, 1);
  at.day = 11;
  munit_assert_int(
      TC_PIV_printed_expiration_check(
          &parsed, (TC_bytes){matching, sizeof matching - 1}, &at, &valid),
      ==, TC_TLV_OK);
  munit_assert_int(valid, ==, 0);
  at.day = 10;
  munit_assert_int(
      TC_PIV_printed_expiration_check(
          &parsed, (TC_bytes){different, sizeof different - 1}, &at, &valid),
      ==, TC_TLV_OK);
  munit_assert_int(valid, ==, 0);
  munit_assert_int(
      TC_PIV_printed_expiration_check(
          &parsed, (TC_bytes){malformed, sizeof malformed - 1}, &at, &valid),
      ==, TC_TLV_INVALID);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/profiles", profiles, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/failures", failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/expiration", expiration, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

int main(int argc, char **argv) {
  MunitSuite suite = {"/piv/printed", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
