/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_certificate.h>
#include "munit.h"
#include "test_util.h"
#include <string.h>

TC_TEST(containers)
{
  static const uint8_t fixtures[][16] = {
      {0x53, 8, 0x70, 1, 0x30, 0x71, 1, 0, 0xfe, 0},
      {0x53, 6, 0x70, 1, 0x30, 0x71, 1, 1},
      {0x53, 12, 0x70, 1, 0x30, 0x71, 1, 0, 0x7f, 0x21, 1, 0x5a, 0xfe, 0}};
  const size_t lengths[] = {10, 8, 14};
  const TC_PIV_certificate_profile profiles[] = {TC_PIV_CERTIFICATE_SLOT, TC_PIV_CERTIFICATE_TWIC,
                                                 TC_PIV_CERTIFICATE_SM_SIGNER};
  for (size_t i = 0; i < 3; ++i) {
    TC_PIV_certificate out;
    TC_bytes input = {fixtures[i], lengths[i]};
    munit_assert_int(
        TC_PIV_certificate_read(input, profiles[i], TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out), ==,
        TC_TLV_OK);
    munit_assert_ptr_equal(out.certificate.data, input.data + 4);
    munit_assert_size(out.certificate.length, ==, 1);
    munit_assert_int(out.compression, ==,
                     i == 1 ? TC_PIV_CERTIFICATE_GZIP : TC_PIV_CERTIFICATE_PLAIN);
    munit_assert_size(out.intermediate_cvc.length, ==, i == 2 ? 4 : 0);
    if (i == 2)
      munit_assert_ptr_equal(out.intermediate_cvc.data, input.data + 8);
    for (size_t n = 0; n < input.length; ++n) {
      TC_bytes prefix = {input.data, n};
      memset(&out, 0x5a, sizeof out);
      TC_PIV_certificate saved = out;
      munit_assert_int(
          TC_PIV_certificate_read(prefix, profiles[i], TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out),
          ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof out, &out, &saved);
    }
    for (size_t j = 0; j < 3; ++j) {
      /* The PIV slot form 70, 71, FE also reads as SM signer and TWIC. */
      if (i == j || (i == 0 && j != 0))
        continue;
      munit_assert_int(
          TC_PIV_certificate_read(input, profiles[j], TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out),
          ==, TC_TLV_INVALID);
    }
  }
  uint8_t buffer[16];
  memcpy(buffer, fixtures[0], sizeof buffer);
  TC_bytes input = {buffer, lengths[0]};
  TC_PIV_certificate out;
  for (unsigned info = 0; info <= 255; ++info) {
    buffer[7] = (uint8_t)info;
    munit_assert_int(TC_PIV_certificate_read(input, TC_PIV_CERTIFICATE_SLOT,
                                             TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out),
                     ==, info <= 1 ? TC_TLV_OK : TC_TLV_INVALID);
  }
  union {
    TC_PIV_certificate out;
    uint8_t bytes[64];
  } alias;
  memset(alias.bytes, 0x5a, sizeof alias.bytes);
  memcpy(alias.bytes, fixtures[0], lengths[0]);
  uint8_t saved[sizeof alias.bytes];
  memcpy(saved, alias.bytes, sizeof saved);
  input.data = alias.bytes;
  munit_assert_int(TC_PIV_certificate_read(input, TC_PIV_CERTIFICATE_SLOT,
                                           TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &alias.out),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof saved, alias.bytes, saved);
  return MUNIT_OK;
}
/* TWIC Part 2 v5 4.7.1 lists 70 and 71 and calls the structure similar to
 * the PIV one without the MSCUID. A NEXGEN card sends the empty FE of the
 * PIV form after 71. */
TC_TEST(twic_error_detection_code)
{
  static const uint8_t accepted[] = {0x53, 8, 0x70, 1, 0x30, 0x71, 1, 0, 0xfe, 0};
  static const uint8_t rejected[][16] = {
      {0x53, 9, 0x70, 1, 0x30, 0x71, 1, 0, 0xfe, 1, 0},
      {0x53, 11, 0x70, 1, 0x30, 0x71, 1, 0, 0x72, 1, 0x5c, 0xfe, 0},
      {0x53, 10, 0x70, 1, 0x30, 0x71, 1, 0, 0xfe, 0, 0xfe, 0},
      {0x53, 8, 0x70, 1, 0x30, 0x71, 1, 0, 0x72, 0}};
  const size_t lengths[] = {11, 13, 12, 10};
  TC_PIV_certificate out;
  munit_assert_int(TC_PIV_certificate_read((TC_bytes){accepted, sizeof accepted},
                                           TC_PIV_CERTIFICATE_TWIC,
                                           TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out),
                   ==, TC_TLV_OK);
  munit_assert_ptr_equal(out.certificate.data, accepted + 4);
  munit_assert_null(out.mscuid.data);
  for (size_t i = 0; i < sizeof lengths / sizeof *lengths; ++i) {
    memset(&out, 0x5a, sizeof out);
    TC_PIV_certificate saved = out;
    munit_assert_int(TC_PIV_certificate_read((TC_bytes){rejected[i], lengths[i]},
                                             TC_PIV_CERTIFICATE_TWIC,
                                             TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out),
                     ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  return MUNIT_OK;
}

TC_TEST(boundaries)
{
  uint8_t buffer[2048];
  for (unsigned intermediate = 0; intermediate <= 1; ++intermediate) {
    const size_t maximum = intermediate ? 601 : 1856;
    for (size_t length = maximum - 1; length <= maximum + 1; ++length) {
      memset(buffer, 0x5a, sizeof buffer);
      buffer[0] = 0x53;
      buffer[1] = 0x82;
      size_t offset = 4;
      if (intermediate) {
        const uint8_t certificate[] = {0x70, 1, 0x30, 0x71, 1, 0};
        memcpy(buffer + offset, certificate, sizeof certificate);
        offset += sizeof certificate;
        buffer[offset++] = 0x7f;
        buffer[offset++] = 0x21;
      } else
        buffer[offset++] = 0x70;
      buffer[offset++] = 0x82;
      buffer[offset++] = (uint8_t)(length >> 8);
      buffer[offset++] = (uint8_t)length;
      const size_t content_offset = offset;
      offset += length;
      if (!intermediate) {
        buffer[offset++] = 0x71;
        buffer[offset++] = 1;
        buffer[offset++] = 0;
      }
      buffer[offset++] = 0xfe;
      buffer[offset++] = 0;
      buffer[2] = (uint8_t)((offset - 4) >> 8);
      buffer[3] = (uint8_t)(offset - 4);
      TC_bytes input = {buffer, offset};
      TC_PIV_certificate out;
      memset(&out, 0x5a, sizeof out);
      uint8_t saved[sizeof out];
      memcpy(saved, &out, sizeof out);
      munit_assert_int(TC_PIV_certificate_read(input, TC_PIV_CERTIFICATE_SM_SIGNER,
                                               TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out),
                       ==, length > maximum ? TC_TLV_LIMIT : TC_TLV_OK);
      if (length > maximum)
        munit_assert_memory_equal(sizeof out, &out, saved);
      else if (intermediate) {
        munit_assert_size(out.intermediate_cvc.length, ==, length + 5);
        munit_assert_ptr_equal(out.intermediate_cvc.data, buffer + content_offset - 5);
      } else {
        munit_assert_size(out.certificate.length, ==, length);
        munit_assert_ptr_equal(out.certificate.data, buffer + content_offset);
      }
    }
  }
  return MUNIT_OK;
}

TC_TEST(malformed)
{
  static const uint8_t fixtures[][18] = {
      {0x53, 8, 0x71, 1, 0, 0x70, 1, 0x30, 0xfe, 0}, /* Reordered fields. */
      {0x53, 11, 0x70, 1, 0x30, 0x71, 1, 0, 0x71, 1, 0, 0xfe, 0},
      {0x53, 10, 0x70, 1, 0x30, 0x71, 1, 0, 0x72, 0, 0xfe, 0},
      {0x53, 9, 0x70, 1, 0x30, 0x71, 1, 0, 0xfe, 1, 0},
      {0x53, 7, 0x70, 0, 0x71, 1, 0, 0xfe, 0},
      {0x53, 7, 0x70, 1, 0x30, 0x71, 0, 0xfe, 0},
      {0x53, 11, 0x70, 1, 0x30, 0x71, 1, 0, 0x7f, 0x21, 0, 0xfe, 0},
      {0x53, 10, 0x70, 1, 0x30, 0x71, 1, 0, 0xfe, 0, 0xfe, 0},
      {0x53, 8, 0x70, 1, 0x30, 0x71, 1, 0, 0xfe, 0, 0x53, 0}};
  const size_t lengths[] = {10, 13, 12, 11, 9, 9, 13, 12, 12};
  for (size_t i = 0; i < sizeof lengths / sizeof *lengths; ++i) {
    TC_PIV_certificate out;
    memset(&out, 0x5a, sizeof out);
    uint8_t saved[sizeof out];
    memcpy(saved, &out, sizeof out);
    TC_bytes input = {fixtures[i], lengths[i]};
    munit_assert_int(TC_PIV_certificate_read(input, TC_PIV_CERTIFICATE_SM_SIGNER,
                                             TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out),
                     ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof out, &out, saved);
  }
  return MUNIT_OK;
}

/* SP 800-73-4 Part 1 Table 10 and SP 800-73-5 Part 1 Tables 21-40 allow an
 * optional MSCUID (72, at most 38 bytes) before FE. */
TC_TEST(mscuid)
{
  uint8_t buffer[64];
  static const size_t sizes[] = {0, 1, 16, 38, 39};
  for (size_t i = 0; i < sizeof sizes / sizeof *sizes; ++i) {
    const size_t size = sizes[i];
    static const uint8_t prefix[] = {0x53, 0, 0x70, 1, 0x30, 0x71, 1, 1, 0x72};
    memcpy(buffer, prefix, sizeof prefix);
    buffer[9] = (uint8_t)size;
    memset(buffer + 10, 0x5c, size);
    buffer[10 + size] = 0xfe;
    buffer[11 + size] = 0;
    buffer[1] = (uint8_t)(10 + size);
    const TC_bytes input = {buffer, 12 + size};
    const int valid = size && size <= 38;
    TC_PIV_certificate out, saved;
    memset(&out, 0x5a, sizeof out);
    saved = out;
    munit_assert_int(TC_PIV_certificate_read(input, TC_PIV_CERTIFICATE_SLOT,
                                             TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out),
                     ==, valid ? TC_TLV_OK : TC_TLV_INVALID);
    if (valid) {
      munit_assert_ptr_equal(out.mscuid.data, buffer + 10);
      munit_assert_size(out.mscuid.length, ==, size);
      munit_assert_ptr_equal(out.certificate.data, buffer + 4);
      munit_assert_int(out.compression, ==, TC_PIV_CERTIFICATE_GZIP);
      munit_assert_null(out.intermediate_cvc.data);
    } else
      munit_assert_memory_equal(sizeof out, &out, &saved);
    /* The SM signer and TWIC containers carry no MSCUID. */
    munit_assert_int(TC_PIV_certificate_read(input, TC_PIV_CERTIFICATE_SM_SIGNER,
                                             TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out),
                     ==, TC_TLV_INVALID);
    munit_assert_int(TC_PIV_certificate_read(input, TC_PIV_CERTIFICATE_TWIC,
                                             TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out),
                     ==, TC_TLV_INVALID);
  }
  /* MSCUID follows CertInfo and precedes FE. */
  static const uint8_t misplaced[][16] = {
      {0x53, 11, 0x70, 1, 0x30, 0x72, 1, 0x5c, 0x71, 1, 0, 0xfe, 0},
      {0x53, 11, 0x70, 1, 0x30, 0x71, 1, 0, 0xfe, 0, 0x72, 1, 0x5c},
      {0x53, 14, 0x70, 1, 0x30, 0x71, 1, 0, 0x72, 1, 0x5c, 0x72, 1, 0x5c, 0xfe, 0}};
  const size_t lengths[] = {13, 13, 16};
  for (size_t i = 0; i < sizeof lengths / sizeof *lengths; ++i) {
    TC_PIV_certificate out;
    munit_assert_int(TC_PIV_certificate_read((TC_bytes){misplaced[i], lengths[i]},
                                             TC_PIV_CERTIFICATE_SLOT,
                                             TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out),
                     ==, TC_TLV_INVALID);
  }
  return MUNIT_OK;
}

/* SP 800-73-5 Part 1 footnote 23: 1856 bytes is a recommended size, so the
 * caller sets the certificate bound. */
TC_TEST(caller_bound)
{
  enum { CERTIFICATE_BYTES = 3000 };
  static uint8_t buffer[CERTIFICATE_BYTES + 16];
  memset(buffer, 0x5a, sizeof buffer);
  static const uint8_t header[] = {
      0x53, 0x82, 0, 0, 0x70, 0x82, CERTIFICATE_BYTES >> 8, CERTIFICATE_BYTES & 0xff};
  memcpy(buffer, header, sizeof header);
  size_t offset = sizeof header + CERTIFICATE_BYTES;
  static const uint8_t trailer[] = {0x71, 1, 0, 0xfe, 0};
  memcpy(buffer + offset, trailer, sizeof trailer);
  offset += sizeof trailer;
  buffer[2] = (uint8_t)((offset - 4) >> 8);
  buffer[3] = (uint8_t)(offset - 4);
  const TC_bytes input = {buffer, offset};
  static const size_t bounds[] = {TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, CERTIFICATE_BYTES - 1,
                                  CERTIFICATE_BYTES, SIZE_MAX};
  for (size_t i = 0; i < sizeof bounds / sizeof *bounds; ++i) {
    TC_PIV_certificate out, saved;
    memset(&out, 0xa5, sizeof out);
    saved = out;
    const TC_TLV_result result =
        TC_PIV_certificate_read(input, TC_PIV_CERTIFICATE_SLOT, bounds[i], &out);
    munit_assert_int(result, ==, bounds[i] >= CERTIFICATE_BYTES ? TC_TLV_OK : TC_TLV_LIMIT);
    if (result == TC_TLV_OK) {
      munit_assert_ptr_equal(out.certificate.data, buffer + sizeof header);
      munit_assert_size(out.certificate.length, ==, CERTIFICATE_BYTES);
    } else
      munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  TC_PIV_certificate out, saved;
  memset(&out, 0xa5, sizeof out);
  saved = out;
  munit_assert_int(TC_PIV_certificate_read(input, TC_PIV_CERTIFICATE_SLOT, 0, &out), ==,
                   TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_certificate_read(input, (TC_PIV_certificate_profile)3,
                                           TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_certificate_read((TC_bytes){NULL, 1}, TC_PIV_CERTIFICATE_SLOT,
                                           TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &out),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_certificate_read(input, TC_PIV_CERTIFICATE_SLOT,
                                           TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, NULL),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/containers", containers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/twic-error-detection-code", twic_error_detection_code, NULL, NULL,
                        MUNIT_TEST_OPTION_NONE, NULL},
                       {"/boundaries", boundaries, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/malformed", malformed, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/mscuid", mscuid, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/caller-bound", caller_bound, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/piv/certificate", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
