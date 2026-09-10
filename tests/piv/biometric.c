/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "munit.h"
#include <string.h>
#include <tiny_crypto/piv_biometric.h>

enum { RECORD_BYTES = 44 };

static const uint8_t valid_record[RECORD_BYTES] = {
    'F', 'M', 'R',  0, ' ', '2', '0',  0,  0, RECORD_BYTES, 0,  1,
    0,   2,   0x80, 1, 1,   0,   1,    0,  0, 197,          0,  197,
    2,   0,   2,    0, 100, 1,   0x40, 10, 0, 20,           90, 80,
    0,   0,   7,    2, 100, 0,   0,    0};

static MunitResult valid(const MunitParameter params[], void *user) {
  (void)params;
  (void)user;
  TC_PIV_fingerprint_record record;
  munit_assert_int(TC_PIV_fingerprint_read(
                       (TC_bytes){valid_record, sizeof valid_record}, &record),
                   ==, TC_TLV_OK);
  munit_assert_ptr_equal(record.encoded.data, valid_record);
  munit_assert_uint(record.product_owner, ==, 1);
  munit_assert_uint(record.product_type, ==, 2);
  munit_assert_uint(record.capture_equipment, ==, 0x8001);
  munit_assert_uint(record.width, ==, 256);
  munit_assert_uint(record.height, ==, 256);
  munit_assert_uint8(record.view_count, ==, 2);
  return MUNIT_OK;
}

static MunitResult invalid(const MunitParameter params[], void *user) {
  (void)params;
  (void)user;
  enum {
    FORMAT,
    VERSION,
    LENGTH,
    OWNER,
    PRODUCT,
    COMPLIANCE,
    EQUIPMENT,
    WIDTH,
    HEIGHT,
    X_RESOLUTION,
    Y_RESOLUTION,
    VIEWS,
    RESERVED,
    POSITION,
    VIEW_NUMBER,
    IMPRESSION,
    FINGER_QUALITY,
    MINUTIA_COUNT,
    MINUTIA_TYPE,
    MINUTIA_Y_BITS,
    MINUTIA_X,
    MINUTIA_ANGLE,
    MINUTIA_QUALITY,
    EXTENSION,
    DUPLICATE_POSITION,
    CASES
  };
  TC_PIV_fingerprint_record out, unchanged;
  memset(&unchanged, 0xa5, sizeof unchanged);
  for (unsigned failure = 0; failure < CASES; ++failure) {
    uint8_t changed[RECORD_BYTES];
    memcpy(changed, valid_record, sizeof changed);
    switch (failure) {
    case FORMAT:
      changed[0] = 'X';
      break;
    case VERSION:
      changed[4] = '2';
      break;
    case LENGTH:
      changed[9] = RECORD_BYTES - 1;
      break;
    case OWNER:
      changed[11] = 0;
      break;
    case PRODUCT:
      changed[13] = 0;
      break;
    case COMPLIANCE:
      changed[14] = 0x90;
      break;
    case EQUIPMENT:
      changed[15] = 0;
      break;
    case WIDTH:
      changed[16] = changed[17] = 0;
      break;
    case HEIGHT:
      changed[18] = changed[19] = 0;
      break;
    case X_RESOLUTION:
      changed[21] = 196;
      break;
    case Y_RESOLUTION:
      changed[23] = 196;
      break;
    case VIEWS:
      changed[24] = 1;
      break;
    case RESERVED:
      changed[25] = 1;
      break;
    case POSITION:
      changed[26] = 11;
      break;
    case VIEW_NUMBER:
      changed[27] = 0x10;
      break;
    case IMPRESSION:
      changed[27] = 1;
      break;
    case FINGER_QUALITY:
      changed[28] = 99;
      break;
    case MINUTIA_COUNT:
      changed[29] = 129;
      break;
    case MINUTIA_TYPE:
      changed[30] = 0xc0;
      break;
    case MINUTIA_Y_BITS:
      changed[32] = 0x40;
      break;
    case MINUTIA_X:
      changed[30] = 0x41;
      break;
    case MINUTIA_ANGLE:
      changed[34] = 180;
      break;
    case MINUTIA_QUALITY:
      changed[35] = 101;
      break;
    case EXTENSION:
      changed[37] = 1;
      break;
    case DUPLICATE_POSITION:
      changed[38] = 2;
      break;
    }
    out = unchanged;
    munit_assert_int(
        TC_PIV_fingerprint_read((TC_bytes){changed, sizeof changed}, &out), !=,
        TC_TLV_OK);
    munit_assert_memory_equal(sizeof out, &out, &unchanged);
  }
  for (size_t length = 0; length < sizeof valid_record; ++length) {
    out = unchanged;
    munit_assert_int(
        TC_PIV_fingerprint_read((TC_bytes){valid_record, length}, &out), !=,
        TC_TLV_OK);
    munit_assert_memory_equal(sizeof out, &out, &unchanged);
  }
  munit_assert_int(
      TC_PIV_fingerprint_read((TC_bytes){valid_record, sizeof valid_record},
                              (TC_PIV_fingerprint_record *)valid_record),
      ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult face(const MunitParameter params[], void *user) {
  (void)params;
  (void)user;
  static const uint8_t encoded[] = {
      'F',  'A', 'C', 0, '0', '1', '0', 0,    0,    0,    0,   50,   0,
      1,    0,   0,   0, 36,  0,   0,   0,    0,    0,    0,   0,    0,
      0,    1,   0,   0, 0,   0,   0,   0,    1,    0,    1,   0xa5, 2,
      0x58, 1,   2,   0, 0,   0,   0,   0xff, 0xd8, 0xff, 0xd9};
  TC_PIV_face_record record;
  TC_PIV_face_image image;
  munit_assert_int(TC_PIV_face_read((TC_bytes){encoded, sizeof encoded},
                                    TC_PIV_FACE_PROFILE_PIV, &record),
                   ==, TC_TLV_OK);
  munit_assert_uint(record.image_count, ==, 1);
  munit_assert_int(TC_PIV_face_image_read(&record, 0, &image), ==, TC_TLV_OK);
  munit_assert_uint(image.width, ==, 421);
  munit_assert_uint(image.height, ==, 600);
  munit_assert_size(image.image.length, ==, 4);
  munit_assert_ptr_equal(image.image.data, encoded + sizeof encoded - 4);

  uint8_t twic[sizeof encoded];
  memcpy(twic, encoded, sizeof twic);
  twic[26] = twic[27] = 0;
  twic[34] = 0;
  twic[36] = 1;
  twic[37] = 18;
  munit_assert_int(TC_PIV_face_read((TC_bytes){twic, sizeof twic},
                                    TC_PIV_FACE_PROFILE_PIV, &record),
                   ==, TC_TLV_INVALID);
  munit_assert_int(TC_PIV_face_read((TC_bytes){twic, sizeof twic},
                                    TC_PIV_FACE_PROFILE_TWIC, &record),
                   ==, TC_TLV_OK);

  static const size_t invalid_offsets[] = {0,  4,  11, 13, 17, 26, 34,
                                           35, 40, 41, 45, 46, 49};
  for (size_t i = 0; i < sizeof invalid_offsets / sizeof *invalid_offsets;
       ++i) {
    uint8_t changed[sizeof encoded];
    memcpy(changed, encoded, sizeof changed);
    changed[invalid_offsets[i]] ^= 0xff;
    munit_assert_int(TC_PIV_face_read((TC_bytes){changed, sizeof changed},
                                      TC_PIV_FACE_PROFILE_PIV, &record),
                     !=, TC_TLV_OK);
  }
  for (size_t offset = 36; offset <= 38; offset += 2) {
    uint8_t changed[sizeof encoded];
    memcpy(changed, encoded, sizeof changed);
    changed[offset] = changed[offset + 1] = 0;
    munit_assert_int(TC_PIV_face_read((TC_bytes){changed, sizeof changed},
                                      TC_PIV_FACE_PROFILE_PIV, &record),
                     !=, TC_TLV_OK);
  }
  munit_assert_int(TC_PIV_face_image_read(&record, 1, &image), ==,
                   TC_TLV_ARGUMENT);
  record.profile = (TC_PIV_face_profile)99;
  munit_assert_int(TC_PIV_face_image_read(&record, 0, &image), ==,
                   TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/valid", valid, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/invalid", invalid, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/face", face, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

int main(int argc, char **argv) {
  MunitSuite suite = {"/piv/fingerprint", tests, NULL, 1,
                      MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
