/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/twic_tpk.h>
#include <tiny_crypto/tlv.h>
#include <tiny_crypto/piv_biometric.h>
#include "munit.h"
#include "test_util.h"
#include <stdio.h>
#include <string.h>

#ifndef TC_TWIC_SYNTHETIC_ROOT
#error "TC_TWIC_SYNTHETIC_ROOT must name the vendored fixture directory"
#endif

enum { OBJECT_CAPACITY = 20000 };

static size_t read_fixture(const char* profile, const char* name, uint8_t out[OBJECT_CAPACITY])
{
  char path[512];
  munit_assert_int(
      snprintf(path, sizeof path, "%s/%s/%s.bin", TC_TWIC_SYNTHETIC_ROOT, profile, name), >, 0);
  FILE* file = fopen(path, "rb");
  munit_assert_not_null(file);
  size_t length = fread(out, 1, OBJECT_CAPACITY, file);
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fgetc(file), ==, EOF);
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(length, >, 0);
  return length;
}

static TC_bytes value_of(TC_bytes encoded, uint8_t tag)
{
  const TC_TLV_limits limits = {OBJECT_CAPACITY, OBJECT_CAPACITY, 32, 2};
  TC_TLV_element element;
  munit_assert_int(TC_TLV_read(encoded, TC_TLV_ISO7816, &limits, &element), ==, TC_TLV_OK);
  munit_assert_size(element.encoded.length, ==, encoded.length);
  munit_assert_uint(element.encoded.data[0], ==, tag);
  return element.value;
}

static void check_profile(const char* profile, int face_and_printed)
{
  uint8_t tpk_data[OBJECT_CAPACITY], object[OBJECT_CAPACITY], saved[OBJECT_CAPACITY];
  size_t length = read_fixture(profile, "tpk", tpk_data);
  TC_bytes fields = value_of((TC_bytes){tpk_data, length}, 0x53);
  TC_TWIC_tpk key;
  munit_assert_int(TC_TWIC_tpk_read(fields, TC_TWIC_TPK_CONTENTS, &key), ==, TC_TLV_OK);
  const char* names[] = {"fingerprint", "face", "printed"};
  for (size_t i = 0; i < (face_and_printed ? 3u : 1u); ++i) {
    length = read_fixture(profile, names[i], object);
    TC_bytes inner = value_of((TC_bytes){object, length}, 0x53);
    TC_bytes ciphertext = value_of(inner, 0xbc);
    munit_assert_size(ciphertext.length, >, 0);
    munit_assert_size(ciphertext.length % 16, ==, 0);
    memcpy(saved, ciphertext.data, ciphertext.length);
    size_t plain_length = SIZE_MAX;
    munit_assert_int(
        TC_TWIC_object_decrypt(&key, (TC_buffer){(uint8_t*)ciphertext.data, ciphertext.length},
                               &plain_length),
        ==, TC_OK);
    munit_assert_size(plain_length, <, ciphertext.length);
    if (i < 2) {
      const uint8_t* cbeff = ciphertext.data;
      munit_assert_size(plain_length, >, 88);
      const size_t record_length =
          ((size_t)cbeff[2] << 24) | ((size_t)cbeff[3] << 16) | ((size_t)cbeff[4] << 8) | cbeff[5];
      munit_assert_size(record_length, <=, plain_length - 88);
      TC_bytes record = {cbeff + 88, record_length};
      if (i == 0) {
        TC_PIV_fingerprint_record parsed;
        munit_assert_int(TC_PIV_fingerprint_read(record, &parsed), ==, TC_TLV_OK);
        munit_assert_size(parsed.view_count, ==, 2);
      } else {
        TC_PIV_face_record parsed;
        munit_assert_int(TC_PIV_face_read(record, TC_PIV_FACE_PROFILE_TWIC, &parsed), ==,
                         TC_TLV_OK);
        munit_assert_size(parsed.image_count, ==, 1);
      }
    }
    size_t encoded_length = SIZE_MAX;
    munit_assert_int(TC_TWIC_object_encrypt(
                         &key, (TC_buffer){(uint8_t*)ciphertext.data, ciphertext.length},
                         plain_length, &encoded_length),
                     ==, TC_OK);
    munit_assert_size(encoded_length, ==, ciphertext.length);
    munit_assert_memory_equal(encoded_length, ciphertext.data, saved);
    TC_TWIC_tpk wrong = key;
    wrong.key[0] ^= 0x80;
    memcpy((uint8_t*)ciphertext.data, saved, ciphertext.length);
    plain_length = SIZE_MAX;
    munit_assert_int(
        TC_TWIC_object_decrypt(&wrong, (TC_buffer){(uint8_t*)ciphertext.data, ciphertext.length},
                               &plain_length),
        ==, TC_ERROR);
    munit_assert_size(plain_length, ==, SIZE_MAX);
  }
}

TC_TEST(fixture_crypto)
{
  check_profile("legacy", 0);
  check_profile("nexgen", 1);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/crypto", fixture_crypto, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/twic/synthetic", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
