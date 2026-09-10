/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/twic_uuid.h>
#include "munit.h"
#include <string.h>

static MunitResult mapping(const MunitParameter params[], void* context)
{
  /* TWIC Part 2 v5, Appendix D: 7099-1055-048796. */
  static const uint8_t known[] = {0x91,0xbe,0x20,0x94,0xf6,0xdc,0x53,0x49,
    0x80,0,0x40,0x90,0xe4,0x9e,0x50,0x5c};
  const uint64_t expected = UINT64_C(70991055048796);
  uint64_t number = 0;
  uint8_t encoded[TC_TWIC_UUID_BYTES + 1];
  munit_assert_int(TC_TWIC_uuid_read((TC_bytes){known,sizeof known},&number), ==, TC_TLV_OK);
  munit_assert_uint64(number, ==, expected);
  memset(encoded,0xa5,sizeof encoded);
  munit_assert_int(TC_TWIC_uuid_write(expected,encoded,sizeof encoded), ==, TC_TLV_OK);
  munit_assert_memory_equal(sizeof known,known,encoded);
  munit_assert_uint(encoded[sizeof known], ==, 0xa5);
  TC_FASCN fascn = {0,48796,7099,1055,0,0,0,0,0};
  int matched = 7;
  munit_assert_int(TC_TWIC_uuid_match((TC_bytes){known,sizeof known},&fascn,&matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 1);
  ++fascn.credential;
  munit_assert_int(TC_TWIC_uuid_match((TC_bytes){known,sizeof known},&fascn,&matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 0);
  for (size_t bit = 0; bit < 80; ++bit) {
    memcpy(encoded,known,sizeof known); encoded[bit / 8] ^= (uint8_t)(1u << (bit % 8));
    number = expected;
    munit_assert_int(TC_TWIC_uuid_read((TC_bytes){encoded,sizeof known},&number), ==, TC_TLV_INVALID);
    munit_assert_uint64(number, ==, expected);
  }
  static const uint64_t numbers[] = {0,1,UINT64_C(99999999999999),UINT64_C(100000000000000),UINT64_MAX};
  for (size_t i = 0; i < sizeof numbers / sizeof *numbers; ++i) {
    memset(encoded,0xa5,sizeof encoded);
    munit_assert_int(TC_TWIC_uuid_write(numbers[i],encoded,sizeof encoded), ==, i < 3 ? TC_TLV_OK : TC_TLV_INVALID);
    if (i < 3) {
      munit_assert_int(TC_TWIC_uuid_read((TC_bytes){encoded,sizeof known},&number), ==, TC_TLV_OK);
      munit_assert_uint64(number, ==, numbers[i]);
    } else for (size_t j = 0; j < sizeof encoded; ++j) munit_assert_uint(encoded[j], ==, 0xa5);
  }
  for (size_t length = 0; length < sizeof known; ++length) {
    memset(encoded,0xa5,sizeof encoded); number = expected;
    munit_assert_int(TC_TWIC_uuid_write(expected,encoded,length), ==, TC_TLV_LIMIT);
    munit_assert_int(TC_TWIC_uuid_read((TC_bytes){known,length},&number), ==, TC_TLV_INVALID);
    munit_assert_uint64(number, ==, expected);
    for (size_t i = 0; i < sizeof encoded; ++i) munit_assert_uint(encoded[i], ==, 0xa5);
  }
  munit_assert_int(TC_TWIC_uuid_read((TC_bytes){NULL,16},&number), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_TWIC_uuid_write(expected,NULL,16), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_TWIC_uuid_match((TC_bytes){known,sizeof known},NULL,&matched), ==, TC_TLV_ARGUMENT);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult invalid_storage(const MunitParameter params[], void* context)
{
  union { uint64_t number; int matched; TC_FASCN fascn; uint8_t bytes[64]; } storage;
  uint8_t saved[sizeof storage];
  memset(&storage,0xa5,sizeof storage);
  munit_assert_int(TC_TWIC_uuid_write(1,storage.bytes,sizeof storage.bytes), ==, TC_TLV_OK);
  memcpy(saved,&storage,sizeof saved);
  const TC_bytes encoded = {storage.bytes,TC_TWIC_UUID_BYTES};
  munit_assert_int(TC_TWIC_uuid_read(encoded,&storage.number), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof saved,saved,&storage);
  TC_FASCN fascn = {0};
  int matched = 7;
  munit_assert_int(TC_TWIC_uuid_match(encoded,&fascn,&storage.matched), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof saved,saved,&storage);
  munit_assert_int(TC_TWIC_uuid_match(encoded,&storage.fascn,&storage.matched), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof saved,saved,&storage);
  munit_assert_int(TC_TWIC_uuid_read(encoded,NULL), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_TWIC_uuid_match(encoded,&fascn,NULL), ==, TC_TLV_ARGUMENT);
  for (unsigned field = 0; field < 3; ++field) {
    memset(&fascn,0,sizeof fascn);
    if (field == 0) fascn.agency = 10000;
    if (field == 1) fascn.system = 10000;
    if (field == 2) fascn.credential = 1000000;
    munit_assert_int(TC_TWIC_uuid_match(encoded,&fascn,&matched), ==, TC_TLV_INVALID);
    munit_assert_int(matched, ==, 7);
  }
  /* The six-byte tail can encode values beyond the fourteen decimal digits. */
  memset(storage.bytes + 10,0xff,6);
  uint64_t number = 42;
  munit_assert_int(TC_TWIC_uuid_read(encoded,&number), ==, TC_TLV_INVALID);
  munit_assert_uint64(number, ==, 42);
  memset(&fascn,0,sizeof fascn);
  munit_assert_int(TC_TWIC_uuid_match(encoded,&fascn,&matched), ==, TC_TLV_INVALID);
  munit_assert_int(matched, ==, 7);
  (void)params; (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/mapping",mapping,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/invalid-storage",invalid_storage,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/twic/uuid",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
