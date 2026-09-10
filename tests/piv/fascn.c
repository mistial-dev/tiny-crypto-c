/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/fascn.h>
#include "munit.h"
#include <string.h>

static void assert_fascn_equal(const TC_FASCN *left, const TC_FASCN *right) {
  munit_assert_uint64(left->person, ==, right->person);
  munit_assert_uint(left->credential, ==, right->credential);
  munit_assert_uint(left->agency, ==, right->agency);
  munit_assert_uint(left->system, ==, right->system);
  munit_assert_uint(left->organization, ==, right->organization);
  munit_assert_uint(left->series, ==, right->series);
  munit_assert_uint(left->issue, ==, right->issue);
  munit_assert_uint(left->category, ==, right->category);
  munit_assert_uint(left->association, ==, right->association);
}

/* PACS TIG v2.3, Figures 8-10. */
static const uint8_t known[TC_FASCN_BYTES] = {
  0xd0,0x43,0x94,0x58,0x21,0x0c,0x2c,0x19,0xa0,0x84,0x6d,0x83,0x68,
  0x5a,0x10,0x82,0x10,0x8c,0xe7,0x39,0x84,0x10,0x8c,0xa3,0xfc
};

/* Encode nibble characters independently, repairing parity and the checksum. */
static void encode_characters(uint8_t symbols[40], uint8_t encoded[TC_FASCN_BYTES])
{
  symbols[39] = 0;
  for (size_t i = 0; i < 39; ++i) symbols[39] ^= symbols[i];
  memset(encoded,0,TC_FASCN_BYTES);
  for (size_t i = 0; i < 40; ++i) {
    unsigned ones = 0;
    for (unsigned bit = 0; bit < 5; ++bit) {
      const unsigned value = bit == 4 ? !(ones & 1) : (symbols[i] >> bit) & 1;
      ones += value;
      const size_t index = i * 5 + bit;
      if (value) encoded[index / 8] |= (uint8_t)(0x80u >> (index % 8));
    }
  }
}

static MunitResult codec(const MunitParameter params[], void* context)
{
  TC_FASCN value, preserved;
  uint8_t encoded[TC_FASCN_BYTES + 1];
  munit_assert_int(TC_FASCN_read((TC_bytes){known,sizeof known},&value), ==, TC_TLV_OK);
  munit_assert_uint(value.agency, ==, 32); munit_assert_uint(value.system, ==, 1);
  munit_assert_uint(value.credential, ==, 92446); munit_assert_uint(value.series, ==, 0);
  munit_assert_uint(value.issue, ==, 1); munit_assert_uint64(value.person, ==, UINT64_C(1112223333));
  munit_assert_uint(value.category, ==, 1); munit_assert_uint(value.organization, ==, 1223);
  munit_assert_uint(value.association, ==, 2);
  memset(encoded,0xa5,sizeof encoded);
  munit_assert_int(TC_FASCN_write(&value,encoded,sizeof encoded), ==, TC_TLV_OK);
  munit_assert_memory_equal(sizeof known,encoded,known);
  munit_assert_uint(encoded[sizeof known], ==, 0xa5);
  const TC_FASCN good = value;
  memset(&preserved,0xa5,sizeof preserved);
  for (size_t bit = 0; bit < sizeof known * 8; ++bit) {
    memcpy(encoded,known,sizeof known); encoded[bit / 8] ^= (uint8_t)(1u << (bit % 8));
    value = preserved;
    munit_assert_int(TC_FASCN_read((TC_bytes){encoded,sizeof known},&value), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof value,&value,&preserved);
  }
  for (size_t length = 0; length < sizeof encoded; ++length) {
    value = preserved;
    if (length == sizeof known) continue;
    munit_assert_int(TC_FASCN_read((TC_bytes){known,length},&value), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof value,&value,&preserved);
    memset(encoded,0xa5,sizeof encoded);
    munit_assert_int(TC_FASCN_write(&good,encoded,length), ==, TC_TLV_LIMIT);
    for (size_t i = 0; i < sizeof encoded; ++i) munit_assert_uint(encoded[i], ==, 0xa5);
  }
  for (unsigned field = 0; field < 9; ++field) {
    value = good;
    switch (field) {
      case 0: value.agency = 10000; break;
      case 1: value.system = 10000; break;
      case 2: value.credential = 1000000; break;
      case 3: value.series = 10; break;
      case 4: value.issue = 10; break;
      case 5: value.person = UINT64_C(10000000000); break;
      case 6: value.category = 10; break;
      case 7: value.organization = 10000; break;
      default: value.association = 10; break;
    }
    memset(encoded,0xa5,sizeof encoded);
    munit_assert_int(TC_FASCN_write(&value,encoded,sizeof encoded), ==, TC_TLV_INVALID);
    for (size_t i = 0; i < sizeof encoded; ++i) munit_assert_uint(encoded[i], ==, 0xa5);
  }
  munit_assert_int(TC_FASCN_read((TC_bytes){NULL,25},&value), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_FASCN_write(NULL,encoded,sizeof encoded), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_FASCN_read((TC_bytes){encoded,sizeof encoded},&value), ==, TC_TLV_INVALID);
  union { TC_FASCN value; uint8_t bytes[TC_FASCN_BYTES]; } alias;
  memcpy(alias.bytes,known,sizeof known);
  munit_assert_int(TC_FASCN_read((TC_bytes){alias.bytes,sizeof alias.bytes},&alias.value), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof known,alias.bytes,known);
  alias.value = good;
  munit_assert_int(TC_FASCN_write(&alias.value,alias.bytes,sizeof alias.bytes), ==, TC_TLV_ARGUMENT);
  assert_fascn_equal(&alias.value,&good);
  static const char digits[] = "b0032d0001d092446d0d1d1112223333112232f7";
  for (size_t position = 0; position < 39; ++position) {
    for (unsigned replacement = 0; replacement < 16; ++replacement) {
      uint8_t symbols[40];
      for (size_t i = 0; i < 40; ++i)
        symbols[i] = (uint8_t)(digits[i] <= '9' ? digits[i] - '0' : digits[i] - 'a' + 10);
      const unsigned original = symbols[position];
      symbols[position] = (uint8_t)replacement;
      encode_characters(symbols,encoded);
      value = preserved;
      const int valid = original <= 9 ? replacement <= 9 : replacement == original;
      munit_assert_int(TC_FASCN_read((TC_bytes){encoded,TC_FASCN_BYTES},&value), ==,
          valid ? TC_TLV_OK : TC_TLV_INVALID);
      if (!valid) munit_assert_memory_equal(sizeof value,&value,&preserved);
    }
  }
  (void)params; (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/codec",codec,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/fascn",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
