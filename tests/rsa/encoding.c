/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/rsa_encoding_internal.h"
#include "munit.h"
#include <string.h>

static MunitResult v15(const MunitParameter params[], void* user)
{
  static const uint8_t prefix[] = {
    0x30,0x31,0x30,0x0d,6,9,0x60,0x86,0x48,1,0x65,3,4,2,1,5,0,4,32
  };
  uint8_t digest[32], encoded[384], expected[384], saved[384];
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof digest; ++i) digest[i] = (uint8_t)i;
  for (size_t length = 128; length <= 384; length += 128) {
    size_t separator = length - sizeof prefix - sizeof digest - 1;
    memset(expected,0xff,length); expected[0] = 0; expected[1] = 1; expected[separator] = 0;
    memcpy(expected + separator + 1,prefix,sizeof prefix);
    memcpy(expected + length - sizeof digest,digest,sizeof digest);
    munit_assert_int(tc_rsa_v15_encode(encoded,length,prefix,sizeof prefix,digest,sizeof digest), ==, TC_OK);
    munit_assert_memory_equal(length,encoded,expected);
    munit_assert_int(tc_rsa_v15_check(encoded,length,prefix,sizeof prefix,digest,sizeof digest), ==, TC_OK);
    for (size_t i = 0; i < length; ++i) {
      encoded[i] ^= 1;
      munit_assert_int(tc_rsa_v15_check(encoded,length,prefix,sizeof prefix,digest,sizeof digest), ==, TC_MISMATCH);
      encoded[i] ^= 1;
    }
  }
  memset(encoded,0xa5,sizeof encoded); memcpy(saved,encoded,sizeof saved);
  for (size_t length = 0; length < sizeof prefix + sizeof digest + 11; ++length) {
    munit_assert_int(tc_rsa_v15_encode(encoded,length,prefix,sizeof prefix,digest,sizeof digest), ==, TC_ERROR);
    munit_assert_memory_equal(sizeof encoded,encoded,saved);
    munit_assert_int(tc_rsa_v15_check(encoded,length,prefix,sizeof prefix,digest,sizeof digest), ==, TC_MISMATCH);
  }
  munit_assert_int(tc_rsa_v15_encode(encoded,62,prefix,sizeof prefix,digest,sizeof digest), ==, TC_OK);
  munit_assert_int(tc_rsa_v15_check(encoded,62,prefix,sizeof prefix,digest,sizeof digest), ==, TC_OK);
  munit_assert_false(tc_rsa_v15_size(384,SIZE_MAX,32));
  munit_assert_false(tc_rsa_v15_size(384,19,SIZE_MAX));
  munit_assert_false(tc_rsa_v15_size(384,0,32));
  munit_assert_int(tc_rsa_v15_check(NULL,128,prefix,sizeof prefix,digest,sizeof digest), ==, TC_ERROR);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/v15",v15,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/rsa/encoding",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
