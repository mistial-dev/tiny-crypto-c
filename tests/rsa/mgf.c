/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/rsa_mgf_internal.h"
#include "munit.h"
#include <string.h>

static MunitResult mask(const MunitParameter params[], void* user)
{
  static const uint8_t expected[] = {
    0x3b,0xda,0xba,0x83,0xcf,0xf1,0x33,0x37,0xb3,0x23,0xac,0x38,0x3c,0xa3,0x99,0x58,
    0x63,0xe9,0x22,0xf5,0x11,0xb9,0x31,0xb9,0xef,0xd4,0xe0,0x11,0x8c,0xfc,0x70,0xf0,
    0x86,0x78,0x39,0x0d,0x67,0xe3,0xc1,0x2d,0xbe,0xb2,0xd7,0xa7,0x8b,0xdf,0xa5,0x97,
    0xb5,0xa3,0x65,0xcc,0x1d,0x0d,0x86,0xf5,0xf9,0x41,0xdf,0x82,0x26,0xf0,0x66,0x3d,0xa2
  };
  static const uint8_t seed[] = {'f','o','o'};
  tc_hash_workspace workspace;
  uint8_t output[sizeof expected], block[64];
  size_t work;
  (void)params; (void)user;
  for (size_t length = 0; length <= sizeof output; ++length) {
    size_t cost = length + ((length + 31) / 32) * 8;
    memset(output,0,sizeof output); work = cost;
    munit_assert_int(tc_rsa_mgf1_xor(TC_HASH_SHA256,(TC_bytes){seed,sizeof seed},output,length,
        block,&workspace,&work), ==, TC_RSA_OK);
    munit_assert_memory_equal(length,output,expected);
    munit_assert_size(work, ==, 0);
    work = cost;
    munit_assert_int(tc_rsa_mgf1_xor(TC_HASH_SHA256,(TC_bytes){seed,sizeof seed},output,length,
        block,&workspace,&work), ==, TC_RSA_OK);
    for (size_t i = 0; i < sizeof output; ++i) munit_assert_uint(output[i], ==, 0);
    if (cost) {
      work = cost - 1;
      munit_assert_int(tc_rsa_mgf1_xor(TC_HASH_SHA256,(TC_bytes){seed,sizeof seed},output,length,
          block,&workspace,&work), ==, TC_RSA_LIMIT);
      for (size_t i = 0; i < sizeof output; ++i) munit_assert_uint(output[i], ==, 0);
    }
  }
  work = SIZE_MAX;
  munit_assert_int(tc_rsa_mgf1_xor(TC_HASH_SHA256,(TC_bytes){seed,SIZE_MAX},output,1,
      block,&workspace,&work), ==, TC_RSA_LIMIT);
  munit_assert_int(tc_rsa_mgf1_xor(TC_HASH_UNKNOWN,(TC_bytes){seed,sizeof seed},output,1,
      block,&workspace,&work), ==, TC_RSA_UNSUPPORTED);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/mask",mask,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/rsa/mgf1",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
