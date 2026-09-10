/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/rsa_pss_internal.h"
#include "munit.h"
#include <string.h>

static void decode_hex(uint8_t* out, size_t length, const char* hex)
{
  const char* digits = "0123456789abcdef";
  munit_assert_size(strlen(hex), ==, length * 2);
  for (size_t i = 0; i < length; ++i)
    out[i] = (uint8_t)(((strchr(digits,hex[2 * i]) - digits) << 4) |
                       (strchr(digits,hex[2 * i + 1]) - digits));
}

static MunitResult representative(const MunitParameter params[], void* user)
{
  /* SHA-256, emBits=1023, digest and salt both 00..1f. */
  static const char hex[] =
    "0f40a4c395c03be3bb5c3aa2e026b83be8c9cc8a14929a4b919c1d3e639412b0"
    "4b2c84c0fae9a9f20d83849e2b964633b04e7826a5f8a281a821c506d671865c"
    "ed433755b4ca3334b687b956fa90fe34e73da8b534135330802af1bd1a25d714"
    "2ce8c3b19f7131ab5c8feb70499418391d35af24aa0f39e508139f58291e93bc";
  uint8_t fixture[128], encoded[128], digest[32], block[64];
  tc_hash_workspace workspace;
  size_t work = 10000, required;
  (void)params; (void)user;
  decode_hex(fixture,sizeof fixture,hex);
  for (size_t i = 0; i < sizeof digest; ++i) digest[i] = (uint8_t)i;
  memcpy(encoded,fixture,sizeof encoded);
  munit_assert_int(tc_rsa_pss_check(encoded,sizeof encoded,1023,TC_HASH_SHA256,TC_HASH_SHA256,
      (TC_bytes){digest,sizeof digest},32,block,&workspace,&work), ==, TC_RSA_OK);
  required = 10000 - work;
  memcpy(encoded,fixture,sizeof encoded); encoded[0] |= 0x80; work = 10000;
  munit_assert_int(tc_rsa_pss_check(encoded,sizeof encoded,1023,TC_HASH_SHA256,TC_HASH_SHA256,
      (TC_bytes){digest,sizeof digest},32,block,&workspace,&work), ==, TC_RSA_INVALID);
  memcpy(encoded,fixture,sizeof encoded); work = 10000;
  munit_assert_int(tc_rsa_pss_check(encoded,sizeof encoded,1023,TC_HASH_SHA256,TC_HASH_SHA256,
      (TC_bytes){digest,sizeof digest},SIZE_MAX,block,&workspace,&work), ==, TC_RSA_INVALID);
  for (size_t i = 0; i < sizeof encoded; ++i) {
    memcpy(encoded,fixture,sizeof encoded); encoded[i] ^= 1; work = 10000;
    munit_assert_int(tc_rsa_pss_check(encoded,sizeof encoded,1023,TC_HASH_SHA256,TC_HASH_SHA256,
        (TC_bytes){digest,sizeof digest},32,block,&workspace,&work), ==, TC_RSA_INVALID);
  }
  for (size_t salt = 0; salt < 33; ++salt) {
    memcpy(encoded,fixture,sizeof encoded); work = 10000;
    munit_assert_int(tc_rsa_pss_check(encoded,sizeof encoded,1023,TC_HASH_SHA256,TC_HASH_SHA256,
        (TC_bytes){digest,sizeof digest},salt,block,&workspace,&work), ==, salt == 32 ? TC_RSA_OK : TC_RSA_INVALID);
  }
  memcpy(encoded,fixture,sizeof encoded); work = required;
  munit_assert_int(tc_rsa_pss_check(encoded,sizeof encoded,1023,TC_HASH_SHA256,TC_HASH_SHA256,
      (TC_bytes){digest,sizeof digest},32,block,&workspace,&work), ==, TC_RSA_OK);
  munit_assert_size(work, ==, 0);
  memcpy(encoded,fixture,sizeof encoded); work = required - 1;
  munit_assert_int(tc_rsa_pss_check(encoded,sizeof encoded,1023,TC_HASH_SHA256,TC_HASH_SHA256,
      (TC_bytes){digest,sizeof digest},32,block,&workspace,&work), ==, TC_RSA_LIMIT);
  return MUNIT_OK;
}

static MunitResult salt_boundaries(const MunitParameter params[], void* user)
{
  static const char* fixtures[] = {
    "3965a3f5891d0f6091fdfd3b81b045cdaf014dd3fa505ad5d419b924daf4cf44"
    "5b67e17bf36e17e8f45b30ae4e1ab3b86045e52625a977874e07e02eb1c1c7e4"
    "c7b0e2be8aec28e0243ad4ee173fb8606c7029b44b5b9680f884f2a9856d28f"
    "4b32977b259a87e6f264a88303ce62961dcac4902c739b89cf9c16bcc955eb6bc",
    "4130ff9f08ed5adce39db3dae05340d0bc4936e3400d12b53873c914ca5f0634a"
    "16b1ecceb544a429001020de0a25cb1a87a9df2d1311f0ac997681cb1b5c4d7e"
    "91af821f6c0bd0e234dfdd7702cd4848ea11dd3821abbae44d749610b997d52"
    "8b8a586faca1433394a0742feebb3e4e4f2cae1c88b5086f36e52650583b13bc"
  };
  uint8_t expected[128], encoded[128], digest[32], salt[94], block[64];
  tc_hash_workspace workspace;
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof digest; ++i) digest[i] = (uint8_t)i;
  for (size_t i = 0; i < sizeof salt; ++i) salt[i] = (uint8_t)i;
  for (size_t i = 0; i < 2; ++i) {
    size_t salt_length = i ? sizeof salt : 0, work = 10000;
    decode_hex(expected,sizeof expected,fixtures[i]);
    munit_assert_int(tc_rsa_pss_encode(encoded,sizeof encoded,1023,TC_HASH_SHA256,TC_HASH_SHA256,
        (TC_bytes){digest,sizeof digest},(TC_bytes){salt,salt_length},block,&workspace,&work), ==, TC_RSA_OK);
    munit_assert_memory_equal(sizeof encoded,encoded,expected);
    work = 10000;
    munit_assert_int(tc_rsa_pss_check(encoded,sizeof encoded,1023,TC_HASH_SHA256,TC_HASH_SHA256,
        (TC_bytes){digest,sizeof digest},salt_length,block,&workspace,&work), ==, TC_RSA_OK);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/representative",representative,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/salt-boundaries",salt_boundaries,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/rsa/pss",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
