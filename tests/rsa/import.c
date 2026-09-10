/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/key.h>
#include "munit.h"
#include <string.h>

static MunitResult rsa_private_import(const MunitParameter params[], void* user)
{
  uint8_t encoded[] = {
    0x30,60,2,1,1,0x30,13,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1,5,0,
    4,29,0x30,27,2,1,0,2,1,15,2,1,3,2,1,3,2,1,3,2,1,5,2,1,1,2,1,3,2,1,2,
    0x81,9,0,0x30,6,2,1,15,2,1,3
  };
  TC_KEY_rsa_private_key key;
  (void)params; (void)user;
  munit_assert_int(TC_KEY_rsa_private_read((TC_bytes){encoded,sizeof encoded},&key), ==, TC_TLV_OK);
  munit_assert_int(key.type, ==, TC_KEY_RSA);
  munit_assert_ptr_equal(key.components.modulus.data,encoded + 29);
  TC_KEY_rsa_private_key preserved;
  memset(&key,0xa5,sizeof key);
  memset(&preserved,0xa5,sizeof preserved);
  for (size_t end = 0; end < sizeof encoded; ++end) {
    munit_assert_int(TC_KEY_rsa_private_read((TC_bytes){encoded,end},&key), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof key,&key,&preserved);
  }
  const size_t mismatches[] = {58,61};
  for (size_t i = 0; i < sizeof mismatches / sizeof *mismatches; ++i) {
    encoded[mismatches[i]] += 2;
    munit_assert_int(TC_KEY_rsa_private_read((TC_bytes){encoded,sizeof encoded},&key), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof key,&key,&preserved);
    encoded[mismatches[i]] -= 2;
  }
  munit_assert_int(TC_KEY_rsa_private_read((TC_bytes){encoded,sizeof encoded},&key), ==, TC_TLV_OK);
  const TC_KEY_rsa_private_key saved = key;
  encoded[17] = 10; encoded[18] = 0x30;
  munit_assert_int(TC_KEY_rsa_private_read((TC_bytes){encoded,sizeof encoded},&key), ==, TC_TLV_OK);
  munit_assert_int(key.type, ==, TC_KEY_RSA_PSS);
  munit_assert_ptr_equal(key.container.algorithm.parameters.data,encoded + 18);
  munit_assert_size(key.container.algorithm.parameters.length, ==, 2);
  const struct {
    TC_signature_algorithm signature;
    TC_TLV_result restricted;
  } uses[] = {
    {{TC_SIGNATURE_RSA_PSS,TC_HASH_SHA1,TC_HASH_SHA1,20},TC_TLV_OK},
    {{TC_SIGNATURE_RSA_PSS,TC_HASH_SHA1,TC_HASH_SHA1,21},TC_TLV_OK},
    {{TC_SIGNATURE_RSA_PSS,TC_HASH_SHA1,TC_HASH_SHA1,19},TC_TLV_INVALID},
    {{TC_SIGNATURE_RSA_PSS,TC_HASH_SHA256,TC_HASH_SHA1,20},TC_TLV_INVALID},
    {{TC_SIGNATURE_RSA_PSS,TC_HASH_SHA1,TC_HASH_SHA256,20},TC_TLV_INVALID},
    {{TC_SIGNATURE_RSA_V15,TC_HASH_SHA256,TC_HASH_UNKNOWN,0},TC_TLV_INVALID}
  };
  for (size_t i = 0; i < sizeof uses / sizeof *uses; ++i) {
    munit_assert_int(TC_KEY_rsa_private_signature_check(&key,&uses[i].signature), ==, uses[i].restricted);
    munit_assert_int(TC_KEY_rsa_private_signature_check(&saved,&uses[i].signature), ==, TC_TLV_OK);
  }
  munit_assert_int(TC_KEY_rsa_private_signature_check(NULL,&uses[0].signature), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_KEY_rsa_private_signature_check(&key,NULL), ==, TC_TLV_ARGUMENT);
  memset(&key,0xa5,sizeof key);
  memset(&preserved,0xa5,sizeof preserved);
  encoded[18] = 5;
  munit_assert_int(TC_KEY_rsa_private_read((TC_bytes){encoded,sizeof encoded},&key), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof key,&key,&preserved);
  encoded[17] = 99;
  munit_assert_int(TC_KEY_rsa_private_read((TC_bytes){encoded,sizeof encoded},&key), ==, TC_TLV_UNSUPPORTED);
  munit_assert_memory_equal(sizeof key,&key,&preserved);
  munit_assert_int(TC_KEY_rsa_private_read((TC_bytes){encoded,sizeof encoded},NULL), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/private",rsa_private_import,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/rsa/import",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
