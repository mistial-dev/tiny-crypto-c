/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/hash_dispatch_internal.h"
#include "munit.h"
#include <string.h>

static MunitResult parts(const MunitParameter params[], void* user)
{
  const uint8_t input[] = {'a','b','c'};
  const TC_bytes whole = {input,sizeof input};
  tc_hash_workspace workspace;
  uint8_t expected[64], actual[64], saved[64];
  tc_hash_info info;
  (void)params; (void)user;
  for (unsigned id = TC_HASH_SHA1; id <= TC_HASH_SHA512; ++id) {
    TC_hash_algorithm hash = (TC_hash_algorithm)id;
    memset(actual,0xa5,sizeof actual); memcpy(saved,actual,sizeof saved);
    if (!tc_hash_available(hash)) {
      munit_assert_int(tc_hash_digest_parts(hash,&whole,1,actual,&workspace), ==, TC_ERROR);
      munit_assert_memory_equal(sizeof actual,actual,saved);
      continue;
    }
    munit_assert_true(tc_hash_info_get(hash,&info));
    munit_assert_int(tc_hash_digest_parts(hash,&whole,1,expected,&workspace), ==, TC_OK);
    for (size_t split = 0; split <= sizeof input; ++split) {
      const TC_bytes segments[] = {{input,split},{NULL,0},{input + split,sizeof input - split}};
      munit_assert_int(tc_hash_digest_parts(hash,segments,3,actual,&workspace), ==, TC_OK);
      munit_assert_memory_equal(info.digest_length,actual,expected);
      for (size_t i = 0; i < sizeof workspace; ++i) munit_assert_uint(((uint8_t*)&workspace)[i], ==, 0);
    }
    {
      const TC_bytes invalid[] = {whole,{NULL,1}};
      memcpy(actual,saved,sizeof actual);
      munit_assert_int(tc_hash_digest_parts(hash,invalid,2,actual,&workspace), ==, TC_ERROR);
      munit_assert_memory_equal(sizeof actual,actual,saved);
    }
  }
  munit_assert_false(tc_hash_available(TC_HASH_UNKNOWN));
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/parts",parts,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/hash/dispatch",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
