/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/pki_hash_internal.h"
#include "munit.h"

static MunitResult identifiers(const MunitParameter params[], void* user)
{
  static const uint8_t null_value[] = {5,0};
  static const uint8_t wrong[] = {4,0};
  static const uint8_t unknown[] = {42,3};
  static const uint8_t malformed[] = {42,0x80};
  TC_hash_algorithm hash;
  TC_DER_algorithm algorithm = {{unknown,sizeof unknown},{NULL,0}};
  (void)params; (void)user;
  for (unsigned id = TC_HASH_SHA1; id <= TC_HASH_SHA512; ++id) {
    tc_hash_info info;
    munit_assert_true(tc_hash_info_get((TC_hash_algorithm)id,&info));
    algorithm.oid = info.oid;
    for (unsigned form = 0; form < 4; ++form) {
      hash = TC_HASH_UNKNOWN;
      algorithm.parameters = form == 0 ? (TC_bytes){NULL,0} :
        form == 1 ? (TC_bytes){null_value,sizeof null_value} :
        form == 2 ? (TC_bytes){wrong,sizeof wrong} : (TC_bytes){null_value,1};
      munit_assert_int(tc_pki_hash_algorithm(&algorithm,&hash), ==,
          form < 2 ? TC_TLV_OK : TC_TLV_INVALID);
      munit_assert_int(hash, ==, form < 2 ? (TC_hash_algorithm)id : TC_HASH_UNKNOWN);
    }
  }
  hash = TC_HASH_UNKNOWN;
  algorithm = (TC_DER_algorithm){{unknown,sizeof unknown},{NULL,0}};
  munit_assert_int(tc_pki_hash_algorithm(&algorithm,&hash), ==, TC_TLV_UNSUPPORTED);
  algorithm.oid = (TC_bytes){malformed,sizeof malformed};
  munit_assert_int(tc_pki_hash_algorithm(&algorithm,&hash), ==, TC_TLV_INVALID);
  algorithm.oid = (TC_bytes){NULL,1};
  munit_assert_int(tc_pki_hash_algorithm(&algorithm,&hash), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_pki_hash_algorithm(NULL,&hash), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_pki_hash_algorithm(&algorithm,NULL), ==, TC_TLV_ARGUMENT);
  munit_assert_int(hash, ==, TC_HASH_UNKNOWN);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/identifiers",identifiers,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/hash/algorithm",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
