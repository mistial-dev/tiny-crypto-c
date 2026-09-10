/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_security.h>
#include "munit.h"
#include <string.h>

static MunitResult schema(const MunitParameter params[], void* context)
{
  /* CMS is opaque at this layer. Its signature is checked by the CMS API. */
  uint8_t encoded[] = {0x53,13,0xba,6,1,0x30,0,16,0x20,3,0xbb,1,0,0xfe,0};
  TC_PIV_security_object object, sentinel;
  memset(&sentinel,0xa5,sizeof sentinel);
  for (unsigned wrapped = 0; wrapped < 2; ++wrapped) {
    const TC_bytes input = {encoded + (wrapped ? 0 : 2),sizeof encoded - (wrapped ? 0 : 2)};
    const TC_PIV_security_encoding encoding = wrapped ? TC_PIV_SECURITY_CONTAINER : TC_PIV_SECURITY_CONTENTS;
    object = sentinel;
    munit_assert_int(TC_PIV_security_read(input,encoding,&object), ==, TC_TLV_OK);
    munit_assert_uint(object.groups, ==, 0x8001);
    munit_assert_ptr_equal(object.mapping.data,encoded + 4);
    munit_assert_size(object.mapping.length, ==, 6);
    munit_assert_ptr_equal(object.cms.data,encoded + 12);
    unsigned group = 99;
    munit_assert_int(TC_PIV_security_group_find(&object,0x3000,&group), ==, TC_TLV_OK);
    munit_assert_uint(group, ==, 1);
    munit_assert_int(TC_PIV_security_group_find(&object,0x2003,&group), ==, TC_TLV_OK);
    munit_assert_uint(group, ==, 16);
    munit_assert_int(TC_PIV_security_group_find(&object,0x3002,&group), ==, TC_TLV_END);
    munit_assert_uint(group, ==, 16);
    for (size_t length = 0; length < input.length; ++length) {
      object = sentinel;
      munit_assert_int(TC_PIV_security_read((TC_bytes){input.data,length},encoding,&object), !=, TC_TLV_OK);
      munit_assert_memory_equal(sizeof object,&object,&sentinel);
    }
  }
  const size_t positions[] = {2,3,4,7,10,11,13,14};
  const uint8_t invalid[] = {0xbb,5,0,1,0xba,0,0xff,1};
  for (size_t i = 0; i < sizeof positions / sizeof positions[0]; ++i) {
    const uint8_t saved = encoded[positions[i]];
    encoded[positions[i]] = invalid[i]; object = sentinel;
    munit_assert_int(TC_PIV_security_read((TC_bytes){encoded,sizeof encoded},TC_PIV_SECURITY_CONTAINER,&object), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof object,&object,&sentinel);
    encoded[positions[i]] = saved;
  }
  encoded[8] = encoded[5]; encoded[9] = encoded[6];
  munit_assert_int(TC_PIV_security_read((TC_bytes){encoded,sizeof encoded},TC_PIV_SECURITY_CONTAINER,&object), ==, TC_TLV_INVALID);
  munit_assert_int(TC_PIV_security_read((TC_bytes){NULL,1},TC_PIV_SECURITY_CONTENTS,&object), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_security_read((TC_bytes){encoded,sizeof encoded},TC_PIV_SECURITY_CONTENTS,NULL), ==, TC_TLV_ARGUMENT);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult mapping_limits(const MunitParameter params[], void* context)
{
  enum { MAX_GROUPS = 16, RECORD_BYTES = 3, HEADER_BYTES = 2, TRAILER_BYTES = 5 };
  uint8_t encoded[HEADER_BYTES + (MAX_GROUPS + 1) * RECORD_BYTES + TRAILER_BYTES];
  TC_PIV_security_object object;
  for (unsigned count = 0; count <= MAX_GROUPS + 1; ++count) {
    size_t used = 0;
    encoded[used++] = 0xba; encoded[used++] = (uint8_t)(count * RECORD_BYTES);
    for (unsigned i = 0; i < count; ++i) {
      encoded[used++] = (uint8_t)(i + 1);
      encoded[used++] = 0x30; encoded[used++] = (uint8_t)i;
    }
    encoded[used++] = 0xbb; encoded[used++] = 1; encoded[used++] = 0;
    encoded[used++] = 0xfe; encoded[used++] = 0;
    munit_assert_int(TC_PIV_security_read((TC_bytes){encoded,used},TC_PIV_SECURITY_CONTENTS,&object), ==,
        count && count <= MAX_GROUPS ? TC_TLV_OK : TC_TLV_INVALID);
    if (!count || count > MAX_GROUPS) continue;
    for (unsigned i = 0; i < count; ++i) {
      unsigned group = 99;
      munit_assert_int(TC_PIV_security_group_find(&object,(uint16_t)(0x3000 + i),&group), ==, TC_TLV_OK);
      munit_assert_uint(group, ==, i + 1);
    }
    unsigned group = 99;
    const uint16_t groups = object.groups;
    object.groups = 0;
    munit_assert_int(TC_PIV_security_group_find(&object,0x3000,&group), ==, TC_TLV_INVALID);
    munit_assert_uint(group, ==, 99);
    object.groups = groups;
    if (count > 1) {
      /* A match in the first record cannot hide a later duplicate. */
      encoded[HEADER_BYTES + RECORD_BYTES] = 1;
      munit_assert_int(TC_PIV_security_group_find(&object,0x3000,&group), ==, TC_TLV_INVALID);
      munit_assert_uint(group, ==, 99);
    }
  }
  munit_assert_int(TC_PIV_security_group_find(NULL,0,NULL), ==, TC_TLV_ARGUMENT);
  (void)params; (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/schema",schema,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/mapping",mapping_limits,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/piv/security",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
