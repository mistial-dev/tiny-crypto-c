/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/pki_octets_internal.h"
#include "munit.h"

typedef struct {
  const uint8_t* input;
  size_t count;
  int fail;
} consumer;

static TC_TLV_result consume(void* context, TC_bytes bytes)
{
  consumer* state = context;
  static const size_t offsets[] = {4,11};
  munit_assert_size(state->count, <, 2);
  munit_assert_ptr_equal(bytes.data,state->input + offsets[state->count]);
  munit_assert_size(bytes.length, ==, state->count ? 2 : 1);
  ++state->count;
  return state->fail ? TC_TLV_LIMIT : TC_TLV_OK;
}

static MunitResult chunks(const MunitParameter params[], void* user)
{
  uint8_t encoded[] = {0x24,0x80,4,1,'a',0x24,0x80,4,0,4,2,'b','c',0,0,0,0};
  /* The empty primitive at offset 7 emits no value bytes. */
  TC_TLV_limits limits = {128,128,32,8};
  TC_TLV_frame frames[8];
  consumer state = {encoded,0,0};
  size_t work = 100;
  (void)params; (void)user;
  munit_assert_int(tc_pki_octets((TC_bytes){encoded,sizeof encoded},TC_TLV_BER,
      &limits,frames,8,&work,consume,&state), ==, TC_TLV_OK);
  munit_assert_size(state.count, ==, 2);
  state.count = 0; state.fail = 1; work = 100;
  munit_assert_int(tc_pki_octets((TC_bytes){encoded,sizeof encoded},TC_TLV_BER,
      &limits,frames,8,&work,consume,&state), ==, TC_TLV_LIMIT);
  munit_assert_size(state.count, ==, 1);
  encoded[9] = 2; work = 100;
  munit_assert_int(tc_pki_octets((TC_bytes){encoded,sizeof encoded},TC_TLV_BER,
      &limits,frames,8,&work,NULL,NULL), ==, TC_TLV_INVALID);
  encoded[9] = 4;
  for (size_t length = 0; length < sizeof encoded; ++length) {
    work = 100;
    munit_assert_int(tc_pki_octets((TC_bytes){encoded,length},TC_TLV_BER,
        &limits,frames,8,&work,NULL,NULL), !=, TC_TLV_OK);
  }
  {
    static const uint8_t constructed[] = {0x24,3,4,1,'a'};
    static const uint8_t empty[] = {4,0,4,0};
    work = 100;
    munit_assert_int(tc_pki_octets((TC_bytes){constructed,sizeof constructed},TC_TLV_BER,
        &limits,frames,8,&work,NULL,NULL), ==, TC_TLV_OK);
    work = 100;
    munit_assert_int(tc_pki_octets((TC_bytes){constructed,sizeof constructed},TC_TLV_DER,
        &limits,frames,8,&work,NULL,NULL), ==, TC_TLV_INVALID);
    work = 100;
    munit_assert_int(tc_pki_octets((TC_bytes){empty,2},TC_TLV_DER,
        &limits,frames,8,&work,NULL,NULL), ==, TC_TLV_OK);
    work = 100;
    munit_assert_int(tc_pki_octets((TC_bytes){empty,sizeof empty},TC_TLV_BER,
        &limits,frames,8,&work,NULL,NULL), ==, TC_TLV_INVALID);
  }
  return MUNIT_OK;
}
static MunitResult contiguous(const MunitParameter params[], void* user)
{
  const uint8_t split[] = {0x24,0x80,4,1,'a',0x24,3,4,1,'b',0,0};
  const uint8_t single[] = {0x24,3,4,1,'a'};
  const uint8_t empty[] = {4,0};
  TC_TLV_limits limits = {128,128,32,8};
  TC_TLV_frame frames[8];
  uint8_t buffer[2];
  TC_bytes out = {NULL,99};
  size_t work = 100, used;
  (void)params; (void)user;
  munit_assert_int(tc_pki_octets_contiguous((TC_bytes){single,sizeof single},
      4,TC_TLV_BER,&limits,frames,8,&work,NULL,0,&out), ==, TC_TLV_OK);
  munit_assert_ptr_equal(out.data,single + 4);
  munit_assert_size(out.length, ==, 1);
  work = 100;
  munit_assert_int(tc_pki_octets_contiguous((TC_bytes){split,sizeof split},
      4,TC_TLV_BER,&limits,frames,8,&work,buffer,sizeof buffer,&out), ==, TC_TLV_OK);
  munit_assert_ptr_equal(out.data,buffer);
  munit_assert_size(out.length, ==, 2);
  munit_assert_memory_equal(2,buffer,"ab");
  used = 100 - work;
  for (size_t budget = 0; budget < used; ++budget) {
    work = budget; out = (TC_bytes){NULL,99};
    munit_assert_int(tc_pki_octets_contiguous((TC_bytes){split,sizeof split},
        4,TC_TLV_BER,&limits,frames,8,&work,buffer,sizeof buffer,&out), ==, TC_TLV_LIMIT);
    munit_assert_null(out.data);
    munit_assert_size(out.length, ==, 99);
  }
  work = 100;
  munit_assert_int(tc_pki_octets_contiguous((TC_bytes){split,sizeof split},
      4,TC_TLV_BER,&limits,frames,8,&work,buffer,1,&out), ==, TC_TLV_LIMIT);
  munit_assert_size(out.length, ==, 99);
  for (size_t length = 0; length < sizeof split; ++length) {
    work = 100;
    munit_assert_int(tc_pki_octets_contiguous((TC_bytes){split,length},
        4,TC_TLV_BER,&limits,frames,8,&work,buffer,sizeof buffer,&out), !=, TC_TLV_OK);
    munit_assert_size(out.length, ==, 99);
  }
  work = 100;
  munit_assert_int(tc_pki_octets_contiguous((TC_bytes){empty,sizeof empty},
      4,TC_TLV_DER,&limits,frames,8,&work,NULL,0,&out), ==, TC_TLV_OK);
  munit_assert_size(out.length, ==, 0);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/chunks",chunks,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/contiguous",contiguous,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/cms/octets",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
