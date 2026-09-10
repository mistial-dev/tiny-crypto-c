/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/source_internal.h"
#include "../../src/source_der_internal.h"
#include "munit.h"
#include <string.h>

typedef struct { size_t calls; int fail; } storage;

static TC_status read_storage(void* context, uint64_t offset,
    uint8_t* destination, size_t length)
{
  storage* state = (storage*)context;
  state->calls++;
  for (size_t i = 0; i < length; ++i) destination[i] = (uint8_t)(offset + i);
  return state->fail ? TC_ERROR : TC_OK;
}

static MunitResult reads(const MunitParameter params[], void* data)
{
  (void)params; (void)data;
  uint8_t window[16];
  storage state = {0,0};
  const TC_source source = {read_storage,&state,UINT64_MAX};
  tc_source_reader reader;
  TC_bytes view = {NULL,0};
  const uint64_t large = UINT64_C(0x100000003);
  munit_assert_int(tc_source_reader_init(&reader,&source,
    (TC_buffer){window,sizeof window},32,2),==,TC_RESULT_OK);
  munit_assert_int(tc_source_reader_view(&reader,large,20,&view),==,TC_RESULT_OK);
  munit_assert_size(view.length,==,sizeof window);
  munit_assert_uint8(view.data[0],==,3);
  munit_assert_size(state.calls,==,1);
  munit_assert_int(tc_source_reader_view(&reader,large + 5,2,&view),==,TC_RESULT_OK);
  munit_assert_size(view.length,==,2);
  munit_assert_uint8(view.data[0],==,8);
  munit_assert_size(state.calls,==,1);
  munit_assert_int(tc_source_reader_view(&reader,UINT64_MAX - 16,16,&view),==,TC_RESULT_OK);
  munit_assert_size(state.calls,==,2);
  TC_bytes held = view;
  munit_assert_int(tc_source_reader_view(&reader,0,1,&view),==,TC_RESULT_LIMIT);
  munit_assert_ptr_equal(view.data,held.data);
  munit_assert_size(view.length,==,held.length);
  munit_assert_int(tc_source_reader_view(&reader,UINT64_MAX - 1,2,&view),==,TC_RESULT_ARGUMENT);
  munit_assert_int(tc_source_reader_view(&reader,UINT64_MAX,0,&view),==,TC_RESULT_OK);
  munit_assert_size(view.length,==,0);
  return MUNIT_OK;
}

static MunitResult failures(const MunitParameter params[], void* data)
{
  (void)params; (void)data;
  uint8_t window[16];
  storage state = {0,1};
  TC_source source = {read_storage,&state,10};
  tc_source_reader reader;
  TC_bytes view = {window,3};
  munit_assert_int(tc_source_reader_init(&reader,&source,
    (TC_buffer){window,sizeof window},8,2),==,TC_RESULT_OK);
  memset(window,0xaa,sizeof window);
  munit_assert_int(tc_source_reader_view(&reader,0,8,&view),==,TC_RESULT_ERROR);
  for (size_t i = 0; i < sizeof window; ++i) munit_assert_uint8(window[i],==,0);
  munit_assert_size(reader.available,==,0);
  munit_assert_size(view.length,==,3);
  munit_assert_int(tc_source_reader_view(&reader,0,1,&view),==,TC_RESULT_LIMIT);
  munit_assert_size(state.calls,==,1);
  state.fail = 0;
  munit_assert_int(tc_source_reader_init(&reader,&source,
    (TC_buffer){window,sizeof window},3,1),==,TC_RESULT_OK);
  munit_assert_int(tc_source_reader_view(&reader,0,10,&view),==,TC_RESULT_OK);
  munit_assert_size(view.length,==,3);
  munit_assert_int(tc_source_reader_view(&reader,2,1,&view),==,TC_RESULT_OK);
  munit_assert_int(tc_source_reader_view(&reader,3,1,&view),==,TC_RESULT_LIMIT);
  munit_assert_int(tc_source_reader_init(&reader,&source,
    (TC_buffer){(uint8_t*)&reader,sizeof reader},3,1),==,TC_RESULT_ARGUMENT);
  return MUNIT_OK;
}

static TC_status read_header(void* context, uint64_t offset,
    uint8_t* destination, size_t length)
{
  const TC_bytes* bytes = (const TC_bytes*)context;
  memset(destination,0,length);
  if (offset < bytes->length) {
    size_t available = bytes->length - (size_t)offset;
    if (available > length) available = length;
    memcpy(destination,bytes->data + (size_t)offset,available);
  }
  return TC_OK;
}

static MunitResult framing(const MunitParameter params[], void* data)
{
  (void)params; (void)data;
  /* A four-GiB value represented by its header and virtual backing storage. */
  const uint8_t large[] = {0x30,0x85,1,0,0,0,0};
  TC_bytes bytes = {large,sizeof large};
  TC_source source = {read_header,&bytes,UINT64_C(0x100000000) + sizeof large};
  uint8_t window[16];
  tc_source_reader reader;
  tc_source_der_element element;
  for (size_t capacity = 1; capacity <= sizeof window; ++capacity) {
    munit_assert_int(tc_source_reader_init(&reader,&source,
      (TC_buffer){window,capacity},128,128),==,TC_RESULT_OK);
    munit_assert_int(tc_source_der_read(&reader,0,source.length,UINT64_MAX,&element),==,TC_TLV_OK);
    munit_assert_true(element.header.length == UINT64_C(0x100000000));
    munit_assert_true(element.end == source.length);
    munit_assert_true(element.value_offset == sizeof large);
    munit_assert_int(tc_source_der_read(&reader,0,source.length - 1,UINT64_MAX,&element),==,TC_TLV_INVALID);
    munit_assert_int(tc_source_der_read(&reader,0,source.length,65535,&element),==,TC_TLV_LIMIT);
    for (uint64_t end = 1; end < sizeof large; ++end)
      munit_assert_int(tc_source_der_read(&reader,0,end,UINT64_MAX,&element),==,TC_TLV_INVALID);
  }
  const uint8_t invalid[][4] = {{0x30,0x80,0,0},{0x30,0x81,0x7f,0},
    {0x30,0x82,0,0x80},{0x1f,0x80,0x20,0},{0x30,0xff,0,0}};
  for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    bytes.data = invalid[i]; bytes.length = sizeof invalid[i];
    source.length = 256;
    munit_assert_int(tc_source_reader_init(&reader,&source,
      (TC_buffer){window,1},128,128),==,TC_RESULT_OK);
    munit_assert_int(tc_source_der_read(&reader,0,source.length,UINT64_MAX,&element),==,TC_TLV_INVALID);
  }
  storage failed = {0,1};
  source.read = read_storage; source.context = &failed;
  munit_assert_int(tc_source_reader_init(&reader,&source,
    (TC_buffer){window,1},128,128),==,TC_RESULT_OK);
  munit_assert_int(tc_source_der_read(&reader,0,source.length,UINT64_MAX,&element),==,TC_TLV_IO);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/reads",reads,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/failures",failures,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/framing",framing,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
};
static const MunitSuite suite = {"/source",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[]) { return munit_suite_main(&suite,NULL,argc,argv); }
