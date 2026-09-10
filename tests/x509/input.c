/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../../examples/pki_input.h"
#include "munit.h"
#include <tiny_crypto/twic_ccl.h>
#include <string.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <fcntl.h>
#endif

static MunitResult streams(const MunitParameter params[], void* context)
{
  static const uint8_t contents[] = {1,2,3,4};
  for (size_t length = 0; length <= sizeof contents; ++length) {
    for (size_t capacity = 1; capacity <= sizeof contents; ++capacity) {
      FILE* file = tmpfile();
      munit_assert_not_null(file);
      munit_assert_size(fwrite(contents,1,length,file), ==, length);
      rewind(file);
      uint8_t buffer[sizeof contents];
      memset(buffer,0xa5,sizeof buffer);
      TC_bytes out = {contents,sizeof contents};
      const int expected = length && length <= capacity;
      munit_assert_int(example_read_stream(file,buffer,capacity,&out), ==, expected);
      if (expected) {
        munit_assert_ptr_equal(out.data,buffer);
        munit_assert_size(out.length, ==, length);
        munit_assert_memory_equal(length,out.data,contents);
      } else {
        munit_assert_ptr_equal(out.data,contents);
        munit_assert_size(out.length, ==, sizeof contents);
        for (size_t i = 0; i < capacity; ++i) munit_assert_uint(buffer[i], ==, 0);
      }
      for (size_t i = capacity; i < sizeof buffer; ++i) munit_assert_uint(buffer[i], ==, 0xa5);
      munit_assert_int(fclose(file), ==, 0);
    }
  }
  uint8_t buffer[8];
  memset(buffer,0xa5,sizeof buffer);
  TC_bytes out = {contents,sizeof contents};
  munit_assert_false(example_read_stream(NULL,buffer,sizeof buffer,&out));
  munit_assert_false(example_read_file(NULL,buffer,sizeof buffer,&out));
  for (size_t i = 0; i < sizeof buffer; ++i) munit_assert_uint(buffer[i], ==, 0xa5);
  munit_assert_ptr_equal(out.data,contents);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult files(const MunitParameter params[], void* context)
{
  uint8_t buffer[8192];
  TC_bytes out = {NULL,0};
  munit_assert_true(example_read_file(TC_INPUT_FILE,buffer,sizeof buffer,&out));
  munit_assert_ptr_equal(out.data,buffer);
  munit_assert_size(out.length, >, 1);
  const size_t length = out.length;
  munit_assert_false(example_read_file(TC_INPUT_FILE,buffer,1,&out));
  munit_assert_uint(buffer[0], ==, 0);
  munit_assert_size(out.length, ==, length);
  memset(buffer,0xa5,sizeof buffer);
  munit_assert_false(example_read_file("",buffer,sizeof buffer,&out));
  for (size_t i = 0; i < sizeof buffer; ++i) munit_assert_uint(buffer[i], ==, 0);
  munit_assert_size(out.length, ==, length);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult created_files(const MunitParameter params[], void* context)
{
  uint8_t expected[8192], buffer[8192];
  TC_bytes contents;
  munit_assert_true(example_read_file(TC_INPUT_FILE,expected,sizeof expected,&contents));
  uint64_t timestamp = 0;
#if defined(__APPLE__)
  struct stat info;
  munit_assert_int(stat(TC_INPUT_FILE,&info), ==, 0);
  if (info.st_birthtimespec.tv_sec > 0) timestamp = (uint64_t)info.st_birthtimespec.tv_sec;
#elif defined(__linux__) && defined(STATX_BTIME)
  struct statx info = {0};
  if (!statx(AT_FDCWD,TC_INPUT_FILE,0,STATX_BTIME,&info) &&
      (info.stx_mask & STATX_BTIME) && info.stx_btime.tv_sec > 0)
    timestamp = (uint64_t)info.stx_btime.tv_sec;
#endif
  TC_bytes out = contents;
  uint64_t created = UINT64_MAX;
  memset(buffer,0xa5,sizeof buffer);
  munit_assert_int(example_read_created_file(TC_INPUT_FILE,buffer,sizeof buffer,&out,&created),
      ==, timestamp != 0);
  if (timestamp) {
    munit_assert_uint64(created, ==, timestamp);
    munit_assert_ptr_equal(out.data,buffer);
    munit_assert_size(out.length, ==, contents.length);
    munit_assert_memory_equal(contents.length,out.data,expected);
  } else {
    munit_assert_uint64(created, ==, UINT64_MAX);
    munit_assert_ptr_equal(out.data,expected);
    for (size_t i = 0; i < sizeof buffer; ++i) munit_assert_uint(buffer[i], ==, 0);
  }
  out = contents;
  created = UINT64_MAX;
  buffer[0] = 0xa5;
  munit_assert_false(example_read_created_file(TC_INPUT_FILE,buffer,1,&out,&created));
  munit_assert_uint(buffer[0], ==, 0);
  munit_assert_ptr_equal(out.data,expected);
  munit_assert_size(out.length, ==, contents.length);
  munit_assert_uint64(created, ==, UINT64_MAX);
  buffer[0] = 0xa5;
  munit_assert_false(example_read_created_file("",buffer,sizeof buffer,&out,&created));
  munit_assert_false(example_read_created_file(NULL,buffer,sizeof buffer,&out,&created));
  munit_assert_false(example_read_created_file(TC_INPUT_FILE,buffer,sizeof buffer,&out,NULL));
  munit_assert_uint(buffer[0], ==, 0xa5);
  munit_assert_ptr_equal(out.data,expected);
  munit_assert_uint64(created, ==, UINT64_MAX);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult cancellation_image(const MunitParameter params[], void* context)
{
  uint8_t packed[2 * TC_TWIC_CCL_FASCN_BYTES] = {0};
  memset(packed + TC_TWIC_CCL_FASCN_BYTES,2,TC_TWIC_CCL_FASCN_BYTES);
  FILE* stream = tmpfile();
  munit_assert_not_null(stream);
  munit_assert_size(fwrite(packed,1,sizeof packed,stream), ==, sizeof packed);
  rewind(stream);
  uint8_t buffer[sizeof packed];
  TC_bytes image;
  munit_assert_true(example_read_stream(stream,buffer,sizeof buffer,&image));
  /* A replacement input cannot change the private image used for validation. */
  rewind(stream);
  memset(packed,1,sizeof packed);
  munit_assert_size(fwrite(packed,1,sizeof packed,stream), ==, sizeof packed);
  munit_assert_int(fclose(stream), ==, 0);
  TC_TWIC_CCL_index index;
  munit_assert_int(TC_TWIC_CCL_index_from_memory(&image,2,&index), ==, TC_TWIC_CCL_OK);
  TC_TWIC_CCL_snapshot slot = {0}, *held;
  TC_TWIC_CCL_store store = {0};
  const TC_TWIC_CCL_metadata metadata = {100,101};
  munit_assert_int(TC_TWIC_CCL_store_prepare(&slot,&index,&metadata), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_publish(&store,0,&slot), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_acquire(&store,&held), ==, TC_TWIC_CCL_OK);
  for (unsigned value = 0; value < 3; ++value) {
    int listed = -1;
    memset(packed,value,TC_TWIC_CCL_FASCN_BYTES);
    munit_assert_int(TC_TWIC_CCL_snapshot_contains(held,
        (TC_bytes){packed,TC_TWIC_CCL_FASCN_BYTES},2,&listed), ==, TC_TWIC_CCL_OK);
    munit_assert_int(listed, ==, value != 1);
  }
  munit_assert_int(TC_TWIC_CCL_store_release(held), ==, TC_TWIC_CCL_OK);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult source(const MunitParameter params[], void* context)
{
  const uint8_t bytes[] = {1,2,3};
  const TC_bytes candidates[] = {{bytes,sizeof bytes}};
  TC_X509_store_anchor anchor = {0}, found;
  anchor.trust.name = candidates[0];
  ExampleX509Source arrays = {candidates,1,&anchor,1};
  const TC_X509_store_source view = example_x509_source(&arrays);
  TC_bytes out = {NULL,0};
  size_t work = 2;
  munit_assert_int(view.candidate(view.context,0,&work,&out), ==, TC_TLV_OK);
  munit_assert_ptr_equal(out.data,bytes);
  munit_assert_int(view.anchor(view.context,0,&work,&found), ==, TC_TLV_OK);
  munit_assert_ptr_equal(found.trust.name.data,bytes);
  munit_assert_size(work, ==, 0);
  munit_assert_int(view.candidate(view.context,0,&work,&out), ==, TC_TLV_LIMIT);
  munit_assert_int(view.anchor(view.context,0,&work,&found), ==, TC_TLV_LIMIT);
  work = 2;
  munit_assert_int(view.candidate(view.context,1,&work,&out), ==, TC_TLV_ARGUMENT);
  munit_assert_int(view.anchor(view.context,1,&work,&found), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, 2);
  munit_assert_ptr_equal(out.data,bytes);
  munit_assert_ptr_equal(found.trust.name.data,bytes);
  const TC_X509_store_source empty = example_x509_source(NULL);
  munit_assert_size(empty.anchor_count, ==, 0);
  munit_assert_size(empty.candidate_count, ==, 0);
  munit_assert_int(empty.anchor(empty.context,0,&work,&found), ==, TC_TLV_ARGUMENT);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult stream_source(const MunitParameter params[], void* context)
{
  FILE* file = tmpfile();
  munit_assert_not_null(file);
  const uint8_t bytes[] = {1,2,3,4,5};
  munit_assert_size(fwrite(bytes,1,sizeof bytes,file), ==, sizeof bytes);
  munit_assert_int(fseek(file,2,SEEK_SET), ==, 0);
  TC_source source = {0};
  munit_assert_true(example_stream_source(file,sizeof bytes,&source));
  munit_assert_int(ftell(file), ==, 2);
  munit_assert_uint64(source.length, ==, sizeof bytes);
  uint8_t output[3];
  munit_assert_int(source.read(source.context,1,output,sizeof output), ==, TC_OK);
  munit_assert_memory_equal(sizeof output,output,bytes + 1);
  const TC_source saved = source;
  munit_assert_false(example_stream_source(file,sizeof bytes - 1,&source));
  munit_assert_memory_equal(sizeof source,&source,&saved);
  munit_assert_int(source.read(source.context,UINT64_MAX,output,sizeof output), ==, TC_ERROR);
  munit_assert_memory_equal(sizeof output,output,bytes + 1);
  munit_assert_int(source.read(source.context,4,output,sizeof output), ==, TC_ERROR);
  const uint8_t zero[sizeof output] = {0};
  munit_assert_memory_equal(sizeof output,output,zero);
  munit_assert_int(source.read(source.context,0,output,sizeof output), ==, TC_OK);
  munit_assert_memory_equal(sizeof output,output,bytes);
  munit_assert_int(fclose(file), ==, 0);
  (void)params; (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/streams",streams,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/stream-source",stream_source,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/files",files,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/created-files",created_files,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/source",source,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/cancellation-image",cancellation_image,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/pki/input",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
