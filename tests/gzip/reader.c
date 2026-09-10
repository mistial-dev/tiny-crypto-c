/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/gzip.h>
#include "munit.h"
#include <stdio.h>
#include <string.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

enum { INPUT_CAPACITY = 262144, OUTPUT_CAPACITY = 131072 };
static uint8_t input[INPUT_CAPACITY], expected[OUTPUT_CAPACITY], output[OUTPUT_CAPACITY + 1];
static size_t big_endian(const uint8_t* bytes)
{ return ((size_t)bytes[0] << 24) | ((size_t)bytes[1] << 16) | ((size_t)bytes[2] << 8) | bytes[3]; }

static MunitResult vectors(const MunitParameter params[], void* context)
{
  uint8_t header[9];
  size_t records = 0;
  TC_GZIP_workspace workspace;
  for (;;) {
    const size_t got = fread(header,1,sizeof header,stdin);
    if (!got) { munit_assert_false(ferror(stdin)); break; }
    munit_assert_size(got, ==, sizeof header);
    const size_t input_length = big_endian(header + 1), expected_length = big_endian(header + 5);
    munit_assert_size(input_length, <=, sizeof input);
    munit_assert_size(expected_length, <=, sizeof expected);
    munit_assert_size(fread(input,1,input_length,stdin), ==, input_length);
    munit_assert_size(fread(expected,1,expected_length,stdin), ==, expected_length);
    size_t work = 100000000, length = SIZE_MAX;
    memset(output,0x5a,sizeof output);
    TC_GZIP_result result = TC_GZIP_decode(input,input_length,output,expected_length,&workspace,&work,&length);
    munit_assert_int(result, ==, header[0]);
    if (result == TC_GZIP_OK) {
      munit_assert_size(length, ==, expected_length);
      munit_assert_memory_equal(length,output,expected);
      if (length) {
        work = 100000000; length = SIZE_MAX;
        munit_assert_int(TC_GZIP_decode(input,input_length,output,expected_length - 1,&workspace,&work,&length), ==, TC_GZIP_LIMIT);
        munit_assert_size(length, ==, SIZE_MAX);
      }
    } else {
      munit_assert_size(length, ==, SIZE_MAX);
      for (size_t i = 0; i < expected_length; ++i) munit_assert_uint(output[i], ==, 0);
    }
    munit_assert_uint(output[expected_length], ==, 0x5a);
    ++records;
  }
  munit_assert_size(records, >, 0);
  printf("%lu GZIP vectors checked\n",(unsigned long)records);
  (void)params; (void)context; return MUNIT_OK;
}
int main(int argc, char** argv)
{
#if defined(_WIN32)
  if (_setmode(_fileno(stdin),_O_BINARY) == -1) return 1;
#endif
  MunitTest tests[] = {{"/vectors",vectors,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/gzip",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
