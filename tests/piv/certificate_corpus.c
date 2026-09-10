/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_certificate.h>
#include "munit.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static MunitResult containers(const MunitParameter params[], void* context)
{
  uint8_t header[7], encoded[4096], expected[1856];
  size_t records = 0, count;
  while ((count = fread(header,1,sizeof header,stdin)) != 0) {
    munit_assert_size(count, ==, sizeof header);
    size_t encoded_length = (size_t)header[3] * 256 + header[4];
    size_t expected_length = (size_t)header[5] * 256 + header[6];
    munit_assert_size(encoded_length, <=, sizeof encoded);
    munit_assert_size(expected_length, <=, sizeof expected);
    munit_assert_size(fread(encoded,1,encoded_length,stdin), ==, encoded_length);
    munit_assert_size(fread(expected,1,expected_length,stdin), ==, expected_length);
    TC_PIV_certificate result, saved;
    memset(&result,0xa5,sizeof result); memcpy(&saved,&result,sizeof saved);
    TC_TLV_result status = TC_PIV_certificate_read((TC_bytes){encoded,encoded_length},
        (TC_PIV_certificate_profile)header[0],&result);
    munit_assert_int(status, ==, header[1] ? TC_TLV_INVALID : TC_TLV_OK);
    if (status == TC_TLV_OK) {
      munit_assert_int(result.compression, ==, header[2]);
      munit_assert_size(result.certificate.length, ==, expected_length);
      munit_assert_memory_equal(expected_length,result.certificate.data,expected);
      munit_assert_size(result.intermediate_cvc.length, ==, 0);
    } else munit_assert_memory_equal(sizeof result,&result,&saved);
    ++records;
  }
  munit_assert_int(ferror(stdin), ==, 0);
  munit_assert_size(records, >, 0);
  printf("%zu certificate-container records checked\n",records);
  (void)params; (void)context; return MUNIT_OK;
}

int main(int argc, char** argv)
{
#ifdef _WIN32
  if (_setmode(_fileno(stdin),_O_BINARY) == -1) return 1;
#endif
  MunitTest tests[] = {{"/containers",containers,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/piv/corpus",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
