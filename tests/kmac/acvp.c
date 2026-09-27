/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* NIST ACVP-Server KMAC-256 fixed-output AFT, tgId 4, tcId 307. */
#include <tiny_crypto/kmac.h>
#include "munit.h"
#include "test_util.h"
#include <stdio.h>
#include <string.h>

#ifndef KMAC_ACVP_FILE
#error "KMAC_ACVP_FILE is required"
#endif

static MunitResult fixed_output(const MunitParameter params[], void* user)
{
  char line[2048];
  uint8_t key[512], message[64], custom[128], expected[32], actual[32];
  FILE* file = fopen(KMAC_ACVP_FILE,"r");
  (void)params; (void)user;
  munit_assert_not_null(file);
  munit_assert_not_null(fgets(line,sizeof line,file));
  munit_assert_null(fgets(line,sizeof line,file));
  munit_assert_int(ferror(file),==,0);
  munit_assert_int(fclose(file),==,0);
  char* fields[5];
  char* token = strtok(line," \t\r\n");
  for (size_t i = 0; i < 5; ++i) {
    munit_assert_not_null(token);
    fields[i] = token;
    token = strtok(NULL," \t\r\n");
  }
  munit_assert_null(token);
  munit_assert_string_equal(fields[4],"307");
  const size_t key_length = tc_test_decode_hex(fields[0],key,sizeof key);
  const size_t message_length = tc_test_decode_hex(fields[1],message,sizeof message);
  const size_t custom_length = tc_test_decode_hex(fields[2],custom,sizeof custom);
  const size_t tag_length = tc_test_decode_hex(fields[3],expected,sizeof expected);
  munit_assert_size(key_length,==,512);
  munit_assert_size(message_length,==,8);
  munit_assert_size(custom_length,==,41);
  munit_assert_size(tag_length,==,32);
  munit_assert_int(TC_KMAC256_digest(key,key_length,message,message_length,
      custom,custom_length,actual,tag_length),==,TC_OK);
  munit_assert_memory_equal(tag_length,actual,expected);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/fixed-output",fixed_output,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
      {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/kmac/acvp",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
