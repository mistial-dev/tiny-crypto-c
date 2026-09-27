/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Full NIST CAVP CMACGen/CMACVer TDES2 and TDES3 response files. */
#include <tiny_crypto/des.h>
#include "munit.h"
#include "test_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CMAC_TDES_CAVP_DIR
#error "CMAC_TDES_CAVP_DIR is required"
#endif

enum { MAX_MESSAGE = 65536, MAX_LINE = 2 * MAX_MESSAGE + 128 };
static char line[MAX_LINE];
static uint8_t message[MAX_MESSAGE];

typedef struct {
  uint8_t key[24], key3[8], mac[8];
  size_t key_count, message_length, tag_length;
  unsigned count;
  int have_count, have_key1, have_key2, have_key3, have_message, have_mac;
} response;

static void field_hex(char* value, uint8_t* output, size_t capacity, size_t expected)
{
  const size_t length = tc_test_decode_hex_relaxed(value,output,capacity);
  munit_assert_size(length,==,expected);
}

static char* field_value(char* entry)
{
  char* equals = strchr(entry,'=');
  munit_assert_not_null(equals);
  return equals + 1;
}

static void run_case(const response* record, int verify, int pass,
                     unsigned* cryptographic, unsigned* invalid_bundle)
{
  uint8_t tag[8];
  const size_t key_length = record->key_count * 8;
  munit_assert_true(record->have_count && record->have_key1 && record->have_key2 &&
                    record->have_key3 && record->have_message && record->have_mac);
  munit_assert_true(record->key_count == 2 || record->key_count == 3);
  munit_assert_true(record->tag_length >= 1 && record->tag_length <= 8);
  if (record->key_count == 2 && memcmp(record->key,record->key3,8)) {
    munit_assert_true(verify && !pass);
    ++*invalid_bundle;
    return;
  }
  ++*cryptographic;
  if (verify) {
    const TC_status status = TC_DES_CMAC_verify(record->key,key_length,
        record->message_length ? message : NULL,record->message_length,
        record->mac,record->tag_length);
    if (status != (pass ? TC_OK : TC_MISMATCH))
      munit_errorf("TDES%zu CMACVer Count %u: status %d",record->key_count,
          record->count,status);
  } else {
    munit_assert_int(TC_DES_CMAC(record->key,key_length,
        record->message_length ? message : NULL,record->message_length,
        tag,record->tag_length),==,TC_OK);
    if (memcmp(tag,record->mac,record->tag_length))
      munit_errorf("TDES%zu CMACGen Count %u: tag mismatch",record->key_count,
          record->count);
  }
}

static void run_file(const char* name, size_t keys, int verify,
                     unsigned expected, unsigned expected_invalid_bundle)
{
  char path[512];
  response record = {0};
  unsigned cases = 0, cryptographic = 0, invalid_bundle = 0;
  snprintf(path,sizeof path,"%s/%s",CMAC_TDES_CAVP_DIR,name);
  FILE* file = fopen(path,"rb");
  munit_assert_not_null(file);
  while (fgets(line,sizeof line,file)) {
    char* entry = line;
    while (*entry == ' ' || *entry == '\t') ++entry;
    if (*entry == '#' || *entry == '\r' || *entry == '\n' || !*entry) continue;
    if (!strncmp(entry,"Count",5)) {
      memset(&record,0,sizeof record);
      record.count = (unsigned)strtoul(field_value(entry),NULL,10);
      munit_assert_uint(record.count,==,cases);
      record.have_count = 1;
    } else if (!strncmp(entry,"Klen",4)) {
      record.key_count = strtoul(field_value(entry),NULL,10);
      munit_assert_size(record.key_count,==,keys);
    } else if (!strncmp(entry,"Mlen",4)) {
      record.message_length = strtoul(field_value(entry),NULL,10);
      munit_assert_size(record.message_length,<=,MAX_MESSAGE);
    } else if (!strncmp(entry,"Tlen",4)) {
      record.tag_length = strtoul(field_value(entry),NULL,10);
    } else if (!strncmp(entry,"Key1",4)) {
      field_hex(field_value(entry),record.key,8,8);
      record.have_key1 = 1;
    } else if (!strncmp(entry,"Key2",4)) {
      field_hex(field_value(entry),record.key + 8,8,8);
      record.have_key2 = 1;
    } else if (!strncmp(entry,"Key3",4)) {
      field_hex(field_value(entry),record.key3,8,8);
      if (keys == 3) memcpy(record.key + 16,record.key3,8);
      record.have_key3 = 1;
    } else if (!strncmp(entry,"Msg",3)) {
      if (record.message_length)
        field_hex(field_value(entry),message,sizeof message,record.message_length);
      record.have_message = 1;
    } else if (!strncmp(entry,"Mac",3)) {
      field_hex(field_value(entry),record.mac,sizeof record.mac,record.tag_length);
      record.have_mac = 1;
      if (!verify) {
        run_case(&record,0,1,&cryptographic,&invalid_bundle);
        ++cases;
      }
    } else if (!strncmp(entry,"Result",6)) {
      munit_assert_true(verify);
      char* value = field_value(entry);
      while (*value == ' ') ++value;
      munit_assert_true(*value == 'P' || *value == 'F');
      run_case(&record,1,*value == 'P',&cryptographic,&invalid_bundle);
      ++cases;
    }
  }
  munit_assert_int(ferror(file),==,0);
  munit_assert_int(fclose(file),==,0);
  munit_assert_uint(cases,==,expected);
  munit_assert_uint(invalid_bundle,==,expected_invalid_bundle);
  munit_assert_uint(cryptographic,==,expected - expected_invalid_bundle);
}

static MunitResult cavp(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  run_file("CMACGenTDES2.rsp",2,0,96,0);
  run_file("CMACVerTDES2.rsp",2,1,360,72);
  run_file("CMACGenTDES3.rsp",3,0,96,0);
  run_file("CMACVerTDES3.rsp",3,1,240,0);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/all",cavp,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
      {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/tdes-cmac-cavp",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
