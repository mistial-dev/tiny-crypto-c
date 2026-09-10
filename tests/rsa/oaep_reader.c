/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#include "munit.h"
#include "test_util.h"
#include "hash_name.h"
#include <stdio.h>
#include <string.h>

static const char* path;

static TC_status blinding_bytes(void* context, uint8_t* output, size_t length)
{
  (void)context;
  /* Fixed blinding makes corpus runs reproducible. */
  memset(output,0,length); output[length - 1] = 2;
  return TC_OK;
}

static TC_bytes decode(const char* text, uint8_t* output, size_t capacity)
{
  size_t length = strcmp(text,"-") ? tc_test_decode_hex(text,output,capacity) : 0;
  if (strcmp(text,"-")) munit_assert_size(length * 2, ==, strlen(text));
  return (TC_bytes){output,length};
}

static MunitResult vectors(const MunitParameter params[], void* data)
{
  enum { KEY_BYTES = 384, PAYLOAD_BYTES = 8192, FIELD_COUNT = 12 };
  char line[65536];
  uint8_t components[5][KEY_BYTES], label[PAYLOAD_BYTES], ciphertext[PAYLOAD_BYTES];
  uint8_t expected[PAYLOAD_BYTES], output[KEY_BYTES];
  TC_RSA_word words[TC_RSA_DECRYPT_WORKSPACE_WORDS(3072)];
  size_t count = 0;
  (void)params; (void)data;
  if (!path) return MUNIT_SKIP;
  FILE* file = fopen(path,"r");
  munit_assert_not_null(file);
  while (fgets(line,sizeof line,file)) {
    char* fields[FIELD_COUNT];
    size_t columns = 0;
    for (char* token = strtok(line," \t\r\n"); token; token = strtok(NULL," \t\r\n")) {
      munit_assert_size(columns, <, FIELD_COUNT);
      fields[columns++] = token;
    }
    munit_assert_size(columns, ==, FIELD_COUNT);
    TC_bytes key_parts[5];
    for (size_t i = 0; i < 5; ++i) key_parts[i] = decode(fields[i],components[i],KEY_BYTES);
    TC_RSA_private_key key = {
      {key_parts[0],key_parts[1]},key_parts[2],key_parts[3],key_parts[4],NULL
    };
    TC_bytes associated = decode(fields[7],label,sizeof label);
    TC_bytes encrypted = decode(fields[8],ciphertext,sizeof ciphertext);
    TC_bytes message = decode(fields[9],expected,sizeof expected);
    munit_assert_true(!strcmp(fields[10],"valid") || !strcmp(fields[10],"invalid"));
    const int valid = !strcmp(fields[10],"valid");
    TC_RSA_workspace workspace = {words,TC_RSA_decrypt_workspace_words((unsigned)(key_parts[0].length * 8))};
    munit_assert_size(workspace.capacity, >, 0);
    memset(words,0xa5,sizeof words); memset(output,0xa5,sizeof output);
    size_t recovered = SIZE_MAX;
    const TC_RSA_oaep_options options = {
      hash_algorithm(fields[5]),hash_algorithm(fields[6]),associated
    };
    TC_RSA_execution execution = {{blinding_bytes,NULL},1,{UINT32_MAX}};
    TC_RSA_result result = TC_RSA_decrypt_oaep(&key,&options,encrypted,&workspace,
        (TC_buffer){output,sizeof output},&recovered,&execution);
    if (result != (valid ? TC_RSA_OK : TC_RSA_INVALID))
      munit_errorf("OAEP vector %s: status %d, expected %s",fields[11],result,fields[10]);
    if (valid) {
      munit_assert_size(recovered, ==, message.length);
      munit_assert_memory_equal(recovered,output,message.data);
    } else munit_assert_size(recovered, ==, SIZE_MAX);
    for (size_t i = valid ? recovered : 0; i < sizeof output; ++i)
      munit_assert_uint(output[i], ==, 0xa5);
    const size_t used = workspace.capacity * sizeof *words;
    for (size_t i = 0; i < sizeof words; ++i)
      munit_assert_uint(((uint8_t*)words)[i], ==,
          encrypted.length != key_parts[0].length || i >= used ? 0xa5 : 0);
    ++count;
  }
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(count, >, 0);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/vectors",vectors,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/rsa-oaep",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  if (argc == 3 && !strcmp(argv[1],"--vectors")) { path = argv[2]; argc = 1; }
  return munit_suite_main(&suite,NULL,argc,argv);
}
