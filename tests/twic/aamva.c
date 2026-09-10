/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/aamva.h>
#include <tiny_crypto/twic_tpk.h>
#include "munit.h"
#include <string.h>

static MunitResult directory(const MunitParameter params[], void* context)
{
  uint8_t bytes[] = "@\n\036\rANSI 999999100002ID00410003ZT00440007ID\rZT\nZTA\r";
  const TC_bytes input = {bytes,sizeof bytes - 1};
  TC_bytes out, saved = {bytes,1};
  munit_assert_int(TC_AAMVA_subfile_find(input,"ZT",&out), ==, TC_TLV_OK);
  munit_assert_ptr_equal(out.data,bytes + 44);
  munit_assert_size(out.length, ==, 7);
  out = saved;
  munit_assert_int(TC_AAMVA_subfile_find(input,"DL",&out), ==, TC_TLV_END);
  munit_assert_memory_equal(sizeof out,&out,&saved);
  for (size_t i = 0; i < input.length; ++i) {
    out = saved;
    munit_assert_int(TC_AAMVA_subfile_find((TC_bytes){bytes,i},"ZT",&out), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof out,&out,&saved);
  }
  const size_t decimal_offsets[] = {9,15,17,19,23,27,33,37};
  for (size_t i = 0; i < sizeof decimal_offsets / sizeof *decimal_offsets; ++i) {
    const size_t offset = decimal_offsets[i];
    const uint8_t original = bytes[offset];
    bytes[offset] = 'X'; out = saved;
    munit_assert_int(TC_AAMVA_subfile_find(input,"ZT",&out), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof out,&out,&saved);
    bytes[offset] = original;
  }
  bytes[15] = '0'; bytes[16] = '0';
  munit_assert_int(TC_AAMVA_subfile_find(input,"ZT",&out), ==, TC_TLV_UNSUPPORTED);
  bytes[15] = '1'; bytes[16] = '0';
  /* Both directory records point to valid subfiles, but their ranges overlap. */
  memcpy(bytes + 27,"0010",4); out = saved;
  munit_assert_int(TC_AAMVA_subfile_find(input,"ZT",&out), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof out,&out,&saved);
  memcpy(bytes + 27,"0003",4);
  uint8_t second_entry[10];
  memcpy(second_entry,bytes + 31,sizeof second_entry);
  memcpy(bytes + 31,bytes + 21,sizeof second_entry);
  munit_assert_int(TC_AAMVA_subfile_find(input,"ID",&out), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof out,&out,&saved);
  memcpy(bytes + 31,second_entry,sizeof second_entry);
  /* Directory order can differ from physical subfile order. */
  memcpy(bytes + 31,bytes + 21,sizeof second_entry);
  memcpy(bytes + 21,second_entry,sizeof second_entry);
  munit_assert_int(TC_AAMVA_subfile_find(input,"ZT",&out), ==, TC_TLV_OK);
  munit_assert_ptr_equal(out.data,bytes + 44);
  bytes[21] = 'z'; bytes[44] = 'z'; out = saved;
  munit_assert_int(TC_AAMVA_subfile_find(input,"ZT",&out), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof out,&out,&saved);
  bytes[21] = 'Z'; bytes[44] = 'Z';
  munit_assert_int(TC_AAMVA_subfile_find(input,"zt",&out), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof out,&out,&saved);
  union { TC_bytes span; uint8_t bytes[sizeof bytes]; } alias;
  memcpy(alias.bytes,bytes,sizeof bytes);
  munit_assert_int(TC_AAMVA_subfile_find((TC_bytes){alias.bytes,input.length},"ZT",&alias.span), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof bytes,alias.bytes,bytes);
  munit_assert_int(TC_AAMVA_subfile_find(input,NULL,&out), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_AAMVA_subfile_find(input,"ZT",NULL), ==, TC_TLV_ARGUMENT);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult fields(const MunitParameter params[], void* context)
{
  static const struct { const char* data; const char* id; TC_TLV_result result; const char* value; } cases[] = {
    {"ZT\nZTA012345\r","ZTA",TC_TLV_OK,"012345"},
    {"ZTZTA012345\n\r","ZTA",TC_TLV_OK,"012345"},
    {"IDDAA\nDABVALUE\r","DAA",TC_TLV_OK,""},
    {"IDDAA\nDABVALUE\r","DAB",TC_TLV_OK,"VALUE"},
    {"ID\r","DAA",TC_TLV_END,NULL},
    {"IDDAAONE\nDAATWO\r","DAA",TC_TLV_INVALID,NULL},
    {"IDDAA\nDAA\r","DAA",TC_TLV_INVALID,NULL},
    {"IDDAAONE\nDA\r","DAA",TC_TLV_INVALID,NULL},
    {"IDDAAONE\rDABTWO\r","DAA",TC_TLV_INVALID,NULL},
    {"IDDAAONE\n\n\r","DAA",TC_TLV_INVALID,NULL},
    {"IDDAAONE\nDAbTWO\r","DAA",TC_TLV_INVALID,NULL},
    {"IDDAAONE\r","daa",TC_TLV_ARGUMENT,NULL}
  };
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    const TC_bytes input = {(const uint8_t*)cases[i].data,strlen(cases[i].data)};
    TC_bytes saved = {input.data,1}, out = saved;
    munit_assert_int(TC_AAMVA_field_find(input,cases[i].id,&out), ==, cases[i].result);
    if (cases[i].result == TC_TLV_OK) {
      munit_assert_size(out.length, ==, strlen(cases[i].value));
      munit_assert_memory_equal(out.length,out.data,cases[i].value);
      munit_assert_true(out.data >= input.data && out.data + out.length <= input.data + input.length);
      for (size_t prefix = 0; prefix < input.length; ++prefix) {
        out = saved;
        munit_assert_int(TC_AAMVA_field_find((TC_bytes){input.data,prefix},cases[i].id,&out), ==, TC_TLV_INVALID);
        munit_assert_memory_equal(sizeof out,&out,&saved);
      }
    } else munit_assert_memory_equal(sizeof out,&out,&saved);
  }
  union { TC_bytes span; uint8_t bytes[32]; } alias;
  static const uint8_t input[] = "ZTZTA1234\r";
  memcpy(alias.bytes,input,sizeof input);
  munit_assert_int(TC_AAMVA_field_find((TC_bytes){alias.bytes,sizeof input - 1},"ZTA",&alias.span), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof input,alias.bytes,input);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult privacy_key(const MunitParameter params[], void* context)
{
  uint8_t container[] = {0xdf,0xc1,1,24,0xc0,16,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0xc1,1,8,0xc2,1,0};
  uint8_t hex[] = "DCF10118C010000102030405060708090A0B0C0D0E0FC10108C20100";
  TC_TWIC_tpk key, saved;
  memset(&saved,0xa5,sizeof saved);
  munit_assert_int(TC_TWIC_tpk_read((TC_bytes){container,sizeof container},TC_TWIC_TPK_CARD,&key), ==, TC_TLV_OK);
  munit_assert_memory_equal(sizeof key.key,key.key,container + 6);
  const TC_bytes contents = {container + 4,sizeof container - 4};
  munit_assert_int(TC_TWIC_tpk_read(contents,TC_TWIC_TPK_CONTENTS,&key), ==, TC_TLV_OK);
  munit_assert_memory_equal(sizeof key.key,key.key,container + 6);
  for (size_t prefix = 0; prefix < contents.length; ++prefix) {
    key = saved;
    munit_assert_int(TC_TWIC_tpk_read((TC_bytes){contents.data,prefix},
      TC_TWIC_TPK_CONTENTS,&key), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof key,&key,&saved);
  }
  key = saved;
  munit_assert_int(TC_TWIC_tpk_read((TC_bytes){container,sizeof container},
    TC_TWIC_TPK_CONTENTS,&key), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof key,&key,&saved);
  for (size_t prefix = 0; prefix < sizeof hex - 1; ++prefix) {
    key = saved;
    munit_assert_int(TC_TWIC_tpk_read((TC_bytes){hex,prefix},TC_TWIC_TPK_BARCODE_HEX,&key), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof key,&key,&saved);
  }
  union { TC_TWIC_tpk key; uint8_t bytes[sizeof hex]; } alias;
  memcpy(alias.bytes,hex,sizeof hex);
  munit_assert_int(TC_TWIC_tpk_read((TC_bytes){alias.bytes,sizeof hex - 1},
      TC_TWIC_TPK_BARCODE_HEX,&alias.key), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof hex,alias.bytes,hex);
  uint8_t extra[sizeof container + 2];
  memcpy(extra,container,sizeof container); extra[sizeof container] = 0xc3; extra[sizeof container + 1] = 0;
  munit_assert_int(TC_TWIC_tpk_read((TC_bytes){extra,sizeof extra},TC_TWIC_TPK_CARD,&key), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof key,&key,&saved);
  extra[3] += 2;
  munit_assert_int(TC_TWIC_tpk_read((TC_bytes){extra,sizeof extra},TC_TWIC_TPK_CARD,&key), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof key,&key,&saved);
  munit_assert_int(TC_TWIC_tpk_read((TC_bytes){NULL,1},TC_TWIC_TPK_CARD,&key), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_TWIC_tpk_read((TC_bytes){container,sizeof container},(TC_TWIC_tpk_encoding)99,&key), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof key,&key,&saved);
  munit_assert_int(TC_TWIC_tpk_read((TC_bytes){hex,sizeof hex - 1},TC_TWIC_TPK_BARCODE_HEX,&key), ==, TC_TLV_OK);
  munit_assert_memory_equal(sizeof key.key,key.key,container + 6);
  for (size_t prefix = 0; prefix < sizeof container; ++prefix) {
    key = saved;
    munit_assert_int(TC_TWIC_tpk_read((TC_bytes){container,prefix},TC_TWIC_TPK_CARD,&key), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof key,&key,&saved);
  }
  container[27] = 1;
  munit_assert_int(TC_TWIC_tpk_read((TC_bytes){container,sizeof container},TC_TWIC_TPK_CARD,&key), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof key,&key,&saved);
  container[27] = 0; container[24] = 9;
  munit_assert_int(TC_TWIC_tpk_read((TC_bytes){container,sizeof container},TC_TWIC_TPK_CARD,&key), ==, TC_TLV_UNSUPPORTED);
  munit_assert_memory_equal(sizeof key,&key,&saved);
  container[24] = 8; container[0] = 0xdc; container[1] = 0xf1;
  munit_assert_int(TC_TWIC_tpk_read((TC_bytes){container,sizeof container},TC_TWIC_TPK_CARD,&key), ==, TC_TLV_INVALID);
  hex[10] = 'X';
  munit_assert_int(TC_TWIC_tpk_read((TC_bytes){hex,sizeof hex - 1},TC_TWIC_TPK_BARCODE_HEX,&key), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof key,&key,&saved);
  (void)params; (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/directory",directory,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/fields",fields,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/privacy-key",privacy_key,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/aamva",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
