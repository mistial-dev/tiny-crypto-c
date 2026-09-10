/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/inflate_internal.h"
#include "munit.h"
#include <string.h>

static MunitResult trees(const MunitParameter params[], void* context)
{
  /* RFC 1951 section 3.2.2 alphabet ABCDEFGH. */
  const uint8_t lengths[] = {3,3,3,3,3,2,4,4};
  const uint16_t order[] = {5,0,1,2,3,4,6,7};
  uint16_t symbols[TC_INFLATE_LITERAL_CODES];
  tc_inflate_tree tree = {{0},symbols};
  size_t work = 2 * sizeof lengths + TC_INFLATE_CODE_BITS;
  munit_assert_int(tc_inflate_tree_build(lengths,sizeof lengths,TC_INFLATE_COMPLETE_TREE,&tree,&work), ==, TC_TLV_OK);
  munit_assert_size(work, ==, 0);
  munit_assert_memory_equal(sizeof order,symbols,order);
  munit_assert_uint(tree.counts[2], ==, 1);
  munit_assert_uint(tree.counts[3], ==, 5);
  munit_assert_uint(tree.counts[4], ==, 2);
  work = 2 * sizeof lengths + TC_INFLATE_CODE_BITS - 1;
  munit_assert_int(tc_inflate_tree_build(lengths,sizeof lengths,TC_INFLATE_COMPLETE_TREE,&tree,&work), ==, TC_TLV_LIMIT);
  munit_assert_size(work, ==, 2 * sizeof lengths + TC_INFLATE_CODE_BITS - 1);
  const uint8_t cases[][3] = {{1,1,1},{2,2,0},{16,0,0},{0,0,0},{1,0,0}};
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    for (unsigned kind = TC_INFLATE_COMPLETE_TREE; kind <= TC_INFLATE_DISTANCE_TREE; ++kind) {
      const int valid = (i == 3 && kind == TC_INFLATE_DISTANCE_TREE) ||
          (i == 4 && kind != TC_INFLATE_COMPLETE_TREE);
      work = SIZE_MAX;
      munit_assert_int(tc_inflate_tree_build(cases[i],3,(tc_inflate_tree_kind)kind,&tree,&work), ==,
          valid ? TC_TLV_OK : TC_TLV_INVALID);
    }
  }
  (void)params; (void)context; return MUNIT_OK;
}
static MunitResult bits_and_symbols(const MunitParameter params[], void* context)
{
  /* ABCDEFGH from RFC 1951's canonical-code example, packed LSB-first. */
  const uint8_t encoded[] = {0x72,0x3a,0xee,0x01};
  const uint8_t lengths[] = {3,3,3,3,3,2,4,4};
  uint16_t symbols[8]; tc_inflate_tree tree = {{0},symbols};
  size_t work = SIZE_MAX;
  munit_assert_int(tc_inflate_tree_build(lengths,8,TC_INFLATE_COMPLETE_TREE,&tree,&work), ==, TC_TLV_OK);
  for (size_t budget = 0; budget <= 25; ++budget) {
    work = budget;
    tc_inflate_bits bits = {{encoded,sizeof encoded},0,0,&work};
    unsigned decoded = 0;
    for (unsigned symbol = 0; symbol < 8; ++symbol) {
      unsigned out = 999;
      TC_TLV_result result = tc_inflate_symbol(&bits,&tree,&out);
      if (result != TC_TLV_OK) {
        munit_assert_int(result, ==, TC_TLV_LIMIT); munit_assert_uint(out, ==, 999);
        break;
      }
      munit_assert_uint(out, ==, symbol); ++decoded;
    }
    unsigned expected_count = 0;
    size_t required = 0;
    while (expected_count < 8 && required + lengths[expected_count] <= budget)
      required += lengths[expected_count++];
    munit_assert_uint(decoded, ==, expected_count);
  }
  for (unsigned start = 0; start < 8; ++start) {
    for (unsigned count = 0; count <= 16; ++count) {
      work = count;
      tc_inflate_bits bits = {{encoded,sizeof encoded},0,start,&work};
      unsigned out = 999;
      const uint32_t packed = UINT32_C(0x01ee3a72);
      const unsigned expected = (unsigned)((packed >> start) & ((UINT32_C(1) << count) - 1));
      munit_assert_int(tc_inflate_bits_read(&bits,count,&out), ==, TC_TLV_OK);
      munit_assert_uint(out, ==, expected); munit_assert_size(work, ==, 0);
      munit_assert_size(bits.offset, ==, (start + count) / 8);
      munit_assert_uint(bits.bit, ==, (start + count) % 8);
    }
  }
  for (size_t length = 0; length < sizeof encoded; ++length) {
    work = SIZE_MAX;
    tc_inflate_bits bits = {{encoded,length},0,0,&work};
    unsigned decoded = 0, out = 999;
    while (tc_inflate_symbol(&bits,&tree,&out) == TC_TLV_OK) ++decoded;
    munit_assert_uint(decoded, <, 8);
  }
  (void)params; (void)context; return MUNIT_OK;
}

static MunitResult tables(const MunitParameter params[], void* context)
{
  /* Python zlib, raw DEFLATE of the sentence below repeated 100 times. */
  static const uint8_t dynamic[] = {
    0xed,0xca,0x47,0x01,0x80,0x30,0x10,0x45,0x41,0x2b,0x5f,0x01,0x6a,0x62,0x80,0x92,
    0xd0,0xd9,0x10,0x08,0x4d,0x3d,0x88,0xe0,0xf8,0xce,0x33,0xae,0xf3,0x5a,0x73,0x5f,
    0x8f,0xaa,0x92,0x9d,0x8b,0x82,0x5d,0x1a,0xf2,0x1c,0x37,0xd9,0xe1,0x93,0xf6,0x8f,
    0xa7,0xf2,0xb9,0xd5,0x58,0x5b,0xc8,0x91,0xc9,0x64,0x32,0x99,0x4c,0x26,0x93,0xc9,
    0x64,0x32,0x99,0x4c,0x26,0x93,0xff,0xc8,0x2f
  };
  tc_inflate_tables storage;
  uint8_t output_bytes[4500];
  const uint8_t sentence[] = "The quick brown fox jumps over the lazy dog. ";
  size_t decode_work = SIZE_MAX;
  tc_inflate_bits stream = {{dynamic,sizeof dynamic},0,0,&decode_work};
  tc_inflate_output output = {output_bytes,sizeof output_bytes,0};
  munit_assert_int(tc_inflate_decode(&stream,&storage,&output), ==, TC_TLV_OK);
  munit_assert_size(output.length, ==, sizeof output_bytes);
  munit_assert_size(stream.offset, ==, sizeof dynamic);
  for (size_t i = 0; i < output.length; ++i)
    munit_assert_uint(output_bytes[i], ==, sentence[i % (sizeof sentence - 1)]);
  const size_t decode_cost = SIZE_MAX - decode_work;
  for (size_t budget = decode_cost - 1; budget <= decode_cost; ++budget) {
    decode_work = budget; stream.offset = 0; stream.bit = 0; output.length = 0;
    munit_assert_int(tc_inflate_decode(&stream,&storage,&output), ==,
        budget == decode_cost ? TC_TLV_OK : TC_TLV_LIMIT);
  }
  for (size_t length = 0; length < sizeof dynamic; ++length) {
    decode_work = SIZE_MAX; stream.input.length = length; stream.offset = 0; stream.bit = 0;
    output.length = 0;
    munit_assert_int(tc_inflate_decode(&stream,&storage,&output), ==, TC_TLV_INVALID);
  }
  decode_work = SIZE_MAX; stream.input.length = sizeof dynamic; stream.offset = 0; stream.bit = 0;
  output.length = 0; output.capacity = sizeof output_bytes - 1;
  munit_assert_int(tc_inflate_decode(&stream,&storage,&output), ==, TC_TLV_LIMIT);
  munit_assert_size(output.length, <=, output.capacity);
  size_t work = SIZE_MAX;
  tc_inflate_bits bits = {{dynamic,sizeof dynamic},0,3,&work};
  munit_assert_int(tc_inflate_tables_read(&bits,2,&storage), ==, TC_TLV_OK);
  const size_t cost = SIZE_MAX - work;
  const size_t header_bytes = bits.offset + (bits.bit != 0);
  unsigned symbol;
  munit_assert_int(tc_inflate_symbol(&bits,&storage.literal,&symbol), ==, TC_TLV_OK);
  munit_assert_uint(symbol, ==, 'T'); /* The quick brown fox jumps over the lazy dog. */
  for (size_t length = 0; length < header_bytes; ++length) {
    work = SIZE_MAX;
    tc_inflate_bits prefix = {{dynamic,length},0,3,&work};
    munit_assert_int(tc_inflate_tables_read(&prefix,2,&storage), ==, TC_TLV_INVALID);
  }
  for (size_t budget = cost - 1; budget <= cost; ++budget) {
    work = budget;
    tc_inflate_bits bounded = {{dynamic,sizeof dynamic},0,3,&work};
    munit_assert_int(tc_inflate_tables_read(&bounded,2,&storage), ==,
        budget == cost ? TC_TLV_OK : TC_TLV_LIMIT);
  }
  uint8_t invalid[sizeof dynamic]; memcpy(invalid,dynamic,sizeof invalid);
  for (unsigned reserved = 30; reserved <= 31; ++reserved) {
    invalid[0] = (uint8_t)((reserved << 3) | 5);
    work = SIZE_MAX;
    tc_inflate_bits bad = {{invalid,sizeof invalid},0,3,&work};
    munit_assert_int(tc_inflate_tables_read(&bad,2,&storage), ==, TC_TLV_INVALID);
  }
  work = SIZE_MAX;
  munit_assert_int(tc_inflate_tables_read(&bits,1,&storage), ==, TC_TLV_OK);
  munit_assert_uint(storage.literal.counts[7], ==, 24);
  munit_assert_uint(storage.literal.counts[8], ==, 152);
  munit_assert_uint(storage.literal.counts[9], ==, 112);
  munit_assert_uint(storage.distance.counts[5], ==, 32);
  (void)params; (void)context; return MUNIT_OK;
}

static MunitResult blocks(const MunitParameter params[], void* context)
{
  /* Independent zlib fixed and stored encodings of six repetitions of abc. */
  const uint8_t fixed[] = {0x4b,0x4c,0x4a,0x4e,0x44,0x45,0};
  const uint8_t stored[] = {1,18,0,0xed,0xff,'a','b','c','a','b','c','a','b','c',
      'a','b','c','a','b','c','a','b','c'};
  const TC_bytes fixtures[] = {{fixed,sizeof fixed},{stored,sizeof stored}};
  tc_inflate_tables tables;
  uint8_t bytes[32];
  for (size_t i = 0; i < 2; ++i) {
    for (size_t capacity = 0; capacity <= 18; ++capacity) {
      size_t work = SIZE_MAX;
      tc_inflate_bits bits = {fixtures[i],0,0,&work};
      tc_inflate_output output = {bytes,capacity,0};
      munit_assert_int(tc_inflate_decode(&bits,&tables,&output), ==,
          capacity == 18 ? TC_TLV_OK : TC_TLV_LIMIT);
      munit_assert_size(output.length, <=, capacity);
      if (capacity == 18) munit_assert_memory_equal(18,bytes,"abcabcabcabcabcabc");
    }
  }
  const uint8_t multiple[] = {0,1,0,0xfe,0xff,'A',1,1,0,0xfe,0xff,'B'};
  size_t work = SIZE_MAX;
  tc_inflate_bits bits = {{multiple,sizeof multiple},0,0,&work};
  tc_inflate_output output = {bytes,sizeof bytes,0};
  munit_assert_int(tc_inflate_decode(&bits,&tables,&output), ==, TC_TLV_OK);
  munit_assert_memory_equal(2,bytes,"AB");
  const uint8_t invalid[][5] = {{7,0,0,0,0},{1,0,0,0,0},{3,2,0,0,0}};
  for (size_t i = 0; i < 3; ++i) {
    work = SIZE_MAX;
    tc_inflate_bits bad = {{invalid[i],sizeof invalid[i]},0,0,&work};
    output.length = 8; /* A new stream cannot reference an earlier member. */
    munit_assert_int(tc_inflate_decode(&bad,&tables,&output), ==, TC_TLV_INVALID);
  }
  (void)params; (void)context; return MUNIT_OK;
}

static MunitResult gzip_members(const MunitParameter params[], void* context)
{
  /* Python gzip.compress(..., mtime=0); optional-header CRC from zlib.crc32. */
  const uint8_t member[] = {0x1f,0x8b,8,0,0,0,0,0,2,0xff,
    0x4b,0x4c,0x4a,0x4e,0x44,0x45,0,4,0xc0,0x26,0xdc,18,0,0,0};
  const uint8_t empty[] = {0x1f,0x8b,8,0,0,0,0,0,2,0xff,3,0,0,0,0,0,0,0,0,0};
  const uint8_t optional[] = {0x1f,0x8b,8,0x1e,0,0,0,0,2,0xff,
    6,0,'A','B',2,0,1,2,'n','a','m','e',0,'c','o','m','m','e','n','t',0,0xf3,0xdf};
  uint8_t output_bytes[36], encoded[80];
  tc_inflate_tables tables;
  tc_inflate_output output = {output_bytes,sizeof output_bytes,0};
  size_t work = SIZE_MAX;
  TC_bytes input = {member,sizeof member};
  munit_assert_int(tc_gzip_decode(input,&tables,&output,&work), ==, TC_TLV_OK);
  munit_assert_size(output.length, ==, 18);
  munit_assert_memory_equal(18,output_bytes,"abcabcabcabcabcabc");
  const size_t cost = SIZE_MAX - work;
  for (size_t budget = cost - 1; budget <= cost; ++budget) {
    output.length = 0; work = budget;
    munit_assert_int(tc_gzip_decode(input,&tables,&output,&work), ==,
        budget == cost ? TC_TLV_OK : TC_TLV_LIMIT);
  }
  for (size_t length = 0; length < sizeof member; ++length) {
    input.length = length; output.length = 0; work = SIZE_MAX;
    munit_assert_int(tc_gzip_decode(input,&tables,&output,&work), ==, TC_TLV_INVALID);
  }
  memcpy(encoded,member,sizeof member); memcpy(encoded + sizeof member,empty,sizeof empty);
  memcpy(encoded + sizeof member + sizeof empty,member,sizeof member);
  input.data = encoded; input.length = 2 * sizeof member + sizeof empty;
  output.length = 0; work = SIZE_MAX;
  munit_assert_int(tc_gzip_decode(input,&tables,&output,&work), ==, TC_TLV_OK);
  munit_assert_size(output.length, ==, 36);
  munit_assert_memory_equal(18,output_bytes,output_bytes + 18);
  memcpy(encoded,optional,sizeof optional);
  memcpy(encoded + sizeof optional,member + 10,sizeof member - 10);
  input.length = sizeof optional + sizeof member - 10;
  output.length = 0; work = SIZE_MAX;
  munit_assert_int(tc_gzip_decode(input,&tables,&output,&work), ==, TC_TLV_OK);
  munit_assert_memory_equal(18,output_bytes,"abcabcabcabcabcabc");
  for (size_t position = sizeof optional - 2; position < sizeof optional; ++position) {
    encoded[position] ^= 1; output.length = 0; work = SIZE_MAX;
    munit_assert_int(tc_gzip_decode(input,&tables,&output,&work), ==, TC_TLV_INVALID);
    encoded[position] ^= 1;
  }
  memcpy(encoded,member,sizeof member); input.length = sizeof member;
  for (size_t position = sizeof member - 8; position < sizeof member; ++position) {
    encoded[position] ^= 1; output.length = 0; work = SIZE_MAX;
    munit_assert_int(tc_gzip_decode(input,&tables,&output,&work), ==, TC_TLV_INVALID);
    encoded[position] ^= 1;
  }
  encoded[3] = 0x20; output.length = 0; work = SIZE_MAX;
  munit_assert_int(tc_gzip_decode(input,&tables,&output,&work), ==, TC_TLV_INVALID);
  encoded[3] = 0; encoded[sizeof member] = 0; ++input.length;
  output.length = 0; work = SIZE_MAX;
  munit_assert_int(tc_gzip_decode(input,&tables,&output,&work), ==, TC_TLV_INVALID);
  input.data = empty; input.length = sizeof empty; output.data = NULL; output.capacity = output.length = 0;
  work = SIZE_MAX;
  munit_assert_int(tc_gzip_decode(input,&tables,&output,&work), ==, TC_TLV_OK);
  (void)params; (void)context; return MUNIT_OK;
}

static MunitResult public_api(const MunitParameter params[], void* context)
{
  uint8_t member[] = {0x1f,0x8b,8,0,0,0,0,0,2,0xff,
    0x4b,0x4c,0x4a,0x4e,0x44,0x45,0,4,0xc0,0x26,0xdc,18,0,0,0};
  uint8_t output[32], zeros[sizeof output] = {0};
  TC_GZIP_workspace workspace;
  size_t work = SIZE_MAX, length = SIZE_MAX;
  munit_assert_int(TC_GZIP_decode(member,sizeof member,output,sizeof output,&workspace,&work,&length), ==, TC_GZIP_OK);
  munit_assert_size(length, ==, 18);
  munit_assert_memory_equal(length,output,"abcabcabcabcabcabc");
  for (size_t i = 0; i < sizeof workspace; ++i)
    munit_assert_uint(((uint8_t*)&workspace)[i], ==, 0);
  member[17] ^= 1; work = SIZE_MAX; length = SIZE_MAX;
  munit_assert_int(TC_GZIP_decode(member,sizeof member,output,sizeof output,&workspace,&work,&length), ==, TC_GZIP_INVALID);
  munit_assert_size(length, ==, SIZE_MAX);
  munit_assert_memory_equal(sizeof output,output,zeros);
  member[17] ^= 1;
  work = 0; memset(output,0x5a,sizeof output);
  munit_assert_int(TC_GZIP_decode(member,sizeof member,output,sizeof output,&workspace,&work,&length), ==, TC_GZIP_LIMIT);
  munit_assert_memory_equal(sizeof output,output,zeros);
  uint8_t saved[sizeof member]; memcpy(saved,member,sizeof member);
  work = SIZE_MAX;
  munit_assert_int(TC_GZIP_decode(member,sizeof member,member,sizeof member,&workspace,&work,&length), ==, TC_GZIP_ARGUMENT);
  munit_assert_memory_equal(sizeof saved,member,saved); munit_assert_size(work, ==, SIZE_MAX);
  munit_assert_int(TC_GZIP_decode(member,sizeof member,output,sizeof output,&workspace,&work,&work), ==, TC_GZIP_ARGUMENT);
  munit_assert_size(work, ==, SIZE_MAX);
  munit_assert_int(TC_GZIP_decode(member,sizeof member,output,sizeof output,NULL,&work,&length), ==, TC_GZIP_ARGUMENT);
  (void)params; (void)context; return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/trees",trees,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/bits-and-symbols",bits_and_symbols,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/tables",tables,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/blocks",blocks,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/gzip-members",gzip_members,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/public-api",public_api,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/inflate",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
