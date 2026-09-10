/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/unicode_internal.h"
#include "../../src/string_internal.h"
#include "munit.h"
#include "test_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static MunitResult known_answers(const MunitParameter params[], void* user)
{
  static const uint32_t inputs[][4] = {
    {0x65,0x301}, {0x65,0x300,0x301}, {0x65,0x327,0x301},
    {0x315,0x301,0x65}, {0xfb01}, {0xac01}, {0xf951}, {0x2f868}
  };
  static const uint32_t expected[][4] = {
    {0xe9}, {0xe8,0x301}, {0x229,0x301}, {0x301,0x315,0x65},
    {0x66,0x69}, {0xac01}, {0x964b}, {0x2136a}
  };
  static const size_t lengths[] = {2,3,3,3,1,1,1,1};
  static const size_t expected_lengths[] = {1,2,2,3,2,1,1,1};
  size_t i;
  (void)params; (void)user;
  for (i = 0; i < sizeof lengths / sizeof lengths[0]; ++i) {
    uint32_t output[32];
    size_t written = 99, work = 1000;
    munit_assert_int(tc_unicode_nfkc(inputs[i], lengths[i], output, 32, &written, &work), ==, TC_TLV_OK);
    munit_assert_size(written, ==, expected_lengths[i]);
    munit_assert_memory_equal(written * sizeof(*output), output, expected[i]);
  }
  return MUNIT_OK;
}

static MunitResult bounds(const MunitParameter params[], void* user)
{
  const uint32_t input[] = {0xfb01,0x315,0x301,0x327};
  const uint32_t invalid[] = {0x110000,0xd800,0xdfff};
  uint32_t output[16];
  size_t written = 99, work = 1000, needed, i;
  (void)params; (void)user;
  munit_assert_int(tc_unicode_nfkc(input, 4, output, 16, &written, &work), ==, TC_TLV_OK);
  needed = 1000 - work;
  for (i = 0; i < needed; ++i) {
    work = i; written = 99;
    munit_assert_int(tc_unicode_nfkc(input, 4, output, 16, &written, &work), ==, TC_TLV_LIMIT);
    munit_assert_size(written, ==, 99);
    munit_assert_size(work, ==, 0);
  }
  work = needed;
  munit_assert_int(tc_unicode_nfkc(input, 4, output, 16, &written, &work), ==, TC_TLV_OK);
  munit_assert_size(work, ==, 0);
  for (i = 0; i < 5; ++i) {
    work = 1000; written = 99;
    munit_assert_int(tc_unicode_nfkc(input, 4, output, i, &written, &work), ==, TC_TLV_LIMIT);
    munit_assert_size(written, ==, 99);
  }
  for (i = 0; i < 3; ++i) {
    work = 1000;
    munit_assert_int(tc_unicode_nfkc(invalid + i, 1, output, 16, &written, &work), ==, TC_TLV_INVALID);
    munit_assert_size(written, ==, 99);
  }
  work = 1000;
  munit_assert_int(tc_unicode_nfkc(output, 1, output, 16, &written, &work), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_unicode_nfkc(input, 1, output, SIZE_MAX, &written, &work), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_unicode_nfkc(input, 1, output, 16, &work, &work), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_unicode_nfkc(NULL, 1, output, 16, &written, &work), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_unicode_nfkc(input, 1, NULL, 16, &written, &work), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_unicode_nfkc(input, 1, output, 16, NULL, &work), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_unicode_nfkc(input, 1, output, 16, &written, NULL), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, 1000);
  work = 0;
  munit_assert_int(tc_unicode_nfkc(NULL, 0, NULL, 0, &written, &work), ==, TC_TLV_OK);
  munit_assert_size(written, ==, 0);
  return MUNIT_OK;
}

static MunitResult mapping(const MunitParameter params[], void* user)
{
  static const uint32_t removed[] = {
    0,8,14,31,0x7f,0x84,0x86,0x9f,0xad,0x34f,0x6dd,0x70f,0x1806,
    0x180b,0x180d,0x180e,0x200b,0x200f,0x202a,0x202e,0x2060,0x2063,
    0x206a,0x206f,0xfe00,0xfe0f,0xfeff,0xfff9,0xfffc,0x1d173,0x1d17a,
    0xe0001,0xe0020,0xe007f
  };
  static const uint32_t spaces[] = {
    9,10,11,12,13,0x85,0x20,0xa0,0x1680,0x2000,0x200a,0x2028,0x2029,
    0x202f,0x205f,0x3000
  };
  static const uint32_t folded[] = {0x41,0xdf,0x130,0x3c2,0x1d400};
  static const uint32_t answers[][2] = {{0x61},{0x73,0x73},{0x69,0x307},{0x3c3},{0x61}};
  static const size_t lengths[] = {1,2,2,1,1};
  uint32_t output[5] = {0,0,0,0,0xdeadbeef};
  size_t i;
  (void)params; (void)user;
  for (i = 0; i < sizeof removed / sizeof removed[0]; ++i)
    munit_assert_size(tc_unicode_map(removed[i], output), ==, 0);
  for (i = 0; i < sizeof spaces / sizeof spaces[0]; ++i) {
    munit_assert_size(tc_unicode_map(spaces[i], output), ==, 1);
    munit_assert_uint32(output[0], ==, 0x20);
  }
  for (i = 0; i < sizeof folded / sizeof folded[0]; ++i) {
    munit_assert_size(tc_unicode_map(folded[i], output), ==, lengths[i]);
    munit_assert_memory_equal(lengths[i] * sizeof(*output), output, answers[i]);
  }
  munit_assert_size(tc_unicode_map(0xfe10, output), ==, 1);
  munit_assert_uint32(output[0], ==, 0xfe10);
  munit_assert_uint32(output[4], ==, 0xdeadbeef);
  return MUNIT_OK;
}

static MunitResult repertoire(const MunitParameter params[], void* user)
{
  static const uint32_t prohibited[] = {
    0x221,0x340,0x341,0x200e,0x202a,0x206f,0xd800,0xdfff,0xe000,
    0xf8ff,0xfdd0,0xfdef,0xfffd,0xfffe,0xffff,0x1ffff,0xf0000,
    0xffffd,0x100000,0x10fffd,0x10ffff,0x110000,0x1f600
  };
  static const uint32_t allowed[] = {0x20,0x41,0xdf,0x220,0x300,0x5d0,0x20000,0x2a6d6};
  size_t i;
  (void)params; (void)user;
  for (i = 0; i < sizeof prohibited / sizeof prohibited[0]; ++i)
    munit_assert_false(tc_unicode_allowed(prohibited[i]));
  for (i = 0; i < sizeof allowed / sizeof allowed[0]; ++i)
    munit_assert_true(tc_unicode_allowed(allowed[i]));
  munit_assert_true(tc_unicode_mark(0x903));
  munit_assert_true(tc_unicode_mark(0x301));
  munit_assert_true(tc_unicode_mark(0x20dd));
  munit_assert_false(tc_unicode_mark(0x904));
  munit_assert_false(tc_unicode_mark(0x20));
  munit_assert_false(tc_unicode_mark(0x110000));
  return MUNIT_OK;
}

static MunitResult name_spaces(const MunitParameter params[], void* user)
{
  static const uint32_t inputs[][8] = {
    {0}, {0x20,0x20}, {0x20,0x61,0x20,0x20,0x62,0x20},
    {0x20,0x301}, {0x61,0x20,0x903,0x62}, {0x61,0x20,0x20,0x301,0x20},
    {0x1036}
  };
  static const uint32_t expected[][8] = {
    {0x20,0x20}, {0x20,0x20}, {0x20,0x61,0x20,0x20,0x62,0x20},
    {0x20,0x20,0x301,0x20}, {0x20,0x61,0x20,0x903,0x62,0x20},
    {0x20,0x61,0x20,0x20,0x20,0x301,0x20}, {0x20,0x1036,0x20}
  };
  static const size_t lengths[] = {0,2,6,2,4,5,1};
  static const size_t result_lengths[] = {2,2,6,4,6,7,3};
  uint32_t buffer[16];
  size_t i, budget, work, written;
  (void)params; (void)user;
  for (i = 0; i < sizeof lengths / sizeof lengths[0]; ++i) {
    memcpy(buffer, inputs[i], sizeof inputs[i]);
    written = 99; work = 1000;
    munit_assert_int(tc_unicode_finish_name(buffer, lengths[i], 16, &written, &work), ==, TC_TLV_OK);
    munit_assert_size(written, ==, result_lengths[i]);
    munit_assert_memory_equal(written * sizeof(*buffer), buffer, expected[i]);
    for (budget = 0; budget < 1000 - work; ++budget) {
      size_t limited = budget;
      memcpy(buffer, inputs[i], sizeof inputs[i]);
      written = 99;
      munit_assert_int(tc_unicode_finish_name(buffer, lengths[i], 16, &written, &limited), ==, TC_TLV_LIMIT);
      munit_assert_size(written, ==, 99);
    }
  }
  buffer[0] = 0xfffd; work = 1000; written = 99;
  munit_assert_int(tc_unicode_finish_name(buffer, 1, 16, &written, &work), ==, TC_TLV_INVALID);
  munit_assert_size(written, ==, 99);
  buffer[0] = 0x61;
  munit_assert_int(tc_unicode_finish_name(buffer, 1, 2, &written, &work), ==, TC_TLV_LIMIT);
  munit_assert_size(written, ==, 99);
  munit_assert_int(tc_unicode_finish_name(NULL, 0, 0, &written, &work), ==, TC_TLV_LIMIT);
  munit_assert_int(tc_unicode_finish_name(buffer, 17, 16, &written, &work), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_unicode_finish_name(buffer, 1, SIZE_MAX, &written, &work), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_unicode_finish_name(buffer, 1, 16, &work, &work), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult normalization_file(const MunitParameter params[], void* user)
{
  const char* path = getenv("TC_UNICODE_NORMALIZATION_FILE");
  FILE* file;
  char line[8192];
  size_t cases = 0;
  (void)params; (void)user;
  munit_assert_not_null(path);
  file = fopen(path, "r");
  munit_assert_not_null(file);
  while (fgets(line, sizeof line, file)) {
    uint32_t columns[5][128], output[256];
    size_t lengths[5] = {0}, column;
    char* cursor = line;
    munit_assert_not_null(strchr(line, '\n'));
    if (*cursor == '#' || *cursor == '@' || *cursor == '\n' || *cursor == '\r') continue;
    for (column = 0; column < 5; ++column) {
      while (*cursor != ';') {
        char* end;
        unsigned long value;
        while (*cursor == ' ' || *cursor == '\t') ++cursor;
        if (*cursor == ';') break;
        value = strtoul(cursor, &end, 16);
        munit_assert_ptr_not_equal(cursor, end);
        munit_assert_ulong(value, <=, 0x10ffff);
        munit_assert_size(lengths[column], <, 128);
        columns[column][lengths[column]++] = (uint32_t)value;
        cursor = end;
      }
      ++cursor;
    }
    for (column = 0; column < 5; ++column) {
      size_t written = 99, work = 100000;
      munit_assert_int(tc_unicode_nfkc(columns[column], lengths[column], output, 256, &written, &work), ==, TC_TLV_OK);
      munit_assert_size(written, ==, lengths[3]);
      munit_assert_memory_equal(written * sizeof(*output), output, columns[3]);
    }
    ++cases;
  }
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(cases, ==, 16992);
  return MUNIT_OK;
}

typedef struct { uint32_t point; size_t count; } decoded_scalar;

static TC_TLV_result collect_scalar(void* context, uint32_t point)
{
  decoded_scalar* output = context;
  output->point = point;
  ++output->count;
  return TC_TLV_OK;
}

static MunitResult decoding(const MunitParameter params[], void* user)
{
  static const uint8_t valid[][4] = {
    {0}, {0x7f}, {0xc2,0x80}, {0xdf,0xbf}, {0xe0,0xa0,0x80},
    {0xed,0x9f,0xbf}, {0xee,0x80,0x80}, {0xef,0xbf,0xbf},
    {0xf0,0x90,0x80,0x80}, {0xf4,0x8f,0xbf,0xbf}
  };
  static const size_t widths[] = {1,1,2,2,3,3,3,3,4,4};
  static const uint32_t points[] = {0,0x7f,0x80,0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,0x10ffff};
  static const uint8_t invalid[][4] = {
    {0x80}, {0xc0,0x80}, {0xc1,0x81}, {0xe0,0x80,0x80}, {0xed,0xa0,0x80},
    {0xf0,0x80,0x80,0x80}, {0xf4,0x90,0x80,0x80}, {0xf5,0x80,0x80,0x80},
    {0xff}, {0xc2,0x20}, {0xe1,0x80,0x20}, {0xf1,0x80,0x80,0x20}
  };
  uint32_t point;
  size_t i, length, offset;
  (void)params; (void)user;
  for (i = 0; i < sizeof widths / sizeof widths[0]; ++i) {
    TC_bytes input = {valid[i], widths[i]};
    point = 99; offset = 0;
    munit_assert_int(tc_asn1_string_next(0x0c, input, &offset, &point), ==, TC_TLV_OK);
    munit_assert_size(offset, ==, widths[i]);
    munit_assert_uint32(point, ==, points[i]);
    munit_assert_int(tc_asn1_string_next(0x0c, input, &offset, &point), ==, TC_TLV_END);
    for (size_t split = 0; split <= input.length; ++split) {
      tc_asn1_string_state decoder = {0x0c,{0},0};
      decoded_scalar collected = {0,0};
      munit_assert_int(tc_asn1_string_feed(&decoder,(TC_bytes){input.data,split},
          collect_scalar,&collected), ==, TC_TLV_OK);
      munit_assert_int(tc_asn1_string_feed(&decoder,(TC_bytes){input.data + split,input.length - split},
          collect_scalar,&collected), ==, TC_TLV_OK);
      munit_assert_size(decoder.used, ==, 0);
      munit_assert_size(collected.count, ==, 1);
      munit_assert_uint32(collected.point, ==, points[i]);
    }
    {
      tc_asn1_string_state decoder = {0x0c,{0},0};
      decoded_scalar collected = {0,0};
      for (size_t byte = 0; byte < input.length; ++byte)
        munit_assert_int(tc_asn1_string_feed(&decoder,(TC_bytes){input.data + byte,1},
            collect_scalar,&collected), ==, TC_TLV_OK);
      munit_assert_size(decoder.used, ==, 0);
      munit_assert_size(collected.count, ==, 1);
      munit_assert_uint32(collected.point, ==, points[i]);
    }
    for (length = 0; length < widths[i]; ++length) {
      input.length = length; offset = 0; point = 99;
      munit_assert_int(tc_asn1_string_next(0x0c, input, &offset, &point), ==,
                       length ? TC_TLV_INVALID : TC_TLV_END);
      munit_assert_size(offset, ==, 0);
      munit_assert_uint32(point, ==, 99);
    }
  }
  for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    TC_bytes input = {invalid[i], 4};
    offset = 0; point = 99;
    munit_assert_int(tc_asn1_string_next(0x0c, input, &offset, &point), ==, TC_TLV_INVALID);
    munit_assert_size(offset, ==, 0);
    munit_assert_uint32(point, ==, 99);
    for (size_t split = 0; split <= input.length; ++split) {
      tc_asn1_string_state decoder = {0x0c,{0},0};
      TC_TLV_result result = tc_asn1_string_feed(&decoder,(TC_bytes){input.data,split},NULL,NULL);
      if (result == TC_TLV_OK)
        result = tc_asn1_string_feed(&decoder,(TC_bytes){input.data + split,input.length - split},NULL,NULL);
      munit_assert_int(result, ==, TC_TLV_INVALID);
    }
  }
  {
    const uint8_t bytes[] = {0,0x41,0xd8,0,0,0x11,0,0};
    TC_bytes input = {bytes,sizeof bytes};
    offset = 0;
    munit_assert_int(tc_asn1_string_next(0x1e, input, &offset, &point), ==, TC_TLV_OK);
    munit_assert_uint32(point, ==, 0x41);
    munit_assert_int(tc_asn1_string_next(0x1e, input, &offset, &point), ==, TC_TLV_INVALID);
    munit_assert_size(offset, ==, 2);
    offset = 4;
    munit_assert_int(tc_asn1_string_next(0x1c, input, &offset, &point), ==, TC_TLV_INVALID);
    input.length = 1; offset = 0;
    munit_assert_int(tc_asn1_string_next(0x1e, input, &offset, &point), ==, TC_TLV_INVALID);
    munit_assert_int(tc_asn1_string_next(0x13, input, &offset, &point), ==, TC_TLV_INVALID);
    munit_assert_int(tc_asn1_string_next(0x16, input, &offset, &point), ==, TC_TLV_OK);
    input.length = 0; offset = 0;
    munit_assert_int(tc_asn1_string_next(0x14, input, &offset, &point), ==, TC_TLV_INVALID);
    tc_asn1_string_state decoder = {0x14,{0},0};
    munit_assert_int(tc_asn1_string_feed(&decoder,input,NULL,NULL), ==, TC_TLV_INVALID);
  }
  return MUNIT_OK;
}

typedef struct {
  uint32_t* output;
  size_t capacity, used, work;
} preparation_state;

static TC_TLV_result prepare_scalar(void* context, uint32_t point)
{
  preparation_state* state = context;
  if (!state->work) return TC_TLV_LIMIT;
  --state->work;
  return tc_unicode_prepare_point(point,state->output,state->capacity,&state->used,&state->work);
}

static MunitResult preparation(const MunitParameter params[], void* user)
{
  static const uint8_t inputs[][10] = {
    {0xc3,0x85}, {0,0xc5}, {0,0,0,0xc5}, {0x41,0xcc,0x8a},
    {0x20,0x41,0x20,0x20,0x42,0x20}, {0xc2,0xad}, {0xcd,0x80},
    {0x41,0xd7,0x90}, {0x53,0x74,0x72,0x61,0xc3,0x9f,0x65}
  };
  static const unsigned tags[] = {0x0c,0x1e,0x1c,0x0c,0x13,0x0c,0x0c,0x0c,0x0c};
  static const size_t lengths[] = {2,2,4,3,6,2,2,3,7};
  static const uint32_t answers[][10] = {
    {0x20,0xe5,0x20}, {0x20,0xe5,0x20}, {0x20,0xe5,0x20}, {0x20,0xe5,0x20},
    {0x20,0x61,0x20,0x20,0x62,0x20}, {0x20,0x20}, {0x20,0x300,0x20},
    {0x20,0x61,0x5d0,0x20}, {0x20,0x73,0x74,0x72,0x61,0x73,0x73,0x65,0x20}
  };
  static const size_t answer_lengths[] = {3,3,3,3,6,2,3,4,9};
  size_t i, work, written;
  uint32_t output[32];
  (void)params; (void)user;
  for (i = 0; i < sizeof lengths / sizeof lengths[0]; ++i) {
    TC_bytes input = {inputs[i],lengths[i]};
    size_t required, limit;
    work = 1000; written = 99;
    munit_assert_int(tc_unicode_prepare(tags[i], input, output, 32, &written, &work), ==, TC_TLV_OK);
    munit_assert_size(written, ==, answer_lengths[i]);
    munit_assert_memory_equal(written * sizeof(*output), output, answers[i]);
    required = 1000 - work;
    for (size_t split = 0; split <= input.length; ++split) {
      tc_asn1_string_state decoder = {tags[i],{0},0};
      preparation_state state = {output,sizeof output / sizeof output[0],0,1000};
      written = 99;
      munit_assert_int(tc_asn1_string_feed(&decoder,(TC_bytes){input.data,split},
          prepare_scalar,&state), ==, TC_TLV_OK);
      munit_assert_int(tc_asn1_string_feed(&decoder,(TC_bytes){input.data + split,input.length - split},
          prepare_scalar,&state), ==, TC_TLV_OK);
      munit_assert_size(decoder.used, ==, 0);
      munit_assert_int(tc_unicode_prepare_finish(output,state.used,state.capacity,&written,&state.work),
          ==, TC_TLV_OK);
      munit_assert_size(written, ==, answer_lengths[i]);
      munit_assert_memory_equal(written * sizeof(*output),output,answers[i]);
      munit_assert_size(1000 - state.work, ==, required);
    }
    for (limit = 0; limit < required; ++limit) {
      work = limit; written = 99;
      munit_assert_int(tc_unicode_prepare(tags[i], input, output, 32, &written, &work), ==, TC_TLV_LIMIT);
      munit_assert_size(written, ==, 99);
    }
  }
  {
    const uint8_t future[] = {0xf0,0x9f,0x98,0x80};
    TC_bytes input = {future,sizeof future};
    work = 1000; written = 99;
    munit_assert_int(tc_unicode_prepare(0x0c, input, output, 32, &written, &work), ==, TC_TLV_INVALID);
    munit_assert_size(written, ==, 99);
    input.data = inputs[0]; input.length = lengths[0];
    munit_assert_int(tc_unicode_prepare(0x0c, input, output, 2, &written, &work), ==, TC_TLV_LIMIT);
    munit_assert_size(written, ==, 99);
    input.data = (const uint8_t*)output;
    munit_assert_int(tc_unicode_prepare(0x0c, input, output, 32, &written, &work), ==, TC_TLV_ARGUMENT);
  }
  return MUNIT_OK;
}

static MunitResult preparation_oracle(const MunitParameter params[], void* user)
{
  const char* path = getenv("TC_UNICODE_ORACLE_FILE");
  FILE* file;
  char input_hex[513], expected_hex[8193];
  uint8_t input[256], expected[4096];
  uint32_t output[1024];
  size_t total, count = 0;
  int status, fields;
  unsigned tag;
  (void)params; (void)user;
  munit_assert_not_null(path);
  file = fopen(path, "r");
  munit_assert_not_null(file);
  munit_assert_int(fscanf(file, "%zu", &total), ==, 1);
  munit_assert_size(total, >, 0);
  while ((fields = fscanf(file, "%u %d %512s %8192s", &tag, &status, input_hex, expected_hex)) == 4) {
    TC_bytes value;
    TC_TLV_result result;
    size_t written = SIZE_MAX, work = 500000, expected_bytes, i;
    value.data = input;
    value.length = strcmp(input_hex, "-") ? tc_test_decode_hex(input_hex, input, sizeof input) : 0;
    expected_bytes = strcmp(expected_hex, "-") ? tc_test_decode_hex(expected_hex, expected, sizeof expected) : 0;
    munit_assert_size(value.length, !=, SIZE_MAX);
    munit_assert_size(expected_bytes, !=, SIZE_MAX);
    munit_assert_size(expected_bytes % 4, ==, 0);
    result = tc_unicode_prepare(tag, value, output, 1024, &written, &work);
    if ((int)result != status)
      munit_errorf("preparation case %zu, tag %u: expected %d, got %d", count, tag, status, (int)result);
    if (result == TC_TLV_OK) {
      munit_assert_size(written, ==, expected_bytes / 4);
      for (i = 0; i < written; ++i) {
        uint32_t point = ((uint32_t)expected[4*i] << 24) | ((uint32_t)expected[4*i+1] << 16)
            | ((uint32_t)expected[4*i+2] << 8) | expected[4*i+3];
        if (output[i] != point)
          munit_errorf("preparation case %zu, scalar %zu: expected %x, got %x", count, i,
                       (unsigned)point, (unsigned)output[i]);
      }
    } else munit_assert_size(written, ==, SIZE_MAX);
    ++count;
  }
  munit_assert_int(fields, ==, EOF);
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(count, ==, total);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/known-answers", known_answers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/bounds", bounds, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/mapping", mapping, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/repertoire", repertoire, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/name-spaces", name_spaces, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/decoding", decoding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/preparation", preparation, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/normalization-file", normalization_file, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/preparation-oracle", preparation_oracle, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
  };
  MunitSuite suite = {"/unicode", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  {
    const size_t end = sizeof tests / sizeof tests[0] - 1;
    size_t next = end - 2;
    const MunitTest normalization = tests[next], oracle = tests[next + 1];
    if (getenv("TC_UNICODE_NORMALIZATION_FILE")) tests[next++] = normalization;
    if (getenv("TC_UNICODE_ORACLE_FILE")) tests[next++] = oracle;
    tests[next] = tests[end];
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
