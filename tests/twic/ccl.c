/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/twic_ccl.h>
#include <tiny_crypto/md5.h>
#include "../../examples/twic_ccl_storage.h"
#include "../../examples/twic_ccl_import.h"
#include "munit.h"
#include "test_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Synthetic identifiers retain leading zeros and exercise every hex digit. */
#define IDENTIFIER "000102030405060708090A0B0C0D0E0F101112131415161718"
static const uint8_t row[] = IDENTIFIER ",29Feb2024";
static const uint8_t list[] = IDENTIFIER ",29Feb2024\r\n" IDENTIFIER ",01Mar2024\n";

typedef struct { size_t count, fail_at; TC_TWIC_CCL_record last; } sink;
static TC_status collect(void* context, const TC_TWIC_CCL_record* record)
{
  sink* output = context;
  if (output->count == output->fail_at) return TC_ERROR;
  output->last = *record;
  ++output->count;
  return TC_OK;
}

static MunitResult test_record(const MunitParameter params[], void* user)
{
  TC_TWIC_CCL_record record, saved;
  uint8_t bad[sizeof row];
  const char* dates[] = {"29Feb1900","00Jan2024","31Apr2024","01Jan0000",
    "01JAN2024","01Foo2024","32Dec2024","0xJan2024","01Jan202x"};
  (void)params; (void)user;
  munit_assert_int(TC_TWIC_CCL_read((TC_bytes){row,sizeof row - 1}, &record), ==, TC_TWIC_CCL_OK);
  for (size_t i = 0; i < sizeof record.fascn; ++i) munit_assert_size(record.fascn[i], ==, i);
  munit_assert_uint(record.year, ==, 2024);
  munit_assert_uint(record.month, ==, 2);
  munit_assert_uint(record.day, ==, 29);
  saved = record;
  for (size_t i = 0; i < sizeof row - 1; ++i) {
    memcpy(bad, row, sizeof row);
    bad[i] = 0;
    munit_assert_int(TC_TWIC_CCL_read((TC_bytes){bad,sizeof row - 1}, &record), ==, TC_TWIC_CCL_INVALID);
    munit_assert_memory_equal(sizeof record, &record, &saved);
    munit_assert_int(TC_TWIC_CCL_read((TC_bytes){row,i}, &record), ==, TC_TWIC_CCL_INVALID);
  }
  for (size_t i = 0; i < sizeof dates / sizeof dates[0]; ++i) {
    memcpy(bad, row, sizeof row);
    memcpy(bad + 2 * TC_TWIC_CCL_FASCN_BYTES + 1, dates[i], 9);
    munit_assert_int(TC_TWIC_CCL_read((TC_bytes){bad,sizeof row - 1}, &record), ==, TC_TWIC_CCL_INVALID);
    munit_assert_memory_equal(sizeof record, &record, &saved);
  }
  memcpy(bad, row, sizeof row);
  for (size_t i = 0; i < 2 * TC_TWIC_CCL_FASCN_BYTES; ++i)
    if (bad[i] >= 'A' && bad[i] <= 'F') bad[i] += 'a' - 'A';
  munit_assert_int(TC_TWIC_CCL_read((TC_bytes){bad,sizeof row - 1}, &record), ==, TC_TWIC_CCL_OK);
  munit_assert_memory_equal(sizeof record.fascn, record.fascn, saved.fascn);
  munit_assert_int(TC_TWIC_CCL_read((TC_bytes){NULL,1}, &record), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_read((TC_bytes){row,sizeof row}, &record), ==, TC_TWIC_CCL_INVALID);
  munit_assert_int(TC_TWIC_CCL_read((TC_bytes){row,sizeof row - 1}, NULL), ==, TC_TWIC_CCL_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult test_chunks(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  for (size_t step = 1; step <= sizeof list; ++step) {
    TC_TWIC_CCL_stream stream;
    sink output = {0,SIZE_MAX,{{0},0,0,0}};
    munit_assert_int(TC_TWIC_CCL_stream_init(&stream,sizeof list - 1,2,collect,&output), ==, TC_TWIC_CCL_OK);
    for (size_t offset = 0; offset < sizeof list - 1;) {
      size_t length = sizeof list - 1 - offset;
      if (length > step) length = step;
      munit_assert_int(TC_TWIC_CCL_stream_update(&stream,(TC_bytes){list + offset,length}), ==, TC_TWIC_CCL_OK);
      offset += length;
    }
    munit_assert_int(TC_TWIC_CCL_stream_finish(&stream), ==, TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_stream_finish(&stream), ==, TC_TWIC_CCL_OK);
    munit_assert_size(output.count, ==, 2);
    munit_assert_size(stream.bytes_left, ==, 0);
    munit_assert_size(stream.records_left, ==, 0);
    munit_assert_uint(output.last.day, ==, 1);
    munit_assert_uint(output.last.month, ==, 3);
    munit_assert_int(TC_TWIC_CCL_stream_update(&stream,(TC_bytes){NULL,0}), ==, TC_TWIC_CCL_ARGUMENT);
  }
  return MUNIT_OK;
}

static MunitResult test_failures(const MunitParameter params[], void* user)
{
  uint8_t bad[sizeof list];
  (void)params; (void)user;
  /* Every prefix except a complete first row is empty or truncated. */
  for (size_t cut = 0; cut < sizeof list - 1; ++cut) {
    TC_TWIC_CCL_stream stream;
    sink output = {0,SIZE_MAX,{{0},0,0,0}};
    munit_assert_int(TC_TWIC_CCL_stream_init(&stream,sizeof list,2,collect,&output), ==, TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_stream_update(&stream,(TC_bytes){list,cut}), ==, TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_stream_finish(&stream), ==,
        cut == TC_TWIC_CCL_RECORD_BYTES + 2 ? TC_TWIC_CCL_OK : TC_TWIC_CCL_INVALID);
  }
  for (size_t position = 0; position < sizeof list - 1; ++position) {
    memcpy(bad,list,sizeof list);
    bad[position] = 0;
    for (size_t split = 0; split < sizeof list; ++split) {
      TC_TWIC_CCL_stream stream;
      sink output = {0,SIZE_MAX,{{0},0,0,0}};
      TC_TWIC_CCL_result result;
      munit_assert_int(TC_TWIC_CCL_stream_init(&stream,sizeof list,2,collect,&output), ==, TC_TWIC_CCL_OK);
      result = TC_TWIC_CCL_stream_update(&stream,(TC_bytes){bad,split});
      if (result == TC_TWIC_CCL_OK)
        result = TC_TWIC_CCL_stream_update(&stream,(TC_bytes){bad + split,sizeof list - 1 - split});
      if (result == TC_TWIC_CCL_OK) result = TC_TWIC_CCL_stream_finish(&stream);
      munit_assert_int(result, ==, TC_TWIC_CCL_INVALID);
      munit_assert_int(TC_TWIC_CCL_stream_finish(&stream), ==, result);
    }
  }
  return MUNIT_OK;
}

static MunitResult test_limits(const MunitParameter params[], void* user)
{
  TC_TWIC_CCL_stream stream, saved;
  sink output = {0,SIZE_MAX,{{0},0,0,0}};
  (void)params; (void)user;
  for (size_t bytes = 0; bytes < sizeof list - 1; ++bytes) {
    munit_assert_int(TC_TWIC_CCL_stream_init(&stream,bytes,2,collect,&output), ==, TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_stream_update(&stream,(TC_bytes){list,sizeof list - 1}), ==, TC_TWIC_CCL_LIMIT);
    munit_assert_size(output.count, ==, 0);
    munit_assert_int(TC_TWIC_CCL_stream_finish(&stream), ==, TC_TWIC_CCL_LIMIT);
  }
  for (size_t records = 0; records < 2; ++records) {
    output.count = 0;
    munit_assert_int(TC_TWIC_CCL_stream_init(&stream,SIZE_MAX,records,collect,&output), ==, TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_stream_update(&stream,(TC_bytes){list,sizeof list - 1}), ==, TC_TWIC_CCL_LIMIT);
    munit_assert_size(output.count, ==, records);
  }
  output.count = 0; output.fail_at = 1;
  munit_assert_int(TC_TWIC_CCL_stream_init(&stream,SIZE_MAX,2,collect,&output), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_stream_update(&stream,(TC_bytes){list,sizeof list - 1}), ==, TC_TWIC_CCL_SINK_ERROR);
  munit_assert_size(output.count, ==, 1);
  munit_assert_int(TC_TWIC_CCL_stream_finish(&stream), ==, TC_TWIC_CCL_SINK_ERROR);
  saved = stream;
  munit_assert_int(TC_TWIC_CCL_stream_init(&stream,1,1,NULL,NULL), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_memory_equal(sizeof stream,&stream,&saved);
  munit_assert_int(TC_TWIC_CCL_stream_init(NULL,1,1,collect,&output), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_stream_finish(NULL), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_stream_update(NULL,(TC_bytes){NULL,0}), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_stream_init(&stream,1,1,collect,&output), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_stream_update(&stream,(TC_bytes){NULL,1}), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_stream_finish(&stream), ==, TC_TWIC_CCL_ARGUMENT);
  return MUNIT_OK;
}

typedef uint8_t packed_key[TC_TWIC_CCL_FASCN_BYTES];
typedef struct { packed_key* keys; size_t count, capacity; } packed_keys;

static TC_status collect_key(void* context, const TC_TWIC_CCL_record* record)
{
  packed_keys* keys = context;
  if (keys->count == keys->capacity) return TC_ERROR;
  memcpy(keys->keys[keys->count++],record->fascn,TC_TWIC_CCL_FASCN_BYTES);
  return TC_OK;
}

static int key_compare(const void* a, const void* b)
{ return memcmp(a,b,TC_TWIC_CCL_FASCN_BYTES); }

static TC_status packed_key_read(void* context, size_t position, TC_bytes* out)
{
  packed_keys* keys = context;
  munit_assert_size(position, <, keys->count);
  *out = (TC_bytes){keys->keys[position],TC_TWIC_CCL_FASCN_BYTES};
  return TC_OK;
}

static MunitResult test_external(const MunitParameter params[], void* user)
{
  const char* path = getenv("TC_TEST_TWIC_CCL");
  const char* checksum = getenv("TC_TEST_TWIC_CCL_MD5");
  ExampleTwicCclImport import_state;
  uint8_t expected[TC_MD5_DIGESTLEN];
  uint8_t buffer[4096];
  packed_keys keys;
  size_t length;
  (void)params; (void)user;
  if (!path) return MUNIT_SKIP;
  munit_assert_not_null(checksum);
  munit_assert_size(strlen(checksum), ==, 2 * sizeof expected);
  munit_assert_size(tc_test_decode_hex(checksum,expected,sizeof expected), ==, sizeof expected);
  FILE* file = fopen(path,"rb");
  munit_assert_not_null(file);
  munit_assert_int(fseek(file,0,SEEK_END), ==, 0);
  long bytes = ftell(file);
  enum { EXTERNAL_MAX_BYTES = 64 * 1024 * 1024, EXTERNAL_MAX_READS = 32 };
  munit_assert_long(bytes, >, 0);
  munit_assert_long(bytes, <=, EXTERNAL_MAX_BYTES);
  munit_assert_int(fseek(file,0,SEEK_SET), ==, 0);
  keys.count = 0;
  keys.capacity = (size_t)bytes / (TC_TWIC_CCL_RECORD_BYTES + 1) + 1;
  keys.keys = malloc(keys.capacity * sizeof *keys.keys);
  munit_assert_not_null(keys.keys);
  munit_assert_int(example_twic_ccl_import_init(&import_state,expected,
      (size_t)bytes,keys.capacity,collect_key,&keys), ==, TC_TWIC_CCL_OK);
  while ((length = fread(buffer,1,sizeof buffer,file)) != 0) {
    munit_assert_int(example_twic_ccl_import_update(&import_state,(TC_bytes){buffer,length}), ==, TC_TWIC_CCL_OK);
  }
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(keys.count, >, 0);
  /* Host sorting prepares the provisioned key image; the library reads it. */
  qsort(keys.keys,keys.count,sizeof *keys.keys,key_compare);
  const TC_TWIC_CCL_source source = {&keys,keys.count,packed_key_read};
  TC_TWIC_CCL_store store = {0};
  TC_TWIC_CCL_snapshot slot = {0}, *held = NULL;
  const TC_TWIC_CCL_metadata metadata = {1,1};
  munit_assert_int(example_twic_ccl_import_finish(&import_state,&source,&metadata,&slot), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_publish(&store,0,&slot), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_acquire(&store,&held), ==, TC_TWIC_CCL_OK);
  for (size_t i = 0; i < keys.count; ++i) {
    int listed = 42;
    munit_assert_int(TC_TWIC_CCL_snapshot_contains(held,
        (TC_bytes){keys.keys[i],sizeof *keys.keys},EXTERNAL_MAX_READS,&listed), ==, TC_TWIC_CCL_OK);
    munit_assert_int(listed, ==, 1);
  }
  packed_key query;
  memcpy(query,keys.keys[0],sizeof query);
  for (unsigned value = 0; value <= UINT8_MAX; ++value) {
    int listed = 42;
    query[0] = (uint8_t)value;
    int expected_listed = bsearch(query,keys.keys,keys.count,sizeof *keys.keys,key_compare) != NULL;
    munit_assert_int(TC_TWIC_CCL_snapshot_contains(held,
        (TC_bytes){query,sizeof query},EXTERNAL_MAX_READS,&listed), ==, TC_TWIC_CCL_OK);
    munit_assert_int(listed, ==, expected_listed);
  }
  munit_assert_int(TC_TWIC_CCL_store_release(held), ==, TC_TWIC_CCL_OK);
  example_twic_ccl_import_clear(&import_state);
  free(keys.keys);
  return MUNIT_OK;
}

static MunitResult test_lookup(const MunitParameter params[], void* user)
{
  uint8_t fascn[TC_TWIC_CCL_FASCN_BYTES], bad[sizeof list];
  int listed = 42;
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof fascn; ++i) fascn[i] = (uint8_t)i;
  munit_assert_int(TC_TWIC_CCL_contains((TC_bytes){list,sizeof list - 1},
      (TC_bytes){fascn,sizeof fascn},2,&listed), ==, TC_TWIC_CCL_OK);
  munit_assert_int(listed, ==, 1);
  for (size_t i = 0; i < sizeof fascn; ++i) {
    fascn[i] ^= 1;
    munit_assert_int(TC_TWIC_CCL_contains((TC_bytes){list,sizeof list - 1},
        (TC_bytes){fascn,sizeof fascn},2,&listed), ==, TC_TWIC_CCL_OK);
    munit_assert_int(listed, ==, 0);
    fascn[i] ^= 1;
  }
  listed = 42;
  memcpy(bad,list,sizeof list);
  bad[sizeof list - 3] = 'x';
  munit_assert_int(TC_TWIC_CCL_contains((TC_bytes){bad,sizeof list - 1},
      (TC_bytes){fascn,sizeof fascn},2,&listed), ==, TC_TWIC_CCL_INVALID);
  munit_assert_int(listed, ==, 42);
  munit_assert_int(TC_TWIC_CCL_contains((TC_bytes){list,sizeof list - 1},
      (TC_bytes){fascn,sizeof fascn},1,&listed), ==, TC_TWIC_CCL_LIMIT);
  munit_assert_int(listed, ==, 42);
  munit_assert_int(TC_TWIC_CCL_contains((TC_bytes){list,sizeof list - 1},
      (TC_bytes){fascn,sizeof fascn - 1},2,&listed), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(listed, ==, 42);
  return MUNIT_OK;
}

enum { INDEX_KEYS = 128 };
typedef struct {
  uint8_t keys[INDEX_KEYS][TC_TWIC_CCL_FASCN_BYTES];
  uint8_t buffer[TC_TWIC_CCL_FASCN_BYTES];
  size_t count, calls, fail_at;
  unsigned fault;
} key_source;

static TC_status source_key(void* context, size_t position, TC_bytes* out)
{
  key_source* source = context;
  munit_assert_size(position, <, source->count);
  ++source->calls;
  if (position == source->fail_at) {
    if (source->fault == 1) return TC_ERROR;
    if (source->fault == 2) { *out = (TC_bytes){NULL,TC_TWIC_CCL_FASCN_BYTES}; return TC_OK; }
    if (source->fault == 3) { *out = (TC_bytes){source->buffer,1}; return TC_OK; }
    if (source->fault == 4) return TC_OK;
  }
  memcpy(source->buffer,source->keys[position],sizeof source->buffer);
  *out = (TC_bytes){source->buffer,sizeof source->buffer};
  return TC_OK;
}

static void source_init(key_source* source)
{
  memset(source,0,sizeof *source);
  source->count = INDEX_KEYS;
  source->fail_at = SIZE_MAX;
  for (size_t i = 0; i < INDEX_KEYS; ++i)
    source->keys[i][TC_TWIC_CCL_FASCN_BYTES - 1] = (uint8_t)(2 * i);
}

static MunitResult test_index(const MunitParameter params[], void* user)
{
  key_source source;
  TC_TWIC_CCL_index index;
  uint8_t query[TC_TWIC_CCL_FASCN_BYTES] = {0};
  int listed;
  (void)params; (void)user;
  source_init(&source);
  TC_TWIC_CCL_source input = {&source,source.count,source_key};
  munit_assert_int(TC_TWIC_CCL_index_prepare(&input,source.count,&index), ==, TC_TWIC_CCL_OK);
  munit_assert_size(source.calls, ==, source.count);
  for (unsigned value = 0; value <= UINT8_MAX; ++value) {
    query[sizeof query - 1] = (uint8_t)value;
    source.calls = 0;
    listed = 42;
    munit_assert_int(TC_TWIC_CCL_index_contains(&index,(TC_bytes){query,sizeof query},8,&listed), ==, TC_TWIC_CCL_OK);
    munit_assert_int(listed, ==, !(value & 1));
    munit_assert_size(source.calls, <=, 8);
    /* A lookup may use a key borrowed from the source's previous read. */
    memcpy(source.buffer,query,sizeof query);
    munit_assert_int(TC_TWIC_CCL_index_contains(&index,
        (TC_bytes){source.buffer,sizeof source.buffer},8,&listed), ==, TC_TWIC_CCL_OK);
    munit_assert_int(listed, ==, !(value & 1));
  }
  /* Equal adjacent keys are valid; descending keys fail preparation. */
  memcpy(source.keys[1],source.keys[0],sizeof query);
  munit_assert_int(TC_TWIC_CCL_index_prepare(&input,source.count,&index), ==, TC_TWIC_CCL_OK);
  source.keys[0][sizeof query - 1] = 1;
  TC_TWIC_CCL_index saved = index;
  munit_assert_int(TC_TWIC_CCL_index_prepare(&input,source.count,&index), ==, TC_TWIC_CCL_INVALID);
  munit_assert_memory_equal(sizeof index,&index,&saved);
  return MUNIT_OK;
}

static MunitResult test_index_failures(const MunitParameter params[], void* user)
{
  key_source source;
  TC_TWIC_CCL_index index, saved;
  uint8_t query[TC_TWIC_CCL_FASCN_BYTES] = {0};
  int listed = 42;
  (void)params; (void)user;
  source_init(&source);
  TC_TWIC_CCL_source input = {&source,source.count,source_key};
  munit_assert_int(TC_TWIC_CCL_index_prepare(&input,source.count,&index), ==, TC_TWIC_CCL_OK);
  saved = index;
  for (size_t budget = 0; budget < source.count; ++budget) {
    source.calls = 0;
    munit_assert_int(TC_TWIC_CCL_index_prepare(&input,budget,&index), ==, TC_TWIC_CCL_LIMIT);
    munit_assert_size(source.calls, ==, 0);
    munit_assert_memory_equal(sizeof index,&index,&saved);
  }
  for (size_t budget = 0; budget < 8; ++budget) {
    source.calls = 0;
    munit_assert_int(TC_TWIC_CCL_index_contains(&index,
        (TC_bytes){query,sizeof query},budget,&listed), ==, TC_TWIC_CCL_LIMIT);
    munit_assert_int(listed, ==, 42);
    munit_assert_size(source.calls, ==, budget);
  }
  for (unsigned fault = 1; fault <= 4; ++fault) {
    source.fault = fault;
    source.fail_at = source.count / 2;
    TC_TWIC_CCL_result expected = fault == 1 ? TC_TWIC_CCL_SOURCE_ERROR : TC_TWIC_CCL_INVALID;
    munit_assert_int(TC_TWIC_CCL_index_prepare(&input,source.count,&index), ==, expected);
    munit_assert_memory_equal(sizeof index,&index,&saved);
    munit_assert_int(TC_TWIC_CCL_index_contains(&index,(TC_bytes){query,sizeof query},8,&listed), ==, expected);
    munit_assert_int(listed, ==, 42);
  }
  input.count = 0;
  munit_assert_int(TC_TWIC_CCL_index_prepare(&input,0,&index), ==, TC_TWIC_CCL_INVALID);
  input.read = NULL;
  munit_assert_int(TC_TWIC_CCL_index_prepare(&input,0,&index), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_index_prepare(NULL,0,&index), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_index_prepare(&input,0,NULL), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_memory_equal(sizeof index,&index,&saved);
  munit_assert_int(TC_TWIC_CCL_index_contains(NULL,(TC_bytes){query,sizeof query},8,&listed), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_index_contains(&index,(TC_bytes){NULL,sizeof query},8,&listed), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_index_contains(&index,(TC_bytes){query,1},8,&listed), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_index_contains(&index,(TC_bytes){query,sizeof query},8,NULL), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(listed, ==, 42);
  return MUNIT_OK;
}

static TC_status read_storage(void* context, size_t offset, uint8_t* out, size_t length)
{
  key_source* source = context;
  munit_assert_size(length, ==, TC_TWIC_CCL_FASCN_BYTES);
  munit_assert_size(offset % TC_TWIC_CCL_FASCN_BYTES, ==, 0);
  TC_bytes key = {0};
  if (source_key(source,offset / TC_TWIC_CCL_FASCN_BYTES,&key) != TC_OK) return TC_ERROR;
  memcpy(out,key.data,length);
  return TC_OK;
}

static MunitResult test_memory(const MunitParameter params[], void* user)
{
  uint8_t keys[3][TC_TWIC_CCL_FASCN_BYTES];
  for (size_t i = 0; i < 3; ++i) memset(keys[i],(int)i,sizeof keys[i]);
  TC_bytes image = {(const uint8_t*)keys,sizeof keys};
  TC_TWIC_CCL_index index, saved;
  munit_assert_int(TC_TWIC_CCL_index_from_memory(&image,3,&index), ==, TC_TWIC_CCL_OK);
  for (size_t i = 0; i < 3; ++i) {
    int listed = -1;
    TC_bytes borrowed;
    munit_assert_int(index.source.read(index.source.context,i,&borrowed), ==, TC_OK);
    munit_assert_ptr_equal(borrowed.data,keys[i]);
    munit_assert_int(TC_TWIC_CCL_index_contains(&index,borrowed,2,&listed), ==, TC_TWIC_CCL_OK);
    munit_assert_int(listed, ==, 1);
  }
  saved = index;
  munit_assert_int(TC_TWIC_CCL_index_from_memory(&image,2,&index), ==, TC_TWIC_CCL_LIMIT);
  munit_assert_memory_equal(sizeof index,&saved,&index);
  TC_bytes malformed = {image.data,image.length - 1};
  munit_assert_int(TC_TWIC_CCL_index_from_memory(&malformed,3,&index), ==, TC_TWIC_CCL_INVALID);
  munit_assert_memory_equal(sizeof index,&saved,&index);
  malformed = (TC_bytes){NULL,0};
  munit_assert_int(TC_TWIC_CCL_index_from_memory(&malformed,3,&index), ==, TC_TWIC_CCL_INVALID);
  malformed.length = 25;
  munit_assert_int(TC_TWIC_CCL_index_from_memory(&malformed,3,&index), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_memory_equal(sizeof index,&saved,&index);
  munit_assert_int(TC_TWIC_CCL_index_from_memory(NULL,3,&index), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_index_from_memory(&image,3,NULL), ==, TC_TWIC_CCL_ARGUMENT);
  union { TC_bytes image; TC_TWIC_CCL_index index; uint8_t bytes[75]; } alias;
  alias.image = image;
  munit_assert_int(TC_TWIC_CCL_index_from_memory(&alias.image,3,&alias.index), ==, TC_TWIC_CCL_ARGUMENT);
  malformed = (TC_bytes){alias.bytes,sizeof alias.bytes};
  munit_assert_int(TC_TWIC_CCL_index_from_memory(&malformed,3,&alias.index), ==, TC_TWIC_CCL_ARGUMENT);
  /* Reopen after changing this test image; discard the old index first. */
  memcpy(keys[1],keys[0],sizeof keys[0]);
  munit_assert_int(TC_TWIC_CCL_index_from_memory(&image,3,&index), ==, TC_TWIC_CCL_OK);
  memset(keys[0],3,sizeof keys[0]);
  munit_assert_int(TC_TWIC_CCL_index_from_memory(&image,3,&index), ==, TC_TWIC_CCL_INVALID);
  (void)params; (void)user;
  return MUNIT_OK;
}

static MunitResult test_storage(const MunitParameter params[], void* user)
{
  key_source source;
  TC_TWIC_CCL_index index, saved;
  int listed = 42;
  (void)params; (void)user;
  source_init(&source);
  ExampleTwicCclStorage storage = {&source,read_storage,sizeof source.keys,{0}};
  munit_assert_int(example_twic_ccl_open(&storage,source.count,&index), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_index_contains(&index,
      (TC_bytes){source.keys[0],sizeof source.keys[0]},8,&listed), ==, TC_TWIC_CCL_OK);
  munit_assert_int(listed, ==, 1);
  saved = index;
  --storage.length;
  munit_assert_int(example_twic_ccl_open(&storage,source.count,&index), ==, TC_TWIC_CCL_INVALID);
  munit_assert_memory_equal(sizeof index,&index,&saved);
  ++storage.length;
  source.fault = 1; source.fail_at = 0;
  munit_assert_int(example_twic_ccl_open(&storage,source.count,&index), ==, TC_TWIC_CCL_SOURCE_ERROR);
  munit_assert_memory_equal(sizeof index,&index,&saved);
  storage.read_at = NULL;
  munit_assert_int(example_twic_ccl_open(&storage,source.count,&index), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(example_twic_ccl_open(NULL,source.count,&index), ==, TC_TWIC_CCL_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult test_freshness(const MunitParameter params[], void* user)
{
  TC_TWIC_CCL_metadata metadata = {100,110};
  TC_TWIC_CCL_freshness_policy policy = {120,20,100};
  (void)params; (void)user;
  munit_assert_int(TC_TWIC_CCL_check_freshness(&metadata,&policy), ==, TC_TWIC_CCL_OK);
  --policy.max_age;
  munit_assert_int(TC_TWIC_CCL_check_freshness(&metadata,&policy), ==, TC_TWIC_CCL_STALE);
  policy.max_age = 20; ++policy.minimum_publication;
  munit_assert_int(TC_TWIC_CCL_check_freshness(&metadata,&policy), ==, TC_TWIC_CCL_STALE);
  policy.minimum_publication = 100;
  /* Downloading an old publication again leaves its age unchanged. */
  metadata.received_at = policy.now; ++policy.now;
  munit_assert_int(TC_TWIC_CCL_check_freshness(&metadata,&policy), ==, TC_TWIC_CCL_STALE);
  metadata.received_at = policy.now + 1;
  munit_assert_int(TC_TWIC_CCL_check_freshness(&metadata,&policy), ==, TC_TWIC_CCL_INVALID);
  metadata.received_at = metadata.published_at - 1;
  munit_assert_int(TC_TWIC_CCL_check_freshness(&metadata,&policy), ==, TC_TWIC_CCL_INVALID);
  metadata.published_at = metadata.received_at = policy.now = UINT64_MAX;
  policy.minimum_publication = UINT64_MAX; policy.max_age = 0;
  munit_assert_int(TC_TWIC_CCL_check_freshness(&metadata,&policy), ==, TC_TWIC_CCL_OK);
  metadata.published_at = metadata.received_at = 0;
  policy.minimum_publication = 0; policy.max_age = UINT64_MAX;
  munit_assert_int(TC_TWIC_CCL_check_freshness(&metadata,&policy), ==, TC_TWIC_CCL_OK);
  --policy.max_age;
  munit_assert_int(TC_TWIC_CCL_check_freshness(&metadata,&policy), ==, TC_TWIC_CCL_STALE);
  munit_assert_int(TC_TWIC_CCL_check_freshness(NULL,&policy), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_check_freshness(&metadata,NULL), ==, TC_TWIC_CCL_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult test_snapshots(const MunitParameter params[], void* user)
{
  key_source old_keys, new_keys;
  TC_TWIC_CCL_index old_index, new_index;
  TC_TWIC_CCL_store store = {0};
  TC_TWIC_CCL_snapshot slots[2] = {0}, *first = NULL, *second = NULL, *current = NULL;
  TC_TWIC_CCL_metadata old_metadata = {100,101}, new_metadata = {110,111};
  TC_TWIC_CCL_freshness_policy policy = {120,20,0};
  uint8_t query[TC_TWIC_CCL_FASCN_BYTES] = {0};
  int listed = 42;
  (void)params; (void)user;
  source_init(&old_keys); source_init(&new_keys);
  new_keys.keys[0][TC_TWIC_CCL_FASCN_BYTES - 1] = 1;
  TC_TWIC_CCL_source old_source = {&old_keys,1,source_key}, new_source = {&new_keys,1,source_key};
  munit_assert_int(TC_TWIC_CCL_index_prepare(&old_source,1,&old_index), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_index_prepare(&new_source,1,&new_index), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_acquire(&store,&first), ==, TC_TWIC_CCL_UNAVAILABLE);
  munit_assert_null(first);
  munit_assert_int(TC_TWIC_CCL_store_prepare(&slots[0],&old_index,&old_metadata), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_publish(&store,0,&slots[0]), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_acquire(&store,&first), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_acquire(&store,&second), ==, TC_TWIC_CCL_OK);
  munit_assert_ptr_equal(first,second);
  munit_assert_int(TC_TWIC_CCL_snapshot_contains(first,
      (TC_bytes){query,sizeof query},1,&listed), ==, TC_TWIC_CCL_OK);
  munit_assert_int(listed, ==, 1);
  munit_assert_int(TC_TWIC_CCL_store_prepare(&slots[1],&new_index,&new_metadata), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_publish(&store,1,&slots[1]), ==, TC_TWIC_CCL_OK);
  munit_assert_int(first->state, ==, TC_SNAPSHOT_RETIRED);
  munit_assert_int(TC_TWIC_CCL_store_acquire(&store,&current), ==, TC_TWIC_CCL_OK);
  munit_assert_ptr_equal(current,&slots[1]);
  listed = 42;
  munit_assert_int(TC_TWIC_CCL_check_freshness(&first->metadata,&policy), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_snapshot_contains(first,
      (TC_bytes){query,sizeof query},1,&listed), ==, TC_TWIC_CCL_STALE);
  munit_assert_int(listed, ==, 42);
  munit_assert_int(TC_TWIC_CCL_snapshot_contains(current,
      (TC_bytes){query,sizeof query},1,&listed), ==, TC_TWIC_CCL_OK);
  munit_assert_int(listed, ==, 0);
  ++policy.now; listed = 42;
  munit_assert_int(TC_TWIC_CCL_snapshot_contains(first,
      (TC_bytes){query,sizeof query},1,&listed), ==, TC_TWIC_CCL_STALE);
  munit_assert_int(listed, ==, 42);
  munit_assert_int(TC_TWIC_CCL_store_release(first), ==, TC_TWIC_CCL_OK);
  munit_assert_int(slots[0].state, ==, TC_SNAPSHOT_RETIRED);
  munit_assert_int(TC_TWIC_CCL_store_release(second), ==, TC_TWIC_CCL_OK);
  munit_assert_int(slots[0].state, ==, TC_SNAPSHOT_FREE);
  munit_assert(!slots[0].index.source.read);
  munit_assert_int(TC_TWIC_CCL_store_release(current), ==, TC_TWIC_CCL_OK);
  munit_assert_int(slots[1].state, ==, TC_SNAPSHOT_CURRENT);
  /* Publishing a replacement preserves the current publication floor. */
  munit_assert_int(TC_TWIC_CCL_store_prepare(&slots[0],&old_index,&old_metadata), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_publish(&store,2,&slots[0]), ==, TC_TWIC_CCL_STALE);
  munit_assert_ptr_equal(store.current,&slots[1]);
  munit_assert_int(TC_TWIC_CCL_store_discard(&slots[0]), ==, TC_TWIC_CCL_OK);
  munit_assert_int(slots[0].state, ==, TC_SNAPSHOT_FREE);
  new_metadata.published_at = new_metadata.received_at = policy.now;
  munit_assert_int(TC_TWIC_CCL_store_prepare(&slots[0],&new_index,&new_metadata), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_publish(&store,2,&slots[0]), ==, TC_TWIC_CCL_OK);
  munit_assert_int(slots[1].state, ==, TC_SNAPSHOT_FREE);
  munit_assert(!slots[1].index.source.read);
  return MUNIT_OK;
}

static MunitResult test_snapshot_failures(const MunitParameter params[], void* user)
{
  key_source keys;
  TC_TWIC_CCL_index index;
  TC_TWIC_CCL_store store = {0}, saved_store;
  TC_TWIC_CCL_snapshot slot = {0}, saved, *reader = NULL;
  TC_TWIC_CCL_metadata metadata = {100,101};
  TC_TWIC_CCL_freshness_policy policy = {120,20,0};
  int listed = 42;
  (void)params; (void)user;
  source_init(&keys);
  TC_TWIC_CCL_source source = {&keys,1,source_key};
  munit_assert_int(TC_TWIC_CCL_index_prepare(&source,1,&index), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_prepare(&slot,&index,&metadata), ==, TC_TWIC_CCL_OK);
  saved = slot;
  munit_assert_int(TC_TWIC_CCL_store_prepare(&slot,&index,&metadata), ==, TC_TWIC_CCL_LIMIT);
  munit_assert_int(TC_TWIC_CCL_store_release(&slot), ==, TC_TWIC_CCL_ARGUMENT);
  saved_store = store;
  munit_assert_int(TC_TWIC_CCL_store_publish(&store,1,&slot), ==, TC_TWIC_CCL_INVALID);
  munit_assert_memory_equal(sizeof store,&store,&saved_store);
  ++policy.now;
  munit_assert_int(TC_TWIC_CCL_check_freshness(&slot.metadata,&policy), ==, TC_TWIC_CCL_STALE);
  munit_assert_memory_equal(sizeof slot,&slot,&saved);
  --policy.now; store.revision = SIZE_MAX;
  munit_assert_int(TC_TWIC_CCL_store_publish(&store,SIZE_MAX,&slot), ==, TC_TWIC_CCL_LIMIT);
  munit_assert_memory_equal(sizeof slot,&slot,&saved);
  store.revision = 0;
  munit_assert_int(TC_TWIC_CCL_store_publish(&store,0,&slot), ==, TC_TWIC_CCL_OK);
  ++policy.now;
  munit_assert_int(TC_TWIC_CCL_store_acquire(&store,&reader), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_check_freshness(&reader->metadata,&policy), ==, TC_TWIC_CCL_STALE);
  munit_assert_int(TC_TWIC_CCL_store_release(reader), ==, TC_TWIC_CCL_OK);
  reader = NULL;
  munit_assert_null(reader);
  munit_assert_size(slot.readers, ==, 0);
  --policy.now; slot.readers = SIZE_MAX;
  munit_assert_int(TC_TWIC_CCL_store_acquire(&store,&reader), ==, TC_TWIC_CCL_LIMIT);
  munit_assert_null(reader);
  munit_assert_size(slot.readers, ==, SIZE_MAX);
  slot.readers = 0;
  munit_assert_int(TC_TWIC_CCL_snapshot_contains(&slot,
      (TC_bytes){keys.keys[0],TC_TWIC_CCL_FASCN_BYTES},1,&listed), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(listed, ==, 42);
  munit_assert_int(TC_TWIC_CCL_store_acquire(&store,&reader), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_discard(&slot), ==, TC_TWIC_CCL_ARGUMENT);
  saved = slot;
  munit_assert_int(TC_TWIC_CCL_store_acquire(&store,&store.current), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_snapshot_contains(&slot,
      (TC_bytes){keys.keys[0],TC_TWIC_CCL_FASCN_BYTES},1,(int*)&slot.state), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_memory_equal(sizeof slot,&slot,&saved);
  keys.fail_at = 0; keys.fault = 1;
  munit_assert_int(TC_TWIC_CCL_snapshot_contains(&slot,
      (TC_bytes){keys.keys[0],TC_TWIC_CCL_FASCN_BYTES},1,&listed), ==, TC_TWIC_CCL_SOURCE_ERROR);
  munit_assert_int(listed, ==, 42);
  munit_assert_int(TC_TWIC_CCL_store_release(reader), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_release(reader), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_store_prepare(NULL,&index,&metadata), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_store_discard(NULL), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_store_release(NULL), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_store_publish(NULL,0,&slot), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(TC_TWIC_CCL_store_acquire(NULL,&reader), ==, TC_TWIC_CCL_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult test_check_example(const MunitParameter params[], void* user)
{
  key_source keys;
  TC_TWIC_CCL_index index;
  TC_TWIC_CCL_store store = {0};
  TC_TWIC_CCL_snapshot slot = {0};
  TC_TWIC_CCL_metadata metadata = {100,101};
  TC_TWIC_CCL_freshness_policy policy = {120,30,0};
  ExampleTwicCclResult result = {42,43}, saved = result;
  uint8_t query[TC_TWIC_CCL_FASCN_BYTES] = {0};
  TC_bytes fascn = {query,sizeof query};
  (void)params; (void)user;
  source_init(&keys);
  TC_TWIC_CCL_source source = {&keys,1,source_key};
  munit_assert_int(example_check_twic_cancellation(&store,&policy,20,fascn,1,&result), ==, TC_TWIC_CCL_UNAVAILABLE);
  munit_assert_memory_equal(sizeof result,&result,&saved);
  munit_assert_int(TC_TWIC_CCL_index_prepare(&source,1,&index), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_prepare(&slot,&index,&metadata), ==, TC_TWIC_CCL_OK);
  munit_assert_int(TC_TWIC_CCL_store_publish(&store,0,&slot), ==, TC_TWIC_CCL_OK);
  munit_assert_int(example_check_twic_cancellation(&store,&policy,20,fascn,1,&result), ==, TC_TWIC_CCL_OK);
  munit_assert_int(result.listed, ==, 1);
  munit_assert_int(result.age_warning, ==, 0);
  munit_assert_size(slot.readers, ==, 0);
  ++policy.now; query[0] = 1;
  munit_assert_int(example_check_twic_cancellation(&store,&policy,20,fascn,1,&result), ==, TC_TWIC_CCL_OK);
  munit_assert_int(result.listed, ==, 0);
  munit_assert_int(result.age_warning, ==, 1);
  munit_assert_size(slot.readers, ==, 0);
  munit_assert_int(example_check_twic_cancellation(&store,&policy,UINT64_MAX,fascn,1,&result), ==, TC_TWIC_CCL_OK);
  munit_assert_int(result.age_warning, ==, 0);
  saved = result;
  policy.now = 131;
  munit_assert_int(example_check_twic_cancellation(&store,&policy,20,fascn,1,&result), ==, TC_TWIC_CCL_STALE);
  munit_assert_memory_equal(sizeof result,&result,&saved);
  munit_assert_size(slot.readers, ==, 0);
  policy.now = 120;
  munit_assert_int(example_check_twic_cancellation(&store,&policy,20,fascn,0,&result), ==, TC_TWIC_CCL_LIMIT);
  munit_assert_memory_equal(sizeof result,&result,&saved);
  munit_assert_size(slot.readers, ==, 0);
  keys.fault = 1; keys.fail_at = 0;
  munit_assert_int(example_check_twic_cancellation(&store,&policy,20,fascn,1,&result), ==, TC_TWIC_CCL_SOURCE_ERROR);
  munit_assert_memory_equal(sizeof result,&result,&saved);
  munit_assert_size(slot.readers, ==, 0);
  munit_assert_int(example_check_twic_cancellation(&store,&policy,20,(TC_bytes){NULL,1},1,&result), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_size(slot.readers, ==, 0);
  munit_assert_int(example_check_twic_cancellation(&store,&policy,20,fascn,1,NULL), ==, TC_TWIC_CCL_ARGUMENT);
  munit_assert_int(example_check_twic_cancellation(&store,NULL,20,fascn,1,&result), ==, TC_TWIC_CCL_ARGUMENT);
  return MUNIT_OK;
}

typedef struct { packed_keys keys; size_t reads; int fail_read; } import_keys;
static TC_status import_key_read(void* context, size_t position, TC_bytes* out)
{
  import_keys* input = context;
  ++input->reads;
  if (input->fail_read) return TC_ERROR;
  return packed_key_read(&input->keys,position,out);
}

static MunitResult test_import(const MunitParameter params[], void* user)
{
  enum { IMPORT_OK, IMPORT_CHECKSUM, IMPORT_ROW_TRUNCATION, IMPORT_BYTE_TRUNCATION,
    IMPORT_SYNTAX, IMPORT_CAPACITY, IMPORT_COUNT, IMPORT_READ, IMPORT_LIMIT, IMPORT_CASES };
  uint8_t expected[TC_MD5_DIGESTLEN];
  (void)params; (void)user;
  munit_assert_int(TC_MD5_digest(list,sizeof list - 1,expected), ==, TC_OK);
  for (unsigned fault = 0; fault < IMPORT_CASES; ++fault) {
    packed_key staged_keys[2], old_keys[1] = {{0}};
    import_keys staged = {{staged_keys,0,2},0,0}, old = {{old_keys,1,1},0,0};
    TC_TWIC_CCL_source old_source = {&old,1,import_key_read};
    TC_TWIC_CCL_store store = {0}, saved_store;
    TC_TWIC_CCL_snapshot slots[2] = {0}, saved_slot;
    TC_TWIC_CCL_index old_index;
    TC_TWIC_CCL_metadata old_metadata = {90,91}, metadata = {100,101};
    ExampleTwicCclImport state;
    uint8_t input[sizeof list], checksum[sizeof expected];
    size_t length = sizeof list - 1;
    memcpy(input,list,sizeof list); memcpy(checksum,expected,sizeof checksum);
    munit_assert_int(TC_TWIC_CCL_index_prepare(&old_source,1,&old_index), ==, TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_store_prepare(&slots[0],&old_index,&old_metadata), ==, TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_store_publish(&store,0,&slots[0]), ==, TC_TWIC_CCL_OK);
    saved_store = store; saved_slot = slots[1];
    if (fault == IMPORT_CHECKSUM) checksum[0] ^= 1;
    if (fault == IMPORT_ROW_TRUNCATION) length = TC_TWIC_CCL_RECORD_BYTES + 2;
    if (fault == IMPORT_BYTE_TRUNCATION) --length;
    if (fault == IMPORT_SYNTAX) input[0] = 'Z';
    if (fault == IMPORT_CAPACITY) staged.keys.capacity = 1;
    if (fault == IMPORT_READ) staged.fail_read = 1;
    munit_assert_int(example_twic_ccl_import_init(&state,checksum,
        fault == IMPORT_LIMIT ? 0 : sizeof input,2,collect_key,&staged.keys), ==, TC_TWIC_CCL_OK);
    TC_TWIC_CCL_result result = TC_TWIC_CCL_OK;
    for (size_t offset = 0; offset < length && result == TC_TWIC_CCL_OK; ++offset)
      result = example_twic_ccl_import_update(&state,(TC_bytes){input + offset,1});
    TC_TWIC_CCL_source source = {&staged,staged.keys.count,import_key_read};
    if (fault == IMPORT_COUNT) --source.count;
    if (result == TC_TWIC_CCL_OK) result = example_twic_ccl_import_finish(&state,&source,&metadata,&slots[1]);
    if (fault == IMPORT_OK) {
      munit_assert_int(result, ==, TC_TWIC_CCL_OK);
      munit_assert_int(slots[1].state, ==, TC_SNAPSHOT_PREPARED);
      munit_assert_memory_equal(sizeof store,&store,&saved_store);
      munit_assert_int(TC_TWIC_CCL_store_publish(&store,1,&slots[1]), ==, TC_TWIC_CCL_OK);
      munit_assert_ptr_equal(store.current,&slots[1]);
      munit_assert_int(example_twic_ccl_import_finish(&state,&source,&metadata,&slots[1]), ==, TC_TWIC_CCL_ARGUMENT);
    } else {
      TC_TWIC_CCL_result wanted = TC_TWIC_CCL_INVALID;
      if (fault == IMPORT_CHECKSUM || fault == IMPORT_ROW_TRUNCATION) wanted = TC_TWIC_CCL_CHECKSUM_MISMATCH;
      if (fault == IMPORT_CAPACITY) wanted = TC_TWIC_CCL_SINK_ERROR;
      if (fault == IMPORT_READ) wanted = TC_TWIC_CCL_SOURCE_ERROR;
      if (fault == IMPORT_LIMIT) wanted = TC_TWIC_CCL_LIMIT;
      munit_assert_int(result, ==, wanted);
      munit_assert_int(example_twic_ccl_import_finish(&state,&source,&metadata,&slots[1]), ==, wanted);
      munit_assert_memory_equal(sizeof slots[1],&slots[1],&saved_slot);
      munit_assert_int(TC_TWIC_CCL_store_publish(&store,1,&slots[1]), ==, TC_TWIC_CCL_ARGUMENT);
      munit_assert_memory_equal(sizeof store,&store,&saved_store);
      if (fault != IMPORT_READ) munit_assert_size(staged.reads, ==, 0);
    }
    munit_assert(tc_test_all_zero(&state.checksum,sizeof state.checksum));
    example_twic_ccl_import_clear(&state);
    munit_assert_int(example_twic_ccl_import_update(&state,(TC_bytes){NULL,0}), ==, TC_TWIC_CCL_ARGUMENT);
  }
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/record",test_record,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/chunks",test_chunks,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/failures",test_failures,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/limits",test_limits,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/lookup",test_lookup,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/index",test_index,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/index-failures",test_index_failures,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/storage",test_storage,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/memory",test_memory,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/freshness",test_freshness,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/snapshots",test_snapshots,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/snapshot-failures",test_snapshot_failures,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/check-example",test_check_example,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/import",test_import,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/external",test_external,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
};
static const MunitSuite suite = {"/twic/ccl",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{ return munit_suite_main(&suite,NULL,argc,argv); }
