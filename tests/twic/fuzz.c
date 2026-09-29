/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* libFuzzer harness for TWIC text and barcode inputs: the TSA canceled card
 * list CSV, AAMVA barcode payloads and the TWIC privacy key container. */
#include <stdlib.h>
#include <string.h>
#include <tiny_crypto/aamva.h>
#include <tiny_crypto/twic_ccl.h>
#include <tiny_crypto/twic_tpk.h>

enum { MAX_INPUT = 32768, MAX_RECORDS = MAX_INPUT / 2 };

static void check_borrowed_span(TC_bytes input, TC_bytes span)
{
  uintptr_t start = (uintptr_t)input.data, borrowed = (uintptr_t)span.data;
  if (!span.data || borrowed < start || borrowed - start > input.length ||
      span.length > input.length - (size_t)(borrowed - start))
    abort();
}

static int record_equal(const TC_TWIC_CCL_record* left, const TC_TWIC_CCL_record* right)
{
  return !memcmp(left->fascn, right->fascn, sizeof left->fascn) && left->year == right->year &&
         left->month == right->month && left->day == right->day;
}

static void fuzz_ccl_record(TC_bytes input)
{
  TC_TWIC_CCL_record record, saved;
  memset(&saved, 0xa5, sizeof saved);
  record = saved;
  const TC_TWIC_CCL_result result = TC_TWIC_CCL_read(input, &record);
  if (result != TC_TWIC_CCL_OK) {
    if (result != TC_TWIC_CCL_INVALID || !record_equal(&record, &saved))
      abort();
    return;
  }
  if (input.length != TC_TWIC_CCL_RECORD_BYTES || record.year < 1 || record.year > 9999 ||
      record.month < 1 || record.month > 12 || record.day < 1 || record.day > 31)
    abort();
}

/* Order-sensitive digest of the records one stream delivered. */
typedef struct {
  size_t count;
  uint64_t hash;
  uint8_t first[TC_TWIC_CCL_FASCN_BYTES];
} ccl_digest;

static TC_status digest_record(void* context, const TC_TWIC_CCL_record* record)
{
  ccl_digest* digest = context;
  if (!digest->count)
    memcpy(digest->first, record->fascn, sizeof digest->first);
  for (size_t i = 0; i < sizeof record->fascn; ++i)
    digest->hash = digest->hash * UINT64_C(1099511628211) ^ record->fascn[i];
  digest->hash = digest->hash * UINT64_C(1099511628211) ^
                 ((uint64_t)record->year << 16 | (uint64_t)record->month << 8 | record->day);
  ++digest->count;
  return TC_OK;
}

static TC_TWIC_CCL_result stream_chunks(TC_bytes input, size_t chunk_bytes, size_t max_records,
                                        ccl_digest* digest)
{
  TC_TWIC_CCL_stream stream;
  TC_TWIC_CCL_result result =
      TC_TWIC_CCL_stream_init(&stream, input.length, max_records, digest_record, digest);
  if (result != TC_TWIC_CCL_OK)
    abort();
  for (size_t offset = 0; result == TC_TWIC_CCL_OK && offset < input.length;) {
    const size_t left = input.length - offset;
    const size_t length = left < chunk_bytes ? left : chunk_bytes;
    result = TC_TWIC_CCL_stream_update(&stream, (TC_bytes){input.data + offset, length});
    offset += length;
  }
  if (result == TC_TWIC_CCL_OK)
    result = TC_TWIC_CCL_stream_finish(&stream);
  /* Errors persist until the next init. */
  if (result != TC_TWIC_CCL_OK &&
      (TC_TWIC_CCL_stream_update(&stream, (TC_bytes){NULL, 0}) != result ||
       TC_TWIC_CCL_stream_finish(&stream) != result))
    abort();
  if (digest->count != stream.records || digest->count > max_records)
    abort();
  return result;
}

static void fuzz_ccl_stream(TC_bytes input)
{
  ccl_digest whole = {0, 0, {0}}, split = {0, 0, {0}}, limited = {0, 0, {0}};
  const size_t chunk = input.length ? (size_t)input.data[0] % 97 + 1 : 1;
  const TC_TWIC_CCL_result result =
      stream_chunks(input, input.length ? input.length : 1, MAX_RECORDS, &whole);
  /* Chunk boundaries never change the result or the delivered records. */
  if (stream_chunks(input, chunk, MAX_RECORDS, &split) != result || split.count != whole.count ||
      split.hash != whole.hash)
    abort();
  if (result == TC_TWIC_CCL_OK) {
    int listed = -1;
    if (!whole.count ||
        TC_TWIC_CCL_contains(input, (TC_bytes){whole.first, sizeof whole.first}, whole.count,
                             &listed) != TC_TWIC_CCL_OK ||
        listed != 1)
      abort();
    listed = -1;
    if (TC_TWIC_CCL_contains(input, (TC_bytes){whole.first, sizeof whole.first}, whole.count - 1,
                             &listed) != TC_TWIC_CCL_LIMIT ||
        listed != -1)
      abort();
    if (stream_chunks(input, chunk, whole.count - 1, &limited) != TC_TWIC_CCL_LIMIT)
      abort();
  } else if (result == TC_TWIC_CCL_ARGUMENT || result == TC_TWIC_CCL_SINK_ERROR)
    abort();
}

static void fuzz_ccl_index(TC_bytes input)
{
  const TC_bytes image = {input.data, input.length - input.length % TC_TWIC_CCL_FASCN_BYTES};
  const size_t count = image.length / TC_TWIC_CCL_FASCN_BYTES;
  TC_TWIC_CCL_index index, saved;
  memset(&saved, 0xa5, sizeof saved);
  memcpy(&index, &saved, sizeof index);
  const TC_TWIC_CCL_result result = TC_TWIC_CCL_index_from_memory(&image, MAX_RECORDS, &index);
  if (result != TC_TWIC_CCL_OK) {
    if (memcmp(&index, &saved, sizeof index))
      abort();
    return;
  }
  if (!count)
    abort();
  /* A binary search over count keys reads at most 64 of them. */
  for (size_t position = 0; position < count; ++position) {
    const TC_bytes key = {image.data + position * TC_TWIC_CCL_FASCN_BYTES, TC_TWIC_CCL_FASCN_BYTES};
    int listed = -1;
    if (position && memcmp(key.data - TC_TWIC_CCL_FASCN_BYTES, key.data, key.length) > 0)
      abort();
    if (TC_TWIC_CCL_index_contains(&index, key, 64, &listed) != TC_TWIC_CCL_OK || listed != 1)
      abort();
  }
  {
    uint8_t query[TC_TWIC_CCL_FASCN_BYTES];
    int listed = -1, present = 0;
    memcpy(query, input.data + input.length - sizeof query, sizeof query);
    query[0] ^= input.data[0];
    for (size_t position = 0; position < count; ++position)
      present |= !memcmp(image.data + position * sizeof query, query, sizeof query);
    if (TC_TWIC_CCL_index_contains(&index, (TC_bytes){query, sizeof query}, 64, &listed) !=
            TC_TWIC_CCL_OK ||
        listed != present)
      abort();
    listed = -1;
    if (TC_TWIC_CCL_index_contains(&index, (TC_bytes){query, sizeof query}, 0, &listed) !=
            TC_TWIC_CCL_LIMIT ||
        listed != -1)
      abort();
  }
}

static int uppercase(uint8_t c)
{
  return c >= 'A' && c <= 'Z';
}

static void fuzz_aamva_fields(TC_bytes subfile, const char identifier[3])
{
  const TC_bytes saved = {subfile.data, 1};
  TC_bytes value = saved;
  const TC_TLV_result result = TC_AAMVA_field_find(subfile, identifier, &value);
  if (result == TC_TLV_OK) {
    if (value.length)
      check_borrowed_span(subfile, value);
    for (size_t i = 0; i < value.length; ++i)
      if (value.data[i] < 0x20 || value.data[i] > 0x7e)
        abort();
  } else if (value.data != saved.data || value.length != saved.length)
    abort();
}

static void fuzz_aamva(TC_bytes input)
{
  char designators[3][2] = {{'Z', 'T'}, {'D', 'L'}, {'I', 'D'}};
  char identifier[3] = {'Z', 'T', 'A'};
  if (input.length >= 5 && uppercase(input.data[0]) && uppercase(input.data[1]))
    memcpy(designators[2], input.data, 2);
  if (input.length >= 5 && uppercase(input.data[2]) && uppercase(input.data[3]) &&
      uppercase(input.data[4]))
    memcpy(identifier, input.data + 2, 3);
  for (size_t i = 0; i < sizeof designators / sizeof *designators; ++i) {
    const TC_bytes saved = {input.data, 1};
    TC_bytes subfile = saved;
    const TC_TLV_result result = TC_AAMVA_subfile_find(input, designators[i], &subfile);
    if (result != TC_TLV_OK) {
      if (subfile.data != saved.data || subfile.length != saved.length)
        abort();
      continue;
    }
    check_borrowed_span(input, subfile);
    if (subfile.length < 3 || memcmp(subfile.data, designators[i], 2) ||
        subfile.data[subfile.length - 1] != '\r')
      abort();
    fuzz_aamva_fields(subfile, identifier);
    fuzz_aamva_fields(subfile, "DAA");
  }
  /* Field lookup also accepts any text a caller already isolated. */
  fuzz_aamva_fields(input, identifier);
}

static void fuzz_tpk(TC_bytes input)
{
  static const TC_TWIC_tpk_encoding encodings[] = {TC_TWIC_TPK_CARD, TC_TWIC_TPK_BARCODE_HEX,
                                                   TC_TWIC_TPK_CONTENTS};
  for (size_t i = 0; i < sizeof encodings / sizeof *encodings; ++i) {
    TC_TWIC_tpk key, saved;
    memset(&saved, 0xa5, sizeof saved);
    key = saved;
    if (TC_TWIC_tpk_read(input, encodings[i], &key) != TC_TLV_OK &&
        memcmp(key.key, saved.key, sizeof key.key))
      abort();
  }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t length);
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t length)
{
  const TC_bytes input = {data, length};
  if (!length || length > MAX_INPUT)
    return 0;
  fuzz_ccl_record(input);
  fuzz_ccl_stream(input);
  if (length >= TC_TWIC_CCL_FASCN_BYTES)
    fuzz_ccl_index(input);
  fuzz_aamva(input);
  fuzz_tpk(input);
  return 0;
}
