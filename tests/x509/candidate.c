/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/pki_candidate_internal.h"
#include "munit.h"
#include "test_io.h"
#include <string.h>

enum { ACCEPT, RETRY, EMPTY, SOURCE_ERROR, SKIP, BAD_MATCH, FILTER_END,
  SOURCE_INCREASE, FILTER_INCREASE, ATTEMPT_INCREASE, ATTEMPT_END, CASE_COUNT };
typedef struct { unsigned scenario, reads, attempts; size_t* work; } fixture;

static TC_TLV_result next_candidate(void* context, const tc_pki_tree_workspace* tree,
    TC_X509_workspace* parser, TC_X509_certificate* out)
{
  fixture* state = context;
  (void)parser;
  ++state->reads;
  if (state->scenario == EMPTY) return TC_TLV_END;
  if (state->scenario == SOURCE_ERROR) return TC_TLV_INVALID;
  if (state->scenario == SOURCE_INCREASE) ++*tree->work;
  memset(out,0,sizeof *out);
  return TC_TLV_OK;
}

static TC_TLV_result filter_candidate(const void* context, const TC_X509_certificate* candidate,
    const TC_TLV_limits* limits, const tc_pki_tree_workspace* tree, int* matched)
{
  const fixture* state = context;
  (void)candidate; (void)limits;
  if (state->scenario == FILTER_END) return TC_TLV_END;
  if (state->scenario == FILTER_INCREASE) ++*tree->work;
  *matched = state->scenario == BAD_MATCH ? 2 : state->scenario != SKIP;
  return TC_TLV_OK;
}

static TC_TLV_result attempt_candidate(const void* context,
    const TC_X509_certificate* candidate, TC_X509_search_result* out)
{
  fixture* state = (fixture*)context;
  (void)candidate;
  ++state->attempts;
  if (state->scenario == ATTEMPT_END) return TC_TLV_END;
  if (state->scenario == ATTEMPT_INCREASE) ++*state->work;
  if (state->scenario == RETRY && state->attempts == 1) return TC_TLV_INVALID;
  memset(out,0,sizeof *out);
  out->anchor_index = 7;
  return TC_TLV_OK;
}

static MunitResult callbacks(const MunitParameter params[], void* user)
{
  const TC_TLV_result expected[] = {TC_TLV_OK,TC_TLV_OK,TC_TLV_INVALID,TC_TLV_INVALID,
    TC_TLV_LIMIT,TC_TLV_ARGUMENT,TC_TLV_ARGUMENT,TC_TLV_ARGUMENT,TC_TLV_ARGUMENT,
    TC_TLV_ARGUMENT,TC_TLV_END};
  const TC_TLV_limits limits = {0};
  const TC_X509_path_workspace validation = {0};
  (void)params; (void)user;
  for (unsigned scenario = 0; scenario < CASE_COUNT; ++scenario) {
    size_t work = 3;
    fixture state = {scenario,0,0,&work};
    const tc_pki_tree_workspace tree = {NULL,0,&work};
    TC_X509_search_result out, saved;
    int source_failed = 0;
    memset(&out,0xa5,sizeof out); memcpy(&saved,&out,sizeof out);
    munit_assert_int(tc_pki_certificate_search(&state,next_candidate,filter_candidate,&state,
        &limits,&tree,&validation,attempt_candidate,&state,&out,&source_failed), ==, expected[scenario]);
    munit_assert_int(source_failed, ==, scenario == SOURCE_ERROR || scenario == SOURCE_INCREASE);
    if (expected[scenario] == TC_TLV_OK) {
      munit_assert_size(out.anchor_index, ==, 7);
      munit_assert_size(out.validation.work_used, ==, state.reads);
      munit_assert_size(work, ==, 3 - state.reads);
    } else munit_assert_memory_equal(sizeof out,&out,&saved);
    if (scenario == SKIP) {
      munit_assert_uint(state.reads, ==, 4);
      munit_assert_uint(state.attempts, ==, 0);
      munit_assert_size(work, ==, 0);
    }
    if (scenario == SOURCE_INCREASE || scenario == FILTER_INCREASE || scenario == ATTEMPT_INCREASE)
      munit_assert_size(work, ==, 0);
  }
  return MUNIT_OK;
}

typedef struct { TC_bytes bytes; TC_TLV_result result; size_t calls; } record_fixture;

static TC_TLV_result read_record(void* context, size_t index, size_t* work, TC_bytes* out)
{
  record_fixture* record = context;
  (void)index; (void)work;
  ++record->calls;
  *out = record->bytes;
  return record->result;
}

static MunitResult store_limits(const MunitParameter params[], void* user)
{
  enum { EMPTY_STORE, NO_RECORDS, NO_BYTES, MALFORMED, READ_ERROR, BAD_INDEX,
    NULL_BYTES, NO_WORK, PARSE_WORK, OVERLAP, STORE_CASE_COUNT };
  const TC_TLV_result expected[] = {TC_TLV_END,TC_TLV_LIMIT,TC_TLV_LIMIT,TC_TLV_INVALID,
    TC_TLV_ARGUMENT,TC_TLV_ARGUMENT,TC_TLV_ARGUMENT,TC_TLV_LIMIT,TC_TLV_LIMIT,TC_TLV_ARGUMENT};
  static const uint8_t invalid[] = {0x30,0};
  TC_TLV_frame frames[8];
  TC_bytes oids[8];
  TC_X509_workspace parser = {frames,8,oids,8};
  (void)params; (void)user;
  for (unsigned scenario = 0; scenario < STORE_CASE_COUNT; ++scenario) {
    size_t work = scenario == NO_WORK ? 0 : scenario == PARSE_WORK ? 1 : 4096;
    record_fixture record = {{invalid,sizeof invalid},TC_TLV_OK,0};
    TC_X509_certificate out, saved;
    memset(&out,0xa5,sizeof out); memcpy(&saved,&out,sizeof out);
    const TC_bytes writes[] = {{(const uint8_t*)&out,sizeof out}};
    const TC_X509_store_source original = {&record,1,0,read_record,NULL};
    const tc_pki_source_guard guard = {&original,writes,1};
    TC_X509_store_source source = {&record,1,0,read_record,NULL};
    tc_pki_store_candidates reader = {&source,{4096,4096,64,8},0,1,4096}, saved_reader;
    if (scenario == EMPTY_STORE) source.candidate_count = 0;
    if (scenario == NO_RECORDS) reader.remaining = 0;
    if (scenario == NO_BYTES) reader.bytes_left = 0;
    if (scenario == READ_ERROR) record.result = TC_TLV_INVALID;
    if (scenario == BAD_INDEX) reader.index = 2;
    if (scenario == NULL_BYTES) record.bytes.data = NULL;
    if (scenario == OVERLAP) {
      record.bytes = writes[0]; source.context = (void*)&guard;
      source.candidate = tc_pki_source_guard_candidate;
    }
    memcpy(&saved_reader,&reader,sizeof reader);
    const tc_pki_tree_workspace tree = {frames,8,&work};
    munit_assert_int(tc_pki_store_candidate_next(&reader,&tree,&parser,&out), ==, expected[scenario]);
    munit_assert_memory_equal(sizeof out,&out,&saved);
    munit_assert_memory_equal(sizeof reader,&reader,&saved_reader);
    munit_assert_size(record.calls, ==,
        scenario == EMPTY_STORE || scenario == NO_RECORDS || scenario == BAD_INDEX || scenario == NO_WORK ? 0 : 1);
  }
  return MUNIT_OK;
}


static MunitResult store_certificates(const MunitParameter params[], void* user)
{
  enum { INPUT_CAPACITY = 1024, FRAME_CAPACITY = 16, OID_CAPACITY = 32, RECORD_COUNT = 2 };
  uint8_t encoded[INPUT_CAPACITY];
  FILE* file = tc_test_fopen(TC_CANDIDATE_FILE,"rb");
  (void)params; (void)user;
  munit_assert_not_null(file);
  const size_t length = fread(encoded,1,sizeof encoded,file);
  const int complete = feof(file) && !ferror(file);
  const int closed = fclose(file);
  munit_assert_true(complete);
  munit_assert_int(closed, ==, 0);
  munit_assert_size(length, >, 0);
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_bytes oids[OID_CAPACITY];
  TC_X509_workspace parser = {frames,FRAME_CAPACITY,oids,OID_CAPACITY};
  record_fixture record = {{encoded,length},TC_TLV_OK,0};
  TC_X509_store_source source = {&record,RECORD_COUNT,0,read_record,NULL};
  tc_pki_store_candidates reader = {&source,{INPUT_CAPACITY,INPUT_CAPACITY,128,FRAME_CAPACITY},
    0,RECORD_COUNT,RECORD_COUNT * length};
  size_t work = RECORD_COUNT * (1 + length);
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  TC_X509_certificate out, saved;
  for (size_t i = 0; i < RECORD_COUNT; ++i) {
    munit_assert_int(tc_pki_store_candidate_next(&reader,&tree,&parser,&out), ==, TC_TLV_OK);
    munit_assert_ptr_equal(out.encoded.data,encoded);
    munit_assert_size(out.encoded.length, ==, length);
    munit_assert_size(reader.index, ==, i + 1);
    munit_assert_size(reader.remaining, ==, RECORD_COUNT - i - 1);
    munit_assert_size(reader.bytes_left, ==, (RECORD_COUNT - i - 1) * length);
  }
  munit_assert_size(work, ==, 0);
  memcpy(&saved,&out,sizeof out);
  munit_assert_int(tc_pki_store_candidate_next(&reader,&tree,&parser,&out), ==, TC_TLV_END);
  munit_assert_memory_equal(sizeof out,&out,&saved);
  munit_assert_size(record.calls, ==, RECORD_COUNT);
  source.candidate_count = 1;
  for (size_t prefix = 0; prefix < length; ++prefix) {
    record.bytes.length = prefix;
    reader.index = 0; reader.remaining = 1; reader.bytes_left = length;
    tc_pki_store_candidates before;
    memcpy(&before,&reader,sizeof reader);
    work = 1 + length;
    munit_assert_int(tc_pki_store_candidate_next(&reader,&tree,&parser,&out), ==,
        prefix ? TC_TLV_MORE : TC_TLV_ARGUMENT);
    munit_assert_memory_equal(sizeof reader,&reader,&before);
    munit_assert_memory_equal(sizeof out,&out,&saved);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/callbacks",callbacks,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/store-limits",store_limits,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/store-certificates",store_certificates,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/x509/candidate",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
