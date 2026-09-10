/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509_store.h>
#include "../../src/pki_source_internal.h"
#include "../../src/x509_path_internal.h"
#include "munit.h"
#include <string.h>

static MunitResult lifecycle(const MunitParameter params[], void* user)
{
  int first_context, second_context;
  TC_X509_store_source first = {&first_context,0,0,NULL,NULL};
  TC_X509_store_source second = {&second_context,0,0,NULL,NULL};
  TC_X509_store store = {0};
  TC_X509_store_snapshot slots[2] = {0}, *reader = NULL, *other = NULL;
  (void)params; (void)user;
  munit_assert_int(TC_X509_store_acquire(&store,&reader), ==, TC_TLV_END);
  munit_assert_null(reader);
  munit_assert_int(TC_X509_store_prepare(&slots[0],&first), ==, TC_TLV_OK);
  munit_assert_null(store.current);
  munit_assert_int(TC_X509_store_publish(&store,0,&slots[0]), ==, TC_TLV_OK);
  munit_assert_size(store.revision, ==, 1);
  munit_assert_int(TC_X509_store_acquire(&store,&reader), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_acquire(&store,&other), ==, TC_TLV_OK);
  munit_assert_ptr_equal(reader,other);
  munit_assert_size(reader->readers, ==, 2);
  munit_assert_int(TC_X509_store_prepare(&slots[1],&second), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_publish(&store,1,&slots[1]), ==, TC_TLV_OK);
  munit_assert_ptr_equal(store.current,&slots[1]);
  munit_assert_ptr_equal(reader->source.context,&first_context);
  munit_assert_int(reader->state, ==, TC_X509_SNAPSHOT_RETIRED);
  munit_assert_int(TC_X509_store_prepare(reader,&second), ==, TC_TLV_LIMIT);
  munit_assert_int(TC_X509_store_release(reader), ==, TC_TLV_OK);
  munit_assert_int(reader->state, ==, TC_X509_SNAPSHOT_RETIRED);
  munit_assert_int(TC_X509_store_release(other), ==, TC_TLV_OK);
  munit_assert_int(slots[0].state, ==, TC_X509_SNAPSHOT_FREE);
  munit_assert_null(slots[0].source.context);
  munit_assert_int(TC_X509_store_release(other), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_store_acquire(&store,&reader), ==, TC_TLV_OK);
  munit_assert_ptr_equal(reader->source.context,&second_context);
  munit_assert_int(TC_X509_store_release(reader), ==, TC_TLV_OK);
  munit_assert_int(reader->state, ==, TC_X509_SNAPSHOT_CURRENT);
  munit_assert_int(TC_X509_store_prepare(&slots[0],&first), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_publish(&store,2,&slots[0]), ==, TC_TLV_OK);
  munit_assert_int(slots[1].state, ==, TC_X509_SNAPSHOT_FREE);
  return MUNIT_OK;
}

static MunitResult failures(const MunitParameter params[], void* user)
{
  TC_X509_store_source source = {0};
  TC_X509_store store = {0}, saved_store;
  TC_X509_store_snapshot slots[2] = {0}, saved_slot, *reader = &slots[1];
  (void)params; (void)user;
  munit_assert_int(TC_X509_store_prepare(&slots[0],&source), ==, TC_TLV_OK);
  memcpy(&saved_store,&store,sizeof store); memcpy(&saved_slot,&slots[0],sizeof saved_slot);
  munit_assert_int(TC_X509_store_publish(&store,1,&slots[0]), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof store,&store,&saved_store);
  munit_assert_memory_equal(sizeof saved_slot,&slots[0],&saved_slot);
  munit_assert_int(TC_X509_store_discard(&slots[0]), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_discard(&slots[0]), ==, TC_TLV_ARGUMENT);
  source.candidate_count = 1;
  munit_assert_int(TC_X509_store_prepare(&slots[0],&source), ==, TC_TLV_ARGUMENT);
  source.candidate_count = 0; source.anchor_count = 1;
  munit_assert_int(TC_X509_store_prepare(&slots[0],&source), ==, TC_TLV_ARGUMENT);
  source.anchor_count = 0;
  munit_assert_int(TC_X509_store_prepare(&slots[0],&source), ==, TC_TLV_OK);
  store.revision = SIZE_MAX;
  munit_assert_int(TC_X509_store_publish(&store,SIZE_MAX,&slots[0]), ==, TC_TLV_LIMIT);
  munit_assert_null(store.current);
  munit_assert_int(slots[0].state, ==, TC_X509_SNAPSHOT_PREPARED);
  store.revision = 0;
  munit_assert_int(TC_X509_store_publish(&store,0,&slots[0]), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_discard(&slots[0]), ==, TC_TLV_ARGUMENT);
  slots[0].readers = SIZE_MAX;
  munit_assert_int(TC_X509_store_acquire(&store,&reader), ==, TC_TLV_LIMIT);
  munit_assert_ptr_equal(reader,&slots[1]);
  munit_assert_size(slots[0].readers, ==, SIZE_MAX);
  slots[0].readers = 0;
  munit_assert_int(TC_X509_store_acquire(&store,&store.current), ==, TC_TLV_ARGUMENT);
  munit_assert_ptr_equal(store.current,&slots[0]);
  munit_assert_size(slots[0].readers, ==, 0);
  munit_assert_int(TC_X509_store_prepare(&slots[1],&slots[1].source), ==, TC_TLV_ARGUMENT);
  munit_assert_int(slots[1].state, ==, TC_X509_SNAPSHOT_FREE);
  munit_assert_int(TC_X509_store_publish(&store,1,&slots[0]), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_store_prepare(NULL,&source), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_store_prepare(&slots[1],NULL), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_store_acquire(NULL,&reader), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_store_release(NULL), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

typedef struct {
  TC_bytes candidate;
  TC_X509_store_anchor anchor;
  TC_TLV_result result;
  int grow_work;
} SourceFixture;

static TC_TLV_result candidate_record(void* context, size_t index, size_t* work, TC_bytes* out)
{
  SourceFixture* fixture = context;
  (void)index;
  if (fixture->grow_work) ++*work;
  *out = fixture->candidate;
  return fixture->result;
}

static TC_TLV_result anchor_record(void* context, size_t index, size_t* work, TC_X509_store_anchor* out)
{
  SourceFixture* fixture = context;
  (void)index;
  if (fixture->grow_work) ++*work;
  *out = fixture->anchor;
  return fixture->result;
}

static MunitResult source_guards(const MunitParameter params[], void* user)
{
  uint8_t input = 1, scratch = 0;
  SourceFixture fixture = {.candidate = {&input,1}, .result = TC_TLV_OK};
  TC_X509_store_source source = {&fixture,1,1,candidate_record,anchor_record};
  TC_bytes writes[] = {{&scratch,1}};
  tc_pki_source_guard guard = {&source,writes,1};
  TC_bytes candidate, saved_candidate = {NULL,7};
  TC_X509_store_anchor anchor, saved_anchor;
  TC_bytes* fields[] = {
    &fixture.anchor.trust.name, &fixture.anchor.trust.public_key.algorithm.oid,
    &fixture.anchor.trust.public_key.algorithm.parameters, &fixture.anchor.trust.public_key.key,
    &fixture.anchor.trust.public_key.modulus, &fixture.anchor.trust.public_key.exponent,
    &fixture.anchor.trust.public_key.curve_oid, &fixture.anchor.names.permitted,
    &fixture.anchor.names.excluded
  };
  const TC_TLV_result failures[] = {TC_TLV_END,TC_TLV_INVALID,TC_TLV_ARGUMENT,
                                   TC_TLV_LIMIT,TC_TLV_UNSUPPORTED};
  size_t work;
  (void)params; (void)user;
  memset(&saved_anchor,0xa5,sizeof saved_anchor);
  work = 100;
  munit_assert_int(tc_pki_source_guard_candidate(&guard,0,&work,&candidate), ==, TC_TLV_OK);
  munit_assert_ptr_equal(candidate.data,&input);
  munit_assert_size(work, ==, 99);
  for (size_t i = 0; i < sizeof fields / sizeof *fields; ++i) *fields[i] = fixture.candidate;
  munit_assert_int(tc_pki_source_guard_anchor(&guard,0,&work,&anchor), ==, TC_TLV_OK);
  munit_assert_ptr_equal(anchor.names.excluded.data,&input);
  /* Each borrowed anchor field can independently alias consumer storage. */
  for (size_t i = 0; i < sizeof fields / sizeof *fields; ++i) {
    *fields[i] = writes[0]; work = 100;
    memcpy(&anchor,&saved_anchor,sizeof anchor);
    munit_assert_int(tc_pki_source_guard_anchor(&guard,0,&work,&anchor), ==, TC_TLV_ARGUMENT);
    munit_assert_memory_equal(sizeof anchor,&anchor,&saved_anchor);
    *fields[i] = fixture.candidate;
  }
  for (size_t budget = 0; budget < sizeof fields / sizeof *fields; ++budget) {
    work = budget; memcpy(&anchor,&saved_anchor,sizeof anchor);
    munit_assert_int(tc_pki_source_guard_anchor(&guard,0,&work,&anchor), ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof anchor,&anchor,&saved_anchor);
  }
  fixture.candidate = writes[0]; work = 100; candidate = saved_candidate;
  munit_assert_int(tc_pki_source_guard_candidate(&guard,0,&work,&candidate), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof candidate,&candidate,&saved_candidate);
  fixture.candidate = (TC_bytes){&input,1};
  for (size_t i = 0; i < sizeof failures / sizeof *failures; ++i) {
    TC_TLV_result expected = failures[i] == TC_TLV_LIMIT || failures[i] == TC_TLV_UNSUPPORTED
        ? failures[i] : TC_TLV_ARGUMENT;
    fixture.result = failures[i]; work = 100;
    candidate = saved_candidate; memcpy(&anchor,&saved_anchor,sizeof anchor);
    munit_assert_int(tc_pki_source_guard_candidate(&guard,0,&work,&candidate), ==, expected);
    munit_assert_int(tc_pki_source_guard_anchor(&guard,0,&work,&anchor), ==, expected);
    munit_assert_memory_equal(sizeof candidate,&candidate,&saved_candidate);
    munit_assert_memory_equal(sizeof anchor,&anchor,&saved_anchor);
  }
  fixture.result = TC_TLV_OK; fixture.grow_work = 1; work = 100;
  munit_assert_int(tc_pki_source_guard_candidate(&guard,0,&work,&candidate), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, 0);
  work = 100;
  munit_assert_int(tc_pki_source_guard_anchor(&guard,0,&work,&anchor), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, 0);
  munit_assert_memory_equal(sizeof candidate,&candidate,&saved_candidate);
  munit_assert_memory_equal(sizeof anchor,&anchor,&saved_anchor);
  fixture.grow_work = 0; work = 100;
  munit_assert_int(tc_pki_source_guard_candidate(&guard,1,&work,&candidate), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_pki_source_guard_anchor(&guard,1,&work,&anchor), ==, TC_TLV_ARGUMENT);
  source.candidate = NULL; source.anchor = NULL;
  munit_assert_int(tc_pki_source_guard_candidate(&guard,0,&work,&candidate), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_pki_source_guard_anchor(&guard,0,&work,&anchor), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof candidate,&candidate,&saved_candidate);
  munit_assert_memory_equal(sizeof anchor,&anchor,&saved_anchor);
  munit_assert_size(work, ==, 100);
  return MUNIT_OK;
}

static MunitResult search_preflight(const MunitParameter params[], void* user)
{
  TC_X509_store_source source = {0};
  TC_X509_path_options options = {0}, saved_options;
  TC_X509_path_workspace validation = {0};
  TC_X509_search_workspace search = {0};
  TC_X509_search_result out, saved_out;
  TC_bytes target = {NULL,0};
  size_t work;
  (void)params; (void)user;
  memset(&out,0xa5,sizeof out); memcpy(&saved_out,&out,sizeof out);
  options.max_work = 10000; memcpy(&saved_options,&options,sizeof options);
  /* Reject the alias before charging a counter inside read-only options. */
  munit_assert_int(tc_x509_path_build_work(target,&source,&options,&validation,&search,
      &options.max_work,&out), ==, TC_X509_PATH_ERROR);
  munit_assert_memory_equal(sizeof options,&options,&saved_options);
  munit_assert_memory_equal(sizeof out,&out,&saved_out);
  for (size_t budget = 0; budget < 100; ++budget) {
    work = budget;
    munit_assert_int(tc_x509_path_build_work(target,&source,&options,&validation,&search,
        &work,&out), ==, TC_X509_PATH_LIMIT);
    munit_assert_size(work, ==, budget);
    munit_assert_memory_equal(sizeof out,&out,&saved_out);
  }
  work = 10000;
  target = (TC_bytes){(const uint8_t*)&work,sizeof work};
  munit_assert_int(tc_x509_path_build_work(target,&source,&options,&validation,&search,
      &work,&out), ==, TC_X509_PATH_ERROR);
  munit_assert_size(work, ==, 10000);
  munit_assert_memory_equal(sizeof out,&out,&saved_out);
  {
    TC_bytes path[1] = {{NULL,10000}}, saved_path;
    TC_X509_search_frame frames[1] = {0}, saved_frame;
    memcpy(&saved_path,path,sizeof saved_path);
    memcpy(&saved_frame,frames,sizeof saved_frame);
    search = (TC_X509_search_workspace){path,frames,1};
    target = (TC_bytes){NULL,0};
    munit_assert_int(tc_x509_path_build_work(target,&source,&options,&validation,&search,
        &path[0].length,&out), ==, TC_X509_PATH_ERROR);
    munit_assert_memory_equal(sizeof saved_path,path,&saved_path);
    munit_assert_memory_equal(sizeof saved_frame,frames,&saved_frame);
    munit_assert_memory_equal(sizeof out,&out,&saved_out);
  }
  return MUNIT_OK;
}

static MunitResult source_status(const MunitParameter params[], void* user)
{
  uint8_t input = 1;
  SourceFixture fixture = {.candidate = {&input,1}, .result = TC_TLV_OK};
  fixture.anchor.trust.name = fixture.candidate;
  fixture.anchor.trust.public_key.algorithm.oid = fixture.candidate;
  fixture.anchor.trust.public_key.key = fixture.candidate;
  TC_X509_store_source source = {&fixture,1,1,candidate_record,anchor_record};
  int failed = 0;
  tc_pki_source_status_guard guard = {{&source,NULL,0},&failed};
  TC_bytes candidate;
  TC_X509_store_anchor anchor;
  size_t work = 100;
  (void)params; (void)user;
  munit_assert_int(tc_pki_source_status_candidate(&guard,0,&work,&candidate), ==, TC_TLV_OK);
  munit_assert_int(failed, ==, 0);
  fixture.result = TC_TLV_LIMIT;
  munit_assert_int(tc_pki_source_status_candidate(&guard,0,&work,&candidate), ==, TC_TLV_LIMIT);
  munit_assert_int(failed, ==, 1);
  fixture.result = TC_TLV_OK;
  munit_assert_int(tc_pki_source_status_candidate(&guard,0,&work,&candidate), ==, TC_TLV_OK);
  munit_assert_int(failed, ==, 1);
  failed = 0;
  munit_assert_int(tc_pki_source_status_anchor(&guard,0,&work,&anchor), ==, TC_TLV_OK);
  munit_assert_int(failed, ==, 0);
  munit_assert_int(tc_pki_source_status_anchor(&guard,1,&work,&anchor), ==, TC_TLV_ARGUMENT);
  munit_assert_int(failed, ==, 1);
  munit_assert_int(tc_pki_source_status_anchor(&guard,0,&work,&anchor), ==, TC_TLV_OK);
  munit_assert_int(failed, ==, 1);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/lifecycle",lifecycle,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/failures",failures,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/source-guards",source_guards,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/source-status",source_status,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/search-preflight",search_preflight,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/x509/store",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
