/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/x509_revocation_internal.h"
#include "../../src/pki_source_internal.h"
#include "munit.h"
#include <string.h>

typedef struct {
  TC_TLV_result result;
  unsigned calls;
} signer_cursor;

static TC_TLV_result signer_next(void* context, const tc_pki_tree_workspace* tree,
    TC_X509_workspace* parser, TC_X509_certificate* out)
{
  signer_cursor* cursor = context;
  (void)tree; (void)parser; (void)out;
  ++cursor->calls;
  return cursor->result;
}

static MunitResult signer_search(const MunitParameter params[], void* user)
{
  const TC_X509_path_options options = {0};
  const TC_X509_path_workspace validation = {0};
  const TC_X509_search_workspace search = {0};
  const TC_X509_store_source source = {NULL,0,1,NULL,tc_pki_source_guard_anchor};
  const tc_x509_crl crl = {0};
  const tc_x509_crl_extension_info extensions = {0};
  const TC_TLV_result results[] = {TC_TLV_END,TC_TLV_INVALID,TC_TLV_LIMIT,TC_TLV_ARGUMENT};
  TC_X509_search_result out, saved;
  memset(&saved,0xa5,sizeof saved);
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof results / sizeof *results; ++i) {
    size_t work = 100;
    const tc_pki_tree_workspace tree = {NULL,0,&work};
    const tc_x509_crl_trust trust = {&source,0,&options,&tree,&validation,&search};
    signer_cursor cursor = {results[i],0};
    int failed = 0;
    out = saved;
    munit_assert_int(tc_x509_crl_search_candidates(&cursor,signer_next,&crl,&extensions,
        &trust,NULL,NULL,&out,&failed), ==, TC_TLV_ARGUMENT);
    munit_assert_uint(cursor.calls, ==, 0);
    munit_assert_int(tc_x509_crl_search_candidates(&cursor,signer_next,&crl,&extensions,
        &trust,tc_x509_crl_check_signer,NULL,&out,&failed), ==,
        results[i] == TC_TLV_END ? TC_TLV_INVALID : results[i]);
    munit_assert_uint(cursor.calls, ==, 1);
    munit_assert_int(failed, ==, results[i] != TC_TLV_END);
    munit_assert_memory_equal(sizeof out,&out,&saved);
    munit_assert_size(work, ==, 100);
  }
  return MUNIT_OK;
}

static MunitResult trust_arguments(const MunitParameter params[], void* user)
{
  enum { VALID, SOURCE, OPTIONS, TREE, WORK, VALIDATION, SEARCH, ANCHOR_CALLBACK,
    ANCHOR_INDEX, EMPTY_ANCHORS, CASE_COUNT };
  const TC_X509_path_options options = {0};
  const TC_X509_path_workspace validation = {0};
  const TC_X509_search_workspace search = {0};
  (void)params; (void)user;
  munit_assert_false(tc_x509_crl_trust_valid(NULL));
  for (unsigned scenario = VALID; scenario < CASE_COUNT; ++scenario) {
    size_t work = 100;
    tc_pki_tree_workspace tree = {NULL,0,&work};
    TC_X509_store_source source = {NULL,0,1,NULL,tc_pki_source_guard_anchor};
    tc_x509_crl_trust trust = {&source,0,&options,&tree,&validation,&search};
    switch (scenario) {
      case SOURCE: trust.source = NULL; break;
      case OPTIONS: trust.options = NULL; break;
      case TREE: trust.tree = NULL; break;
      case WORK: tree.work = NULL; break;
      case VALIDATION: trust.validation = NULL; break;
      case SEARCH: trust.search = NULL; break;
      case ANCHOR_CALLBACK: source.anchor = NULL; break;
      case ANCHOR_INDEX: trust.anchor_index = source.anchor_count; break;
      case EMPTY_ANCHORS: source.anchor_count = 0; break;
      default: break;
    }
    munit_assert_int(tc_x509_crl_trust_valid(&trust), ==, scenario == VALID);
    munit_assert_size(work, ==, 100);
  }
  return MUNIT_OK;
}

static MunitResult dependencies(const MunitParameter params[], void* user)
{
  static const uint8_t first[] = {1,2}, duplicate[] = {1,2}, second[] = {1,3};
  const TC_bytes a = {first,sizeof first}, b = {second,sizeof second};
  TC_X509_revocation_node nodes[1] = {0}, saved[1];
  size_t count = 0, index = SIZE_MAX, work = 0;
  (void)params; (void)user;
  munit_assert_int(tc_x509_crl_dependency_find(nodes,1,&count,a,&work,&index), ==, TC_TLV_OK);
  munit_assert_size(count, ==, 1);
  munit_assert_size(index, ==, 0);
  munit_assert_ptr_equal(nodes[0].certificate.data,first);
  nodes[0].status = TC_X509_CRL_REVOKED;
  memcpy(saved,nodes,sizeof nodes);
  for (size_t budget = 0; budget <= sizeof first; ++budget) {
    work = budget; index = SIZE_MAX;
    munit_assert_int(tc_x509_crl_dependency_find(nodes,1,&count,a,&work,&index), ==, TC_TLV_LIMIT);
    munit_assert_size(index, ==, SIZE_MAX);
    munit_assert_size(count, ==, 1);
    munit_assert_memory_equal(sizeof nodes,nodes,saved);
  }
  work = 1 + sizeof first;
  munit_assert_int(tc_x509_crl_dependency_find(nodes,1,&count,
      (TC_bytes){duplicate,sizeof duplicate},&work,&index), ==, TC_TLV_OK);
  munit_assert_size(index, ==, 0);
  munit_assert_size(work, ==, 0);
  munit_assert_memory_equal(sizeof nodes,nodes,saved);
  work = 1 + sizeof first; index = SIZE_MAX;
  munit_assert_int(tc_x509_crl_dependency_find(nodes,1,&count,b,&work,&index), ==, TC_TLV_LIMIT);
  munit_assert_size(index, ==, SIZE_MAX);
  munit_assert_memory_equal(sizeof nodes,nodes,saved);
  return MUNIT_OK;
}

static MunitResult dependency_status(const MunitParameter params[], void* user)
{
  static const uint8_t encoded[] = {1,2};
  const TC_bytes certificate = {encoded,sizeof encoded};
  const tc_x509_crl_status statuses[] = {TC_X509_CRL_UNREVOKED,TC_X509_CRL_REVOKED,
    TC_X509_CRL_UNDETERMINED,(tc_x509_crl_status)-1};
  const TC_X509_path_status expected[] = {TC_X509_PATH_VALID,TC_X509_PATH_INVALID,
    TC_X509_PATH_UNSUPPORTED,TC_X509_PATH_ERROR};
  TC_X509_search_result path = {0};
  path.path = &certificate; path.count = 1;
  TC_X509_revocation_node node = {certificate,TC_X509_CRL_UNDETERMINED};
  tc_x509_crl_resolution_workspace workspace = {0};
  workspace.nodes = &node; workspace.node_capacity = 1;
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof statuses / sizeof *statuses; ++i) {
    size_t count = 1, work = 100;
    node.status = statuses[i];
    munit_assert_int(tc_x509_crl_dependencies_path(&path,&workspace,&count,NULL,0,&work), ==, expected[i]);
    munit_assert_size(count, ==, 1);
    munit_assert_int(node.status, ==, statuses[i]);
  }
  size_t count = 0, work = 100;
  munit_assert_int(tc_x509_crl_dependencies_path(&path,&workspace,&count,NULL,0,&work), ==, TC_X509_PATH_UNSUPPORTED);
  munit_assert_size(count, ==, 1);
  munit_assert_int(node.status, ==, TC_X509_CRL_UNDETERMINED);
  munit_assert_ptr_equal(node.certificate.data,encoded);
  return MUNIT_OK;
}

static MunitResult dependency_failures(const MunitParameter params[], void* user)
{
  enum { PATH, WORKSPACE, COUNT, WORK, PATH_BYTES, WRITES, NODES, COUNT_RANGE,
    OVERLAP, NO_WORK, CASE_COUNT };
  static const uint8_t encoded[] = {1,2};
  const TC_bytes certificate = {encoded,sizeof encoded};
  (void)params; (void)user;
  for (unsigned scenario = 0; scenario < CASE_COUNT; ++scenario) {
    TC_X509_revocation_node node = {certificate,TC_X509_CRL_UNREVOKED}, saved;
    memcpy(&saved,&node,sizeof node);
    TC_X509_search_result path = {0};
    path.path = scenario == PATH_BYTES ? NULL : &certificate; path.count = 1;
    tc_x509_crl_resolution_workspace workspace = {0};
    workspace.nodes = scenario == NODES ? NULL : &node; workspace.node_capacity = 1;
    size_t count = scenario == COUNT_RANGE ? 2 : 1;
    const size_t initial_count = count;
    size_t work = scenario == NO_WORK ? 0 : 100;
    const TC_bytes* writes = scenario == OVERLAP ? &certificate : NULL;
    const size_t write_count = scenario == WRITES || scenario == OVERLAP ? 1 : 0;
    munit_assert_int(tc_x509_crl_dependencies_path(scenario == PATH ? NULL : &path,
        scenario == WORKSPACE ? NULL : &workspace,scenario == COUNT ? NULL : &count,
        writes,write_count,scenario == WORK ? NULL : &work), ==,
        scenario == NO_WORK ? TC_X509_PATH_LIMIT : TC_X509_PATH_ERROR);
    munit_assert_size(count, ==, initial_count);
    munit_assert_memory_equal(sizeof node,&node,&saved);
  }
  return MUNIT_OK;
}

enum { RESOLVE_CHAIN, RESOLVE_CYCLE, RESOLVE_STOP, RESOLVE_WORK_INCREASE, RESOLVE_COUNT_INCREASE,
  RESOLVE_COUNT_DECREASE, RESOLVE_STOP_OK, RESOLVE_BAD_EVIDENCE, RESOLVE_PARTIAL,
  RESOLVE_INVALID, RESOLVE_LIMIT, RESOLVE_CASE_COUNT };
typedef struct {
  TC_X509_revocation_node* nodes;
  size_t* count;
  size_t* work;
  unsigned scenario, calls;
} resolution_fixture;

static TC_TLV_result evaluate_node(void* context, size_t index,
    tc_x509_crl_evidence* evidence, int* stop)
{
  resolution_fixture* state = context;
  ++state->calls;
  if (state->scenario == RESOLVE_STOP) { *stop = 1; return TC_TLV_INVALID; }
  if (state->scenario == RESOLVE_WORK_INCREASE) { ++*state->work; return TC_TLV_UNSUPPORTED; }
  if (state->scenario == RESOLVE_COUNT_INCREASE) { *state->count = 3; return TC_TLV_UNSUPPORTED; }
  if (state->scenario == RESOLVE_COUNT_DECREASE) { *state->count = 0; return TC_TLV_UNSUPPORTED; }
  if (state->scenario == RESOLVE_STOP_OK) { *stop = 1; return TC_TLV_OK; }
  if (state->scenario == RESOLVE_BAD_EVIDENCE) { evidence->revocation.found = 2; return TC_TLV_OK; }
  if (state->scenario == RESOLVE_PARTIAL) return TC_TLV_OK;
  if (state->scenario == RESOLVE_INVALID) return TC_TLV_INVALID;
  if (state->scenario == RESOLVE_LIMIT) return TC_TLV_LIMIT;
  if (state->scenario == RESOLVE_CYCLE) return TC_TLV_UNSUPPORTED;
  if (index == 0 && *state->count == 1) { *state->count = 2; return TC_TLV_UNSUPPORTED; }
  if (index == 0 && state->nodes[1].status != TC_X509_CRL_UNREVOKED) return TC_TLV_UNSUPPORTED;
  evidence->reasons = TC_X509_CRL_ALL_REASONS;
  return TC_TLV_OK;
}

static MunitResult resolution(const MunitParameter params[], void* user)
{
  const TC_TLV_result expected[] = {TC_TLV_OK,TC_TLV_UNSUPPORTED,TC_TLV_INVALID,
    TC_TLV_ARGUMENT,TC_TLV_ARGUMENT,TC_TLV_ARGUMENT,TC_TLV_ARGUMENT,TC_TLV_ARGUMENT,
    TC_TLV_UNSUPPORTED,TC_TLV_INVALID,TC_TLV_LIMIT};
  (void)params; (void)user;
  for (unsigned scenario = RESOLVE_CHAIN; scenario < RESOLVE_CASE_COUNT; ++scenario) {
    TC_X509_revocation_node nodes[2] = {0};
    size_t count = 1, work = 100;
    resolution_fixture state = {nodes,&count,&work,scenario,0};
    tc_x509_crl_evidence out, saved;
    memset(&out,0xa5,sizeof out); memcpy(&saved,&out,sizeof out);
    munit_assert_int(tc_x509_crl_nodes_resolve(nodes,2,&count,0,&work,evaluate_node,&state,&out), ==, expected[scenario]);
    if (scenario == RESOLVE_CHAIN) {
      munit_assert_uint(state.calls, ==, 3);
      munit_assert_uint(out.reasons, ==, TC_X509_CRL_ALL_REASONS);
      munit_assert_int(nodes[0].status, ==, TC_X509_CRL_UNREVOKED);
      munit_assert_int(nodes[1].status, ==, TC_X509_CRL_UNREVOKED);
    } else {
      munit_assert_uint(state.calls, ==, 1);
      munit_assert_memory_equal(sizeof out,&out,&saved);
    }
  }
  return MUNIT_OK;
}

typedef struct { size_t calls, fail_at, revoked_at; TC_TLV_result result; int complete; } path_fixture;

static TC_TLV_result resolve_certificate(void* context, TC_bytes certificate,
    tc_x509_crl_evidence* evidence)
{
  path_fixture* state = context;
  munit_assert_size(certificate.length, ==, 1);
  munit_assert_size(certificate.data[0], ==, state->calls);
  if (state->calls++ == state->fail_at) return state->result;
  if (state->complete) evidence->reasons = TC_X509_CRL_ALL_REASONS;
  if (state->calls - 1 == state->revoked_at) {
    evidence->revocation.found = 1;
    evidence->revocation.revoked_at = (TC_X509_time){2025,1,2,3,4,5};
  }
  return TC_TLV_OK;
}

static MunitResult held_path(const MunitParameter params[], void* user)
{
  enum { COMPLETE, LATER_LIMIT, INCOMPLETE, FIRST_REVOKED, LAST_REVOKED, CASE_COUNT };
  static const uint8_t bytes[] = {0,1};
  const TC_bytes chain[] = {{bytes,1},{bytes + 1,1}};
  (void)params; (void)user;
  for (unsigned scenario = 0; scenario < CASE_COUNT; ++scenario) {
    const size_t revoked_at = scenario == FIRST_REVOKED ? 0 : scenario == LAST_REVOKED ? 1 : SIZE_MAX;
    path_fixture state = {0,scenario == LATER_LIMIT ? 1 : SIZE_MAX,revoked_at,TC_TLV_LIMIT,scenario != INCOMPLETE};
    TC_X509_revocation_result out, saved;
    memset(&out,0xa5,sizeof out); memcpy(&saved,&out,sizeof out);
    munit_assert_int(tc_x509_crl_path_resolve(chain,2,resolve_certificate,&state,&out), ==,
        scenario == LATER_LIMIT ? TC_TLV_LIMIT : scenario == INCOMPLETE ? TC_TLV_UNSUPPORTED : TC_TLV_OK);
    munit_assert_size(state.calls, ==, scenario == INCOMPLETE || scenario == FIRST_REVOKED ? 1 : 2);
    if (scenario == COMPLETE) {
      munit_assert_int(out.status, ==, TC_X509_CRL_UNREVOKED);
      munit_assert_size(out.certificate_index, ==, SIZE_MAX);
    } else if (revoked_at != SIZE_MAX) {
      munit_assert_int(out.status, ==, TC_X509_CRL_REVOKED);
      munit_assert_size(out.certificate_index, ==, revoked_at);
      munit_assert_int(out.evidence.revocation.found, ==, 1);
      munit_assert_uint(out.evidence.revocation.revoked_at.year, ==, 2025);
      munit_assert_uint(out.evidence.revocation.revoked_at.second, ==, 5);
    } else munit_assert_memory_equal(sizeof out,&out,&saved);
  }
  return MUNIT_OK;
}

static MunitResult storage_spans(const MunitParameter params[], void* user)
{
  enum { TREE_LARGER, VALIDATION_LARGER, SEPARATE, MISSING_STATES, FRAME_OVERFLOW, CASE_COUNT };
  TC_TLV_frame frames[2], other[2];
  uint8_t states[2];
  const TC_X509_path_options options = {0};
  const TC_X509_search_workspace search = {0};
  const TC_X509_store_source source = {NULL,0,1,NULL,tc_pki_source_guard_anchor};
  (void)params; (void)user;
  for (unsigned scenario = 0; scenario < CASE_COUNT; ++scenario) {
    size_t work = 100;
    TC_X509_path_workspace validation = {0};
    validation.frames = frames;
    validation.frame_capacity = scenario == VALIDATION_LARGER ? 2 : 1;
    tc_pki_tree_workspace tree = {scenario == SEPARATE ? other : frames,
      scenario == VALIDATION_LARGER ? 1 : 2,&work};
    if (scenario == FRAME_OVERFLOW) tree.capacity = SIZE_MAX;
    const tc_x509_crl_trust trust = {&source,0,&options,&tree,&validation,&search};
    tc_x509_crl_evidence evidence = {0};
    tc_x509_crl_scope_processing processing = {0};
    processing.states = scenario == MISSING_STATES ? NULL : states;
    processing.capacity = sizeof states; processing.evidence = &evidence;
    TC_X509_search_result out;
    TC_bytes writes[CRL_SCOPE_WRITES], saved[CRL_SCOPE_WRITES];
    memset(writes,0xa5,sizeof writes); memcpy(saved,writes,sizeof writes);
    munit_assert_int(tc_x509_crl_scope_storage_writes(&processing,&trust,&out,writes), ==,
        scenario == MISSING_STATES || scenario == FRAME_OVERFLOW ? TC_TLV_ARGUMENT : TC_TLV_OK);
    munit_assert_size(work, ==, 100);
    munit_assert_memory_equal(sizeof writes - CRL_SCOPE_NODES * sizeof *writes,
        writes + CRL_SCOPE_NODES,saved + CRL_SCOPE_NODES);
    if (scenario <= SEPARATE) {
      munit_assert_ptr_equal(writes[TC_X509_PATH_STORAGE_FRAMES].data,frames);
      munit_assert_size(writes[TC_X509_PATH_STORAGE_FRAMES].length, ==,
          (scenario == SEPARATE ? 1 : 2) * sizeof *frames);
      munit_assert_size(writes[CRL_SCOPE_TREE].length, ==, scenario == SEPARATE ? sizeof other : 0);
      munit_assert_ptr_equal(writes[CRL_SCOPE_STATES].data,states);
      munit_assert_ptr_equal(writes[CRL_SCOPE_EVIDENCE].data,&evidence);
      munit_assert_ptr_equal(writes[CRL_SCOPE_RESULT].data,&out);
      munit_assert_ptr_equal(writes[CRL_SCOPE_WORK].data,&work);
    }
  }
  return MUNIT_OK;
}

static MunitResult record_storage(const MunitParameter params[], void* user)
{
  uint8_t byte = 0;
  const TC_bytes write = {&byte,1};
  TC_X509_crl_record record = {0};
  TC_X509_crl_index index = {0};
  index.records = &record; index.count = 1;
  TC_bytes* fields[] = {&record.crl.encoded,
    &record.crl.tbs,
    &record.crl.issuer,
    &record.crl.signature,
    &record.crl.revoked,
    &record.crl.extensions,
    &record.crl.signature_algorithm.oid,
    &record.crl.signature_algorithm.parameters,
    &record.extensions.number,
    &record.extensions.base_number,
    &record.extensions.distribution_encoded,
    &record.extensions.freshest,
    &record.extensions.issuer_alt,
    &record.extensions.unknown_critical_oid,
    &record.extensions.authority.key_identifier,
    &record.extensions.authority.issuer,
    &record.extensions.authority.serial,
    &record.extensions.distribution.name.encoded,
    &record.extensions.distribution.name.contents};
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof fields / sizeof *fields; ++i) {
    size_t work = 1000;
    *fields[i] = write;
    munit_assert_int(tc_x509_crl_index_storage_bytes(&index,&write,1,&work), ==, TC_TLV_ARGUMENT);
    *fields[i] = (TC_bytes){NULL,0};
  }
  size_t work = 1000;
  munit_assert_int(tc_x509_crl_index_storage_bytes(&index,&write,1,&work), ==, TC_TLV_OK);
  return MUNIT_OK;
}

static MunitResult scope_inputs(const MunitParameter params[], void* user)
{
  uint8_t byte = 0;
  const TC_bytes bytes = {&byte,1};
  TC_X509_certificate certificate = {0};
  tc_pki_distribution_point point = {0};
  tc_x509_crl_query query = {&certificate,&point,0};
  TC_X509_crl_index index = {0};
  TC_X509_path_options options = {0};
  TC_X509_path_workspace validation = {0};
  TC_X509_search_workspace search = {0};
  TC_X509_store_source source = {NULL,0,1,NULL,tc_pki_source_guard_anchor};
  size_t work = 1000;
  tc_pki_tree_workspace tree = {NULL,0,&work};
  const tc_x509_crl_trust trust = {&source,0,&options,&tree,&validation,&search};
  tc_x509_crl_scope_processing processing = {0};
  processing.index = &index; processing.query = &query;
#define OBJECT_SPAN(object) {(const uint8_t*)&(object),sizeof(object)}
  const TC_bytes metadata[] = {OBJECT_SPAN(index),OBJECT_SPAN(query),OBJECT_SPAN(certificate),
    OBJECT_SPAN(point),OBJECT_SPAN(source),OBJECT_SPAN(options),OBJECT_SPAN(validation),
    OBJECT_SPAN(search),OBJECT_SPAN(tree)};
#undef OBJECT_SPAN
  TC_bytes* fields[] = {&certificate.encoded,&certificate.extensions,&certificate.issuer,
    &certificate.serial,&point.name.encoded,&point.name.contents,&point.issuer,
    &options.purpose,&options.anchor_names.permitted,&options.anchor_names.excluded};
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof metadata / sizeof *metadata; ++i) {
    work = 1000;
    munit_assert_int(tc_x509_crl_scope_storage_inputs(&processing,&trust,&metadata[i],1,&work), ==, TC_TLV_ARGUMENT);
  }
  for (size_t i = 0; i < sizeof fields / sizeof *fields; ++i) {
    work = 1000; *fields[i] = bytes;
    munit_assert_int(tc_x509_crl_scope_storage_inputs(&processing,&trust,&bytes,1,&work), ==, TC_TLV_ARGUMENT);
    *fields[i] = (TC_bytes){NULL,0};
  }
  work = 1000;
  munit_assert_int(tc_x509_crl_scope_storage_inputs(&processing,&trust,&bytes,1,&work), ==, TC_TLV_OK);
  work = 0;
  munit_assert_int(tc_x509_crl_scope_storage_inputs(&processing,&trust,&bytes,1,&work), ==, TC_TLV_LIMIT);
  return MUNIT_OK;
}

static TC_TLV_result unexpected_search(const void* candidates, const tc_x509_crl* crl,
    const tc_x509_crl_extension_info* extensions, const tc_x509_crl_trust* trust,
    tc_x509_crl_attempt attempt, const void* context, TC_X509_search_result* out, int* failed)
{
  (void)candidates; (void)crl; (void)extensions; (void)trust;
  (void)attempt; (void)context; (void)out; (void)failed;
  munit_error("Rejected CRL records must be filtered before signer search");
}

static MunitResult scope_traversal(const MunitParameter params[], void* user)
{
  enum { EMPTY, BAD_REFERENCE, MISSING_RECORDS, INVALID_RECORD, UNSUPPORTED_RECORD,
    NO_WORK, CASE_COUNT };
  const TC_X509_path_options options = {0};
  const TC_X509_path_workspace validation = {0};
  const TC_X509_search_workspace search = {0};
  const TC_X509_certificate certificate = {0};
  const tc_pki_distribution_point point = {0};
  tc_x509_crl_query query = {0};
  query.certificate = &certificate; query.point = &point;
  TC_X509_search_result out, saved;
  memset(&saved,0xa5,sizeof saved);
  (void)params; (void)user;
  for (unsigned scenario = EMPTY; scenario < CASE_COUNT; ++scenario) {
    size_t work = scenario == NO_WORK ? 0 : 100;
    const tc_pki_tree_workspace tree = {NULL,0,&work};
    const TC_X509_store_source source = {NULL,0,1,NULL,tc_pki_source_guard_anchor};
    const tc_x509_crl_trust trust = {&source,0,&options,&tree,&validation,&search};
    TC_X509_crl_record record = {0}; record.policy = TC_TLV_INVALID;
    TC_X509_crl_index index = {0}; index.records = &record; index.count = 1;
    tc_x509_crl_evidence evidence = {0};
    const tc_x509_crl_evidence before = evidence;
    tc_x509_crl_scope_processing processing = {0};
    processing.index = &index; processing.query = &query; processing.evidence = &evidence;
    tc_x509_crl_certificate_fields fields = {0};
    TC_TLV_reader reader = {0};
    int failed = 0;
    TC_TLV_result expected = TC_TLV_ARGUMENT;
    switch (scenario) {
      case EMPTY: index.count = 0; expected = TC_TLV_END; break;
      case BAD_REFERENCE: processing.reference = index.count + 1; break;
      case MISSING_RECORDS: index.records = NULL; break;
      case INVALID_RECORD: expected = TC_TLV_INVALID; break;
      case UNSUPPORTED_RECORD: record.policy = expected = TC_TLV_UNSUPPORTED; break;
      case NO_WORK: expected = TC_TLV_LIMIT; break;
    }
    out = saved;
    munit_assert_int(tc_x509_crl_scopes(NULL,unexpected_search,&processing,&trust,
        &fields,&reader,1,&failed,&out), ==, expected);
    munit_assert_memory_equal(sizeof evidence,&evidence,&before);
    munit_assert_memory_equal(sizeof out,&out,&saved);
    munit_assert_int(failed, ==, 0);
    munit_assert_size(work, ==, scenario == NO_WORK ? 0 :
        (scenario == INVALID_RECORD || scenario == UNSUPPORTED_RECORD ? 99 : 100));
  }
  return MUNIT_OK;
}

static MunitResult path_inputs(const MunitParameter params[], void* user)
{
  enum { VALID, CHAIN_OVERLAP, CERTIFICATE_OVERLAP, OPTIONS_OVERLAP, WORKSPACE_OVERLAP,
    MISSING_CHAIN, EMPTY_CERTIFICATE, MISSING_CERTIFICATE, COUNT_OVERFLOW, NO_WORK, CASE_COUNT };
  const uint8_t encoded[] = {1,2};
  uint8_t scratch;
  (void)params; (void)user;
  for (unsigned scenario = VALID; scenario < CASE_COUNT; ++scenario) {
    TC_bytes chain[] = {{encoded,sizeof encoded}};
    TC_bytes writes = {&scratch,sizeof scratch};
    tc_x509_crl_held_path path = {0};
    path.chain = chain; path.count = 1;
    path.metadata[CRL_PATH_OPTIONS] = (TC_bytes){encoded,sizeof encoded};
    path.metadata[CRL_PATH_WORKSPACE] = (TC_bytes){encoded,sizeof encoded};
    size_t work = scenario == NO_WORK ? 0 : 1000;
    switch (scenario) {
      case CHAIN_OVERLAP: writes = (TC_bytes){(const uint8_t*)chain,sizeof chain}; break;
      case CERTIFICATE_OVERLAP: chain[0] = writes; break;
      case OPTIONS_OVERLAP: path.metadata[CRL_PATH_OPTIONS] = writes; break;
      case WORKSPACE_OVERLAP: path.metadata[CRL_PATH_WORKSPACE] = writes; break;
      case MISSING_CHAIN: path.chain = NULL; break;
      case EMPTY_CERTIFICATE: chain[0].length = 0; break;
      case MISSING_CERTIFICATE: chain[0].data = NULL; break;
      case COUNT_OVERFLOW: path.count = SIZE_MAX; break;
      default: break;
    }
    const tc_x509_crl_held_path saved = path;
    const TC_bytes saved_chain = chain[0];
    munit_assert_int(tc_x509_crl_path_storage_inputs(&path,&writes,1,&work), ==,
        scenario == VALID ? TC_TLV_OK : scenario == NO_WORK ? TC_TLV_LIMIT : TC_TLV_ARGUMENT);
    munit_assert_memory_equal(sizeof path,&path,&saved);
    munit_assert_memory_equal(sizeof saved_chain,chain,&saved_chain);
  }
  return MUNIT_OK;
}

static MunitResult dependency_context(const MunitParameter params[], void* user)
{
  const uint8_t encoded[] = {1,2};
  const TC_bytes certificate = {encoded,sizeof encoded};
  const TC_X509_path_options options = {0};
  const TC_X509_path_workspace validation = {0};
  const TC_X509_trust_anchor anchor = {0};
  TC_X509_revocation_node nodes[1] = {0};
  tc_x509_crl_resolution_workspace workspace = {0};
  workspace.validation = &validation; workspace.nodes = nodes; workspace.node_capacity = 1;
  tc_x509_crl_dependencies dependencies = {&options,0,&workspace,&anchor,NULL,0,0};
  TC_X509_search_result path = {0};
  size_t work = 100, index = SIZE_MAX;
  (void)params; (void)user;
  munit_assert_int(tc_x509_crl_dependencies_check(NULL,&path,NULL,&work), ==, TC_X509_PATH_ERROR);
  munit_assert_int(tc_x509_crl_dependencies_check(&dependencies,&path,NULL,&work), ==, TC_X509_PATH_UNSUPPORTED);
  path.anchor_index = 1;
  munit_assert_int(tc_x509_crl_dependencies_check(&dependencies,&path,NULL,&work), ==, TC_X509_PATH_ERROR);
  munit_assert_size(work, ==, 100);
  munit_assert_int(tc_x509_crl_dependency_add(&dependencies,certificate,&work,&index), ==, TC_TLV_OK);
  munit_assert_size(index, ==, 0);
  munit_assert_size(dependencies.count, ==, 1);
  munit_assert_ptr_equal(nodes[0].certificate.data,encoded);
  const TC_X509_revocation_node saved = nodes[0];
  dependencies.writes = &certificate; dependencies.write_count = 1;
  index = SIZE_MAX;
  munit_assert_int(tc_x509_crl_dependency_add(&dependencies,certificate,&work,&index), ==, TC_TLV_ARGUMENT);
  munit_assert_size(index, ==, SIZE_MAX);
  munit_assert_size(dependencies.count, ==, 1);
  munit_assert_memory_equal(sizeof saved,nodes,&saved);
  dependencies.writes = NULL;
  munit_assert_int(tc_x509_crl_dependency_add(&dependencies,certificate,&work,&index), ==, TC_TLV_ARGUMENT);
  dependencies.write_count = 0; work = 0;
  munit_assert_int(tc_x509_crl_dependency_add(&dependencies,certificate,&work,&index), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof saved,nodes,&saved);
  munit_assert_size(index, ==, SIZE_MAX);
  return MUNIT_OK;
}

static MunitResult dependency_read(const MunitParameter params[], void* user)
{
  enum { FRAME_CAPACITY = 8, OID_CAPACITY = 8, WORK_BUDGET = 100, ELEMENT_LIMIT = 20 };
  enum { TRUNCATED, BAD_INDEX, BAD_COUNT, MISSING_TREE, MISSING_BYTES, NO_WORK, CASE_COUNT };
  const uint8_t encoded[] = {0x30};
  TC_TLV_frame frames[FRAME_CAPACITY]; TC_bytes oids[OID_CAPACITY];
  TC_X509_path_options options = {0};
  options.parsing = (TC_TLV_limits){WORK_BUDGET,WORK_BUDGET,ELEMENT_LIMIT,FRAME_CAPACITY};
  TC_X509_path_workspace validation = {0};
  validation.frames = frames; validation.frame_capacity = FRAME_CAPACITY;
  validation.oids = oids; validation.oid_capacity = OID_CAPACITY;
  TC_X509_certificate out, saved;
  memset(&saved,0xa5,sizeof saved);
  (void)params; (void)user;
  for (unsigned scenario = TRUNCATED; scenario < CASE_COUNT; ++scenario) {
    size_t work = scenario == NO_WORK ? 0 : WORK_BUDGET;
    const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
    TC_X509_revocation_node node = {{encoded,sizeof encoded},TC_X509_CRL_UNDETERMINED};
    tc_x509_crl_resolution_workspace workspace = {0};
    workspace.tree = &tree; workspace.validation = &validation;
    workspace.nodes = &node; workspace.node_capacity = 1;
    tc_x509_crl_dependencies dependencies = {0};
    dependencies.options = &options; dependencies.workspace = &workspace; dependencies.count = 1;
    size_t index = 0;
    TC_TLV_result expected = TC_TLV_ARGUMENT;
    switch (scenario) {
      case TRUNCATED: expected = TC_TLV_MORE; break;
      case BAD_INDEX: index = 1; break;
      case BAD_COUNT: dependencies.count = 2; break;
      case MISSING_TREE: workspace.tree = NULL; break;
      case MISSING_BYTES: node.certificate.data = NULL; break;
      case NO_WORK: expected = TC_TLV_LIMIT; break;
    }
    out = saved;
    munit_assert_int(tc_x509_crl_dependency_read(&dependencies,index,&out), ==, expected);
    munit_assert_memory_equal(sizeof out,&out,&saved);
  }
  return MUNIT_OK;
}

static MunitResult extra_inputs(const MunitParameter params[], void* user)
{
  enum { VALID, RESOLUTION_OVERLAP, WORKSPACE_OVERLAP, NODE_OVERLAP, MISSING_NODES,
    NO_WORK, CASE_COUNT };
  const uint8_t encoded[] = {1,2};
  uint8_t scratch;
  const TC_bytes writes = {&scratch,sizeof scratch};
  (void)params; (void)user;
  for (unsigned scenario = VALID; scenario < CASE_COUNT; ++scenario) {
    TC_X509_revocation_node node;
    tc_x509_crl_extra_storage extra;
    memset(&node,0,sizeof node);
    memset(&extra,0,sizeof extra);
    node.certificate = (TC_bytes){encoded,sizeof encoded};
    node.status = TC_X509_CRL_UNDETERMINED;
    extra.nodes = &node; extra.count = 1;
    extra.inputs[CRL_EXTRA_RESOLUTION] = node.certificate;
    extra.inputs[CRL_EXTRA_WORKSPACE] = node.certificate;
    size_t work = scenario == NO_WORK ? 0 : 100;
    switch (scenario) {
      case RESOLUTION_OVERLAP: extra.inputs[CRL_EXTRA_RESOLUTION] = writes; break;
      case WORKSPACE_OVERLAP: extra.inputs[CRL_EXTRA_WORKSPACE] = writes; break;
      case NODE_OVERLAP: node.certificate = writes; break;
      case MISSING_NODES: extra.nodes = NULL; break;
      default: break;
    }
    const tc_x509_crl_extra_storage saved = extra;
    const TC_X509_revocation_node saved_node = node;
    munit_assert_int(tc_x509_crl_extra_storage_inputs(&extra,&writes,1,&work), ==,
        scenario == VALID ? TC_TLV_OK : scenario == NO_WORK ? TC_TLV_LIMIT : TC_TLV_ARGUMENT);
    munit_assert_memory_equal(sizeof extra,&extra,&saved);
    munit_assert_memory_equal(sizeof node,&node,&saved_node);
  }
  return MUNIT_OK;
}

static MunitResult resolve_dependencies(const MunitParameter params[], void* user)
{
  enum { NEW_CHAIN, CACHED, CYCLE, OVERLAP, NO_WORK, CASE_COUNT };
  const uint8_t first[] = {1,2}, second[] = {1,3};
  const TC_bytes target = {first,sizeof first};
  (void)params; (void)user;
  for (unsigned scenario = NEW_CHAIN; scenario < CASE_COUNT; ++scenario) {
    TC_X509_revocation_node nodes[2] = {
      {target,TC_X509_CRL_UNDETERMINED},{{second,sizeof second},TC_X509_CRL_UNDETERMINED}};
    size_t work = scenario == NO_WORK ? 0 : 100;
    const tc_pki_tree_workspace tree = {NULL,0,&work};
    tc_x509_crl_resolution_workspace workspace = {0};
    workspace.tree = &tree; workspace.nodes = nodes; workspace.node_capacity = 2;
    tc_x509_crl_dependencies dependencies = {0}; dependencies.workspace = &workspace;
    tc_x509_crl_held_path path = {0};
    if (scenario == CACHED || scenario == NO_WORK) dependencies.count = path.dependency_count = 1;
    if (scenario == CACHED) nodes[0].status = TC_X509_CRL_UNREVOKED;
    if (scenario == OVERLAP) { dependencies.writes = &target; dependencies.write_count = 1; }
    const size_t initial_count = path.dependency_count;
    resolution_fixture state = {nodes,&dependencies.count,&work,
      scenario == CYCLE ? RESOLVE_CYCLE : RESOLVE_CHAIN,0};
    tc_x509_crl_evidence out, saved;
    memset(&saved,0xa5,sizeof saved); out = saved;
    const TC_TLV_result expected = scenario == CYCLE ? TC_TLV_UNSUPPORTED :
        scenario == OVERLAP ? TC_TLV_ARGUMENT : scenario == NO_WORK ? TC_TLV_LIMIT : TC_TLV_OK;
    munit_assert_int(tc_x509_crl_resolve_dependencies(target,&dependencies,evaluate_node,&state,&path,&out),
        ==, expected);
    if (expected == TC_TLV_OK) {
      munit_assert_uint(out.reasons, ==, TC_X509_CRL_ALL_REASONS);
      munit_assert_size(path.dependency_count, ==, scenario == CACHED ? 1 : 2);
    } else {
      munit_assert_memory_equal(sizeof out,&out,&saved);
      munit_assert_size(path.dependency_count, ==, initial_count);
    }
    munit_assert_uint(state.calls, ==, scenario == NEW_CHAIN ? 3 : scenario == CYCLE ? 1 : 0);
  }
  return MUNIT_OK;
}

static MunitResult scope_arguments(const MunitParameter params[], void* user)
{
  enum { VALID, BAD_CA, MISSING_QUERY, MISSING_RECORDS, BAD_DELTA, BAD_ORDER, MISSING_STATES,
    SHORT_STATES, MISSING_CHECK, BAD_REFERENCE, RECORD_POLICY, DETERMINED, BAD_EVIDENCE, CASE_COUNT };
  const TC_X509_path_options options = {0};
  const TC_X509_path_workspace validation = {0};
  const TC_X509_search_workspace search = {0};
  const TC_X509_store_source source = {NULL,0,1,NULL,tc_pki_source_guard_anchor};
  const TC_X509_certificate certificate = {0};
  const tc_pki_distribution_point point = {0};
  const tc_x509_crl_path_check check = {0};
  TC_X509_search_result out, saved;
  memset(&saved,0xa5,sizeof saved);
  (void)params; (void)user;
  for (unsigned scenario = VALID; scenario < CASE_COUNT; ++scenario) {
    size_t work = 100;
    const tc_pki_tree_workspace tree = {NULL,0,&work};
    const tc_x509_crl_trust trust = {&source,0,&options,&tree,&validation,&search};
    TC_X509_crl_record record = {0}; record.policy = TC_TLV_OK;
    TC_X509_crl_index index = {0}; index.records = &record; index.count = 1;
    tc_x509_crl_query query = {&certificate,&point,0};
    tc_x509_crl_evidence evidence = {0};
    uint8_t state = 0;
    tc_x509_crl_scope_processing processing = {&index,0,TC_X509_CRL_COMPLETE_ONLY,
      TC_X509_CRL_ORDER_NUMBER,&query,&state,1,&evidence,NULL,NULL,NULL};
    TC_TLV_result expected = TC_TLV_ARGUMENT;
    switch (scenario) {
      case VALID: expected = TC_TLV_OK; break;
      case BAD_CA: query.certificate_ca = 2; break;
      case MISSING_QUERY: processing.query = NULL; break;
      case MISSING_RECORDS: index.records = NULL; break;
      case BAD_DELTA: processing.delta_policy = (TC_X509_crl_delta_policy)-1; break;
      case BAD_ORDER: processing.order_policy = (TC_X509_crl_order_policy)-1; break;
      case MISSING_STATES: processing.states = NULL; break;
      case SHORT_STATES: processing.capacity = 0; expected = TC_TLV_LIMIT; break;
      case MISSING_CHECK: processing.check = &check; break;
      case BAD_REFERENCE: processing.reference = index.count; break;
      case RECORD_POLICY: record.policy = expected = TC_TLV_UNSUPPORTED; break;
      case DETERMINED: evidence.reasons = TC_X509_CRL_ALL_REASONS; expected = TC_TLV_END; break;
      case BAD_EVIDENCE: evidence.revocation.found = 2; break;
    }
    out = saved;
    munit_assert_int(tc_x509_crl_scope_arguments(&processing,&trust,0,&out), ==, expected);
    munit_assert_memory_equal(sizeof out,&out,&saved);
    munit_assert_size(work, ==, 100);
    munit_assert_uint(state, ==, 0);
  }
  return MUNIT_OK;
}

static MunitResult scope_storage_check(const MunitParameter params[], void* user)
{
  enum { VALID, EMPTY, NODE_OVERLAP, OUTPUT_OVERLAP, PATH_OVERLAP, MISSING_PATH_OUTPUT,
    BAD_SPAN, NO_WORK, CASE_COUNT };
  uint8_t bytes[3];
  TC_X509_revocation_result output = {0};
  (void)params; (void)user;
  for (unsigned scenario = VALID; scenario < CASE_COUNT; ++scenario) {
    TC_bytes writes[CRL_SCOPE_WRITES] = {{NULL,0}};
    const TC_bytes prefix = {bytes,1};
    writes[0] = prefix;
    tc_x509_crl_extra_storage extra = {0};
    extra.nodes_storage = (TC_bytes){bytes + 1,1};
    extra.output_storage = (TC_bytes){bytes + 2,1};
    tc_x509_crl_held_path path = {0}; path.out = &output;
    size_t work = scenario == NO_WORK ? 0 : 1000;
    switch (scenario) {
      case NODE_OVERLAP: extra.nodes_storage = prefix; break;
      case OUTPUT_OVERLAP: extra.output_storage = extra.nodes_storage; break;
      case PATH_OVERLAP: extra.output_storage = (TC_bytes){(const uint8_t*)&output,sizeof output}; break;
      case MISSING_PATH_OUTPUT: path.out = NULL; break;
      case BAD_SPAN: extra.nodes_storage.data = NULL; break;
      default: break;
    }
    munit_assert_int(tc_x509_crl_scope_storage_check(scenario == EMPTY ? NULL : &extra,
        scenario == EMPTY ? NULL : &path,writes,&work), ==,
        scenario == VALID || scenario == EMPTY ? TC_TLV_OK :
        scenario == NO_WORK ? TC_TLV_LIMIT : TC_TLV_ARGUMENT);
    munit_assert_ptr_equal(writes[0].data,prefix.data);
    munit_assert_size(writes[0].length, ==, prefix.length);
    if (scenario == VALID) {
      munit_assert_ptr_equal(writes[CRL_SCOPE_NODES].data,extra.nodes_storage.data);
      munit_assert_ptr_equal(writes[CRL_SCOPE_OUTPUT].data,extra.output_storage.data);
      munit_assert_ptr_equal(writes[CRL_SCOPE_PATH_OUTPUT].data,&output);
      munit_assert_size(writes[CRL_SCOPE_PATH_OUTPUT].length, ==, sizeof output);
    } else if (scenario == EMPTY) {
      munit_assert_size(writes[CRL_SCOPE_NODES].length, ==, 0);
      munit_assert_size(writes[CRL_SCOPE_OUTPUT].length, ==, 0);
      munit_assert_size(writes[CRL_SCOPE_PATH_OUTPUT].length, ==, 0);
    }
  }
  return MUNIT_OK;
}

typedef struct {
  TC_TLV_result result;
  TC_bytes encoded;
  unsigned calls;
} store_search_fixture;

static TC_TLV_result store_search_record(void* context, size_t index, size_t* work, TC_bytes* out)
{
  store_search_fixture* fixture = context;
  (void)index; (void)work;
  ++fixture->calls;
  if (fixture->result == TC_TLV_OK) *out = fixture->encoded;
  return fixture->result;
}

static MunitResult store_search(const MunitParameter params[], void* user)
{
  enum { FRAME_CAPACITY = 8, WORK_BUDGET = 100, ELEMENT_LIMIT = 20 };
  enum { EMPTY, NO_RECORDS, NO_BYTES, READ_LIMIT, READ_ERROR, TRUNCATED, BAD_INDEX, NO_WORK, CASE_COUNT };
  const TC_TLV_result expected[] = {TC_TLV_INVALID,TC_TLV_LIMIT,TC_TLV_LIMIT,TC_TLV_LIMIT,
    TC_TLV_ARGUMENT,TC_TLV_MORE,TC_TLV_ARGUMENT,TC_TLV_LIMIT};
  const uint8_t encoded[] = {0x30};
  const tc_x509_crl crl = {0};
  const tc_x509_crl_extension_info extensions = {0};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_X509_path_options options = {0};
  options.parsing = (TC_TLV_limits){WORK_BUDGET,WORK_BUDGET,ELEMENT_LIMIT,FRAME_CAPACITY};
  TC_X509_path_workspace validation = {0};
  validation.frames = frames; validation.frame_capacity = FRAME_CAPACITY;
  const TC_X509_search_workspace search = {0};
  TC_X509_search_result out, saved;
  memset(&saved,0xa5,sizeof saved);
  (void)params; (void)user;
  for (unsigned scenario = EMPTY; scenario < CASE_COUNT; ++scenario) {
    size_t work = scenario == NO_WORK ? 0 : WORK_BUDGET;
    const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
    store_search_fixture fixture = {TC_TLV_OK,{encoded,sizeof encoded},0};
    TC_X509_store_source source = {&fixture,1,1,store_search_record,tc_pki_source_guard_anchor};
    const tc_x509_crl_trust trust = {&source,0,&options,&tree,&validation,&search};
    tc_pki_store_candidates cursor = {&source,options.parsing,0,1,sizeof encoded};
    switch (scenario) {
      case EMPTY: source.candidate_count = 0; break;
      case NO_RECORDS: cursor.remaining = 0; break;
      case NO_BYTES: cursor.bytes_left = 0; break;
      case READ_LIMIT: fixture.result = TC_TLV_LIMIT; break;
      case READ_ERROR: fixture.result = TC_TLV_INVALID; break;
      case BAD_INDEX: cursor.index = 2; break;
      default: break;
    }
    const tc_pki_store_candidates initial = cursor;
    int failed = 0;
    out = saved;
    munit_assert_int(tc_x509_crl_store_search(&cursor,&crl,&extensions,&trust,
        tc_x509_crl_check_signer,NULL,&out,&failed), ==, expected[scenario]);
    munit_assert_memory_equal(sizeof cursor,&cursor,&initial);
    munit_assert_memory_equal(sizeof out,&out,&saved);
    munit_assert_int(failed, ==, scenario != EMPTY);
    munit_assert_uint(fixture.calls, ==,
        scenario == EMPTY || scenario == NO_RECORDS || scenario == BAD_INDEX || scenario == NO_WORK ? 0 : 1);
    /* The bound operation supplies its guarded source without changing the snapshot. */
    cursor.source = NULL;
    const tc_pki_store_candidates unbound = cursor;
    tc_x509_crl_candidate_source bound = {&cursor,&source,tc_x509_crl_store_source_search};
    fixture.calls = 0; failed = 0; work = scenario == NO_WORK ? 0 : WORK_BUDGET;
    out = saved;
    munit_assert_int(tc_x509_crl_source_search(&bound,&crl,&extensions,&trust,
        tc_x509_crl_check_signer,NULL,&out,&failed), ==, expected[scenario]);
    munit_assert_memory_equal(sizeof cursor,&cursor,&unbound);
    munit_assert_memory_equal(sizeof out,&out,&saved);
    munit_assert_int(failed, ==, scenario != EMPTY);
    munit_assert_uint(fixture.calls, ==,
        scenario == EMPTY || scenario == NO_RECORDS || scenario == BAD_INDEX || scenario == NO_WORK ? 0 : 1);
    bound.search = NULL;
    const unsigned calls = fixture.calls;
    munit_assert_int(tc_x509_crl_source_search(&bound,&crl,&extensions,&trust,
        tc_x509_crl_check_signer,NULL,&out,&failed), ==, TC_TLV_ARGUMENT);
    munit_assert_uint(fixture.calls, ==, calls);
    munit_assert_memory_equal(sizeof out,&out,&saved);
  }
  return MUNIT_OK;
}

static TC_TLV_result guarded_scope_search(const void* candidates, const TC_X509_store_source* external,
    const tc_x509_crl* crl, const tc_x509_crl_extension_info* extensions,
    const tc_x509_crl_trust* trust, tc_x509_crl_attempt attempt, const void* context,
    TC_X509_search_result* out, int* source_failed)
{
  (void)crl; (void)extensions; (void)attempt; (void)context; (void)out; (void)source_failed;
  munit_assert_ptr_not_equal(external,candidates);
  munit_assert_ptr_not_equal(trust->source,candidates);
  TC_bytes encoded;
  TC_TLV_result result = tc_pki_source_candidate(external,0,trust->tree->work,&encoded);
  return result == TC_TLV_OK ? TC_TLV_END : result;
}

static MunitResult scope_operation(const MunitParameter params[], void* user)
{
  enum { FRAME_CAPACITY = 8, WORK_BUDGET = 10000, ELEMENT_LIMIT = 20 };
  enum { VALID, OVERLAP, MISSING_ADAPTER, BAD_POINTS, NO_WORK, CASE_COUNT };
  const uint8_t issuer[] = {0x30,0}, encoded[] = {1,2}, bad_points[] = {0x30};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_X509_path_options options = {0};
  options.parsing = (TC_TLV_limits){WORK_BUDGET,WORK_BUDGET,ELEMENT_LIMIT,FRAME_CAPACITY};
  TC_X509_path_workspace validation = {0};
  validation.frames = frames; validation.frame_capacity = FRAME_CAPACITY;
  const TC_X509_search_workspace search = {0};
  TC_X509_search_result out, saved;
  memset(&saved,0xa5,sizeof saved);
  (void)params; (void)user;
  for (unsigned scenario = VALID; scenario < CASE_COUNT; ++scenario) {
    size_t work = scenario == NO_WORK ? 0 : WORK_BUDGET;
    const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
    store_search_fixture fixture = {TC_TLV_OK,{encoded,sizeof encoded},0};
    const TC_X509_store_source external = {&fixture,1,1,store_search_record,tc_pki_source_guard_anchor};
    const tc_x509_crl_trust trust = {&external,0,&options,&tree,&validation,&search};
    tc_x509_crl_candidate_source adapter = {&external,&external,guarded_scope_search};
    TC_X509_certificate certificate = {0}; certificate.issuer = (TC_bytes){issuer,sizeof issuer};
    const tc_pki_distribution_point point = {0};
    const tc_x509_crl_query query = {&certificate,&point,0};
    TC_X509_crl_record record = {0}; record.crl.issuer = certificate.issuer; record.policy = TC_TLV_OK;
    TC_X509_crl_index index = {0}; index.records = &record; index.count = 1;
    tc_x509_crl_evidence evidence = {0};
    const tc_x509_crl_evidence initial = evidence;
    uint8_t state = 0;
    const tc_x509_crl_scope_processing processing = {&index,0,TC_X509_CRL_COMPLETE_ONLY,
      TC_X509_CRL_ORDER_NUMBER,&query,&state,1,&evidence,NULL,NULL,NULL};
    TC_bytes metadata[] = {
      scenario == OVERLAP ? (TC_bytes){&state,sizeof state} :
        (TC_bytes){(const uint8_t*)&external,sizeof external},
      fixture.encoded
    };
    if (scenario == MISSING_ADAPTER) adapter.search = NULL;
    const tc_x509_crl_operation_source source = {
      adapter,metadata,sizeof metadata / sizeof *metadata
    };
    const TC_bytes points = {bad_points,sizeof bad_points};
    out = saved;
    munit_assert_int(tc_x509_crl_scope_execute(&source,&processing,&trust,
        scenario == BAD_POINTS ? &points : NULL,0,0,NULL,NULL,&out), ==,
        scenario == VALID ? TC_TLV_END : scenario == BAD_POINTS ? TC_TLV_MORE :
        scenario == NO_WORK ? TC_TLV_LIMIT : TC_TLV_ARGUMENT);
    munit_assert_uint(fixture.calls, ==, scenario == VALID ? 1 : 0);
    munit_assert_memory_equal(sizeof out,&out,&saved);
    munit_assert_memory_equal(sizeof evidence,&evidence,&initial);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/trust-arguments",trust_arguments,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/signer-search",signer_search,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/dependencies",dependencies,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/dependency-status",dependency_status,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/dependency-failures",dependency_failures,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/resolution",resolution,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/held-path",held_path,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/storage-spans",storage_spans,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/record-storage",record_storage,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/scope-inputs",scope_inputs,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/scope-traversal",scope_traversal,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/path-inputs",path_inputs,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/dependency-context",dependency_context,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/dependency-read",dependency_read,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/extra-inputs",extra_inputs,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/resolve-dependencies",resolve_dependencies,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/scope-arguments",scope_arguments,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/scope-storage-check",scope_storage_check,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/store-search",store_search,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/scope-operation",scope_operation,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/x509/revocation",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
