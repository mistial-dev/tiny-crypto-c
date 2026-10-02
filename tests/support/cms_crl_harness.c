/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Test harness: CMS revocation collections and CRL processing built on the
 * library's X.509 CRL functions. CMS validation ignores embedded revocation
 * information, so this code is outside the shipped library. The tests use it
 * to drive CRL indexing, scope selection, signer search and resolution. */
#include "cms_crl_harness.h"

/* SignerInfo-based candidate filter over the shared collection iterator. */
typedef struct {
  const TC_CMS_signer_info* signer;
  TC_TLV_profile profile;
  const TC_X509_name_workspace* names;
} harness_signer_filter;

static TC_TLV_result harness_signer_candidate(const void* context,
                                              const TC_X509_certificate* candidate,
                                              const TC_TLV_limits* limits,
                                              const tc_pki_tree_workspace* tree, int* matched)
{
  const harness_signer_filter* filter = context;
  return tc_cms_signer_matches(filter->signer, filter->profile, candidate, limits, filter->names,
                               tree, matched);
}

TC_TLV_result tc_cms_signer_candidate_next(tc_cms_candidates* reader,
                                           const TC_CMS_signer_info* signer, TC_TLV_profile profile,
                                           const TC_X509_name_workspace* names,
                                           const tc_pki_tree_workspace* tree,
                                           const TC_X509_workspace* parser,
                                           TC_X509_certificate* scratch, TC_bytes* out)
{
  const harness_signer_filter filter = {signer, profile, names};
  if (!signer || (profile != TC_TLV_DER && profile != TC_TLV_BER))
    return TC_TLV_ARGUMENT;
  return tc_cms_x509_candidate_next(reader, harness_signer_candidate, &filter, tree, parser,
                                    scratch, out);
}

TC_TLV_result tc_cms_revocations_init(TC_bytes embedded, const tc_pki_record_source* external,
                                      size_t max_records, size_t max_bytes,
                                      const TC_TLV_limits* limits,
                                      const tc_pki_tree_workspace* tree, tc_cms_revocations* out)
{
  tc_cms_revocations parsed;
  TC_TLV_result result;
  if (!out || (external && external->count && !external->read))
    return TC_TLV_ARGUMENT;
  result = tc_cms_collection_init(embedded, 0xa1, max_records, max_bytes, limits, tree,
                                  &parsed.collection);
  if (result != TC_TLV_OK)
    return result;
  parsed.external = external;
  *out = parsed;
  return TC_TLV_OK;
}

TC_TLV_result tc_cms_revocations_next(tc_cms_revocations* reader, const tc_pki_tree_workspace* tree,
                                      tc_cms_revocation_choice* out)
{
  tc_cms_revocations next;
  tc_cms_revocation_choice choice = {{NULL, 0}, TC_CMS_REVOCATION_CRL};
  TC_TLV_element element;
  TC_TLV_result result;
  int embedded;
  if (!reader || !out)
    return TC_TLV_ARGUMENT;
  next = *reader;
  result = tc_cms_collection_next(&next.collection, next.external, tree, &element, &embedded);
  if (result != TC_TLV_OK)
    return result;
  if (embedded && !tc_pki_tag(&element, 0x30)) {
    tc_cms_other_format other;
    if (!tc_pki_tag(&element, 0xa1))
      return TC_TLV_INVALID;
    result = tc_cms_other_format_read(element.encoded, TC_CMS_OTHER_REVOCATION,
                                      &next.collection.embedded.limits, tree, &other);
    if (result != TC_TLV_OK)
      return result;
    choice.kind = TC_CMS_REVOCATION_OTHER;
  }
  choice.encoded = element.encoded;
  *reader = next;
  *out = choice;
  return TC_TLV_OK;
}

TC_TLV_result tc_cms_crl_index_init(const tc_cms_revocations* reader,
                                    const tc_pki_tree_workspace* tree, TC_bytes* oids,
                                    size_t oid_capacity, TC_X509_crl_record* records,
                                    size_t capacity, TC_X509_crl_index* out)
{
  enum { CRL_ROWS, CRL_OIDS, CRL_FRAMES, CRL_WORK, CRL_OUTPUT, CRL_WRITES };
  tc_cms_revocations next;
  tc_cms_revocation_choice choice;
  TC_X509_crl_index index = {records, 0, 0};
  TC_bytes writes[CRL_WRITES];
  TC_TLV_result result;
  if (!reader || !tree || !tree->work || !out)
    return TC_TLV_ARGUMENT;
  tc_pki_storage_plan plan;
  tc_pki_storage_plan_begin(&plan, writes, CRL_WRITES, *tree->work);
  TC_PKI_PLAN_WRITE(&plan, records, capacity);
  TC_PKI_PLAN_WRITE(&plan, oids, oid_capacity);
  TC_PKI_PLAN_WRITE(&plan, tree->frames, tree->capacity);
  TC_PKI_PLAN_WRITE(&plan, tree->work, 1);
  TC_PKI_PLAN_WRITE(&plan, out, 1);
  tc_pki_storage_plan_seal(&plan);
  TC_PKI_PLAN_INPUT(&plan, reader, 1);
  TC_PKI_PLAN_INPUT(&plan, tree, 1);
  if (reader->external)
    TC_PKI_PLAN_INPUT(&plan, reader->external, 1);
  tc_pki_storage_plan_input_span(&plan, reader->collection.embedded.input);
  /* Keep bookkeeping private until work is known to be disjoint from inputs. */
  result = tc_pki_storage_plan_finish(&plan, tree->work);
  if (result != TC_TLV_OK)
    return result;
  tc_pki_record_guard guard = {reader->external, writes, CRL_WRITES};
  const tc_pki_record_source guarded = {&guard, reader->external ? reader->external->count : 0,
                                        tc_pki_record_guard_read};
  next = *reader;
  if (reader->external)
    next.external = &guarded;
  while ((result = tc_cms_revocations_next(&next, tree, &choice)) == TC_TLV_OK) {
    if (choice.kind == TC_CMS_REVOCATION_OTHER) {
      ++index.other_count;
      continue;
    }
    if (index.count == capacity)
      return TC_TLV_LIMIT;
    TC_X509_crl_record* record = &records[index.count];
    result = tc_x509_crl_record_read(choice.encoded, &next.collection.embedded.limits, tree, oids,
                                     oid_capacity, record);
    if (result != TC_TLV_OK)
      return result;
    ++index.count;
  }
  if (result != TC_TLV_END)
    return result;
  *out = index;
  return TC_TLV_OK;
}

TC_TLV_result tc_cms_crl_source_search(const void* candidates, const TC_X509_store_source* external,
                                       const tc_x509_crl_signer_query* query,
                                       const tc_x509_crl_trust* trust, TC_X509_search_report* out,
                                       int* source_failed)
{
  if (!candidates)
    return TC_TLV_ARGUMENT;
  tc_cms_candidate_cursor storage;
  void* cursor;
  const tc_pki_candidate_next next = tc_cms_candidate_cursor_init(candidates, &storage, &cursor);
  if (next == tc_pki_store_candidate_next)
    storage.store.source = external;
  else
    storage.collection.external = external;
  return tc_x509_crl_search_candidates(cursor, next, query, trust, out, source_failed);
}

TC_TLV_result tc_cms_crl_search(const void* candidates, const tc_x509_crl_signer_query* query,
                                const tc_x509_crl_trust* trust, TC_X509_search_report* out,
                                int* source_failed)
{
  const tc_cms_candidates* source = candidates;
  if (!source)
    return TC_TLV_ARGUMENT;
  return tc_cms_crl_source_search(source, source->external, query, trust, out, source_failed);
}

TC_TLV_result tc_cms_crl_signer_candidate_next(tc_cms_candidates* reader, const TC_X509_crl* crl,
                                               const TC_X509_crl_extensions* extensions,
                                               const TC_X509_name_workspace* names,
                                               const tc_pki_tree_workspace* tree,
                                               const TC_X509_workspace* parser,
                                               TC_X509_certificate* scratch, TC_bytes* out)
{
  const tc_x509_crl_filter filter = {crl, extensions, names};
  if (!crl || !extensions || !names)
    return TC_TLV_ARGUMENT;
  return tc_cms_x509_candidate_next(reader, tc_x509_crl_filter_match, &filter, tree, parser,
                                    scratch, out);
}

TC_X509_path_status tc_cms_crl_signer_find(const tc_cms_candidates* candidates,
                                           const TC_X509_crl* crl,
                                           const TC_X509_crl_extensions* extensions,
                                           const tc_x509_crl_trust* trust,
                                           TC_X509_search_report* out)
{
  return tc_x509_path_status(tc_cms_crl_search(
      candidates, &(tc_x509_crl_signer_query){crl, extensions, tc_x509_crl_check_signer, crl},
      trust, out, NULL));
}

static TC_TLV_result cms_crl_operation_source(const tc_cms_candidates* candidates,
                                              tc_pki_store_candidates* store, TC_bytes metadata[3],
                                              tc_x509_crl_operation_source* out);

/* Run one scope operation through the library's shared executor. */
static TC_TLV_result cms_crl_scope_run(const tc_cms_candidates* candidates,
                                       const tc_x509_crl_scope_processing* processing,
                                       const tc_x509_crl_trust* trust,
                                       const tc_x509_crl_scope_selection* selection,
                                       TC_X509_search_report* out)
{
  if (!candidates)
    return TC_TLV_ARGUMENT;
  tc_pki_store_candidates store;
  TC_bytes metadata[3];
  tc_x509_crl_operation_source source;
  TC_TLV_result result = cms_crl_operation_source(candidates, &store, metadata, &source);
  if (result != TC_TLV_OK)
    return result;
  return tc_x509_crl_scope_execute(&source, processing, trust, selection, out);
}

TC_TLV_result tc_cms_crl_scope_process(const tc_cms_candidates* candidates,
                                       const tc_x509_crl_scope_processing* processing,
                                       const tc_x509_crl_trust* trust, TC_X509_search_report* out)
{
  if (!processing)
    return TC_TLV_ARGUMENT;
  return cms_crl_scope_run(candidates, processing, trust,
                           &(tc_x509_crl_scope_selection){NULL, 0, 0}, out);
}

TC_TLV_result tc_cms_crl_point_process(const tc_cms_candidates* candidates,
                                       const tc_x509_crl_scope_processing* processing,
                                       const tc_x509_crl_trust* trust)
{
  TC_X509_search_report scratch;
  if (!processing || !processing->check || !processing->check->verify)
    return TC_TLV_ARGUMENT;
  return cms_crl_scope_run(candidates, processing, trust,
                           &(tc_x509_crl_scope_selection){NULL, 0, 1}, &scratch);
}

TC_TLV_result tc_cms_crl_points_process(const tc_cms_candidates* candidates,
                                        const tc_x509_crl_scope_processing* processing,
                                        TC_bytes points, const tc_x509_crl_trust* trust)
{
  TC_X509_search_report scratch;
  if (!processing || !processing->check || !processing->check->verify)
    return TC_TLV_ARGUMENT;
  return cms_crl_scope_run(candidates, processing, trust,
                           &(tc_x509_crl_scope_selection){&points, 0, 1}, &scratch);
}

TC_TLV_result tc_cms_crl_certificate_process(const tc_cms_candidates* candidates,
                                             const tc_x509_crl_scope_processing* processing,
                                             const TC_X509_certificate* certificate,
                                             const tc_x509_crl_trust* trust)
{
  TC_X509_search_report scratch;
  const tc_pki_distribution_point fallback = {0};
  const tc_x509_crl_query query = {certificate, &fallback, 0};
  if (!processing || !processing->check || !processing->check->verify)
    return TC_TLV_ARGUMENT;
  tc_x509_crl_scope_processing with_query = *processing;
  with_query.query = &query;
  return cms_crl_scope_run(candidates, &with_query, trust,
                           &(tc_x509_crl_scope_selection){NULL, 1, 1}, &scratch);
}

static TC_TLV_result cms_crl_operation_source(const tc_cms_candidates* candidates,
                                              tc_pki_store_candidates* store, TC_bytes metadata[3],
                                              tc_x509_crl_operation_source* out)
{
  if (!candidates || !store || !metadata || !out)
    return TC_TLV_ARGUMENT;
  tc_x509_crl_candidate_source adapter = {candidates, candidates->external,
                                          tc_cms_crl_source_search};
  if (candidates->external && tc_pki_end(&candidates->collection.embedded)) {
    *store = tc_cms_store_cursor(candidates);
    adapter.context = store;
    adapter.search = tc_x509_crl_store_source_search;
  }
  size_t count = 0;
  TC_TLV_result result = tc_pki_storage_span(candidates, 1, sizeof *candidates, &metadata[count++]);
  if (result != TC_TLV_OK)
    return result;
  if (candidates->external) {
    result = tc_pki_storage_span(candidates->external, 1, sizeof *candidates->external,
                                 &metadata[count++]);
    if (result != TC_TLV_OK)
      return result;
  }
  metadata[count++] = candidates->collection.embedded.input;
  *out = (tc_x509_crl_operation_source){adapter, metadata, count};
  return TC_TLV_OK;
}

static TC_TLV_result cms_crl_resolution_init(const tc_cms_crl_resolution* input,
                                             tc_pki_store_candidates* store, TC_bytes metadata[3],
                                             tc_x509_crl_operation_source* source,
                                             TC_X509_revocation_time* time,
                                             tc_x509_crl_resolution* out)
{
  if (!input || !input->options || !out)
    return TC_TLV_ARGUMENT;
  /* The harness evaluates CRL freshness at the signer policy time. */
  *time = (TC_X509_revocation_time){input->options->at, 0, 0};
  TC_TLV_result result = cms_crl_operation_source(input->candidates, store, metadata, source);
  if (result != TC_TLV_OK)
    return result;
  *out = (tc_x509_crl_resolution){source,
                                  input->index,
                                  input->source,
                                  input->options,
                                  input->anchor_index,
                                  input->delta_policy,
                                  input->order_policy,
                                  time};
  return TC_TLV_OK;
}

TC_TLV_result tc_cms_crl_resolve(const TC_X509_certificate* target,
                                 const tc_cms_crl_resolution* resolution,
                                 const tc_x509_crl_resolution_workspace* workspace,
                                 TC_X509_crl_evidence* out)
{
  tc_pki_store_candidates store;
  TC_bytes metadata[3];
  tc_x509_crl_operation_source source;
  tc_x509_crl_resolution operation;
  TC_X509_revocation_time time;
  TC_TLV_result result =
      cms_crl_resolution_init(resolution, &store, metadata, &source, &time, &operation);
  if (result != TC_TLV_OK)
    return result;
  return tc_x509_crl_resolve(target, &operation, workspace, out);
}

TC_TLV_result tc_cms_crl_path_resolve(const TC_bytes* chain, size_t count,
                                      const tc_cms_crl_resolution* resolution,
                                      const tc_x509_crl_resolution_workspace* workspace,
                                      TC_X509_revocation_report* out)
{
  tc_pki_store_candidates store;
  TC_bytes metadata[3];
  tc_x509_crl_operation_source source;
  tc_x509_crl_resolution operation;
  TC_X509_revocation_time time;
  TC_TLV_result result =
      cms_crl_resolution_init(resolution, &store, metadata, &source, &time, &operation);
  if (result != TC_TLV_OK)
    return result;
  tc_x509_crl_held_path held = {0};
  held.chain = chain;
  held.count = count;
  held.out = out;
  return tc_x509_crl_path_operation(&held, &operation, workspace);
}
