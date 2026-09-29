/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Test harness: X.509 CRL and path-search entry points that the library does
 * not call itself. Each wraps library functions, so tests can drive CRL
 * selection, matching and signer checks without shipping the wrappers. */
#include "x509_crl_harness.h"

#if TC_ENABLE_X509_REVOCATION
TC_TLV_result tc_x509_crl_entry_matches(const tc_x509_crl_revoked_entry* entry,
                                        const TC_X509_certificate* certificate,
                                        const TC_TLV_limits* limits,
                                        const tc_pki_tree_workspace* tree,
                                        const TC_X509_name_workspace* names, int* matched)
{
  if (!certificate)
    return TC_TLV_ARGUMENT;
  const TC_X509_crl_target query = {certificate->serial, certificate->issuer};
  return tc_x509_crl_query_matches(entry, &query, limits, tree, names, matched);
}

TC_TLV_result tc_x509_crl_process(const tc_x509_crl_selected* selected,
                                  const TC_X509_certificate* signer, const tc_x509_crl_query* query,
                                  const TC_X509_store_source* source, size_t anchor_index,
                                  const TC_X509_path_options* options,
                                  const TC_X509_path_workspace* validation,
                                  const TC_X509_search_workspace* search, size_t* work,
                                  TC_X509_crl_evidence* evidence, TC_X509_search_result* out)
{
  tc_pki_anchor_source anchor;
  TC_X509_store_source restricted;
  TC_X509_search_result found;
  tc_x509_crl_coverage coverage;
  TC_X509_revocation_status status;
  TC_TLV_result result;
  if (!selected || !selected->base || !selected->base_info || !signer || !query ||
      !query->certificate || !query->point || !options || !validation || !search || !work || !out ||
      (query->certificate_ca != 0 && query->certificate_ca != 1) ||
      !!selected->delta != !!selected->delta_info)
    return TC_TLV_ARGUMENT;
  result = tc_x509_crl_evidence_status(evidence, &status);
  if (result != TC_TLV_OK)
    return result;
  result = tc_pki_source_select_anchor(source, anchor_index, &anchor, &restricted);
  if (result != TC_TLV_OK)
    return result;
  if (status != TC_X509_CRL_UNDETERMINED)
    return TC_TLV_END;
  const size_t initial_work = *work;
  const tc_pki_tree_workspace tree = {validation->frames, validation->frame_capacity, work};
  result = tc_x509_crl_selected_coverage(
      selected, query, &options->at,
      &(tc_x509_crl_decode){&options->parsing, &tree, &validation->names, NULL, 0}, evidence,
      &coverage);
  if (result != TC_TLV_OK)
    return result;
  result = tc_x509_crl_selected_path(
      selected, signer,
      &(tc_x509_crl_trust){
          &restricted, anchor_index, options,
          &(tc_pki_tree_workspace){validation->frames, validation->frame_capacity, work},
          validation, search},
      &found);
  if (result != TC_TLV_OK)
    return result;
  /* Entry scans can be large; defer them until a signer path succeeds. */
  result = tc_x509_crl_selected_evidence(selected, query->certificate, coverage.reasons,
                                         &(tc_x509_crl_decode){&options->parsing, &tree,
                                                               &validation->names, validation->oids,
                                                               validation->oid_capacity},
                                         evidence);
  if (result != TC_TLV_OK)
    return result;
  found.validation.work_used = initial_work - *work;
  *out = found;
  return TC_TLV_OK;
}

TC_TLV_result
tc_x509_crl_selected_find(const tc_x509_crl_selected* selected, const TC_X509_certificate* signer,
                          const TC_X509_certificate* certificate,
                          const TC_X509_signature_provider* provider, const TC_TLV_limits* limits,
                          const tc_pki_tree_workspace* tree, const TC_X509_name_workspace* names,
                          TC_bytes* oids, size_t capacity, TC_X509_crl_match* out)
{
  TC_TLV_result result;
  if (!selected || !selected->base || !selected->base_info || !signer || !certificate || !limits ||
      !tree || !tree->work || !names || !out || !!selected->delta != !!selected->delta_info)
    return TC_TLV_ARGUMENT;
  result = tc_x509_crl_selected_authenticate(selected, signer, provider,
                                             &(tc_x509_crl_decode){limits, tree, names, NULL, 0});
  if (result != TC_TLV_OK)
    return result;
  return tc_x509_crl_selected_lookup(
      selected, certificate, &(tc_x509_crl_decode){limits, tree, names, oids, capacity}, out);
}

TC_TLV_result tc_x509_crl_selected_validate(const tc_x509_crl_selected* selected,
                                            const TC_X509_certificate* signer,
                                            const TC_X509_store_source* source, size_t anchor_index,
                                            const TC_X509_path_options* options,
                                            const TC_X509_path_workspace* validation,
                                            const TC_X509_search_workspace* search, size_t* work,
                                            TC_X509_search_result* out)
{
  tc_pki_anchor_source anchor;
  TC_X509_store_source restricted;
  TC_X509_search_result found;
  if (!selected || !selected->base || !selected->base_info || !signer || !options || !validation ||
      !search || !work || !out || !!selected->delta != !!selected->delta_info)
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = tc_pki_source_select_anchor(source, anchor_index, &anchor, &restricted);
  if (result != TC_TLV_OK)
    return result;
  const size_t initial_work = *work;
  result = tc_x509_crl_selected_path(
      selected, signer,
      &(tc_x509_crl_trust){
          &restricted, anchor_index, options,
          &(tc_pki_tree_workspace){validation->frames, validation->frame_capacity, work},
          validation, search},
      &found);
  if (result != TC_TLV_OK)
    return result;
  found.validation.work_used = initial_work - *work;
  *out = found;
  return TC_TLV_OK;
}

TC_X509_signature_result tc_x509_crl_signer_digest_check(
    const TC_X509_crl* crl, TC_hash_algorithm hash, TC_bytes digest,
    const TC_X509_certificate* signer, const TC_X509_signature_provider* provider,
    const TC_TLV_limits* limits, const TC_X509_name_workspace* names, size_t* work)
{
  if (!crl || !signer || !limits || !names || !work)
    return TC_X509_SIGNATURE_ERROR;
  if (!provider || !provider->verify_digest)
    return TC_X509_SIGNATURE_UNSUPPORTED;
  TC_X509_public_key key;
  TC_TLV_result result = tc_x509_crl_signer_key(crl, signer, limits, names, work, &key);
  if (result != TC_TLV_OK)
    return tc_pki_signature_error(result);
  return tc_x509_crl_digest_signature(crl, hash, digest, &key, provider, work);
}

TC_TLV_result tc_x509_crl_check_signer(const void* context, const TC_X509_certificate* candidate,
                                       const tc_x509_crl_trust* trust, TC_X509_search_result* out)
{
  return tc_x509_path_result_status(tc_x509_crl_signer_validate(context, candidate, trust, out));
}

TC_TLV_result tc_x509_crl_store_search(const void* candidates,
                                       const tc_x509_crl_signer_query* query,
                                       const tc_x509_crl_trust* trust, TC_X509_search_result* out,
                                       int* source_failed)
{
  if (!candidates)
    return TC_TLV_ARGUMENT;
  const tc_pki_store_candidates* cursor = candidates;
  return tc_x509_crl_store_source_search(cursor, cursor->source, query, trust, out, source_failed);
}

TC_TLV_result tc_x509_crl_index_attempt(const void* context, const TC_X509_certificate* signer,
                                        const tc_x509_crl_trust* trust, TC_X509_search_result* out)
{
  const tc_x509_crl_index_processing* processing = context;
  const TC_X509_crl_record* base = &processing->index->records[processing->base];
  tc_x509_crl_selected selected = {&base->crl, &base->extensions, NULL, NULL};
  TC_X509_search_result found;
  if (processing->delta_policy == TC_X509_CRL_COMPLETE_ONLY)
    return tc_x509_crl_process(&selected, signer, processing->query, trust->source,
                               trust->anchor_index, trust->options, trust->validation,
                               trust->search, trust->tree->work, processing->evidence, out);
  TC_TLV_result result = tc_x509_crl_selected_validate(
      &selected, signer, trust->source, trust->anchor_index, trust->options, trust->validation,
      trust->search, trust->tree->work, &found);
  if (result != TC_TLV_OK)
    return result;
  const tc_x509_crl_signature_cache verifier = {processing->index,
                                                signer,
                                                &trust->options->signatures,
                                                &trust->options->parsing,
                                                &trust->validation->names,
                                                NULL,
                                                0,
                                                NULL};
  result = tc_x509_crl_delta_select(&verifier, processing->base, &trust->options->at, trust->tree,
                                    NULL, &selected);
  if (result != TC_TLV_OK &&
      !(result == TC_TLV_END && processing->delta_policy == TC_X509_CRL_DELTA_IF_AVAILABLE))
    return result;
  /* Selection preserves the established signer path and verified base. */
  result = tc_x509_crl_apply(
      &selected, processing->query, &trust->options->at,
      &(tc_x509_crl_decode){&trust->options->parsing, trust->tree, &trust->validation->names,
                            trust->validation->oids, trust->validation->oid_capacity},
      processing->evidence);
  if (result != TC_TLV_OK)
    return result;
  *out = found;
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_crl_process_candidate(const void* context,
                                            const TC_X509_certificate* candidate,
                                            const tc_x509_crl_trust* trust,
                                            TC_X509_search_result* out)
{
  const tc_x509_crl_processing* processing = context;
  return tc_x509_crl_process(processing->selected, candidate, processing->query, trust->source,
                             trust->anchor_index, trust->options, trust->validation, trust->search,
                             trust->tree->work, processing->evidence, out);
}

TC_TLV_result tc_x509_crl_source_scan_finish(const tc_x509_crl_source_scan* scan,
                                             TC_X509_crl_match* out, size_t capacity)
{
  if (!scan || scan->phase != TC_CRL_SCAN_COMPLETE || (scan->count && !out))
    return TC_TLV_ARGUMENT;
  if (scan->count > capacity)
    return TC_TLV_LIMIT;
  if (scan->count)
    memcpy(out, scan->matches, scan->count * sizeof *out);
  return TC_TLV_OK;
}

/* CRLNumber of the latest effective CRL in the reference scope. */
TC_TLV_result tc_x509_crl_latest_number(const tc_x509_crl_scope_context* scope, size_t reference,
                                        TC_bytes* out)
{
  tc_x509_crl_selected latest;
  if (!scope || !out)
    return TC_TLV_ARGUMENT;
  tc_x509_crl_scope_context numbered = *scope;
  numbered.order_policy = TC_X509_CRL_ORDER_NUMBER;
  TC_TLV_result result = tc_x509_crl_latest(&numbered, reference, &latest, NULL);
  if (result == TC_TLV_OK)
    *out = latest.delta ? latest.delta_info->number : latest.base_info->number;
  return result;
}

/* Schema-check CRL-level and entry extensions with the library readers. */
TC_TLV_result tc_x509_crl_extensions_check(const TC_X509_crl* crl, const TC_TLV_limits* limits,
                                           const tc_pki_tree_workspace* tree, TC_bytes* oids,
                                           size_t capacity)
{
  TC_X509_crl_extensions info;
  TC_TLV_reader entries;
  TC_TLV_result result;
  if (!crl || !tree)
    return TC_TLV_ARGUMENT;
  result = tc_x509_crl_extension_info_read(crl->extensions, limits, tree, oids, capacity, &info);
  if (result != TC_TLV_OK)
    return result;
  result = tc_x509_crl_entries_init(crl->revoked, limits, tree, &entries);
  if (result != TC_TLV_OK)
    return result;
  while (!tc_pki_end(&entries)) {
    tc_x509_crl_entry entry;
    tc_x509_crl_entry_info entry_info;
    result = tc_x509_crl_entry_next(&entries, crl->version, tree, &entry);
    if (result != TC_TLV_OK)
      return result;
    result =
        tc_x509_crl_entry_info_read(entry.extensions, limits, tree, oids, capacity, &entry_info);
    if (result != TC_TLV_OK)
      return result;
  }
  return TC_TLV_OK;
}

/* tc_x509_crl_scope_evaluate without a ranking preference. */
TC_TLV_result tc_x509_crl_scope_apply(const tc_x509_crl_scope_context* scope, size_t reference,
                                      const tc_x509_crl_query* query,
                                      TC_X509_crl_evidence* evidence)
{
  return tc_x509_crl_scope_evaluate(scope, reference, query, evidence, NULL);
}

#endif

#if TC_ENABLE_X509_PATH
typedef struct {
  const TC_bytes* candidates;
  const TC_X509_trust_anchor* anchors;
} array_source;

static TC_TLV_result array_candidate(void* context, size_t index, size_t* work, TC_bytes* out)
{
  const array_source* source = context;
  (void)work;
  *out = source->candidates[index];
  return TC_TLV_OK;
}

static TC_TLV_result array_anchor(void* context, size_t index, size_t* work,
                                  TC_X509_store_anchor* out)
{
  const array_source* source = context;
  (void)work;
  out->trust = source->anchors[index];
  out->names = (TC_X509_name_constraints){{NULL, 0}, {NULL, 0}};
  return TC_TLV_OK;
}

TC_X509_path_status tc_x509_path_search(TC_bytes target, const TC_bytes* candidates,
                                        size_t candidate_count, const TC_X509_trust_anchor* anchors,
                                        size_t anchor_count, const TC_X509_path_options* options,
                                        const TC_X509_path_workspace* validation,
                                        const TC_X509_search_workspace* search, size_t* work,
                                        TC_X509_search_result* out)
{
  array_source arrays = {candidates, anchors};
  TC_X509_store_source source = {&arrays, candidate_count, anchor_count, array_candidate,
                                 array_anchor};
  if ((candidate_count && !candidates) || (anchor_count && !anchors))
    return TC_X509_PATH_ERROR;
  return tc_x509_path_search_source(target, &source, options, validation, search, work, out);
}
#endif
