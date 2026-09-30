/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * CRL-based revocation for a validated path: dependency nodes, their
 * resolution order, and TC_X509_path_check_revocation. */
#include <tiny_crypto/x509.h>
#if TC_ENABLE_X509_REVOCATION
#include "x509_revocation_internal.h"
#include "pki_storage_internal.h"
#include "pki_spans_internal.h"
#include "pki_status_internal.h"
#include "pki_identifier_internal.h"
#include "pki_extensions_internal.h"
#include "pki_source_internal.h"
#if TC_ENABLE_X509_OCSP
#include <tiny_crypto/x509_ocsp.h>
#endif

TC_TLV_result tc_x509_crl_resolve_dependencies(TC_bytes target,
                                               tc_x509_crl_dependencies* dependencies,
                                               tc_x509_crl_node_evaluate evaluate, void* context,
                                               tc_x509_crl_held_path* path,
                                               TC_X509_crl_evidence* out)
{
  if (!dependencies || !dependencies->workspace || !dependencies->workspace->tree ||
      !dependencies->workspace->tree->work || !evaluate || !out)
    return TC_TLV_ARGUMENT;
  const tc_x509_crl_resolution_workspace* workspace = dependencies->workspace;
  size_t* work = workspace->tree->work;
  size_t root;
  TC_TLV_result result = tc_x509_crl_dependency_add(dependencies, target, work, &root);
  if (result != TC_TLV_OK)
    return result;
  if (workspace->nodes[root].status == TC_X509_REVOCATION_GOOD) {
    /* A proven node already covers every revocation reason. */
    TC_X509_crl_evidence evidence = {0};
    evidence.reasons = TC_X509_CRL_ALL_REASONS;
    *out = evidence;
    return TC_TLV_OK;
  }
  result = tc_x509_crl_nodes_resolve(workspace->nodes, workspace->node_capacity,
                                     &dependencies->count, root, work, evaluate, context, out);
  /* Keep nodes added by an unresolved target too. Their lookup links stay in
   * the table, and a later target of the held path (such as the member after
   * an OCSP delegate) must see them. LIMIT and ARGUMENT end the operation. */
  if (path && result != TC_TLV_LIMIT && result != TC_TLV_ARGUMENT)
    path->dependency_count = dependencies->count;
  return result;
}

TC_TLV_result tc_x509_crl_dependency_read(const tc_x509_crl_dependencies* dependencies,
                                          size_t index, TC_X509_certificate* out)
{
  if (!dependencies || !dependencies->options || !dependencies->workspace || !out)
    return TC_TLV_ARGUMENT;
  const tc_x509_crl_resolution_workspace* workspace = dependencies->workspace;
  if (!workspace->tree || !workspace->tree->work || !workspace->validation || !workspace->nodes ||
      dependencies->count > workspace->node_capacity || index >= dependencies->count)
    return TC_TLV_ARGUMENT;
  const TC_bytes encoded = workspace->nodes[index].certificate;
  TC_X509_workspace parser = {workspace->validation->frames, workspace->validation->oids,
                              workspace->validation->oid_capacity};
  TC_TLV_result result = tc_pki_work_charge(workspace->tree->work, encoded.length);
  if (result != TC_TLV_OK)
    return result;
  return TC_X509_read(encoded, &dependencies->options->parsing, &parser, out);
}

TC_TLV_result tc_x509_crl_dependency_add(tc_x509_crl_dependencies* dependencies,
                                         TC_bytes certificate, size_t* work, size_t* index)
{
  if (!dependencies || !dependencies->workspace || !work || !index ||
      (dependencies->write_count && !dependencies->writes))
    return TC_TLV_ARGUMENT;
  const tc_x509_crl_resolution_workspace* workspace = dependencies->workspace;
  TC_TLV_result result =
      tc_pki_storage_input(dependencies->writes, dependencies->write_count, certificate, work);
  if (result != TC_TLV_OK)
    return result;
  if (workspace->indexed_dependencies)
    return tc_x509_crl_dependency_find_indexed(workspace->nodes, workspace->node_capacity,
                                               &dependencies->count, certificate, work, index);
  return tc_x509_crl_dependency_find(workspace->nodes, workspace->node_capacity,
                                     &dependencies->count, certificate, work, index);
}

TC_X509_path_status tc_x509_crl_dependencies_check(void* context, const TC_X509_search_result* path,
                                                   const tc_x509_crl_selected* selected,
                                                   size_t* work)
{
  tc_x509_crl_dependencies* dependencies = context;
  if (!dependencies || !path || !work || !dependencies->options || !dependencies->workspace ||
      !dependencies->workspace->validation || !dependencies->anchor ||
      (dependencies->write_count && !dependencies->writes))
    return TC_X509_PATH_ERROR;
  const TC_X509_path_options* options = dependencies->options;
  if (path->anchor_index != dependencies->anchor_index)
    return TC_X509_PATH_ERROR;
  if (!selected)
    return TC_X509_PATH_UNSUPPORTED;
  TC_X509_signature_result signature = tc_x509_crl_selected_anchor_check(
      selected, dependencies->anchor, &options->signatures, &options->parsing,
      &dependencies->workspace->validation->names, work);
  if (signature == TC_X509_SIGNATURE_LIMIT)
    return TC_X509_PATH_LIMIT;
  if (signature == TC_X509_SIGNATURE_ERROR)
    return TC_X509_PATH_ERROR;
  if (signature == TC_X509_SIGNATURE_VALID)
    return TC_X509_PATH_VALID;
  return tc_x509_crl_dependencies_path(path, dependencies->workspace, &dependencies->count,
                                       dependencies->writes, dependencies->write_count, work);
}

TC_TLV_result tc_x509_crl_path_resolve(const TC_bytes* chain, size_t count,
                                       tc_x509_crl_certificate_resolve resolve, void* context,
                                       TC_X509_revocation_result* out)
{
  TC_bytes storage;
  if (!chain || !count || !resolve || !out)
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = tc_pki_storage_span(chain, count, sizeof *chain, &storage);
  if (result != TC_TLV_OK)
    return result;
  TC_X509_revocation_result proposed = {TC_X509_REVOCATION_GOOD, SIZE_MAX, {0}};
  for (size_t i = 0; i < count; ++i) {
    TC_X509_crl_evidence evidence = {0};
    result = resolve(context, i, chain[i], &evidence);
    if (result != TC_TLV_OK)
      return result;
    TC_X509_revocation_status status;
    result = tc_x509_crl_evidence_status(&evidence, &status);
    if (result != TC_TLV_OK)
      return result;
    if (status == TC_X509_REVOCATION_UNDETERMINED)
      return TC_TLV_UNSUPPORTED;
    if (status == TC_X509_REVOCATION_REVOKED) {
      proposed.status = status;
      proposed.certificate_index = i;
      proposed.evidence = evidence;
      break;
    }
  }
  *out = proposed;
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_crl_nodes_resolve(TC_X509_revocation_node* nodes, size_t capacity,
                                        size_t* count, size_t root, size_t* work,
                                        tc_x509_crl_node_evaluate evaluate, void* context,
                                        TC_X509_crl_evidence* out)
{
  if (!nodes || !count || !work || !evaluate || !out || *count > capacity || root >= *count)
    return TC_TLV_ARGUMENT;
  TC_TLV_result root_result = TC_TLV_UNSUPPORTED;
  for (;;) {
    const size_t previous_count = *count;
    size_t resolved = 0;
    for (size_t i = 0; i < *count; ++i) {
      /* Re-evaluate the root to recover its revocation reason and date. */
      if (i != root && nodes[i].status != TC_X509_REVOCATION_UNDETERMINED)
        continue;
      TC_X509_crl_evidence evidence = {0};
      int stop = 0;
      const size_t before_work = *work, before_count = *count;
      TC_TLV_result result = evaluate(context, i, &evidence, &stop);
      if (*work > before_work) {
        *work = 0;
        return TC_TLV_ARGUMENT;
      }
      if (*count < before_count || *count > capacity)
        return TC_TLV_ARGUMENT;
      if (stop)
        return result == TC_TLV_OK ? TC_TLV_ARGUMENT : result;
      if (result == TC_TLV_ARGUMENT || result == TC_TLV_LIMIT)
        return result;
      if (i == root)
        root_result = result;
      if (result != TC_TLV_OK)
        continue;
      TC_X509_revocation_status status;
      result = tc_x509_crl_evidence_status(&evidence, &status);
      if (result != TC_TLV_OK)
        return result;
      if (status == TC_X509_REVOCATION_UNDETERMINED)
        continue;
      nodes[i].status = status;
      ++resolved;
      if (i == root) {
        *out = evidence;
        return TC_TLV_OK;
      }
    }
    if (!resolved && *count == previous_count)
      return root_result == TC_TLV_INVALID ? TC_TLV_INVALID : TC_TLV_UNSUPPORTED;
  }
}

/* One validated CRL resolution with its storage preflight. Every target
 * resolved through it reuses the sealed write set, the anchor, the scope
 * groups and the scratch below, which the preflight covered. */
typedef struct {
  const tc_x509_crl_resolution* resolution;
  const tc_x509_crl_resolution_workspace* workspace;
  tc_x509_crl_held_path* path;
  TC_bytes writes[CRL_SCOPE_WRITES];
  TC_X509_store_anchor anchor;
  /* Evidence and discarded signer path of the node being evaluated. */
  TC_X509_crl_evidence pending;
  TC_X509_search_result scratch;
  int source_failed;
} x509_crl_prepared;

/* Validate the resolution and preflight its storage once. target is the
 * single target to resolve, or NULL for the members of path. out is that
 * target's evidence, or NULL with a path, whose result is recorded instead. */
static TC_TLV_result x509_crl_prepare(const TC_X509_certificate* target,
                                      const tc_x509_crl_resolution* resolution,
                                      const tc_x509_crl_resolution_workspace* workspace,
                                      tc_x509_crl_held_path* path, TC_X509_crl_evidence* out,
                                      x509_crl_prepared* prepared)
{
  const TC_X509_certificate no_target = {0};
  if (!resolution || !workspace || !resolution->candidates || !!target == !!path ||
      (target && (!out || !target->encoded.data || !target->encoded.length)))
    return TC_TLV_ARGUMENT;
  const tc_x509_crl_trust trust = {
      resolution->source,    resolution->anchor_index, resolution->options, workspace->tree,
      workspace->validation, workspace->search,        resolution->time};
  const tc_pki_distribution_point fallback = {0};
  const tc_x509_crl_query query = {target ? target : &no_target, &fallback, 0};
  if (!tc_x509_crl_index_arguments(resolution->index, &query, &trust, &prepared->scratch) ||
      !x509_crl_delta_policy_valid(resolution->delta_policy) ||
      !x509_crl_order_policy_valid(resolution->order_policy))
    return TC_TLV_ARGUMENT;
  if (!workspace->node_capacity || workspace->state_capacity < resolution->index->count)
    return TC_TLV_LIMIT;
  if (workspace->scopes && workspace->scope_capacity < resolution->index->count)
    return TC_TLV_LIMIT;
  tc_x509_crl_extra_storage extra = {0};
  extra.count = path ? path->dependency_count : 0;
  if (extra.count > workspace->node_capacity)
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = tc_pki_storage_span(workspace->nodes, workspace->node_capacity,
                                             sizeof *workspace->nodes, &extra.nodes_storage);
  if (result == TC_TLV_OK && out)
    result = tc_pki_storage_span(out, 1, sizeof *out, &extra.output_storage);
  if (result != TC_TLV_OK)
    return result;
  extra.inputs[CRL_EXTRA_RESOLUTION] = (TC_bytes){(const uint8_t*)resolution, sizeof *resolution};
  extra.inputs[CRL_EXTRA_WORKSPACE] = (TC_bytes){(const uint8_t*)workspace, sizeof *workspace};
  extra.nodes = workspace->nodes;
  prepared->resolution = resolution;
  prepared->workspace = workspace;
  prepared->path = path;
  prepared->pending = (TC_X509_crl_evidence){0};
  prepared->source_failed = 0;
  const tc_x509_crl_scope_processing processing = {resolution->index,
                                                   0,
                                                   resolution->delta_policy,
                                                   resolution->order_policy,
                                                   &query,
                                                   workspace->states,
                                                   workspace->state_capacity,
                                                   &prepared->pending,
                                                   NULL,
                                                   NULL,
                                                   NULL,
                                                   workspace->scopes,
                                                   workspace->signer_cache};
  result = tc_x509_crl_scope_prepare(resolution->candidates, &processing, &trust, NULL, &extra,
                                     path, &prepared->scratch, prepared->writes);
  if (result != TC_TLV_OK)
    return result;
  if (workspace->scopes) {
    result = tc_x509_crl_scopes_index(resolution->index, &resolution->options->parsing,
                                      workspace->tree, &workspace->validation->names,
                                      workspace->scopes, workspace->scope_capacity);
    if (result != TC_TLV_OK)
      return result;
  }
  const tc_pki_source_guard source_guard = {resolution->source, prepared->writes, CRL_SCOPE_WRITES};
  return tc_pki_source_guard_anchor((void*)&source_guard, resolution->anchor_index,
                                    workspace->tree->work, &prepared->anchor);
}

typedef struct {
  x509_crl_prepared* prepared;
  tc_x509_crl_dependencies* dependencies;
  const tc_x509_crl_path_check* check;
} x509_crl_node_context;

/* Evaluate one dependency node over every indexed scope. The prepared
 * resolution already validated and preflighted this operation. */
static TC_TLV_result x509_crl_node_evaluate(void* context, size_t index,
                                            TC_X509_crl_evidence* evidence, int* stop)
{
  const x509_crl_node_context* node = context;
  x509_crl_prepared* prepared = node->prepared;
  const tc_x509_crl_resolution* resolution = prepared->resolution;
  const tc_x509_crl_resolution_workspace* workspace = prepared->workspace;
  TC_X509_certificate certificate;
  TC_TLV_result result = tc_x509_crl_dependency_read(node->dependencies, index, &certificate);
  if (result != TC_TLV_OK) {
    *stop = 1;
    return result;
  }
  const tc_pki_distribution_point fallback = {0};
  const tc_x509_crl_query query = {&certificate, &fallback, 0};
  prepared->pending = (TC_X509_crl_evidence){0};
  const tc_x509_crl_scope_processing processing = {resolution->index,
                                                   0,
                                                   resolution->delta_policy,
                                                   resolution->order_policy,
                                                   &query,
                                                   workspace->states,
                                                   workspace->state_capacity,
                                                   &prepared->pending,
                                                   node->check,
                                                   NULL,
                                                   NULL,
                                                   workspace->scopes,
                                                   workspace->signer_cache};
  result = tc_x509_crl_scope_run(&resolution->candidates->candidates, &processing,
                                 &(tc_x509_crl_trust){resolution->source, resolution->anchor_index,
                                                      resolution->options, workspace->tree,
                                                      workspace->validation, workspace->search,
                                                      resolution->time},
                                 &(tc_x509_crl_scope_selection){NULL, 1, 1}, prepared->writes,
                                 &prepared->source_failed, &prepared->scratch);
  *stop = prepared->source_failed;
  if (result == TC_TLV_OK)
    *evidence = prepared->pending;
  return result;
}

/* Resolve one target through a prepared resolution. The dependency table
 * guards the target bytes against the sealed writes before any use. */
static TC_TLV_result x509_crl_resolve_target(x509_crl_prepared* prepared, TC_bytes target,
                                             TC_X509_crl_evidence* out)
{
  const tc_x509_crl_resolution* resolution = prepared->resolution;
  tc_x509_crl_held_path* path = prepared->path;
  tc_x509_crl_dependencies dependencies = {resolution->options,
                                           resolution->anchor_index,
                                           prepared->workspace,
                                           &prepared->anchor.trust,
                                           prepared->writes,
                                           CRL_SCOPE_WRITES,
                                           path ? path->dependency_count : 0};
  const tc_x509_crl_path_check check = {&dependencies, tc_x509_crl_dependencies_check};
  x509_crl_node_context node = {prepared, &dependencies, &check};
  prepared->source_failed = 0;
  return tc_x509_crl_resolve_dependencies(target, &dependencies, x509_crl_node_evaluate, &node,
                                          path, out);
}

TC_TLV_result tc_x509_crl_resolve(const TC_X509_certificate* target,
                                  const tc_x509_crl_resolution* resolution,
                                  const tc_x509_crl_resolution_workspace* workspace,
                                  TC_X509_crl_evidence* out)
{
  x509_crl_prepared prepared;
  if (!target)
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = x509_crl_prepare(target, resolution, workspace, NULL, out, &prepared);
  if (result != TC_TLV_OK)
    return result;
  return x509_crl_resolve_target(&prepared, target->encoded, out);
}

/* OCSP evidence for the members of one path check. writes records the
 * validation workspace that OCSP verification modifies, so issuer anchors
 * and delegate candidates are checked against it. */
typedef struct {
  const TC_X509_revocation_options* options;
  const TC_bytes* chain;
  TC_bytes writes[TC_X509_PATH_STORAGE_COUNT];
} x509_ocsp_members;

typedef struct {
  x509_crl_prepared* prepared;
  const x509_ocsp_members* ocsp;
} x509_crl_path_context;

#if TC_ENABLE_X509_OCSP
/* The issuer of chain[index]: the selected anchor for the first member,
 * otherwise the previous member. Both borrow stable input bytes. */
static TC_TLV_result x509_ocsp_issuer(const x509_crl_path_context* path, size_t index,
                                      TC_X509_trust_anchor* out)
{
  const x509_ocsp_members* ocsp = path->ocsp;
  const TC_X509_path_workspace* validation = path->prepared->workspace->validation;
  size_t* work = path->prepared->workspace->tree->work;
  TC_TLV_result result;
  if (!index) {
    const tc_pki_source_guard guard = {ocsp->options->source, ocsp->writes,
                                       TC_X509_PATH_STORAGE_COUNT};
    TC_X509_store_anchor anchor;
    result = tc_pki_source_guard_anchor((void*)&guard, ocsp->options->anchor_index, work, &anchor);
    if (result == TC_TLV_OK)
      *out = anchor.trust;
    return result;
  }
  TC_X509_workspace parser = {validation->frames, validation->oids, validation->oid_capacity};
  TC_X509_certificate issuer = {0};
  const TC_bytes encoded = ocsp->chain[index - 1];
  result = tc_pki_work_charge(work, encoded.length);
  if (result == TC_TLV_OK)
    result = TC_X509_read(encoded, &ocsp->options->signer_policy->parsing, &parser, &issuer);
  if (result == TC_TLV_OK)
    *out = (TC_X509_trust_anchor){issuer.subject, issuer.public_key};
  return result;
}

/* RFC 6960 4.2.2.2.1: a delegate without id-pkix-ocsp-nocheck is trusted
 * only when separate evidence shows it unrevoked. Here that evidence is the
 * CRL index. OK means the delegate is proven unrevoked. */
static TC_TLV_result x509_ocsp_delegate_checked(const x509_crl_path_context* path,
                                                TC_bytes delegate)
{
  TC_X509_crl_evidence evidence = {0};
  TC_X509_revocation_status status = TC_X509_REVOCATION_UNDETERMINED;
  TC_TLV_result result = x509_crl_resolve_target(path->prepared, delegate, &evidence);
  if (result == TC_TLV_OK)
    result = tc_x509_crl_evidence_status(&evidence, &status);
  if (result != TC_TLV_OK)
    return result;
  return status == TC_X509_REVOCATION_GOOD ? TC_TLV_OK : TC_TLV_UNSUPPORTED;
}

/* Verify the member's OCSP response and convert an accepted result to CRL
 * evidence with complete reason coverage. Any result other than OK leaves
 * evidence unchanged, and the caller falls back to CRLs unless it is LIMIT or
 * ARGUMENT. */
static TC_TLV_result x509_ocsp_member(const x509_crl_path_context* path, size_t index,
                                      TC_bytes certificate, TC_X509_crl_evidence* evidence)
{
  const TC_X509_revocation_options* options = path->ocsp->options;
  const TC_X509_path_workspace* validation = path->prepared->workspace->validation;
  size_t* work = path->prepared->workspace->tree->work;
  TC_X509_trust_anchor issuer;
  TC_TLV_result result = x509_ocsp_issuer(path, index, &issuer);
  if (result != TC_TLV_OK)
    return result;
  tc_pki_source_guard guard = {options->source, path->ocsp->writes, TC_X509_PATH_STORAGE_COUNT};
  const TC_X509_store_source delegates = tc_pki_source_guard_bind(&guard);
  const TC_X509_ocsp_verify_request request = {options->ocsp.responses[index],
                                               certificate,
                                               {NULL, 0},
                                               &issuer,
                                               &delegates,
                                               options->time,
                                               options->ocsp.max_responses,
                                               options->ocsp.max_certificates,
                                               &options->signer_policy->parsing,
                                               &options->signer_policy->signatures};
  TC_X509_ocsp_result verified;
  result = TC_X509_ocsp_response_verify(&request, validation, work, &verified);
  if (result == TC_TLV_OK && verified.responder_certificate.data && !verified.responder_nocheck)
    result = x509_ocsp_delegate_checked(path, verified.responder_certificate);
  if (result != TC_TLV_OK)
    return result;
  TC_X509_crl_evidence accepted = {0};
  accepted.reasons = TC_X509_CRL_ALL_REASONS;
  if (verified.status == TC_X509_REVOCATION_REVOKED) {
    accepted.revocation.found = 1;
    accepted.revocation.revoked_at = verified.revocation_time;
    accepted.revocation.reason =
        verified.has_reason ? verified.reason : TC_PKI_CRL_REASON_UNSPECIFIED;
  }
  *evidence = accepted;
  return TC_TLV_OK;
}
#endif

static TC_TLV_result x509_crl_path_certificate(void* context, size_t index, TC_bytes encoded,
                                               TC_X509_crl_evidence* evidence)
{
  const x509_crl_path_context* path = context;
#if !TC_ENABLE_X509_OCSP
  /* The callback type passes index for OCSP response lookup. */
  (void)index;
#else
  /* An accepted OCSP response settles the member. Other outcomes fall back
   * to CRLs, except exhausted limits and argument errors. */
  if (path->ocsp && path->ocsp->options->ocsp.count &&
      path->ocsp->options->ocsp.responses[index].length) {
    TC_TLV_result result = x509_ocsp_member(path, index, encoded, evidence);
    if (result == TC_TLV_OK || result == TC_TLV_LIMIT || result == TC_TLV_ARGUMENT)
      return result;
  }
#endif
  return x509_crl_resolve_target(path->prepared, encoded, evidence);
}

/* Prepare the resolution once for the whole held path, then resolve each
 * member. ocsp is NULL when no member carries a response. */
static TC_TLV_result x509_crl_path_run(tc_x509_crl_held_path* held,
                                       const tc_x509_crl_resolution* resolution,
                                       const tc_x509_crl_resolution_workspace* workspace,
                                       const x509_ocsp_members* ocsp)
{
  x509_crl_prepared prepared;
  if (!held || !held->chain || !held->count || !held->out)
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = x509_crl_prepare(NULL, resolution, workspace, held, NULL, &prepared);
  if (result != TC_TLV_OK)
    return result;
  x509_crl_path_context context = {&prepared, ocsp};
  return tc_x509_crl_path_resolve(held->chain, held->count, x509_crl_path_certificate, &context,
                                  held->out);
}

TC_TLV_result tc_x509_crl_path_operation(tc_x509_crl_held_path* held,
                                         const tc_x509_crl_resolution* resolution,
                                         const tc_x509_crl_resolution_workspace* workspace)
{
  return x509_crl_path_run(held, resolution, workspace, NULL);
}

/* Check the OCSP responses and the chain against the validation workspace
 * that OCSP verification writes. The CRL operation checks the other
 * workspace arrays against these inputs. */
static TC_TLV_result x509_ocsp_preflight(x509_ocsp_members* ocsp, size_t count,
                                         const TC_X509_path_workspace* validation, size_t* work)
{
  const TC_X509_revocation_ocsp* responses = &ocsp->options->ocsp;
  tc_pki_storage_plan plan;
  tc_pki_storage_plan_begin(&plan, ocsp->writes, TC_X509_PATH_STORAGE_COUNT, *work);
  tc_x509_path_storage_plan(&plan, validation);
  tc_pki_storage_plan_seal(&plan);
  TC_PKI_PLAN_INPUT(&plan, ocsp->options, 1);
  TC_PKI_PLAN_INPUT(&plan, responses->responses, count);
  TC_PKI_PLAN_INPUT(&plan, ocsp->chain, count);
  tc_pki_storage_plan_input_spans(&plan, responses->responses, count);
  tc_pki_storage_plan_input_spans(&plan, ocsp->chain, count);
  return tc_pki_storage_plan_finish(&plan, work);
}

TC_TLV_result TC_X509_path_check_revocation(const TC_bytes* chain, size_t count,
                                            const TC_X509_revocation_options* options,
                                            const TC_X509_revocation_workspace* workspace,
                                            size_t* work, TC_X509_revocation_result* out)
{
  if (!options || !options->source || !options->signer_policy || !workspace ||
      !workspace->validation || !workspace->search || !workspace->scopes ||
      !workspace->signer_path || !workspace->signer_policies || !work)
    return TC_TLV_ARGUMENT;
  /* CRL signer paths validate at signer_policy->at. Freshness and OCSP use
   * options->time.at. A single evaluation time keeps them consistent. */
  int time_order = 1;
  if (TC_X509_time_compare(&options->time.at, &options->signer_policy->at, &time_order) !=
          TC_TLV_OK ||
      time_order ||
      (options->ocsp.count &&
       (options->ocsp.count != count || !options->ocsp.responses || !options->ocsp.max_responses)))
    return TC_TLV_ARGUMENT;
  if (workspace->signer_path_capacity < workspace->search->capacity ||
      workspace->signer_policy_capacity < workspace->validation->policy_capacity)
    return TC_TLV_LIMIT;
  x509_ocsp_members ocsp = {options, chain, {{NULL, 0}}};
  if (options->ocsp.count) {
    if (!chain)
      return TC_TLV_ARGUMENT;
    TC_TLV_result result = x509_ocsp_preflight(&ocsp, count, workspace->validation, work);
    if (result != TC_TLV_OK)
      return result;
  }
  const tc_pki_tree_workspace tree = {workspace->validation->frames.data,
                                      workspace->validation->frames.capacity, work};
  tc_pki_store_candidates cursor = {options->source, options->signer_policy->parsing, 0,
                                    options->source->candidate_count, options->max_candidate_bytes};
  const TC_bytes candidate_metadata[] = {{(const uint8_t*)&cursor, sizeof cursor}};
  const tc_x509_crl_operation_source candidates = {
      {&cursor, options->source, tc_x509_crl_store_source_search},
      candidate_metadata,
      sizeof candidate_metadata / sizeof *candidate_metadata};
  const tc_x509_crl_resolution resolution = {
      &candidates,           options->index,        options->source,       options->signer_policy,
      options->anchor_index, options->delta_policy, options->order_policy, &options->time};
  tc_x509_crl_signer_cache signer_cache = {{0},
                                           {0},
                                           workspace->signer_path,
                                           workspace->signer_path_capacity,
                                           workspace->signer_policies,
                                           workspace->signer_policy_capacity,
                                           0};
  const tc_x509_crl_resolution_workspace scratch = {&tree,
                                                    workspace->validation,
                                                    workspace->search,
                                                    workspace->states,
                                                    workspace->state_capacity,
                                                    workspace->nodes,
                                                    workspace->node_capacity,
                                                    1,
                                                    workspace->scopes,
                                                    workspace->scope_capacity,
                                                    &signer_cache};
  tc_x509_crl_held_path held = {0};
  held.chain = chain;
  held.count = count;
  held.out = out;
  held.metadata[CRL_PATH_OPTIONS] = (TC_bytes){(const uint8_t*)options, sizeof *options};
  held.metadata[CRL_PATH_WORKSPACE] = (TC_bytes){(const uint8_t*)workspace, sizeof *workspace};
  held.ocsp = options->ocsp.responses;
  held.ocsp_count = options->ocsp.count;
  return x509_crl_path_run(&held, &resolution, &scratch, options->ocsp.count ? &ocsp : NULL);
}

TC_X509_path_status tc_x509_crl_dependencies_path(const TC_X509_search_result* path,
                                                  const tc_x509_crl_resolution_workspace* workspace,
                                                  size_t* count, const TC_bytes* writes,
                                                  size_t write_count, size_t* work)
{
  if (!path || !workspace || !count || !work || (path->count && !path->path) ||
      (write_count && !writes) || *count > workspace->node_capacity ||
      (workspace->node_capacity && !workspace->nodes))
    return TC_X509_PATH_ERROR;
  int unresolved = 0;
  for (size_t i = 0; i < path->count; ++i) {
    size_t index;
    TC_TLV_result result = tc_pki_storage_input(writes, write_count, path->path[i], work);
    if (result != TC_TLV_OK)
      return tc_x509_path_status(result);
    result = workspace->indexed_dependencies
                 ? tc_x509_crl_dependency_find_indexed(workspace->nodes, workspace->node_capacity,
                                                       count, path->path[i], work, &index)
                 : tc_x509_crl_dependency_find(workspace->nodes, workspace->node_capacity, count,
                                               path->path[i], work, &index);
    if (result != TC_TLV_OK)
      return tc_x509_path_status(result);
    switch (workspace->nodes[index].status) {
    case TC_X509_REVOCATION_REVOKED:
      return TC_X509_PATH_INVALID;
    case TC_X509_REVOCATION_UNDETERMINED:
      unresolved = 1;
      break;
    case TC_X509_REVOCATION_GOOD:
      break;
    default:
      return TC_X509_PATH_ERROR;
    }
  }
  return unresolved ? TC_X509_PATH_UNSUPPORTED : TC_X509_PATH_VALID;
}

TC_X509_signature_result tc_x509_crl_selected_anchor_check(
    const tc_x509_crl_selected* selected, const TC_X509_trust_anchor* anchor,
    const TC_X509_signature_provider* provider, const TC_TLV_limits* limits,
    const TC_X509_name_workspace* names, size_t* work)
{
  if (!selected || !selected->base || !anchor || !provider || !limits || !names || !work)
    return TC_X509_SIGNATURE_ERROR;
  const TC_X509_crl* records[] = {selected->base, selected->delta};
  for (size_t i = 0; i < sizeof records / sizeof *records; ++i) {
    if (!records[i])
      continue;
    TC_X509_signature_result result =
        tc_x509_crl_anchor_check(records[i], anchor, provider, limits, names, work);
    if (result != TC_X509_SIGNATURE_VALID)
      return result;
  }
  return TC_X509_SIGNATURE_VALID;
}

TC_TLV_result tc_x509_crl_dependency_find(TC_X509_revocation_node* nodes, size_t capacity,
                                          size_t* count, TC_bytes certificate, size_t* work,
                                          size_t* index)
{
  if (!count || !work || !index || *count > capacity || (capacity && !nodes) || !certificate.data ||
      !certificate.length)
    return TC_TLV_ARGUMENT;
  for (size_t i = 0; i < *count; ++i) {
    const TC_bytes previous = nodes[i].certificate;
    TC_TLV_result result = tc_pki_work_charge(work, 1);
    if (result != TC_TLV_OK)
      return result;
    if (previous.length != certificate.length)
      continue;
    result = tc_pki_work_charge(work, certificate.length);
    if (result != TC_TLV_OK)
      return result;
    if (tc_pki_equal(previous, certificate)) {
      *index = i;
      return TC_TLV_OK;
    }
  }
  if (*count == capacity)
    return TC_TLV_LIMIT;
  nodes[*count] = (TC_X509_revocation_node){.certificate = certificate,
                                            .status = TC_X509_REVOCATION_UNDETERMINED};
  *index = (*count)++;
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_crl_dependency_find_indexed(TC_X509_revocation_node* nodes, size_t capacity,
                                                  size_t* count, TC_bytes certificate, size_t* work,
                                                  size_t* index)
{
  size_t cursor, bucket;
  if (!nodes || !count || !work || !index || *count > capacity || !certificate.data ||
      !certificate.length)
    return TC_TLV_ARGUMENT;
  if (!capacity)
    return TC_TLV_LIMIT;
  if (!*count) {
    if (tc_pki_work_charge(work, capacity) != TC_TLV_OK)
      return TC_TLV_LIMIT;
    for (size_t i = 0; i < capacity; ++i)
      nodes[i].hash_head = SIZE_MAX;
  }
  if (tc_pki_work_charge(work, certificate.length) != TC_TLV_OK)
    return TC_TLV_LIMIT;
  bucket = (size_t)tc_x509_crl_bytes_hash(certificate) % capacity;
  for (cursor = nodes[bucket].hash_head; cursor != SIZE_MAX; cursor = nodes[cursor].hash_next) {
    if (cursor >= *count)
      return TC_TLV_ARGUMENT;
    const TC_bytes previous = nodes[cursor].certificate;
    if (tc_pki_work_charge(work, 1) != TC_TLV_OK)
      return TC_TLV_LIMIT;
    if (previous.length != certificate.length)
      continue;
    if (tc_pki_work_charge(work, certificate.length) != TC_TLV_OK)
      return TC_TLV_LIMIT;
    if (tc_pki_equal(previous, certificate)) {
      *index = cursor;
      return TC_TLV_OK;
    }
  }
  if (*count == capacity)
    return TC_TLV_LIMIT;
  nodes[*count].certificate = certificate;
  nodes[*count].status = TC_X509_REVOCATION_UNDETERMINED;
  nodes[*count].hash_next = nodes[bucket].hash_head;
  nodes[bucket].hash_head = *count;
  *index = (*count)++;
  return TC_TLV_OK;
}
#endif
