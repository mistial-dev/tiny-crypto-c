/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * CMS signer path building and credential validation: signer selection,
 * path storage checks, path build and revocation checking. */
#include <tiny_crypto/cms_validation.h>
#include <tiny_crypto/piv_oid.h>
#if TC_ENABLE_CMS_VALIDATION
#include "cms_internal.h"
#include "credential_status_internal.h"
#include "pki_identifier_internal.h"
#include "cms_signature_internal.h"
#include "pki_status_internal.h"
#include "pki_hash_parts_internal.h"

typedef struct {
  const TC_CMS_signer_info* signer;
  TC_TLV_profile profile;
  const TC_X509_name_workspace* names;
} cms_signer_filter;
static TC_TLV_result cms_signer_candidate(const void* context, const TC_X509_certificate* candidate,
                                          const TC_TLV_limits* limits,
                                          const tc_pki_tree_workspace* tree, int* matched)
{
  const cms_signer_filter* filter = context;
  return tc_cms_signer_matches(filter->signer, filter->profile, candidate, limits, filter->names,
                               tree, matched);
}

typedef struct {
  const TC_CMS_signer_info* signer;
  TC_bytes content_type, digest;
  TC_CMS_verification_policy policy;
  const TC_X509_store_source* source;
  const TC_X509_path_options* options;
  const tc_pki_tree_workspace* tree;
  const TC_CMS_signature_workspace* signature;
  const TC_X509_path_workspace* validation;
  const TC_X509_search_workspace* search;
  tc_cms_signed_attrs_cache* signed_attrs;
} cms_signer_trust;

static TC_TLV_result cms_signer_attempt(const void* context, const TC_X509_certificate* candidate,
                                        TC_X509_search_result* out)
{
  const cms_signer_trust* trust = context;
  TC_bytes signer_name = {NULL, 0};
  TC_X509_signature_result signature = tc_cms_signer_verify_cached(
      trust->signer, trust->content_type, trust->digest, TC_CMS_VERIFY_DIGEST, trust->policy,
      &candidate->public_key, &trust->options->signatures, &trust->options->parsing,
      trust->signature, trust->tree->work, &signer_name, trust->signed_attrs);
  if (signature != TC_X509_SIGNATURE_VALID)
    return tc_pki_signature_status(signature);
  if (signer_name.data) {
    int matched;
    TC_TLV_result result = tc_pki_name_equal(
        signer_name, trust->policy.attributes == TC_CMS_ATTRIBUTES_DER ? TC_TLV_DER : TC_TLV_BER,
        candidate->subject, TC_TLV_DER, &trust->options->parsing, &trust->validation->names,
        trust->tree, &matched);
    if (result != TC_TLV_OK)
      return result;
    if (!matched)
      return TC_TLV_INVALID;
  }
  return tc_x509_path_result_status(tc_x509_path_build_work(candidate->encoded, trust->source,
                                                            trust->options, trust->validation,
                                                            trust->search, trust->tree->work, out));
}

TC_X509_path_status
tc_cms_signer_find(const tc_cms_candidates* candidates, const TC_CMS_signer_info* signer,
                   TC_bytes content_type, TC_bytes digest, TC_CMS_verification_policy policy,
                   const TC_X509_store_source* path_source, const TC_X509_path_options* options,
                   const tc_pki_tree_workspace* tree, const TC_CMS_signature_workspace* signature,
                   const TC_X509_path_workspace* validation, const TC_X509_search_workspace* search,
                   TC_X509_search_result* out, tc_cms_signed_attrs_cache* signed_attrs)
{
  if (!signer || !path_source || !options || !signature || !validation || !search ||
      !content_type.data || !content_type.length || !digest.data || !digest.length ||
      !tc_cms_verification_policy_valid(policy))
    return TC_X509_PATH_ERROR;
  const cms_signer_filter filter = {signer, TC_TLV_BER, &validation->names};
  const cms_signer_trust trust = {signer, content_type, digest,     policy, path_source, options,
                                  tree,   signature,    validation, search, signed_attrs};
  return tc_x509_path_status(tc_cms_certificate_search(candidates, cms_signer_candidate, &filter,
                                                       &options->parsing, tree, validation,
                                                       cms_signer_attempt, &trust, out, NULL));
}

enum {
  CMS_PATH_WRITE = TC_X509_PATH_STORAGE_COUNT,
  CMS_SEARCH_WRITE,
  CMS_INDEX_WRITE,
  CMS_SIGNATURE_WRITE,
  CMS_SIGNED_DIGEST_WRITE,
  CMS_RESULT_WRITE,
  CMS_WORK_WRITE,
  CMS_PATH_WRITE_COUNT
};

/* Record path, search, index, signature, result and work writes in
 * CMS_*_WRITE slot order. */
static void cms_path_plan_writes(tc_pki_storage_plan* plan, const TC_CMS_path_workspace* workspace,
                                 size_t* work, TC_X509_search_result* out)
{
  tc_x509_path_storage_plan(plan, &workspace->validation);
  TC_PKI_PLAN_WRITE(plan, workspace->search.path, workspace->search.capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->search.frames, workspace->search.capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->certificates, workspace->certificate_capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->signature, workspace->signature_capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->signed_digest, workspace->signed_digest_capacity);
  TC_PKI_PLAN_WRITE(plan, out, 1);
  TC_PKI_PLAN_WRITE(plan, work, 1);
}

static void cms_path_plan_inputs(tc_pki_storage_plan* plan, const TC_CMS_signer_info* signer,
                                 const TC_bytes* inputs, size_t input_count, const TC_bytes* parts,
                                 size_t part_count, const TC_X509_store_source* source,
                                 const TC_CMS_path_options* options,
                                 const TC_CMS_path_workspace* workspace)
{
  if (signer)
    TC_PKI_PLAN_INPUT(plan, signer, 1);
  TC_PKI_PLAN_INPUT(plan, source, 1);
  TC_PKI_PLAN_INPUT(plan, options, 1);
  TC_PKI_PLAN_INPUT(plan, workspace, 1);
  TC_PKI_PLAN_INPUT(plan, parts, part_count);
  if (signer) {
    TC_bytes signer_fields[TC_CMS_SIGNER_SPAN_COUNT];
    tc_cms_signer_spans(signer, signer_fields);
    tc_pki_storage_plan_input_spans(plan, signer_fields, TC_CMS_SIGNER_SPAN_COUNT);
  }
  tc_pki_storage_plan_input_spans(plan, inputs, input_count);
  tc_pki_storage_plan_input_spans(plan, parts, part_count);
  tc_x509_path_options_plan_inputs(plan, &options->path);
}

static TC_TLV_result cms_path_storage(const TC_CMS_signer_info* signer, const TC_bytes* inputs,
                                      size_t input_count, const TC_bytes* parts, size_t part_count,
                                      const TC_X509_store_source* source,
                                      const TC_CMS_path_options* options,
                                      const TC_CMS_path_workspace* workspace, size_t* work,
                                      TC_X509_search_result* out,
                                      TC_bytes writes[CMS_PATH_WRITE_COUNT], size_t* remaining)
{
  tc_pki_storage_plan plan;
  tc_pki_storage_plan_begin(&plan, writes, CMS_PATH_WRITE_COUNT, *work);
  cms_path_plan_writes(&plan, workspace, work, out);
  tc_pki_storage_plan_seal(&plan);
  cms_path_plan_inputs(&plan, signer, inputs, input_count, parts, part_count, source, options,
                       workspace);
  return tc_pki_storage_plan_finish(&plan, remaining);
}

static int cms_path_arguments(const TC_X509_store_source* source,
                              const TC_CMS_path_options* options,
                              const TC_CMS_path_workspace* workspace, size_t* work,
                              TC_X509_search_result* out)
{
  return source && options && workspace && work && out && workspace->signed_digest &&
         workspace->signed_digest_capacity >= TC_CMS_SIGNED_DIGEST_BYTES &&
         (!source->candidate_count || source->candidate) &&
         (!source->anchor_count || source->anchor) &&
         tc_cms_verification_policy_valid(
             (TC_CMS_verification_policy){options->attributes, options->rsa_parameters});
}

static TC_TLV_result cms_selected_certificate(void* context, size_t index, size_t* work,
                                              TC_bytes* out)
{
  (void)work;
  if (index)
    return TC_TLV_END;
  *out = *(const TC_bytes*)context;
  return TC_TLV_OK;
}

/* All inputs and source records are covered by the caller's storage preflight. */
static TC_X509_path_status
cms_signer_path_build(const TC_CMS_signer_info* signer, TC_bytes content_type, TC_bytes digest,
                      TC_bytes embedded, TC_bytes selected, const TC_X509_store_source* source,
                      const TC_CMS_path_options* options, const TC_CMS_path_workspace* workspace,
                      size_t* work, TC_X509_search_result* out,
                      const TC_bytes writes[CMS_PATH_WRITE_COUNT])
{
  tc_cms_candidates candidates;
  tc_cms_path_source context;
  TC_X509_store_source indexed;
  TC_TLV_result result;
  tc_pki_source_guard guard = {source, writes, CMS_PATH_WRITE_COUNT};
  TC_X509_store_source guarded = tc_pki_source_guard_bind(&guard);
  const tc_pki_tree_workspace tree = {workspace->validation.frames,
                                      workspace->validation.frame_capacity, work};
  const TC_CMS_signature_workspace signature = {
      workspace->validation.frames, workspace->validation.frame_capacity, workspace->signature,
      workspace->signature_capacity};
  result = tc_cms_candidates_init(embedded, &guarded, options->max_candidates,
                                  options->max_candidate_bytes, &options->path.parsing, &tree,
                                  &candidates);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  result = tc_cms_path_source_init(&candidates, &tree, workspace->certificates,
                                   workspace->certificate_capacity, &context, &indexed);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  /* Reuse the index for identity search and path construction. External records
   * have already been fetched and checked against every writable range. */
  /* Explicit selection limits the signer search; issuers still use the index. */
  const TC_X509_store_source selection = {&selected, 1, 0, cms_selected_certificate, NULL};
  const TC_X509_store_source* signers = selected.length ? &selection : &indexed;
  result = tc_cms_candidates_init(
      (TC_bytes){NULL, 0}, signers,
      selected.length ? options->max_candidates : indexed.candidate_count,
      options->max_candidate_bytes, &options->path.parsing, &tree, &candidates);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  tc_cms_signed_attrs_cache signed_attrs = {0};
  signed_attrs.digest = workspace->signed_digest;
  signed_attrs.capacity = workspace->signed_digest_capacity;
  const TC_X509_path_status status =
      tc_cms_signer_find(&candidates, signer, content_type, digest,
                         (TC_CMS_verification_policy){options->attributes, options->rsa_parameters},
                         &indexed, &options->path, &tree, &signature, &workspace->validation,
                         &workspace->search, out, &signed_attrs);
  TC_secure_zero(workspace->signed_digest, TC_CMS_SIGNED_DIGEST_BYTES);
  return status;
}

TC_X509_path_status TC_CMS_signer_path_build(const TC_CMS_signer_info* signer,
                                             TC_bytes content_type, TC_bytes digest,
                                             TC_bytes embedded, const TC_X509_store_source* source,
                                             const TC_CMS_path_options* options,
                                             const TC_CMS_path_workspace* workspace, size_t* work,
                                             TC_X509_search_result* out)
{
  TC_bytes writes[CMS_PATH_WRITE_COUNT];
  TC_TLV_result result;
  TC_X509_path_status status;
  size_t initial_work;
  if (!signer || !content_type.data || !content_type.length || !digest.data || !digest.length ||
      !cms_path_arguments(source, options, workspace, work, out))
    return TC_X509_PATH_ERROR;
  initial_work = *work;
  const TC_bytes inputs[] = {content_type, digest, embedded};
  result = cms_path_storage(signer, inputs, sizeof inputs / sizeof *inputs, NULL, 0, source,
                            options, workspace, work, out, writes, work);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  status = cms_signer_path_build(signer, content_type, digest, embedded, (TC_bytes){NULL, 0},
                                 source, options, workspace, work, out, writes);
  if (status == TC_X509_PATH_VALID)
    out->validation.work_used = initial_work - *work;
  return status;
}

/* Keep the hash context local to the content phase. */
static TC_TLV_result cms_signed_content_digest(const TC_CMS_signed_data* data,
                                               const TC_bytes* detached, size_t detached_count,
                                               TC_hash_algorithm algorithm,
                                               const TC_TLV_limits* limits,
                                               const tc_pki_tree_workspace* tree, uint8_t* digest)
{
  TC_hash_context scratch;
  TC_TLV_result result =
      data->has_content
          ? tc_cms_hash_content(data->content, TC_CMS_CONTENT_BER_OCTETS, algorithm, limits, tree,
                                &scratch, digest)
          : tc_pki_hash_parts(detached, detached_count, algorithm, limits, tree, &scratch, digest);
  TC_secure_zero(&scratch, sizeof scratch);
  return result;
}

static TC_X509_path_status cms_signed_data_path_build_parts(
    TC_bytes encoded, size_t signer_index, TC_bytes expected_type, const TC_bytes* detached_content,
    size_t detached_count, TC_bytes selected, const tc_cms_prepared_signed_data* prepared,
    const TC_X509_store_source* source, const TC_CMS_path_options* options,
    const TC_CMS_path_workspace* workspace, size_t* work, TC_X509_search_result* out)
{
  enum { MAX_DIGEST_BYTES = 64 };
  TC_bytes writes[CMS_PATH_WRITE_COUNT];
  TC_CMS_signed_data data;
  TC_CMS_signer_info signer;
  TC_hash_algorithm algorithm;
  tc_hash_info hash;
  uint8_t digest[MAX_DIGEST_BYTES];
  TC_TLV_result result;
  TC_X509_path_status status;
  size_t initial_work;
  if (!encoded.data || !encoded.length || !expected_type.data || !expected_type.length ||
      !cms_path_arguments(source, options, workspace, work, out))
    return TC_X509_PATH_ERROR;
  initial_work = *work;
  const TC_bytes inputs[] = {encoded, expected_type, selected};
  result = cms_path_storage(prepared ? prepared->signer : NULL, inputs,
                            sizeof inputs / sizeof *inputs, detached_content, detached_count,
                            source, options, workspace, work, out, writes, work);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  const TC_TLV_limits* limits = &options->path.parsing;
  const tc_pki_tree_workspace tree = {workspace->validation.frames,
                                      workspace->validation.frame_capacity, work};
  if (tc_pki_work_charge(work, expected_type.length) != TC_TLV_OK)
    return TC_X509_PATH_LIMIT;
  if (TC_DER_oid_contents(expected_type.data, expected_type.length) != TC_TLV_OK)
    return TC_X509_PATH_ERROR;
  if (prepared) {
    if (signer_index || !prepared->data || !prepared->signer ||
        prepared->data->encoded.data != encoded.data ||
        prepared->data->encoded.length != encoded.length)
      return TC_X509_PATH_ERROR;
    data = *prepared->data;
  } else {
    result = tc_cms_signed_data_read(encoded, limits, tree.frames, tree.capacity, work, &data);
    if (result != TC_TLV_OK)
      return tc_x509_path_status(result);
  }
  /* Attached content cannot be replaced by application bytes. */
  if (data.has_content && detached_count)
    return TC_X509_PATH_ERROR;
  if (tc_pki_work_charge(work, data.content_type.length) != TC_TLV_OK)
    return TC_X509_PATH_LIMIT;
  if (!tc_pki_equal(data.content_type, expected_type))
    return TC_X509_PATH_INVALID;
  if (prepared)
    signer = *prepared->signer;
  else {
    result = tc_cms_signed_data_check(&data, limits, &tree, signer_index, &signer);
    if (result != TC_TLV_OK)
      return tc_x509_path_status(result);
  }
  result = tc_cms_digest_algorithms(data.digest_algorithms, &signer.digest_algorithm, limits, &tree,
                                    &algorithm);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  if (!tc_hash_info_get(algorithm, &hash))
    return TC_X509_PATH_UNSUPPORTED;
  result = cms_signed_content_digest(&data, detached_content, detached_count, algorithm, limits,
                                     &tree, digest);
  if (result == TC_TLV_OK)
    status = cms_signer_path_build(&signer, data.content_type,
                                   (TC_bytes){digest, hash.digest_length}, data.certificates,
                                   selected, source, options, workspace, work, out, writes);
  else
    status = tc_x509_path_status(result);
  TC_secure_zero(digest, sizeof digest);
  if (status == TC_X509_PATH_VALID)
    out->validation.work_used = initial_work - *work;
  return status;
}

TC_X509_path_status TC_CMS_signed_data_path_build_parts(
    TC_bytes encoded, size_t signer_index, TC_bytes expected_type, const TC_bytes* detached_content,
    size_t detached_count, const TC_X509_store_source* source, const TC_CMS_path_options* options,
    const TC_CMS_path_workspace* workspace, size_t* work, TC_X509_search_result* out)
{
  return cms_signed_data_path_build_parts(encoded, signer_index, expected_type, detached_content,
                                          detached_count, (TC_bytes){NULL, 0}, NULL, source,
                                          options, workspace, work, out);
}

TC_X509_path_status TC_CMS_signed_data_path_build(TC_bytes encoded, size_t signer_index,
                                                  TC_bytes expected_type, TC_bytes detached_content,
                                                  const TC_X509_store_source* source,
                                                  const TC_CMS_path_options* options,
                                                  const TC_CMS_path_workspace* workspace,
                                                  size_t* work, TC_X509_search_result* out)
{
  const size_t count = detached_content.data || detached_content.length ? 1u : 0u;
  return TC_CMS_signed_data_path_build_parts(encoded, signer_index, expected_type,
                                             count ? &detached_content : NULL, count, source,
                                             options, workspace, work, out);
}

static TC_credential_status cms_credential_error(TC_TLV_result result)
{
  return tc_credential_tlv_status(result, &tc_credential_tlv_cms);
}

TC_credential_status tc_cms_path_revocation_check(const TC_X509_search_result* path,
                                                  const TC_X509_store_source* source,
                                                  const TC_CMS_revocation_policy* revocation,
                                                  const TC_CMS_credential_workspace* workspace,
                                                  size_t* work)
{
  for (size_t i = 0; i < path->count; ++i)
    workspace->held_path[i] = path->path[i];
  const TC_X509_revocation_options policy = {revocation->index,
                                             source,
                                             revocation->signer_policy,
                                             path->anchor_index,
                                             revocation->max_candidate_bytes,
                                             revocation->delta_policy,
                                             revocation->order_policy};
  const TC_X509_revocation_workspace scratch = {&workspace->path->validation,
                                                &workspace->path->search,
                                                workspace->crl_states,
                                                workspace->crl_capacity,
                                                workspace->nodes,
                                                workspace->node_capacity,
                                                workspace->scopes,
                                                workspace->scope_capacity,
                                                workspace->signer_path,
                                                workspace->signer_path_capacity,
                                                workspace->signer_policies,
                                                workspace->signer_policy_capacity};
  TC_X509_revocation_result checked;
  TC_TLV_result result = TC_X509_path_check_revocation(workspace->held_path, path->count, &policy,
                                                       &scratch, work, &checked);
  if (result != TC_TLV_OK)
    return cms_credential_error(result);
  if (checked.status == TC_X509_CRL_REVOKED)
    return TC_CREDENTIAL_REVOKED;
  return checked.status == TC_X509_CRL_UNREVOKED ? TC_CREDENTIAL_VALID : TC_CREDENTIAL_UNSUPPORTED;
}

static TC_credential_status cms_credential_validate_impl(
    const TC_CMS_validation_request* request, const TC_X509_store_source* source,
    const TC_CMS_path_options* options, const TC_CMS_revocation_policy* revocation,
    const TC_CMS_credential_workspace* workspace, size_t* work, const TC_bytes* metadata,
    size_t metadata_count, const tc_cms_prepared_signed_data* prepared)
{
  enum { HELD_PATH = CMS_PATH_WRITE_COUNT, CRL_STATES, CRL_NODES, WRITE_COUNT };
  TC_bytes writes[WRITE_COUNT];
  TC_X509_search_result path;
  TC_TLV_result result;
  int time_order;
  if (!request || (metadata_count && !metadata))
    return TC_CREDENTIAL_ERROR;
  const TC_bytes encoded = request->encoded;
  const TC_bytes expected_type = request->expected_type;
  const TC_bytes* detached_content = request->detached_content;
  const size_t detached_count = request->detached_count;
  const size_t signer_index = request->signer_index;
  const TC_bytes selected = request->signer_certificate;
  if (prepared && (signer_index || !prepared->data || !prepared->signer ||
                   prepared->data->encoded.data != encoded.data ||
                   prepared->data->encoded.length != encoded.length))
    return TC_CREDENTIAL_ERROR;
  if ((!selected.data) != (!selected.length))
    return TC_CREDENTIAL_ERROR;
  if (!encoded.data || !encoded.length || !expected_type.data || !expected_type.length ||
      !workspace || !workspace->path || !revocation || !revocation->index ||
      !revocation->signer_policy ||
      !cms_path_arguments(source, options, workspace->path, work, &path) ||
      (revocation->index->count && !revocation->index->records) ||
      (revocation->delta_policy != TC_X509_CRL_COMPLETE_ONLY &&
       revocation->delta_policy != TC_X509_CRL_DELTA_IF_AVAILABLE &&
       revocation->delta_policy != TC_X509_CRL_DELTA_REQUIRED) ||
      (revocation->order_policy != TC_X509_CRL_ORDER_NUMBER &&
       revocation->order_policy != TC_X509_CRL_ORDER_THIS_UPDATE) ||
      TC_X509_time_compare(&options->path.at, &revocation->signer_policy->at, &time_order) !=
          TC_TLV_OK ||
      time_order)
    return TC_CREDENTIAL_ERROR;
  if (workspace->path_capacity < workspace->path->search.capacity ||
      workspace->crl_capacity < revocation->index->count)
    return TC_CREDENTIAL_LIMIT;
  const TC_bytes inputs[] = {encoded, expected_type, selected};
  size_t budget;
  tc_pki_storage_plan plan;
  tc_pki_storage_plan_begin(&plan, writes, WRITE_COUNT, *work);
  cms_path_plan_writes(&plan, workspace->path, work, &path);
  TC_PKI_PLAN_WRITE(&plan, workspace->held_path, workspace->path_capacity);
  TC_PKI_PLAN_WRITE(&plan, workspace->crl_states, workspace->crl_capacity);
  TC_PKI_PLAN_WRITE(&plan, workspace->nodes, workspace->node_capacity);
  tc_pki_storage_plan_seal(&plan);
  cms_path_plan_inputs(&plan, NULL, inputs, sizeof inputs / sizeof *inputs, detached_content,
                       detached_count, source, options, workspace->path);
  TC_PKI_PLAN_INPUT(&plan, workspace, 1);
  TC_PKI_PLAN_INPUT(&plan, request, 1);
  TC_PKI_PLAN_INPUT(&plan, revocation, 1);
  TC_PKI_PLAN_INPUT(&plan, revocation->index, 1);
  TC_PKI_PLAN_INPUT(&plan, revocation->index->records, revocation->index->count);
  TC_PKI_PLAN_INPUT(&plan, revocation->signer_policy, 1);
  if (prepared) {
    TC_PKI_PLAN_INPUT(&plan, prepared, 1);
    TC_PKI_PLAN_INPUT(&plan, prepared->data, 1);
    TC_PKI_PLAN_INPUT(&plan, prepared->signer, 1);
  }
  tc_x509_path_options_plan_inputs(&plan, revocation->signer_policy);
  tc_pki_storage_plan_input_spans(&plan, metadata, metadata_count);
  tc_x509_crl_index_plan_inputs(&plan, revocation->index);
  result = tc_pki_storage_plan_finish(&plan, &budget);
  if (result != TC_TLV_OK)
    return cms_credential_error(result);
  tc_pki_source_guard guard = {source, writes, WRITE_COUNT};
  const TC_X509_store_source guarded = tc_pki_source_guard_bind(&guard);
  *work = budget;
  switch (cms_signed_data_path_build_parts(encoded, signer_index, expected_type, detached_content,
                                           detached_count, selected, prepared, &guarded, options,
                                           workspace->path, work, &path)) {
  case TC_X509_PATH_VALID:
    break;
  case TC_X509_PATH_INVALID:
    return TC_CREDENTIAL_INVALID;
  case TC_X509_PATH_UNSUPPORTED:
    return TC_CREDENTIAL_UNSUPPORTED;
  case TC_X509_PATH_LIMIT:
    return TC_CREDENTIAL_LIMIT;
  default:
    return TC_CREDENTIAL_ERROR;
  }
  return tc_cms_path_revocation_check(&path, &guarded, revocation, workspace, work);
}

TC_credential_status tc_cms_credential_validate_with_metadata(
    const TC_CMS_validation_request* request, const TC_X509_store_source* source,
    const TC_CMS_path_options* options, const TC_CMS_revocation_policy* revocation,
    const TC_CMS_credential_workspace* workspace, size_t* work, const TC_bytes* metadata,
    size_t metadata_count)
{
  return cms_credential_validate_impl(request, source, options, revocation, workspace, work,
                                      metadata, metadata_count, NULL);
}

TC_credential_status tc_cms_credential_validate_prepared(
    const TC_CMS_validation_request* request, const TC_X509_store_source* source,
    const TC_CMS_path_options* options, const TC_CMS_revocation_policy* revocation,
    const TC_CMS_credential_workspace* workspace, size_t* work,
    const tc_cms_prepared_signed_data* prepared)
{
  return cms_credential_validate_impl(request, source, options, revocation, workspace, work, NULL,
                                      0, prepared);
}

TC_credential_status TC_CMS_credential_validate(const TC_CMS_validation_request* request,
                                                const TC_X509_store_source* source,
                                                const TC_CMS_path_options* options,
                                                const TC_CMS_revocation_policy* revocation,
                                                const TC_CMS_credential_workspace* workspace,
                                                size_t* work)
{
  return tc_cms_credential_validate_with_metadata(request, source, options, revocation, workspace,
                                                  work, NULL, 0);
}

TC_TLV_result tc_cms_signer_matches(const TC_CMS_signer_info* signer, TC_TLV_profile profile,
                                    const TC_X509_certificate* certificate,
                                    const TC_TLV_limits* limits,
                                    const TC_X509_name_workspace* names,
                                    const tc_pki_tree_workspace* tree, int* matched)
{
  TC_TLV_result result;
  if (!signer || !certificate || !limits || !tree || !tree->work || !matched ||
      (profile != TC_TLV_DER && profile != TC_TLV_BER))
    return TC_TLV_ARGUMENT;
  if (signer->version == 1) {
    if (!names || !signer->issuer.data || !signer->serial.length || signer->subject_key_id.data)
      return TC_TLV_ARGUMENT;
    if (tc_pki_work_charge(tree->work, signer->serial.length) != TC_TLV_OK ||
        tc_pki_work_charge(tree->work, certificate->serial.length) != TC_TLV_OK)
      return TC_TLV_LIMIT;
    /* Both readers require minimal INTEGER contents, including sign padding. */
    if (signer->serial_negative != certificate->serial_negative ||
        !tc_pki_equal(signer->serial, certificate->serial)) {
      *matched = 0;
      return TC_TLV_OK;
    }
    return tc_pki_name_equal(signer->issuer, profile, certificate->issuer, TC_TLV_DER, limits,
                             names, tree, matched);
  }
  if (signer->version == 3) {
    TC_bytes ski = {NULL, 0};
    if (!signer->subject_key_id.data || signer->issuer.data || signer->serial.length)
      return TC_TLV_ARGUMENT;
    result = tc_pki_subject_key_identifier(certificate, limits, tree->work, &ski);
    if (result != TC_TLV_OK)
      return result;
    if (!ski.data) {
      *matched = 0;
      return TC_TLV_OK;
    }
    return tc_pki_octets_equal(signer->subject_key_id, 0x80, ski, profile, limits, tree, matched);
  }
  return TC_TLV_ARGUMENT;
}

#endif
