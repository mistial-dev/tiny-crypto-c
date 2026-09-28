/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/validation.h>
#include "cms_internal.h"
#include "credential_status_internal.h"
#include "internal.h"
#include "validation_internal.h"
#include "pki_storage_internal.h"
#include "pki_source_internal.h"
#include "x509_revocation_internal.h"

#if TC_ENABLE_CMS_VALIDATION

typedef struct {
  char byte;
  TC_validation_storage storage;
} validation_alignment;

size_t TC_validation_workspace_alignment(void)
{
  return offsetof(validation_alignment, storage);
}

TC_result TC_validation_capacity_init(TC_validation_profile profile, TC_validation_capacity* out)
{
  static const TC_validation_capacity presets[] = {{.frames = 16,
                                                    .oids = 16,
                                                    .name_scalars = 64,
                                                    .name_attributes = 8,
                                                    .policy_nodes = 32,
                                                    .policy_edges = 64,
                                                    .policy_expected = 64,
                                                    .policy_mappings = 16,
                                                    .policies = 16,
                                                    .path = 4,
                                                    .certificates = 8,
                                                    .signature_bytes = 384,
                                                    .crls = 4,
                                                    .revocation_nodes = 8},
                                                   {.frames = 24,
                                                    .oids = 32,
                                                    .name_scalars = 128,
                                                    .name_attributes = 16,
                                                    .policy_nodes = 64,
                                                    .policy_edges = 128,
                                                    .policy_expected = 128,
                                                    .policy_mappings = 32,
                                                    .policies = 32,
                                                    .path = 8,
                                                    .certificates = 16,
                                                    .signature_bytes = 384,
                                                    .crls = 16,
                                                    .revocation_nodes = 32},
                                                   {.frames = 32,
                                                    .oids = 64,
                                                    .name_scalars = 512,
                                                    .name_attributes = 64,
                                                    .policy_nodes = 256,
                                                    .policy_edges = 512,
                                                    .policy_expected = 512,
                                                    .policy_mappings = 128,
                                                    .policies = 128,
                                                    .path = 16,
                                                    .certificates = 128,
                                                    .signature_bytes = 512,
                                                    .crls = 128,
                                                    .revocation_nodes = 256}};
  if (!out || profile < TC_VALIDATION_MICRO || profile > TC_VALIDATION_DESKTOP)
    return TC_RESULT_ARGUMENT;
  *out = presets[profile];
  return TC_RESULT_OK;
}

/* Reserve an aligned array in the arena; reject size arithmetic overflow. */
static int reserve(size_t* offset, size_t count, size_t width, size_t* start)
{
  const size_t alignment = TC_validation_workspace_alignment();
  const size_t remainder = *offset % alignment;
  const size_t padding = remainder ? alignment - remainder : 0;
  if (padding > SIZE_MAX - *offset)
    return 0;
  *start = *offset + padding;
  if (count > (SIZE_MAX - *start) / width)
    return 0;
  *offset = *start + count * width;
  return 1;
}

/* Calculate the arena layout and array capacities. A NULL arena sizes the
 * workspace without assigning storage. */
static TC_result layout(const TC_validation_capacity* c, uint8_t* arena, TC_validation_workspace* w,
                        size_t* bytes)
{
  size_t offset = 0, start;
  if (!c || !c->frames || !c->oids || !c->name_scalars || !c->name_attributes || !c->path ||
      !c->certificates)
    return TC_RESULT_ARGUMENT;
#define ARRAY(field, type, count)                                                                  \
  do {                                                                                             \
    if (!reserve(&offset, (count), sizeof(type), &start))                                          \
      return TC_RESULT_LIMIT;                                                                      \
    w->field = arena && (count) ? (type*)(arena + start) : NULL;                                   \
  } while (0)
  ARRAY(path.validation.frames, TC_TLV_frame, c->frames);
  ARRAY(path.validation.oids, TC_bytes, c->oids);
  ARRAY(path.validation.names.left, uint32_t, c->name_scalars);
  ARRAY(path.validation.names.right, uint32_t, c->name_scalars);
  ARRAY(path.validation.names.matched, uint8_t, c->name_attributes);
  ARRAY(path.validation.nodes, TC_X509_policy_node, c->policy_nodes);
  ARRAY(path.validation.edges, TC_X509_policy_edge, c->policy_edges);
  ARRAY(path.validation.expected, TC_X509_policy_expected, c->policy_expected);
  ARRAY(path.validation.mappings, TC_X509_policy_mapping, c->policy_mappings);
  ARRAY(path.validation.policies, TC_bytes, c->policies);
  ARRAY(path.validation.certificates, TC_X509_certificate, c->path);
  ARRAY(path.validation.summaries, TC_X509_extension_summary, c->path);
  ARRAY(path.search.path, TC_bytes, c->path);
  ARRAY(path.search.frames, TC_X509_search_frame, c->path);
  ARRAY(path.certificates, TC_bytes, c->certificates);
  ARRAY(path.signature, uint8_t, c->signature_bytes);
  ARRAY(path.signed_digest, uint8_t, TC_CMS_SIGNED_DIGEST_BYTES);
  ARRAY(credential.held_path, TC_bytes, c->path);
  ARRAY(credential.crl_states, uint8_t, c->crls);
  ARRAY(credential.nodes, TC_X509_revocation_node, c->revocation_nodes);
  ARRAY(credential.scopes, TC_X509_revocation_scope, c->crls);
  ARRAY(credential.signer_path, TC_bytes, c->path);
  ARRAY(credential.signer_policies, TC_bytes, c->policies);
#undef ARRAY
  w->path.validation.frame_capacity = c->frames;
  w->path.validation.oid_capacity = c->oids;
  w->path.validation.names.scalar_capacity = c->name_scalars;
  w->path.validation.names.attribute_capacity = c->name_attributes;
  w->path.validation.node_capacity = c->policy_nodes;
  w->path.validation.edge_capacity = c->policy_edges;
  w->path.validation.expected_capacity = c->policy_expected;
  w->path.validation.mapping_capacity = c->policy_mappings;
  w->path.validation.policy_capacity = c->policies;
  w->path.validation.certificate_capacity = c->path;
  w->path.validation.summary_capacity = c->path;
  w->path.search.capacity = c->path;
  w->path.certificate_capacity = c->certificates;
  w->path.signature_capacity = c->signature_bytes;
  w->path.signed_digest_capacity = TC_CMS_SIGNED_DIGEST_BYTES;
  w->credential.path_capacity = c->path;
  w->credential.crl_capacity = c->crls;
  w->credential.node_capacity = c->revocation_nodes;
  w->credential.scope_capacity = c->crls;
  w->credential.signer_path_capacity = c->path;
  w->credential.signer_policy_capacity = c->policies;
  *bytes = offset;
  return TC_RESULT_OK;
}

TC_result TC_validation_workspace_size(const TC_validation_capacity* capacity, size_t* bytes)
{
  TC_validation_workspace workspace = {0};
  size_t size;
  if (!bytes)
    return TC_RESULT_ARGUMENT;
  TC_result result = layout(capacity, NULL, &workspace, &size);
  if (result == TC_RESULT_OK)
    *bytes = size;
  return result;
}

TC_result TC_validation_workspace_init(const TC_validation_capacity* capacity, TC_buffer arena,
                                       TC_validation_workspace* out)
{
  TC_validation_workspace workspace = {0};
  size_t size;
  if (!out || !capacity || !arena.data ||
      (uintptr_t)arena.data % TC_validation_workspace_alignment() ||
      arena.capacity > UINTPTR_MAX - (uintptr_t)arena.data ||
      !tc_internal_ranges_disjoint(arena.data, arena.capacity, out, sizeof *out) ||
      !tc_internal_ranges_disjoint(arena.data, arena.capacity, capacity, sizeof *capacity) ||
      !tc_internal_ranges_disjoint(out, sizeof *out, capacity, sizeof *capacity))
    return TC_RESULT_ARGUMENT;
  TC_result result = layout(capacity, NULL, &workspace, &size);
  if (result != TC_RESULT_OK)
    return result;
  if (arena.capacity < size)
    return TC_RESULT_LIMIT;
  result = layout(capacity, arena.data, &workspace, &size);
  if (result != TC_RESULT_OK)
    return result;
  workspace.credential.path = &out->path;
  *out = workspace;
  return TC_RESULT_OK;
}

TC_result TC_validation_context_init(const TC_validation_trust* trust,
                                     const TC_validation_options* options,
                                     const TC_CMS_credential_workspace* workspace,
                                     TC_validation_context* out)
{
  int order;
  if (!trust || !trust->certificates || !trust->crls || !options || !workspace ||
      !workspace->path || !out || !options->max_certificates || !options->max_input ||
      !options->max_candidates || !options->max_candidate_bytes ||
      TC_X509_time_compare(&options->at, &options->at, &order) != TC_TLV_OK ||
      (options->attributes != TC_CMS_ATTRIBUTES_DER &&
       options->attributes != TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER) ||
      (options->rsa_parameters != TC_CMS_RSA_PARAMETERS_NULL &&
       options->rsa_parameters != TC_CMS_RSA_PARAMETERS_ALLOW_ABSENT) ||
      options->delta_policy < TC_X509_CRL_COMPLETE_ONLY ||
      options->delta_policy > TC_X509_CRL_DELTA_REQUIRED ||
      (options->order_policy != TC_X509_CRL_ORDER_NUMBER &&
       options->order_policy != TC_X509_CRL_ORDER_THIS_UPDATE) ||
      !tc_internal_ranges_disjoint(out, sizeof *out, trust, sizeof *trust) ||
      !tc_internal_ranges_disjoint(out, sizeof *out, trust->certificates,
                                   sizeof *trust->certificates) ||
      !tc_internal_ranges_disjoint(out, sizeof *out, trust->crls, sizeof *trust->crls) ||
      !tc_internal_ranges_disjoint(out, sizeof *out, options, sizeof *options) ||
      !tc_internal_ranges_disjoint(out, sizeof *out, workspace, sizeof *workspace) ||
      !tc_internal_ranges_disjoint(out, sizeof *out, workspace->path, sizeof *workspace->path))
    return TC_RESULT_ARGUMENT;
  const TC_validation_context context = {*trust, options, workspace};
  *out = context;
  return TC_RESULT_OK;
}

static TC_X509_path_options path_policy(const TC_validation_options* options,
                                        const TC_validation_certificate_policy* policy)
{
  TC_X509_path_options path = {0};
  path.at = options->at;
  path.signatures = options->signatures;
  path.parsing = options->parsing;
  path.max_certificates = options->max_certificates;
  path.max_input = options->max_input;
  path.initial_policies = policy->initial_policies;
  path.initial_policy_count = policy->initial_policy_count;
  path.anchor_names = policy->anchor_names;
  path.purpose = policy->purpose;
  path.key_usage = policy->key_usage;
  path.flags = policy->flags;
  return path;
}

int tc_validation_policies(const TC_validation_context* context, TC_CMS_path_options* cms,
                           TC_X509_path_options* crl, TC_CMS_revocation_policy* revocation)
{
  if (!context || !context->options || !context->trust.certificates || !context->trust.crls ||
      !context->workspace || !context->workspace->path)
    return 0;
  const TC_validation_options* options = context->options;
  cms->path = path_policy(options, &options->certificate);
  cms->max_candidates = options->max_candidates;
  cms->max_candidate_bytes = options->max_candidate_bytes;
  cms->attributes = options->attributes;
  cms->rsa_parameters = options->rsa_parameters;
  *crl = path_policy(options, &options->crl_signer);
  revocation->index = context->trust.crls;
  revocation->signer_policy = crl;
  revocation->max_candidate_bytes = options->max_candidate_bytes;
  revocation->delta_policy = options->delta_policy;
  revocation->order_policy = options->order_policy;
  return 1;
}

void tc_validation_plan_writes(tc_pki_storage_plan* plan, const TC_validation_context* context,
                               size_t* work, void* out, size_t out_size)
{
  if (!context || !context->options || !context->workspace || !context->workspace->path ||
      !context->trust.certificates || !context->trust.crls || !work) {
    tc_pki_storage_plan_fail(plan, TC_TLV_ARGUMENT);
    return;
  }
  const TC_CMS_credential_workspace* w = context->workspace;
  const TC_CMS_path_workspace* p = w->path;
  tc_x509_path_storage_plan(plan, &p->validation);
  TC_PKI_PLAN_WRITE(plan, p->search.path, p->search.capacity);
  TC_PKI_PLAN_WRITE(plan, p->search.frames, p->search.capacity);
  TC_PKI_PLAN_WRITE(plan, p->certificates, p->certificate_capacity);
  TC_PKI_PLAN_WRITE(plan, p->signature, p->signature_capacity);
  TC_PKI_PLAN_WRITE(plan, p->signed_digest, p->signed_digest_capacity);
  TC_PKI_PLAN_WRITE(plan, w->held_path, w->path_capacity);
  TC_PKI_PLAN_WRITE(plan, w->crl_states, w->crl_capacity);
  TC_PKI_PLAN_WRITE(plan, w->nodes, w->node_capacity);
  TC_PKI_PLAN_WRITE(plan, work, 1);
  TC_PKI_PLAN_WRITE(plan, (uint8_t*)out, out_size);
}

void tc_validation_plan_inputs(tc_pki_storage_plan* plan, const TC_validation_context* context,
                               const TC_bytes* inputs, size_t input_count)
{
  if (plan->status != TC_TLV_OK)
    return;
  if (input_count && !inputs) {
    tc_pki_storage_plan_fail(plan, TC_TLV_ARGUMENT);
    return;
  }
  const TC_CMS_credential_workspace* w = context->workspace;
  const TC_validation_certificate_policy* policies[] = {&context->options->certificate,
                                                        &context->options->crl_signer};
  TC_PKI_PLAN_INPUT(plan, context, 1);
  TC_PKI_PLAN_INPUT(plan, context->options, 1);
  TC_PKI_PLAN_INPUT(plan, context->trust.certificates, 1);
  TC_PKI_PLAN_INPUT(plan, context->trust.crls, 1);
  TC_PKI_PLAN_INPUT(plan, w, 1);
  TC_PKI_PLAN_INPUT(plan, w->path, 1);
  TC_PKI_PLAN_INPUT(plan, inputs, input_count);
  for (size_t i = 0; i < sizeof policies / sizeof *policies; ++i)
    tc_x509_policy_plan_inputs(plan, policies[i]->initial_policies,
                               policies[i]->initial_policy_count, policies[i]->purpose,
                               &policies[i]->anchor_names);
  tc_pki_storage_plan_input_spans(plan, inputs, input_count);
  tc_x509_crl_index_plan_inputs(plan, context->trust.crls);
  if (w->path_capacity < w->path->search.capacity || w->crl_capacity < context->trust.crls->count)
    tc_pki_storage_plan_fail(plan, TC_TLV_LIMIT);
}

TC_TLV_result tc_validation_storage(const TC_validation_context* context, const TC_bytes* inputs,
                                    size_t input_count, size_t* work, void* out, size_t out_size,
                                    TC_bytes writes[TC_VALIDATION_WRITES])
{
  tc_pki_storage_plan plan;
  if (!work)
    return TC_TLV_ARGUMENT;
  tc_pki_storage_plan_begin(&plan, writes, TC_VALIDATION_WRITES, *work);
  tc_validation_plan_writes(&plan, context, work, out, out_size);
  tc_pki_storage_plan_seal(&plan);
  tc_validation_plan_inputs(&plan, context, inputs, input_count);
  return tc_pki_storage_plan_finish(&plan, work);
}

TC_credential_status TC_CMS_validate(const TC_CMS_validation_request* request,
                                     const TC_validation_context* context, size_t* work)
{
  TC_CMS_path_options cms;
  TC_X509_path_options crl;
  TC_CMS_revocation_policy revocation;
  if (!tc_validation_policies(context, &cms, &crl, &revocation))
    return TC_CREDENTIAL_ERROR;
  if (!request || !work)
    return TC_CREDENTIAL_ERROR;
  const TC_bytes metadata[] = {{(const uint8_t*)context, sizeof *context},
                               {(const uint8_t*)context->options, sizeof *context->options}};
  return tc_cms_credential_validate_with_metadata(request, context->trust.certificates, &cms,
                                                  &revocation, context->workspace, work, metadata,
                                                  sizeof metadata / sizeof *metadata);
}

TC_credential_status tc_validation_status(TC_TLV_result status)
{
  return tc_credential_tlv_status(status, &tc_credential_tlv_validation);
}

TC_credential_status TC_X509_validate(TC_bytes encoded, const TC_validation_context* context,
                                      size_t* work, TC_X509_validation_result* out)
{
  TC_CMS_path_options cms;
  TC_X509_path_options crl;
  TC_CMS_revocation_policy revocation;
  if (!encoded.data || !encoded.length || !out || !work ||
      !tc_validation_policies(context, &cms, &crl, &revocation))
    return TC_CREDENTIAL_ERROR;
  if (context->trust.certificates->candidate_count > cms.max_candidates)
    return TC_CREDENTIAL_LIMIT;
  TC_bytes writes[TC_VALIDATION_WRITES];
  TC_TLV_result status =
      tc_validation_storage(context, &encoded, 1, work, out, sizeof *out, writes);
  if (status != TC_TLV_OK)
    return tc_validation_status(status);
  tc_pki_source_guard guard = {context->trust.certificates, writes, TC_VALIDATION_WRITES};
  const TC_X509_store_source source = tc_pki_source_guard_bind(&guard);
  const TC_CMS_credential_workspace* workspace = context->workspace;
  TC_X509_search_result path;
  const TC_X509_path_status found =
      tc_x509_path_build_work(encoded, &source, &cms.path, &workspace->path->validation,
                              &workspace->path->search, work, &path);
  if (found != TC_X509_PATH_VALID)
    return tc_validation_status(tc_x509_path_result_status(found));

  TC_X509_validation_result result;
  /* Revocation signer searches reuse the certificate cache. Hold the target
   * descriptor while its encoded bytes remain owned by the caller. */
  result.certificate = workspace->path->validation.certificates[path.count - 1];
  TC_credential_status revocation_status =
      tc_cms_path_revocation_check(&path, &source, &revocation, workspace, work);
  if (revocation_status != TC_CREDENTIAL_VALID)
    return revocation_status;
  result.at = context->options->at;
  result.anchor_index = path.anchor_index;
  *out = result;
  return TC_CREDENTIAL_VALID;
}

#endif
