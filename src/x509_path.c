/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509.h>
#if TC_ENABLE_X509_PATH
#include "x509_path_internal.h"
#include "pki_status_internal.h"
#include "pki_internal.h"
#include "pki_storage_internal.h"
#include "pki_extensions_internal.h"
#include "internal.h"

int tc_x509_path_source_valid(const tc_x509_path_input* input)
{
  return input && (input->certificates || (input->encoded && input->parser && input->cache));
}

static TC_bytes path_encoded(const tc_x509_path_input* input, size_t index)
{
  return input->certificates ? input->certificates[index].encoded : input->encoded[index];
}

TC_TLV_result tc_x509_path_certificate(const tc_x509_path_input* input, size_t index, size_t* work,
                                       const TC_X509_certificate** certificate)
{
  TC_bytes encoded;
  TC_TLV_result result;
  if (input->certificates) {
    *certificate = &input->certificates[index];
    return TC_TLV_OK;
  }
  encoded = input->encoded[index];
  if (tc_pki_work_charge(work, encoded.length) != TC_TLV_OK)
    return TC_TLV_LIMIT;
  result = TC_X509_read(encoded.data, encoded.length, input->limits, input->parser,
                        &input->cache[index]);
  if (result != TC_TLV_OK)
    return result;
  *certificate = &input->cache[index];
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_path_summary(const tc_x509_path_input* input, size_t index, size_t* work,
                                   TC_X509_extension_summary* storage,
                                   const TC_X509_extension_summary** out)
{
  TC_X509_extension_summary* summary = input->summaries ? &input->summaries[index] : storage;
  const TC_X509_certificate* certificate;
  TC_TLV_result result;
  if (!summary->ready) {
    result = tc_x509_path_certificate(input, index, work, &certificate);
    if (result != TC_TLV_OK)
      return result;
    result = tc_x509_extensions_summarize(certificate, input->limits, work, summary);
    if (result != TC_TLV_OK)
      return result;
  }
  *out = summary;
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_path_basic(const tc_x509_path_input* input,
                                 const TC_X509_name_workspace* workspace, size_t* work,
                                 int* accepted)
{
  size_t i, j, total = 0, remaining, anchor_remaining;
  TC_bytes issuer_name;
  TC_X509_public_key issuer_key;
  if (!tc_x509_path_source_valid(input) || !workspace || !work || !accepted || !input->anchor ||
      !input->at || !input->limits || !input->count)
    return TC_TLV_ARGUMENT;
  anchor_remaining = input->anchor_path_len;
  if (input->count > input->max_certificates)
    return TC_TLV_LIMIT;
  for (i = 0; i < input->count; ++i) {
    const TC_bytes encoded = path_encoded(input, i);
    if (!encoded.data || !encoded.length)
      return TC_TLV_ARGUMENT;
    if (encoded.length > input->max_input - total)
      return TC_TLV_LIMIT;
    total += encoded.length;
    if (tc_pki_work_charge(work, encoded.length) != TC_TLV_OK)
      return TC_TLV_LIMIT;
    for (j = 0; j < i; ++j) {
      const TC_bytes previous = path_encoded(input, j);
      if (tc_pki_work_charge(work, 1) != TC_TLV_OK)
        return TC_TLV_LIMIT;
      if (encoded.length == previous.length) {
        if (tc_pki_work_charge(work, encoded.length) != TC_TLV_OK)
          return TC_TLV_LIMIT;
        if (tc_pki_equal(encoded, previous)) {
          *accepted = 0;
          return TC_TLV_OK;
        }
      }
    }
  }
  remaining = input->count - 1;
  issuer_name = input->anchor->name;
  issuer_key = input->anchor->public_key;
  for (i = 0; i < input->count; ++i) {
    const TC_X509_certificate* certificate;
    TC_X509_signature_result signature;
    TC_TLV_result result;
    int valid;
    result = tc_x509_path_certificate(input, i, work, &certificate);
    if (result != TC_TLV_OK)
      return result;
    if (tc_pki_work_charge(work, 1) != TC_TLV_OK)
      return TC_TLV_LIMIT;
    result = TC_X509_valid_at(certificate, input->at, &valid);
    if (result != TC_TLV_OK)
      return result;
    if (!valid) {
      *accepted = 0;
      return TC_TLV_OK;
    }
    signature = TC_X509_issuer_check(certificate, issuer_name, &issuer_key, input->signatures,
                                     input->limits, workspace, work);
    if (signature == TC_X509_SIGNATURE_INVALID) {
      *accepted = 0;
      return TC_TLV_OK;
    }
    result = tc_pki_signature_status(signature);
    if (result != TC_TLV_OK)
      return result;
    if (i + 1 < input->count) {
      TC_X509_extension_summary storage = {0};
      const TC_X509_extension_summary* extensions;
      TC_X509_basic_constraints basic;
      int self_issued;
      result = tc_x509_path_summary(input, i, work, &storage, &extensions);
      if (result != TC_TLV_OK)
        return result;
      basic = extensions->basic;
      /* An intermediate must be a CA with keyCertSign when keyUsage is present. */
      if (!tc_x509_summary_has(extensions, TC_X509_SUMMARY_BASIC_CONSTRAINTS) || !basic.ca ||
          (tc_x509_summary_has(extensions, TC_X509_SUMMARY_KEY_USAGE) &&
           !(extensions->key_usage & TC_KEY_USAGE_CERT_SIGN))) {
        *accepted = 0;
        return TC_TLV_OK;
      }
      result = TC_X509_name_equal(certificate->subject, certificate->issuer, input->limits,
                                  workspace, work, &self_issued);
      if (result != TC_TLV_OK)
        return result;
      if (!self_issued) {
        if (!remaining) {
          *accepted = 0;
          return TC_TLV_OK;
        }
        --remaining;
        if (input->has_anchor_path_len) {
          if (!anchor_remaining) {
            *accepted = 0;
            return TC_TLV_OK;
          }
          --anchor_remaining;
        }
      }
      if (basic.has_path_length && basic.path_length < remaining)
        remaining = basic.path_length;
    }
    issuer_name = certificate->subject;
    issuer_key = certificate->public_key;
  }
  *accepted = 1;
  return TC_TLV_OK;
}
TC_TLV_result tc_x509_path_constraint_distances(const TC_X509_name_constraints* constraints,
                                                const TC_TLV_limits* limits,
                                                const TC_X509_constraint_workspace* workspace,
                                                size_t* work)
{
  const TC_bytes lists[] = {constraints->permitted, constraints->excluded};
  TC_TLV_limits budget = *limits;
  unsigned i;
  for (i = 0; i < 2; ++i) {
    TC_TLV_reader reader;
    TC_X509_general_subtree subtree;
    TC_TLV_result result;
    if (tc_pki_work_charge(work, lists[i].length) != TC_TLV_OK)
      return TC_TLV_LIMIT;
    result = TC_TLV_reader_init(&reader, lists[i].data, lists[i].length, TC_TLV_DER, &budget);
    if (result != TC_TLV_OK)
      return result;
    while ((result = TC_X509_general_subtree_next(
                &reader, workspace->frames, workspace->frame_capacity, &subtree)) == TC_TLV_OK) {
      if (tc_pki_work_charge(work, 1) != TC_TLV_OK)
        return TC_TLV_LIMIT;
      if (subtree.minimum || subtree.has_maximum)
        return TC_TLV_UNSUPPORTED;
    }
    if (result != TC_TLV_END)
      return result;
    budget.max_elements -= reader.elements;
  }
  return TC_TLV_OK;
}

static TC_TLV_result
path_constraint_target(const TC_X509_certificate* certificate, int is_target, int charge_step,
                       const TC_X509_name_constraints* constraints, const TC_TLV_limits* limits,
                       const TC_X509_constraint_workspace* workspace, size_t* work, int* accepted)
{
  TC_TLV_result result;
  if (charge_step && tc_pki_work_charge(work, 1) != TC_TLV_OK)
    return TC_TLV_LIMIT;
  /* A self-issued intermediate may carry old names through key rollover. */
  if (!is_target) {
    result = TC_X509_name_equal(certificate->subject, certificate->issuer, limits, workspace->names,
                                work, accepted);
    if (result != TC_TLV_OK || *accepted)
      return result;
  }
  return TC_X509_certificate_names_check(certificate, constraints, limits, workspace, work,
                                         accepted);
}

TC_TLV_result tc_x509_path_names(const tc_x509_path_input* input,
                                 const TC_X509_constraint_workspace* workspace, size_t* work,
                                 int* accepted)
{
  size_t i, j;
  if (!tc_x509_path_source_valid(input) || !workspace || !workspace->names || !work || !accepted ||
      !input->limits || !input->count)
    return TC_TLV_ARGUMENT;
  if (input->count > input->max_certificates)
    return TC_TLV_LIMIT;
  for (i = 0; i + 1 < input->count; ++i) {
    TC_X509_extension_summary storage = {0};
    const TC_X509_extension_summary* extensions;
    TC_X509_name_constraints constraints;
    TC_TLV_result result;
    result = tc_x509_path_summary(input, i, work, &storage, &extensions);
    if (result != TC_TLV_OK)
      return result;
    if (!tc_x509_summary_has(extensions, TC_X509_SUMMARY_NAME_CONSTRAINTS))
      continue;
    const TC_bytes value = extensions->values[TC_X509_SUMMARY_NAME_CONSTRAINTS];
    result = TC_X509_name_constraints_read(value.data, value.length, input->limits, &constraints);
    if (result != TC_TLV_OK)
      return result;
    result = tc_x509_path_constraint_distances(&constraints, input->limits, workspace, work);
    if (result != TC_TLV_OK)
      return result;
    for (j = i + 1; j < input->count; ++j) {
      const TC_X509_certificate* certificate;
      int valid;
      /* Constraint spans borrow the issuer DER throughout this pass. */
      result = tc_x509_path_certificate(input, j, work, &certificate);
      if (result != TC_TLV_OK)
        return result;
      result = path_constraint_target(certificate, j + 1 == input->count, 1, &constraints,
                                      input->limits, workspace, work, &valid);
      if (result != TC_TLV_OK)
        return result;
      if (!valid) {
        *accepted = 0;
        return TC_TLV_OK;
      }
    }
  }
  *accepted = 1;
  return TC_TLV_OK;
}

void tc_x509_policy_counters_advance(tc_x509_policy_counters* counters,
                                     const tc_x509_policy_controls* controls, int self_issued,
                                     int target)
{
  const TC_X509_policy_constraints* constraints = &controls->constraints;
  if (target) {
    if (counters->explicit_policy)
      --counters->explicit_policy;
    if (constraints->has_require_explicit_policy && !constraints->require_explicit_policy)
      counters->explicit_policy = 0;
    return;
  }
  if (!self_issued) {
    if (counters->explicit_policy)
      --counters->explicit_policy;
    if (counters->mapping)
      --counters->mapping;
    if (counters->any)
      --counters->any;
  }
  if (constraints->has_require_explicit_policy &&
      constraints->require_explicit_policy < counters->explicit_policy)
    counters->explicit_policy = constraints->require_explicit_policy;
  if (constraints->has_inhibit_policy_mapping &&
      constraints->inhibit_policy_mapping < counters->mapping)
    counters->mapping = constraints->inhibit_policy_mapping;
  if (controls->has_inhibit_any && controls->inhibit_any < counters->any)
    counters->any = controls->inhibit_any;
}
static TC_TLV_result certificate_policies(const TC_X509_extension_summary* extensions, int target,
                                          const TC_TLV_limits* limits,
                                          const tc_x509_policy_workspace* workspace, size_t* work,
                                          size_t* policy_count, size_t* mapping_count,
                                          tc_x509_policy_controls* controls)
{
  TC_TLV_result result;
  *policy_count = *mapping_count = 0;
  tc_x509_policy_controls_from_summary(extensions, controls);
  if (tc_x509_summary_has(extensions, TC_X509_SUMMARY_POLICIES)) {
    const TC_bytes value = extensions->values[TC_X509_SUMMARY_POLICIES];
    const int critical = tc_x509_summary_critical(extensions, TC_X509_SUMMARY_POLICIES);
    TC_X509_policy_reader policies;
    TC_X509_policy policy;
    result = TC_X509_policies_init(&policies, value.data, value.length, limits, workspace->policies,
                                   workspace->policy_capacity);
    if (result != TC_TLV_OK)
      return result;
    for (;;) {
      /* Includes the decoder's comparisons against previously seen OIDs. */
      if (tc_pki_work_charge(work, value.length) != TC_TLV_OK)
        return TC_TLV_LIMIT;
      result = TC_X509_policy_next(&policies, &policy);
      if (result != TC_TLV_OK)
        break;
      result = tc_x509_policy_qualifiers_check(&policy, critical, limits, workspace->frames,
                                               workspace->frame_capacity, work);
      if (result != TC_TLV_OK)
        return result;
    }
    if (result != TC_TLV_END)
      return result;
    *policy_count = policies.count;
  }
  if (tc_x509_summary_has(extensions, TC_X509_SUMMARY_POLICY_MAPPINGS)) {
    const TC_bytes value = extensions->values[TC_X509_SUMMARY_POLICY_MAPPINGS];
    TC_TLV_reader mappings;
    TC_X509_policy_mapping mapping;
    if (target && tc_x509_summary_critical(extensions, TC_X509_SUMMARY_POLICY_MAPPINGS))
      return TC_TLV_INVALID;
    result = TC_X509_policy_mappings_init(&mappings, value.data, value.length, limits);
    if (result != TC_TLV_OK)
      return result;
    while ((result = TC_X509_policy_mapping_next(&mappings, &mapping)) == TC_TLV_OK) {
      if (tc_pki_work_charge(work, value.length) != TC_TLV_OK)
        return TC_TLV_LIMIT;
      if (*mapping_count == workspace->mapping_capacity)
        return TC_TLV_LIMIT;
      workspace->mappings[(*mapping_count)++] = mapping;
    }
    if (result != TC_TLV_END)
      return result;
  }
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_path_policies(const tc_x509_path_input* input,
                                    const tc_x509_policy_options* options,
                                    TC_bytes anchor_policy_set,
                                    const tc_x509_policy_workspace* workspace, size_t* work,
                                    size_t* count, int* accepted)
{
  tc_x509_policy_counters counters;
  TC_TLV_result result;
  size_t i, output_count;
  if (!tc_x509_path_source_valid(input) || !options || !workspace || !workspace->graph ||
      !workspace->names || !work || !count || !accepted || !input->limits || !input->count ||
      (workspace->policy_capacity && !workspace->policies) ||
      (workspace->mapping_capacity && !workspace->mappings) ||
      (workspace->output_capacity && !workspace->output) ||
      (options->initial_count && !options->initial))
    return TC_TLV_ARGUMENT;
  if (input->count > input->max_certificates || input->count == SIZE_MAX)
    return TC_TLV_LIMIT;
  counters.explicit_policy = options->require_explicit ? 0 : input->count + 1;
  counters.mapping = options->inhibit_mapping ? 0 : input->count + 1;
  counters.any = options->inhibit_any ? 0 : input->count + 1;
  result = tc_x509_policy_graph_init(workspace->graph);
  if (result != TC_TLV_OK)
    return result;
  for (i = 0; i < input->count; ++i) {
    const TC_X509_certificate* certificate;
    tc_x509_policy_controls controls;
    size_t policy_count, mapping_count;
    int self_issued, target = i + 1 == input->count;
    result = tc_x509_path_certificate(input, i, work, &certificate);
    if (result != TC_TLV_OK)
      return result;
    result = TC_X509_name_equal(certificate->subject, certificate->issuer, input->limits,
                                workspace->names, work, &self_issued);
    if (result != TC_TLV_OK)
      return result;
    TC_X509_extension_summary storage = {0};
    const TC_X509_extension_summary* extensions;
    result = tc_x509_path_summary(input, i, work, &storage, &extensions);
    if (result != TC_TLV_OK)
      return result;
    result = certificate_policies(extensions, target, input->limits, workspace, work, &policy_count,
                                  &mapping_count, &controls);
    if (result != TC_TLV_OK)
      return result;
    result = tc_x509_policy_graph_step(workspace->graph, workspace->policies, policy_count, NULL, 0,
                                       counters.any > 0 || (self_issued && !target), 0, work);
    if (result != TC_TLV_OK)
      return result;
    if (!counters.explicit_policy && !workspace->graph->nodes[0].alive) {
      *accepted = 0;
      *count = 0;
      return TC_TLV_OK;
    }
    if (!target) {
      result = tc_x509_policy_graph_map(workspace->graph, workspace->mappings, mapping_count,
                                        counters.mapping > 0, work);
      if (result != TC_TLV_OK)
        return result;
    }
    tc_x509_policy_counters_advance(&counters, &controls, self_issued, target);
  }
  result = tc_x509_policy_graph_output(workspace->graph, options->initial, options->initial_count,
                                       anchor_policy_set, input->limits, workspace->output,
                                       workspace->output_capacity, work, &output_count);
  if (result != TC_TLV_OK)
    return result;
  *count = output_count;
  *accepted = counters.explicit_policy > 0 || output_count > 0;
  return TC_TLV_OK;
}
void tc_x509_path_storage_plan(tc_pki_storage_plan* plan, const TC_X509_path_workspace* workspace)
{
  TC_PKI_PLAN_WRITE(plan, workspace->frames, workspace->frame_capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->oids, workspace->oid_capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->names.left, workspace->names.scalar_capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->names.right, workspace->names.scalar_capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->names.matched, workspace->names.attribute_capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->nodes, workspace->node_capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->edges, workspace->edge_capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->expected, workspace->expected_capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->mappings, workspace->mapping_capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->policies, workspace->policy_capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->certificates, workspace->certificate_capacity);
  TC_PKI_PLAN_WRITE(plan, workspace->summaries, workspace->summary_capacity);
}

void tc_x509_policy_plan_inputs(tc_pki_storage_plan* plan, const TC_bytes* initial_policies,
                                size_t initial_policy_count, TC_bytes purpose,
                                const TC_X509_name_constraints* anchor_names)
{
  const TC_bytes fields[] = {purpose, anchor_names->permitted, anchor_names->excluded};
  TC_PKI_PLAN_INPUT(plan, initial_policies, initial_policy_count);
  tc_pki_storage_plan_input_spans(plan, fields, sizeof fields / sizeof *fields);
  tc_pki_storage_plan_input_spans(plan, initial_policies, initial_policy_count);
}

void tc_x509_path_options_plan_inputs(tc_pki_storage_plan* plan,
                                      const TC_X509_path_options* options)
{
  tc_x509_policy_plan_inputs(plan, options->initial_policies, options->initial_policy_count,
                             options->purpose, &options->anchor_names);
}

/* Validation consumes the caller's work directly: storage checks are part of
 * the operation's cost, and work is one of the checked writes. */
static TC_TLV_result path_storage(const TC_bytes* chain, size_t count,
                                  const TC_X509_store_anchor* anchor,
                                  const TC_X509_path_options* options,
                                  const TC_X509_path_workspace* workspace, TC_X509_path_result* out,
                                  size_t* work)
{
  TC_bytes writes[TC_X509_PATH_STORAGE_COUNT + 1];
  const TC_bytes anchor_fields[] = {anchor->trust.name,
                                    anchor->trust.public_key.algorithm.oid,
                                    anchor->trust.public_key.algorithm.parameters,
                                    anchor->trust.public_key.key,
                                    anchor->trust.public_key.modulus,
                                    anchor->trust.public_key.exponent,
                                    anchor->trust.public_key.curve_oid,
                                    anchor->names.permitted,
                                    anchor->names.excluded,
                                    anchor->key_id,
                                    anchor->policy_set,
                                    anchor->extensions,
                                    anchor->certificate_extensions};
  tc_pki_storage_plan plan;
  TC_TLV_result result;

  tc_pki_storage_plan_begin(&plan, writes, sizeof writes / sizeof *writes, *work);
  tc_x509_path_storage_plan(&plan, workspace);
  TC_PKI_PLAN_WRITE(&plan, out, 1);
  tc_pki_storage_plan_seal(&plan);
  TC_PKI_PLAN_INPUT(&plan, chain, count);
  TC_PKI_PLAN_INPUT(&plan, anchor, 1);
  TC_PKI_PLAN_INPUT(&plan, options, 1);
  TC_PKI_PLAN_INPUT(&plan, workspace, 1);
  tc_pki_storage_plan_input_spans(&plan, anchor_fields,
                                  sizeof anchor_fields / sizeof *anchor_fields);
  tc_pki_storage_plan_input_spans(&plan, chain, count);
  tc_x509_path_options_plan_inputs(&plan, options);
  result = tc_pki_storage_plan_finish(&plan, NULL);
  *work = plan.budget;
  return result;
}

/* Anchor controls are normalized by the TrustAnchorInfo reader. Reject critical
 * extensions whose path semantics this validator does not implement. */
/* Check a trust anchor's extensions. The certificate's own extensions may
 * carry the path controls the validator applies. TrustAnchorInfo exts must
 * not carry them (RFC 5914 section 2.6), so any such extension there is
 * INVALID. Other critical extensions are UNSUPPORTED. */
static TC_TLV_result anchor_extensions_check(TC_bytes contents, int trust_anchor_info,
                                             const TC_TLV_limits* limits, size_t* work)
{
  TC_TLV_reader reader;
  TC_X509_extension extension;
  TC_TLV_result result;
  if (!contents.data)
    return contents.length ? TC_TLV_ARGUMENT : TC_TLV_OK;
  result = TC_TLV_reader_init(&reader, contents.data, contents.length, TC_TLV_DER, limits);
  if (result != TC_TLV_OK)
    return result;
  while ((result = tc_pki_extension_next(&reader, work, &extension)) == TC_TLV_OK) {
    const unsigned id = tc_pki_extension_id(&extension);
    const int path_control = tc_pki_extension_path_control(id);
    if (trust_anchor_info && path_control)
      return TC_TLV_INVALID;
    if (extension.critical && id != TC_PKI_EXT_SUBJECT_KEY_IDENTIFIER && id != TC_PKI_EXT_KEY_USAGE &&
        id != TC_PKI_EXT_BASIC_CONSTRAINTS && !path_control)
      return TC_TLV_UNSUPPORTED;
  }
  return result == TC_TLV_END ? TC_TLV_OK : result;
}

TC_X509_path_status tc_x509_path_validate_anchor(const TC_bytes* chain, size_t count,
                                                 const TC_X509_store_anchor* anchor,
                                                 const TC_X509_path_options* options,
                                                 const TC_X509_path_workspace* workspace,
                                                 size_t* work, TC_X509_path_result* out)
{
  TC_X509_workspace parser;
  TC_X509_constraint_workspace names;
  tc_x509_path_input input;
  tc_x509_policy_graph graph;
  tc_x509_policy_options policy_options;
  tc_x509_policy_workspace policy_workspace;
  tc_x509_path_usage usage;
  tc_x509_extension_workspace extension_workspace;
  const TC_X509_certificate* target;
  TC_X509_path_result validated;
  TC_TLV_result result;
  size_t i, set, initial_work, total = 0, policy_count;
  int accepted;
  if (!chain || !anchor || !options || !workspace || !work || !out ||
      (options->flags & ~(unsigned)TC_X509_PATH_SUPPORTED_FLAGS))
    return TC_X509_PATH_ERROR;
  if (anchor->x509_unusable)
    return TC_X509_PATH_INVALID;
  if (anchor->policy_flags &
      ~(unsigned)(TC_X509_PATH_REQUIRE_EXPLICIT_POLICY | TC_X509_PATH_INHIBIT_MAPPING |
                  TC_X509_PATH_INHIBIT_ANY_POLICY))
    return TC_X509_PATH_ERROR;
  if (!count)
    return TC_X509_PATH_INVALID;
  if (count > options->max_certificates || count > SIZE_MAX / sizeof *chain ||
      options->initial_policy_count > options->parsing.max_elements)
    return TC_X509_PATH_LIMIT;
  if (!workspace->certificates || count > workspace->certificate_capacity)
    return TC_X509_PATH_LIMIT;
  initial_work = *work;
  result = path_storage(chain, count, anchor, options, workspace, out, work);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  result = anchor_extensions_check(anchor->extensions, 1, &options->parsing, work);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  result = anchor_extensions_check(anchor->certificate_extensions, 0, &options->parsing, work);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  if (TC_X509_time_compare(&options->at, &options->at, &accepted) != TC_TLV_OK)
    return TC_X509_PATH_ERROR;
  for (i = 0; i < count; ++i) {
    if (tc_pki_work_charge(work, 1) != TC_TLV_OK)
      return TC_X509_PATH_LIMIT;
    if (!chain[i].length)
      return TC_X509_PATH_INVALID;
    if (chain[i].length > options->max_input - total)
      return TC_X509_PATH_LIMIT;
    total += chain[i].length;
  }
  for (i = 0; i < options->initial_policy_count; ++i) {
    TC_bytes oid = options->initial_policies[i];
    if (tc_pki_work_charge(work, oid.length) != TC_TLV_OK)
      return TC_X509_PATH_LIMIT;
    if (TC_DER_oid_contents(oid.data, oid.length) != TC_TLV_OK)
      return TC_X509_PATH_ERROR;
  }
  if (options->purpose.length) {
    if (tc_pki_work_charge(work, options->purpose.length) != TC_TLV_OK)
      return TC_X509_PATH_LIMIT;
    if (TC_DER_oid_contents(options->purpose.data, options->purpose.length) != TC_TLV_OK)
      return TC_X509_PATH_ERROR;
  }
  parser.frames = workspace->frames;
  parser.frame_capacity = workspace->frame_capacity;
  parser.extension_oids = workspace->oids;
  parser.extension_capacity = workspace->oid_capacity;
  names.frames = workspace->frames;
  names.frame_capacity = workspace->frame_capacity;
  names.names = &workspace->names;
  memset(&input, 0, sizeof input);
  input.count = count;
  input.max_certificates = options->max_certificates;
  input.max_input = options->max_input;
  input.anchor = &anchor->trust;
  input.at = &options->at;
  input.signatures = &options->signatures;
  input.anchor_path_len = anchor->path_len;
  input.has_anchor_path_len = anchor->has_path_len;
  input.limits = &options->parsing;
  input.encoded = chain;
  input.parser = &parser;
  input.cache = workspace->certificates;
  /* Each validation fills the summary cache afresh, so clear stale entries. */
  if (workspace->summaries && workspace->summary_capacity >= count) {
    for (i = 0; i < count; ++i)
      workspace->summaries[i].ready = 0;
    input.summaries = workspace->summaries;
  }
  result = tc_x509_path_basic(&input, &workspace->names, work, &accepted);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  if (!accepted)
    return TC_X509_PATH_INVALID;
  input.certificates = workspace->certificates;
  result = tc_x509_path_names(&input, &names, work, &accepted);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  if (!accepted)
    return TC_X509_PATH_INVALID;
  /* Apply application and stored-anchor constraints independently. */
  for (set = 0; set < 2; ++set) {
    const TC_X509_name_constraints* constraints = set ? &anchor->names : &options->anchor_names;
    if (!constraints || (!constraints->permitted.length && !constraints->excluded.length))
      continue;
    result = tc_x509_path_constraint_distances(constraints, input.limits, &names, work);
    if (result != TC_TLV_OK)
      return tc_x509_path_status(result);
    for (i = 0; i < count; ++i) {
      result = tc_x509_path_certificate(&input, i, work, &target);
      if (result != TC_TLV_OK)
        return tc_x509_path_status(result);
      result = path_constraint_target(target, i + 1 == count, 0, constraints, input.limits, &names,
                                      work, &accepted);
      if (result != TC_TLV_OK)
        return tc_x509_path_status(result);
      if (!accepted)
        return TC_X509_PATH_INVALID;
    }
  }
  memset(&graph, 0, sizeof graph);
  graph.nodes = workspace->nodes;
  graph.node_capacity = workspace->node_capacity;
  graph.edges = workspace->edges;
  graph.edge_capacity = workspace->edge_capacity;
  graph.expected = workspace->expected;
  graph.expected_capacity = workspace->expected_capacity;
  policy_options.initial = options->initial_policies;
  policy_options.initial_count = options->initial_policy_count;
  policy_options.require_explicit =
      ((options->flags | anchor->policy_flags) & TC_X509_PATH_REQUIRE_EXPLICIT_POLICY) != 0;
  policy_options.inhibit_mapping =
      ((options->flags | anchor->policy_flags) & TC_X509_PATH_INHIBIT_MAPPING) != 0;
  policy_options.inhibit_any =
      ((options->flags | anchor->policy_flags) & TC_X509_PATH_INHIBIT_ANY_POLICY) != 0;
  policy_workspace.graph = &graph;
  policy_workspace.policies = workspace->oids;
  policy_workspace.policy_capacity = workspace->oid_capacity;
  policy_workspace.mappings = workspace->mappings;
  policy_workspace.mapping_capacity = workspace->mapping_capacity;
  policy_workspace.output = workspace->policies;
  policy_workspace.output_capacity = workspace->policy_capacity;
  policy_workspace.names = &workspace->names;
  policy_workspace.frames = workspace->frames;
  policy_workspace.frame_capacity = workspace->frame_capacity;
  result = tc_x509_path_policies(&input, &policy_options, anchor->policy_set, &policy_workspace,
                                 work, &policy_count, &accepted);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  if (!accepted)
    return TC_X509_PATH_INVALID;
  usage.purpose = options->purpose;
  usage.key_usage = options->key_usage;
  usage.require_key_usage = (options->flags & TC_X509_PATH_REQUIRE_KEY_USAGE) != 0;
  usage.require_extended_key_usage =
      (options->flags & TC_X509_PATH_REQUIRE_EXTENDED_KEY_USAGE) != 0;
  usage.inhibit_any_purpose = (options->flags & TC_X509_PATH_INHIBIT_ANY_PURPOSE) != 0;
  extension_workspace.oids = workspace->oids;
  extension_workspace.oid_capacity = workspace->oid_capacity;
  extension_workspace.names = names;
  result = tc_x509_path_extensions(&input, &usage, &extension_workspace, work, &accepted);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  if (!accepted)
    return TC_X509_PATH_INVALID;
  result = tc_x509_path_certificate(&input, count - 1, work, &target);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  validated.public_key = target->public_key;
  validated.policies = workspace->policies;
  validated.policy_count = policy_count;
  validated.work_used = initial_work - *work;
  *out = validated;
  return TC_X509_PATH_VALID;
}

TC_X509_path_status tc_x509_path_validate_budget(const TC_bytes* chain, size_t count,
                                                 const TC_X509_trust_anchor* anchor,
                                                 const TC_X509_path_options* options,
                                                 const TC_X509_path_workspace* workspace,
                                                 size_t* work, TC_X509_path_result* out)
{
  TC_X509_store_anchor stored = {0};
  if (!anchor)
    return TC_X509_PATH_ERROR;
  stored.trust = *anchor;
  return tc_x509_path_validate_anchor(chain, count, &stored, options, workspace, work, out);
}

TC_X509_path_status TC_X509_path_validate_with_anchor(const TC_bytes* chain, size_t count,
                                                      const TC_X509_store_anchor* anchor,
                                                      const TC_X509_path_options* options,
                                                      const TC_X509_path_workspace* workspace,
                                                      TC_X509_path_result* out)
{
  size_t work;
  if (!options)
    return TC_X509_PATH_ERROR;
  work = options->max_work;
  return tc_x509_path_validate_anchor(chain, count, anchor, options, workspace, &work, out);
}

TC_X509_path_status TC_X509_path_validate(const TC_bytes* chain, size_t count,
                                          const TC_X509_trust_anchor* anchor,
                                          const TC_X509_path_options* options,
                                          const TC_X509_path_workspace* workspace,
                                          TC_X509_path_result* out)
{
  size_t work;
  if (!options)
    return TC_X509_PATH_ERROR;
  work = options->max_work;
  return tc_x509_path_validate_budget(chain, count, anchor, options, workspace, &work, out);
}
#endif
