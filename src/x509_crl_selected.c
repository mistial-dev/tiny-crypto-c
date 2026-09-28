/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Authenticating a selected CRL: signer path, signature, cRLSign usage, and
 * applying the CRL to a certificate (RFC 5280 section 6.3.3). */
#include <tiny_crypto/common.h>
#if TC_ENABLE_X509_REVOCATION
#include "x509_crl_internal.h"
#include "x509_time_internal.h"
#include "pki_extensions_internal.h"
#include "pki_names_internal.h"
#include "pki_bits_internal.h"
#include "pki_distribution_internal.h"
#include "pki_status_internal.h"
#include "pki_source_internal.h"
#include "pki_reader_internal.h"
#include "x509_crl_source_internal.h"
#include "pki_signature_internal.h"
#include "hash_dispatch_internal.h"

static TC_TLV_result
crl_selected_authenticate(const tc_x509_crl_selected* selected, const TC_X509_certificate* signer,
                          const TC_X509_signature_provider* provider, const TC_TLV_limits* limits,
                          const tc_pki_tree_workspace* tree, const TC_X509_name_workspace* names);
static TC_TLV_result crl_selected_lookup(const tc_x509_crl_selected* selected,
                                         const TC_X509_certificate* certificate,
                                         const TC_TLV_limits* limits,
                                         const tc_pki_tree_workspace* tree,
                                         const TC_X509_name_workspace* names, TC_bytes* oids,
                                         size_t capacity, tc_x509_crl_match* out);

static TC_X509_path_status crl_signer_path(const TC_X509_certificate* signer,
                                           const TC_X509_store_source* restricted,
                                           size_t anchor_index, const TC_X509_path_options* options,
                                           const TC_X509_path_workspace* validation,
                                           const TC_X509_search_workspace* search, size_t* work,
                                           TC_X509_search_result* out)
{
  TC_X509_path_options signer_options = *options;
  TC_X509_search_result found;
  signer_options.key_usage |= TC_KEY_USAGE_CRL_SIGN;
  TC_X509_path_status status = tc_x509_path_build_work(signer->encoded, restricted, &signer_options,
                                                       validation, search, work, &found);
  if (status != TC_X509_PATH_VALID)
    return status;
  found.anchor_index = anchor_index;
  *out = found;
  return TC_X509_PATH_VALID;
}

static TC_TLV_result
crl_selected_path(const tc_x509_crl_selected* selected, const TC_X509_certificate* signer,
                  const TC_X509_store_source* restricted, size_t anchor_index,
                  const TC_X509_path_options* options, const TC_X509_path_workspace* validation,
                  const TC_X509_search_workspace* search, size_t* work, TC_X509_search_result* out)
{
  const tc_pki_tree_workspace tree = {validation->frames, validation->frame_capacity, work};
  TC_TLV_result result = crl_selected_authenticate(selected, signer, &options->signatures,
                                                   &options->parsing, &tree, &validation->names);
  if (result != TC_TLV_OK)
    return result;
  return tc_x509_path_result_status(
      crl_signer_path(signer, restricted, anchor_index, options, validation, search, work, out));
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
  result = crl_selected_path(selected, signer, &restricted, anchor_index, options, validation,
                             search, work, &found);
  if (result != TC_TLV_OK)
    return result;
  found.validation.work_used = initial_work - *work;
  *out = found;
  return TC_TLV_OK;
}

TC_X509_path_status tc_x509_crl_signer_validate(
    const tc_x509_crl* crl, const TC_X509_certificate* signer, const TC_X509_store_source* source,
    size_t anchor_index, const TC_X509_path_options* options,
    const TC_X509_path_workspace* validation, const TC_X509_search_workspace* search, size_t* work,
    TC_X509_search_result* out)
{
  tc_pki_anchor_source selected;
  TC_X509_store_source restricted;
  TC_X509_search_result found;
  TC_X509_path_status status;
  TC_X509_signature_result signature;
  TC_TLV_result result;
  size_t initial_work;
  if (!crl || !signer || !options || !validation || !search || !work || !out)
    return TC_X509_PATH_ERROR;
  result = tc_pki_source_select_anchor(source, anchor_index, &selected, &restricted);
  if (result != TC_TLV_OK)
    return tc_x509_path_status(result);
  initial_work = *work;
  signature = tc_x509_crl_signer_check(crl, signer, &options->signatures, &options->parsing,
                                       &validation->names, work);
  if (signature != TC_X509_SIGNATURE_VALID)
    return tc_x509_path_status(tc_pki_signature_status(signature));
  status =
      crl_signer_path(signer, &restricted, anchor_index, options, validation, search, work, &found);
  if (status != TC_X509_PATH_VALID)
    return status;
  found.validation.work_used = initial_work - *work;
  *out = found;
  return TC_X509_PATH_VALID;
}

static TC_X509_signature_result crl_digest_signature(const tc_x509_crl* crl, TC_hash_algorithm hash,
                                                     TC_bytes digest, const TC_X509_public_key* key,
                                                     const TC_X509_signature_provider* provider,
                                                     size_t* work)
{
  TC_signature_algorithm algorithm;
  TC_TLV_result result = tc_pki_signature_resolve(&crl->signature_algorithm, key, &algorithm);
  if (result != TC_TLV_OK)
    return tc_pki_signature_error(result);
  if (hash != algorithm.hash)
    return TC_X509_SIGNATURE_INVALID;
  return TC_X509_signature_verify_digest(digest, &algorithm, crl->signature, key, provider, work);
}

static TC_X509_signature_result crl_key_signature(const tc_x509_crl* crl,
                                                  const TC_X509_public_key* key,
                                                  const TC_X509_signature_provider* provider,
                                                  size_t* work)
{
  if (crl->prepared) {
    if (crl->encoded.length || crl->tbs.length || crl->revoked.length)
      return TC_X509_SIGNATURE_ERROR;
    return crl_digest_signature(crl, crl->prepared->hash, crl->prepared->digest, key, provider,
                                work);
  }
  return TC_X509_signature_verify_message(&crl->tbs, 1, &crl->signature_algorithm, crl->signature,
                                          key, provider, work);
}

TC_X509_signature_result tc_x509_crl_anchor_check(const tc_x509_crl* crl,
                                                  const TC_X509_trust_anchor* anchor,
                                                  const TC_X509_signature_provider* provider,
                                                  const TC_TLV_limits* limits,
                                                  const TC_X509_name_workspace* names, size_t* work)
{
  int matched;
  if (!crl || !anchor || !limits || !names || !work)
    return TC_X509_SIGNATURE_ERROR;
  if (!provider || (crl->prepared ? !provider->verify_digest : !provider->verify))
    return TC_X509_SIGNATURE_UNSUPPORTED;
  TC_TLV_result result =
      TC_X509_name_equal(crl->issuer, anchor->name, limits, names, work, &matched);
  if (result != TC_TLV_OK)
    return tc_pki_signature_error(result);
  if (!matched)
    return TC_X509_SIGNATURE_INVALID;
  return crl_key_signature(crl, &anchor->public_key, provider, work);
}

static TC_TLV_result crl_signer_key(const tc_x509_crl* crl, const TC_X509_certificate* signer,
                                    const TC_TLV_limits* limits,
                                    const TC_X509_name_workspace* names, size_t* work,
                                    TC_X509_public_key* key)
{
  TC_TLV_result result;
  int accepted;
  if (!crl || !signer || !limits || !names || !work || !key)
    return TC_TLV_ARGUMENT;
  result = TC_X509_name_equal(crl->issuer, signer->subject, limits, names, work, &accepted);
  if (result != TC_TLV_OK)
    return result;
  if (!accepted)
    return TC_TLV_INVALID;
  result = tc_x509_crl_signer_usage(signer, limits, work, &accepted);
  if (result != TC_TLV_OK)
    return result;
  if (!accepted)
    return TC_TLV_INVALID;
  if (tc_pki_work_charge(work, signer->spki.length) != TC_TLV_OK)
    return TC_TLV_LIMIT;
  return TC_X509_subject_public_key(signer->spki.data, signer->spki.length, key);
}

TC_X509_signature_result tc_x509_crl_signer_check(const tc_x509_crl* crl,
                                                  const TC_X509_certificate* signer,
                                                  const TC_X509_signature_provider* provider,
                                                  const TC_TLV_limits* limits,
                                                  const TC_X509_name_workspace* names, size_t* work)
{
  if (!crl || !signer || !limits || !names || !work)
    return TC_X509_SIGNATURE_ERROR;
  if (!provider || (crl->prepared ? !provider->verify_digest : !provider->verify))
    return TC_X509_SIGNATURE_UNSUPPORTED;
  TC_X509_public_key key;
  TC_TLV_result result = crl_signer_key(crl, signer, limits, names, work, &key);
  if (result != TC_TLV_OK)
    return tc_pki_signature_error(result);
  return crl_key_signature(crl, &key, provider, work);
}

TC_X509_signature_result tc_x509_crl_signer_digest_check(
    const tc_x509_crl* crl, TC_hash_algorithm hash, TC_bytes digest,
    const TC_X509_certificate* signer, const TC_X509_signature_provider* provider,
    const TC_TLV_limits* limits, const TC_X509_name_workspace* names, size_t* work)
{
  if (!crl || !signer || !limits || !names || !work)
    return TC_X509_SIGNATURE_ERROR;
  if (!provider || !provider->verify_digest)
    return TC_X509_SIGNATURE_UNSUPPORTED;
  TC_X509_public_key key;
  TC_TLV_result result = crl_signer_key(crl, signer, limits, names, work, &key);
  if (result != TC_TLV_OK)
    return tc_pki_signature_error(result);
  return crl_digest_signature(crl, hash, digest, &key, provider, work);
}

TC_TLV_result tc_x509_crl_signer_usage(const TC_X509_certificate* signer,
                                       const TC_TLV_limits* limits, size_t* work, int* authorized)
{
  TC_X509_extension_summary extensions;
  TC_TLV_result result;
  if (!signer || !limits || !work || !authorized)
    return TC_TLV_ARGUMENT;
  result = tc_x509_extensions_summarize(signer, limits, work, &extensions);
  if (result != TC_TLV_OK)
    return result;
  const int present = tc_x509_summary_has(&extensions, TC_X509_SUMMARY_KEY_USAGE);
  /* RFC 10007 requires explicit cRLSign for a version 3 CRL signer. */
  *authorized = (signer->version < 3 && !present) ||
                (present && !!(extensions.key_usage & TC_KEY_USAGE_CRL_SIGN));
  return TC_TLV_OK;
}

static TC_TLV_result
crl_selected_coverage(const tc_x509_crl_selected* selected, const tc_x509_crl_query* query,
                      const TC_X509_time* at, const TC_TLV_limits* limits,
                      const tc_pki_tree_workspace* tree, const TC_X509_name_workspace* names,
                      const tc_x509_crl_evidence* evidence, tc_x509_crl_coverage* coverage)
{
  /* The delta supplies the effective update interval. */
  TC_TLV_result result = tc_x509_crl_coverage_at(
      selected->delta ? selected->delta : selected->base,
      selected->delta ? selected->delta_info : selected->base_info, at, query->point,
      query->certificate->issuer, query->certificate_ca, limits, tree, names, coverage);
  if (result != TC_TLV_OK)
    return result;
  return coverage->reasons & ~evidence->reasons ? TC_TLV_OK : TC_TLV_END;
}

static TC_TLV_result crl_selected_evidence(const tc_x509_crl_selected* selected,
                                           const TC_X509_certificate* certificate, uint16_t reasons,
                                           const TC_TLV_limits* limits,
                                           const tc_pki_tree_workspace* tree,
                                           const TC_X509_name_workspace* names, TC_bytes* oids,
                                           size_t oid_capacity, tc_x509_crl_evidence* evidence)
{
  tc_x509_crl_match match;
  TC_TLV_result result =
      crl_selected_lookup(selected, certificate, limits, tree, names, oids, oid_capacity, &match);
  if (result != TC_TLV_OK)
    return result;
  return tc_x509_crl_evidence_add(evidence, reasons, &match);
}

TC_TLV_result tc_x509_crl_apply(const tc_x509_crl_selected* selected,
                                const tc_x509_crl_query* query, const TC_X509_time* at,
                                const TC_TLV_limits* limits, const tc_pki_tree_workspace* tree,
                                const TC_X509_name_workspace* names, TC_bytes* oids,
                                size_t oid_capacity, tc_x509_crl_evidence* evidence)
{
  tc_x509_crl_status status;
  tc_x509_crl_coverage coverage;
  if (!selected || !selected->base || !selected->base_info || !query || !query->certificate ||
      !query->point || !at || !limits || !tree || !tree->work || !names ||
      (query->certificate_ca != 0 && query->certificate_ca != 1) ||
      !!selected->delta != !!selected->delta_info)
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = tc_x509_crl_evidence_status(evidence, &status);
  if (result != TC_TLV_OK)
    return result;
  if (status != TC_X509_CRL_UNDETERMINED)
    return TC_TLV_END;
  result = crl_selected_coverage(selected, query, at, limits, tree, names, evidence, &coverage);
  if (result != TC_TLV_OK)
    return result;
  return crl_selected_evidence(selected, query->certificate, coverage.reasons, limits, tree, names,
                               oids, oid_capacity, evidence);
}

TC_TLV_result tc_x509_crl_process(const tc_x509_crl_selected* selected,
                                  const TC_X509_certificate* signer, const tc_x509_crl_query* query,
                                  const TC_X509_store_source* source, size_t anchor_index,
                                  const TC_X509_path_options* options,
                                  const TC_X509_path_workspace* validation,
                                  const TC_X509_search_workspace* search, size_t* work,
                                  tc_x509_crl_evidence* evidence, TC_X509_search_result* out)
{
  tc_pki_anchor_source anchor;
  TC_X509_store_source restricted;
  TC_X509_search_result found;
  tc_x509_crl_coverage coverage;
  tc_x509_crl_status status;
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
  result = crl_selected_coverage(selected, query, &options->at, &options->parsing, &tree,
                                 &validation->names, evidence, &coverage);
  if (result != TC_TLV_OK)
    return result;
  result = crl_selected_path(selected, signer, &restricted, anchor_index, options, validation,
                             search, work, &found);
  if (result != TC_TLV_OK)
    return result;
  /* Entry scans can be large; defer them until a signer path succeeds. */
  result = crl_selected_evidence(selected, query->certificate, coverage.reasons, &options->parsing,
                                 &tree, &validation->names, validation->oids,
                                 validation->oid_capacity, evidence);
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
                          TC_bytes* oids, size_t capacity, tc_x509_crl_match* out)
{
  TC_TLV_result result;
  if (!selected || !selected->base || !selected->base_info || !signer || !certificate || !limits ||
      !tree || !tree->work || !names || !out || !!selected->delta != !!selected->delta_info)
    return TC_TLV_ARGUMENT;
  result = crl_selected_authenticate(selected, signer, provider, limits, tree, names);
  if (result != TC_TLV_OK)
    return result;
  return crl_selected_lookup(selected, certificate, limits, tree, names, oids, capacity, out);
}

static TC_TLV_result
crl_selected_authenticate(const tc_x509_crl_selected* selected, const TC_X509_certificate* signer,
                          const TC_X509_signature_provider* provider, const TC_TLV_limits* limits,
                          const tc_pki_tree_workspace* tree, const TC_X509_name_workspace* names)
{
  TC_TLV_result result;
  if (selected->base_info->present & TC_CRL_EXT_DELTA)
    return TC_TLV_INVALID;
  if (selected->delta) {
    int compatible;
    result = tc_x509_crl_delta_compatible(selected->base, selected->base_info, selected->delta,
                                          selected->delta_info, limits, tree, names, &compatible);
    if (result != TC_TLV_OK)
      return result;
    if (!compatible)
      return TC_TLV_INVALID;
  } else {
    result = tc_x509_crl_extension_policy(selected->base_info);
    if (result != TC_TLV_OK)
      return result;
  }
  /* Matching AKIDs alone do not prove that both signatures use the same key. */
  const tc_x509_crl* crls[] = {selected->base, selected->delta};
  for (size_t i = 0; i < sizeof crls / sizeof crls[0]; ++i) {
    if (!crls[i])
      continue;
    result = tc_pki_signature_status(
        tc_x509_crl_signer_check(crls[i], signer, provider, limits, names, tree->work));
    if (result != TC_TLV_OK)
      return result;
  }
  return TC_TLV_OK;
}

static TC_TLV_result crl_selected_lookup(const tc_x509_crl_selected* selected,
                                         const TC_X509_certificate* certificate,
                                         const TC_TLV_limits* limits,
                                         const tc_pki_tree_workspace* tree,
                                         const TC_X509_name_workspace* names, TC_bytes* oids,
                                         size_t capacity, tc_x509_crl_match* out)
{
  tc_x509_crl_match base, delta;
  TC_TLV_result result = tc_x509_crl_find(selected->base, selected->base_info, certificate, limits,
                                          tree, names, oids, capacity, &base);
  if (result != TC_TLV_OK)
    return result;
  if (selected->delta) {
    result = tc_x509_crl_find(selected->delta, selected->delta_info, certificate, limits, tree,
                              names, oids, capacity, &delta);
    if (result != TC_TLV_OK)
      return result;
  }
  return tc_x509_crl_combine(&base, selected->delta ? &delta : NULL, out);
}
#endif
