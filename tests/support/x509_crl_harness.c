/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Test harness: thin accessors over X.509 CRL internals that the library does
 * not call itself. Each forwards to one library function, so tests can reach
 * entry matching, signer checks and extension schemas without shipping the
 * wrappers. CRL processing tests use the production scope executor. */
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
                                       const tc_x509_crl_trust* trust, TC_X509_search_report* out)
{
  return tc_x509_path_result_status(tc_x509_crl_signer_validate(context, candidate, trust, out));
}

TC_TLV_result tc_x509_crl_store_search(const void* candidates,
                                       const tc_x509_crl_signer_query* query,
                                       const tc_x509_crl_trust* trust, TC_X509_search_report* out,
                                       int* source_failed)
{
  if (!candidates)
    return TC_TLV_ARGUMENT;
  const tc_pki_store_candidates* cursor = candidates;
  return tc_x509_crl_store_source_search(cursor, cursor->source, query, trust, out, source_failed);
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

#endif
