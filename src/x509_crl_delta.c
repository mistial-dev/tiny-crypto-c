/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * CRL selection within one scope: signature cache, delta pairing, the
 * effective and latest CRL, and scope evaluation (RFC 5280 section 6.3). */
#include <tiny_crypto/x509.h>
#if TC_ENABLE_X509_REVOCATION
#include "x509_revocation_internal.h"
#include "pki_storage_internal.h"
#include "pki_spans_internal.h"
#include "pki_status_internal.h"
#include "pki_identifier_internal.h"
#include "pki_extensions_internal.h"

TC_TLV_result tc_x509_crl_delta_next(const TC_X509_crl_index* index, size_t base, size_t* cursor,
                                     const TC_TLV_limits* limits, const tc_pki_tree_workspace* tree,
                                     const TC_X509_name_workspace* names, tc_x509_crl_selected* out)
{
  if (!index || !index->records || base >= index->count || !cursor || *cursor > index->count ||
      !limits || !tree || !tree->work || !names || !out)
    return TC_TLV_ARGUMENT;
  const TC_X509_crl_record* complete = &index->records[base];
  if (complete->policy != TC_TLV_OK)
    return complete->policy;
  if (complete->extensions.present & TC_CRL_EXT_DELTA)
    return TC_TLV_ARGUMENT;
  for (size_t i = *cursor; i < index->count; ++i) {
    TC_TLV_result result = tc_pki_work_charge(tree->work, 1);
    if (result != TC_TLV_OK)
      return result;
    const TC_X509_crl_record* delta = &index->records[i];
    if (i == base || delta->policy != TC_TLV_OK || !(delta->extensions.present & TC_CRL_EXT_DELTA))
      continue;
    int compatible;
    result = tc_x509_crl_delta_compatible(&complete->crl, &complete->extensions, &delta->crl,
                                          &delta->extensions, limits, tree, names, &compatible);
    if (result != TC_TLV_OK)
      return result;
    if (!compatible)
      continue;
    *out = (tc_x509_crl_selected){&complete->crl, &complete->extensions, &delta->crl,
                                  &delta->extensions};
    *cursor = i + 1;
    return TC_TLV_OK;
  }
  return TC_TLV_END;
}

TC_TLV_result tc_x509_crl_signature_cache_init(const TC_X509_crl_index* index,
                                               const TC_X509_certificate* signer,
                                               const TC_X509_signature_provider* provider,
                                               const TC_TLV_limits* limits,
                                               const TC_X509_name_workspace* names, uint8_t* states,
                                               size_t capacity, size_t* work,
                                               tc_x509_crl_signature_cache* out)
{
  TC_bytes storage;
  if (!index || (index->count && !index->records) || !signer || !limits || !names || !work ||
      !out || tc_pki_storage_span(states, capacity, sizeof *states, &storage) != TC_TLV_OK)
    return TC_TLV_ARGUMENT;
  if (capacity < index->count)
    return TC_TLV_LIMIT;
  TC_TLV_result result = tc_pki_work_charge(work, index->count);
  if (result != TC_TLV_OK)
    return result;
  if (index->count)
    memset(states, CRL_SIGNATURE_UNCHECKED, index->count);
  *out =
      (tc_x509_crl_signature_cache){index, signer, provider, limits, names, states, capacity, NULL};
  return TC_TLV_OK;
}

static int x509_crl_signature_cache_valid(const tc_x509_crl_signature_cache* cache)
{
  return cache && cache->index && cache->signer && cache->limits && cache->names &&
         (!cache->index->count || (cache->index->records && cache->states)) &&
         cache->capacity >= cache->index->count;
}

TC_TLV_result tc_x509_crl_signature_cached(const tc_x509_crl_signature_cache* cache, size_t record,
                                           size_t* work)
{
  if (!x509_crl_signature_cache_valid(cache) || !work || record >= cache->index->count)
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = tc_pki_work_charge(work, 1);
  if (result != TC_TLV_OK)
    return result;
  if (cache->states[record] == CRL_SIGNATURE_VALID)
    return TC_TLV_OK;
  if (cache->states[record] == CRL_SIGNATURE_INVALID)
    return TC_TLV_INVALID;
  if (cache->states[record] != CRL_SIGNATURE_UNCHECKED)
    return TC_TLV_ARGUMENT;
  result = tc_pki_signature_status(tc_x509_crl_signer_check(&cache->index->records[record].crl,
                                                            cache->signer, cache->provider,
                                                            cache->limits, cache->names, work));
  if (result == TC_TLV_OK)
    cache->states[record] = CRL_SIGNATURE_VALID;
  else if (result == TC_TLV_INVALID)
    cache->states[record] = CRL_SIGNATURE_INVALID;
  return result;
}

static TC_TLV_result x509_crl_delta_select(
    const TC_X509_crl_index* index, size_t base, const TC_X509_certificate* signer,
    const TC_X509_time* at, const TC_X509_signature_provider* provider, const TC_TLV_limits* limits,
    const tc_pki_tree_workspace* tree, const TC_X509_name_workspace* names,
    const tc_x509_crl_signature_cache* cache, int* conflict, tc_x509_crl_selected* out)
{
  tc_x509_crl_selected candidate, chosen = {0};
  TC_TLV_result result;
  size_t cursor = 0;
  int conflicting = 0;
  if (!signer || !at || !out)
    return TC_TLV_ARGUMENT;
  while ((result = tc_x509_crl_delta_next(index, base, &cursor, limits, tree, names, &candidate)) ==
         TC_TLV_OK) {
    tc_x509_crl_freshness freshness;
    result = tc_x509_crl_fresh_at(candidate.delta, at, &freshness);
    if (result != TC_TLV_OK)
      return result;
    if (freshness != TC_X509_CRL_CURRENT)
      continue;
    result = cache ? tc_x509_crl_signature_cached(cache, cursor - 1, tree->work)
                   : tc_pki_signature_status(tc_x509_crl_signer_check(
                         candidate.delta, signer, provider, limits, names, tree->work));
    if (result == TC_TLV_INVALID)
      continue;
    if (result != TC_TLV_OK)
      return result;
    if (chosen.delta) {
      int order;
      result = tc_x509_crl_number_compare(candidate.delta_info->number, chosen.delta_info->number,
                                          tree->work, &order);
      if (result != TC_TLV_OK)
        return result;
      if (order < 0)
        continue;
      if (!order) {
        int equal;
        result = tc_x509_crl_content_equal(candidate.delta, chosen.delta, tree->work, &equal);
        if (result != TC_TLV_OK)
          return result;
        /* A higher authenticated number may supersede this conflict. */
        if (!equal) {
          conflicting = 1;
          result = tc_pki_work_charge(tree->work, 1);
          if (result != TC_TLV_OK)
            return result;
          result = TC_X509_time_compare(&candidate.delta->this_update, &chosen.delta->this_update,
                                        &order);
          if (result != TC_TLV_OK)
            return result;
          if (order > 0)
            chosen = candidate;
        }
        continue;
      }
    }
    chosen = candidate;
    conflicting = 0;
  }
  if (result != TC_TLV_END)
    return result;
  if (!chosen.delta)
    return TC_TLV_END;
  /* Scope selection can defer rejection until it knows the highest number. */
  if (conflicting && !conflict)
    return TC_TLV_INVALID;
  if (conflict)
    *conflict = conflicting;
  *out = chosen;
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_crl_delta_select(const TC_X509_crl_index* index, size_t base,
                                       const TC_X509_certificate* signer, const TC_X509_time* at,
                                       const TC_X509_signature_provider* provider,
                                       const TC_TLV_limits* limits,
                                       const tc_pki_tree_workspace* tree,
                                       const TC_X509_name_workspace* names,
                                       tc_x509_crl_selected* out)
{
  return x509_crl_delta_select(index, base, signer, at, provider, limits, tree, names, NULL, NULL,
                               out);
}

TC_TLV_result tc_x509_crl_delta_select_cached(const tc_x509_crl_signature_cache* cache, size_t base,
                                              const TC_X509_time* at,
                                              const tc_pki_tree_workspace* tree,
                                              tc_x509_crl_selected* out)
{
  if (!x509_crl_signature_cache_valid(cache))
    return TC_TLV_ARGUMENT;
  return x509_crl_delta_select(cache->index, base, cache->signer, at, cache->provider,
                               cache->limits, tree, cache->names, cache, NULL, out);
}

static TC_TLV_result
x509_crl_effective_next(const tc_x509_crl_signature_cache* cache, size_t reference, size_t* cursor,
                        TC_X509_crl_delta_policy delta_policy, const TC_X509_time* at,
                        const tc_pki_tree_workspace* tree, int* conflict, tc_x509_crl_selected* out)
{
  if (!x509_crl_signature_cache_valid(cache) || reference >= cache->index->count || !cursor ||
      *cursor > cache->index->count || !at || !tree || !tree->work || !out ||
      !x509_crl_delta_policy_valid(delta_policy))
    return TC_TLV_ARGUMENT;
  const TC_X509_crl_record* scope = &cache->index->records[reference];
  for (size_t i = *cursor; i < cache->index->count; ++i) {
    TC_TLV_result result = tc_pki_work_charge(tree->work, 1);
    if (result != TC_TLV_OK)
      return result;
    const TC_X509_crl_record* base = &cache->index->records[i];
    if (base->policy != TC_TLV_OK || (base->extensions.present & TC_CRL_EXT_DELTA))
      continue;
    int same_scope;
    if (cache->scopes)
      same_scope = cache->scopes[i].representative == cache->scopes[reference].representative;
    else {
      result =
          tc_x509_crl_scope_equal(&scope->crl, &scope->extensions, &base->crl, &base->extensions,
                                  cache->limits, tree, cache->names, &same_scope);
      if (result != TC_TLV_OK)
        return result;
    }
    if (!same_scope)
      continue;
    tc_x509_crl_freshness freshness;
    result = tc_x509_crl_fresh_at(&base->crl, at, &freshness);
    if (result != TC_TLV_OK)
      return result;
    if (freshness == TC_X509_CRL_FUTURE ||
        (delta_policy == TC_X509_CRL_COMPLETE_ONLY && freshness != TC_X509_CRL_CURRENT))
      continue;
    result = tc_x509_crl_signature_cached(cache, i, tree->work);
    if (result == TC_TLV_INVALID)
      continue;
    if (result != TC_TLV_OK)
      return result;
    tc_x509_crl_selected selected = {&base->crl, &base->extensions, NULL, NULL};
    int conflicting = 0;
    if (delta_policy != TC_X509_CRL_COMPLETE_ONLY) {
      result = x509_crl_delta_select(cache->index, i, cache->signer, at, cache->provider,
                                     cache->limits, tree, cache->names, cache,
                                     conflict ? &conflicting : NULL, &selected);
      if (result == TC_TLV_END) {
        if (delta_policy == TC_X509_CRL_DELTA_REQUIRED || freshness != TC_X509_CRL_CURRENT)
          continue;
      } else if (result != TC_TLV_OK)
        return result;
    }
    if (conflict)
      *conflict = conflicting;
    *out = selected;
    *cursor = i + 1;
    return TC_TLV_OK;
  }
  return TC_TLV_END;
}

TC_TLV_result tc_x509_crl_effective_next(const tc_x509_crl_signature_cache* cache, size_t reference,
                                         size_t* cursor, TC_X509_crl_delta_policy delta_policy,
                                         const TC_X509_time* at, const tc_pki_tree_workspace* tree,
                                         tc_x509_crl_selected* out)
{
  return x509_crl_effective_next(cache, reference, cursor, delta_policy, at, tree, NULL, out);
}

static TC_TLV_result x509_crl_latest(const tc_x509_crl_signature_cache* cache, size_t reference,
                                     TC_X509_crl_delta_policy delta_policy,
                                     TC_X509_crl_order_policy order_policy, const TC_X509_time* at,
                                     const tc_pki_tree_workspace* tree, tc_x509_crl_selected* out,
                                     int* conflict_out)
{
  tc_x509_crl_selected selected, latest = {0};
  TC_TLV_result result;
  size_t cursor = 0;
  int conflict, latest_conflict = 0;
  if (!out || !x509_crl_order_policy_valid(order_policy))
    return TC_TLV_ARGUMENT;
  while ((result = x509_crl_effective_next(cache, reference, &cursor, delta_policy, at, tree,
                                           &conflict, &selected)) == TC_TLV_OK) {
    int order;
    result = x509_crl_order(&selected, latest.base ? &latest : &selected, order_policy, tree->work,
                            &order);
    if (result != TC_TLV_OK)
      return result;
    if (latest.base) {
      if (order < 0)
        continue;
      if (!order) {
        latest_conflict |= conflict;
        continue;
      }
    }
    latest = selected;
    latest_conflict = conflict;
  }
  if (result != TC_TLV_END)
    return result;
  if (!latest.base)
    return TC_TLV_END;
  if (latest_conflict && !conflict_out)
    return TC_TLV_INVALID;
  if (conflict_out)
    *conflict_out = latest_conflict;
  *out = latest;
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_crl_latest_number(const tc_x509_crl_signature_cache* cache, size_t reference,
                                        TC_X509_crl_delta_policy delta_policy,
                                        const TC_X509_time* at, const tc_pki_tree_workspace* tree,
                                        TC_bytes* out)
{
  tc_x509_crl_selected latest;
  if (!out)
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = x509_crl_latest(cache, reference, delta_policy, TC_X509_CRL_ORDER_NUMBER,
                                         at, tree, &latest, NULL);
  if (result == TC_TLV_OK)
    *out = latest.delta ? latest.delta_info->number : latest.base_info->number;
  return result;
}

TC_TLV_result tc_x509_crl_scope_evaluate(const tc_x509_crl_signature_cache* cache, size_t reference,
                                         TC_X509_crl_delta_policy delta_policy,
                                         TC_X509_crl_order_policy order_policy,
                                         const tc_x509_crl_query* query, const TC_X509_time* at,
                                         const tc_pki_tree_workspace* tree, TC_bytes* oids,
                                         size_t oid_capacity, tc_x509_crl_evidence* evidence,
                                         tc_x509_crl_selected* preference)
{
  tc_x509_crl_status status;
  tc_x509_crl_selected selected;
  tc_x509_crl_evidence chosen = {0};
  const TC_X509_time* update = NULL;
  tc_x509_crl_selected latest;
  size_t cursor = 0;
  int conflict = 0;
  if (!x509_crl_signature_cache_valid(cache) || reference >= cache->index->count ||
      !x509_crl_delta_policy_valid(delta_policy) || !x509_crl_order_policy_valid(order_policy) ||
      !query || !query->certificate || !query->point ||
      (query->certificate_ca != 0 && query->certificate_ca != 1) || !at || !tree || !tree->work)
    return TC_TLV_ARGUMENT;
  TC_TLV_result result = tc_x509_crl_evidence_status(evidence, &status);
  if (result != TC_TLV_OK)
    return result;
  if (status != TC_X509_CRL_UNDETERMINED)
    return TC_TLV_END;
  result = x509_crl_latest(cache, reference, delta_policy, order_policy, at, tree, &latest,
                           preference ? &conflict : NULL);
  if (result != TC_TLV_OK)
    return result;
  /* A proposal retains its rank even when entries or tied records conflict. */
  if (preference)
    *preference = latest;
  if (conflict)
    return TC_TLV_INVALID;
  while ((result = x509_crl_effective_next(cache, reference, &cursor, delta_policy, at, tree,
                                           &conflict, &selected)) == TC_TLV_OK) {
    const tc_x509_crl* effective = selected.delta ? selected.delta : selected.base;
    int order, equal;
    result = x509_crl_order(&selected, &latest, order_policy, tree->work, &order);
    if (result != TC_TLV_OK)
      return result;
    if (order)
      continue;
    if (conflict)
      return TC_TLV_INVALID;
    tc_x509_crl_evidence candidate = {0};
    result = tc_x509_crl_apply(&selected, query, at, cache->limits, tree, cache->names, oids,
                               oid_capacity, &candidate);
    if (result == TC_TLV_END)
      continue;
    if (result != TC_TLV_OK)
      return result;
    if (update) {
      result = TC_X509_time_compare(update, &effective->this_update, &order);
      if (result != TC_TLV_OK)
        return result;
      if (order)
        return TC_TLV_INVALID;
      result = tc_x509_crl_evidence_equal(&chosen, &candidate, &equal);
      if (result != TC_TLV_OK)
        return result;
      if (!equal)
        return TC_TLV_INVALID;
    } else {
      chosen = candidate;
      update = &effective->this_update;
    }
  }
  if (result != TC_TLV_END)
    return result;
  if (!update || !(chosen.reasons & ~evidence->reasons))
    return TC_TLV_END;
  return tc_x509_crl_evidence_add(evidence, chosen.reasons, &chosen.revocation);
}

TC_TLV_result tc_x509_crl_scope_apply(const tc_x509_crl_signature_cache* cache, size_t reference,
                                      TC_X509_crl_delta_policy delta_policy,
                                      TC_X509_crl_order_policy order_policy,
                                      const tc_x509_crl_query* query, const TC_X509_time* at,
                                      const tc_pki_tree_workspace* tree, TC_bytes* oids,
                                      size_t oid_capacity, tc_x509_crl_evidence* evidence)
{
  return tc_x509_crl_scope_evaluate(cache, reference, delta_policy, order_policy, query, at, tree,
                                    oids, oid_capacity, evidence, NULL);
}
#endif
