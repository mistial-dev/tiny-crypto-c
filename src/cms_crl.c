/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * CRL processing over CMS revocation collections: CRL signer search, scope
 * and distribution-point processing and CRL resolution. */
#include <tiny_crypto/cms_validation.h>
#include <tiny_crypto/piv_oid.h>
#if TC_ENABLE_CMS_VALIDATION
#include "cms_internal.h"

TC_TLV_result tc_cms_crl_signer_candidate_next(tc_cms_candidates* reader,
    const tc_x509_crl* crl, const tc_x509_crl_extension_info* extensions,
    const TC_X509_name_workspace* names, const tc_pki_tree_workspace* tree,
    TC_X509_workspace* parser, TC_X509_certificate* scratch, TC_bytes* out)
{
  const tc_x509_crl_filter filter = {crl,extensions,names};
  if (!crl || !extensions || !names) return TC_TLV_ARGUMENT;
  return tc_cms_x509_candidate_next(reader,tc_x509_crl_filter_match,&filter,tree,parser,scratch,out);
}

TC_X509_path_status tc_cms_crl_signer_find(const tc_cms_candidates* candidates,
    const tc_x509_crl* crl, const tc_x509_crl_extension_info* extensions,
    const TC_X509_store_source* path_source, size_t anchor_index,
    const TC_X509_path_options* options, const tc_pki_tree_workspace* tree,
    const TC_X509_path_workspace* validation, const TC_X509_search_workspace* search,
    TC_X509_search_result* out)
{
  const tc_x509_crl_trust trust = {path_source,anchor_index,options,tree,validation,search};
  return tc_x509_path_status(tc_cms_crl_search(candidates,crl,extensions,&trust,
      tc_x509_crl_check_signer,crl,out,NULL));
}

TC_TLV_result tc_cms_crl_process(const tc_cms_candidates* candidates,
    const tc_x509_crl_selected* selected, const tc_x509_crl_query* query,
    const TC_X509_store_source* path_source, size_t anchor_index,
    const TC_X509_path_options* options, const tc_pki_tree_workspace* tree,
    const TC_X509_path_workspace* validation, const TC_X509_search_workspace* search,
    tc_x509_crl_evidence* evidence, TC_X509_search_result* out)
{
  tc_x509_crl_status status;
  TC_TLV_result result;
  const tc_x509_crl_trust trust = {path_source,anchor_index,options,tree,validation,search};
  if (!candidates || !tc_x509_crl_trust_valid(&trust) || !selected || !selected->base || !selected->base_info ||
      !!selected->delta != !!selected->delta_info || !query || !query->certificate ||
      !query->point || (query->certificate_ca != 0 && query->certificate_ca != 1) || !out)
    return TC_TLV_ARGUMENT;
  result = tc_x509_crl_evidence_status(evidence,&status);
  if (result != TC_TLV_OK) return result;
  if (status != TC_X509_CRL_UNDETERMINED) return TC_TLV_END;
  const tc_x509_crl_processing processing = {selected,query,evidence};
  return tc_cms_crl_search(candidates,selected->base,selected->base_info,&trust,
      tc_x509_crl_process_candidate,&processing,out,NULL);
}

TC_TLV_result tc_cms_crl_index_process(const tc_cms_candidates* candidates,
    const TC_X509_crl_index* index, size_t base, TC_X509_crl_delta_policy delta_policy,
    const tc_x509_crl_query* query, const TC_X509_store_source* path_source, size_t anchor_index,
    const TC_X509_path_options* options, const tc_pki_tree_workspace* tree,
    const TC_X509_path_workspace* validation, const TC_X509_search_workspace* search,
    tc_x509_crl_evidence* evidence, TC_X509_search_result* out)
{
  const tc_x509_crl_trust trust = {path_source,anchor_index,options,tree,validation,search};
  tc_x509_crl_status status;
  if (!candidates || !tc_x509_crl_index_arguments(index,query,&trust,out) || base >= index->count ||
      !x509_crl_delta_policy_valid(delta_policy)) return TC_TLV_ARGUMENT;
  const TC_X509_crl_record* record = &index->records[base];
  if (record->policy != TC_TLV_OK) return record->policy;
  if (record->extensions.present & TC_CRL_EXT_DELTA) return TC_TLV_ARGUMENT;
  TC_TLV_result result = tc_x509_crl_evidence_status(evidence,&status);
  if (result != TC_TLV_OK) return result;
  if (status != TC_X509_CRL_UNDETERMINED) return TC_TLV_END;
  const tc_x509_crl_index_processing processing = {index,base,delta_policy,query,evidence};
  return tc_cms_crl_search(candidates,&record->crl,&record->extensions,&trust,
      tc_x509_crl_index_attempt,&processing,out,NULL);
}

static TC_TLV_result cms_crl_operation_source(const tc_cms_candidates* candidates,
    tc_pki_store_candidates* store, TC_bytes metadata[3],
    tc_x509_crl_operation_source* out);

static TC_TLV_result cms_crl_scope_run(const tc_cms_candidates* candidates,
    const TC_X509_crl_index* index, size_t reference, TC_X509_crl_delta_policy delta_policy,
    TC_X509_crl_order_policy order_policy, const tc_x509_crl_query* query,
    const TC_X509_store_source* path_source, size_t anchor_index,
    const TC_X509_path_options* options, const tc_pki_tree_workspace* tree,
    const TC_X509_path_workspace* validation, const TC_X509_search_workspace* search,
    uint8_t* states, size_t capacity, const tc_x509_crl_path_check* check, int all_scopes,
    const TC_bytes* points, int from_certificate, const tc_x509_crl_extra_storage* extra,
    const tc_x509_crl_held_path* path,
    tc_x509_crl_evidence* evidence, TC_X509_search_result* out)
{
  const tc_x509_crl_trust trust = {path_source,anchor_index,options,tree,validation,search};
  if (!candidates) return TC_TLV_ARGUMENT;
  tc_x509_crl_scope_processing processing = {index,reference,delta_policy,order_policy,
    query,states,capacity,evidence,check,NULL,NULL,NULL,NULL};
  tc_pki_store_candidates store;
  TC_bytes metadata[3];
  tc_x509_crl_operation_source source;
  TC_TLV_result result = cms_crl_operation_source(candidates,&store,metadata,&source);
  if (result != TC_TLV_OK) return result;
  return tc_x509_crl_scope_execute(&source,&processing,&trust,points,from_certificate,
      all_scopes,extra,path,out);
}

TC_TLV_result tc_cms_crl_scope_process(const tc_cms_candidates* candidates,
    const TC_X509_crl_index* index, size_t reference, TC_X509_crl_delta_policy delta_policy,
    TC_X509_crl_order_policy order_policy, const tc_x509_crl_query* query,
    const TC_X509_store_source* path_source, size_t anchor_index,
    const TC_X509_path_options* options, const tc_pki_tree_workspace* tree,
    const TC_X509_path_workspace* validation, const TC_X509_search_workspace* search,
    uint8_t* states, size_t capacity, tc_x509_crl_evidence* evidence, TC_X509_search_result* out)
{
  return cms_crl_scope_run(candidates,index,reference,delta_policy,order_policy,query,path_source,anchor_index,
      options,tree,validation,search,states,capacity,NULL,0,NULL,0,NULL,NULL,evidence,out);
}

TC_TLV_result tc_cms_crl_point_process(const tc_cms_candidates* candidates,
    const TC_X509_crl_index* index, TC_X509_crl_delta_policy delta_policy,
    TC_X509_crl_order_policy order_policy, const tc_x509_crl_query* query,
    const TC_X509_store_source* path_source, size_t anchor_index,
    const TC_X509_path_options* options, const tc_pki_tree_workspace* tree,
    const TC_X509_path_workspace* validation, const TC_X509_search_workspace* search,
    uint8_t* states, size_t capacity, const tc_x509_crl_path_check* check,
    tc_x509_crl_evidence* evidence)
{
  TC_X509_search_result scratch;
  if (!check || !check->verify) return TC_TLV_ARGUMENT;
  return cms_crl_scope_run(candidates,index,0,delta_policy,order_policy,query,path_source,anchor_index,
      options,tree,validation,search,states,capacity,check,1,NULL,0,NULL,NULL,evidence,&scratch);
}

TC_TLV_result tc_cms_crl_points_process(const tc_cms_candidates* candidates,
    const TC_X509_crl_index* index, TC_X509_crl_delta_policy delta_policy,
    TC_X509_crl_order_policy order_policy, const tc_x509_crl_query* query,
    TC_bytes points, const TC_X509_store_source* path_source, size_t anchor_index,
    const TC_X509_path_options* options, const tc_pki_tree_workspace* tree,
    const TC_X509_path_workspace* validation, const TC_X509_search_workspace* search,
    uint8_t* states, size_t capacity, const tc_x509_crl_path_check* check,
    tc_x509_crl_evidence* evidence)
{
  TC_X509_search_result scratch;
  if (!check || !check->verify) return TC_TLV_ARGUMENT;
  return cms_crl_scope_run(candidates,index,0,delta_policy,order_policy,query,path_source,anchor_index,
      options,tree,validation,search,states,capacity,check,1,&points,0,NULL,NULL,evidence,&scratch);
}

TC_TLV_result tc_cms_crl_certificate_process(const tc_cms_candidates* candidates,
    const TC_X509_crl_index* index, TC_X509_crl_delta_policy delta_policy,
    TC_X509_crl_order_policy order_policy, const TC_X509_certificate* certificate,
    const TC_X509_store_source* path_source, size_t anchor_index,
    const TC_X509_path_options* options, const tc_pki_tree_workspace* tree,
    const TC_X509_path_workspace* validation, const TC_X509_search_workspace* search,
    uint8_t* states, size_t capacity, const tc_x509_crl_path_check* check,
    tc_x509_crl_evidence* evidence)
{
  TC_X509_search_result scratch;
  const tc_pki_distribution_point fallback = {0};
  const tc_x509_crl_query query = {certificate,&fallback,0};
  if (!check || !check->verify) return TC_TLV_ARGUMENT;
  return cms_crl_scope_run(candidates,index,0,delta_policy,order_policy,&query,path_source,anchor_index,
      options,tree,validation,search,states,capacity,check,1,NULL,1,NULL,NULL,evidence,&scratch);
}

static TC_TLV_result cms_crl_operation_source(const tc_cms_candidates* candidates,
    tc_pki_store_candidates* store, TC_bytes metadata[3],
    tc_x509_crl_operation_source* out)
{
  if (!candidates || !store || !metadata || !out) return TC_TLV_ARGUMENT;
  tc_x509_crl_candidate_source adapter = {candidates,candidates->external,tc_cms_crl_source_search};
  if (candidates->external && tc_pki_end(&candidates->collection.embedded)) {
    *store = tc_cms_store_cursor(candidates);
    adapter.context = store;
    adapter.search = tc_x509_crl_store_source_search;
  }
  size_t count = 0;
  TC_TLV_result result = tc_pki_storage_span(candidates,1,sizeof *candidates,&metadata[count++]);
  if (result != TC_TLV_OK) return result;
  if (candidates->external) {
    result = tc_pki_storage_span(candidates->external,1,sizeof *candidates->external,&metadata[count++]);
    if (result != TC_TLV_OK) return result;
  }
  metadata[count++] = candidates->collection.embedded.input;
  *out = (tc_x509_crl_operation_source){adapter,metadata,count};
  return TC_TLV_OK;
}

static TC_TLV_result cms_crl_resolution_init(const tc_cms_crl_resolution* input,
    tc_pki_store_candidates* store, TC_bytes metadata[3],
    tc_x509_crl_operation_source* source, tc_x509_crl_resolution* out)
{
  if (!input || !out) return TC_TLV_ARGUMENT;
  TC_TLV_result result = cms_crl_operation_source(input->candidates,store,metadata,source);
  if (result != TC_TLV_OK) return result;
  *out = (tc_x509_crl_resolution){source,input->index,input->source,input->options,
    input->anchor_index,input->delta_policy,input->order_policy};
  return TC_TLV_OK;
}

TC_TLV_result tc_cms_crl_resolve(const TC_X509_certificate* target,
    const tc_cms_crl_resolution* resolution, const tc_x509_crl_resolution_workspace* workspace,
    tc_x509_crl_evidence* out)
{
  tc_pki_store_candidates store;
  TC_bytes metadata[3];
  tc_x509_crl_operation_source source;
  tc_x509_crl_resolution operation;
  TC_TLV_result result = cms_crl_resolution_init(resolution,&store,metadata,&source,&operation);
  if (result != TC_TLV_OK) return result;
  return tc_x509_crl_resolve(target,&operation,workspace,NULL,out);
}

TC_TLV_result tc_cms_crl_path_resolve(const TC_bytes* chain, size_t count,
    const tc_cms_crl_resolution* resolution, const tc_x509_crl_resolution_workspace* workspace,
    TC_X509_revocation_result* out)
{
  tc_pki_store_candidates store;
  TC_bytes metadata[3];
  tc_x509_crl_operation_source source;
  tc_x509_crl_resolution operation;
  TC_TLV_result result = cms_crl_resolution_init(resolution,&store,metadata,&source,&operation);
  if (result != TC_TLV_OK) return result;
  tc_x509_crl_held_path held = {0};
  held.chain = chain; held.count = count; held.out = out;
  return tc_x509_crl_path_operation(&held,&operation,workspace);
}

#endif
