/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/cms_validation.h>
#include <tiny_crypto/piv_oid.h>
#if TC_ENABLE_CMS_VALIDATION
#include "cms_base_internal.h"
#include "cms_internal.h"
#include "credential_status_internal.h"
#include "x509_revocation_internal.h"
#include "x509_path_internal.h"
#include "x509_time_internal.h"
#include "pki_internal.h"
#include "pki_children_internal.h"
#include "pki_octets_internal.h"
#include "pki_tree_internal.h"
#include "pki_extensions_internal.h"
#include "pki_source_internal.h"
#include "pki_identifier_internal.h"
#include "pki_storage_internal.h"
#include "pki_reader_internal.h"
#include "cms_digest_internal.h"
#include "cms_signature_internal.h"
#include "pki_status_internal.h"
#include "pki_hash_parts_internal.h"

TC_TLV_result tc_cms_other_format_read(TC_bytes encoded, tc_cms_other_kind kind,
    const TC_TLV_limits* limits, const tc_pki_tree_workspace* tree, tc_cms_other_format* out)
{
  tc_pki_oid_value parsed;
  TC_TLV_result result;
  unsigned tag;
  if (!out) return TC_TLV_ARGUMENT;
  if (kind == TC_CMS_OTHER_CERTIFICATE) tag = 0xa3;
  else if (kind == TC_CMS_OTHER_REVOCATION) tag = 0xa1;
  else return TC_TLV_ARGUMENT;
  result = tc_pki_tree_oid_value(encoded,tag,TC_TLV_BER,limits,tree,&parsed);
  if (result != TC_TLV_OK) return result;
  if (!parsed.value.data) return TC_TLV_INVALID;
  *out = (tc_cms_other_format){parsed.oid,parsed.value};
  return TC_TLV_OK;
}

static TC_TLV_result cms_collection_init(TC_bytes embedded, unsigned tag,
    size_t max_records, size_t max_bytes, const TC_TLV_limits* limits,
    const tc_pki_tree_workspace* tree, tc_cms_collection* out)
{
  tc_cms_collection parsed = {0};
  TC_TLV_result result;
  if (!out || !tree || !tree->work || (!embedded.data && embedded.length))
    return TC_TLV_ARGUMENT;
  if (embedded.length > max_bytes) return TC_TLV_LIMIT;
  if (embedded.length)
    result = tc_pki_tree_open(embedded,tag,TC_TLV_BER,limits,tree,&parsed.embedded);
  else result = TC_TLV_reader_init(&parsed.embedded,NULL,0,TC_TLV_DER,limits);
  if (result != TC_TLV_OK) return result;
  parsed.remaining = max_records;
  parsed.bytes_left = max_bytes - embedded.length;
  *out = parsed;
  return TC_TLV_OK;
}

/* One bounded traversal for certificates and revocation objects. Typed wrappers
 * classify embedded choices before committing the reader position. */
static TC_TLV_result cms_collection_next(tc_cms_collection* reader,
    const tc_pki_record_source* external, const tc_pki_tree_workspace* tree,
    TC_TLV_element* out, int* embedded)
{
  tc_cms_collection next;
  TC_TLV_element element = {0};
  TC_TLV_result result;
  if (!reader || !tree || !tree->work || !out) return TC_TLV_ARGUMENT;
  next = *reader;
  if (tc_pki_end(&next.embedded) && (!external || next.external_index == external->count)) return TC_TLV_END;
  if (!next.remaining || tc_pki_work_charge(tree->work,1) != TC_TLV_OK) return TC_TLV_LIMIT;
  if (!tc_pki_end(&next.embedded)) {
    result = tc_pki_tree_next(&next.embedded,tree,&element);
    if (result != TC_TLV_OK) return result;
    *embedded = 1;
  } else {
    result = tc_pki_record_read(external,next.external_index,tree->work,&element.encoded);
    if (result != TC_TLV_OK) return result;
    if (element.encoded.length > next.bytes_left) return TC_TLV_LIMIT;
    next.bytes_left -= element.encoded.length;
    ++next.external_index;
    *embedded = 0;
  }
  --next.remaining;
  *reader = next;
  *out = element;
  return TC_TLV_OK;
}

TC_TLV_result tc_cms_candidates_init(TC_bytes embedded, const TC_X509_store_source* external,
    size_t max_candidates, size_t max_bytes, const TC_TLV_limits* limits,
    const tc_pki_tree_workspace* tree, tc_cms_candidates* out)
{
  tc_cms_candidates parsed;
  TC_TLV_result result;
  if (!out || (external && external->candidate_count && !external->candidate)) return TC_TLV_ARGUMENT;
  result = cms_collection_init(embedded,0xa0,max_candidates,max_bytes,limits,tree,&parsed.collection);
  if (result != TC_TLV_OK) return result;
  parsed.external = external;
  *out = parsed;
  return TC_TLV_OK;
}

TC_TLV_result tc_cms_candidates_next(tc_cms_candidates* reader, const tc_pki_tree_workspace* tree,
    tc_cms_certificate_choice* out)
{
  tc_cms_candidates next;
  tc_pki_record_source external = {0};
  tc_cms_certificate_choice choice = {{NULL,0},TC_CMS_CERT_X509};
  TC_TLV_element element;
  TC_TLV_result result;
  int embedded;
  if (!reader || !out) return TC_TLV_ARGUMENT;
  next = *reader;
  if (next.external) external = (tc_pki_record_source){next.external->context,
    next.external->candidate_count,next.external->candidate};
  result = cms_collection_next(&next.collection,&external,tree,&element,&embedded);
  if (result != TC_TLV_OK) return result;
  if (embedded) {
    result = tc_cms_classify_certificate(&element,&choice.kind);
    if (result != TC_TLV_OK) return result;
    if (choice.kind == TC_CMS_CERT_OTHER) {
      tc_cms_other_format other;
      result = tc_cms_other_format_read(element.encoded,TC_CMS_OTHER_CERTIFICATE,
          &next.collection.embedded.limits,tree,&other);
      if (result != TC_TLV_OK) return result;
    }
  }
  choice.encoded = element.encoded;
  *reader = next; *out = choice;
  return TC_TLV_OK;
}

TC_TLV_result tc_cms_revocations_init(TC_bytes embedded, const tc_pki_record_source* external,
    size_t max_records, size_t max_bytes, const TC_TLV_limits* limits,
    const tc_pki_tree_workspace* tree, tc_cms_revocations* out)
{
  tc_cms_revocations parsed;
  TC_TLV_result result;
  if (!out || (external && external->count && !external->read)) return TC_TLV_ARGUMENT;
  result = cms_collection_init(embedded,0xa1,max_records,max_bytes,limits,tree,&parsed.collection);
  if (result != TC_TLV_OK) return result;
  parsed.external = external;
  *out = parsed;
  return TC_TLV_OK;
}

TC_TLV_result tc_cms_revocations_next(tc_cms_revocations* reader,
    const tc_pki_tree_workspace* tree, tc_cms_revocation_choice* out)
{
  tc_cms_revocations next;
  tc_cms_revocation_choice choice = {{NULL,0},TC_CMS_REVOCATION_CRL};
  TC_TLV_element element;
  TC_TLV_result result;
  int embedded;
  if (!reader || !out) return TC_TLV_ARGUMENT;
  next = *reader;
  result = cms_collection_next(&next.collection,next.external,tree,&element,&embedded);
  if (result != TC_TLV_OK) return result;
  if (embedded && !tc_pki_tag(&element,0x30)) {
    tc_cms_other_format other;
    if (!tc_pki_tag(&element,0xa1)) return TC_TLV_INVALID;
    result = tc_cms_other_format_read(element.encoded,TC_CMS_OTHER_REVOCATION,
        &next.collection.embedded.limits,tree,&other);
    if (result != TC_TLV_OK) return result;
    choice.kind = TC_CMS_REVOCATION_OTHER;
  }
  choice.encoded = element.encoded;
  *reader = next; *out = choice;
  return TC_TLV_OK;
}


TC_TLV_result tc_cms_crl_index_init(const tc_cms_revocations* reader,
    const tc_pki_tree_workspace* tree, TC_bytes* oids, size_t oid_capacity,
    TC_X509_crl_record* records, size_t capacity, TC_X509_crl_index* out)
{
  enum { CRL_ROWS, CRL_OIDS, CRL_FRAMES, CRL_WORK, CRL_OUTPUT, CRL_WRITES };
  tc_cms_revocations next;
  tc_cms_revocation_choice choice;
  TC_X509_crl_index index = {records,0,0};
  TC_bytes writes[CRL_WRITES];
  TC_TLV_result result;
  if (!reader || !tree || !tree->work || !out) return TC_TLV_ARGUMENT;
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
  if (reader->external) TC_PKI_PLAN_INPUT(&plan, reader->external, 1);
  tc_pki_storage_plan_input_span(&plan, reader->collection.embedded.input);
  /* Keep bookkeeping private until work is known to be disjoint from inputs. */
  result = tc_pki_storage_plan_finish(&plan, tree->work);
  if (result != TC_TLV_OK) return result;
  tc_pki_record_guard guard = {reader->external,writes,CRL_WRITES};
  const tc_pki_record_source guarded = {&guard,reader->external ? reader->external->count : 0,
    tc_pki_record_guard_read};
  next = *reader;
  if (reader->external) next.external = &guarded;
  while ((result = tc_cms_revocations_next(&next,tree,&choice)) == TC_TLV_OK) {
    if (choice.kind == TC_CMS_REVOCATION_OTHER) { ++index.other_count; continue; }
    if (index.count == capacity) return TC_TLV_LIMIT;
    TC_X509_crl_record* record = &records[index.count];
    result = tc_x509_crl_record_read(choice.encoded,&next.collection.embedded.limits,
        tree,oids,oid_capacity,record);
    if (result != TC_TLV_OK) return result;
    ++index.count;
  }
  if (result != TC_TLV_END) return result;
  *out = index;
  return TC_TLV_OK;
}

static TC_TLV_result cms_indexed_candidate(void* context, size_t index, size_t* work, TC_bytes* out)
{
  const tc_cms_path_source* source = context;
  if (!source || index >= source->count || !work || !out) return TC_TLV_ARGUMENT;
  if (tc_pki_work_charge(work,1) != TC_TLV_OK) return TC_TLV_LIMIT;
  *out = source->certificates[index];
  return TC_TLV_OK;
}

static TC_TLV_result cms_indexed_anchor(void* context, size_t index, size_t* work,
    TC_X509_store_anchor* out)
{
  const tc_cms_path_source* source = context;
  if (!source || !source->external || !source->external->anchor ||
      index >= source->external->anchor_count || !work || !out) return TC_TLV_ARGUMENT;
  return source->external->anchor(source->external->context,index,work,out);
}

TC_TLV_result tc_cms_path_source_init(const tc_cms_candidates* candidates,
    const tc_pki_tree_workspace* tree, TC_bytes* index, size_t capacity,
    tc_cms_path_source* context, TC_X509_store_source* out)
{
  tc_cms_candidates reader;
  tc_cms_certificate_choice choice;
  TC_TLV_result result;
  size_t count = 0;
  if (!candidates || !tree || !tree->work || (!index && capacity) || !context || !out ||
      (candidates->external && candidates->external->anchor_count && !candidates->external->anchor))
    return TC_TLV_ARGUMENT;
  reader = *candidates;
  while ((result = tc_cms_candidates_next(&reader,tree,&choice)) == TC_TLV_OK) {
    if (choice.kind != TC_CMS_CERT_X509) continue;
    if (count == capacity) return TC_TLV_LIMIT;
    index[count++] = choice.encoded;
  }
  if (result != TC_TLV_END) return result;
  *context = (tc_cms_path_source){index,count,candidates->external};
  *out = (TC_X509_store_source){context,count,
      candidates->external ? candidates->external->anchor_count : 0,
      cms_indexed_candidate,cms_indexed_anchor};
  return TC_TLV_OK;
}

TC_TLV_result tc_cms_x509_candidate_next(tc_cms_candidates* reader,
    tc_pki_candidate_filter filter, const void* context, const tc_pki_tree_workspace* tree,
    TC_X509_workspace* parser, TC_X509_certificate* scratch, TC_bytes* out)
{
  tc_cms_candidates next;
  tc_cms_certificate_choice choice;
  TC_TLV_result result;
  if (!reader || !tree || !tree->work || !parser || !scratch || !out)
    return TC_TLV_ARGUMENT;
  next = *reader;
  for (;;) {
    int matched = -1;
    result = tc_cms_candidates_next(&next,tree,&choice);
    if (result == TC_TLV_END) { *reader = next; return result; }
    if (result != TC_TLV_OK) return result;
    if (choice.kind != TC_CMS_CERT_X509) continue;
    if (tc_pki_work_charge(tree->work,choice.encoded.length) != TC_TLV_OK) return TC_TLV_LIMIT;
    result = TC_X509_read(choice.encoded.data,choice.encoded.length,&next.collection.embedded.limits,parser,scratch);
    if (result != TC_TLV_OK) return result;
    if (filter) {
      const size_t before = *tree->work;
      result = filter(context,scratch,&next.collection.embedded.limits,tree,&matched);
      if (*tree->work > before) { *tree->work = 0; return TC_TLV_ARGUMENT; }
      if (result == TC_TLV_END) return TC_TLV_ARGUMENT;
      if (result != TC_TLV_OK) return result;
      if (matched != 0 && matched != 1) return TC_TLV_ARGUMENT;
    } else matched = 1;
    if (matched) { *reader = next; *out = choice.encoded; return TC_TLV_OK; }
  }
}

typedef struct {
  const tc_cms_signer_info* signer;
  TC_TLV_profile profile;
  const TC_X509_name_workspace* names;
} cms_signer_filter;
static TC_TLV_result cms_signer_candidate(const void* context,
    const TC_X509_certificate* candidate, const TC_TLV_limits* limits,
    const tc_pki_tree_workspace* tree, int* matched)
{
  const cms_signer_filter* filter = context;
  return tc_cms_signer_matches(filter->signer,filter->profile,candidate,limits,filter->names,tree,matched);
}

TC_TLV_result tc_cms_signer_candidate_next(tc_cms_candidates* reader,
    const tc_cms_signer_info* signer, TC_TLV_profile profile,
    const TC_X509_name_workspace* names, const tc_pki_tree_workspace* tree,
    TC_X509_workspace* parser, TC_X509_certificate* scratch, TC_bytes* out)
{
  const cms_signer_filter filter = {signer,profile,names};
  if (!signer || (profile != TC_TLV_DER && profile != TC_TLV_BER)) return TC_TLV_ARGUMENT;
  return tc_cms_x509_candidate_next(reader,cms_signer_candidate,&filter,tree,parser,scratch,out);
}

TC_TLV_result tc_cms_crl_signer_candidate_next(tc_cms_candidates* reader,
    const tc_x509_crl* crl, const tc_x509_crl_extension_info* extensions,
    const TC_X509_name_workspace* names, const tc_pki_tree_workspace* tree,
    TC_X509_workspace* parser, TC_X509_certificate* scratch, TC_bytes* out)
{
  const tc_x509_crl_filter filter = {crl,extensions,names};
  if (!crl || !extensions || !names) return TC_TLV_ARGUMENT;
  return tc_cms_x509_candidate_next(reader,tc_x509_crl_filter_match,&filter,tree,parser,scratch,out);
}

static TC_TLV_result cms_next_candidate(void* context,
    const tc_pki_tree_workspace* tree, TC_X509_workspace* parser, TC_X509_certificate* out)
{
  TC_bytes encoded;
  return tc_cms_x509_candidate_next(context,NULL,NULL,tree,parser,out,&encoded);
}

typedef union {
  tc_cms_candidates collection;
  tc_pki_store_candidates store;
} cms_candidate_cursor;

static tc_pki_store_candidates cms_store_cursor(const tc_cms_candidates* source)
{
  return (tc_pki_store_candidates){source->external,source->collection.embedded.limits,
    source->collection.external_index,source->collection.remaining,source->collection.bytes_left};
}

/* Each search owns its cursor; certificate bytes remain borrowed from the source. */
static tc_pki_candidate_next cms_candidate_cursor_init(const tc_cms_candidates* source,
    cms_candidate_cursor* storage, void** cursor)
{
  if (source->external && tc_pki_end(&source->collection.embedded)) {
    storage->store = cms_store_cursor(source);
    *cursor = &storage->store;
    return tc_pki_store_candidate_next;
  }
  storage->collection = *source;
  *cursor = &storage->collection;
  return cms_next_candidate;
}

static TC_TLV_result cms_certificate_search(const tc_cms_candidates* candidates,
    tc_pki_candidate_filter filter, const void* filter_context,
    const TC_TLV_limits* limits, const tc_pki_tree_workspace* tree,
    const TC_X509_path_workspace* validation, tc_pki_candidate_attempt attempt, const void* context,
    TC_X509_search_result* out, int* source_failed)
{
  if (!candidates) return TC_TLV_ARGUMENT;
  cms_candidate_cursor storage;
  void* cursor;
  const tc_pki_candidate_next next = cms_candidate_cursor_init(candidates,&storage,&cursor);
  return tc_pki_certificate_search(cursor,next,filter,filter_context,
      limits,tree,validation,attempt,context,out,source_failed);
}

static TC_TLV_result cms_crl_source_search(const void* candidates, const TC_X509_store_source* external,
    const tc_x509_crl* crl, const tc_x509_crl_extension_info* extensions,
    const tc_x509_crl_trust* trust, tc_x509_crl_attempt attempt, const void* context,
    TC_X509_search_result* out, int* source_failed)
{
  if (!candidates) return TC_TLV_ARGUMENT;
  cms_candidate_cursor storage;
  void* cursor;
  const tc_pki_candidate_next next = cms_candidate_cursor_init(candidates,&storage,&cursor);
  if (next == tc_pki_store_candidate_next) storage.store.source = external;
  else storage.collection.external = external;
  return tc_x509_crl_search_candidates(cursor,next,crl,extensions,
      trust,attempt,context,out,source_failed);
}

static TC_TLV_result cms_crl_search(const void* candidates,
    const tc_x509_crl* crl, const tc_x509_crl_extension_info* extensions,
    const tc_x509_crl_trust* trust, tc_x509_crl_attempt attempt, const void* context,
    TC_X509_search_result* out, int* source_failed)
{
  const tc_cms_candidates* source = candidates;
  if (!source) return TC_TLV_ARGUMENT;
  return cms_crl_source_search(source,source->external,crl,extensions,trust,attempt,context,out,source_failed);
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

static TC_TLV_result cms_signer_attempt(const void* context,
    const TC_X509_certificate* candidate, TC_X509_search_result* out)
{
  const cms_signer_trust* trust = context;
  TC_bytes signer_name = {NULL,0};
  TC_X509_signature_result signature = tc_cms_signer_verify_cached(trust->signer,
      trust->content_type,trust->digest,TC_CMS_VERIFY_DIGEST,trust->policy,&candidate->public_key,
      &trust->options->signatures,&trust->options->parsing,trust->signature,trust->tree->work,&signer_name,
      trust->signed_attrs);
  if (signature != TC_X509_SIGNATURE_VALID) return tc_pki_signature_status(signature);
  if (signer_name.data) {
    int matched;
    TC_TLV_result result = tc_pki_name_equal(signer_name,
        trust->policy.attributes == TC_CMS_ATTRIBUTES_DER ? TC_TLV_DER : TC_TLV_BER,
        candidate->subject,TC_TLV_DER,&trust->options->parsing,
        &trust->validation->names,trust->tree,&matched);
    if (result != TC_TLV_OK) return result;
    if (!matched) return TC_TLV_INVALID;
  }
  return tc_x509_path_result_status(tc_x509_path_build_work(candidate->encoded,trust->source,
      trust->options,trust->validation,trust->search,trust->tree->work,out));
}

static TC_X509_path_status cms_signer_find_policy(const tc_cms_candidates* candidates,
    const TC_CMS_signer_info* signer, TC_bytes content_type, TC_bytes digest,
    TC_CMS_verification_policy policy, const TC_X509_store_source* path_source,
    const TC_X509_path_options* options, const tc_pki_tree_workspace* tree,
    const TC_CMS_signature_workspace* signature, const TC_X509_path_workspace* validation,
    const TC_X509_search_workspace* search, TC_X509_search_result* out,
    tc_cms_signed_attrs_cache* signed_attrs)
{
  if (!signer || !path_source || !options || !signature || !validation || !search ||
      !content_type.data || !content_type.length || !digest.data || !digest.length ||
      !tc_cms_verification_policy_valid(policy))
    return TC_X509_PATH_ERROR;
  const cms_signer_filter filter = {signer,TC_TLV_BER,&validation->names};
  const cms_signer_trust trust = {signer,content_type,digest,policy,path_source,
      options,tree,signature,validation,search,signed_attrs};
  return tc_x509_path_status(cms_certificate_search(candidates,cms_signer_candidate,&filter,
      &options->parsing,tree,validation,cms_signer_attempt,&trust,out,NULL));
}

TC_X509_path_status tc_cms_signer_find(const tc_cms_candidates* candidates,
    const TC_CMS_signer_info* signer, TC_bytes content_type, TC_bytes digest,
    TC_CMS_attribute_encoding encoding, const TC_X509_store_source* path_source,
    const TC_X509_path_options* options, const tc_pki_tree_workspace* tree,
    const TC_CMS_signature_workspace* signature, const TC_X509_path_workspace* validation,
    const TC_X509_search_workspace* search, TC_X509_search_result* out)
{
  return cms_signer_find_policy(candidates,signer,content_type,digest,
      (TC_CMS_verification_policy){encoding,TC_CMS_RSA_PARAMETERS_NULL},path_source,
      options,tree,signature,validation,search,out,NULL);
}

enum {
  CMS_PATH_WRITE = TC_X509_PATH_STORAGE_COUNT, CMS_SEARCH_WRITE, CMS_INDEX_WRITE,
  CMS_SIGNATURE_WRITE, CMS_SIGNED_DIGEST_WRITE, CMS_RESULT_WRITE, CMS_WORK_WRITE, CMS_PATH_WRITE_COUNT
};

/* Record path, search, index, signature, result and work writes in
 * CMS_*_WRITE slot order. */
static void cms_path_plan_writes(tc_pki_storage_plan* plan,
    const TC_CMS_path_workspace* workspace, size_t* work, TC_X509_search_result* out)
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
    const TC_bytes* inputs, size_t input_count, const TC_bytes* parts, size_t part_count,
    const TC_X509_store_source* source, const TC_CMS_path_options* options,
    const TC_CMS_path_workspace* workspace)
{
  if (signer) TC_PKI_PLAN_INPUT(plan, signer, 1);
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

static TC_TLV_result cms_path_storage(const TC_CMS_signer_info* signer,
    const TC_bytes* inputs, size_t input_count,
    const TC_bytes* parts, size_t part_count,
    const TC_X509_store_source* source, const TC_CMS_path_options* options,
    const TC_CMS_path_workspace* workspace, size_t* work, TC_X509_search_result* out,
    TC_bytes writes[CMS_PATH_WRITE_COUNT], size_t* remaining)
{
  tc_pki_storage_plan plan;
  tc_pki_storage_plan_begin(&plan, writes, CMS_PATH_WRITE_COUNT, *work);
  cms_path_plan_writes(&plan, workspace, work, out);
  tc_pki_storage_plan_seal(&plan);
  cms_path_plan_inputs(&plan, signer, inputs, input_count, parts, part_count,
      source, options, workspace);
  return tc_pki_storage_plan_finish(&plan, remaining);
}

static int cms_path_arguments(const TC_X509_store_source* source,
    const TC_CMS_path_options* options, const TC_CMS_path_workspace* workspace,
    size_t* work, TC_X509_search_result* out)
{
  return source && options && workspace && work && out && workspace->signed_digest &&
      workspace->signed_digest_capacity >= TC_CMS_SIGNED_DIGEST_BYTES &&
      (!source->candidate_count || source->candidate) && (!source->anchor_count || source->anchor) &&
      tc_cms_verification_policy_valid((TC_CMS_verification_policy){options->attributes,options->rsa_parameters});
}

static TC_TLV_result cms_selected_certificate(void* context, size_t index,
    size_t* work, TC_bytes* out)
{
  (void)work;
  if (index) return TC_TLV_END;
  *out = *(const TC_bytes*)context;
  return TC_TLV_OK;
}

/* All inputs and source records are covered by the caller's storage preflight. */
static TC_X509_path_status cms_signer_path_build(const TC_CMS_signer_info* signer,
    TC_bytes content_type, TC_bytes digest, TC_bytes embedded, TC_bytes selected,
    const TC_X509_store_source* source, const TC_CMS_path_options* options,
    const TC_CMS_path_workspace* workspace, size_t* work, TC_X509_search_result* out,
    const TC_bytes writes[CMS_PATH_WRITE_COUNT])
{
  tc_cms_candidates candidates;
  tc_cms_path_source context;
  TC_X509_store_source indexed;
  TC_TLV_result result;
  tc_pki_source_guard guard = {source,writes,CMS_PATH_WRITE_COUNT};
  TC_X509_store_source guarded = tc_pki_source_guard_bind(&guard);
  const tc_pki_tree_workspace tree = {workspace->validation.frames,workspace->validation.frame_capacity,work};
  const TC_CMS_signature_workspace signature = {workspace->validation.frames,
    workspace->validation.frame_capacity,workspace->signature,workspace->signature_capacity};
  result = tc_cms_candidates_init(embedded,&guarded,options->max_candidates,options->max_candidate_bytes,
      &options->path.parsing,&tree,&candidates);
  if (result != TC_TLV_OK) return tc_x509_path_status(result);
  result = tc_cms_path_source_init(&candidates,&tree,workspace->certificates,
      workspace->certificate_capacity,&context,&indexed);
  if (result != TC_TLV_OK) return tc_x509_path_status(result);
  /* Reuse the index for identity search and path construction. External records
   * have already been fetched and checked against every writable range. */
  /* Explicit selection limits the signer search; issuers still use the index. */
  const TC_X509_store_source selection = {&selected,1,0,cms_selected_certificate,NULL};
  const TC_X509_store_source* signers = selected.length ? &selection : &indexed;
  result = tc_cms_candidates_init((TC_bytes){NULL,0},signers,
      selected.length ? options->max_candidates : indexed.candidate_count,
      options->max_candidate_bytes,&options->path.parsing,&tree,&candidates);
  if (result != TC_TLV_OK) return tc_x509_path_status(result);
  tc_cms_signed_attrs_cache signed_attrs = {0};
  signed_attrs.digest = workspace->signed_digest;
  signed_attrs.capacity = workspace->signed_digest_capacity;
  const TC_X509_path_status status = cms_signer_find_policy(&candidates,signer,content_type,digest,
      (TC_CMS_verification_policy){options->attributes,options->rsa_parameters},
      &indexed,&options->path,&tree,&signature,&workspace->validation,&workspace->search,out,
      &signed_attrs);
  TC_secure_zero(workspace->signed_digest,TC_CMS_SIGNED_DIGEST_BYTES);
  return status;
}

TC_X509_path_status TC_CMS_signer_path_build(const TC_CMS_signer_info* signer,
    TC_bytes content_type, TC_bytes digest, TC_bytes embedded,
    const TC_X509_store_source* source, const TC_CMS_path_options* options,
    const TC_CMS_path_workspace* workspace, size_t* work, TC_X509_search_result* out)
{
  TC_bytes writes[CMS_PATH_WRITE_COUNT];
  TC_TLV_result result;
  TC_X509_path_status status;
  size_t initial_work;
  if (!signer || !content_type.data || !content_type.length || !digest.data || !digest.length ||
      !cms_path_arguments(source,options,workspace,work,out)) return TC_X509_PATH_ERROR;
  initial_work = *work;
  const TC_bytes inputs[] = {content_type,digest,embedded};
  result = cms_path_storage(signer,inputs,sizeof inputs / sizeof *inputs,NULL,0,
      source,options,workspace,work,out,writes,work);
  if (result != TC_TLV_OK) return tc_x509_path_status(result);
  status = cms_signer_path_build(signer,content_type,digest,embedded,(TC_bytes){NULL,0},
      source,options,workspace,work,out,writes);
  if (status == TC_X509_PATH_VALID) out->validation.work_used = initial_work - *work;
  return status;
}

/* Keep the hash context local to the content phase. */
static TC_TLV_result cms_signed_content_digest(const TC_CMS_signed_data* data,
    const TC_bytes* detached, size_t detached_count,
    TC_hash_algorithm algorithm, const TC_TLV_limits* limits,
    const tc_pki_tree_workspace* tree, uint8_t* digest)
{
  tc_hash_workspace scratch;
  TC_TLV_result result = data->has_content ?
      tc_cms_hash_content(data->content,TC_CMS_CONTENT_BER_OCTETS,algorithm,limits,tree,&scratch,digest) :
      tc_pki_hash_parts(detached,detached_count,algorithm,limits,tree,&scratch,digest);
  TC_secure_zero(&scratch,sizeof scratch);
  return result;
}

static TC_X509_path_status cms_signed_data_path_build_parts(TC_bytes encoded, size_t signer_index,
    TC_bytes expected_type, const TC_bytes* detached_content, size_t detached_count,
    TC_bytes selected, const tc_cms_prepared_signed_data* prepared,
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
      !cms_path_arguments(source,options,workspace,work,out)) return TC_X509_PATH_ERROR;
  initial_work = *work;
  const TC_bytes inputs[] = {encoded,expected_type,selected};
  result = cms_path_storage(prepared ? prepared->signer : NULL,inputs,sizeof inputs / sizeof *inputs,
      detached_content,detached_count,
      source,options,workspace,work,out,writes,work);
  if (result != TC_TLV_OK) return tc_x509_path_status(result);
  const TC_TLV_limits* limits = &options->path.parsing;
  const tc_pki_tree_workspace tree = {workspace->validation.frames,workspace->validation.frame_capacity,work};
  if (tc_pki_work_charge(work,expected_type.length) != TC_TLV_OK) return TC_X509_PATH_LIMIT;
  if (TC_DER_oid_contents(expected_type.data,expected_type.length) != TC_TLV_OK) return TC_X509_PATH_ERROR;
  if (prepared) {
    if (signer_index || !prepared->data || !prepared->signer ||
        prepared->data->encoded.data != encoded.data ||
        prepared->data->encoded.length != encoded.length) return TC_X509_PATH_ERROR;
    data = *prepared->data;
  } else {
    result = tc_cms_signed_data_read(encoded,limits,tree.frames,tree.capacity,work,&data);
    if (result != TC_TLV_OK) return tc_x509_path_status(result);
  }
  /* Attached content cannot be replaced by application bytes. */
  if (data.has_content && detached_count) return TC_X509_PATH_ERROR;
  if (tc_pki_work_charge(work,data.content_type.length) != TC_TLV_OK) return TC_X509_PATH_LIMIT;
  if (!tc_pki_equal(data.content_type,expected_type)) return TC_X509_PATH_INVALID;
  if (prepared) signer = *prepared->signer;
  else {
    result = tc_cms_signed_data_check(&data,limits,&tree,signer_index,&signer);
    if (result != TC_TLV_OK) return tc_x509_path_status(result);
  }
  result = tc_cms_digest_algorithms(data.digest_algorithms,&signer.digest_algorithm,limits,&tree,&algorithm);
  if (result != TC_TLV_OK) return tc_x509_path_status(result);
  if (!tc_hash_info_get(algorithm,&hash)) return TC_X509_PATH_UNSUPPORTED;
  result = cms_signed_content_digest(&data,detached_content,detached_count,algorithm,limits,&tree,digest);
  if (result == TC_TLV_OK)
    status = cms_signer_path_build(&signer,data.content_type,(TC_bytes){digest,hash.digest_length},
        data.certificates,selected,source,options,workspace,work,out,writes);
  else status = tc_x509_path_status(result);
  TC_secure_zero(digest,sizeof digest);
  if (status == TC_X509_PATH_VALID) out->validation.work_used = initial_work - *work;
  return status;
}

TC_X509_path_status TC_CMS_signed_data_path_build_parts(TC_bytes encoded, size_t signer_index,
    TC_bytes expected_type, const TC_bytes* detached_content, size_t detached_count,
    const TC_X509_store_source* source, const TC_CMS_path_options* options,
    const TC_CMS_path_workspace* workspace, size_t* work, TC_X509_search_result* out)
{
  return cms_signed_data_path_build_parts(encoded,signer_index,expected_type,
      detached_content,detached_count,(TC_bytes){NULL,0},NULL,source,options,workspace,work,out);
}

TC_X509_path_status TC_CMS_signed_data_path_build(TC_bytes encoded, size_t signer_index,
    TC_bytes expected_type, TC_bytes detached_content,
    const TC_X509_store_source* source, const TC_CMS_path_options* options,
    const TC_CMS_path_workspace* workspace, size_t* work, TC_X509_search_result* out)
{
  const size_t count = detached_content.data || detached_content.length ? 1u : 0u;
  return TC_CMS_signed_data_path_build_parts(encoded,signer_index,expected_type,
      count ? &detached_content : NULL,count,source,options,workspace,work,out);
}

static TC_credential_status cms_credential_error(TC_TLV_result result)
{
  return tc_credential_tlv_status(result,&tc_credential_tlv_cms);
}

TC_credential_status tc_cms_path_revocation_check(const TC_X509_search_result* path,
    const TC_X509_store_source* source, const TC_CMS_revocation_policy* revocation,
    const TC_CMS_credential_workspace* workspace, size_t* work)
{
  for (size_t i = 0; i < path->count; ++i) workspace->held_path[i] = path->path[i];
  const TC_X509_revocation_options policy = {
    revocation->index,source,revocation->signer_policy,path->anchor_index,
    revocation->max_candidate_bytes,revocation->delta_policy,revocation->order_policy
  };
  const TC_X509_revocation_workspace scratch = {
    &workspace->path->validation,&workspace->path->search,
    workspace->crl_states,workspace->crl_capacity,workspace->nodes,workspace->node_capacity,
    workspace->scopes,workspace->scope_capacity,
    workspace->signer_path,workspace->signer_path_capacity,
    workspace->signer_policies,workspace->signer_policy_capacity
  };
  TC_X509_revocation_result checked;
  TC_TLV_result result = TC_X509_path_check_revocation(workspace->held_path,path->count,
      &policy,&scratch,work,&checked);
  if (result != TC_TLV_OK) return cms_credential_error(result);
  if (checked.status == TC_X509_CRL_REVOKED) return TC_CREDENTIAL_REVOKED;
  return checked.status == TC_X509_CRL_UNREVOKED ? TC_CREDENTIAL_VALID : TC_CREDENTIAL_UNSUPPORTED;
}

static TC_credential_status cms_credential_validate_impl(
    const TC_CMS_validation_request* request,
    const TC_X509_store_source* source, const TC_CMS_path_options* options,
    const TC_CMS_revocation_policy* revocation,
    const TC_CMS_credential_workspace* workspace, size_t* work,
    const TC_bytes* metadata, size_t metadata_count,
    const tc_cms_prepared_signed_data* prepared)
{
  enum { HELD_PATH = CMS_PATH_WRITE_COUNT, CRL_STATES, CRL_NODES, WRITE_COUNT };
  TC_bytes writes[WRITE_COUNT];
  TC_X509_search_result path;
  TC_TLV_result result;
  int time_order;
  if (!request || (metadata_count && !metadata)) return TC_CREDENTIAL_ERROR;
  const TC_bytes encoded = request->encoded;
  const TC_bytes expected_type = request->expected_type;
  const TC_bytes* detached_content = request->detached_content;
  const size_t detached_count = request->detached_count;
  const size_t signer_index = request->signer_index;
  const TC_bytes selected = request->signer_certificate;
  if (prepared && (signer_index || !prepared->data || !prepared->signer ||
      prepared->data->encoded.data != encoded.data ||
      prepared->data->encoded.length != encoded.length)) return TC_CREDENTIAL_ERROR;
  if ((!selected.data) != (!selected.length)) return TC_CREDENTIAL_ERROR;
  if (!encoded.data || !encoded.length || !expected_type.data || !expected_type.length ||
      !workspace || !workspace->path || !revocation || !revocation->index ||
      !revocation->signer_policy || !cms_path_arguments(source,options,workspace->path,work,&path) ||
      (revocation->index->count && !revocation->index->records) ||
      (revocation->delta_policy != TC_X509_CRL_COMPLETE_ONLY &&
       revocation->delta_policy != TC_X509_CRL_DELTA_IF_AVAILABLE &&
       revocation->delta_policy != TC_X509_CRL_DELTA_REQUIRED) ||
      (revocation->order_policy != TC_X509_CRL_ORDER_NUMBER &&
       revocation->order_policy != TC_X509_CRL_ORDER_THIS_UPDATE) ||
      TC_X509_time_compare(&options->path.at,&revocation->signer_policy->at,&time_order) != TC_TLV_OK ||
      time_order) return TC_CREDENTIAL_ERROR;
  if (workspace->path_capacity < workspace->path->search.capacity ||
      workspace->crl_capacity < revocation->index->count) return TC_CREDENTIAL_LIMIT;
  const TC_bytes inputs[] = {encoded,expected_type,selected};
  size_t budget;
  tc_pki_storage_plan plan;
  tc_pki_storage_plan_begin(&plan, writes, WRITE_COUNT, *work);
  cms_path_plan_writes(&plan, workspace->path, work, &path);
  TC_PKI_PLAN_WRITE(&plan, workspace->held_path, workspace->path_capacity);
  TC_PKI_PLAN_WRITE(&plan, workspace->crl_states, workspace->crl_capacity);
  TC_PKI_PLAN_WRITE(&plan, workspace->nodes, workspace->node_capacity);
  tc_pki_storage_plan_seal(&plan);
  cms_path_plan_inputs(&plan, NULL, inputs, sizeof inputs / sizeof *inputs,
      detached_content, detached_count, source, options, workspace->path);
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
  if (result != TC_TLV_OK) return cms_credential_error(result);
  tc_pki_source_guard guard = {source,writes,WRITE_COUNT};
  const TC_X509_store_source guarded = tc_pki_source_guard_bind(&guard);
  *work = budget;
  switch (cms_signed_data_path_build_parts(encoded,signer_index,expected_type,
      detached_content,detached_count,selected,prepared,&guarded,options,workspace->path,work,&path)) {
    case TC_X509_PATH_VALID: break;
    case TC_X509_PATH_INVALID: return TC_CREDENTIAL_INVALID;
    case TC_X509_PATH_UNSUPPORTED: return TC_CREDENTIAL_UNSUPPORTED;
    case TC_X509_PATH_LIMIT: return TC_CREDENTIAL_LIMIT;
    default: return TC_CREDENTIAL_ERROR;
  }
  return tc_cms_path_revocation_check(&path,&guarded,revocation,workspace,work);
}

TC_credential_status tc_cms_credential_validate_with_metadata(
    const TC_CMS_validation_request* request,
    const TC_X509_store_source* source, const TC_CMS_path_options* options,
    const TC_CMS_revocation_policy* revocation,
    const TC_CMS_credential_workspace* workspace, size_t* work,
    const TC_bytes* metadata, size_t metadata_count)
{
  return cms_credential_validate_impl(request,source,options,revocation,
      workspace,work,metadata,metadata_count,NULL);
}

TC_credential_status tc_cms_credential_validate_prepared(
    const TC_CMS_validation_request* request,
    const TC_X509_store_source* source, const TC_CMS_path_options* options,
    const TC_CMS_revocation_policy* revocation,
    const TC_CMS_credential_workspace* workspace, size_t* work,
    const tc_cms_prepared_signed_data* prepared)
{
  return cms_credential_validate_impl(request,source,options,revocation,
      workspace,work,NULL,0,prepared);
}

TC_credential_status TC_CMS_credential_validate(const TC_CMS_validation_request* request,
    const TC_X509_store_source* source, const TC_CMS_path_options* options,
    const TC_CMS_revocation_policy* revocation,
    const TC_CMS_credential_workspace* workspace, size_t* work)
{
  return tc_cms_credential_validate_with_metadata(request,source,options,
      revocation,workspace,work,NULL,0);
}


TC_X509_path_status tc_cms_crl_signer_find(const tc_cms_candidates* candidates,
    const tc_x509_crl* crl, const tc_x509_crl_extension_info* extensions,
    const TC_X509_store_source* path_source, size_t anchor_index,
    const TC_X509_path_options* options, const tc_pki_tree_workspace* tree,
    const TC_X509_path_workspace* validation, const TC_X509_search_workspace* search,
    TC_X509_search_result* out)
{
  const tc_x509_crl_trust trust = {path_source,anchor_index,options,tree,validation,search};
  return tc_x509_path_status(cms_crl_search(candidates,crl,extensions,&trust,
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
  return cms_crl_search(candidates,selected->base,selected->base_info,&trust,
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
  return cms_crl_search(candidates,&record->crl,&record->extensions,&trust,
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
  tc_x509_crl_candidate_source adapter = {candidates,candidates->external,cms_crl_source_search};
  if (candidates->external && tc_pki_end(&candidates->collection.embedded)) {
    *store = cms_store_cursor(candidates);
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

TC_TLV_result tc_cms_signer_matches(const tc_cms_signer_info* signer, TC_TLV_profile profile,
    const TC_X509_certificate* certificate, const TC_TLV_limits* limits,
    const TC_X509_name_workspace* names, const tc_pki_tree_workspace* tree, int* matched)
{
  TC_TLV_result result;
  if (!signer || !certificate || !limits || !tree || !tree->work || !matched ||
      (profile != TC_TLV_DER && profile != TC_TLV_BER)) return TC_TLV_ARGUMENT;
  if (signer->version == 1) {
    if (!names || !signer->issuer.data || !signer->serial.length || signer->subject_key_id.data)
      return TC_TLV_ARGUMENT;
    if (tc_pki_work_charge(tree->work,signer->serial.length) != TC_TLV_OK ||
        tc_pki_work_charge(tree->work,certificate->serial.length) != TC_TLV_OK) return TC_TLV_LIMIT;
    /* Both readers require minimal INTEGER contents, including sign padding. */
    if (signer->serial_negative != certificate->serial_negative ||
        !tc_pki_equal(signer->serial,certificate->serial)) { *matched = 0; return TC_TLV_OK; }
    return tc_pki_name_equal(signer->issuer,profile,certificate->issuer,TC_TLV_DER,
        limits,names,tree,matched);
  }
  if (signer->version == 3) {
    TC_bytes ski = {NULL,0};
    if (!signer->subject_key_id.data || signer->issuer.data || signer->serial.length)
      return TC_TLV_ARGUMENT;
    result = tc_pki_subject_key_identifier(certificate,limits,tree->work,&ski);
    if (result != TC_TLV_OK) return result;
    if (!ski.data) { *matched = 0; return TC_TLV_OK; }
    return tc_pki_octets_equal(signer->subject_key_id,0x80,ski,profile,limits,
        tree->frames,tree->capacity,tree->work,matched);
  }
  return TC_TLV_ARGUMENT;
}

#endif
