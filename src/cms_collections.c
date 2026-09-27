/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * CMS certificate and revocation collections: readers, the CRL index and
 * candidate search over embedded and external sources. */
#include <tiny_crypto/cms_validation.h>
#include <tiny_crypto/piv_oid.h>
#if TC_ENABLE_CMS_VALIDATION
#include "cms_internal.h"

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

tc_pki_store_candidates tc_cms_store_cursor(const tc_cms_candidates* source)
{
  return (tc_pki_store_candidates){source->external,source->collection.embedded.limits,
    source->collection.external_index,source->collection.remaining,source->collection.bytes_left};
}

/* Each search owns its cursor; certificate bytes remain borrowed from the source. */
static tc_pki_candidate_next cms_candidate_cursor_init(const tc_cms_candidates* source,
    cms_candidate_cursor* storage, void** cursor)
{
  if (source->external && tc_pki_end(&source->collection.embedded)) {
    storage->store = tc_cms_store_cursor(source);
    *cursor = &storage->store;
    return tc_pki_store_candidate_next;
  }
  storage->collection = *source;
  *cursor = &storage->collection;
  return cms_next_candidate;
}

TC_TLV_result tc_cms_certificate_search(const tc_cms_candidates* candidates,
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

TC_TLV_result tc_cms_crl_source_search(const void* candidates, const TC_X509_store_source* external,
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

TC_TLV_result tc_cms_crl_search(const void* candidates,
    const tc_x509_crl* crl, const tc_x509_crl_extension_info* extensions,
    const tc_x509_crl_trust* trust, tc_x509_crl_attempt attempt, const void* context,
    TC_X509_search_result* out, int* source_failed)
{
  const tc_cms_candidates* source = candidates;
  if (!source) return TC_TLV_ARGUMENT;
  return tc_cms_crl_source_search(source,source->external,crl,extensions,trust,attempt,context,out,source_failed);
}

#endif
