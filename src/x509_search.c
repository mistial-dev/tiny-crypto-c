/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509_path.h>
#if TC_ENABLE_X509_PATH
#include "x509_path_internal.h"
#include "pki_storage_internal.h"
#include "pki_source_internal.h"
#include <string.h>

static TC_TLV_result search_read(TC_bytes encoded, const TC_X509_path_options* options,
                                 const TC_X509_path_workspace* workspace, size_t* work,
                                 TC_X509_certificate* out)
{
  TC_X509_workspace parser = {workspace->frames, workspace->frame_capacity, workspace->oids,
                              workspace->oid_capacity};
  if (tc_pki_work_charge(work, encoded.length) != TC_TLV_OK)
    return TC_TLV_LIMIT;
  return TC_X509_read(encoded.data, encoded.length, &options->parsing, &parser, out);
}

/* Read only the fixed TBSCertificate prefix needed to locate the subject.
 * Any framing error falls back to the full parser, which owns error status. */
static TC_TLV_result search_subject(TC_bytes encoded, const TC_TLV_limits* limits,
                                    TC_bytes* subject)
{
  TC_TLV_element element;
  TC_TLV_reader outer, tbs;
  TC_TLV_result result;
  if (limits->max_depth < 3 || limits->max_elements < 8)
    return TC_TLV_LIMIT;
  result = TC_TLV_read(encoded.data, encoded.length, TC_TLV_DER, limits, &element);
  if (result != TC_TLV_OK)
    return result;
  if (element.header.tag_length != 1 || element.header.tag[0] != 0x30 ||
      element.encoded.length != encoded.length)
    return TC_TLV_INVALID;
  result = TC_TLV_reader_init(&outer, element.value.data, element.value.length, TC_TLV_DER, limits);
  if (result != TC_TLV_OK)
    return result;
  result = TC_TLV_next(&outer, &element);
  if (result != TC_TLV_OK)
    return result;
  if (element.header.tag_length != 1 || element.header.tag[0] != 0x30)
    return TC_TLV_INVALID;
  result = TC_TLV_reader_init(&tbs, element.value.data, element.value.length, TC_TLV_DER, limits);
  if (result != TC_TLV_OK)
    return result;
  result = TC_TLV_next(&tbs, &element);
  if (result != TC_TLV_OK)
    return result;
  if (element.header.tag_length == 1 && element.header.tag[0] == 0xa0) {
    result = TC_TLV_next(&tbs, &element);
    if (result != TC_TLV_OK)
      return result;
  }
  if (element.header.tag_length != 1 || element.header.tag[0] != 0x02)
    return TC_TLV_INVALID;
  for (unsigned field = 0; field < 4; ++field) {
    result = TC_TLV_next(&tbs, &element);
    if (result != TC_TLV_OK)
      return result;
    if (element.header.tag_length != 1 || element.header.tag[0] != 0x30)
      return TC_TLV_INVALID;
  }
  *subject = element.encoded;
  return TC_TLV_OK;
}

static TC_X509_path_status source_status(TC_TLV_result status, size_t before, size_t* work)
{
  if (*work > before) {
    *work = 0;
    return TC_X509_PATH_ERROR;
  }
  if (status == TC_TLV_OK)
    return TC_X509_PATH_VALID;
  if (status == TC_TLV_LIMIT)
    return TC_X509_PATH_LIMIT;
  if (status == TC_TLV_UNSUPPORTED)
    return TC_X509_PATH_UNSUPPORTED;
  return TC_X509_PATH_ERROR;
}

TC_X509_path_status tc_x509_path_search_source(TC_bytes target, const tc_x509_search_source* source,
                                               const TC_X509_path_options* options,
                                               const TC_X509_path_workspace* validation,
                                               const tc_x509_search_workspace* search, size_t* work,
                                               tc_x509_search_result* out)
{
  TC_X509_certificate issuer;
  TC_X509_path_status failure = TC_X509_PATH_INVALID, status;
  TC_TLV_result parsed;
  size_t depth = 1, capacity, initial_work;
  if (!source || !options || !validation || !search || !work || !out ||
      (source->candidate_count && !source->candidate) ||
      (source->anchor_count && !source->anchor) ||
      (search->capacity && (!search->path || !search->frames)))
    return TC_X509_PATH_ERROR;
  capacity =
      search->capacity < options->max_certificates ? search->capacity : options->max_certificates;
  if (!capacity)
    return TC_X509_PATH_LIMIT;
  if (!source->anchor_count)
    return TC_X509_PATH_INVALID;
  initial_work = *work;
  if (target.length > options->max_input)
    return TC_X509_PATH_LIMIT;
  parsed = search_read(target, options, validation, work, &issuer);
  if (parsed != TC_TLV_OK)
    return tc_x509_path_status(parsed);
  search->path[capacity - 1] = target;
  search->frames[0] = (tc_x509_search_frame){0, 0, target.length, issuer.issuer};
  while (depth) {
    tc_x509_search_frame* frame = &search->frames[depth - 1];
    TC_bytes* path = search->path + capacity - depth;
    int equal;
    if (tc_pki_work_charge(work, 1) != TC_TLV_OK)
      return TC_X509_PATH_LIMIT;
    if (frame->anchor < source->anchor_count) {
      size_t anchor = frame->anchor++;
      size_t before = *work;
      tc_x509_search_anchor trust = {0};
      tc_x509_search_result found;
      parsed = source->anchor(source->context, anchor, work, &trust);
      status = source_status(parsed, before, work);
      if (status != TC_X509_PATH_VALID)
        return status;
      if (!trust.trust.name.data || !trust.trust.name.length)
        return TC_X509_PATH_ERROR;
      parsed = TC_X509_name_equal(frame->issuer, trust.trust.name, &options->parsing,
                                  &validation->names, work, &equal);
      if (parsed != TC_TLV_OK) {
        if (parsed == TC_TLV_ARGUMENT)
          return TC_X509_PATH_ERROR;
        tc_x509_path_remember(tc_x509_path_status(parsed), &failure);
        continue;
      }
      if (!equal)
        continue;
      status = tc_x509_path_validate_anchor(path, depth, &trust, options, validation, work,
                                            &found.validation);
      if (status == TC_X509_PATH_VALID) {
        found.path = path;
        found.count = depth;
        found.anchor_index = anchor;
        found.validation.work_used = initial_work - *work;
        *out = found;
        return status;
      }
      if (status == TC_X509_PATH_ERROR)
        return status;
      tc_x509_path_remember(status, &failure);
    } else if (frame->candidate < source->candidate_count) {
      TC_bytes candidate = {NULL, 0};
      TC_bytes subject;
      int subject_checked = 0;
      size_t i, before = *work;
      parsed = source->candidate(source->context, frame->candidate++, work, &candidate);
      status = source_status(parsed, before, work);
      if (status != TC_X509_PATH_VALID)
        return status;
      if (!candidate.data || !candidate.length)
        return TC_X509_PATH_ERROR;
      /* Compare encodings, not entry IDs: duplicate records must not form cycles. */
      for (i = 0; i < depth; ++i) {
        if (tc_pki_work_charge(work, 1) != TC_TLV_OK)
          return TC_X509_PATH_LIMIT;
        if (candidate.length != path[i].length)
          continue;
        if (tc_pki_work_charge(work, candidate.length) != TC_TLV_OK)
          return TC_X509_PATH_LIMIT;
        if (!candidate.length || !memcmp(candidate.data, path[i].data, candidate.length))
          break;
      }
      if (i != depth)
        continue;
      if (search_subject(candidate, &options->parsing, &subject) == TC_TLV_OK) {
        parsed = TC_X509_name_equal(frame->issuer, subject, &options->parsing, &validation->names,
                                    work, &equal);
        if (parsed != TC_TLV_OK) {
          if (parsed == TC_TLV_ARGUMENT)
            return TC_X509_PATH_ERROR;
          tc_x509_path_remember(tc_x509_path_status(parsed), &failure);
          continue;
        }
        if (!equal)
          continue;
        subject_checked = 1;
      }
      parsed = search_read(candidate, options, validation, work, &issuer);
      if (parsed != TC_TLV_OK) {
        if (parsed == TC_TLV_ARGUMENT)
          return TC_X509_PATH_ERROR;
        tc_x509_path_remember(tc_x509_path_status(parsed), &failure);
        continue;
      }
      if (!subject_checked) {
        parsed = TC_X509_name_equal(frame->issuer, issuer.subject, &options->parsing,
                                    &validation->names, work, &equal);
        if (parsed != TC_TLV_OK) {
          if (parsed == TC_TLV_ARGUMENT)
            return TC_X509_PATH_ERROR;
          tc_x509_path_remember(tc_x509_path_status(parsed), &failure);
          continue;
        }
        if (!equal)
          continue;
      }
      if (depth == capacity || candidate.length > options->max_input - frame->bytes) {
        failure = TC_X509_PATH_LIMIT;
        continue;
      }
      path[-1] = candidate;
      search->frames[depth++] =
          (tc_x509_search_frame){0, 0, frame->bytes + candidate.length, issuer.issuer};
    } else {
      --depth;
    }
  }
  return failure;
}

typedef struct {
  const TC_bytes* candidates;
  const TC_X509_trust_anchor* anchors;
} array_source;

enum {
  SEARCH_PATH_WRITE = TC_X509_PATH_STORAGE_COUNT,
  SEARCH_FRAMES_WRITE,
  SEARCH_RESULT_WRITE,
  SEARCH_WORK_WRITE,
  SEARCH_WRITE_COUNT
};
TC_X509_path_status tc_x509_path_build_work(TC_bytes target, const TC_X509_store_source* source,
                                            const TC_X509_path_options* options,
                                            const TC_X509_path_workspace* validation,
                                            const TC_X509_search_workspace* search, size_t* work,
                                            TC_X509_search_result* out)
{
  TC_bytes writes[SEARCH_WRITE_COUNT];
  tc_pki_source_guard checked = {source, writes, SEARCH_WRITE_COUNT};
  TC_X509_store_source guarded;
  TC_TLV_result result;
  size_t initial_work;
  if (!source || !options || !validation || !search || !work || !out ||
      (options->flags & ~(unsigned)TC_X509_PATH_SUPPORTED_FLAGS) ||
      (source->candidate_count && !source->candidate) || (source->anchor_count && !source->anchor))
    return TC_X509_PATH_ERROR;
  initial_work = *work;
  {
    tc_pki_storage_plan plan;
    /* Preflight uses private bookkeeping: work may itself alias an input. */
    tc_pki_storage_plan_begin(&plan, writes, SEARCH_WRITE_COUNT, *work);
    tc_x509_path_storage_plan(&plan, validation);
    TC_PKI_PLAN_WRITE(&plan, search->path, search->capacity);
    TC_PKI_PLAN_WRITE(&plan, search->frames, search->capacity);
    TC_PKI_PLAN_WRITE(&plan, out, 1);
    TC_PKI_PLAN_WRITE(&plan, work, 1);
    tc_pki_storage_plan_seal(&plan);
    TC_PKI_PLAN_INPUT(&plan, source, 1);
    TC_PKI_PLAN_INPUT(&plan, options, 1);
    TC_PKI_PLAN_INPUT(&plan, validation, 1);
    TC_PKI_PLAN_INPUT(&plan, search, 1);
    tc_pki_storage_plan_input_span(&plan, target);
    tc_x509_path_options_plan_inputs(&plan, options);
    result = tc_pki_storage_plan_finish(&plan, work);
    if (result != TC_TLV_OK)
      return tc_x509_path_status(result);
  }
  guarded = tc_pki_source_guard_bind(&checked);
  {
    TC_X509_path_status status =
        tc_x509_path_search_source(target, &guarded, options, validation, search, work, out);
    if (status == TC_X509_PATH_VALID)
      out->validation.work_used = initial_work - *work;
    return status;
  }
}

TC_X509_path_status TC_X509_path_build(TC_bytes target, const TC_X509_store_source* source,
                                       const TC_X509_path_options* options,
                                       const TC_X509_path_workspace* validation,
                                       const TC_X509_search_workspace* search,
                                       TC_X509_search_result* out)
{
  size_t work;
  if (!options)
    return TC_X509_PATH_ERROR;
  work = options->max_work;
  return tc_x509_path_build_work(target, source, options, validation, search, &work, out);
}

static TC_TLV_result array_candidate(void* context, size_t index, size_t* work, TC_bytes* out)
{
  const array_source* source = context;
  (void)work;
  *out = source->candidates[index];
  return TC_TLV_OK;
}

static TC_TLV_result array_anchor(void* context, size_t index, size_t* work,
                                  tc_x509_search_anchor* out)
{
  const array_source* source = context;
  (void)work;
  out->trust = source->anchors[index];
  out->names = (TC_X509_name_constraints){{NULL, 0}, {NULL, 0}};
  return TC_TLV_OK;
}

TC_X509_path_status tc_x509_path_search(TC_bytes target, const TC_bytes* candidates,
                                        size_t candidate_count, const TC_X509_trust_anchor* anchors,
                                        size_t anchor_count, const TC_X509_path_options* options,
                                        const TC_X509_path_workspace* validation,
                                        const tc_x509_search_workspace* search, size_t* work,
                                        tc_x509_search_result* out)
{
  array_source arrays = {candidates, anchors};
  tc_x509_search_source source = {&arrays, candidate_count, anchor_count, array_candidate,
                                  array_anchor};
  if ((candidate_count && !candidates) || (anchor_count && !anchors))
    return TC_X509_PATH_ERROR;
  return tc_x509_path_search_source(target, &source, options, validation, search, work, out);
}
#endif
