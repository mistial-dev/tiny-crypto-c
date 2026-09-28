/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_PKI_READER_INTERNAL_H_
#define TC_PKI_READER_INTERNAL_H_
#include "pki_storage_internal.h"
#include "x509_path_internal.h"

enum {
  TC_PKI_READER_RANGES = 5,
  TC_PKI_READER_STORAGE_WORK = TC_PKI_READER_RANGES * (TC_PKI_READER_RANGES - 1) / 2
};

/* Reader storage: every range, including read-only ones, is kept disjoint
 * from every other range, so all of them are recorded as writes. */
static inline TC_TLV_result tc_pki_reader_storage_check(TC_bytes encoded, const void* metadata,
                                                        size_t metadata_size, TC_TLV_frame* frames,
                                                        size_t frame_capacity, size_t* work,
                                                        void* out, size_t out_size)
{
  TC_bytes ranges[TC_PKI_READER_RANGES];
  tc_pki_storage_plan plan;
  if (!metadata || !work || !out)
    return TC_TLV_ARGUMENT;
  tc_pki_storage_plan_begin(&plan, ranges, TC_PKI_READER_RANGES, SIZE_MAX);
  tc_pki_storage_plan_write_span(&plan, encoded);
  tc_pki_storage_plan_write(&plan, metadata, 1, metadata_size);
  TC_PKI_PLAN_WRITE(&plan, frames, frame_capacity);
  TC_PKI_PLAN_WRITE(&plan, work, 1);
  tc_pki_storage_plan_write(&plan, out, out_size, 1);
  /* Check the work pointer before charging the caller's budget. */
  tc_pki_storage_plan_seal(&plan);
  return tc_pki_storage_plan_finish(&plan, NULL);
}

static inline TC_TLV_result tc_pki_reader_storage(TC_bytes encoded, const TC_TLV_limits* limits,
                                                  TC_TLV_frame* frames, size_t frame_capacity,
                                                  size_t* work, void* out, size_t out_size)
{
  TC_TLV_result result = tc_pki_reader_storage_check(encoded, limits, sizeof *limits, frames,
                                                     frame_capacity, work, out, out_size);
  return result == TC_TLV_OK ? tc_pki_work_charge(work, TC_PKI_READER_STORAGE_WORK) : result;
}

static inline TC_TLV_result tc_pki_reader_workspace_storage(TC_bytes encoded,
                                                            const TC_TLV_limits* limits,
                                                            const TC_X509_workspace* workspace,
                                                            size_t* work, void* out,
                                                            size_t out_size)
{
  TC_bytes ranges[7];
  tc_pki_storage_plan plan;
  if (!limits || !workspace || !work || !out)
    return TC_TLV_ARGUMENT;
  tc_pki_storage_plan_begin(&plan, ranges, 7, SIZE_MAX);
  tc_pki_storage_plan_write_span(&plan, encoded);
  TC_PKI_PLAN_WRITE(&plan, limits, 1);
  TC_PKI_PLAN_WRITE(&plan, workspace, 1);
  TC_PKI_PLAN_WRITE(&plan, workspace->frames, workspace->frame_capacity);
  TC_PKI_PLAN_WRITE(&plan, workspace->extension_oids, workspace->extension_capacity);
  TC_PKI_PLAN_WRITE(&plan, work, 1);
  tc_pki_storage_plan_write(&plan, out, out_size, 1);
  tc_pki_storage_plan_seal(&plan);
  TC_TLV_result result = tc_pki_storage_plan_finish(&plan, NULL);
  return result == TC_TLV_OK ? tc_pki_work_charge(work, tc_pki_storage_plan_used(&plan)) : result;
}
#endif
