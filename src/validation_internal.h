/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_VALIDATION_INTERNAL_H_
#define TC_VALIDATION_INTERNAL_H_
#include <tiny_crypto/validation.h>
#include "cms_internal.h"

static inline int tc_validation_revocation_valid(TC_validation_revocation revocation)
{
  return revocation == TC_VALIDATION_REVOCATION_REQUIRED ||
         revocation == TC_VALIDATION_REVOCATION_WHEN_AVAILABLE;
}

/* Credential workspace writes plus work and the caller's result. */
enum { TC_VALIDATION_WRITES = TC_CMS_CREDENTIAL_WORKSPACE_WRITES + 2 };
TC_credential_status tc_validation_status(TC_TLV_result status);
/* Validation storage preflight. The two plan steps let a caller add its own
 * writes before seal and its own inputs after it. tc_validation_storage runs
 * the common sequence and commits the remaining work on success. */
void tc_validation_plan_writes(tc_pki_storage_plan* plan, const TC_validation_context* context,
                               size_t* work, void* out, size_t out_size);
void tc_validation_plan_inputs(tc_pki_storage_plan* plan, const TC_validation_context* context,
                               const TC_bytes* inputs, size_t input_count);
TC_TLV_result tc_validation_storage(const TC_validation_context* context, const TC_bytes* inputs,
                                    size_t input_count, size_t* work, void* out, size_t out_size,
                                    TC_bytes writes[TC_VALIDATION_WRITES]);

/* The revocation evidence rule of a context whose policies were adapted by
 * tc_validation_policies. checked may be NULL. */
tc_cms_revocation_evidence tc_validation_evidence(const TC_validation_context* context,
                                                  uint8_t* checked);

/* Adapt shared execution settings to the path and revocation engines. Returns
 * 0 for an incomplete context or an unknown revocation policy. */
int tc_validation_policies(const TC_validation_context* context, TC_CMS_path_options* cms,
                           TC_X509_path_options* crl, TC_CMS_revocation_policy* revocation);
#endif
