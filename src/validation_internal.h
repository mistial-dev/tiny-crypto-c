/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_VALIDATION_INTERNAL_H_
#define TC_VALIDATION_INTERNAL_H_
#include <tiny_crypto/validation.h>
#include "x509_path_internal.h"

enum { TC_VALIDATION_WRITES = TC_X509_PATH_STORAGE_COUNT + 10 };
TC_credential_status tc_validation_status(TC_TLV_result status);
/* Validation storage preflight. The two plan steps let a caller add its own
 * writes before seal and its own inputs after it. tc_validation_storage runs
 * the common sequence and commits the remaining work on success. */
void tc_validation_plan_writes(tc_pki_storage_plan* plan,
    const TC_validation_context* context, size_t* work, void* out, size_t out_size);
void tc_validation_plan_inputs(tc_pki_storage_plan* plan,
    const TC_validation_context* context, const TC_bytes* inputs, size_t input_count);
TC_TLV_result tc_validation_storage(const TC_validation_context* context,
    const TC_bytes* inputs, size_t input_count, size_t* work,
    void* out, size_t out_size, TC_bytes writes[TC_VALIDATION_WRITES]);

/* Adapt shared execution settings to the path and revocation engines. */
int tc_validation_policies(const TC_validation_context* context,
    TC_CMS_path_options* cms, TC_X509_path_options* crl,
    TC_CMS_revocation_policy* revocation);
#endif
