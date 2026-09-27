/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Shared RSA argument checks. Each helper checks that workspace words are
 * aligned, that scratch and output are disjoint from each other and from the
 * borrowed inputs, and returns TC_RSA_ARGUMENT for invalid storage. */
#ifndef TC_RSA_INPUTS_INTERNAL_H_
#define TC_RSA_INPUTS_INTERNAL_H_
#include <tiny_crypto/rsa.h>
#include "pki_storage_internal.h"

/* Maps a sealed plan's final status to an RSA result. */
TC_RSA_result tc_rsa_storage_status(const tc_pki_storage_plan* plan);

/* Workspace only. Inputs must stay clear of scratch. */
TC_RSA_result tc_rsa_workspace_inputs(const TC_RSA_workspace* workspace,
    const TC_bytes* inputs, size_t count);

/* Workspace and output: both are written, so neither may overlap an input. */
TC_RSA_result tc_rsa_output_inputs(const TC_RSA_workspace* workspace,
    const TC_bytes* inputs, size_t count, TC_bytes output);

/* Two caller control structures (key, options) against workspace and output. */
TC_RSA_result tc_rsa_control_inputs(const TC_RSA_workspace* workspace,
    TC_bytes output, const void* first, size_t first_size,
    const void* second, size_t second_size);

/* Public key plus up to two message spans. */
TC_RSA_result tc_rsa_public_inputs(const TC_RSA_public_key* key,
    TC_bytes first, TC_bytes second, TC_bytes output, const TC_RSA_workspace* workspace);

/* Private key and digest. Also rejects empty or oversized d, p and q. */
TC_RSA_result tc_rsa_private_inputs(const TC_RSA_private_key* key,
    TC_bytes digest, TC_bytes output, const TC_RSA_workspace* workspace);

/* CRT parameters. Rejects values longer than a prime after leading zeros. */
TC_RSA_result tc_rsa_crt_inputs(const TC_RSA_private_key* key,
    const TC_RSA_crt* crt, TC_bytes output, const TC_RSA_workspace* workspace);

#endif
