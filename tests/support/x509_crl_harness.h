/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Test harness: thin accessors over X.509 CRL internals that the library does
 * not call itself. Each forwards to one library function, so tests can reach
 * entry matching, signer checks and extension schemas without shipping the
 * wrappers. CRL processing tests use the production scope executor. */
#ifndef TC_TEST_X509_CRL_HARNESS_H_
#define TC_TEST_X509_CRL_HARNESS_H_
#include <tiny_crypto/x509.h>
#include <tiny_crypto/x509_path.h>
#include <string.h>
#include "../../src/internal.h"
#include "../../src/pki_internal.h"
#include "../../src/pki_extensions_internal.h"
#include "../../src/pki_identifier_internal.h"
#include "../../src/pki_signature_internal.h"
#include "../../src/pki_source_internal.h"
#include "../../src/pki_spans_internal.h"
#include "../../src/pki_status_internal.h"
#include "../../src/pki_storage_internal.h"
#include "../../src/x509_crl_internal.h"
#include "../../src/x509_crl_source_internal.h"
#include "../../src/x509_path_internal.h"
#include "../../src/x509_revocation_internal.h"
#include "../../src/x509_time_internal.h"

/* Match parsed serial/issuer fields against a resolved entry. Explicit issuer
 * DNs require the certificate's encoding (5.3.3); the default issuer uses Name
 * comparison. Output changes only on OK. Inputs and scratch are disjoint. */
TC_TLV_result tc_x509_crl_entry_matches(const tc_x509_crl_revoked_entry* entry,
                                        const TC_X509_certificate* certificate,
                                        const TC_TLV_limits* limits,
                                        const tc_pki_tree_workspace* tree,
                                        const TC_X509_name_workspace* names, int* matched);

/* Digest covers the exact source TBS encoding. Check issuer linkage, cRLSign,
 * algorithm/key restrictions and signature. Signer trust and CRL scope follow. */
TC_X509_signature_result tc_x509_crl_signer_digest_check(
    const TC_X509_crl* crl, TC_hash_algorithm hash, TC_bytes digest,
    const TC_X509_certificate* signer, const TC_X509_signature_provider* provider,
    const TC_TLV_limits* limits, const TC_X509_name_workspace* names, size_t* work);

/* Candidate callbacks borrow validated search state for the whole attempt. */
TC_TLV_result tc_x509_crl_check_signer(const void* context, const TC_X509_certificate* candidate,
                                       const tc_x509_crl_trust* trust, TC_X509_search_result* out);

/* candidates points to a guarded store cursor snapshot, reused across searches. */
TC_TLV_result tc_x509_crl_store_search(const void* candidates,
                                       const tc_x509_crl_signer_query* query,
                                       const tc_x509_crl_trust* trust, TC_X509_search_result* out,
                                       int* source_failed);

/* Copy matches after the complete entry scan. Signature, signer trust, freshness
 * and CRL applicability must also succeed before a credential verdict is issued. */
TC_TLV_result tc_x509_crl_source_scan_finish(const tc_x509_crl_source_scan* scan,
                                             TC_X509_crl_match* out, size_t capacity);

TC_TLV_result tc_x509_crl_latest_number(const tc_x509_crl_scope_context* scope, size_t reference,
                                        TC_bytes* out);

/* Check CRL and entry extension wrappers, embedded DER, and duplicate OIDs.
 * Checks numbers, reasons, dates, AKIDs, issuer names and issuing distribution points.
 * Reuses OID scratch per list. Critical flags, cross-field rules and other
 * extension semantics remain separate from this structural check. */
TC_TLV_result tc_x509_crl_extensions_check(const TC_X509_crl* crl, const TC_TLV_limits* limits,
                                           const tc_pki_tree_workspace* tree, TC_bytes* oids,
                                           size_t capacity);

#endif
