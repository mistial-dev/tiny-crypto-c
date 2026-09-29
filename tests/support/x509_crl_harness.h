/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Test harness: X.509 CRL and path-search entry points that the library does
 * not call itself. Each wraps library functions, so tests can drive CRL
 * selection, matching and signer checks without shipping the wrappers. */
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

/* Process selected CRLs for one distribution point and proposed signer.
 * Checks effective freshness/scope, both signatures and the signer path to the
 * target certificate's anchor, then accumulates reasons and resolved entries.
 * A delta supplies the effective update times (RFC 5280 5.2.4).
 * END means no new eligible reasons or an already determined status.
 * options hold signer policy; certificate_ca is the target's validated cA.
 * Signer-path revocation is separate. The source is the target path's held
 * snapshot. Inputs, scratch, work, evidence and out are disjoint; parsed views
 * must match unchanged encodings. Evidence/out change only on OK. Scratch/work
 * are provisional. out borrows the signer path and records total work used. */
TC_TLV_result tc_x509_crl_process(const tc_x509_crl_selected* selected,
                                  const TC_X509_certificate* signer, const tc_x509_crl_query* query,
                                  const tc_x509_crl_trust* trust, TC_X509_crl_evidence* evidence,
                                  TC_X509_search_result* out);

/* Check pairing, authenticate both CRLs with one signer's key, then resolve
 * their entries. Omit both delta pointers for a complete CRL alone. The caller
 * must establish signer trust, freshness and scope before using this result.
 * Parsed inputs and scratch/output are disjoint. Output changes only on OK.
 * Work and scratch are consumed on failure. */
TC_TLV_result tc_x509_crl_selected_find(const tc_x509_crl_selected* selected,
                                        const TC_X509_certificate* signer,
                                        const TC_X509_certificate* certificate,
                                        const TC_X509_signature_provider* provider,
                                        const tc_x509_crl_decode* decode, TC_X509_crl_match* out);

/* Check pair compatibility, signatures under one key, and the signer's path to
 * the target anchor. Entries, scope, CRL freshness and signer-path revocation
 * are separate checks. Parsed inputs and writable storage are
 * disjoint. Work/scratch are provisional. out changes only on OK and borrows
 * the signer path. Source records remain stable for the operation. */
TC_TLV_result tc_x509_crl_selected_validate(const tc_x509_crl_selected* selected,
                                            const TC_X509_certificate* signer,
                                            const tc_x509_crl_trust* trust,
                                            TC_X509_search_result* out);

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

/* Caller validates the index, base, query and trust before candidate search.
 * Establish the signer path before selecting and applying a delta CRL. */
TC_TLV_result tc_x509_crl_index_attempt(const void* context, const TC_X509_certificate* signer,
                                        const tc_x509_crl_trust* trust, TC_X509_search_result* out);

TC_TLV_result tc_x509_crl_process_candidate(const void* context,
                                            const TC_X509_certificate* candidate,
                                            const tc_x509_crl_trust* trust,
                                            TC_X509_search_result* out);

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

/* Candidate certificates and trust anchors held in caller arrays. */
typedef struct {
  const TC_bytes* candidates;
  size_t candidate_count;
  const TC_X509_trust_anchor* anchors;
  size_t anchor_count;
} tc_x509_path_arrays;
/* Internal engine: caller validates storage ranges and keeps input/store records
 * stable and disjoint from both workspaces, work, and out. Path storage is scratch.
 * Successful output borrows its suffix in anchor-issued-first order. */
TC_X509_path_status tc_x509_path_search(TC_bytes target, const tc_x509_path_arrays* arrays,
                                        const TC_X509_path_options* options,
                                        const TC_X509_path_workspace* validation,
                                        const TC_X509_search_workspace* search, size_t* work,
                                        TC_X509_search_result* out);
TC_TLV_result tc_x509_crl_scope_apply(const tc_x509_crl_scope_context* scope, size_t reference,
                                      const tc_x509_crl_query* query,
                                      TC_X509_crl_evidence* evidence);
#endif
