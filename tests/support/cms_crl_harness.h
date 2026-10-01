/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Test harness declarations: CMS revocation collections and CRL processing.
 * See cms_crl_harness.c. */
#ifndef TC_TEST_CMS_CRL_HARNESS_H_
#define TC_TEST_CMS_CRL_HARNESS_H_
#include <tiny_crypto/cms_validation.h>
#include <tiny_crypto/piv_oid.h>
#include "../../src/cms_internal.h"
#include "x509_crl_harness.h"

typedef struct {
  tc_cms_collection collection;
  const tc_pki_record_source* external;
} tc_cms_revocations;
typedef enum { TC_CMS_REVOCATION_CRL, TC_CMS_REVOCATION_OTHER } tc_cms_revocation_kind;
typedef struct {
  TC_bytes encoded;
  tc_cms_revocation_kind kind;
} tc_cms_revocation_choice;
/* Embedded [1] RevocationInfoChoices followed by external DER CRL records.
 * OtherRevocationInfoFormat receives its OID/value schema check. CRL schema,
 * signature, scope, freshness and trust checks follow selection.
 * Shared record/byte/work bounds and borrowed-storage rules match candidates.
 * Source snapshots and bytes remain stable. Callers check source-record overlap
 * with scratch before parsing. Reader/out change only on OK. Work is provisional. */
TC_TLV_result tc_cms_revocations_init(TC_bytes embedded, const tc_pki_record_source* external,
                                      size_t max_records, size_t max_bytes,
                                      const TC_TLV_limits* limits,
                                      const tc_pki_tree_workspace* tree, tc_cms_revocations* out);
TC_TLV_result tc_cms_revocations_next(tc_cms_revocations* reader, const tc_pki_tree_workspace* tree,
                                      tc_cms_revocation_choice* out);

/* Decode CRL headers and CRL-level extensions once into caller-owned records.
 * Other revocation formats consume traversal bounds and increment other_count.
 * Retain policy failures for selection; malformed schemas/source errors stop
 * indexing. Entry extensions and signatures are checked later during authenticated
 * processing.
 * Index spans borrow stable record bytes. Checks disjoint records, OID/tree
 * scratch, work and output against input/metadata and returned source records.
 * Callers guard any additional writable storage used by subsequent stages.
 * Index/OID scratch and work are provisional. Reader and out remain unchanged
 * on failure. Empty input permits NULL/0 storage. */
TC_TLV_result tc_cms_crl_index_init(const tc_cms_revocations* reader,
                                    const tc_pki_tree_workspace* tree, TC_bytes* oids,
                                    size_t oid_capacity, TC_X509_crl_record* records,
                                    size_t capacity, TC_X509_crl_index* out);
/* Yield each matching X.509 candidate. Other certificate formats are skipped.
 * scratch holds the parsed candidate on OK and may change on any result.
 * Reader advances on OK/END; out changes only on OK. Other failures preserve
 * reader/out, but consume work and may change callback state. */
TC_TLV_result tc_cms_signer_candidate_next(tc_cms_candidates* reader,
                                           const TC_CMS_signer_info* signer, TC_TLV_profile profile,
                                           const TC_X509_name_workspace* names,
                                           const tc_pki_tree_workspace* tree,
                                           const TC_X509_workspace* parser,
                                           TC_X509_certificate* scratch, TC_bytes* out);
/* Select CRL signer candidates by subject, authority hints and cRLSign usage.
 * Same iterator/storage contract as above. Signature, path, scope and freshness
 * checks remain separate. Unsupported authority-name matching is reported. */
TC_TLV_result tc_cms_crl_signer_candidate_next(tc_cms_candidates* reader, const TC_X509_crl* crl,
                                               const TC_X509_crl_extensions* extensions,
                                               const TC_X509_name_workspace* names,
                                               const tc_pki_tree_workspace* tree,
                                               const TC_X509_workspace* parser,
                                               TC_X509_certificate* scratch, TC_bytes* out);
/* CRL signer search with an explicit external store. */
TC_TLV_result tc_cms_crl_source_search(const void* candidates, const TC_X509_store_source* external,
                                       const tc_x509_crl_signer_query* query,
                                       const tc_x509_crl_trust* trust, TC_X509_search_result* out,
                                       int* source_failed);
/* tc_x509_crl_search callback: candidates is a tc_cms_candidates. */
TC_TLV_result tc_cms_crl_search(const void* candidates, const tc_x509_crl_signer_query* query,
                                const tc_x509_crl_trust* trust, TC_X509_search_result* out,
                                int* source_failed);
/* Find a candidate with a valid CRL signature and path to the selected anchor.
 * Candidates remain unchanged. Failed candidate paths do not end the search.
 * Unresolved limits/algorithms are retained if no candidate succeeds. Malformed
 * candidate records and source read errors stop iteration.
 * path_source must provide needed intermediates, including embedded ones, and
 * retain the target certificate's anchor snapshot. Scope/freshness and signer
 * revocation are separate. Parsed inputs/source data are stable and disjoint
 * from all scratch/work/out. Tree and validation may share frame storage.
 * Work covers all attempts, out changes only on VALID and borrows path storage. */
TC_X509_path_status tc_cms_crl_signer_find(const tc_cms_candidates* candidates,
                                           const TC_X509_crl* crl,
                                           const TC_X509_crl_extensions* extensions,
                                           const tc_x509_crl_trust* trust,
                                           TC_X509_search_result* out);
/* Process all indexed scopes for one distribution point. check is required.
 * OK publishes new evidence, which may still have incomplete reason coverage.
 * END means no contribution or terminal input evidence. Failures preserve
 * evidence. Scratch is provisional. Invalid/unsupported alternatives are tried
 * until status is determined, otherwise their failure is returned. LIMIT and
 * source errors stop processing. Inputs/source snapshot remain stable.
 * Records sharing issuer and IDP are ranked across validated signer keys.
 * The check callback performs the signer revocation work. */
TC_TLV_result tc_cms_crl_point_process(const tc_cms_candidates* candidates,
                                       const tc_x509_crl_scope_processing* processing,
                                       const tc_x509_crl_trust* trust);
/* Process an encoded CRLDistributionPoints value, then query->point as fallback
 * if coverage is incomplete. An absent value uses only the fallback. The caller
 * supplies the target's validated CA flag and an issuer-wide fallback point.
 * The whole list is checked before processing. Same storage, callback and
 * transactional evidence rules as point_process. One budget covers all points. */
TC_TLV_result tc_cms_crl_points_process(const tc_cms_candidates* candidates,
                                        const tc_x509_crl_scope_processing* processing,
                                        TC_bytes points, const tc_x509_crl_trust* trust);
/* Read BasicConstraints, CRLDistributionPoints and issuerAltName from a target
 * whose path has already been validated to anchor_index. Try listed points,
 * then issuer DN and alternative names while coverage remains incomplete.
 * Extension uniqueness/framing and relevant values are checked here; other
 * extension policy belongs to path validation. Same rules as points_process. */
TC_TLV_result tc_cms_crl_certificate_process(const tc_cms_candidates* candidates,
                                             const tc_x509_crl_scope_processing* processing,
                                             const TC_X509_certificate* certificate,
                                             const tc_x509_crl_trust* trust);
typedef struct {
  const tc_cms_candidates* candidates;
  const TC_X509_crl_index* index;
  const TC_X509_store_source* source;
  const TC_X509_path_options* options;
  size_t anchor_index;
  TC_X509_crl_delta_policy delta_policy;
  TC_X509_crl_order_policy order_policy;
} tc_cms_crl_resolution;
/* Resolve a previously validated target's revocation and signer dependencies.
 * options specify CRL signer policy, including the signer's EKU/purpose.
 * Sources, policy and time stay fixed. Nodes borrow certificate encodings and
 * are provisional scratch. One shared budget covers all retries without recursion.
 * OK publishes a determined status. Ungrounded cycles/missing evidence return
 * UNSUPPORTED. Every failure preserves out. All input/output/scratch disjoint. */
TC_TLV_result tc_cms_crl_resolve(const TC_X509_certificate* target,
                                 const tc_cms_crl_resolution* resolution,
                                 const tc_x509_crl_resolution_workspace* workspace,
                                 TC_X509_crl_evidence* out);
/* Check a previously validated path, anchor-issued first, target last.
 * The anchor is excluded. Hold chain spans outside search/validation scratch.
 * A revoked member supplies its index and evidence; an unrevoked path reports
 * SIZE_MAX and zero evidence. All members share one budget and source snapshot.
 * Nodes retain proven dependencies across the members of one call. Capacity
 * must cover the path and all distinct signer dependencies visited during it.
 * Resolution policy and disjoint storage rules match tc_cms_crl_resolve.
 * Failure preserves out; OK reports REVOKED or UNREVOKED, never UNDETERMINED. */
TC_TLV_result tc_cms_crl_path_resolve(const TC_bytes* chain, size_t count,
                                      const tc_cms_crl_resolution* resolution,
                                      const tc_x509_crl_resolution_workspace* workspace,
                                      TC_X509_revocation_result* out);
/* Find a trusted signer for the reference CRL, then select/apply its scope.
 * The reference may be complete or delta; its signature identifies the signer.
 * Scopes with no new reason coverage return END before signer discovery.
 * State storage needs one byte per indexed CRL and is reset for each signer.
 * Reference verification is reused during selection. Evidence/out change only
 * on OK. States and other scratch are provisional. Preflight checks metadata,
 * used input spans and writable ranges. Source records are guarded on return.
 * Opaque source/provider contexts must remain separate from writable storage.
 * Tree/path frames may share an array. Partial overlaps are rejected.
 * Candidate/index views stay unchanged. Signer-path revocation is separate. */
TC_TLV_result tc_cms_crl_scope_process(const tc_cms_candidates* candidates,
                                       const tc_x509_crl_scope_processing* processing,
                                       const tc_x509_crl_trust* trust, TC_X509_search_result* out);
#endif
