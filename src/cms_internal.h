/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_CMS_INTERNAL_H_
#define TC_CMS_INTERNAL_H_
#include <tiny_crypto/cms_validation.h>
#include "cms_base_internal.h"
#include "pki_tree_internal.h"
#include "pki_source_internal.h"
#include "x509_revocation_internal.h"
#include "pki_candidate_internal.h"

typedef enum { TC_CMS_OTHER_CERTIFICATE, TC_CMS_OTHER_REVOCATION } tc_cms_other_kind;
typedef struct {
  TC_bytes format, value;
} tc_cms_other_format;
/* RFC 5652 OtherCertificateFormat/OtherRevocationInfoFormat, implicitly tagged.
 * The value is required and retained verbatim. Format-specific validation is
 * the application's responsibility. Input/scratch/out must be disjoint;
 * spans borrow input and out changes only on OK. */
TC_TLV_result tc_cms_other_format_read(TC_bytes encoded, tc_cms_other_kind kind,
                                       const TC_TLV_limits* limits,
                                       const tc_pki_tree_workspace* tree, tc_cms_other_format* out);

/* Match parsed SignerInfo and certificate views. Inputs must come from their
 * schema readers. A match identifies a candidate. Trust validation is separate.
 * Missing SKI is a mismatch. Callers preflight disjoint input metadata/spans,
 * name/tree scratch and matched. matched changes only on OK. */
TC_TLV_result tc_cms_signer_matches(const TC_CMS_signer_info* signer, TC_TLV_profile profile,
                                    const TC_X509_certificate* certificate,
                                    const TC_TLV_limits* limits,
                                    const TC_X509_name_workspace* names,
                                    const tc_pki_tree_workspace* tree, int* matched);

typedef struct {
  TC_TLV_reader embedded;
  size_t external_index, remaining, bytes_left;
} tc_cms_collection;
typedef struct {
  tc_cms_collection collection;
  const TC_X509_store_source* external;
} tc_cms_candidates;
typedef struct {
  TC_bytes encoded;
  tc_cms_certificate_kind kind;
} tc_cms_certificate_choice;
/* Shared bounded traversal of an embedded [tag] SET followed by external
 * records. Record, byte and work bounds cover both parts. out and reader
 * change only on OK. embedded reports whether the element came from the SET. */
TC_TLV_result tc_cms_collection_init(TC_bytes embedded, unsigned tag, size_t max_records,
                                     size_t max_bytes, const TC_TLV_limits* limits,
                                     const tc_pki_tree_workspace* tree, tc_cms_collection* out);
TC_TLV_result tc_cms_collection_next(tc_cms_collection* reader,
                                     const tc_pki_record_source* external,
                                     const tc_pki_tree_workspace* tree, TC_TLV_element* out,
                                     int* embedded);

/* Views returned by the PIV CMS reader for this same immutable encoding. */
typedef struct {
  const TC_CMS_signed_data* data;
  const TC_CMS_signer_info* signer;
} tc_cms_prepared_signed_data;

TC_credential_status tc_cms_path_revocation_check(const TC_X509_search_result* path,
                                                  const TC_X509_store_source* source,
                                                  const TC_CMS_revocation_policy* revocation,
                                                  const TC_CMS_credential_workspace* workspace,
                                                  size_t* work);
/* Optional inputs of the shared validation engine. metadata spans preserve
 * caller-owned configuration alias checks when public options are adapted on
 * the stack. prepared supplies views already read from request->encoded. */
typedef struct {
  const TC_bytes* metadata;
  size_t metadata_count;
  const tc_cms_prepared_signed_data* prepared;
} tc_cms_validation_extras;
TC_credential_status tc_cms_credential_validate_internal(
    const TC_CMS_validation_request* request, const TC_X509_store_source* source,
    const TC_CMS_path_options* options, const TC_CMS_revocation_policy* revocation,
    const TC_CMS_credential_workspace* workspace, size_t* work,
    const tc_cms_validation_extras* extras);
/* Embedded [0] CertificateSet followed by external candidate records. Limits
 * bound total records and bytes, including the embedded collection framing.
 * Records/order and source metadata must stay stable throughout iteration.
 * OtherCertificateFormat requires its OID and value. Remaining choice schemas
 * and SignedData version consistency are separate checks.
 * Callers preflight disjoint inputs, source results, scratch and outputs. */
TC_TLV_result tc_cms_candidates_init(TC_bytes embedded, const TC_X509_store_source* external,
                                     size_t max_candidates, size_t max_bytes,
                                     const TC_TLV_limits* limits, const tc_pki_tree_workspace* tree,
                                     tc_cms_candidates* out);
TC_TLV_result tc_cms_candidates_next(tc_cms_candidates* reader, const tc_pki_tree_workspace* tree,
                                     tc_cms_certificate_choice* out);

typedef struct {
  const TC_bytes* certificates;
  size_t count;
  const TC_X509_store_source* external;
} tc_cms_path_source;
/* Index X.509 choice encodings from an initialized candidate iterator. Other
 * certificate choices still consume record/byte limits but need no index slot.
 * Certificate schemas are checked when path discovery reads a candidate.
 * Each external candidate is fetched once. Anchors retain external indexing.
 * Index spans borrow record bytes; keep them, context and external snapshot
 * stable until all path results expire. Inputs, index, context and outputs are
 * disjoint from each other and tree scratch/work. Index is provisional on
 * failure. Candidates/context/out remain unchanged. */
TC_TLV_result tc_cms_path_source_init(const tc_cms_candidates* candidates,
                                      const tc_pki_tree_workspace* tree, TC_bytes* index,
                                      size_t capacity, tc_cms_path_source* context,
                                      TC_X509_store_source* out);
/* Match the signer ID, authenticate the supplied content digest under policy,
 * and find a
 * valid path to an explicit source anchor. Reuse one digest across candidates.
 * Path options control time, usage, policies and signature providers. Embedded
 * intermediates must be present in path_source. Revocation is separate.
 * Caller checks all input/metadata/source spans against scratch, work and out.
 * Tree, signature and validation may share frames across processing phases.
 * Candidate/source bytes stay stable through result use. Search scratch may
 * change on failure. out changes only on VALID and borrows the selected path.
 * Work includes all candidate attempts. The candidate iterator is unchanged. */
typedef struct {
  const TC_CMS_signer_info* signer;
  TC_bytes content_type, digest;
  TC_CMS_verification_policy policy;
  const TC_X509_store_source* path_source;
  const TC_X509_path_options* options;
  const tc_pki_tree_workspace* tree;
  const TC_CMS_signature_workspace* signature;
  const TC_X509_path_workspace* validation;
  const TC_X509_search_workspace* search;
  /* Optional signed-attribute digest cache shared across candidates. */
  tc_cms_signed_attrs_cache* signed_attrs;
} tc_cms_signer_search;
TC_X509_path_status tc_cms_signer_find(const tc_cms_candidates* candidates,
                                       const tc_cms_signer_search* search,
                                       TC_X509_search_result* out);
/* Shared parsed-certificate iterator. NULL filter yields every X.509 record.
 * Filters consume bounded work, return
 * OK with matched=0/1, and leave the certificate/limits unchanged. Context
 * must be disjoint from parser scratch, reader, output and work. */
TC_TLV_result tc_cms_x509_candidate_next(tc_cms_candidates* reader, tc_pki_candidate_filter filter,
                                         const void* context, const tc_pki_tree_workspace* tree,
                                         TC_X509_workspace* parser, TC_X509_certificate* scratch,
                                         TC_bytes* out);
/* Candidate searches over a collection and its external store. Each search owns
 * its cursor, and certificate and CRL bytes stay borrowed from the source.
 * tc_cms_store_cursor views the external store from the collection position. */
tc_pki_store_candidates tc_cms_store_cursor(const tc_cms_candidates* source);
/* Candidate cursor over a collection, or over its external store once the
 * embedded SET is exhausted. storage holds the cursor state. */
typedef union {
  tc_cms_candidates collection;
  tc_pki_store_candidates store;
} tc_cms_candidate_cursor;
tc_pki_candidate_next tc_cms_candidate_cursor_init(const tc_cms_candidates* source,
                                                   tc_cms_candidate_cursor* storage, void** cursor);
TC_TLV_result tc_cms_certificate_search(const tc_cms_candidates* candidates,
                                        const tc_pki_candidate_checks* checks,
                                        const TC_TLV_limits* limits,
                                        const tc_pki_tree_workspace* tree,
                                        const TC_X509_path_workspace* validation,
                                        TC_X509_search_result* out, int* source_failed);
#endif
