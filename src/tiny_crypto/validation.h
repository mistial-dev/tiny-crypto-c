/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Shared validation context and arena for complete X.509 and CMS
 * validation: capacity presets, workspace sizing and the composed CMS and
 * certificate checks.
 * Standards: RFC 5280 section 6, RFC 5652.
 * Configuration: TC_ENABLE_CMS_VALIDATION.
 * Limitations: revocation uses CRL evidence.
 * Contracts: docs/api.md, including its size_t work units.
 * Guide: docs/validation.md. */
#ifndef TINY_CRYPTO_VALIDATION_H_
#define TINY_CRYPTO_VALIDATION_H_

#include <tiny_crypto/cms_validation.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  TC_VALIDATION_MICRO,
  TC_VALIDATION_MINI,
  TC_VALIDATION_DESKTOP
} TC_validation_profile;

/* Element counts, except signature_bytes. Adjust these to the held trust set
 * and expected credentials. Exhausted capacities return a limit result. */
typedef struct {
  size_t frames, oids, name_scalars, name_attributes;
  size_t policy_nodes, policy_edges, policy_expected, policy_mappings, policies;
  size_t path, certificates, signature_bytes, crls, revocation_nodes;
} TC_validation_capacity;

/* Suitable alignment for statically allocated arena storage. */
typedef union {
  TC_TLV_frame frame;
  TC_X509_policy_node policy;
  TC_X509_policy_mapping mapping;
  TC_X509_search_frame search;
  TC_X509_revocation_node revocation;
  TC_X509_revocation_scope scope;
  uint32_t scalar;
} TC_validation_storage;

typedef struct {
  TC_CMS_path_workspace path;
  TC_CMS_credential_workspace credential;
} TC_validation_workspace;

/* Write the capacity preset of profile to out. Presets select storage
 * capacities only. Algorithms and trust policy are configured separately.
 * Charges no work. Returns OK, or ARGUMENT for a NULL out or an unknown
 * profile with out unchanged. */
TC_result TC_validation_capacity_init(TC_validation_profile profile, TC_validation_capacity* out);
/* Return the byte alignment that TC_validation_workspace_init requires of the
 * arena. An array of TC_validation_storage meets it. */
size_t TC_validation_workspace_alignment(void);
/* Write the arena bytes for capacity to bytes, including alignment padding
 * between arrays. The size includes TC_CMS_SIGNED_DIGEST_BYTES for the
 * signed-attribute digest. Charges no work.
 * Returns OK with bytes written. ARGUMENT for NULL arguments or a zero
 * frames, oids, name_scalars, name_attributes, path or certificates count.
 * LIMIT when the size overflows size_t. bytes changes only on OK. */
TC_result TC_validation_workspace_size(const TC_validation_capacity* capacity, size_t* bytes);

/* Lay out the workspace arrays in arena and write their pointers and
 * capacities to out. out->credential.path points at out->path, so keep out at
 * the same address until its last use. Arena bytes are scratch for one
 * operation at a time. Initialization leaves the arena bytes untouched.
 * capacity, arena and out must be disjoint. Charges no work.
 * Returns OK with out written. ARGUMENT for NULL arguments, an arena that is
 * misaligned for TC_validation_workspace_alignment or wraps the address
 * space, overlap, or an invalid capacity as in TC_validation_workspace_size.
 * LIMIT for an arena smaller than TC_validation_workspace_size reports or a
 * size overflow. Failure leaves out and arena unchanged. For fixed array
 * locations, fill the workspace fields directly. */
TC_result TC_validation_workspace_init(const TC_validation_capacity* capacity, TC_buffer arena,
                                       TC_validation_workspace* out);

typedef struct {
  const TC_bytes* initial_policies;
  size_t initial_policy_count;
  TC_X509_name_constraints anchor_names;
  TC_bytes purpose;
  uint16_t key_usage;
  unsigned flags;
} TC_validation_certificate_policy;

typedef struct {
  TC_X509_time at;
  TC_X509_signature_provider signatures;
  TC_TLV_limits parsing;
  size_t max_certificates, max_input, max_candidates, max_candidate_bytes;
  TC_validation_certificate_policy certificate, crl_signer;
  /* CMS encodings and attribute policy. PIV and TWIC validators replace
   * attribute_oids with the identifier set of the card profile. */
  TC_CMS_verification_policy verification;
  TC_X509_crl_delta_policy delta_policy;
  TC_X509_crl_order_policy order_policy;
} TC_validation_options;

/* Hold both sources stable through validation and the acceptance decision. */
typedef struct {
  const TC_X509_store_source* certificates;
  const TC_X509_crl_index* crls;
} TC_validation_trust;

/* Borrowed configuration for a sequence of validation operations. Use separate
 * contexts when card certificates and content signers have different trust. */
typedef struct {
  TC_validation_trust trust;
  const TC_validation_options* options;
  const TC_CMS_credential_workspace* workspace;
} TC_validation_context;

/* Bind trust sources, options and workspace for later validation calls. The
 * context borrows all three. Keep them alive and unchanged while the context
 * is in use. out must be disjoint from trust, both sources, options,
 * workspace and workspace->path. Charges no work.
 * Returns OK with out written. ARGUMENT for NULL arguments or sources, a NULL
 * workspace->path, a zero max_certificates, max_input, max_candidates or
 * max_candidate_bytes, an invalid options->at, an unknown verification,
 * delta or order policy value, or overlap. out changes only on OK. */
TC_result TC_validation_context_init(const TC_validation_trust* trust,
                                     const TC_validation_options* options,
                                     const TC_CMS_credential_workspace* workspace,
                                     TC_validation_context* out);

/* Validate CMS content, signer path and CRL revocation under the context's
 * time, provider and policies. options->certificate governs the signer path
 * and options->crl_signer the CRL signer paths. request follows
 * TC_CMS_validation_request. Inputs and source bytes stay borrowed, stable
 * and disjoint from the workspace. The workspace is reusable on return.
 * Work, statuses and failure behavior match TC_CMS_credential_validate. A
 * NULL or incomplete context also returns ERROR before any work. */
TC_credential_status TC_CMS_validate(const TC_CMS_validation_request* request,
                                     const TC_validation_context* context, size_t* work);

typedef struct {
  TC_X509_certificate certificate;
  TC_X509_time at;
  size_t anchor_index;
} TC_X509_validation_result;

/* Build a trusted path for the DER certificate in encoded and require CRL
 * evidence that every path member is unrevoked at options->at (RFC 5280
 * sections 6.1 and 6.3). options->certificate governs the path and
 * options->crl_signer the CRL signer paths. The context's source supplies
 * issuers and anchors.
 * - encoded and the held trust snapshot stay stable through the acceptance
 *   decision. They must be disjoint from the workspace, work and out.
 * - out: certificate borrows encoded and survives workspace reuse. at is the
 *   evaluation time and anchor_index names the anchor in the source.
 *
 * Work: one unit per storage comparison, charged before any parsing, then the
 * path build and the revocation check.
 * Returns VALID with out written. REVOKED when a path member is revoked.
 * UNSUPPORTED when no CRL covers a member, or for an unsupported algorithm or
 * feature. ERROR for NULL or empty arguments, an incomplete context or
 * overlap, with work unchanged. LIMIT for more source candidates than
 * max_candidates or workspace capacities below the path or CRL index size,
 * before any work, and for exhausted work or capacities. INVALID for a
 * malformed certificate or a failed path or CRL check. out changes only on
 * VALID. */
TC_credential_status TC_X509_validate(TC_bytes encoded, const TC_validation_context* context,
                                      size_t* work, TC_X509_validation_result* out);

#ifdef __cplusplus
}
#endif
#endif
