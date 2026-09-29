/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Composed PIV and TWIC credential validation: signed CHUID, biometric
 * objects, the security object and PIV secure-messaging signer CVCs, bound to
 * an accepted CHUID and a shared validation context.
 * Standards: SP 800-73-5 Part 1, SP 800-76-2, FIPS 201-3, TWIC Part 2 v5.
 * Configuration: TC_ENABLE_CREDENTIAL, with CVC checks from
 * TC_ENABLE_PIV_CVC.
 * Limitations: card transport, cancellation status and the access decision
 * belong to the application. Iris records are unsupported.
 * Contracts: docs/api.md. Guides: docs/cms.md, docs/credential-validation.md. */
#ifndef TINY_CRYPTO_CREDENTIAL_H_
#define TINY_CRYPTO_CREDENTIAL_H_

#include <tiny_crypto/cms.h>
#include <tiny_crypto/lds.h>
#include <tiny_crypto/piv_card.h>
#include <tiny_crypto/piv_chuid.h>
#include <tiny_crypto/piv_cms.h>
#include <tiny_crypto/piv_security.h>
#include <tiny_crypto/validation.h>
#if TC_ENABLE_PIV_CVC
#include <tiny_crypto/piv_cvc.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  TC_bytes encoded;
  TC_PIV_CHUID_encoding encoding;
  TC_PIV_card_profile profile;
  TC_PIV_CHUID_profile chuid_profile;
  /* Accept registered TWIC aliases and reader identifier rules for a PIV app.
   */
  int twic_reader_policy;
  /* Identifiers and expiration from the already validated card certificate. */
  const TC_PIV_card_identifiers* card;
  const TC_X509_time* card_expiration;
} TC_PIV_CHUID_validation_request;

/* Borrowed views of an accepted CHUID. The profile and time record the
 * validation that produced the result. Dependent validators take the FASC-N,
 * GUID and signer from it and reject a result from another profile or time. */
typedef struct {
  TC_PIV_CHUID object;
  TC_bytes signer;
  TC_X509_time at;
  TC_PIV_card_profile profile;
} TC_PIV_CHUID_result;

/* Authenticate a signed CHUID and bind its identifiers to the validated card.
 * Choose the card OID policy and CHUID schema explicitly. Expiration includes
 * the final second of its UTC date. On VALID, out borrows CHUID and signer
 * bytes. Other statuses leave out unchanged. Keep writable state disjoint from
 * inputs. */
TC_credential_status TC_PIV_CHUID_validate(const TC_PIV_CHUID_validation_request* request,
                                           const TC_validation_context* context, size_t* work,
                                           TC_PIV_CHUID_result* out);

typedef struct {
  /* Complete BC value, after any outer TWIC privacy-key decryption. */
  TC_bytes encoded;
  /* Must equal chuid->profile. */
  TC_PIV_card_profile profile;
  /* Accepted CHUID from TC_PIV_CHUID_validate at context->options->at. */
  const TC_PIV_CHUID_result* chuid;
  const TC_X509_time* card_expiration;
  /* Select the current or legacy biometric CMS profile explicitly. */
  TC_PIV_CMS_kind signature_profile;
  TC_PIV_CBEFF_format format;
  /* Set to one to require the CBEFF validity period at context time. */
  int require_current;
} TC_PIV_biometric_validation_request;

/* Borrowed views of an authenticated biometric object. record and
 * metadata.creator borrow request->encoded. signer borrows the embedded CMS
 * certificate or the CHUID signer. */
typedef struct {
  TC_PIV_CBEFF_format format;
  TC_PIV_CBEFF_metadata metadata;
  TC_bytes record;
  TC_bytes signer;
  TC_PIV_card_profile profile;
  TC_X509_time at;
} TC_PIV_biometric_result;

/* Authenticate a biometric object's CBEFF header and record and bind the
 * FASC-N and GUID of the accepted CHUID. An omitted CMS certificate selects the
 * CHUID signer. An embedded certificate must carry a different key (SP 800-76-2
 * section 9.3). VALID covers object authentication, identifier binding and the
 * selected record profile. Inputs remain borrowed. out is disjoint from inputs
 * and changes only on VALID.
 *
 * ERROR: NULL arguments, overlap, an unknown profile or format, or a CHUID
 * result whose profile differs from request->profile or whose time differs
 * from context->options->at. UNSUPPORTED: iris images. LIMIT: work or parsing
 * limits. INVALID: malformed or mismatched object data. Other statuses come
 * from signer path and revocation checks. */
TC_credential_status TC_PIV_biometric_validate(const TC_PIV_biometric_validation_request* request,
                                               const TC_validation_context* context, size_t* work,
                                               TC_PIV_biometric_result* out);

typedef struct {
  uint16_t container;
  const TC_bytes* parts;
  size_t count;
} TC_PIV_security_data;

typedef struct {
  TC_bytes encoded;
  TC_PIV_security_encoding encoding;
  /* Must equal chuid->profile. */
  TC_PIV_card_profile profile;
  /* Accepted CHUID from TC_PIV_CHUID_validate at context->options->at. */
  const TC_PIV_CHUID_result* chuid;
  const TC_X509_time* card_expiration;
  /* Complete inventory. Container IDs must be unique, and each object has parts. */
  const TC_PIV_security_data* objects;
  size_t count;
} TC_PIV_security_validation_request;

typedef struct {
  /* Decoded LDS content scratch. Capacity is bounded by the application. */
  uint8_t* content;
  size_t content_capacity;
} TC_PIV_security_validation_workspace;

/* Inventory descriptors and their bytes remain borrowed and immutable through
 * subsequent checks. This result survives reuse of the validation workspace. */
typedef struct {
  const TC_PIV_security_data* objects;
  size_t count;
  TC_bytes signer;
  TC_PIV_card_profile profile;
  TC_X509_time at;
} TC_PIV_security_result;

/* Authenticate a Security Object with the accepted CHUID signer, then check
 * the exact inventory against signed LDS digests (SP 800-73-5 Part 1 section
 * 3.1.7). Parts supply each object's bytes in hash order. All buffers remain
 * caller-owned. content is disjoint mutable scratch. On VALID, out borrows the
 * inventory and signer bytes. Other statuses leave out unchanged.
 *
 * ERROR: NULL arguments, overlap, empty parts, or a CHUID result whose profile
 * differs from request->profile or whose time differs from
 * context->options->at. LIMIT: more than TC_LDS_MAX_GROUPS objects, work or
 * parsing limits. INVALID: malformed data, fewer than two objects, duplicate
 * containers or an inventory that differs from the signed digests. Other
 * statuses come from signer path and revocation checks. */
TC_credential_status TC_PIV_security_validate(const TC_PIV_security_validation_request* request,
                                              const TC_validation_context* context,
                                              const TC_PIV_security_validation_workspace* workspace,
                                              size_t* work, TC_PIV_security_result* out);

enum { TC_TWIC_UNSIGNED_CHUID_CONTAINER = 0x3002 };

typedef struct {
  TC_bytes encoded;
  TC_PIV_CHUID_encoding encoding;
  /* Must equal security->profile. */
  TC_PIV_card_profile profile;
  const TC_PIV_card_identifiers* card;
  /* Accepted inventory from TC_PIV_security_validate at context->options->at. */
  const TC_PIV_security_result* security;
} TC_TWIC_unsigned_CHUID_validation_request;

/* Check an unsigned CHUID against a previously authenticated inventory at the
 * same evaluation time. Container 3002 must match encoded byte for byte.
 * The inventory and inputs remain borrowed. Keep work disjoint from them.
 * ERROR: NULL arguments, overlap, a non-TWIC profile, or a security result
 * whose profile or time differs. LIMIT: work or parsing limits. INVALID: a
 * missing or different container 3002, an expired CHUID or other card
 * identifiers. */
TC_credential_status
TC_TWIC_unsigned_CHUID_validate(const TC_TWIC_unsigned_CHUID_validation_request* request,
                                const TC_validation_context* context, size_t* work);

#if TC_ENABLE_PIV_CVC
typedef struct {
  TC_bytes card, intermediate, expected_uuid, signer_certificate;
  TC_EC_curve curve;
  TC_PIV_card_profile profile;
} TC_PIV_CVC_validation_request;

/* Validate the X.509 signer's path and CRLs, then authenticate the CVC chain.
 * The card profile selects compatible OIDs. On VALID, out borrows card bytes.
 * Keep point scratch disjoint from inputs, provider state, work and out. */
TC_credential_status TC_PIV_CVC_validate(const TC_PIV_CVC_validation_request* request,
                                         const TC_validation_context* context,
                                         TC_EC_workspace* point, size_t* work, TC_PIV_CVC* out);
#endif

#ifdef __cplusplus
}
#endif
#endif
