/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_X509_OCSP_H_
#define TINY_CRYPTO_X509_OCSP_H_

/* RFC 6960 OCSP request encoding and response verification for one
 * certificate. Requires TC_ENABLE_X509_OCSP, which requires X.509 path
 * support and SHA-1: a byKey ResponderID is always a SHA-1 key hash
 * (RFC 6960 4.2.1). Nonces follow RFC 9654. See docs/api.md. */

#include <tiny_crypto/x509_path.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { TC_OCSP_GOOD, TC_OCSP_REVOKED, TC_OCSP_UNKNOWN, TC_OCSP_UNAVAILABLE } TC_OCSP_status;

typedef struct {
  TC_OCSP_status status;
  TC_X509_time produced_at, this_update, next_update, revocation_time;
  int has_next_update, has_revocation_time;
  /* DER certificate of the delegated responder that signed the response
   * (RFC 6960 4.2.2.2). It is {NULL, 0} when the issuer signed directly and
   * for UNAVAILABLE. The span borrows request->response or a store record. */
  TC_bytes responder_certificate;
  /* Nonzero when that delegate carries id-pkix-ocsp-nocheck. Zero for a
   * delegate means the caller must establish the delegate's own revocation
   * status before relying on the result (RFC 6960 4.2.2.2.1). */
  int responder_nocheck;
} TC_OCSP_result;

typedef struct {
  /* A complete DER OCSPResponse and the certificate it should cover. */
  TC_bytes response;
  TC_bytes certificate;
  /* Empty, or the 32..128 byte nonce sent in the request (RFC 9654 2.1).
   * When present, the response must echo it. */
  TC_bytes expected_nonce;
  /* The issuer name and key must come from the already validated path. */
  const TC_X509_trust_anchor* issuer;
  /* Optional untrusted delegate candidates, searched after the response's
   * own certs field. */
  const TC_X509_store_source* certificates;
  /* Evaluation time. Checked with TC_X509_time_check. */
  TC_X509_time at;
  /* Seconds. producedAt and thisUpdate may be up to clock_skew_seconds after
   * at. thisUpdate may be up to max_age_seconds before at - clock_skew_seconds.
   * A present nextUpdate must not be before at - clock_skew_seconds. Both
   * values must be at most INT64_MAX. */
  size_t max_age_seconds, clock_skew_seconds;
  /* max_responses bounds the SingleResponses read and must be nonzero.
   * max_certificates bounds the delegate candidates examined, from the certs
   * field and the store together. Zero examines none, which suffices for a
   * response signed by the issuer. */
  size_t max_responses, max_certificates;
  /* Applied to the OCSPResponse, the nested BasicOCSPResponse, the target
   * certificate and every delegate candidate. max_input bounds the response. */
  const TC_TLV_limits* parsing;
  const TC_X509_signature_provider* signatures;
} TC_OCSP_verify_request;

/* Caller-owned scratch. frames need one entry per constructed nesting level
 * of the deepest object parsed. extension_oids holds the extended key usage
 * OIDs of one delegate candidate and also bounds the extensions read from
 * each extension list. names is the Name comparison workspace. */
typedef struct {
  TC_TLV_frame* frames;
  size_t frame_capacity;
  TC_bytes* extension_oids;
  size_t extension_capacity;
  TC_X509_name_workspace names;
} TC_OCSP_workspace;

/* Verify a complete DER OCSPResponse, including one received by stapling.
 * Response, certificate, store records and issuer remain borrowed and
 * unchanged during the call and while out->responder_certificate is used.
 * The certificate path and issuer must already be trusted by the caller.
 *
 * A response is accepted when the issuer signed it, or when a delegate
 * signed it that matches the ResponderID, is issued and signed by the issuer,
 * is valid at `at` and carries id-kp-OCSPSigning (RFC 6960 4.2.2.2). The
 * result names that delegate. The caller establishes the delegate's own
 * revocation status, using responder_nocheck for RFC 6960 4.2.2.2.1.
 *
 * OK: out holds the status. A successful responseStatus is authenticated,
 *   and its nonce and freshness are checked. The unsigned responseStatus
 *   values internalError, tryLater and unauthorized yield UNAVAILABLE, which
 *   is unauthenticated and skips the signature, nonce and time checks.
 * ARGUMENT: a required pointer or issuer span is NULL, a store with
 *   candidates has no candidate callback, max_responses is zero, the nonce
 *   length is outside 32..128, `at` fails TC_X509_time_check, or a time limit
 *   exceeds INT64_MAX or overflows with `at`. Checked before any parsing.
 *   Later, a store callback failure other than LIMIT or UNSUPPORTED, or a
 *   signature provider error for the issuer's own signature, is ARGUMENT.
 * LIMIT: work, a parsing limit, max_responses or max_certificates is exceeded.
 * UNSUPPORTED: an unknown response type, CertID hash, version, critical
 *   extension or signature algorithm, or the sigRequired responseStatus.
 * INVALID: malformed DER, no SingleResponse for the certificate, a wrong
 *   issuer, a nonce mismatch, stale or future times, or no authorized signer.
 * Every result other than OK leaves out unchanged. Work is charged for the
 * response and BasicOCSPResponse bytes, hashing, Name comparison and
 * signature verification. Work and scratch may change on every result. */
TC_TLV_result TC_OCSP_response_verify(const TC_OCSP_verify_request* request,
                                      const TC_OCSP_workspace* workspace, size_t* work,
                                      TC_OCSP_result* out);

/* One OCSPRequest for a single certificate. issuer names and holds the key
 * of the certificate's issuer. hash selects the CertID hash: SHA-256 is
 * recommended, and TC_HASH_SHA1 serves a legacy responder. A present nonce is
 * generated by the caller and must be 32..128 bytes (RFC 9654 2.1). */
typedef struct {
  TC_bytes certificate;
  const TC_X509_trust_anchor* issuer;
  TC_hash_algorithm hash;
  TC_bytes nonce;
  const TC_TLV_limits* parsing;
} TC_OCSP_encode_request;

/* Encode one unsigned OCSPRequest (RFC 6960 4.1.1) into encoded and write its
 * size to length. The certificate, issuer and nonce stay borrowed and
 * unchanged during the call and must not overlap encoded.
 *
 * Sizing: pass encoded = {NULL, 0} to query the size. When encoded is too
 * small the result is LIMIT, *length holds the required size and encoded is
 * unchanged. The size is fixed by the hash, the serial number length and the
 * nonce length.
 *
 * OK: encoded[0..*length) holds the DER request.
 * ARGUMENT: a required pointer or issuer span is NULL, the nonce length is
 *   outside 32..128, or encoded overlaps an input, request, work or length.
 *   Outputs unchanged.
 * UNSUPPORTED: hash is other than SHA-1 or SHA-256, or is disabled.
 * INVALID: the certificate is malformed or its issuer differs from
 *   issuer->name.
 * LIMIT: encoded is too small, with *length set to the required size, or
 *   work or a parsing limit is exceeded, with *length set to 0.
 * After argument validation, failures other than a short buffer set *length
 * to 0 and leave encoded unchanged. Work is charged for Name comparison and
 * for hashing the issuer name and key. */
TC_TLV_result TC_OCSP_request_encode(const TC_OCSP_encode_request* request,
                                     const TC_OCSP_workspace* workspace, size_t* work,
                                     TC_buffer encoded, size_t* length);

#ifdef __cplusplus
}
#endif
#endif
