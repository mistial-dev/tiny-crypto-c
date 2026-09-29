/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_CMS_H_
#define TINY_CRYPTO_CMS_H_
#include <tiny_crypto/x509.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  /* RFC 5652 section 1.2: the envelope may use any BER encoding. */
  TC_CMS_ENVELOPE_BER = 0,
  /* Restrict envelope framing to DER: minimal definite lengths and primitive
   * OCTET STRING values. Signed attributes follow their own encoding. */
  TC_CMS_ENVELOPE_DER = 1
} TC_CMS_envelope_encoding;

typedef enum {
  /* RFC 5652 signed attributes, including DER SET OF ordering. */
  TC_CMS_ATTRIBUTES_DER = 0,
  /* Application opt-in. Preserves definite length octets and member order. */
  TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER = 1
} TC_CMS_attribute_encoding;

typedef enum {
  TC_CMS_RSA_PARAMETERS_NULL = 0,
  /* Accept an omitted rsaEncryption signatureAlgorithm parameter. */
  TC_CMS_RSA_PARAMETERS_ALLOW_ABSENT = 1
} TC_CMS_rsa_parameters;

/* Signed-attribute identifiers the reader interprets. */
typedef enum {
  /* contentType, messageDigest, signingTime (RFC 5652 section 11),
   * SMIMECapabilities (RFC 8551 section 2.5.2) and entryUUID (RFC 4530). */
  TC_CMS_ATTRIBUTE_OIDS_CMS = 0,
  /* CMS identifiers plus pivSigner-DN and pivFASC-N (FIPS 201-3 Table B-2).
   * twicFASC-N returns UNSUPPORTED under every other-attribute policy. */
  TC_CMS_ATTRIBUTE_OIDS_PIV = 1,
  /* PIV identifiers plus twicFASC-N (TWIC Part 2 v5 section 6). */
  TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC = 2
} TC_CMS_attribute_oids;

/* Handling of signed attributes outside the selected identifiers. Skipped
 * attributes stay covered by the signature and are left to the application.
 * A repeated attribute type returns INVALID. */
typedef enum {
  /* Skip cmsAlgorithmProtection (RFC 6211), signingCertificate and
   * signingCertificateV2 (RFC 5035). Each needs one SEQUENCE value. Other
   * attributes return UNSUPPORTED. */
  TC_CMS_OTHER_ATTRIBUTES_SKIP_LISTED = 0,
  /* Every attribute outside the selected identifiers returns UNSUPPORTED. */
  TC_CMS_OTHER_ATTRIBUTES_REJECT = 1,
  /* Skip listed attributes as above and any other attribute with a nonempty
   * value SET. DER attributes also need that SET in DER order. */
  TC_CMS_OTHER_ATTRIBUTES_SKIP_ALL = 2
} TC_CMS_other_attributes;

/* CMS encoding and attribute policy shared by readers and verifiers.
 * A zero-initialized policy selects a BER envelope, DER signed attributes,
 * NULL rsaEncryption parameters (RFC 3370 section 3.2), CMS attribute
 * identifiers and skipping of the listed attributes. Readers and verifiers
 * copy the policy at entry, so it may overlap any input. An unknown enum
 * value returns ARGUMENT. */
typedef struct {
  TC_CMS_envelope_encoding envelope;
  TC_CMS_attribute_encoding attributes;
  TC_CMS_rsa_parameters rsa_parameters;
  TC_CMS_attribute_oids attribute_oids;
  TC_CMS_other_attributes other_attributes;
} TC_CMS_verification_policy;

typedef struct {
  TC_bytes encoded;
  TC_bytes digest_algorithms, content_type, content;
  TC_bytes certificates, revocations, signers;
  uint32_t version;
  int has_content;
} TC_CMS_signed_data;

/* Read a ContentInfo carrying SignedData, including its version consistency.
 * policy->envelope selects BER or DER framing. Requires TC_TLV_ENABLE_BER and
 * TC_ENABLE_X509. content_type holds OID contents. Other spans retain complete
 * encodings. content is an OCTET STRING, constructed only in BER. has_content
 * distinguishes detached content from an embedded empty value. Missing
 * optional collections have zero-length spans. Use the typed readers for
 * signers, certificates and revocations. Check the selected signer's digest
 * with TC_CMS_digest_algorithms_check. Signature and trust validation are
 * separate steps.
 *
 * All spans borrow input, which must remain alive and unchanged. Input, limits,
 * frames, work and out must be disjoint. Bad storage or policy arguments
 * return ARGUMENT and leave them unchanged. Parsing may consume work and
 * frames. out changes only on OK. Limits bound framing. Work covers storage
 * checks and all parsing passes. Missing or extra fields, wrong tags, framing
 * outside the envelope encoding and trailing bytes return INVALID. */
TC_TLV_result TC_CMS_signed_data_read(TC_bytes encoded, const TC_CMS_verification_policy* policy,
                                      const TC_TLV_limits* limits, TC_TLV_frames frames,
                                      size_t* work, TC_CMS_signed_data* out);

typedef struct {
  TC_bytes encoded;
  TC_bytes issuer, serial, subject_key_id;
  TC_DER_algorithm digest_algorithm, signature_algorithm;
  TC_bytes signed_attributes, unsigned_attributes, signature;
  uint32_t version;
  int serial_negative;
} TC_CMS_signer_info;

/* Read one complete SignerInfo under policy->envelope. Version 1 uses
 * issuer/serial. Version 3 uses subject_key_id. issuer is an encoded Name and
 * serial retains INTEGER contents, including sign padding. subject_key_id is
 * the complete implicit OCTET STRING. signature is a complete OCTET STRING.
 * Either OCTET STRING may be constructed in a BER envelope. Attribute spans
 * retain their encodings. Read signed attributes with
 * TC_CMS_signed_attributes_read.
 *
 * Checks identifier/version consistency, Name and algorithm syntax, and field
 * framing. Algorithm selection, signature verification and signer trust are
 * separate steps. Spans borrow input. Storage, policy, work and output rules
 * match signed_data_read. Requires TC_ENABLE_X509 and TC_TLV_ENABLE_BER. */
TC_TLV_result TC_CMS_signer_info_read(TC_bytes encoded, const TC_CMS_verification_policy* policy,
                                      const TC_TLV_limits* limits, TC_TLV_frames frames,
                                      size_t* work, TC_CMS_signer_info* out);

/* Initialize from SignedData.signers, including its SET tag, under
 * policy->envelope. Checks the set framing. next performs each member's schema
 * checks with the same envelope encoding. Empty sets are valid. Input, limits,
 * frames, work and out are disjoint. out changes only on OK. Keep the encoded
 * bytes stable and treat the returned reader as managed state. */
TC_TLV_result TC_CMS_signers_init(TC_bytes encoded, const TC_CMS_verification_policy* policy,
                                  const TC_TLV_limits* limits, TC_TLV_frames frames, size_t* work,
                                  TC_TLV_reader* out);
/* Reader and out change only on OK. Frames/work are provisional on failure.
 * END leaves all storage unchanged, even with zero work remaining. Reuse one
 * budget across init/next calls. Reader, its input, frames, work and out must be
 * disjoint. Output spans borrow input and outlive scratch and reader state. */
TC_TLV_result TC_CMS_signer_next(TC_TLV_reader* reader, TC_TLV_frames frames, size_t* work,
                                 TC_CMS_signer_info* out);

/* Check that digest_algorithm, usually a SignerInfo.digest_algorithm, is
 * listed in signed_data->digest_algorithms with valid parameters. RFC 5652
 * section 5.1 lists every signer's digest there. Equal parameters may use
 * distinct BER encodings. Other listed hashes only need valid syntax because
 * they may belong to other signers.
 *
 * OK writes the recognized hash to out. An unlisted digest returns INVALID.
 * An unknown or disabled selected hash returns UNSUPPORTED. signed_data comes
 * from TC_CMS_signed_data_read and keeps its input stable. Inputs may overlap
 * each other and must be disjoint from limits, frames, work and out. Bad
 * storage returns ARGUMENT and leaves caller state unchanged. out changes only
 * on OK. Requires TC_ENABLE_X509 and TC_TLV_ENABLE_BER. */
TC_TLV_result TC_CMS_digest_algorithms_check(const TC_CMS_signed_data* signed_data,
                                             const TC_DER_algorithm* digest_algorithm,
                                             const TC_TLV_limits* limits, TC_TLV_frames frames,
                                             size_t* work, TC_hash_algorithm* out);

typedef struct {
  TC_bytes content_type, message_digest;
  TC_bytes signature_input[2];
  TC_X509_time signing_time;
  int has_signing_time;
  /* Encoded SMIMECapabilities sequence. Absent when data is NULL. */
  TC_bytes smime_capabilities;
  /* Encoded Name from the optional pivSigner-DN attribute. */
  TC_bytes signer_name;
  /* Original FASC-N OID and encoded OCTET STRING, including BER chunks. */
  TC_bytes fascn_oid, fascn_octets;
  /* Encoded entryUUID OCTET STRING (16 value bytes). */
  TC_bytes entry_uuid_octets;
} TC_CMS_signed_attributes;

/* Read the complete IMPLICIT [0] signedAttrs field. policy->attributes
 * selects DER, or BER_DEFINITE_ORDER for signatures made over unsorted
 * attributes. Both modes require content-type and message-digest exactly once
 * and reject indefinite lengths. policy->attribute_oids selects the
 * interpreted identifiers: optional signingTime, SMIMECapabilities and
 * entryUUID in every set, pivSigner-DN and pivFASC-N in the PIV sets, and
 * twicFASC-N in PIV_TWIC. FASC-N values contain exactly 25 bytes and entryUUID
 * values 16 bytes. fascn_oid holds the identifier that matched.
 * policy->other_attributes handles the remaining attributes. signingTime is
 * asserted by the signer. Capabilities retain their advertised order and
 * opaque parameter values. Applications interpret them after signature and
 * trust validation. Path-building APIs match signer_name to the certificate
 * subject. Signature-only APIs verify with the supplied key, and the caller
 * handles certificate/name binding.
 *
 * signature_input substitutes the SET OF tag and borrows the original length
 * and contents. Keep input alive and unchanged while using returned spans.
 * Input, limits, frames, work and out must be disjoint. Bad storage or policy
 * arguments return ARGUMENT and leave them unchanged. Frames/work may change on
 * other failures. out changes only on OK. Limits bound framing. Work bounds
 * bytes examined across passes, including the repeated-type scan for skipped
 * attributes. Requires TC_ENABLE_X509.
 *
 * This parses attributes only. The caller must check content type and digest,
 * verify the signature over signature_input, and validate the signer's trust. */
TC_TLV_result TC_CMS_signed_attributes_read(TC_bytes encoded,
                                            const TC_CMS_verification_policy* policy,
                                            const TC_TLV_limits* limits, TC_TLV_frames frames,
                                            size_t* work, TC_CMS_signed_attributes* out);

/* Hash SignedData.content, including its complete OCTET STRING encoding.
 * BER chunk headers and end markers are excluded from the digest. For detached
 * content, hash the application's raw message with the ordinary hash API.
 * Requires TC_ENABLE_X509, TC_TLV_ENABLE_BER and the selected hash implementation.
 * Unknown or disabled hashes return UNSUPPORTED. A short digest buffer returns
 * LIMIT. Success writes the algorithm's full digest and leaves spare bytes alone.
 *
 * Input, limits, frames, work and the entire digest buffer must be disjoint.
 * Bad storage leaves them unchanged. Other errors may consume frames/work but
 * preserve digest. Work covers storage checks, encoded bytes and hashed bytes.
 * Uses one temporary hash context on the stack and hashes BER chunks in place. */
TC_TLV_result TC_CMS_content_digest(TC_bytes encoded, TC_hash_algorithm algorithm,
                                    const TC_TLV_limits* limits, TC_TLV_frames frames, size_t* work,
                                    uint8_t* digest, size_t digest_capacity);

/* Compare parsed signed attributes with the content type OID contents and a
 * computed digest. Hash content value bytes, excluding OCTET STRING framing.
 * Reuse that digest for signers using the same digest algorithm. The selected
 * algorithm determines the required digest length. Hashing may be external.
 *
 * OK writes matched as 0 or 1. Signature and trust verification are separate steps.
 * Errors leave matched unchanged. Unknown algorithms return UNSUPPORTED.
 * All inputs are borrowed and may overlap each other, but must be disjoint
 * from work and matched, which must also be disjoint. Invalid storage leaves
 * both unchanged. Otherwise work covers storage checks and compared bytes.
 * Requires TC_ENABLE_X509. */
TC_TLV_result TC_CMS_content_digest_check(const TC_CMS_signed_attributes* attributes,
                                          TC_bytes expected_type, TC_hash_algorithm algorithm,
                                          TC_bytes digest, size_t* work, int* matched);

typedef struct {
  TC_TLV_frame* frames;
  size_t frame_capacity;
  /* Needed only for a signature split across BER chunks. NULL/0 is allowed.
   * Capacity must hold the decoded signature. */
  uint8_t* signature;
  size_t signature_capacity;
} TC_CMS_signature_workspace;

/* One SignerInfo verification.
 * - signer and key come from their schema readers and retain stable input.
 * - content_type is the envelope's eContentType OID contents.
 * - policy selects the envelope and signed-attribute encodings, the
 *   interpreted attribute identifiers and the rsaEncryption parameter rule.
 *   The zero-initialized policy is the RFC 5652 / RFC 3370 section 3.2
 *   default. ALLOW_ABSENT applies only to rsaEncryption in SignerInfo. Present
 *   parameters must encode NULL.
 * - provider verifies the signature. limits bound every decode. */
typedef struct {
  const TC_CMS_signer_info* signer;
  TC_bytes content_type;
  TC_CMS_verification_policy policy;
  const TC_X509_public_key* key;
  const TC_X509_signature_provider* provider;
  const TC_TLV_limits* limits;
} TC_CMS_signer_verify_request;

/* Verify one parsed SignerInfo against an independently computed content digest.
 * Hash content with SignerInfo.digest_algorithm. For PSS, the signed-attribute
 * hash may differ.
 * Checks digest binding, signed attributes, algorithm/key compatibility and the
 * signature. Without signed attributes, content_type must be id-data.
 * CMS field framing uses BER. Verification ignores unsigned_attributes,
 * including countersignatures. RFC 5652 sections 5.3 and 11.4 exclude them
 * from the signature, so their contents are unauthenticated.
 *
 * The caller checks signer/certificate identity, trust and application
 * algorithm policy, and checks the envelope's digestAlgorithms with
 * TC_CMS_digest_algorithms_check.
 * A VALID result authenticates the supplied digest with the supplied key only.
 *
 * The request, its inputs and all metadata may overlap each other. They must be
 * disjoint from frames, signature storage and work, which must also be mutually
 * disjoint. Provider context and its scratch must be separate from all CMS
 * inputs and workspace storage.
 * Bad storage leaves caller state unchanged. Other failures may consume scratch
 * and work. Uses a temporary hash context/digest for signed attributes. Requires
 * X509, BER, a digest provider, and the signed-attribute hash when attributes exist. */
TC_X509_signature_result TC_CMS_signer_verify_digest(const TC_CMS_signer_verify_request* request,
                                                     TC_bytes digest,
                                                     const TC_CMS_signature_workspace* workspace,
                                                     size_t* work);

typedef enum { TC_CMS_CONTENT_RAW, TC_CMS_CONTENT_BER_OCTETS } TC_CMS_content_encoding;

/* Hash content and verify one parsed signer, resolving its hash internally.
 * RAW accepts application content, including NULL/0 for an empty message.
 * BER_OCTETS accepts SignedData.content with its complete OCTET STRING encoding.
 * The caller selects the format explicitly. Raw content is bounded by
 * max_input and max_value. BER content also uses the framing limits.
 *
 * Storage, provider, trust and unsigned-attribute rules match
 * signer_verify_digest. The content hash must be enabled. Hash scratch is reused
 * for signed attributes, without copying the message. For cached or externally
 * computed digests, use the digest API. */
TC_X509_signature_result TC_CMS_signer_verify_content(const TC_CMS_signer_verify_request* request,
                                                      TC_bytes content,
                                                      TC_CMS_content_encoding encoding,
                                                      const TC_CMS_signature_workspace* workspace,
                                                      size_t* work);

#ifdef __cplusplus
}
#endif
#endif
