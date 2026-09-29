/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_X509_H_
#define TINY_CRYPTO_X509_H_
#include <tiny_crypto/key.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  unsigned year;
  uint8_t month, day, hour, minute, second;
} TC_X509_time;

typedef struct {
  TC_DER_algorithm algorithm;
  TC_bytes key, modulus, exponent, curve_oid;
  TC_key_type type;
  TC_EC_curve curve;
  unsigned bits;
} TC_X509_public_key;

/* Decode SubjectPublicKeyInfo. Unknown algorithms retain their OID and key
 * bytes with type UNKNOWN. The caller checks EC coordinates for curve membership.
 * encoded is the complete encoding, so truncation returns INVALID. The fixed
 * key schemas bound their own parsing. out changes only on OK. */
TC_TLV_result TC_X509_subject_public_key(TC_bytes encoded, TC_X509_public_key* out);

typedef struct {
  /* One frame per constructed nesting level of the deepest object parsed. */
  TC_TLV_frames frames;
  /* One slot per extension, used to detect duplicate OIDs. */
  TC_bytes* extension_oids;
  size_t extension_capacity;
} TC_X509_workspace;

typedef struct {
  TC_bytes encoded, tbs, serial, issuer, subject, spki, extensions, signature;
  TC_DER_algorithm signature_algorithm;
  TC_X509_public_key public_key;
  TC_X509_time not_before, not_after;
  unsigned version;
  int serial_negative;
} TC_X509_certificate;

/* Parse one DER certificate. Returned spans borrow encoded.
 * Validate signatures, paths, revocation and time before accepting the certificate.
 * Interpret extension values according to their OIDs.
 * limits->max_elements counts every element parsed, including the DER inside
 * each extension value. A certificate needing more returns LIMIT.
 * Workspace may change on failure. out remains unchanged. */
TC_TLV_result TC_X509_read(TC_bytes encoded, const TC_TLV_limits* limits,
                           TC_X509_workspace* workspace, TC_X509_certificate* out);
/* UTC calendar times, years 1..9999, without leap-second values. order receives
 * -1, 0 or 1. valid_at includes both endpoints and rejects reversed intervals.
 * Outputs must be disjoint from inputs and change only on OK. valid_at checks
 * only the validity interval. */
TC_TLV_result TC_X509_time_compare(const TC_X509_time* left, const TC_X509_time* right, int* order);
/* OK when value is a valid UTC calendar time in years 1..9999, INVALID
 * otherwise, and ARGUMENT for NULL. */
TC_TLV_result TC_X509_time_check(const TC_X509_time* value);
/* Convert UTC years 1..9999 to seconds since 1970-01-01, excluding leap seconds.
 * Earlier dates produce negative values. Output changes only on OK and must be
 * disjoint from the input. The result is independent of platform time_t and timezone state. */
TC_TLV_result TC_X509_time_to_unix(const TC_X509_time* value, int64_t* seconds);
TC_TLV_result TC_X509_valid_at(const TC_X509_certificate* certificate, const TC_X509_time* at,
                               int* valid);

typedef enum {
  TC_X509_SIGNATURE_VALID,
  TC_X509_SIGNATURE_INVALID,
  TC_X509_SIGNATURE_UNSUPPORTED,
  TC_X509_SIGNATURE_ERROR,
  TC_X509_SIGNATURE_LIMIT
} TC_X509_signature_result;
typedef TC_X509_signature_result (*TC_X509_signature_verify_fn)(
    void* context, const TC_bytes* message, size_t count, const TC_DER_algorithm* algorithm,
    TC_bytes signature, const TC_X509_public_key* issuer_key, size_t* work);
typedef TC_X509_signature_result (*TC_X509_signature_verify_digest_fn)(
    void* context, TC_bytes digest, const TC_signature_algorithm* algorithm, TC_bytes signature,
    const TC_X509_public_key* issuer_key, size_t* work);
typedef struct {
  TC_X509_signature_verify_fn verify;
  void* context;
  /* Optional prehashed operation for CMS and other externally hashed content. */
  TC_X509_signature_verify_digest_fn verify_digest;
} TC_X509_signature_provider;
/* Supplied through the application's trusted configuration. A self-signed
 * certificate can supply these fields. Trust comes from the configuration,
 * independent of the self-signature. Anchor constraints and policy settings
 * belong to path inputs. */
typedef struct {
  TC_bytes name;
  TC_X509_public_key public_key;
} TC_X509_trust_anchor;
/* Signature work: before the callback, each verification charges one unit
 * plus the byte length of every signed-data span (message segment or
 * digest), the signature, the DER algorithm oid and parameters (message
 * forms), and the issuer key's algorithm oid, parameters and key. The key's
 * modulus, exponent and curve_oid are parts of key and are not charged again.
 * A budget exhausted before the callback returns LIMIT with *work set to 0.
 * The callback then consumes its own work. A callback that returns more work
 * than it received makes the result ERROR with *work set to 0.
 *
 * Verify a parsed certificate's signature using an application-supplied
 * provider. The callback receives one message segment containing the original
 * DER TBSCertificate, including its header, the signature bytes without the
 * BIT STRING header and unused-bits count, and unmodified algorithm
 * parameters. It must check algorithm/key compatibility and return VALID only
 * after cryptographic verification. Missing callbacks return UNSUPPORTED.
 * Issuer identity, validity and trust are separate checks. work is disjoint
 * from all inputs. Provider context and work may change on failure. Inputs
 * must remain unchanged throughout the call. */
TC_X509_signature_result TC_X509_signature_verify(const TC_X509_certificate* certificate,
                                                  const TC_X509_public_key* issuer_key,
                                                  const TC_X509_signature_provider* provider,
                                                  size_t* work);
/* Verify the ordered concatenation of borrowed message segments. For a supplied
 * digest, use TC_X509_signature_verify_digest. Empty segments are allowed. Count
 * zero represents an empty message. The provider hashes/consumes each segment in
 * order and checks algorithm/key compatibility. Input bytes stay in place,
 * unmodified. All input storage and provider metadata must be disjoint from work.
 * Provider work rules are as above. */
TC_X509_signature_result TC_X509_signature_verify_message(
    const TC_bytes* message, size_t count, const TC_DER_algorithm* algorithm, TC_bytes signature,
    const TC_X509_public_key* issuer_key, const TC_X509_signature_provider* provider, size_t* work);

/* Verify a full digest as supplied. Parameters must describe the
 * signature, including its digest algorithm and PSS MGF/salt settings. Providers
 * must check key restrictions and verify the signature mathematically. An absent
 * verify_digest callback returns UNSUPPORTED.
 * Input storage and provider metadata must be disjoint from work. The callback
 * consumes bounded work and may not increase it. VALID authenticates the digest
 * under the key. Digest origin and certificate trust are separate checks. */
TC_X509_signature_result
TC_X509_signature_verify_digest(TC_bytes digest, const TC_signature_algorithm* algorithm,
                                TC_bytes signature, const TC_X509_public_key* issuer_key,
                                const TC_X509_signature_provider* provider, size_t* work);

typedef struct {
  TC_bytes encoded, oid, value;
} TC_X509_name_attribute;
/* Iterate a DER Name. Each RDN is a nonempty, DER-sorted SET of attributes.
 * Returned RDN spans contain SET contents, suitable for a DER reader passed to
 * attribute_next. Attribute values retain their complete encoding. Unknown
 * value types remain opaque. The caller checks their application-specific syntax.
 * Element limits include the Name, SETs, attribute sequences, OIDs and values.
 * Readers and outputs change only on OK. */
TC_TLV_result TC_X509_name_init(TC_TLV_reader* reader, TC_bytes encoded,
                                const TC_TLV_limits* limits);
TC_TLV_result TC_X509_rdn_next(TC_TLV_reader* reader, TC_bytes* out);
TC_TLV_result TC_X509_attribute_next(TC_TLV_reader* reader, TC_X509_name_attribute* out);

typedef struct {
  uint32_t *left, *right;
  size_t scalar_capacity;
  uint8_t* matched;
  size_t attribute_capacity;
} TC_X509_name_workspace;
/* Compare DER Names using RFC 5280 section 7.1. Standard X.520 case-ignore
 * attributes and userId use RFC 4518 preparation. domainComponent and
 * emailAddress (RFC 2985 section 5.2.1) use ASCII case-insensitive
 * comparison. Values without a supported preparation, such as TeletexString
 * or an attribute type with no known matching rule, match only when their
 * encodings are identical. When such a difference is all that separates the
 * names, the result is UNSUPPORTED and matched is unchanged. A difference in
 * any other attribute or in the RDN structure still returns OK with matched
 * zero. Domain label validity beyond ASCII is a separate check.
 * Workspace holds two prepared attributes and one byte per RDN attribute.
 * Work covers traversed bytes, scalar processing and ordering moves. All
 * writable ranges must be disjoint from each other and from the inputs.
 * Workspace and work may change on failure. matched changes only on OK. */
TC_TLV_result TC_X509_name_equal(TC_bytes left, TC_bytes right, const TC_TLV_limits* limits,
                                 const TC_X509_name_workspace* workspace, size_t* work,
                                 int* matched);
TC_TLV_result TC_X509_name_within(TC_bytes name, TC_bytes subtree, const TC_TLV_limits* limits,
                                  const TC_X509_name_workspace* workspace, size_t* work,
                                  int* matched);
/* Check issuer-name linkage before asking the provider to verify the signature.
 * issuer_name/key may come from a candidate issuer or a configured trust anchor.
 * VALID covers this link only. Issuer trust, CA authorization, validity, path
 * and revocation checks are separate.
 * Inputs and provider context must not overlap scratch or work. */
TC_X509_signature_result
TC_X509_issuer_check(const TC_X509_certificate* certificate, TC_bytes issuer_name,
                     const TC_X509_public_key* issuer_key,
                     const TC_X509_signature_provider* provider, const TC_TLV_limits* limits,
                     const TC_X509_name_workspace* workspace, size_t* work);

typedef struct {
  TC_bytes oid, value;
  int critical;
} TC_X509_extension;
typedef struct {
  TC_bytes key_identifier, issuer, serial;
  int has_key_identifier, serial_negative;
} TC_X509_authority_key_identifier;
/* Extension-value decoders.
 * Each decoder and reader init below takes one complete extension value, the
 * bytes inside the extnValue OCTET STRING, unless it names a contents span.
 * Returned spans borrow those bytes, which must stay unchanged while the
 * spans are used. max_elements counts the outer element and every element the
 * decoder reads beneath it. max_depth counts the constructed levels it opens,
 * the outer SEQUENCE included. A constructed field returned as a span, such as
 * an AKI issuer or a name-constraint list, counts as one element. Decode it
 * under its own limits. A reader's next spends the budget left by earlier
 * calls, so the limits bound the whole list. Exhausted limits return LIMIT.
 * Malformed or truncated values return INVALID. NULL arguments return
 * ARGUMENT. Outputs, and reader state for next, change only on OK. */

/* Identifiers have no assumed hash or fixed length. Authority issuer and
 * serial must occur together. issuer contains GeneralNames contents for
 * TC_X509_general_names_contents_init. Serial retains its signed INTEGER
 * contents. Empty AuthorityKeyIdentifier is syntactically valid.
 * Certificate-profile requirements and issuer selection are separate checks. */
TC_TLV_result TC_X509_authority_key_identifier_read(TC_bytes value, const TC_TLV_limits* limits,
                                                    TC_X509_authority_key_identifier* out);
TC_TLV_result TC_X509_subject_key_identifier_read(TC_bytes value, const TC_TLV_limits* limits,
                                                  TC_bytes* out);
typedef struct {
  unsigned type;
  TC_bytes encoded, value;
} TC_X509_general_name;
/* GeneralNames reader for subject/issuer alternative names, AKI issuers and
 * CRL names. Name-constraint subtrees use the subtree reader below. type is
 * the ASN.1 choice number (0..8). IP addresses are 4 or 16 bytes. Spans borrow
 * input. x400Address and ediPartyName retain their DER structure. Their
 * schemas and otherName's OID-specific value require caller interpretation.
 * init binds the input, limits and frames. frames need one entry per
 * constructed level inside one GeneralName. next walks each name's complete
 * tree and charges every nested element to the limits. Consume through END
 * to check the full list. Frames may change on failure. Reader and out
 * change only on OK. Input, frames, reader and out must be disjoint. Keep
 * the input and frames alive and unchanged while the reader is used. */
typedef struct {
  TC_TLV_reader reader;
  TC_TLV_frames frames;
} TC_X509_general_names_reader;
/* encoded is a complete, nonempty GeneralNames SEQUENCE, such as a
 * subjectAltName or issuerAltName extension value. */
TC_TLV_result TC_X509_general_names_init(TC_X509_general_names_reader* reader, TC_bytes encoded,
                                         const TC_TLV_limits* limits, TC_TLV_frames frames);
/* contents holds GeneralNames fields without their SEQUENCE header, such as
 * authority_key_identifier.issuer or a CRL fullName. limits cover contents
 * alone. Empty contents return END from the first next. */
TC_TLV_result TC_X509_general_names_contents_init(TC_X509_general_names_reader* reader,
                                                  TC_bytes contents, const TC_TLV_limits* limits,
                                                  TC_TLV_frames frames);
TC_TLV_result TC_X509_general_name_next(TC_X509_general_names_reader* reader,
                                        TC_X509_general_name* out);
typedef struct {
  TC_bytes permitted, excluded;
} TC_X509_name_constraints;
/* Decode the two optional, nonempty subtree lists. At least one is required.
 * Spans contain the IMPLICIT sequence contents, without a SEQUENCE wrapper.
 * Individual GeneralSubtree values still require decoding and name matching.
 * out is unchanged on failure. */
TC_TLV_result TC_X509_name_constraints_read(TC_bytes value, const TC_TLV_limits* limits,
                                            TC_X509_name_constraints* out);
typedef struct {
  TC_X509_general_name base;
  uint32_t minimum, maximum;
  int has_maximum;
} TC_X509_general_subtree;
/* GeneralSubtrees reader over a permitted or excluded contents span from
 * TC_X509_name_constraints_read. Consume through END. IP bases contain address
 * and mask (8 or 32 bytes). Distances above UINT32_MAX return LIMIT. RFC 5280
 * path validation requires minimum zero and maximum absent. This decoder
 * retains other encoded values. limits cover contents alone. frames need one
 * entry per constructed level inside one GeneralSubtree. Binding, budget,
 * borrowing and failure rules match the GeneralNames reader. */
typedef struct {
  TC_TLV_reader reader;
  TC_TLV_frames frames;
} TC_X509_general_subtrees_reader;
TC_TLV_result TC_X509_general_subtrees_init(TC_X509_general_subtrees_reader* reader,
                                            TC_bytes contents, const TC_TLV_limits* limits,
                                            TC_TLV_frames frames);
TC_TLV_result TC_X509_general_subtree_next(TC_X509_general_subtrees_reader* reader,
                                           TC_X509_general_subtree* out);
/* Test a decoded name against one subtree. Different name forms do not match,
 * except SmtpUTF8Mailbox otherName follows rfc822Name constraints (RFC 9598).
 * Supports directoryName, dNSName, rfc822Name, URI and CIDR iPAddress ranges. DNS constraints
 * include the base domain. A leading dot restricts them to proper subdomains.
 * Email constraints match an exact host, or proper subdomains with a leading
 * dot (RFC 9549). Mailbox-specific constraints and address literals return
 * UNSUPPORTED, as do DNS wildcards, other forms and non-default distances.
 * URI constraints use the email host/domain rules. Missing authority hosts and
 * IP-literal hosts return INVALID. Percent-encoded unreserved host characters
 * are decoded for matching, and the decoded host must be a valid DNS host.
 * SmtpUTF8Mailbox requires a non-ASCII local part and lowercase domain labels.
 * IDNA A-label validation is separate. Workspace is required for directoryName
 * only. Input objects/spans, workspace, work and matched must be disjoint.
 * Workspace/work may change on failure. matched changes only on OK. */
TC_TLV_result TC_X509_general_name_within(const TC_X509_general_name* name,
                                          const TC_X509_general_subtree* subtree,
                                          const TC_TLV_limits* limits,
                                          const TC_X509_name_workspace* workspace, size_t* work,
                                          int* matched);
typedef struct {
  TC_TLV_frames frames;
  const TC_X509_name_workspace* names;
} TC_X509_constraint_workspace;
/* Check one decoded name against one certificate's constraint lists. A name
 * must match at least one permitted subtree of its form, if any, and no
 * excluded subtree. Both lists are fully parsed. Empty spans mean no constraints.
 * Apply each issuer's lists separately to intersect their permitted sets.
 * names is needed only for directoryName. Input, scratch, work and permitted
 * must be disjoint. Scratch/work may change on failure. permitted changes only
 * on OK. */
TC_TLV_result TC_X509_name_constraints_check(const TC_X509_general_name* name,
                                             const TC_X509_name_constraints* constraints,
                                             const TC_TLV_limits* limits,
                                             const TC_X509_constraint_workspace* workspace,
                                             size_t* work, int* permitted);
/* Apply one issuer's constraints to a certificate returned by TC_X509_read.
 * Checks the nonempty subject DN and every subjectAltName. Without that
 * extension, subject emailAddress attributes also receive email constraints.
 * The path validator decides when the self-issued exception applies.
 * Limits bound each parsed structure. Work bounds their combined processing.
 * Workspace and output rules match name_constraints_check. */
TC_TLV_result TC_X509_certificate_names_check(const TC_X509_certificate* certificate,
                                              const TC_X509_name_constraints* constraints,
                                              const TC_TLV_limits* limits,
                                              const TC_X509_constraint_workspace* workspace,
                                              size_t* work, int* permitted);
/* Pass certificate.extensions, or {NULL, 0} for an absent extension sequence.
 * limits cover the Extensions SEQUENCE under the extension-value rules above.
 * next checks one Extension's fields and returns its extnValue contents.
 * Consume through END to check every extension. */
TC_TLV_result TC_X509_extensions_init(TC_TLV_reader* reader, TC_bytes encoded,
                                      const TC_TLV_limits* limits);
TC_TLV_result TC_X509_extension_next(TC_TLV_reader* reader, TC_X509_extension* out);

typedef struct {
  TC_bytes issuer_policy, subject_policy;
} TC_X509_policy_mapping;
/* Pass the PolicyMappings extension value. init checks the outer sequence.
 * next validates each OID pair and rejects mappings to or from anyPolicy.
 * Consume through END to check every pair. */
TC_TLV_result TC_X509_policy_mappings_init(TC_TLV_reader* reader, TC_bytes value,
                                           const TC_TLV_limits* limits);
TC_TLV_result TC_X509_policy_mapping_next(TC_TLV_reader* reader, TC_X509_policy_mapping* out);

typedef struct {
  TC_bytes oid, qualifiers;
} TC_X509_policy;
typedef struct {
  TC_TLV_reader reader;
  TC_bytes* seen;
  size_t capacity, count;
} TC_X509_policy_reader;
/* Pass the CertificatePolicies extension value. seen has one slot per
 * policy, used to reject duplicate identifiers. More policies than capacity
 * return LIMIT. Input, seen, reader and output must be disjoint. next checks
 * PolicyInformation structure. qualifiers retain their complete SEQUENCE
 * encoding for separate interpretation. The qualifier SEQUENCE counts as one
 * element here. An absent qualifier sequence is {NULL, 0}.
 * Consume through END. A failed next leaves reader, seen and out unchanged. */
TC_TLV_result TC_X509_policies_init(TC_X509_policy_reader* reader, TC_bytes value,
                                    const TC_TLV_limits* limits, TC_bytes* seen, size_t capacity);
TC_TLV_result TC_X509_policy_next(TC_X509_policy_reader* reader, TC_X509_policy* out);

typedef struct {
  TC_bytes oid, value;
} TC_X509_policy_qualifier;
/* Pass policy.qualifiers, including {NULL, 0} when absent. value retains its
 * DER tag and length and counts as one element. OID-specific syntax and
 * acceptance are caller checks. */
TC_TLV_result TC_X509_policy_qualifiers_init(TC_TLV_reader* reader, TC_bytes qualifiers,
                                             const TC_TLV_limits* limits);
TC_TLV_result TC_X509_policy_qualifier_next(TC_TLV_reader* reader, TC_X509_policy_qualifier* out);

typedef struct {
  int ca, has_path_length;
  uint32_t path_length;
} TC_X509_basic_constraints;
/* DistributionPointName wrapper and its GeneralNames or relative-RDN contents. */
typedef struct {
  TC_bytes encoded, contents;
  int relative;
} TC_X509_distribution_name;
TC_TLV_result TC_X509_basic_constraints_read(TC_bytes value, const TC_TLV_limits* limits,
                                             TC_X509_basic_constraints* out);
/* Mask bit n is ASN.1 KeyUsage bit n, independent of encoded byte order. */
enum {
  TC_KEY_USAGE_DIGITAL_SIGNATURE = 1u << 0,
  TC_KEY_USAGE_CONTENT_COMMITMENT = 1u << 1,
  TC_KEY_USAGE_KEY_ENCIPHERMENT = 1u << 2,
  TC_KEY_USAGE_DATA_ENCIPHERMENT = 1u << 3,
  TC_KEY_USAGE_KEY_AGREEMENT = 1u << 4,
  TC_KEY_USAGE_CERT_SIGN = 1u << 5,
  TC_KEY_USAGE_CRL_SIGN = 1u << 6,
  TC_KEY_USAGE_ENCIPHER_ONLY = 1u << 7,
  TC_KEY_USAGE_DECIPHER_ONLY = 1u << 8,
  TC_KEY_USAGE_ALL = (1u << 9) - 1
};
/* Returns a combination of the KeyUsage masks above. */
TC_TLV_result TC_X509_key_usage_read(TC_bytes value, const TC_TLV_limits* limits, uint16_t* out);

/* Decode the nonempty sequence of key-purpose OIDs inside an EKU extension.
 * capacity counts span slots. Input, oids and count must be disjoint. On
 * failure neither output changes. More OIDs than capacity return LIMIT.
 * Unknown purpose OIDs are retained. */
TC_TLV_result TC_X509_extended_key_usage_read(TC_bytes value, const TC_TLV_limits* limits,
                                              TC_bytes* oids, size_t capacity, size_t* count);

typedef struct {
  int has_require_explicit_policy, has_inhibit_policy_mapping;
  uint32_t require_explicit_policy, inhibit_policy_mapping;
} TC_X509_policy_constraints;
/* At least one field must be present. Counts above UINT32_MAX return LIMIT.
 * A present zero count applies immediately. An absent field adds no constraint. */
TC_TLV_result TC_X509_policy_constraints_read(TC_bytes value, const TC_TLV_limits* limits,
                                              TC_X509_policy_constraints* out);
/* InhibitAnyPolicy is a nonnegative INTEGER. Decode it with TC_DER_uint32. */

#ifdef __cplusplus
}
#endif
#endif
