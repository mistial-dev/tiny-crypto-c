<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# CMS parsing and signature verification

CMS support has two layers:

- `<tiny_crypto/cms.h>` (`TINY_CRYPTO_ENABLE_CMS`) parses metadata, hashes content and verifies
  signatures under a caller-selected public key. It depends on X.509 key parsing, BER framing and
  the PIV/TWIC identifier classifier used by the PIV signed attributes.
- `<tiny_crypto/cms_validation.h>` (`TINY_CRYPTO_ENABLE_CMS_VALIDATION`) adds signer discovery,
  certificate paths and revocation. It requires the X.509 path and revocation features.
  Applications that only parse or verify signatures can omit it.

Every reader and verifier takes a [verification policy](#verification-policy). [PIV and TWIC
objects](#piv-and-twic-objects) build on both layers.

Readers return spans that borrow the input. Use a result only after success and keep the input
unchanged while using it. Frames are reusable after each call. Storage follows [Input stability and
overlap](api.md#input-stability-and-overlap). Bad storage arguments return `TC_TLV_ARGUMENT` before
any write. Other failures may consume work and scratch and leave the output unchanged.
`TC_TLV_LIMIT` leaves the message's validity undetermined.

## SignedData envelopes

`TC_CMS_signed_data_read` reads a complete ContentInfo carrying SignedData. It checks envelope
framing, digest AlgorithmIdentifier syntax and SignedData version consistency. CMS envelopes allow
definite and indefinite BER lengths, so enable `TINY_CRYPTO_TLV_ENABLE_BER`. `policy.envelope`
selects BER or DER framing, separately from the signed-attribute encoding.

`content_type` holds the OID contents, and the other fields keep their complete encodings. `content`
is an OCTET STRING whose payload may be split into nested chunks. `has_content` distinguishes
detached content from an embedded empty value. The certificate, revocation and signer collections
need further parsing. Validation reads certificates from the embedded CertificateSet and ignores the
embedded RevocationInfoChoices, taking revocation status from the caller's CRL index.

`TC_CMS_digest_algorithms_check` checks that a signer's digest algorithm appears in
`digestAlgorithms` with valid parameters, as RFC 5652 section 5.1 requires, and returns the
recognized hash. An unlisted digest returns `TC_TLV_INVALID` and an unknown selected digest returns
`TC_TLV_UNSUPPORTED`. Other listed digests need only valid syntax, because they may belong to other
signers. The signature-only verifiers leave this check to the caller.

The fixed-workspace [example](../examples/cms_reader.c) and its [header](../examples/cms_reader.h)
read envelopes up to 16 KiB for C and C++ callers. Compile the source with your application and link
`tiny-crypto-c::tiny-crypto-c`.

## SignerInfo

`TC_CMS_signer_info_read` reads one complete SignerInfo with `policy.envelope` framing. Version 1
identifies the signer by issuer Name and serial number, version 3 by subject key identifier, and the
reader checks that the identifier matches the version. Names and algorithm identifiers get syntax
checks only, so algorithms the library lacks still parse.

`issuer` keeps its Name encoding. `serial` holds the INTEGER bytes, including sign padding.
`subject_key_id` and `signature` keep their complete OCTET STRING encodings, including BER chunks,
so decode them before passing their contents to a cryptographic API. The SignerInfo signature covers
only the signed attributes.

To read the signerInfos SET, pass `signed_data.signers` and the policy to `TC_CMS_signers_init`,
then call `TC_CMS_signer_next` until it returns `TC_TLV_END`, sharing one work counter. Init checks
the SET framing and each next call checks one SignerInfo, both under `policy.envelope`. A failure
leaves the reader position and output unchanged. An exhausted reader returns `END` even with zero
work left. SignedData may hold no signers, and an empty collection authenticates nothing.

The example also provides `example_read_cms_signer`, with BER framing and the envelope bounds, and
`example_parse_cms_signers`, which propagates member errors and treats only `TC_TLV_END` as success.

## Verification policy

`TC_CMS_verification_policy` holds every CMS encoding and attribute choice. Readers and verifiers
copy it at entry. A zero-initialized policy selects the RFC 5652 defaults. Unknown enum values
return an argument error.

| Field              | Default                               | Other values                                                                   |
| ------------------ | ------------------------------------- | ------------------------------------------------------------------------------ |
| `envelope`         | `TC_CMS_ENVELOPE_BER`                 | `TC_CMS_ENVELOPE_DER` restricts SignedData and SignerInfo framing to DER       |
| `attributes`       | `TC_CMS_ATTRIBUTES_DER`               | `TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER` for signatures over unsorted attributes |
| `rsa_parameters`   | `TC_CMS_RSA_PARAMETERS_NULL`          | `TC_CMS_RSA_PARAMETERS_ALLOW_ABSENT`                                           |
| `attribute_oids`   | `TC_CMS_ATTRIBUTE_OIDS_CMS`           | `TC_CMS_ATTRIBUTE_OIDS_PIV`, `TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC`                  |
| `other_attributes` | `TC_CMS_OTHER_ATTRIBUTES_SKIP_LISTED` | `TC_CMS_OTHER_ATTRIBUTES_REJECT`, `TC_CMS_OTHER_ATTRIBUTES_SKIP_ALL`           |

`TC_CMS_path_options.verification` and `TC_validation_options.verification` embed the same policy.
The PIV and TWIC credential validators replace `attribute_oids` with the card profile's identifier
set.

### RSA parameters

`TC_CMS_RSA_PARAMETERS_NULL` requires a `NULL` parameter for CMS `rsaEncryption`, as RFC 3370
section 3.2 specifies. Some captured PIV biometric signatures omit it. To accept them, select
`TC_CMS_RSA_PARAMETERS_ALLOW_ABSENT`:

```c
TC_CMS_verification_policy policy = {
    .attributes = TC_CMS_ATTRIBUTES_DER,
    .rsa_parameters = TC_CMS_RSA_PARAMETERS_ALLOW_ABSENT,
    .attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV,
};
```

Present parameters must still encode `NULL`. Certificate algorithms and RSA signature padding keep
their standard checks.

### Attribute identifiers

`attribute_oids` selects the signed attributes the reader interprets:

- `TC_CMS_ATTRIBUTE_OIDS_CMS`: contentType, messageDigest and signingTime (RFC 5652 section 11),
  SMIMECapabilities (RFC 8551 section 2.5.2) and entryUUID (RFC 4530).
- `TC_CMS_ATTRIBUTE_OIDS_PIV`: adds pivSigner-DN and pivFASC-N from FIPS 201-3 Table B-2. It returns
  `TC_TLV_UNSUPPORTED` for twicFASC-N under every `other_attributes` value, so a card identifier is
  never skipped.
- `TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC`: also accepts twicFASC-N, the TWIC Part 2 v5 section 6 pair of
  pivFASC-N.

The PIV sets require `TINY_CRYPTO_ENABLE_PIV_OIDS`.

`other_attributes` handles every attribute outside the selected set:

- `TC_CMS_OTHER_ATTRIBUTES_SKIP_LISTED` skips cmsAlgorithmProtection (RFC 6211) and
  signingCertificate and signingCertificateV2 (RFC 5035). Each must carry one SEQUENCE value. Other
  attributes return `TC_TLV_UNSUPPORTED`.
- `TC_CMS_OTHER_ATTRIBUTES_REJECT` returns `TC_TLV_UNSUPPORTED` for all of them.
- `TC_CMS_OTHER_ATTRIBUTES_SKIP_ALL` also skips any other attribute with a nonempty value set. DER
  attributes also need their values in SET OF order.

RFC 6211 section 3.1 applies its algorithm comparison to validators that support the attribute, and
RFC 5035 section 2 recommends recognizing the signing-certificate attributes. An application that
relies on them compares the signer certificate hash after validation, or selects
`TC_CMS_OTHER_ATTRIBUTES_REJECT`. A skipped attribute stays covered by the signature. A repeated
attribute type returns `TC_TLV_INVALID`. Under the CMS set, a PIV signer name or FASC-N is an
outside attribute, so `SKIP_ALL` skips it and path building performs no signer-name binding.

## Signed attributes

Pass the complete `SignerInfo.signedAttrs` field, including its implicit `[0]` tag, to
`TC_CMS_signed_attributes_read`.

`policy.attributes` selects `TC_CMS_ATTRIBUTES_DER` for RFC 5652 encoding, or
`TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER` for TWIC/MyID compatibility with
`TINY_CRYPTO_TLV_ENABLE_BER=ON`. The library uses the selected mode as given, without card detection
or a retry in another mode. The compatibility mode accepts definite BER lengths and preserves
attribute order. It rejects indefinite lengths, duplicate attributes, a missing content-type or
message-digest, and malformed values.

```c
#include <tiny_crypto/cms.h>

TC_TLV_result read_attributes(TC_bytes input,
    const TC_CMS_verification_policy *policy, TC_CMS_signed_attributes *attributes)
{
    const TC_TLV_limits limits = {4096, 4096, 64, 8};
    TC_TLV_frame frames[8];
    size_t work = 16384;
    return TC_CMS_signed_attributes_read(input, policy, &limits,
        (TC_TLV_frames){frames, 8}, &work, attributes);
}
```

Choose limits for the largest object your application accepts.

`smime_capabilities` borrows the encoded capability sequence with its tag and length. The reader
checks the single attribute/value rule and that each capability is an OID with at most one parameter
value ([RFC 8551 section 2.5.2](https://datatracker.ietf.org/doc/html/rfc8551#section-2.5.2)).
Unknown capabilities stay opaque, and the list keeps the signer's preference order. Algorithm
selection and local policy ignore it. Interpret it only after signature and trust validation.

`signer_name` borrows the Name in `pivSigner-DN` (`2.16.840.1.101.3.6.5`), read under the PIV
identifier sets. The reader validates its X.509 name structure and requires a single value. CMS path
building matches it against the candidate certificate's subject. Callers of the signature-only APIs,
which take a public key, bind the certificate to the name themselves. A PIV CHUID profile requires
this attribute.

`fascn_oid` keeps the PIV or TWIC FASC-N identifier that matched `policy.attribute_oids`, and
twicFASC-N is read only under `TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC`. `fascn_octets` borrows the encoded
OCTET STRING with its tag and length. The reader requires 25 value bytes and rejects duplicate
FASC-N attributes, including a PIV/TWIC pair. DER requires a primitive value, and the BER mode also
accepts definite-length chunks. Read a primitive value with the TLV reader, or walk the chunks of a
fragmented value in order.

`entry_uuid_octets` borrows the encoded `entryUUID` value (`1.3.6.1.1.16.4`), a 16-byte OCTET STRING
([RFC 4530 section 2.1](https://www.rfc-editor.org/rfc/rfc4530.html#section-2.1)), with the same
chunk handling and duplicate checks as FASC-N. Credential validation binds both identifiers to the
CHUID.

To verify, hash the two `signature_input` spans in order. They substitute the SET OF tag and keep
the original length and content bytes, so compatibility-mode attributes are hashed as received.

## Content digests

`TC_CMS_content_digest` hashes `signed_data.content` directly from its BER encoding, including
nested definite or indefinite chunks. Enable BER and the selected hash. It uses one stack hash
context and caller-owned frames, with no message-sized copy. Success writes only the digest bytes,
and failure leaves the buffer unchanged.

`TC_CMS_content_digest_check` compares parsed signed attributes with a computed digest and the
SignedData content type, given as OID contents. Hash the content value bytes without OCTET STRING
headers, chunk headers and end markers, using the SignerInfo digest algorithm. Compute each distinct
digest once and reuse it across signers. The digest can come from the library or an external
provider, and the comparison itself needs no hash support in the build.

Check both the return status and `matched`. `TC_TLV_OK` with `matched == 0` means the content type
or digest differs. Errors preserve `matched`, and `TC_TLV_LIMIT` counts as neither a match nor a
mismatch. A match still requires signature and signer trust validation.

## Verify a signer

`TC_CMS_signer_verify_content` hashes content and verifies one parsed SignerInfo with a supplied
public key. A `TC_CMS_signer_verify_request` names the signer, the envelope's content type, the
verification policy, the key, the signature provider and the parsing limits:

```c
const TC_CMS_signer_verify_request request = {
    &signer, signed_data.content_type, policy, &key, &provider, &limits};
TC_X509_signature_result result = TC_CMS_signer_verify_content(
    &request, signed_data.content, TC_CMS_CONTENT_BER_OCTETS, &workspace, &work);
```

The content and signature hashes come from the signer's algorithm identifiers. Use
`TC_CMS_CONTENT_BER_OCTETS` with `signed_data.content`, or `TC_CMS_CONTENT_RAW` for application
message bytes, where NULL/0 is an empty message. Raw content is bounded by `limits.max_input` and
`limits.max_value`, and encoded content also by the framing limits. Hashing is charged to the work
budget and reuses one hash context and digest buffer, with no message-sized copy.

`TC_CMS_signer_verify_digest` takes a cached or external digest computed with the signer's
`digest_algorithm`, so several signers can share one digest. Both APIs handle a PSS signer whose
signed-attribute hash differs. The verifier checks attribute binding, hashes the original signed
bytes and calls the provider's digest operation. Without signed attributes, only `id-data` content
is allowed.

Verification ignores `unsigned_attributes`, which RFC 5652 section 5.3 leaves outside the signature.
Countersignatures (RFC 5652 section 11.4) and other unsigned attributes stay unauthenticated, so
parse and authenticate any you rely on separately.

`TC_CMS_signature_workspace` holds parser frames and optional signature storage. A primitive
signature is borrowed directly. Fragmented BER signatures are joined in the storage, so size it for
the largest signature. Insufficient capacity returns `TC_X509_SIGNATURE_LIMIT`.

`example_verify_cms_content` and `example_verify_cms_digest` use 16 frames and a 384-byte signature
buffer, enough for RSA through 3072 bits and the supported ECDSA signatures, with DER signed
attributes and an explicit work budget. Give the native provider its own workspace, as in [signature
verification](x509-crypto.md).

`TC_X509_SIGNATURE_VALID` confirms the signature under the supplied key. Establishing the signer and
trust also takes selecting the signer certificate, validating its path and usage, applying
revocation and algorithm policy, and checking `digestAlgorithms` membership.

## Find a signer path

The APIs from here on come from `<tiny_crypto/cms_validation.h>`.

`TC_CMS_signer_path_build` selects a certificate by issuer/serial or subject key identifier,
verifies the signature against a supplied content digest and builds a path to an
application-provided trust anchor. `TC_CMS_signer_path_request` holds a parsed SignerInfo, the
envelope's content type, the digest computed with the signer's `digest_algorithm`, and
`signed_data.certificates`, or `{NULL, 0}` when certificates are external only. `signer_certificate`
optionally requires one DER signer certificate, and other certificates remain available as issuers.

Trust anchors come only from the source. Embedded certificates and the source can supply the signer
and intermediates. Hold the source snapshot and its returned bytes stable during the call and while
using the result. The call performs no network fetching.

`TC_CMS_path_options` fields:

- `path`: time, usage, policy, provider and path limits for the authenticated object, as in
  [X.509 path validation](x509-path.md#inputs). This call ignores `path.max_work`, and the supplied
  work counter covers indexing and every candidate attempt.
- `verification`: the [verification policy](#verification-policy).
- `max_candidates`: all embedded choices plus external candidates.
- `max_candidate_bytes`: their combined encoding size, including embedded collection framing.

`TC_CMS_path_workspace` combines validation and search scratch, a certificate-span index, 64 bytes
of signed-attribute digest scratch and optional fragmented-signature storage. Size the index for
every X.509 candidate, including intermediates. Other certificate formats count against the record
and byte limits without an index slot. The index borrows bytes, and external candidates are fetched
once. CMS and path processing share the parsing frames and name scratch. The signed digest lives
while candidates for one signer are checked and is cleared when the search ends.

On success, `result.path` holds the path anchor-issued first and signer last, and `anchor_index`
identifies the source trust anchor. `validation.work_used` includes indexing and failed attempts.
Keep the input bytes, source snapshot, search path and policy output alive while using the result.
Reusing the workspace invalidates its path and policy outputs.

An invalid candidate signature or path moves on to the next candidate. Source and provider errors
stop discovery. Unresolved algorithms and resource limits keep their own status. Failures preserve
the result object, and scratch and work may be consumed after the storage preflight.

The application applies the rest of the SignedData policy: revocation, acceptable algorithms, signer
membership and `digestAlgorithms`.

`example_find_cms_signer_path` in [cms_validate.c](../examples/cms_validate.c) has storage for eight
certificates, four path entries and signatures through RSA-3072, and shares the [workspace
setup](../examples/x509_workspace.h) of the X.509 examples. Allocate `ExampleCMSPathWorkspace`
outside a small task stack and check for `TC_X509_PATH_VALID` before using the result. Larger inputs
return `LIMIT`.

## Validate a SignedData signer

`TC_CMS_signed_data_path_build` takes the complete encoded envelope and handles parsing, content
hashing, signer selection and path construction, with the options, workspace and trust source of the
prehashed API. Use it when the application holds the whole CMS object and needs no cached digests.
Its `TC_CMS_validation_request` holds:

- The encoded CMS object.
- `signer_index`: a zero-based member of `signerInfos` in encoded order. The function checks every
  signer's schema with the envelope version and authenticates only the selected signer. An absent
  index returns `INVALID`, so an empty signer set always fails.
- The expected content type as OID contents. A different envelope content type returns
  `TC_X509_PATH_INVALID`.
- Detached content spans. For attached content, pass zero spans, and the function hashes the
  envelope's OCTET STRING value without BER headers and chunk markers. A detached span with an
  attached envelope returns `ERROR`. For a detached envelope, pass the raw message as one or more
  spans hashed in array order, where zero spans is an empty message. Malformed attached content is
  never retried as detached.
- `signer_certificate`: a borrowed DER certificate when the application requires a particular
  signer. The validator checks its SignerInfo identity, signature, path and revocation, and other
  message and source certificates remain available as issuers. `{NULL, 0}` discovers the signer
  from the message and source.

The selected signer's digest must appear in `digestAlgorithms`, a validation policy that [RFC 5652
section 5.1](https://www.rfc-editor.org/rfc/rfc5652.html#section-5.1) permits. SHA identifiers
accept absent or NULL parameters, including BER NULL encodings, and these compare as equal. Unknown
algorithms for other signers are allowed. An unknown or disabled selected hash returns
`UNSUPPORTED`. The content hash follows `digestAlgorithm`, even when PSS uses a different hash for
signed attributes.

Content is hashed once, before candidates are tried, and the digest is wiped after path
construction. The work counter covers the whole operation, including failed candidates.

`example_check_cms_signed_data` in [cms_validate.c](../examples/cms_validate.c) initializes the
workspace and propagates the result. Supply time, usage, policy and providers in `options.path`,
candidate bounds in `options.max_candidates` and `options.max_candidate_bytes`, and encodings in
`options.verification`.

`TC_X509_PATH_VALID` confirms the selected signature and certificate path. The application applies
revocation and algorithm policy, and validates each signer explicitly when a protocol requires
several.

## Credential validation

`TC_CMS_credential_validate` combines signature, path and revocation validation. Its workspace adds
to the CMS path workspace a retained path-span array, one cache byte and one scope slot per CRL, a
caller-sized revocation-node array, and signer path and policy span arrays, as in the
[revocation workspace](x509-revocation.md#workspace). It checks the input and scratch ranges of
both phases before processing and checks borrowed source records as callbacks return them.

The application supplies a stable source, a CRL index and two policies with the same validation
time. Revocation uses the trust anchor selected during path construction. CRL freshness uses the
CRL-signer policy's time and clock skew, with no age bound (see
[freshness](x509-revocation.md#freshness)). Additional CRL signer certificates must come from the
held source. Include the root certificate as a candidate when it signs a CRL. The trust anchor
establishes trust, and the candidate supplies the CRL signer's certificate and extensions.

`TC_CREDENTIAL_VALID` confirms the selected signature, path and unrevoked status, and
`TC_CREDENTIAL_REVOKED` reports a revoked path certificate. Missing evidence follows the [revocation
evidence policy](validation.md#revocation-evidence-policy). The protocol's object profile,
credential identifiers and access policy need separate checks.

### Example

`example_validate_cms_credential` in [cms_validate.c](../examples/cms_validate.c) runs this workflow
on a held snapshot. Acquire the snapshot before the call and release it after the acceptance
decision, under the application's lock, and keep the CRL index bytes stable throughout. Supply the
expected content type, signer index, signed-attribute encoding, holder usage policy and
`TC_CMS_revocation_policy`, which holds the CRL index, CRL-signer path policy, candidate-byte limit,
delta policy and ordering policy.

Allocate `ExampleCMSCredentialWorkspace` outside a small task stack. It retains four path spans and
reuses CMS search scratch for revocation, with room for four CRLs and eight certificate
dependencies. Missing index storage, invalid revocation policy values and an index above the
example's CRL capacity are rejected before hashing or signature checks.

`example_validate_cms_from_store` acquires and releases the snapshot around the same workflow. Hold
the store lock through the call and the acceptance decision. It returns `TC_CREDENTIAL_UNAVAILABLE`
when nothing is published and releases the snapshot on every return path. The status holds no
borrowed views, so the workspace is reusable after the call.

### Command-line example

[cms_check.c](../examples/cms_check.c) loads a SignedData object with an attached payload, an
explicitly trusted root, one intermediate and their two complete CRLs, all DER. It checks signer
zero with the native provider at the supplied UTC time, with content type `id-data` and
digital-signature key usage. It uses the CMS identifier set with DER signed attributes, so it reads
content type, message digest, signing time, S/MIME capabilities and entryUUID, skips
cmsAlgorithmProtection, signingCertificate and signingCertificateV2, and returns `unsupported` for
others, including pivSigner-DN and the PIV/TWIC FASC-N.

Build against an installed library with X.509, EC and RSA enabled:

```sh
cmake -S . -B build-library -DTINY_CRYPTO_RESOURCE_PROFILE=desktop \
  -DTINY_CRYPTO_BUILD_TESTS=OFF -DTINY_CRYPTO_BUILD_BENCHMARKS=OFF \
  -DCMAKE_INSTALL_PREFIX="$PWD/build-install"
cmake --build build-library
cmake --install build-library
cmake -S examples/cms_check -B build-cms-check \
  -DCMAKE_PREFIX_PATH="$PWD/build-install"
cmake --build build-cms-check
./build-cms-check/cms_check signed-data.der root.der issuer.der \
  root.crl issuer.crl 20260908120000
```

Exit status is zero for valid signature, path and revocation evidence, one for a validation failure
and two for input or setup errors. The root file is a trust decision, so provision it through an
authorized channel.

The example reserves static buffers for a 16 KiB CMS object, two 4 KiB certificates and two 16 KiB
CRLs, and its RSA workspace supports keys through 3072 bits. Adapt these capacities and the object
policy to your application.

## PIV and TWIC objects

### Identifiers

`<tiny_crypto/piv_oid.h>` provides `TC_PIV_oid_identify` for OID contents. `TC_PIV_OIDS_ONLY`
accepts PIV identifiers and `TC_PIV_OIDS_TWIC_COMPATIBLE` also accepts the PIV/TWIC pairs listed in
[TWIC Part 2 v5, section
6](https://www.tsa.gov/sites/default/files/twic-nexgen-_-legacy-part-2-card-specification-v5.pdf).
The application chooses, and the choice applies to objects from either card application.
`TC_CMS_ATTRIBUTE_OIDS_PIV` and `TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC` map to these two profiles. Enable
the helper with `TINY_CRYPTO_ENABLE_PIV_OIDS` (`TC_ENABLE_PIV_OIDS`), which CMS support requires.

The result identifies certificate-policy, FASC-N, content-signing, card-authentication and
background-check OIDs. Each `TC_PIV_oid` value names one PIV/TWIC pair from the section 6 table, and
the header lists both names. `TC_PIV_OID_POLICY_COMMON` is `id-fpki-common-policy`
(`2.16.840.1.101.3.2.1.3.6`), paired with `id-TWIC-key-management` (`1.3.6.1.4.1.29138.2.1.3.6`).
PIV CHUID content, biometric content, signer-DN and the `id-fpki-common-piv-contentSigning` policy
have no TWIC pair in section 6 and are recognized under their PIV OIDs only. The TWIC
digital-signature policy has no PIV pair and is recognized in compatibility mode only. Unknown,
malformed and disabled identifiers return `TC_PIV_OID_UNKNOWN`. Keep the original OID bytes for
signature verification and path policy processing. Recognition grants no trust or permitted usage.

### Signed objects

Enable `TINY_CRYPTO_ENABLE_PIV_OBJECTS`, include `<tiny_crypto/piv_cms.h>` and call
`TC_PIV_CMS_read` with `TC_PIV_CMS_CHUID`, `TC_PIV_CMS_BIOMETRIC` or `TC_PIV_CMS_SECURITY`, the
Security Object profile with attached LDS content. The reader checks the external-signature layout
and required attributes from SP 800-73-5 Part 1 and SP 800-76-2, and the selected digest's
parameters and `digestAlgorithms` membership. Unknown selected hashes return `TC_TLV_UNSUPPORTED`.
`attribute_oids` must be `TC_CMS_ATTRIBUTE_OIDS_PIV` for PIV cards or
`TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC` for TWIC readers, and the same selection applies to the content
type (TWIC Part 2 v5 section 6).

`TC_PIV_CMS_BIOMETRIC` requires both FASC-N and entryUUID. Select `TC_PIV_CMS_BIOMETRIC_FIPS201_1`
explicitly for the FIPS 201-1 signature profile, where FASC-N stays mandatory and a present
entryUUID must match CHUID. Use the same profile for identifier matching and set
`TC_PIV_biometric_validation_request.signature_profile` when validating.

The result borrows the envelope, signer, attributes and optional certificate. Pass the certificate
to `TC_X509_read`, then check signer identity, usage, policy and trust with the content signature.

`TC_PIV_CMS_identifiers_match` compares the signed FASC-N and entryUUID with the credential's
25-byte FASC-N and 16-byte CHUID GUID. Pass the same stable buffers and `TC_PIV_CMS_kind` used by
the reader. Biometric signatures require both attributes, CHUID signatures permit either to be
absent, and each present attribute must match. The comparison scans OCTET STRING chunks and writes
`matched` only on success, with zero for a mismatch. Malformed data and exhausted limits return an
error. Also bind the CHUID's signed FASC-N and GUID to the card-authentication certificate with
`TC_PIV_card_identifiers_match`.

### Biometric CBEFF objects

`TC_PIV_CBEFF_read` takes a biometric object's `BC` value and returns the biometric record, CMS
signature, header FASC-N and complete signed-content span. It checks the version and block lengths
without copying payload bytes. Pass `signature` to `TC_PIV_CMS_read` and `signed_content` to content
verification.

`TC_PIV_CBEFF_metadata_read` checks the header's calendar values, date ordering, security options,
quality range, creator text and reserved bytes, and returns format identifiers and the encryption
flag. Creation, valid-from and valid-until use `TC_X509_time`, and the caller decides how they
compare with its current time.

`TC_PIV_CBEFF_format_identify` recognizes the fingerprint image, fingerprint template, iris image
and facial image header tuples in SP 800-76-2 Table 15, checking owner, format, biometric type and
processing bits together. Use it to select a record reader. Validate the record and handle any
encryption before using its data.

TWIC Part 2 Appendix G requires checking fingerprint minutiae before interpreting header quality. A
quality of `-2` can accompany usable templates, so inspect the ANSI/INCITS 378 record to decide
whether matching is possible.

TWIC's enciphered fingerprint `BC` value wraps the complete CBEFF object in TPK encryption and
PKCS#7 padding (Part 2, section 4.6.4). Decrypt it and validate the padding before using these
readers. The header's encryption flag describes the biometric data block inside CBEFF.

### CHUID content

`TC_PIV_CHUID_read` returns two borrowed `signed_content` spans for a signed CHUID. They cover the
encoded fields before and after the `3E` signature field, including the trailing `FE 00`, and
exclude the outer `53` wrapper and a leading Buffer Length (`EE`) field (SP 800-73-4 Part 1 section
3.1.2). Hash them in order with the signer's digest algorithm, keeping the original tag and length
bytes, including nonminimal lengths the reader accepts, and pass the digest to
`TC_CMS_signer_verify_digest`. Both spans are empty for unsigned TWIC CHUIDs, which need the
unsigned profile selected explicitly and their own TWIC authentication workflow.

`TC_CMS_signed_data_path_build` accepts the spans directly as detached content: pass
`chuid.signature` as the envelope and `chuid.signed_content` with a count of two. The CMS credential
examples carry them through signature, path and revocation validation:

```c
TC_CMS_validation_request request = {
    chuid.signature, 0, expected_content_type, chuid.signed_content, 2, {NULL, 0}
};
TC_credential_status status = example_validate_cms_credential(
    &request, snapshot, &options, &revocation, &work, &workspace);
```

Keep the request, spans, source buffers and CRL index stable until the acceptance decision. The
CHUID profile and identifier checks come from `TC_PIV_CHUID_validate`.

### Validate a CHUID against a card certificate

`TC_PIV_CHUID_validate` in `<tiny_crypto/credential.h>` combines the signed CHUID checks. First
validate the slot 9E certificate and read its identifiers with `TC_PIV_card_identifiers_read`. Hold
the certificate, CHUID, trust source and CRL index through the decision.

```c
TC_PIV_CHUID_validation_request request = {
    .encoded = encoded_chuid,
    .encoding = TC_PIV_CHUID_CONTAINER,
    .profile = TC_TWIC_NEXGEN_CARD,
    .chuid_profile = TC_CHUID_PROFILE_TWIC_SIGNED,
    .twic_reader_policy = 0,
    .card = &card_identifiers,
    .card_expiration = &card_certificate.not_after
};
TC_CMS_path_workspace path_workspace = /* caller-owned arrays and capacities */;
TC_CMS_credential_workspace workspace = {
    &path_workspace, held_path, path_capacity,
    crl_states, crl_capacity, revocation_nodes, node_capacity,
    crl_scopes, crl_capacity, signer_path, path_capacity,
    signer_policies, policy_capacity
};
TC_validation_trust trust = { &snapshot->source, &crl_index };
TC_validation_context context;
if (TC_validation_context_init(&trust, &validation_options,
        &workspace, &context) != TC_RESULT_OK) {
    return TC_CREDENTIAL_ERROR;
}
TC_PIV_CHUID_report accepted;
TC_credential_status status = TC_PIV_CHUID_validate(
    &request, &context, &work, &accepted);
if (status != TC_CREDENTIAL_VALID) {
    /* Report the validation outcome and end this credential check. */
    return status;
}
```

`profile` selects the card OID policy and `chuid_profile` the CHUID schema. `card` and
`card_expiration` bind the CHUID to the validated card certificate. Set `twic_reader_policy` to 1 to
accept the registered TWIC aliases and reader identifier rules for a PIV application.

One `TC_validation_options` value supplies time, provider, certificate and CRL-signer policies,
limits and CMS compatibility. The operation checks the signed FASC-N and GUID against the
certificate and any matching signed attributes, requires content-signing key usage and purpose, and
verifies the signature, path and revocation. Scratch is provisional and caller-owned, so clear it
when its lifetime ends.

For `TC_PIV_CARD`, the operation selects the registered PIV content-signing initial policy, requires
that exact policy in the signer certificate and requires the signer to stay valid through the card
certificate's expiration. TWIC profiles keep the caller's policy settings and accept either
registered PIV/TWIC content-signing purpose. An empty `validation_options.certificate.purpose`
selects the signer's one exact compatible content-signing EKU, and an explicit value requires that
OID.

On success, `accepted` borrows the authenticated CHUID fields and signer certificate. Pass
`&accepted` as the `chuid` of dependent Security Object and biometric requests, with the same card
profile and evaluation time, and keep the backing bytes unchanged meanwhile.

The example treats the CHUID's expiration date as valid through 23:59:59 UTC on that date and
rejects unsigned CHUIDs. Card cancellation, active-card authentication and access authorization
need their own checks.

### Validate a biometric object

`TC_PIV_biometric_validate` takes a complete CBEFF `BC` value, the `TC_PIV_CHUID_report` and the
validated card certificate's expiration. The FASC-N, GUID and CHUID signer come from the report. The
request profile and context time must equal the report's `profile` and `at`, or the call returns
`TC_CREDENTIAL_ERROR` before charging work.

```c
TC_PIV_biometric_validation_request biometric = {
    .encoded = fingerprint_bc_value,
    .profile = TC_TWIC_NEXGEN_CARD,
    .chuid = &accepted,
    .card_expiration = &card_certificate.not_after,
    .signature_profile = TC_PIV_CMS_BIOMETRIC,
    .format = TC_PIV_CBEFF_FINGERPRINT_TEMPLATE,
    .require_current = 1
};
TC_PIV_biometric_report fingerprint;
status = TC_PIV_biometric_validate(&biometric, &context, &work, &fingerprint);
if (status != TC_CREDENTIAL_VALID) {
    return status;
}
/* fingerprint.record borrows fingerprint_bc_value for the matcher. */
```

It checks header metadata, binds the header and signed identifiers, and validates the CMS signature,
signer path and revocation, sharing the CHUID operation's content-signing policy, context and
workspace. `TC_PIV_biometric_report` reports the format, CBEFF metadata, borrowed record, signer
certificate, profile and evaluation time.

An object without an embedded certificate uses the authenticated CHUID signing certificate, so keep
that buffer stable. An embedded certificate must carry a signing key different from CHUID's,
compared by RSA modulus and exponent or by named EC curve and point in either compressed or
uncompressed form. A reissued certificate with the CHUID key falls under the omission rule.

Decrypt any outer TWIC privacy-key wrapping first, and keep the CHUID report, biometric and
certificate buffers stable through the acceptance decision. Success authenticates the object. The
application selects acceptable formats and dates, validates record contents and matches a physical
sample. The reader command authenticates encrypted TWIC biometric objects with `--tpk-hex`.

## Testing

```sh
cmake -S . -B build -DTINY_CRYPTO_BUILD_TESTS=ON -DTINY_CRYPTO_RESOURCE_PROFILE=desktop \
  -DTINY_CRYPTO_TEST_OPENSSL=ON -DTINY_CRYPTO_TEST_EC_ORACLE=ON
cmake --build build --parallel 4
ctest --test-dir build -R '^test_(cms_|piv_oid$|piv_cms_identifiers$)' --output-on-failure
```

`test_cms_native`, `test_cms_path`, `test_cms_revocation` and `test_cms_pss` compare against OpenSSL
and need `TINY_CRYPTO_TEST_OPENSSL=ON`. `test_cms_command` runs the command-line example with
fixtures from Python `cryptography` and also needs `TINY_CRYPTO_TEST_EC_ORACLE=ON`.

The native CHUID tests generate their own CA, content-signing certificate and CRL. They cover a
valid signer path, signer revocation, an unrelated trust key, changed detached content, optional
PIV/TWIC identifier attributes and a validly signed object naming the wrong signer. Both registered
content-signing purpose OIDs run under TWIC policy. Unsigned TWIC objects pass their parsing schema
and then fail the signed-object validator.
