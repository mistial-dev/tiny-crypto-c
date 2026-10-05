<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# LDS security objects

Include `<tiny_crypto/lds.h>` and enable `TINY_CRYPTO_ENABLE_PIV_OBJECTS`. `TC_LDS_read` parses the
DER `LDSSecurityObject` carried in CMS eContent, as specified in
[ICAO Doc 9303 Part 10](https://www.icao.int/sites/default/files/publications/DocSeries/9303_p10_cons_en.pdf).
The PIV/TWIC CMS Security Object profile uses content-type OID `1.3.27.1.1.1` (NIST SP 800-85B,
AS06.04.06). Select `TC_PIV_CMS_SECURITY` to check that envelope before relying on its LDS content.

## Parsing

`TC_LDS_read` takes the encoded bytes, TLV limits, caller-owned frame storage and a work budget.
Use the returned object only after `TC_TLV_OK`. Its spans borrow the input, which must stay
unchanged. Keep input, limits, frames, budget and result disjoint. Argument errors preserve caller
state. Processing failures may consume work and scratch and preserve the result.

Versions 0 and 1 are supported. The parser requires 2–16 distinct data groups numbered 1–16 and
checks each digest length against its SHA algorithm. The `groups` bitmap sets bit `n-1` for group
`n`. `hashes` is the encoded sequence of group-number/digest pairs in the input buffer. Version 1
also returns borrowed LDS and Unicode version strings.

Hash identifiers accept absent or NULL parameters, as inspection systems require. Unknown
algorithms or object versions return `TC_TLV_UNSUPPORTED`. Hash metadata parses with the
corresponding hash implementation disabled.

For `TC_CMS_signed_data.content`, use `TC_LDS_read_content` with the complete OCTET STRING
encoding, the same limits and work budget, and optional caller-owned byte storage. It borrows
single-chunk content directly and joins fragmented BER content in the buffer before parsing it as
DER. A buffer the size of the encoded content is enough, and less returns `TC_TLV_LIMIT`. Pass
`NULL, 0` to accept single-chunk content only. Returned spans borrow the input or the buffer, so
keep both stable while using the result. Processing errors preserve the result and may change the
work counter, frames and byte buffer.

## Digest lookup and check

`TC_LDS_hash_find` takes the parsed object, a group number, limits, frames and the shared work
budget. `TC_TLV_OK` returns a borrowed digest span, `TC_TLV_END` means the group is absent, and
other results are errors. The output changes only when a digest is returned. Lookup scans at most
16 entries with the same schema checks as parsing. Keep the parsed object and its backing bytes
unchanged through lookup and verification.

`TC_LDS_hash_check` hashes an array of `TC_bytes` spans in order and compares the complete digest
with the group's value, so callers can hash shared buffers without concatenating them. Pass zero
spans for empty content. `TC_TLV_OK` sets `matched` to 0 or 1, `TC_TLV_END` means the group is
absent, and other results are errors that preserve `matched`. The selected hash must be enabled.
The work budget covers lookup, hashing and comparison. TLV limits bound the span count and total
length. Keep inputs separate from frames, the work counter and the match result.

## PIV and TWIC containers

Include `<tiny_crypto/piv_security.h>` for `TC_PIV_security_read`. Select
`TC_PIV_SECURITY_CONTAINER` for a complete `53` response or `TC_PIV_SECURITY_CONTENTS` for its
value. The parser requires `BA`, nonempty `BB` and empty `FE` in that order and returns borrowed
mapping and CMS spans plus a group bitmap. Each mapping record holds a group number (1–16) and a
two-byte big-endian container ID. Repeated groups or container IDs are rejected. The output changes
only on `TC_TLV_OK`.

`TC_PIV_security_group_find` maps a container ID to its group number for `TC_LDS_hash_check`. A
missing container returns `TC_TLV_END`, and errors preserve the output. The `BA` mapping lies
outside the CMS signature. Require its `groups` bitmap to equal the authenticated LDS object's
`groups`, and reconcile it with the required container policy.

Read the `BB` value with `TC_PIV_CMS_read` and `TC_PIV_CMS_SECURITY` to check the single-signer
security-object profile: attached content of the ICAO LDS type, signed attributes and an omitted
signing certificate. Issuer/serial and subject-key-ID identifiers are both accepted. PIV and TWIC
sign the Security Object with the CHUID key. Pass the authenticated CHUID certificate as
`signer_certificate` in the CMS validation request with zero detached-content spans, and apply the
CHUID's content-signing usage, path and revocation policy. Parse the authenticated eContent with
`TC_LDS_read` before checking object hashes.

## Validating an inventory

`TC_PIV_security_validate` in `<tiny_crypto/credential.h>` composes these steps with signer path
and revocation validation. Its `TC_PIV_security_validation_request` holds the Security Object, the
`TC_PIV_CHUID_report` from `TC_PIV_CHUID_validate`, the card profile and expiration, and a complete
array of `TC_PIV_security_data` records. The CHUID report supplies the signer certificate, and its
profile and time must equal the request profile and the context's evaluation time. Each record
pairs a container ID with the ordered spans to hash. The operation rejects missing, extra and
repeated containers, unequal mapping and LDS group sets, and digest mismatches.

Supply the shared `TC_validation_context` and a `TC_PIV_security_validation_workspace` with a
bounded LDS content buffer. For a partial inventory, such as objects read without the PIN,
`TC_PIV_security_authenticate` authenticates the Security Object into a `TC_PIV_security_map`, and
`TC_PIV_security_digest_check` checks one `TC_PIV_security_data` record at a time against it. Keep
the request, object data, trust source, CRLs, policy and work counter separate from mutable
scratch. Accept only `TC_CREDENTIAL_VALID`. The application selects the required inventory and the
exact hash inputs, including any framing or decryption
([inventory hash inputs](credential-validation.md#inventory-hash-inputs)).

## TWIC objects

TWIC support requires `TC_ENABLE_TWIC`. The TWIC unsigned CHUID is a separate object.
`TC_TWIC_unsigned_CHUID_validate` takes the `TC_PIV_security_report` in the request's `security`
field. It requires container `0x3002` in the validated inventory, compares its exact ordered parts
with the supplied CHUID, and binds the authenticated FASC-N, GUID and expiration to the card
certificate. `TC_PIV_CHUID_validate` requires a signed CHUID.

The
[TSA reader/card specification, section 11.3 note 4](https://www.ports.org/files/PDFs/TWIC%20Reader%20Hardware%20%26%20Card%20Application%20Specification.pdf)
defines TWIC hashes over stored object contents, which the section 11.5.2 GET DATA response wraps
in `53`. Hash the response's value bytes with the inner field tags and lengths, including the
CHUID's `FE 00`. Hash encrypted fields in their stored form. Privacy-key decryption needs separate
working storage while the encrypted bytes are still needed for validation.
