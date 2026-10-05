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

`<tiny_crypto/credential.h>` composes these steps with signer path and revocation validation. Each
request takes the `TC_PIV_CHUID_report` from `TC_PIV_CHUID_validate` ([CHUID
validation](cms.md#validate-a-chuid-against-a-card-certificate)), which supplies the signer
certificate. Its profile and time must equal the request profile and the context's evaluation time.
Supply the shared `TC_validation_context` and a `TC_PIV_security_validation_workspace` whose
`content` buffer receives the decoded LDS content. Size it for the largest LDSSecurityObject the
application accepts.

`TC_PIV_security_validate` checks a complete inventory: an array of `TC_PIV_security_data` records,
each pairing a container ID with the ordered spans to hash. It rejects missing, extra and repeated
containers, unequal mapping and LDS group sets, and digest mismatches. The returned
`TC_PIV_security_report` borrows the inventory descriptors and their bytes and survives reuse of the
validation arena.

For a partial inventory, such as objects read without the PIN, `TC_PIV_security_authenticate`
authenticates the Security Object once into a `TC_PIV_security_map` that holds the container map,
the signed LDS digests and the parsing limits. The map borrows the Security Object bytes and the
workspace `content` buffer, and survives reuse of the validation arena.
`TC_PIV_security_digest_check` then checks one object at a time:

- `TC_CREDENTIAL_VALID`: the digest matches.
- `TC_CREDENTIAL_INVALID`: the digest differs.
- `TC_CREDENTIAL_UNAVAILABLE`: the container is outside the signed map, so the issuer signed no
  digest for it.

```c
#include <tiny_crypto/credential.h>

/* Authenticate the Security Object into map, then check each object that was
 * read. results[i] receives the status of objects[i]. */
TC_credential_status check_read_objects(const TC_PIV_security_signature_request* request,
    const TC_validation_context* context,
    const TC_PIV_security_validation_workspace* lds,
    const TC_PIV_security_data* objects, size_t count,
    size_t* work, TC_PIV_security_map* map, TC_credential_status* results)
{
    TC_credential_status status =
        TC_PIV_security_authenticate(request, context, lds, work, map);
    if (status != TC_CREDENTIAL_VALID) return status;
    for (size_t i = 0; i < count; ++i) {
        results[i] = TC_PIV_security_digest_check(map, &objects[i], work);
        if (results[i] == TC_CREDENTIAL_LIMIT || results[i] == TC_CREDENTIAL_ERROR)
            return results[i];
    }
    return TC_CREDENTIAL_VALID;
}
```

A `TC_CREDENTIAL_VALID` return here means the Security Object is authentic, and each `results` entry
decides its own object. Read `revocation_checked` in the map or report before relying on the
signer's revocation status.

Keep the request, object data, trust source, CRLs, policy and work counter separate from mutable
scratch, and share one work counter across the sequence. Accept only `TC_CREDENTIAL_VALID`. The
application selects the required inventory and the exact hash inputs ([inventory hash
inputs](credential-validation.md#inventory-hash-inputs)).

## TWIC objects

TWIC support requires `TC_ENABLE_TWIC`. The unsigned TWIC CHUID in container `0x3002` is
authenticated through the inventory. Pass a successful `TC_PIV_security_report` as the `security`
field of `TC_TWIC_unsigned_CHUID_validate`, with the same profile and evaluation time. It requires
container `0x3002` in the validated inventory and compares its exact ordered parts with the supplied
CHUID. The CHUID must be current, and its identifiers must match the card certificate under TWIC
reader rules. `TC_PIV_CHUID_validate` accepts signed CHUIDs only.
