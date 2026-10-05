<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Trust anchors

Enable `TINY_CRYPTO_ENABLE_TRUST_ANCHOR_FORMAT` to read RFC 5914 `TrustAnchorList` DER. The reader
accepts the certificate, TBS certificate and `TrustAnchorInfo` choices whose
`TINY_CRYPTO_TAF_ENABLE_*` options are enabled, and returns views that borrow the original DER.

[RFC 5914](https://www.rfc-editor.org/info/rfc5914/) defines the encoded anchor and its path
controls. [RFC 5937](https://www.rfc-editor.org/info/rfc5937/) describes how those controls
constrain X.509 path validation. Path validation always enforces the selected anchor's constraints.

## Read a list

Bind the list, parsing limits and a bounded `TC_X509_workspace` to a `TC_X509_trust_anchor_reader`
with `TC_X509_trust_anchor_list_init`. Call `TC_X509_trust_anchor_next` until it returns
`TC_TLV_END`, and store each result in a caller-owned array of `TC_X509_store_anchor` records. The
reader uses the workspace on every call, so keep it alive and unshared until the last call. The
reader, frames and extension OID array must be pairwise disjoint and lie outside the list and the
workspace struct. Init returns `TC_TLV_ARGUMENT` for any overlap. A disabled choice returns
`TC_TLV_UNSUPPORTED`.

```c
enum { ANCHOR_CAPACITY = 8 };
TC_TLV_frame frames[16];
TC_bytes oids[32];
const TC_X509_workspace parser = {{frames, 16}, oids, 32};
const TC_TLV_limits limits = {16384, 16384, 2048, 16};
TC_X509_store_anchor anchors[ANCHOR_CAPACITY], record;
TC_X509_trust_anchor_reader reader;
size_t count = 0;
TC_TLV_result result = TC_X509_trust_anchor_list_init(&reader, list, &limits, &parser);
if (result != TC_TLV_OK)
  return result; /* ARGUMENT, INVALID or LIMIT. */
while ((result = TC_X509_trust_anchor_next(&reader, &record)) == TC_TLV_OK) {
  if (count == ANCHOR_CAPACITY)
    return TC_TLV_LIMIT;
  anchors[count++] = record;
}
if (result != TC_TLV_END)
  return result; /* A malformed, unsupported or oversized anchor. */
```

`list` is a `TC_bytes` span over the DER TrustAnchorList. A valid `TrustAnchorInfo` without
`certPath` is marked `x509_unusable` and authorizes no X.509 path.

Certificate, TBS certificate and embedded `CertPathControls` certificates follow the `TC_X509_read`
field rules. An anchor issues certificates, so it also needs a nonempty subject (RFC 5280 section
4.1.2.6), a validity period that starts at or before its end, and keyCertSign in a present keyUsage
extension. Other records are `TC_TLV_INVALID`. Path validation ignores the anchor's validity period.

## Publish the anchors

Keep the DER and record array immutable while any validation uses them.
`TC_X509_store_array_source` turns the records and untrusted candidate spans into a
`TC_X509_store_source` for the [certificate store](x509-store.md), whose snapshot rules decide when
the backing DER can be reclaimed.

Parsing a list grants no trust. Authenticate and authorize it before `TC_X509_store_publish`. A list
delivered as CMS SignedData needs its signature and content type verified under an independent
bootstrap trust context before the extracted DER reaches this reader. Network retrieval and
persistent storage belong to the application.

## Build an anchor from a certificate

`TC_X509_store_anchor_from_certificate` turns a parsed root certificate into a
`TC_X509_store_anchor` under the rules of the list's certificate choice. It needs only the path
module. The record's `names`, `policy_set`, `policy_flags` and `path_len` come from the root's
nameConstraints, certificatePolicies, policyConstraints, inhibitAnyPolicy and basicConstraints
extensions. The record borrows the root DER, so keep that DER unchanged while the record is in use.

```c
TC_X509_certificate root;
TC_X509_store_anchor anchor;
if (TC_X509_read((TC_bytes){der, der_length}, &limits, &parser, &root) != TC_TLV_OK ||
    TC_X509_store_anchor_from_certificate(&root, &limits, &parser, &anchor) != TC_TLV_OK)
  return 0; /* ARGUMENT leaves anchor unchanged. Other failures zero it. */
```

Use the builder for application-provisioned roots. A record that copies only the subject and public
key, with `certificate_extensions` empty, validates without the root's constraints.

[Synthetic TWIC validation](../tests/twic/synthetic_validation.c) runs bounded parsing,
caller-owned records, store publication and path validation against a constrained anchor.

## Path controls

The selected anchor applies to that attempted path only, and another anchor leaves its controls
intact. A root certificate present only among untrusted candidates never becomes an anchor.

- Policies: the anchor's policies intersect the application's initial policies. A
  `TrustAnchorInfo` policySet lists unique policy identifiers (RFC 5280 section 4.2.1.4) without
  policyQualifiers (RFC 5914 section 2.5). An anchor certificate's certificatePolicies must also
  list unique identifiers.
- Names: permitted names intersect the application's permitted names, and excluded names from both
  apply.
- Flags: restrictive policy flags combine with the application flags. An inhibitAnyPolicy or
  policyConstraints field on the anchor sets the matching Boolean path input, and its SkipCerts
  count is ignored, as RFC 5937 section 2 specifies.
- Path length: an anchor limit counts non-self-issued intermediate CAs.
- Unknown critical anchor extensions prevent validation.

### Record fields and extensions

Validation applies the record fields `names`, `policy_set`, `policy_flags` and `path_len`, and also
checks `certificate_extensions`. A path control in `certificate_extensions` whose record field is
empty returns `TC_X509_PATH_UNSUPPORTED`, because the control would otherwise be dropped (RFC 5914
section 2.5). This covers nameConstraints without subtrees in `names`, certificatePolicies without
`policy_set`, policyConstraints or inhibitAnyPolicy without its policy flag, and a basicConstraints
pathLen without `has_path_len`.

In a `TrustAnchorInfo`, the path-control fields take precedence over matching extensions in the
embedded certificate (RFC 5914 section 2.5). The reader records each `CertPathControls` field it
applied in `replaced_controls`:

| Bit                                    | Field             |
| -------------------------------------- | ----------------- |
| `TC_X509_ANCHOR_REPLACED_POLICY_SET`   | policySet         |
| `TC_X509_ANCHOR_REPLACED_POLICY_FLAGS` | policyFlags       |
| `TC_X509_ANCHOR_REPLACED_NAMES`        | nameConstr        |
| `TC_X509_ANCHOR_REPLACED_PATH_LEN`     | pathLenConstraint |

Validation then uses the record field in place of the matching `certificate_extensions` control.
A policyFlags field that clears a flag set by the embedded certificate's policyConstraints or
inhibitAnyPolicy therefore validates with the flag cleared. A caller-built record sets a bit only
when its field holds the replacing value. Without the bit, the same record returns
`TC_X509_PATH_UNSUPPORTED`. The `CertPathControls` values are always enforced.

A basicConstraints pathLen in `exts` can only lower `pathLenConstraint`, so the reader keeps the
smaller value. A caller-built record whose `extensions` pathLen is below its `path_len`, or that
lacks `path_len`, returns `TC_X509_PATH_UNSUPPORTED`.

RFC 5914 section 2.6 excludes certificatePolicies, policyConstraints, inhibitAnyPolicy and
nameConstraints from `exts`, because `CertPathControls` carries them, and ignores them if present.
The reader and path validation ignore them in `exts` and in a caller-built anchor's `extensions`, so
a list with such an anchor stays readable to its end. Set those controls in the record fields of a
caller-built anchor. A duplicate extension in `exts` is still `TC_TLV_INVALID`.

A `TrustAnchorInfo` embedded certificate must match the stated name and public key, and a present
subject key identifier must match the anchor key identifier.

## Build options

Each of the three choice options can be disabled to remove its decoder. At least one must stay
enabled with the format module. The default resource profile disables the format module, and the
desktop profile enables all choices. Invalid combinations fail at compile time and in CMake
configuration. See the [README](../README.md) for the option table.

Run the parser, path and TWIC tests with `ctest --output-on-failure` from a configured build
directory. These mandatory tests use committed DER fixtures and run without OpenSSL.
