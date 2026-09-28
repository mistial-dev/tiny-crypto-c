<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Trust anchors

Enable `TINY_CRYPTO_ENABLE_TRUST_ANCHOR_FORMAT` to read RFC 5914
`TrustAnchorList` DER. The list accepts certificate, TBS certificate, and
`TrustAnchorInfo` choices when their corresponding `TINY_CRYPTO_TAF_*` build
options are enabled. The format reader returns views that borrow the original DER.

RFC 5914 defines the encoded anchor and its path controls. RFC 5937 describes
how those controls constrain X.509 path validation. The implementation always
enforces constraints on a selected anchor. See the
[RFC 5914](https://www.rfc-editor.org/info/rfc5914/) and
[RFC 5937](https://www.rfc-editor.org/info/rfc5937/) publications.

## Read and publish a list

Use `TC_X509_trust_anchor_list_init` and call
`TC_X509_trust_anchor_next` until it returns `TC_TLV_END`. Supply a bounded
`TC_X509_workspace` and a caller-owned array of `TC_X509_store_anchor`
records. A disabled choice returns `TC_TLV_UNSUPPORTED`. A valid
`TrustAnchorInfo` without `certPath` is marked `x509_unusable` and cannot
authorize an X.509 path.

Certificate, TBS certificate and embedded `CertPathControls` certificates
follow the `TC_X509_read` field rules. An anchor also needs a non-empty
subject, because it issues certificates (RFC 5280 section 4.1.2.6), and a
validity period whose start does not follow its end. Other records are
`TC_TLV_INVALID`. The anchor's validity period is not checked against the
validation time.

Keep the DER and record array immutable while any validation uses them.
`TC_X509_store_array_source` turns the records and untrusted candidate
certificate spans into a `TC_X509_store_source`. The application must
authenticate and authorize the list before calling `TC_X509_store_publish`.
Parsing a list or receiving it inside CMS does not grant trust. If the list
arrives as CMS SignedData, verify its signature and content type using an
independent bootstrap trust context before passing the extracted DER list to
this reader.

The store retains borrowed source configuration. Follow the snapshot lifetime
rules in [Certificate store](x509-store.md). The backing DER may be reclaimed
only after the last reader releases its snapshot. Network retrieval and
persistent-storage updates belong to the application.

[Synthetic TWIC validation](../tests/twic/synthetic_validation.c) is an
executable example of bounded parsing, caller-owned records, explicit store
publication, and path validation against a constrained anchor.

## Path controls

An anchor's policies intersect the application's initial policies. Its
permitted names intersect the application's permitted names, and excluded
names from both sources apply. Restrictive policy flags combine with the
application flags. An anchor path-length limit counts non-self-issued
intermediate CAs. Unknown critical anchor extensions prevent validation.
An inhibitAnyPolicy or policyConstraints field on the anchor sets the
corresponding Boolean path input. Its SkipCerts count is ignored, as
RFC 5937 section 2 specifies.

For `TrustAnchorInfo`, its path-control fields take precedence over matching
extensions in its embedded certificate. RFC 5914 section 2.6 forbids
certificatePolicies, policyConstraints, inhibitAnyPolicy and nameConstraints
in the `exts` field, because `CertPathControls` carries them. Such an
extension makes the anchor `TC_TLV_INVALID` when parsed and
`TC_X509_PATH_INVALID` when a caller-built anchor carries it in
`extensions`. Its embedded certificate must match
the stated name and public key, and any subject key identifier must match the
anchor key identifier. The anchor record selected by path search applies only
to that attempted path. Another anchor cannot relax its controls.

Validation also requires a signature provider, an application-supplied UTC
time, and bounded path workspaces. Revocation is a separate check. A root
certificate present only among untrusted candidates never becomes an anchor.

## Resource options

The three choice options can be disabled independently to remove their
decoders. At least one must be enabled when the format module is enabled.
The default resource profile leaves the format module disabled. The desktop
profile includes all choices. Invalid feature combinations fail at compile
time and in CMake configuration.

Run the vendored parser, path, and TWIC tests with `ctest --output-on-failure`
from a configured build directory. The mandatory tests use the committed DER
fixtures and run without OpenSSL.
