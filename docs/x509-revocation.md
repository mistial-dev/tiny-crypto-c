<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# X.509 path revocation

Include `<tiny_crypto/x509_revocation.h>` and enable `TINY_CRYPTO_ENABLE_X509_REVOCATION`.
`TC_X509_path_check_revocation` checks CRLs and optional OCSP responses for a validated certificate
path. The caller validates the path and retrieves certificates, CRLs and OCSP responses. One
argument check and one storage preflight cover every path member and dependency node. CMS
validation uses the same operation through an adapter for embedded certificate collections.

Validate or [discover](x509-store.md#build-a-path) the path first. Keep its anchor, validation time
and trust-store snapshot fixed for the revocation check. Pass the certificates anchor-issued first
and target last, without the anchor certificate. Copy the path-span array out of search scratch
before reusing that workspace.

## Configuration

Build a [CRL index](x509-crl.md#indexing-a-collection) and set `TC_X509_revocation_options`:

- `index`: the parsed CRL collection, unchanged throughout the call.
- `source`: the held source with CRL signer certificates, intermediates and anchors.
- `anchor_index`: the source anchor that validated the path. The anchor key signs CRLs only when its
  record carries `TC_X509_ANCHOR_USAGE_CRL_SIGN` (RFC 5280 section 6.3.3 (f), RFC 10007 section 4).
  A source certificate with the anchor's name and complete SubjectPublicKeyInfo signs as the anchor
  key.
- `signer_policy`: path options for CRL signers, with `at` equal to `time.at`. Omit holder-specific
  EKU and key-usage requirements. cRLSign is added internally, and version 3 CRL signers must carry
  keyUsage with cRLSign set. Its clock skew applies to the signer certificates.
- `max_candidate_bytes`: total encoded bytes of the candidate collection.
- `time`: the evaluation time and freshness limits, described below.
- `ocsp`: optional OCSP responses, one per path member.

`delta_policy` selects complete CRLs only, deltas when available, or required deltas.
`order_policy` normally orders CRLs by CRL number. `TC_X509_CRL_ORDER_THIS_UPDATE` enables time
ordering for CRLs without a number. It is an explicit choice, and delta pairing still requires
numbers.

## Freshness

`TC_X509_revocation_time` holds `at`, `clock_skew_seconds` and `max_age_seconds`. CRLs and OCSP
responses share one rule. Evidence is current when:

- thisUpdate is at most `at + clock_skew_seconds`,
- a present nextUpdate is later than `at - clock_skew_seconds`, and
- with a nonzero `max_age_seconds`, thisUpdate is at most `max_age_seconds` before
  `at - clock_skew_seconds`.

A CRL without nextUpdate is never current (RFC 5280 section 6.3.3). An OCSP response without
nextUpdate is current only under a nonzero `max_age_seconds`. An OCSP producedAt must also be at
most `at + clock_skew_seconds`.

## OCSP evidence

Set `ocsp.responses` to one DER OCSPResponse span per path member in chain order, and `ocsp.count`
to the path length. An empty span means no response for that member. `max_responses` and
`max_certificates` bound each response as in `TC_X509_ocsp_verify_request`. Leave `ocsp` zeroed for
CRLs only. A build without `TINY_CRYPTO_ENABLE_X509_OCSP` uses CRLs for every member.
[X.509 OCSP](x509-ocsp.md) covers single-response verification and responder authorization.

Each response is verified as by `TC_X509_ocsp_response_verify` against the member's issuer: the
selected anchor for the first member and the previous member otherwise. The composed check verifies
responses without a nonce. Delegate candidates come from the response's certs, then from `source`.
Each delegate is validated as the last certificate of the path above its issuer, under the selected
anchor's path controls (RFC 5937 section 3.1). That delegate path uses `search.path` as scratch, and
a search capacity below the member's index plus one returns `TC_TLV_LIMIT`.

| OCSP outcome for a member                                       | Effect                                                          |
| --------------------------------------------------------------- | --------------------------------------------------------------- |
| Accepted REVOKED                                                | The member is revoked.                                          |
| Accepted GOOD                                                   | CRLs are still consulted, and a CRL listing the member wins.    |
| GOOD from a delegate without `id-pkix-ocsp-nocheck`             | Accepted only when the CRL index proves the delegate unrevoked. |
| REVOKED from a delegate without nocheck                         | Accepted unless the CRL index shows the delegate revoked.       |
| Missing, malformed, unauthorized, stale, UNKNOWN or unavailable | Falls back to CRLs.                                             |
| Delegate without nocheck and without CRL proof                  | Falls back to CRLs.                                             |

The nocheck rule follows RFC 6960 section 4.2.2.2.1, and a checked delegate takes one dependency
node. Exhausted limits and argument errors stop the call. Responses must stay unchanged during the
call and lie outside every workspace array.

## Workspace

`TC_X509_revocation_workspace` borrows validation and search workspaces and adds:

- `states`: one byte per indexed CRL.
- `scopes`: one slot per indexed CRL, each carrying three `size_t` links.
- Nodes: one per distinct path certificate and signer dependency visited, each carrying two
  `size_t` lookup links.
- `signer_path`: `search.capacity` spans.
- `signer_policies`: `validation.policy_capacity` spans.

The signer arrays borrow views into the fixed source snapshot. OCSP verification uses the
validation workspace. Insufficient storage or work returns `TC_TLV_LIMIT`.

Scope groups are reused across point scans for each target. The most recently validated signer path
and its per-CRL signature results are reused when the same signer appears again, and verified
dependencies are shared across path members. Each call starts with no cached trust.

## Results

`TC_TLV_OK` means a decision is in `result.status`:

- `TC_X509_REVOCATION_GOOD`: every path member has complete reason coverage. `certificate_index` is
  `SIZE_MAX` and `evidence` is zero.
- `TC_X509_REVOCATION_REVOKED`: `certificate_index` identifies the member and `evidence` holds the
  reason and date. Read the invalidity date only when `has_invalidity_date` is set. For OCSP
  evidence, the date is the revocationTime and the reason is the CRLReason, or unspecified (0) when
  the response has none.

Other return codes leave the result unchanged. Work, cache arrays and node storage are provisional.

- `TC_TLV_UNSUPPORTED`: a cycle without independent evidence, a member with no accepted OCSP
  response and no CRL evidence, or an unsettled member with an unsupported candidate CRL, such as
  one with an unknown critical extension.
- `TC_TLV_INVALID`: a member has no accepted OCSP response and all its candidate CRLs failed as
  invalid data. Causes include a failed CRL signature, no signer candidate with a valid path to the
  anchor, a revoked CRL signer, conflicting CRLs in one scope and malformed CRL entries.
- `TC_TLV_ARGUMENT`: an invalid `time.at`, a `time.at` that differs from `signer_policy->at`, an
  `ocsp.count` other than zero or the path length, or OCSP responses with a zero
  `ocsp.max_responses`.
- `TC_TLV_LIMIT`: storage or work ran out.

Inputs, options, source records and workspace metadata stay stable for the whole call. The CMS and
credential validators map these outcomes onto the
[revocation evidence policy](validation.md#revocation-evidence-policy).

## Example

[examples/x509_revocation.c](../examples/x509_revocation.c) builds the typed workspaces from
[caller-owned storage](../examples/x509_revocation.h) for four indexed CRLs and eight dependency
nodes. `test_cms_revocation` runs it with unrevoked and revoked issuer paths.

After configuring `options` and preserving `held_path`:

```c
TC_X509_revocation_report result;
TC_TLV_result status = example_check_path_revocation(
    held_path, path_count, &options, &work, storage, &result);
int accepted = status == TC_TLV_OK && result.status == TC_X509_REVOCATION_GOOD;
```

Keep the workspace outside a small task stack and serialize calls that share it. The result copies
dates and status. The path, source and CRL index keep their own buffer lifetimes.
