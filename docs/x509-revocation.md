<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# X.509 path revocation

Include `<tiny_crypto/x509_revocation.h>` and enable
`TINY_CRYPTO_ENABLE_X509_REVOCATION`.
`TC_X509_path_check_revocation` checks CRLs for a previously validated certificate
path. Path validation and certificate and CRL retrieval stay with the caller.
The path operation, candidate-source guards, storage preflight and dependency
resolution are implemented by the X.509 revocation layer. CMS validation uses
the same operation with an adapter for embedded certificate collections.

First validate or discover the path. Keep its anchor, validation time and
[trust-store snapshot](x509-store.md) fixed for revocation checking. Pass the
certificates anchor-issued first and target last, without the anchor certificate.
Copy the path-span array out of search scratch before reusing that workspace.
The DER buffers themselves stay shared.

## Configuration

Build a [CRL index](x509-crl.md#indexing-a-collection) and set
`TC_X509_revocation_options`:

- `index`: the parsed CRL collection, kept unchanged throughout the call.
- `source`: the held source with CRL signer certificates, intermediates and anchors.
- `anchor_index`: the same source anchor used to validate the target path.
- `signer_policy`: validation options for CRL signers at the same time. Omit
  holder-specific EKU and key-usage requirements. cRLSign is added internally.
  Version 3 CRL signers must carry keyUsage with cRLSign set.
- `max_candidate_bytes`: the total encoded-byte limit for the candidate collection.

`delta_policy` selects complete CRLs only, deltas when available, or required
deltas. `order_policy` normally uses CRL numbers. `TC_X509_CRL_ORDER_THIS_UPDATE`
explicitly enables time ordering for legacy unnumbered CRLs. It is never selected
automatically, and delta pairing still requires numbers.

## Workspace and results

`TC_X509_revocation_workspace` borrows validation and search workspaces. Its
`states` array needs one byte per indexed CRL. `scopes` needs one slot per
indexed CRL. Its node array must cover all distinct path certificates and signer
dependencies visited during the call. Each node carries two `size_t` lookup
links, and each scope slot carries three `size_t` links. `signer_path` needs
`search.capacity` spans. `signer_policies` needs
`validation.policy_capacity` spans. The signer arrays hold borrowed views into
the fixed source snapshot. Keep those source bytes unchanged through the call.
Insufficient storage or work returns `TC_TLV_LIMIT`.

Scope groups are reused across point scans for each target. The most recently
validated signer path and its per-CRL signature results are reused when the
same signer appears again. Verified dependencies are shared across path members.
Each call starts with no trusted cached results.
Cycles without independent evidence
and missing CRLs return `TC_TLV_UNSUPPORTED`. Input bytes, options, source records
and workspace metadata must remain stable while the call runs.

`TC_TLV_OK` means a decision is available in `result.status`:

- `TC_X509_CRL_UNREVOKED`: every path member has complete reason coverage.
- `TC_X509_CRL_REVOKED`: `certificate_index` identifies the member and `evidence`
  contains its revocation reason and date. Read the invalidity date only when
  `has_invalidity_date` is set.

Other return codes leave the result unchanged. Work, cache arrays and node
storage are provisional and may change. An unrevoked result uses `SIZE_MAX` for
the member index and zero evidence.

## Example

[examples/x509_revocation.c](../examples/x509_revocation.c) sets up the typed
workspaces from [caller-owned storage](../examples/x509_revocation.h). It supports
four indexed CRLs and eight dependency nodes. The native tests compile and run
the example with unrevoked and revoked issuer paths.

After configuring `options` and preserving `held_path`:

```c
TC_X509_revocation_result result;
TC_TLV_result status = example_check_path_revocation(
    held_path, path_count, &options, &work, storage, &result);
int accepted = status == TC_TLV_OK && result.status == TC_X509_CRL_UNREVOKED;
```

Keep the workspace outside a small task stack. Calls sharing its scratch must
be serialized. The result copies dates and status, but the path, source and CRL
index retain their original buffer lifetimes.
