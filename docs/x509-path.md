<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# X.509 path validation

Include `<tiny_crypto/x509_path.h>` and enable `TINY_CRYPTO_ENABLE_X509_PATH`.
`TC_X509_path_validate` checks an ordered certificate path against an explicit trust anchor. Related
steps have their own guides:

- [Certificate store](x509-store.md): path discovery with `TC_X509_path_build`.
- [Trust anchors](x509-trust-anchors.md): RFC 5914 anchor records and their RFC 5937 path controls,
  used by `TC_X509_path_validate_with_anchor`.
- [Path revocation](x509-revocation.md): CRL and OCSP checks after validation.
- [Native signature verification](x509-crypto.md): `TC_X509_native_provider` and the provider
  callback contract.

Set the signature provider in `options.signatures`, either the native provider or a hardware
provider. The OpenSSL provider used by the tests stays in the test tree. Certificate verification
passes the provider one span holding the original DER TBSCertificate.
`TC_X509_signature_verify_message` accepts segmented messages without joining them.

## Inputs

Pass an array of DER spans from the certificate the anchor issued to the target. Leave the anchor
certificate out. The anchor supplies the trusted name and public key, and a self-signature carries
no trust.

Initialize `TC_X509_path_options` to zero, then set:

- `at`: the validation time in UTC from the caller's clock.
- `clock_skew_seconds`: widens each validity period by this amount on both sides. Zero requires
  `notBefore <= at <= notAfter`. `TC_X509_time_check` validates a caller-built time.
- `parsing`: per-certificate input, value, element and nesting limits.
- `max_certificates`, `max_input`: chain length and total DER bytes.
- `max_work`: a shared [work budget](api.md#work-budgets) that includes the signature provider.
- `signatures`: the verifier callback and its context.

### Usage

`purpose` holds an EKU OID's DER contents without tag and length. `key_usage` takes the
`TC_KEY_USAGE_*` masks, for example `TC_KEY_USAGE_DIGITAL_SIGNATURE` for a signing key.

- EKU extensions present anywhere in the path constrain the requested purpose. The key-usage bits
  apply to the target.
- `REQUIRE_KEY_USAGE` and `REQUIRE_EXTENDED_KEY_USAGE` also require those extensions on the target.
- `TC_X509_PATH_INHIBIT_ANY_PURPOSE` disables the `anyExtendedKeyUsage` wildcard throughout the
  path, so a present EKU extension must list the requested OID. Add `REQUIRE_EXTENDED_KEY_USAGE`
  when the target must carry EKU.

Profile rules such as EKU criticality or exclusive use of one EKU need separate checks.

### Policies and names

`initial_policies` lists acceptable policy OIDs as DER contents. An empty list is the RFC 5280
default user-initial-policy-set, `{anyPolicy}`, and accepts the authority-constrained policy set.
Listing `anyPolicy` (`55 1d 20 00`) has the same effect. Set `TC_X509_PATH_REQUIRE_EXPLICIT_POLICY`
to require a nonempty selected set. The mapping and any-policy inhibition flags apply independently.

`anchor_names` adds permitted and excluded subtrees from trusted configuration, as GeneralSubtree
list contents returned by `TC_X509_name_constraints_read`. Self-issued intermediates receive the
standard exception, and the target receives none.

## CA requirements and limitations

Every intermediate must be version 3 with `basicConstraints` `cA` TRUE. A present `keyUsage` must
set `keyCertSign`. RFC 5280 section 6.1.4(k) lets a relying party establish CA status for v1 and v2
certificates by other means. The validator has no such input, so a v1 or v2 intermediate makes the
path `TC_X509_PATH_INVALID`. A v1 root used as the anchor is accepted, because
`TC_X509_store_anchor` supplies its trust.

Name constraints use `TC_X509_name_within`. The unimplemented forms listed in `x509.h` make the path
`TC_X509_PATH_UNSUPPORTED` when they apply to a name in the path. Examples are mailbox-specific
constraints, DNS wildcards and subtrees with a nondefault minimum or maximum.

## Workspace

The validator uses twelve caller-owned scratch arrays. Describe their element counts in a
`TC_X509_path_capacity` and let the library partition one arena:

```c
#include <tiny_crypto/x509_path.h>

static TC_X509_path_storage arena[1024];

TC_result prepare_path_workspace(TC_X509_path_workspace* workspace)
{
    static const TC_X509_path_capacity capacity = {
        .frames = 16, .oids = 16, .name_scalars = 64, .name_attributes = 8,
        .policy_nodes = 32, .policy_edges = 64, .policy_expected = 64,
        .policy_mappings = 16, .policies = 16, .path = 4};
    const TC_buffer storage = {(uint8_t*)arena, sizeof arena};
    size_t required;
    TC_result status = TC_X509_path_workspace_size(&capacity, &required);
    if (status != TC_RESULT_OK)
        return status;
    if (required > sizeof arena)
        return TC_RESULT_LIMIT;
    return TC_X509_path_workspace_init(&capacity, storage, workspace);
}
```

`TC_X509_path_workspace_size` reports the exact arena bytes, including alignment padding between
arrays. `TC_X509_path_workspace_alignment` reports the base alignment, which an array of
`TC_X509_path_storage` meets. `TC_X509_path_workspace_init` returns `TC_RESULT_ARGUMENT` for a
misaligned base and `TC_RESULT_LIMIT` for a short arena, with the workspace unchanged in both cases.
Initialization writes only the descriptor.

Capacity fields:

- `path`: one certificate view and one `TC_X509_extension_summary` per path certificate. A shorter
  array returns `TC_X509_PATH_LIMIT`.
- `oids`: shared by extension decoding, policy decoding and EKU checks.
- `name_scalars`: sizes both name buffers of prepared Unicode scalars. `name_attributes` holds
  matching state for one RDN.
- Policy counts: zero leaves those arrays NULL. `policy_nodes` needs at least one entry for the
  anyPolicy root. A full policy array returns `TC_X509_PATH_LIMIT`. `policies` holds the returned
  policy spans.

For fixed array locations, set each `TC_X509_path_workspace` field directly with capacities as
element counts. `TC_X509_PATH_WORKSPACE_INIT` fills the workspace from arrays, including array
members of a storage structure, and infers their capacities. Pointers lose the array size. The
smaller name array sets the scalar capacity. [examples/x509_workspace.h](../examples/x509_workspace.h)
uses this form.

The validator owns the node, edge, expected-policy and summary fields. Treat them as private.

Each certificate is parsed once into its view and its extensions are scanned once per validation.
The subject and issuer of each intermediate are compared once. Workspace limits bound the policy
graph, and the work budget bounds scanning and comparison.

### Lifetimes

The workspace borrows the arena. Give each concurrent validation its own arena, and keep it alive
while the workspace or a result that borrows it is in use. Workspace arrays, inputs, the result and
the provider context follow [Input stability and overlap](api.md#input-stability-and-overlap).
Certificate views borrow the input DER and are overwritten by the next validation.

After success, the returned key borrows the target DER. Policy OIDs borrow issuer DER or
`initial_policies`, and the policy-span array lives in the workspace, so reusing the workspace
overwrites it.

Path discovery returns its path-span array in search workspace. Copy the path and policy spans you
still need into caller-owned arrays before reusing either workspace. A copy of
`TC_X509_search_report` alone still points into the scratch arrays. Certificate DER stays in its
shared buffers, so keep those and the source snapshot alive.

## Results

- `TC_X509_PATH_VALID`: the ordered-path checks succeeded and `out` is populated.
- `TC_X509_PATH_INVALID`: the certificate encoding or path requirements failed.
- `TC_X509_PATH_UNSUPPORTED`: a required algorithm, name rule or critical extension is missing from
  the build.
- `TC_X509_PATH_LIMIT`: an input, workspace or processing limit was reached.
- `TC_X509_PATH_ERROR`: invalid arguments or options, overlapping storage, a provider error or a
  storage source that failed to supply bytes. Invalid options, such as `options.at` or a malformed
  initial-policy OID, are reported before any work is charged.

Only `VALID` authorizes the returned key under the supplied settings. Other results leave `out`
unchanged. Workspace and provider state may change on any result. Revocation needs a separate check.

## Client-certificate example

[examples/x509_client.c](../examples/x509_client.c) requires a client-authentication purpose and
digital-signature key usage, and accepts up to four certificates of 4096 bytes each. Its
`TC_X509_path_capacity` sets explicit graph and name capacities. Adjust those limits to your
certificates and memory.

Compile the source with your application and link `tiny-crypto-c`. Check the arena once at startup
against `example_client_workspace_size`, then pass the anchor, UTC time, signature provider and work
budget to `example_check_client_certificate`. It returns the library statuses and leaves the result
unchanged on failure. A short arena returns `TC_X509_PATH_LIMIT`, and a NULL or misaligned arena
`TC_X509_PATH_ERROR`. Place the arena outside a small task stack, keep it and the certificate
buffers alive while using the result, and check revocation before granting access.

The installed-consumer test builds this example as C99 and C++11 callers against an installed
library. The OpenSSL suite runs valid, invalid and work-limited signed chains through it, and the
signed-chain tests compare the public API with OpenSSL verdicts for signatures, validity periods,
CA, name and policy constraints, usage restrictions and unknown critical extensions. See
[Testing](testing.md).
