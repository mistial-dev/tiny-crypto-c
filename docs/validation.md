<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Credential validation

`<tiny_crypto/validation.h>` validates certificates and CMS objects, and
`<tiny_crypto/credential.h>` validates PIV and TWIC objects. These operations combine signature
checks, path discovery, certificate policy and CRL evidence. Enable
`TINY_CRYPTO_ENABLE_CMS_VALIDATION` for the generic API. PIV objects and composed credentials are
separate optional features.

## Set up storage

`TC_validation_capacity_init` fills one of three starting layouts. Adjust any field before sizing
the arena.

| Profile | Path certificates | CMS candidates | CRL records |
| :------ | ----------------: | -------------: | ----------: |
| Micro   |                 4 |              8 |           4 |
| Mini    |                 8 |             16 |          16 |
| Desktop |                16 |            128 |         128 |

Profiles set resource capacities, and build options set algorithms. Size capacities for your
provisioned trust set and the credentials you accept. Each path entry holds one parsed certificate
view, which borrows the certificate DER during validation.

```c
#include <tiny_crypto/validation.h>

TC_result prepare_validation(TC_buffer arena,
    const TC_validation_trust* trust,
    const TC_validation_options* options,
    TC_validation_workspace* workspace,
    TC_validation_context* context)
{
    TC_validation_capacity capacity;
    TC_result status = TC_validation_capacity_init(TC_VALIDATION_MINI, &capacity);
    if (status != TC_RESULT_OK) return status;
    status = TC_validation_workspace_init(&capacity, arena, workspace);
    if (status != TC_RESULT_OK) return status;
    return TC_validation_context_init(trust, options, &workspace->credential, context);
}
```

`TC_validation_workspace_size` returns the required bytes and `TC_validation_workspace_alignment`
the alignment. An array of `TC_validation_storage` is suitably aligned for static storage. Check its
byte size against the reported size. To place each array yourself, fill the
`TC_validation_workspace` fields directly.

The arena holds CRL scope slots sized from `capacity.crls`, signer path spans from `capacity.path`,
signer policy spans from `capacity.policies`, and 64 bytes for the signed-attribute digest during
CMS signer search. Signature-provider scratch is separate. Keep the workspace descriptor at the
address used during initialization, and let one operation at a time use an arena. See
[Workspaces and limits](api.md#workspaces-and-limits) for placement and limit results.

## Configure policy and trust

`TC_validation_options` holds one evaluation time, signature provider, parsing limits and search
bounds.

- `certificate` and `crl_signer`: separate usage, policy and name constraints, using the
  [path options](x509-path.md#inputs).
- `verification`: the [CMS verification policy](cms.md#verification-policy). The PIV and TWIC
  validators set its attribute identifier set from the card profile.
- `revocation`: the revocation evidence policy, described below.

`TC_validation_trust` refers to a held certificate source and a CRL index. Only source anchors
establish trust. Keep both unchanged until the acceptance decision and every use of borrowed
results end. Use separate contexts when card and content-signing trust have different anchors or
policies. Sequential contexts can share one arena.

### Revocation evidence policy

`revocation` selects how missing CRL evidence is treated (RFC 5280 section 6.3.3). A path member
lacks evidence when no current CRL in the index covers it. A CRL past its nextUpdate counts as no
evidence, so expired held CRLs leave members without evidence. A covering CRL with a failed
signature returns `TC_CREDENTIAL_INVALID` under both values.

| Policy                                     | Member without CRL evidence   | Covering CRL lists the member | Only unsupported CRLs cover |
| :----------------------------------------- | :---------------------------- | :---------------------------- | :-------------------------- |
| `TC_VALIDATION_REVOCATION_REQUIRED` (zero) | `TC_CREDENTIAL_UNAVAILABLE`   | `TC_CREDENTIAL_REVOKED`       | `TC_CREDENTIAL_UNSUPPORTED` |
| `TC_VALIDATION_REVOCATION_WHEN_AVAILABLE`  | valid, `revocation_checked` 0 | `TC_CREDENTIAL_REVOKED`       | `TC_CREDENTIAL_UNSUPPORTED` |

A revoked member outranks a member without evidence. An unsupported CRL, such as one with an unknown
critical extension, is skipped when another current CRL covers the member. Under `WHEN_AVAILABLE`, a
CRL whose signer has no evidence still applies, and the members it covers report
`revocation_checked` 0.

`TC_X509_validation_report`, `TC_PIV_CHUID_report`, `TC_PIV_biometric_report`,
`TC_PIV_security_map` and `TC_PIV_security_report` carry `revocation_checked`, and
`TC_CMS_validate` writes it through an optional pointer. Choose `WHEN_AVAILABLE` explicitly, for
example after the held CRLs expire, and treat `revocation_checked` 0 as missing evidence in the
acceptance decision. [Path revocation](x509-revocation.md) describes the underlying CRL and OCSP
checks.

## Validate and reuse results

`TC_X509_validate` takes certificate DER and returns the validated certificate, evaluation time and
selected anchor index. The certificate fields borrow the DER and stay usable after another operation
reuses the arena.

`TC_CMS_validate` checks one selected signer, attached or detached content, its certificate path and
revocation. Application-specific object checks follow it. See
[CMS signer paths](cms.md#find-a-signer-path).

`TC_PIV_content_signer_validate` validates a content signer certificate, such as the secure
messaging Certificate Signer of container `5FC122`, under the CHUID signer's content-signing policy
for the card profile. `TC_PIV_CVC_validate` validates the X.509 signer the same way, then verifies
the card's CVC chain. Secure-messaging key confirmation completes session setup. The
[card check](piv-card-check.md) composes these validators over a card inventory.

### Signed card objects

1. Validate the card certificate and read its identifiers.
1. Pass the identifiers and card expiration to `TC_PIV_CHUID_validate`
   ([CHUID validation](cms.md#validate-a-chuid-against-a-card-certificate)).
1. Pass the returned `TC_PIV_CHUID_report` as the `chuid` field of biometric and Security Object
   requests, with the same card profile and evaluation time.
1. Pass a successful `TC_PIV_security_report` as the `security` field of
   `TC_TWIC_unsigned_CHUID_validate` to check container 3002.

`TC_PIV_security_validate` requires the complete inventory of signed containers. For a partial
inventory, such as objects read without the PIN, authenticate the Security Object once with
`TC_PIV_security_authenticate`. It returns a `TC_PIV_security_map` with the container map, the
signed LDS digests and the parsing limits. Then check each object read with
`TC_PIV_security_digest_check`:

- `TC_CREDENTIAL_VALID`: the digest matches.
- `TC_CREDENTIAL_INVALID`: the digest differs.
- `TC_CREDENTIAL_UNAVAILABLE`: the container is outside the signed map, so the issuer signed no
  digest for it.

The map borrows the Security Object bytes and the LDS scratch in its workspace, and survives reuse
of the validation arena.

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

A `TC_CREDENTIAL_VALID` return here means the Security Object is authentic. Each `results` entry
decides its own object. Read `map->revocation_checked` before relying on the signer's revocation
status.

CHUID and Security Object results borrow the original buffers and inventory descriptors. Keep those
buffers unchanged while using the results. Encrypted biometric entries hash their stored ciphertext
for the inventory. TWIC printed information can require decrypted TLVs. Select the representation
the card profile requires and retain those bytes through validation. See
[inventory hash inputs](credential-validation.md#inventory-hash-inputs).

Share one remaining-work counter across the sequence. Accept only `TC_CREDENTIAL_VALID`, and handle
invalid signatures, revocation, unavailable evidence, unsupported algorithms and exhausted limits
explicitly.

## TWIC example

[credential_workflow.c](../examples/credential_workflow.c) composes public APIs over caller-provided
objects, held trust and CRL sources, a held CCL snapshot and a fresh card-proof callback. Card
commands stay in the reader example. The [composition walkthrough](credential-validation.md)
documents its policy sequence, borrowed lifetimes and final recheck.

The result covers the requested checks at the supplied evaluation time. Recheck time-sensitive
evidence before a later access decision. Release held snapshots and wipe plaintext and key material
on every exit path.
