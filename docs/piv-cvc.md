<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# PIV secure-messaging CVCs

Include `<tiny_crypto/piv_cvc.h>`. `TC_PIV_CVC_read` reads a complete `7F21` container and returns
borrowed fields, including the original signed TLVs. `TC_PIV_CVC_chain_verify` verifies a card
CVC and an optional intermediate under a content-signing certificate that the caller has already
validated for trust path, content-signing usage, certificate policy, time and revocation. Hold
the certificate bytes and trust inputs stable through the call. See
[X.509 validation](x509-path.md) for path validation and [CMS](cms.md) for content signing.

The chain rules follow SP 800-73-5 Part 2, section 4.1.5:

- A direct card CVC names its signer by the first eight bytes of the certificate's
  subjectKeyIdentifier.
- An intermediate uses the same issuer link. Its subject identifier is the first eight bytes of
  SHA-1 over its public-key object, `04 || X || Y`, and the card CVC names it by that identifier.
- The intermediate signature uses RSA/SHA-256. Card signatures use ECDSA/SHA-256 for CS2 or
  ECDSA/SHA-384 for CS7.

The selected curve must match the CVC public keys, and both points are checked for curve
membership. Pass a known card UUID to bind the subject to that card, or an empty span to take the
identifier from the verified CVC. Accept the card session only after secure-messaging key
confirmation succeeds.

## Calling the verifier

Enable `TINY_CRYPTO_ENABLE_PIV_CVC`, `TINY_CRYPTO_ENABLE_DER`, `TINY_CRYPTO_ENABLE_X509`,
`TINY_CRYPTO_ENABLE_EC` and the selected curve. An intermediate also needs
`TINY_CRYPTO_ENABLE_SHA1`. The signature provider must support the required RSA, ECDSA and SHA
algorithms.

```c
#include <tiny_crypto/piv_cvc.h>

TC_X509_signature_result verify_card_cvc(
    TC_bytes encoded, TC_bytes intermediate, TC_bytes expected_uuid,
    TC_EC_curve curve, const TC_X509_certificate* validated_signer,
    const TC_X509_signature_provider* provider,
    TC_EC_workspace* point_scratch, size_t* work, TC_PIV_CVC* result)
{
    const TC_TLV_limits limits = {4096, 4096, 128, 16};
    const TC_PIV_CVC_chain_request request = {
        encoded, intermediate, expected_uuid, curve, validated_signer
    };
    return TC_PIV_CVC_chain_verify(&request, &limits, provider,
        point_scratch, work, result);
}
```

Keep `TC_EC_workspace` off small task stacks and separate from the signature provider's scratch.
Inputs, result, work and point scratch must be disjoint. The verifier retains no storage and clears
point scratch after use. On `TC_X509_SIGNATURE_VALID` the result borrows the card CVC's original
bytes. Every other outcome preserves the result and ends this attempt. Handle `INVALID`,
`UNSUPPORTED`, `LIMIT` and `ERROR` explicitly.

## Signer trust and revocation

`TC_PIV_CVC_validate` in `<tiny_crypto/credential.h>` combines signer path discovery,
content-signing policy, revocation and CVC verification through a `TC_validation_context`.
`example_validate_cvc` in `examples/credential_object.c` adapts path and CRL inputs to it.

For PIV the signer needs `id-fpki-common-piv-contentSigning`, digitalSignature key usage and the
content-signing EKU, and must be valid at the evaluation time. A TWIC profile accepts the
registered PIV and TWIC content-signing purposes and keeps the caller's certificate-policy
settings. TWIC profiles require `TC_ENABLE_TWIC`. Certificate and CRL policies must use the same
evaluation time.

The result is a `TC_credential_status`, shared with CMS credential validation. Only
`TC_CREDENTIAL_VALID` writes the borrowed CVC result. Revoked, unavailable, unsupported, invalid,
limit and API-error outcomes stay distinct. Path and point checks can share scratch across their
sequential phases. `example_validate_cvc` uses the micro validation capacity with four certificate
and four CRL slots and clears its workspace before returning. Hold the snapshot, issuer
candidates, anchors, CRLs and credential bytes stable through the decision.

During key establishment, `TC_PIV_SM_authenticate_response` in `<tiny_crypto/piv_sm_authenticate.h>`
runs this chain check on the decoded GENERAL AUTHENTICATE answer and completes key confirmation.
`<tiny_crypto/piv_sm.h>` builds without the CVC and X.509 modules. EAC certificates use their own
profile. See [PIV secure messaging](piv-sm.md#key-establishment).
