<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Composing PIV and TWIC validation

[`examples/credential_workflow.c`](../examples/credential_workflow.c) runs the public validation
APIs over retained PIV or TWIC objects, trust snapshots and policy. The application owns card
commands, response framing and reader access. `example_credential_validate` runs these steps:

1. Validate the card-key certificate under card-key trust and read its identifiers with
   `TC_PIV_card_certificate_validate` ([card check](piv-card-check.md#retained-certificates)).
1. For TWIC, check the held canceled-card-list snapshot and its freshness.
1. Ask the application for a fresh proof with the accepted public key.
1. Validate the signed CHUID under separate content-signer trust.
1. If supplied, validate the Security Object over the retained inventory.
1. If supplied, parse authenticated printed information and check its expiration against the
   CHUID.
1. If supplied, bind the unsigned TWIC CHUID to the inventory.
1. If supplied, check each biometric format and authenticate it against the CHUID.
1. For TWIC, check the CCL snapshot again.

The [credential reader example](credential-reader.md) runs the same checks against a live card,
and the [card check](piv-card-check.md) reports each check over an inventory separately.

## Profiles and identifiers

The request selects PIV, TWIC Legacy or TWIC NEXGEN and a signed CHUID schema.
TWIC takes `TC_CHUID_PROFILE_TWIC_SIGNED`. PIV takes `TC_CHUID_PROFILE_PIV` for SP 800-73-5, or
`TC_CHUID_PROFILE_PIV_SP800_73_4` to opt in to SP 800-73-4 fields and the historical `3D` field.
`TC_PIV_CHUID_validate` also accepts the SP 800-73-4 schema under TWIC profiles for a TWIC card's
PIV application, where NEXGEN sends an empty `3D`.

PIV applies strict identifier and OID rules (`TC_PIV_card_identifiers_read`) and the PIV
card-authentication OID. TWIC follows Part 3 section 4.4.4 (`TC_TWIC_card_identifiers_read` and
`TC_TWIC_card_identifiers_match`). The full certificate FASC-N identifies the credential and must
match the CHUID. A UUID URI is optional, and a present one must satisfy the profile and match the
CHUID GUID. TWIC accepts the registered PIV or TWIC card-authentication OID and passes the
certificate's exact encoded OID to path validation.

`card_key` selects slot 9E Card Authentication or slot 9A PIV Authentication. Slot 9A requires
`TC_PIV_CARD` and takes the Card UUID from the signed CHUID GUID, which strict PIV requires in the
certificate. With `twic_reader_policy`, slot 9A on a TWIC card's PIV application accepts either
registered FASC-N OID and an absent Card UUID, and still checks any UUIDs present.

The card context may name an exact card-authentication purpose OID. With an empty purpose,
`TC_PIV_card_certificate_validate` derives one exact PIV/TWIC-compatible purpose from the
certificate. Slot 9E requires digital-signature key usage, extended key usage and an explicit
purpose match. Slot 9A requires digital-signature key usage.

## Key proof and time

The proof callback owns the transport and challenge exchange. It receives the profile, the key
reference, the accepted public key, and the signature scheme, hash, MGF hash and salt length. The
request chooses RSA v1.5 or PSS. NEXGEN requires RSA-2048. TWIC Legacy accepts RSA-1024 only with
`allow_rsa1024`.

The two `TC_validation_context` values run in sequence, so they may share one initialized
validation arena. Both use the same evaluation time, which TWIC also requires to equal
`TC_TWIC_CCL_freshness_policy.now`. PIV leaves the CCL and freshness fields zero.

`required_objects` names the evidence the decision needs: the Security Object, unsigned CHUID,
printed information or each biometric modality. Missing required evidence returns
`EXAMPLE_CREDENTIAL_UNAVAILABLE` before the card proof.

## Inventory hash inputs

`TC_PIV_security_data.parts` selects the bytes hashed for each container. Choose them before the
check and keep them fixed for the decision. The library hashes the supplied spans as given, with no
decryption or fallback, and a mismatch fails. Both forms exclude the outer GET DATA `53` wrapper:

- Encrypted biometric objects use their stored `BC` field, including its tag and length.
- Under a printed-plaintext policy, container `0x3001` uses the decrypted printed-information TLVs.
  Keep that buffer stable until inventory validation ends, then wipe it.

`security.printed`, when supplied, must equal the authenticated `0x3001` bytes and is parsed with
`TC_PIV_printed_read`. TWIC applies the DFC109 rules of TWIC Part 2 section 4.7.2, including field
order, the eight-digit card serial and the `7099` issuer prefix. The printed expiration must match
the signed CHUID and be current at the validation time. The result then sets `result.has_printed`
and exposes borrowed fields in `result.printed`.

## Results and lifetimes

All encoded inputs and trust sources are borrowed. Keep the certificate, CHUID, inventory, CCL
snapshot and their storage unchanged until the decision ends. `ExampleCredentialValidationResult`
holds views into them. Its `biometrics` array holds one `TC_PIV_biometric_report` per supplied
biometric, in request order, with the authenticated record for a matcher.

The typed verdict separates invalid credentials, revocation, cancellation, stale data, unavailable
evidence, unsupported algorithms, exhausted limits and failed key possession.
`EXAMPLE_CREDENTIAL_VALID` is authentication evidence. Site authorization, live biometric matching
and required-object policy stay with the application.

For a later access decision, create fresh card and content contexts at the current time, acquire
the current CCL snapshot for TWIC, and call `example_credential_validate` again over the retained
bytes.
