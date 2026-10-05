<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# PIV card check

Enable `TINY_CRYPTO_ENABLE_PIV_CARD_CHECK=ON` and include `<tiny_crypto/piv_card_check.h>`. The
module turns a card [inventory](piv-card.md#catalog-and-inventory) into a report. Each entry names
one check and its outcome: `TC_PIV_CHECK_PASSED`, `TC_PIV_CHECK_FAILED`, or
`TC_PIV_CHECK_NOT_CHECKABLE` with a reason. The application states what it requires, and
`TC_PIV_card_report_accepts` compares the report with those requirements.

The module needs the credential validators, the catalog, X.509 paths and revocation, and GZIP.
OCSP evidence needs `TINY_CRYPTO_ENABLE_X509_OCSP`, key proofs `TINY_CRYPTO_ENABLE_PIV_KEY_PROOF`
and the card CVC check `TINY_CRYPTO_ENABLE_PIV_CVC`. TWIC profiles and the TWIC application need
`TC_ENABLE_TWIC`. The module allocates nothing, and the key proofs are the only commands it sends
to the card.

## Flow

1. Open a `TC_PIV_link` and select the application ([PIV card commands](piv-card.md)).
1. When secure messaging follows, read `5FC122` and the CHUID in plaintext. Establish secure
   messaging, the VCI and the PIN as the card and the application allow
   ([PIV secure messaging](piv-sm.md)).
1. Read the inventory with `TC_PIV_inventory_read`.
1. Call `TC_PIV_card_check` with the inventory, the link, the card profile and two validation
   contexts.
1. Call `TC_PIV_card_prove_keys` for the card keys to prove.
1. Decide with `TC_PIV_card_report_accepts`.
1. Clear the inventory, the link and the secure messaging session on every exit path.

`TC_PIV_OK` from `TC_PIV_card_check` means the report is complete, and acceptance is a separate
decision. Only a `PASSED` entry counts as success, and a requirement that matches a
`NOT_CHECKABLE` entry rejects the card.

## Inputs

`TC_PIV_card_check_request` borrows everything for the call. The report keeps views of the
inventory pool, the workspace buffers and the trust inputs, so keep them unchanged while the
report is in use.

| Field                              | Purpose                                                                          |
| ---------------------------------- | -------------------------------------------------------------------------------- |
| `inventory`                        | the read inventory. Its `link` member gives the interface and access state.      |
| `link`                             | the link that read it, or `NULL` for retained objects                            |
| `profile`                          | the credential profile (see below)                                               |
| `card`                             | trust, CRLs, time and revocation policy for the card certificates                |
| `content`                          | trust, CRLs, time and revocation policy for the signed objects and `5FC122`      |
| `ocsp`                             | one DER OCSP response per card certificate slot and its bounds, or `NULL`        |
| `sm_card_cvc`                      | the card CVC of the secure messaging session, or empty                           |
| `plain_copies`, `plain_copy_count` | objects read before secure messaging, for `COPY_MATCH`                           |
| `piv_card_chuid`                   | CHUID profile of a PIV card's PIV application, `TC_CHUID_PROFILE_PIV` by default |

On the TWIC application the profile equals the SELECT profile of the inventory. On the PIV
application it is `TC_PIV_CARD`, or a TWIC profile for the PIV application of a TWIC card. Both
contexts use the same evaluation time and may share one validation arena. Each context's
`TC_validation_options.revocation` selects its revocation evidence policy
([validation](validation.md#configure-policy-and-trust)).

A PIV card CHUID must follow SP 800-73-5 Part 1 Table 10 by default. Cards issued under
SP 800-73-4 may carry Buffer Length, Organizational Identifier or DUNS fields, or a GUID of another
UUID version. Set `piv_card_chuid` to `TC_CHUID_PROFILE_PIV_SP800_73_4` for those cards.
`TC_PIV_card_chuid_profile` returns the CHUID profile the check uses.

`TC_PIV_card_check_workspace` holds GZIP and EC scratch and two caller buffers. `certificates`
receives the decoded GZIP certificates one after another, and 16 KiB holds the five certificates
of an SD 33 card. `lds_content` receives the decoded LDS of the Security Object, and 4 KiB covers
16 data groups. The workspace and the report are each under 3 KiB on a 64-bit desktop, so keep
them in static or caller-owned storage on small stacks.

## Large CRLs

An issuer CRL can be far larger than a card. TWIC CA 1 publishes a CRL of about 17 MB with more
than 750,000 entries. Prepare such a CRL from a byte source ([CRLs](x509-crl.md)) for only the
certificates the card check will query:

1. Read the inventory.
1. `TC_PIV_card_crl_targets` lists the issuer and serial of each card certificate, the secure
   messaging signer and every certificate embedded in the CMS of the CHUID, the Security Object
   and the biometric objects, each pair once. `TC_PIV_crl_target_workspace` holds GZIP scratch, a
   buffer for decoded certificates and parser frames.
1. Prepare each CRL for those targets with `TC_X509_crl_prepare_begin`,
   `TC_X509_crl_prepare_step` and `TC_X509_crl_prepare_finish`, and index the records.
1. Build the card and content contexts with that index and run `TC_PIV_card_check`.

Preparation scans each CRL once and keeps only the target entries. The resolver verifies each
prepared CRL's signature, issuer and dates. Targets are collected before authentication, and the
card check authenticates every certificate it relies on. A certificate outside the targets has no
usable lookup, so its revocation check lacks evidence.

## Checks

The report lists the checks in this order. Container IDs follow SP 800-73-5
Part 1 Table 8.

| Check                     | Source                                                                  |
| ------------------------- | ----------------------------------------------------------------------- |
| `MANDATORY_OBJECT`        | each mandatory catalog entry: Part 1 Table 2 M rows, TWIC Part 2 v5 4.5 |
| `CERTIFICATE_PATH`        | each card certificate: GZIP decode and the path for the key's purpose   |
| `REVOCATION`              | OCSP or CRL evidence for a certificate or a signer path                 |
| `CERTIFICATE_IDENTIFIERS` | the subjectAltName of `9E`, and of `9A` against the CHUID               |
| `CHUID`                   | `TC_PIV_CHUID_validate`: signature, signer, policy and expiration       |
| `SECURITY_SIGNATURE`      | `TC_PIV_security_authenticate`: signature, signer and container map     |
| `SECURITY_DIGEST`         | `TC_PIV_security_digest_check` for each container in the signed map     |
| `BIOMETRIC`               | `TC_PIV_biometric_validate` for the fingerprints and the facial image   |
| `PRINTED_EXPIRATION`      | the printed expiration equals the CHUID and is current (Part 1 3.3.1)   |
| `DISCOVERY_CONSISTENCY`   | a nonempty BIT group needs the Discovery OCC bit (Part 1 3.3.6)         |
| `SM_SIGNER`               | the `5FC122` Certificate Signer as a content signer (Part 1 3.3.7)      |
| `SM_CVC`                  | the session CVC under that signer (Part 2 4.1.5)                        |
| `KEY_PROOF`               | a card key signed a fresh challenge (`TC_PIV_card_prove_keys`)          |
| `COPY_MATCH`              | a plain copy equals the inventory object byte for byte                  |

The certificates run in the order `9E`, CHUID, `9A`, `9C`, `9D`. `9E` needs digitalSignature and
the one card authentication EKU: the PIV OID under the PIV profile, or the PIV or TWIC OID under
TWIC profiles (TWIC Part 2 v5 section 6). `9A` and `9C` need digitalSignature. `9D` keeps the
purpose of the card context. The path check accepts missing evidence, which the certificate's
`REVOCATION` entry reports. `certificate_valid[slot]` is 1 when the path is valid and the card
context policy accepts the evidence. Only those certificates take identifiers and key proofs.

A mapped container that is absent, denied or empty fails its digest, because the signed map
proves the object exists. The Discovery Object digest covers the value of `7E`, and every other
digest the value of the `53` container. Iris records and the TWIC Privacy Key encrypted objects of
the TWIC application are `NOT_CHECKABLE` with reason `UNSUPPORTED`. So is the TWIC application
digest of `3001`, which covers the plaintext printed information (TWIC Part 2 v5 section 4.6.5
note 1) that the card stores TPK-encrypted.

`SM_CVC` passes only on a link that reports secured with no lost session, with the curve of its
suite. Key confirmation took place at session establishment, so the check re-verifies the CVC
chain under the signer it validated itself.

On the PIV application of a TWIC card every object except the Discovery Object is Never on
contactless (TWIC Part 2 v5 section 4.2). A contactless denial there is `NOT_CHECKABLE` under a
TWIC profile and `FAILED` under `TC_PIV_CARD`.

## Outcomes and reasons

`TC_PIV_check.status` holds the validator status behind the outcome:

| Validator status | Outcome                             |
| ---------------- | ----------------------------------- |
| `VALID`          | `PASSED`                            |
| `INVALID`        | `FAILED`                            |
| `REVOKED`        | `FAILED`                            |
| `UNAVAILABLE`    | `NOT_CHECKABLE`, `NO_EVIDENCE`      |
| `UNSUPPORTED`    | `NOT_CHECKABLE`, `UNSUPPORTED`      |
| `LIMIT`          | `NOT_CHECKABLE`, `LIMIT`            |
| `ERROR`          | `TC_PIV_card_check` returns `ERROR` |

| Reason          | Meaning                                                           |
| --------------- | ----------------------------------------------------------------- |
| `ABSENT`        | the card reported the object missing (`card_status` holds the SW) |
| `EMPTY`         | the object is `53 00`                                             |
| `RESTRICTED`    | the access rule was unmet, or the link is unsecured for `SM_CVC`  |
| `DENIED`        | the card refused a read whose rule was met                        |
| `NO_EVIDENCE`   | no current OCSP response or CRL covers a path member              |
| `UNSUPPORTED`   | an algorithm, format or object outside this build's support       |
| `DEPENDENCY`    | a prerequisite check has another outcome than `PASSED`            |
| `NOT_REQUESTED` | the input was missing, such as an empty `sm_card_cvc`             |
| `LIMIT`         | a capacity, parsing limit or work budget ran out                  |
| `CARD_STATUS`   | the card answered a key proof with `card_status`                  |
| `OVERSIZED`     | the object exceeded the inventory pool                            |

Prerequisites: the CHUID needs a usable `9E` certificate. The signed objects and the `9A`
identifiers need an accepted CHUID. The printed expiration needs a passed `3001` digest. Discovery
consistency needs an authenticated Security Object and a passed digest of the Discovery Object and
the BIT group when the map names them (Part 1 sections 3.3.2 and 3.3.6).

Under `TC_VALIDATION_REVOCATION_REQUIRED` with no evidence the CHUID is
`NOT_CHECKABLE/NO_EVIDENCE`, so every signed object check depends on it. Under
`TC_VALIDATION_REVOCATION_WHEN_AVAILABLE` the checks pass and each `REVOCATION` entry is
`NOT_CHECKABLE/NO_EVIDENCE`. An application that requires revocation lists `REVOCATION` among its
requirements.

## Requirements

`TC_PIV_check_requirement` names a check kind. A nonzero `key_reference` or `container` narrows
it. `TC_PIV_card_report_accepts` returns 1 when every requirement matches at least one entry and
every matching entry passed. `{TC_PIV_CHECK_SECURITY_DIGEST, 0, 0}` therefore needs every mapped
container, the PIN-gated ones included. `TC_PIV_card_report_find` returns the first matching
entry.

A contactless reader without the VCI can still accept a card on `{TC_PIV_CHECK_KEY_PROOF, 0x9e, 0}`
with the `9E` path and revocation, because the card authentication key is Always on both
interfaces (Part 1 Table 5).

## Key proofs

`TC_PIV_card_prove_keys` proves the keys of `TC_PIV_card_proof_request.keys` with
[`TC_PIV_key_prove`](piv-card.md#key-proofs) and appends one `KEY_PROOF` entry per key in the
order `9C`, `9A`, `9E`. `9C` is PIN Always, so it runs first, directly after the caller's PIN
submission. A proof uses `report->certificates[slot]` and needs `certificate_valid`. Without it
the entry is `NOT_CHECKABLE/DEPENDENCY` and nothing is sent. `TC_PIV_REFUSED` becomes `RESTRICTED`,
and `TC_PIV_CARD_STATUS` becomes `CARD_STATUS` with the card's answer. The TWIC application proves
`9E` only. The policy profile equals the report profile. The report certificates must lie outside
the link storage, which holds when the workspace certificate buffer and the inventory pool are
separate from the link buffers.

## Retained certificates

`TC_PIV_card_certificate_validate` checks one retained `9E` or `9A` certificate with the same
purpose rules and reads its identifiers. `9A` reads against the CHUID GUID, with the TWIC reader
rules of TWIC Part 3 v4 section 4.4.4 when `twic_reader_policy` is 1.
`examples/credential_workflow.c` calls it before the CHUID, Security Object and biometric
validators and the TWIC canceled card list
([credential validation](credential-validation.md)).

## Trust for the SD 33 cards

The SD 33 root is unavailable, so the tests pin the issuing CAs of `tests/vectors/x509/ocsp/sd33`.
Card 2 has its card certificates and CHUID signer under the RSA 3072 CA and its secure messaging
signer under the ECC P-384 CA. Card 4 has all of them under the ECC P-256 CA. A pinned issuing CA
signs its own CRLs, and the revocation engine accepts it as CRL signer with an empty path when its
certificate is current and permits cRLSign (RFC 5280 section 6.3.3 (f)). The vendored CRLs in
`tests/vectors/x509/crl/sd33` expire on 2026-10-01 and the OCSP responses on 2026-09-30, so the
tests evaluate at 2026-09-29T18:00:00Z. Later live runs find no current evidence. Use
`TC_VALIDATION_REVOCATION_WHEN_AVAILABLE` for them and treat the `REVOCATION` entries as
unchecked.

## Example

```c
#include <tiny_crypto/piv_card_check.h>

/* Check an inventory read on link and accept the card on its card
 * authentication path and revocation, the CHUID and the Security Object.
 * card and content share one evaluation time. The report borrows the
 * inventory pool and the workspace buffers. Returns 1 to accept, 0 to reject
 * and -1 when the check failed. */
int check_card(const TC_PIV_link* link, const TC_PIV_inventory* inventory,
               const TC_validation_context* card, const TC_validation_context* content,
               TC_PIV_card_check_workspace* workspace, TC_PIV_card_report* report)
{
  static const TC_PIV_check_requirement required[] = {
      {TC_PIV_CHECK_CERTIFICATE_PATH, 0x9e, 0},
      {TC_PIV_CHECK_REVOCATION, 0x9e, 0},
      {TC_PIV_CHECK_CHUID, 0, 0},
      {TC_PIV_CHECK_SECURITY_SIGNATURE, 0, 0},
      {TC_PIV_CHECK_SECURITY_DIGEST, 0, 0x3000}};
  const TC_PIV_card_check_request request = {
      inventory, link, TC_PIV_CARD, card, content, NULL, {NULL, 0}, NULL, 0, 0};
  size_t work = 100000000;
  const TC_PIV_result result = TC_PIV_card_check(&request, workspace, &work, report);
  if (result != TC_PIV_OK)
    return -1; /* ARGUMENT changed nothing. LIMIT and ERROR wiped the report. */
  return TC_PIV_card_report_accepts(report, required, sizeof required / sizeof *required);
}
```

`<tiny_crypto/piv_card_check.hpp>` wraps the functions as
`tiny_crypto::piv_card_check`, `piv_card_report_find`,
`piv_card_report_accepts`, `piv_card_certificate_validate` and
`piv_card_prove_keys`, which takes a `PIVLink`.

## Inspect a card

`examples/piv_inspect.c` runs the whole flow on any `TC_APDU_transport` and prints the report.
`example_piv_inspect_run` takes the interface, the length format, the PIN and pairing code, the
trust anchors, CRLs and OCSP responses, the revocation policy, the evaluation time and a random
source. It selects the TWIC application, inventories it in plaintext and checks it when present.
On the PIV application it then:

1. reads `5FC122` and the CHUID in plaintext and validates the secure messaging signer,
1. establishes secure messaging with `TC_PIV_SM_key_request`, `TC_PIV_SM_authenticate_response`
   under that signer and the CHUID GUID, and `TC_PIV_link_secure`,
1. reads the Discovery Object and establishes the VCI on contactless,
1. verifies the PIN with the reference the Discovery Object prefers,
1. reads the inventory, runs `TC_PIV_card_check` with the plain copies and the card CVC, and
   proves `9E`, and `9A` after the PIN, with `TC_PIV_card_prove_keys`.

CRLs are byte sources of any size. `examples/piv_inspect_crl.c` prepares each one for the secure
messaging signer before key establishment, then again for every inventory target before the check
([Large CRLs](#large-crls)). The `piv_inspect` command reads each `--crl` file from disk in pieces,
so the 17 MB TWIC CA 1 CRL needs no more memory than a small one.

A card without secure messaging runs in plaintext, and on contactless without the VCI only the
Always objects are read. The example skips the PIN Always key `9C`.

The example accepts the card when no entry is `FAILED`, the card accepted every PIN and pairing
code supplied, and these requirements pass:

| Condition              | Requirements                                                       |
| ---------------------- | ------------------------------------------------------------------ |
| always                 | `9E` path, `REVOCATION` of `0500`, `9E` key proof, CHUID           |
| contact or VCI         | `SECURITY_SIGNATURE`                                               |
| secure messaging suite | `SM_SIGNER`, `SM_CVC`, `COPY_MATCH`                                |
| PIN verified           | `9A` key proof, every `SECURITY_DIGEST`, `BIOMETRIC` 6010 and 6030 |

On a NEXGEN TWIC card the TWIC application report must also have no `FAILED` entry and pass the
`9E` path, `REVOCATION` of `0500`, the `9E` key proof and the CHUID (TWIC Part 2 v5 sections 4.6
and 5.3). A card whose application template offers a secure messaging suite must complete key
establishment, so a refused or failed establishment rejects the card.

The run returns 0 for an accepted card, 1 for a rejected card or a failed step and 2 for invalid
options. It never prints objects flagged `TC_PIV_OBJECT_SECRET` or passes them to the dump
callback, and the inventory skips the pairing code. Every return clears the inventory, the link
and the session and wipes the run's storage.

`examples/piv_inspect/CMakeLists.txt` builds the `piv_inspect` command against an installed
package with the PC/SC transport of `examples/credential_pcsc.c`. The library needs the card
check, key proofs, secure messaging framing and the VCI. Run it on SD 33 card 2 with the pinned
issuing CAs:

```sh
cmake -S examples/piv_inspect -B build/piv-inspect \
  -DCMAKE_PREFIX_PATH=/path/to/tiny-crypto-install
cmake --build build/piv-inspect
build/piv-inspect/piv_inspect --reader 'ACR1552 1S CL Reader PICC' \
  --anchor tests/vectors/x509/ocsp/sd33/card01_issuer.der \
  --anchor tests/vectors/x509/ocsp/sd33/card04_issuer.der \
  --crl tests/vectors/x509/crl/sd33/RSA3072IssuingCA.crl \
  --crl tests/vectors/x509/crl/sd33/ECCP384IssuingCA.crl \
  --revocation when-available --pin-prompt
```

`--reader` defaults to `TC_PIV_READER`, and exactly one reader name must contain it. The PC/SC
transport refuses reader names and ATRs that name a Yubico device before it connects, and refuses a
contact request on a reader whose ATR shows a contactless card. `--interface` defaults to the
interface the ATR shows. The PIN and pairing code come from `TC_PIV_PIN` and `TC_PIV_PAIRING_CODE`,
or from a prompt without echo. A PIN makes the reader reset the card on disconnect, which clears its
PIN status. Other options:

- `--anchor-sha256` pins the preceding anchor.
- `--ocsp 9a|9c|9d|9e FILE` supplies the OCSP response of one slot.
- `--at` sets the evaluation time as `YYYY-MM-DDTHH:MM:SSZ`.
- `--min-retries` sets the PIN retry floor of `TC_PIV_pin_verify`, 2 to 15, default 3.
- `--extended` selects extended length.
- `--chuid-sp800-73-4` selects `TC_CHUID_PROFILE_PIV_SP800_73_4`.
- `--dump-dir` writes each present object to a directory only its owner can read.

`TC_PIV_HARDWARE_GUARD=1` installs the transmit guard of the
[PIV card hardware tests](testing.md#piv-card-hardware-tests). Only the `test_piv_inspect_live`
build provides that guard, and other builds exit with status 2.

## Limits

- A report holds `TC_PIV_CARD_CHECKS_MAX` entries. More return `TC_PIV_LIMIT` with the report
  wiped. SD 33 card 2 on contactless with secure messaging, the VCI, the PIN and two key proofs
  fills 40.
- Iris records, TWIC Privacy Key decryption and the TWIC canceled card list stay with the
  application.
- The card context takes one OCSP response per certificate slot. The other path members use its
  CRLs.
- Work covers the validators and the GZIP decoding. Exhausted work makes the remaining checks
  `NOT_CHECKABLE/LIMIT`.
