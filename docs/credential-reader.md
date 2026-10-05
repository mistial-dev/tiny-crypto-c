<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Credential reader example

`examples/credential_check` builds two PC/SC commands. `credential_check` inspects the TWIC and
PIV applications. `twic_authenticate` authenticates a TWIC card with locally provisioned trust
material. [Composing PIV and TWIC validation](credential-validation.md) applies the same policy to
retained objects without APDUs.

The commands need an installed tiny-crypto-c package with TWIC support (`TC_ENABLE_TWIC`). The
`desktop` resource profile and the `twic` [application target](targets.md) enable everything they
use. A custom selection needs TLV with BER, DER, APDU, the PIV commands, CHUID, objects, OIDs,
catalog and key proofs, FASC-N, TWIC with UUID, TPK and CCL, X.509 with path validation and
revocation, CMS with validation, credential validation, key challenges, GZIP, RSA, EC and the
certificates' hashes, including SHA-1.

```sh
cmake -S examples/credential_check -B build/credential-check \
  -DCMAKE_PREFIX_PATH=/path/to/tiny-crypto-install
cmake --build build/credential-check
ctest --test-dir build/credential-check --output-on-failure
build/credential-check/credential_check --reader 'Your PC/SC reader name'
```

macOS builds use the system PC/SC framework. Linux builds need the PC/SC development package and
`pkg-config`. The CTest entries cover help and argument handling.

## Authenticate a TWIC card

```sh
build/credential-check/twic_authenticate \
  --reader 'Your PC/SC reader name' \
  --root /path/to/approved-root.der \
  --root-sha256 64-hex-digit-provisioned-fingerprint \
  --issuer /path/to/issuer.der \
  --ccl /path/to/provisioned-ccl.bin \
  --marsec-level 1
```

The command selects the TWIC application and reads the slot 9E certificate. Legacy TWIC switches
to its PIV application for that step. It accepts either registered PIV/TWIC card-authentication
purpose OID, validates the path and identifiers, checks the CCL, and verifies a fresh card challenge
with native crypto. NEXGEN requires RSA-2048. RSA-1024 requires `--allow-rsa1024`. No PIN is sent.

| Option                       | Meaning                                                           |
| ---------------------------- | ----------------------------------------------------------------- |
| `--reader`                   | Substring matching exactly one PC/SC reader name                  |
| `--root`                     | Locally approved CA certificate that anchors the card path        |
| `--root-sha256`              | SHA-256 of the exact DER root, from the same trusted channel      |
| `--issuer`                   | Untrusted issuer candidate, up to three, omitted for direct issue |
| `--ccl`                      | Packed CCL image from a completed import                          |
| `--marsec-level`             | 1, 2 or 3 (default 1), which sets the CCL age limit               |
| `--minimum-publication`      | Floor in Unix seconds for the CCL file creation time              |
| `--allow-rsa1024`            | Accept RSA-1024 card keys on TWIC Legacy                          |
| `--rsa-padding`              | `v15` (default) or `pss` for RSA card challenges                  |
| `--extended-reads`           | Read objects with extended APDUs                                  |
| `--piv-certificate-envelope` | Read the TWIC certificate in the PIV container envelope           |

The root's subject, public key and name constraints define the anchor. CA key usage and
path-length constraints apply when present, and other critical root extensions fail. The root's
own signature is outside the path checks. A root file that differs from `--root-sha256` fails
before card access.

The `--ccl` file holds sorted 25-byte FASC-Ns (see [indexed storage](twic-ccl.md#indexed-storage)).
The command reads it into its own buffer and closes it before opening the card, with no network
retrieval. Its age comes from the file creation time: up to seven days at MARSEC level 1 and one day
at levels 2 and 3. A missing or future creation time fails. Copying or rebuilding the file can reset
that time, so preserve the acquisition date when preparing the image. Provision the latest list,
refresh it within 12 hours of a MARSEC increase, and track level changes in the system that
supplies the CCL ([33 CFR 101.525](https://www.law.cornell.edu/cfr/text/33/101.525)).

`--extended-reads` requests each object within the buffer limit and follows `61xx` with GET
RESPONSE. A `6282` end-of-object warning is accepted only with a complete `53` envelope, and
truncated objects fail even with `9000`. An answer longer than the Le of its command is malformed
(ISO/IEC 7816-4:2020 section 5.1 Table 1). `--piv-certificate-envelope` accepts the PIV `70`, `71`,
empty `FE` envelope in place of the TWIC `70`, `71` envelope. It changes framing only.

`pss` uses SHA-256, MGF1-SHA-256 and a fresh 32-byte salt. `v15` uses PKCS #1 v1.5 with SHA-256. EC
challenges use SHA-256 for P-256 and SHA-384 for P-384. Certificate signatures use the algorithm
each certificate records. A failed card proof stops the command.

The system UTC clock supplies the evaluation time. After the card exchange, the command checks CCL
freshness and the certificate path again. Clock rollback or an exchange over 30 seconds fails.
Output holds status and fixed failure descriptions, without credential identifiers. Exit status is
0 for active-card authentication, 1 for a failed check or operation, and 2 for invalid arguments.
Apply access authorization separately.

The command reserves a 16 MiB CCL image and 8 KiB per provisioned certificate. Card-response,
decompression and crypto workspaces are locked in memory and cleared at cleanup, and a failed lock
aborts the command. Reader access is exclusive. Cleanup releases it with `SCARD_LEAVE_CARD`.

### Include a signed CHUID

Add content-signer trust and revocation inputs:

```sh
build/credential-check/twic_authenticate \
  --reader 'Your PC/SC reader name' \
  --root /path/to/approved-card-root.der \
  --root-sha256 64-hex-digit-card-root-fingerprint \
  --ccl /path/to/provisioned-ccl.bin \
  --marsec-level 1 \
  --chuid-root /path/to/approved-content-root.der \
  --chuid-root-sha256 64-hex-digit-content-root-fingerprint \
  --chuid-issuer /path/to/content-issuer.der \
  --chuid-crl /path/to/content-root.crl \
  --chuid-crl /path/to/content-issuer.crl
```

`--chuid-root` is the approved content-signing root and requires `--chuid-root-sha256` and at least
one `--chuid-crl`. Card-key and content-signer trust stay separate. Repeat `--chuid-issuer` for up
to three candidates, or omit it for a directly issued signer. Supply up to four CRLs covering the
content signer's and the card certificate's paths. Missing, stale or unverifiable revocation
evidence fails.

Certificates and the CCL load before reader access. CRLs are scanned once the CHUID names its
signer candidates, in bounded windows with a 64 MiB limit per file. Keep the files unchanged during
the operation. Unsupported or oversized entries fail. Parsed CRL metadata and serial results stay
held through the final time check, which repeats the card path's revocation check.

After the card proof, the command reads the CHUID from the PIV application on Legacy TWIC and the
TWIC application on NEXGEN, into its own 16 KiB locked buffer. Validation binds its FASC-N and GUID
to the card certificate and checks the signature, content-signing usage (either registered purpose
OID), trust, revocation and expiration. Expiration is inclusive through the stated UTC date.
Unsigned CHUIDs fail.

- `--chuid-ber` selects [TWIC BER attribute compatibility](cms.md). DER is the default.
- `--cms-rsa-parameters allow-absent` accepts RSA signatures that omit the NULL algorithm
  parameters in the CHUID, biometric and Security Object signatures. It requires `--chuid-root`.
  `null`, the default, requires them.

Exit status 0 then also requires every requested CHUID check. The command prints a separate
signed-CHUID success line and clears its CHUID and CMS workspace at cleanup.

### Authenticate encrypted biometric objects

Add `--tpk-hex /path/to/ZTA.txt` to the signed-CHUID command. The file holds the hexadecimal ZTA
field of an already decoded TWIC barcode, optionally ending in a newline. It is a privacy key, so
keep it outside the repository and readable only by the reader application. The build needs
`TINY_CRYPTO_ENABLE_AES=ON`, `TINY_CRYPTO_AES_ENABLE_ECB=ON` and 128-bit AES.

The TPK loads into locked memory before the reader opens. After card-key and CHUID authentication,
the command reads the protected fingerprint object from the TWIC application, plus the protected
facial image on NEXGEN. It keeps each stored response and decrypts a copy of its `BC` value (see
[TWIC barcodes and privacy keys](twic-barcode.md)). It checks each CBEFF format and record, binds
the header and signed identifiers to the CHUID, and validates each biometric signature, signer path
and revocation. An omitted signing certificate selects the CHUID signer. The parser uses the
version-3 CBEFF header of SP 800-76-1 and SP 800-76-2 and requires a signed entryUUID by default.

`--fips201-1-biometric-signature` selects the FIPS 201-1 section 4.4.2 signature profile that the
older TWIC biometric specification references. It permits an absent signed entryUUID. A present
one must match the CHUID. Signed FASC-N stays mandatory and must match the CHUID and CBEFF header.

Each plaintext and stored response has its own 16 KiB locked buffer through the final check, wiped
with the TPK. Success requires every requested object check, including record structure and the
CBEFF validity period. Matching a live sample is an application step. The command prints no key or
biometric data.

### Collecting a security-object inventory

Add `--security-object` with the signed-CHUID options. The command reads each inventory object
from the TWIC application once, binds the signed CHUID to the authenticated card, and verifies the
Security Object signature, signer path, revocation and every stored-object hash. These checks run
again over the retained bytes at the final time. With `--tpk-hex`, decryption reuses the collected
biometric objects.

The stored object is hashed by default. `--printed-plaintext` hashes the decrypted
printed-information TLVs instead, for cards whose Security Object covers them, and requires
`--security-object` and `--tpk-hex`. The command then parses the DFC109 fields, checks their date
against the signed CHUID and validation time, and wipes the plaintext at cleanup. See
[inventory hash inputs](credential-validation.md#inventory-hash-inputs).

The inventory comes from `TC_PIV_inventory_read` over the TWIC
[catalog](piv-card.md#catalog-and-inventory). Legacy requires the signed CHUID, unsigned CHUID and
fingerprints. NEXGEN also requires the facial image. Every object must be present or reported
absent (`6A82` or `6A88`). The command fails when a required object is missing, an object is denied
or exceeds 16 KiB, or the signed hash list differs from the inventory. Decrypting and interpreting
the remaining NEXGEN objects is left to the application.

A locked pool holds the 12 NEXGEN catalog objects plus one more answer. Phases share scratch
storage in sequence, while encoded objects and decrypted records keep separate buffers. The present
stored objects borrow the pool and go to `TC_PIV_security_validate` with the complete `53` answer
of the Security Object ([validating an inventory](lds.md#validating-an-inventory)). The certificate,
Discovery Object and TWIC Privacy Key are outside the signed map. The command validates the signed
CHUID against the card before selecting its signer, binds the unsigned CHUID (container `3002`)
with `TC_TWIC_unsigned_CHUID_validate`, and clears the pool with `TC_PIV_inventory_clear`.

## Inspect both applications

```sh
build/credential-check/credential_check --reader NAME [--twic-unsigned-chuid]
```

`credential_check` selects the TWIC and PIV applications and reads their CHUID and
card-authentication certificate containers. It checks application identity, CHUID fields,
certificate-container fields and X.509 structure, and decodes GZIP certificates with bounded output
and work. It checks structure only, so its exit status is never an acceptance decision.

TWIC CHUIDs use the signed profile unless `--twic-unsigned-chuid` selects the unsigned schema. PIV
always uses its signed schema. Output holds fixed object labels and status.

The command disables core files and locks its 16 KiB response buffer, 8 KiB certificate buffer and
GZIP workspace before opening the reader, aborting if locking fails. Credential bytes are cleared
after each object and before exit. One exclusive transaction spans the operation. Transport
failures end processing, responses share one exchange budget, and an oversized object fails with a
resource limit. Cleanup requests `SCARD_LEAVE_CARD`.

Card commands come from the library ([PIV card commands](piv-card.md)).
`examples/credential_pcsc.c` supplies the PC/SC transport as a `TC_APDU_transmit`, also used by
[`piv_inspect`](piv-card-check.md#inspect-a-card):

- `example_card_pcsc_open` takes a reader substring that must match exactly one reader. It reads
  the ATR with `SCardGetStatusChange` before connecting and refuses reader names and ATRs that
  contain `yubico` or `yubikey` in any case, so an attached YubiKey receives no command.
- A PC/SC contactless ATR (`3B 8X 80 01`) refuses a contact request. `example_card_pcsc_interface`
  reports the interface for the link.
- An optional `ExampleCardPCSCGuard` sees every command before it is sent and every answer.
- `example_card_pcsc_reset_on_close` resets the card on close, which clears its PIN status.

## Card-key authentication

`TC_PIV_key_prove` in `<tiny_crypto/piv_key_proof.h>` proves possession of a card key. See
[key proofs](piv-card.md#key-proofs) for its key policy, command format, slot rules and workspace.
Call it after validating the certificate path and identifiers, and hold the reader transaction and
certificate buffer throughout. Use a cryptographically secure RNG. A failed RNG request ends
processing before any card command. `TC_PIV_OK` reports key possession only. Report trust and
credential policy separately. [PIV secure messaging](piv-sm.md) runs on the same link.

### Certificate identifiers

`TC_PIV_card_identifiers_read` reads the subject alternative name `GeneralNames` of the slot 9E
certificate under an explicit `TC_PIV_CARD`, `TC_TWIC_LEGACY_CARD` or `TC_TWIC_NEXGEN_CARD`
profile. The result borrows the FASC-N, its encoded OID and the UUID URN from the certificate
buffer, so keep that buffer unchanged while using it.

- TWIC profiles accept the registered PIV and TWIC FASC-N OIDs. Duplicate identifiers fail, also
  under different OIDs. FASC-N parity, delimiters and decimal fields are checked.
- PIV requires a version 1, 4 or 5 UUID.
- NEXGEN requires the Appendix D namespace and a UUID card number matching the FASC-N agency,
  system and credential fields. Use it for the TWIC application's certificate.
- Legacy TWIC permits an absent or nil UUID. An absent UUID matches a nil CHUID GUID.

Pass the borrowed 25-byte `fascn` to `TC_TWIC_CCL_contains`, or compare the identifiers with a
CHUID's FASC-N and GUID through `TC_PIV_card_identifiers_match`. Check both its status and its
`matched` output.

For a slot 9A certificate, `TC_PIV_authentication_identifiers_read` takes the Card UUID from the
signed CHUID and uses it to pick the Card UUID when the SAN also holds a Cardholder UUID. It
returns both borrowed URNs and requires a version 4 Cardholder UUID.
`TC_TWIC_authentication_identifiers_read` applies TWIC reader policy: either registered FASC-N OID
and an optional Card UUID.

### TWIC active-card authentication

`example_twic_authenticate` in `credential_validate.h` combines the checks of TWIC Part 2 section
7.5. Its `ExampleTWICRequest` borrows a trust source, path policy, TWIC profile, an acquired CCL
snapshot and the slot 9E certificate as DER. Use `TC_TWIC_NEXGEN_CARD` after selecting the NEXGEN
TWIC application and `TC_TWIC_LEGACY_CARD` after selecting the Legacy card's PIV application.

The helper discovers the path from the source's issuer candidates and anchors. The path purpose
must be the registered PIV or TWIC card-authentication OID the certificate uses, with
digital-signature key usage and an explicit extended key usage match. It then reads the
identifiers, checks CCL freshness and cancellation, and proves possession of the card key. A second
CCL query catches a publication that supersedes the snapshot during card I/O. The command checks
the snapshot again before its final path check.

Freshness uses the path's evaluation time in Unix seconds, from 1970 onward. Supply `ccl_max_age`
in seconds and the persisted `ccl_minimum_publication` floor from trusted provisioning. `ccl_reads`
bounds each lookup, and certificate processing and the key proof share the work budget. Hold the
reader transaction and snapshot until the call returns, then release the snapshot under the store
lock. Apply the application's transaction duration and clock policy before acting on a result.

`EXAMPLE_TWIC_AUTHENTICATED` reports active-card authentication at that instant. Other results
distinguish cancellation, stale or unavailable status, invalid credentials, unsupported
algorithms, resource limits, transport failure and API or provider errors. With content-signer
inputs, the command adds `TC_PIV_CHUID_validate`, and its accepted identifiers and signer feed the
Security Object and biometric checks. The caller-owned `ExampleTWICWorkspace` is cleared after
processing. Keep it off a small task stack, disjoint from request data and provider scratch.

### Provisioned inputs

`pki_input.h` holds the file reader and trust source shared by the example commands.
`example_read_file` reads into caller storage, rejects empty or oversized files, and clears the
buffer on failure. The returned span borrows that buffer. `example_read_stream` does the same for
an open stream. `example_x509_source` takes separate arrays of issuer candidates and locally
authorized anchors, which must stay unchanged during validation. Populate anchors through trusted
provisioning. An issuer candidate carries no anchor authority.

## Tests

The tests need no reader and use no live-card data.

- `test_card_authentication` (with `TINY_CRYPTO_TEST_OPENSSL=ON`) runs key proofs and the
  combined TWIC workflow against an OpenSSL-backed synthetic card with generated keys. It covers
  all five key sizes and curves, both purpose OIDs, tampered and replayed replies, transport and
  RNG failures, exhausted budgets, and stale, missing or updated lists. Rejected pre-challenge
  checks assert that neither the RNG nor the transport ran.
- `test_twic_command` runs `credential_check` over synthetic scripts. On macOS it also replaces the
  reader and memory-protection calls to check cleanup, wiping and each transfer failure.
- `test_twic_apdu_replay` replays the TWIC scripts through the library's card commands and
  catalog inventory.
- `test_twic_pcsc` (macOS) replaces the PC/SC calls to test cleanup, transport failures, the
  reader filter, Yubico refusals, the interface check, the guard and the reset on close.
- `test_twic_authenticate_command` runs `twic_authenticate` with synthetic files and PC/SC
  services. It covers NEXGEN and Legacy cards, compressed certificates, root constraints, signed
  CHUID trust and revocation, BER and RSA-parameter modes, argument errors before reader access,
  and tampering, clock and expiry failures during the exchange. Every cleanup checks that protected
  storage was cleared.

```sh
cmake --build build --target test_card_authentication
ctest --test-dir build --output-on-failure -R '^test_card_authentication$'
```
