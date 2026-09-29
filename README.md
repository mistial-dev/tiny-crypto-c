<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# tiny-crypto-c

[![CI](https://github.com/mistial-dev/tiny-crypto-c/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/mistial-dev/tiny-crypto-c/actions/workflows/ci.yml)
[![License: GPL v2+](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](LICENSE)
[![CLA assistant](https://cla-assistant.io/readme/badge/mistial-dev/tiny-crypto-c)](https://cla-assistant.io/mistial-dev/tiny-crypto-c)

tiny-crypto-c provides small, portable cryptographic primitives for embedded C
and C++. Library code is heap free. Callers supply all memory. The C++11 wrappers
take pointer-length pairs, `bytes` spans and C arrays, work without the standard
library or exceptions, and return the C API's result types as `[[nodiscard]]`
values. Disabled algorithms and
modes are left out of the build.

The default profile enables **AES-128 CTR and SHA-256**. DES, 3DES, SHA-1,
SHA-224, SHA-384, SHA-512, HMAC, KMAC256, the NIST SP 800-108 key-based KDF,
[SP 800-90A DRBGs](docs/drbg.md) and other block-cipher modes can be enabled
as needed.

## Uses

Use the primitives in firmware that needs bounded AES, hashing, MACs, key
derivation, or caller-seeded random-bit generation. The optional credential
modules support PIV and TWIC reader workflows: parsing card data, checking
CMS signatures and X.509 paths, applying credential policy, and checking CRLs.
Feature gates let a small device link only the algorithms its application uses.
See the [credential reader guide](docs/credential-reader.md) and
[API guide](docs/api.md) for the supported workflows and buffer requirements.

## Versioning

Releases follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
using `MAJOR.MINOR.PATCH`. A major version can change public C or C++ calls or
documented behavior in ways that require caller changes. A minor version adds
compatible functionality. A patch version contains compatible fixes.

The public API comprises installed headers, documented behavior and status
values, build options, and the installed CMake target. Applications should
rebuild the library with their toolchain when upgrading. Binary compatibility
across different toolchains is outside this versioning policy. Version
**2.0.0** includes public API changes that require callers upgrading from 1.x
to review and update their code.

## Build

```sh
make
make test            # quick suite, skips tests labelled extended
make test-full       # every test, including NIST CAVP and Wycheproof corpora
make test-sanitize   # address + undefined behavior sanitizers
make benchmark
make size
```

Make passes all `TINY_CRYPTO_*` command-line variables to CMake:

```sh
make TINY_CRYPTO_ENABLE_HMAC=ON TINY_CRYPTO_AES_GCM=ON
```

Or build with CMake directly:

```sh
cmake -S . -B build -DTINY_CRYPTO_ENABLE_HMAC=ON -DTINY_CRYPTO_AES_GCM=ON
cmake --build build
```

As a CMake dependency:

```cmake
add_subdirectory(path/to/tiny-crypto-c)
target_link_libraries(firmware PRIVATE tiny-crypto-c::tiny-crypto-c)
```

`cmake --install` installs the headers, the archive, a CMake package and a
generated `tiny_crypto/build_config.h`. That header records the configuration
the archive was built with, so consumers that use the installed headers without
CMake get the same structure layouts. A `-D` definition that contradicts it
fails with "differs from the installed library configuration".

Public headers are in `src/tiny_crypto/`, following the Arduino library layout:

```c
#include <tiny_crypto/tiny_crypto.h>
```

Use `<tiny_crypto/tiny_crypto.hpp>` for the C++11 wrappers in the
`tiny_crypto` namespace.

## Configuration

All options are CMake cache variables. The defaults enable AES-128 CTR and
SHA-256, with memory wiping and pointer checks turned on.

`TINY_CRYPTO_RESOURCE_PROFILE=micro` favors small code and byte-limb EC
arithmetic. `mini` uses native arithmetic while keeping optional algorithms
off. `desktop` enables the supported capabilities, including legacy algorithms
and both PIV secure-messaging suites. Use this profile when broad compatibility
is required, and set application policy to restrict legacy algorithms.

`TINY_CRYPTO_TARGET=piv-acu` or `piv-pd` selects a fixed role-specific algorithm
set independently of resource tuning. See [PIV targets and ESP32-P4](docs/esp32-p4.md)
for the role requirements and ESP-IDF builds.

Feature options accept `AUTO`, `ON`, or `OFF`. `AUTO` follows the selected
profile. Explicit settings survive a profile change. Configuration compiles
`config.h` with the selected values and stops with its `#error` text when an
option lacks a dependency, so CMake and direct-source builds accept the same
combinations. Direct-source builds select
`TC_RESOURCE_PROFILE=TC_RESOURCE_MICRO`, `TC_RESOURCE_MINI`, or
`TC_RESOURCE_DESKTOP`. The defaults below describe a build with no profile
selected.

### Cryptography

| Option                       | Default | Purpose                                                             |
| ---------------------------- | ------: | ------------------------------------------------------------------- |
| `TINY_CRYPTO_ENABLE_AES`     |      ON | AES implementation                                                  |
| `TINY_CRYPTO_AES_DYNAMIC`    |     OFF | Per-context AES-128/192/256 keys, CBC, and CMAC                     |
| `TINY_CRYPTO_ENABLE_DES`     |     OFF | DES and 3DES implementation                                         |
| `TINY_CRYPTO_DES_ISO9797`    |     OFF | ISO/IEC 9797-1 DES MAC algorithms 1 and 3, requires DES             |
| `TINY_CRYPTO_ENABLE_EC`      |     OFF | P-192/P-256/P-384 ECDH, key generation, and ECDSA                   |
| `TINY_CRYPTO_ENABLE_RSA`     |     OFF | RSA public and private-key operations                               |
| `TINY_CRYPTO_ENABLE_SHA1`    |     OFF | SHA-1 implementation                                                |
| `TINY_CRYPTO_ENABLE_SHA224`  |     OFF | SHA-224 using the SHA-256 core                                      |
| `TINY_CRYPTO_ENABLE_SHA256`  |      ON | SHA-256 implementation                                              |
| `TINY_CRYPTO_ENABLE_SHA384`  |     OFF | SHA-384 using the SHA-512 core                                      |
| `TINY_CRYPTO_ENABLE_SHA512`  |     OFF | SHA-512 implementation                                              |
| `TINY_CRYPTO_ENABLE_MD5`     |     OFF | MD5 checksums for legacy data                                       |
| `TINY_CRYPTO_ENABLE_HMAC`    |     OFF | HMAC for enabled hashes                                             |
| `TINY_CRYPTO_ENABLE_KMAC256` |     OFF | Fixed-output KMAC256 with customization                             |
| `TINY_CRYPTO_ENABLE_KDF`     |     OFF | SP 800-108r1 KBKDF over enabled HMAC and CMAC PRFs                  |
| `TINY_CRYPTO_ENABLE_HKDF`    |     OFF | RFC 5869 HKDF over enabled HMAC-SHA algorithms                      |
| `TINY_CRYPTO_ENABLE_SSKDF`   |     OFF | SP 800-56C one-step hash KDF over the enabled SHA algorithms        |
| `TINY_CRYPTO_ENABLE_DRBG`    |     OFF | [SP 800-90A DRBGs](docs/drbg.md): Hash_DRBG, HMAC_DRBG and CTR_DRBG |
| `TINY_CRYPTO_DRBG_HASH`      |     OFF | Hash_DRBG over the enabled SHA algorithms                           |
| `TINY_CRYPTO_DRBG_HMAC`      |     OFF | HMAC_DRBG, which requires `TINY_CRYPTO_ENABLE_HMAC`                 |
| `TINY_CRYPTO_DRBG_CTR`       |     OFF | CTR_DRBG, which requires AES with `TINY_CRYPTO_AES_DYNAMIC`         |

### Formats, compression, and trust

| Option                                   | Default | Purpose                                                       |
| ---------------------------------------- | ------: | ------------------------------------------------------------- |
| `TINY_CRYPTO_ENABLE_TLV`                 |     OFF | Bounded TLV readers and tree traversal                        |
| `TINY_CRYPTO_TLV_BER`                    |     OFF | ASN.1 BER, including indefinite lengths, requires TLV         |
| `TINY_CRYPTO_TLV_STREAM`                 |     OFF | Incremental TLV reader, requires TLV                          |
| `TINY_CRYPTO_ENABLE_DER`                 |     OFF | DER value helpers, requires TLV                               |
| `TINY_CRYPTO_ENABLE_X509`                |     OFF | X.509 certificate and public-key readers, requires DER        |
| `TINY_CRYPTO_ENABLE_X509_PATH`           |     OFF | Path validation and stores, requires X.509                    |
| `TINY_CRYPTO_ENABLE_TRUST_ANCHOR_FORMAT` |     OFF | RFC 5914 lists, requires X.509 path validation                |
| `TINY_CRYPTO_TAF_CERTIFICATE`            |     OFF | Certificate choice in RFC 5914 lists                          |
| `TINY_CRYPTO_TAF_TBS_CERTIFICATE`        |     OFF | TBS certificate choice in RFC 5914 lists                      |
| `TINY_CRYPTO_TAF_TRUST_ANCHOR_INFO`      |     OFF | TrustAnchorInfo choice in RFC 5914 lists                      |
| `TINY_CRYPTO_ENABLE_X509_REVOCATION`     |     OFF | CRL parsing and path revocation, requires X.509 path support  |
| `TINY_CRYPTO_ENABLE_X509_OCSP`           |     OFF | OCSP requests and responses, requires X.509 paths and SHA-1   |
| `TINY_CRYPTO_ENABLE_KEY_CHALLENGE`       |     OFF | Key proof-of-possession challenge, requires X.509             |
| `TINY_CRYPTO_ENABLE_GZIP`                |     OFF | Bounded GZIP decompression                                    |

### PIV, TWIC, and credentials

| Option                                  | Default | Purpose                                                                |
| --------------------------------------- | ------: | ---------------------------------------------------------------------- |
| `TINY_CRYPTO_ENABLE_PIV_OIDS`           |     OFF | PIV and TWIC identifier classification                                 |
| `TINY_CRYPTO_ENABLE_CMS`                |     OFF | CMS parsing and verification, requires X.509, BER, and identifiers     |
| `TINY_CRYPTO_ENABLE_CMS_VALIDATION`     |     OFF | CMS signer paths and revocation, requires CMS and X.509 revocation     |
| `TINY_CRYPTO_ENABLE_PIV_OBJECTS`        |     OFF | PIV and TWIC object readers, requires CMS, TWIC UUID, and identifiers  |
| `TINY_CRYPTO_ENABLE_CREDENTIAL`         |     OFF | Credential validation, requires PIV objects, CHUID, and CMS validation |
| `TINY_CRYPTO_ENABLE_PIV_CHUID`          |     OFF | PIV CHUID reader, requires TLV                                         |
| `TINY_CRYPTO_ENABLE_PIV_CVC`            |     OFF | PIV secure messaging CVC reader, requires DER                          |
| `TINY_CRYPTO_ENABLE_EAC_CVC`            |     OFF | TR-03110 EAC CVC reader, requires DER                                  |
| `TINY_CRYPTO_ENABLE_PIV_SM`             |     OFF | Client-side PIV secure messaging, CS2 and CS7                          |
| `TINY_CRYPTO_ENABLE_FASCN`              |     OFF | FASC-N readers and writers                                             |
| `TINY_CRYPTO_ENABLE_TWIC_UUID`          |     OFF | TWIC NEXGEN UUID helpers, requires FASC-N                              |
| `TINY_CRYPTO_ENABLE_TWIC_CCL`           |     OFF | TWIC canceled card list reader                                         |
| `TINY_CRYPTO_ENABLE_TWIC_TPK`           |     OFF | TWIC privacy-key container reader, requires TLV                        |
| `TINY_CRYPTO_ENABLE_TWIC_OBJECT_CRYPTO` |     OFF | TWIC private-object encryption, requires AES-128 ECB                   |
| `TINY_CRYPTO_ENABLE_AAMVA`              |     OFF | ANSI AAMVA payload readers                                             |

### Safety and target storage

| Option                    | Default | Purpose                              |
| ------------------------- | ------: | ------------------------------------ |
| `TINY_CRYPTO_AVR_PROGMEM` |      ON | Keep constant tables out of AVR SRAM |

Secret wiping and public argument checks are always on. Finals, one-shot
calls and failure paths wipe contexts and stack secrets, and every public
entry validates its pointers.

The three `TINY_CRYPTO_TAF_*` choices follow the trust-anchor-format switch
under `AUTO`. At least one choice must be enabled when the format is enabled.
See [Trust anchors](docs/x509-trust-anchors.md) for importing authenticated
lists and applying their constraints.

### Modes and implementation choices

AES uses `TINY_CRYPTO_AES_KEY_BITS=128`, constant-time S-box access, and CTR by
default. `AES_CBC`, `AES_ECB`, `AES_OFB`, `AES_GCM`, `AES_CCM`,
`AES_EAX`, `AES_EAX_PRIME`, `AES_SIV`, and `AES_CMAC` enable individual modes
when prefixed with `TINY_CRYPTO_`. The S-box choices are `constant-time`,
`runtime`, and `fast`. GCM multiplication choices are `auto`, `bitwise`,
`wide`, `fast-table`, and `hardware`.

The non-constant-time `fast-table` mode adds 256 bytes to each GCM context.
Small MCUs can keep `TINY_CRYPTO_AES_TINY=ON` or use `auto`, `bitwise`, or
`wide` to avoid that RAM cost.

Enabling `TINY_CRYPTO_ENABLE_DES` also enables CTR and 3DES. `DES_ECB`,
`DES_CBC`, `DES_OFB`, `DES_CFB1`, `DES_CFB8`, `DES_CFB64`, `DES_CMAC`, and
`DES_ISO9797` select the remaining modes when prefixed with `TINY_CRYPTO_`.
One `struct TC_DES_ctx` serves single DES and TDEA, selected by an 8, 16 or
24-byte key. See [DES and TDEA](docs/api.md#des-and-tdea).
ISO 9797-1 MAC stays off in every resource profile. Enable it explicitly.
See [DES message authentication](docs/api.md#des-message-authentication) for
algorithm, padding, and tag requirements.
`TINY_CRYPTO_DES_REJECT_WEAK_KEYS=ON` rejects weak or semi-weak DES component
keys and TDEA bundles that collapse to single DES. It is off by default for
legacy-vector compatibility. Firmware builds may instead define
`TC_DES_REJECT_WEAK_KEYS=1` directly.

SHA-1, SHA-224, and SHA-256 are implemented in `hash.c`. SHA-384 and SHA-512
share a 64-bit core in `sha512.c`. SHA-224 and SHA-384 reuse the compression
functions of SHA-256 and SHA-512, respectively, but each hash can be enabled
independently.

`TINY_CRYPTO_ENABLE_KDF` builds the SP 800-108r1 key-based key derivation
function in counter, feedback and double-pipeline mode. It needs at least one
PRF: HMAC with an enabled SHA digest, `TINY_CRYPTO_AES_CMAC`, or
`TINY_CRYPTO_DES_CMAC`. Each PRF gets its own function family
(`TC_KBKDF_HMAC_SHA256_counter`, `TC_KBKDF_AES_CMAC_feedback`, ...), so unused
PRFs compile out. AES-CMAC keys follow `TINY_CRYPTO_AES_KEY_BITS`. TDEA-CMAC is
kept for legacy interoperability only. `kdf.h` describes the SP 800-108r1
key-control mitigations for the CMAC PRFs.

`TINY_CRYPTO_ENABLE_HKDF` needs HMAC and at least one enabled SHA family.
The C and C++ APIs provide extract, expand, and one-shot derive operations.
They also accept a revision 2 hybrid secret as separate `Z` and `T` spans.
See [HKDF usage](docs/hkdf.md) and the [C example](examples/hkdf.c).

Projects that compile the C files directly can define the corresponding
`TC_*` macros documented in [`config.h`](src/tiny_crypto/config.h).

## API behavior

See [Working with the API](docs/api.md) for buffer lifetimes, workspace setup,
result handling and complete workflow guides.

Cryptographic operations that can fail return a `TC_status` code:

```c
TC_OK        /* success */
TC_MISMATCH  /* valid comparison or authentication failure */
TC_ERROR     /* malformed argument or invalid state */
```

One-shot AEAD functions take inputs as `TC_bytes` and outputs as `TC_buffer`.
The tag buffer capacity selects the tag length. The text output must hold the
whole text input, and it may be the same buffer as the input:

```c
uint8_t ciphertext[sizeof message], tag[16];
TC_status status = TC_AES_GCM_encrypt(key, (TC_bytes){iv, 12}, (TC_bytes){aad, sizeof aad},
                                      (TC_bytes){message, sizeof message},
                                      (TC_buffer){ciphertext, sizeof ciphertext},
                                      (TC_buffer){tag, sizeof tag});
if (status != TC_OK)
  return status; /* ciphertext and tag hold no usable output */

status = TC_AES_GCM_decrypt(key, (TC_bytes){iv, 12}, (TC_bytes){aad, sizeof aad},
                            (TC_bytes){ciphertext, sizeof ciphertext},
                            (TC_bytes){tag, sizeof tag},
                            (TC_buffer){ciphertext, sizeof ciphertext});
if (status == TC_MISMATCH)
  return status; /* in-place ciphertext has been wiped */
```

Authentication checks examine the entire tag. GCM, CCM, EAX and EAX'
decryptors authenticate before writing plaintext. SIV writes candidate
plaintext to recompute its synthetic IV, so its associated data must be
disjoint from the output. Every AEAD failure after the argument checks wipes
the text output, separate or in-place. GCM decryption is one-shot. The
streaming GCM context encrypts only. See the
[AEAD contract](docs/api.md#authenticated-encryption) for overlap rules and
error conditions.
GCM requires a 12 to 16-byte tag by default. Use the explicit
`TC_AES_GCM_init_short_tag` or one-shot `_short_tag` functions when a protocol
requires a 4 or 8-byte tag. The GCM packet limits still apply.
CCM, EAX, AES-CMAC and DES-CMAC take tags of at least `TC_MIN_TAG_LEN` bytes
(default 8, raise-only up to 16). Protocols with shorter tags, such as 4-byte
CCM tags, call the `_short_tag` forms. EAX' keeps its fixed 4-byte tag. See
[Tag lengths](docs/api.md#tag-lengths).

CTR, CBC, ECB, OFB, and CFB provide no authentication. Pair them with a MAC or
use an authenticated mode such as GCM, CCM, EAX, or SIV. Never reuse a CTR,
GCM, CCM, EAX, or OFB nonce with the same key.

DES has only a 56-bit effective key and exists for legacy interoperability.
Its table lookups have no cache-timing protection. Limit 3DES to compatibility
code as well.

SHA-1 remains available for compatibility. Do not use it for new
collision-resistant signatures or content identity. HMAC-SHA-1 is a separate
construction whose security is independent of collision resistance. It remains
an acceptable MAC and KBKDF PRF, and is the smallest HMAC option on AVR.

For KBKDF, include the purpose, parties, and requested length in the fixed input
to distinguish keys derived for different uses. `TC_KBKDF_fixed_input` builds
this input as `Label || 0x00 || Context || [L]_32`. Never reuse a
key-derivation key as a derived key. Output lengths are in bytes. A
derivation of `n = ceil(out_len / h)` PRF blocks needs `n <= 2^r - 1` for an
`r`-bit counter. Output buffers must not overlap any input, and `TC_ERROR`
wipes the output when derivation had already started.

HKDF output lengths are in bytes and must be from 1 to `255 * HashLen`.
Pass purpose and protocol context as `info`. Extracted keys are cleared by the
one-shot derive functions. Callers using extract and expand clear their PRK
after the final expansion.

## TLV parsing

Enable `TINY_CRYPTO_ENABLE_TLV` and include `<tiny_crypto/tlv.h>`:

```c
const uint8_t data[] = {0x30, 0x03, 0x02, 0x01, 0x2a};
const TC_TLV_limits limits = {4096, 4096, 256, 16};
TC_TLV_reader reader;
TC_TLV_element element;
TC_TLV_result result = TC_TLV_reader_init(&reader, data, sizeof data,
                                         TC_TLV_DER, &limits);
if (result == TC_TLV_OK) {
    result = TC_TLV_next(&reader, &element);
    /* element.value borrows data; use it only if result is TC_TLV_OK. */
}
```

The limits are input bytes, value bytes, element count, and nesting depth.
A zero limit permits zero bytes or elements. The reader advances through
siblings without descending into their values. `TC_TLV_reader_child` opens a
reader on one element's template with the same profile and limits.
`TC_TLV_walk` checks nested containers using a caller-provided frame array and
one shared budget for the whole input.

Choose DER, ISO 7816, or optional ASN.1 BER explicitly. ISO padding has separate
profiles and is accepted only between root objects. A child reader rejects it
(ISO/IEC 7816-4:2020 section 6.4). `TC_TLV_read` and the sibling reader handle
definite lengths. Use the walker or incremental reader
for indefinite BER. `TC_TLV_read_tree` reads one definite or indefinite object,
checks its constructed boundaries, and leaves following siblings unread.
See [TLV parsing](docs/tlv.md) for workspace setup and borrowed-span usage.
For SignedData envelopes and signed attributes, see [CMS parsing](docs/cms.md).

`TC_TLV_END` means the sibling reader is exhausted. `TC_TLV_MORE` means a root
reader needs more input. A child reader reports truncation as `TC_TLV_INVALID`.
Other results distinguish malformed input, resource limits, unsupported
features, and invalid arguments. Bounds checks are always on.

Returned spans borrow the input. Keep that buffer unchanged while using
them. Incremental callbacks borrow bytes only during the callback. Call
`TC_TLV_stream_finish` when the message ends to detect truncation. Discard a
stream after an error or reinitialize it for a new message.

`<tiny_crypto/der.h>` adds INTEGER, BIT STRING, OID, BOOLEAN, NULL, SEQUENCE,
and SET helpers. They take complete encoded values and report truncation as
`TC_TLV_INVALID`. Framing checks cover encoding structure. Schema, certificate,
and signature validation are separate steps. C++11 code can use `tiny_crypto::TLVReader` from `<tiny_crypto/tlv.hpp>`.

## Certificates and PIV objects

`TC_X509_read` reads one DER certificate using caller-owned scratch space:

```c
#include <tiny_crypto/x509.h>

TC_TLV_frame frames[16];
TC_bytes extension_oids[32];
TC_X509_workspace workspace = {frames, 16, extension_oids, 32};
const TC_TLV_limits limits = {8192, 8192, 1024, 16};
TC_X509_certificate certificate;
TC_TLV_result result = TC_X509_read(data, length, &limits, &workspace,
                                   &certificate);
```

Choose the limits for your application. Each extension needs one OID slot.
Exceeding a limit returns `TC_TLV_LIMIT`. Results borrow the input buffer, so
keep it alive while using them. The workspace can be reused after the call.

`certificate.public_key` identifies the subject's algorithm, key size, and
named curve. `TC_X509_subject_public_key` also reads a standalone
SubjectPublicKeyInfo. The extension iterator exposes OIDs, critical flags,
and values. Helpers decode Basic Constraints and Key Usage.

`<tiny_crypto/key_challenge.h>` prepares and verifies a fresh proof-of-possession
challenge from a validated public key and explicit signature parameters. Card
commands and slot policy stay in protocol code, which selects its algorithm,
key usage and transport identifiers before issuing a challenge.

`TC_PIV_CHUID_read` returns the FASC-N, card UUID (GUID), optional cardholder
UUID, expiration date, and signature. Select `TC_PIV_CHUID_CONTENTS` for the
object contents or `TC_PIV_CHUID_CONTAINER` for a `53`-wrapped object.
Choose the profile from the requested card object before reading its contents.
`TC_CHUID_PROFILE_PIV` enforces the SP 800-73-4 Part 1 Table 9 field order and
requires a nonempty signature field. It accepts the deprecated Buffer Length
(`EE`), Organizational Identifier (`32`) and DUNS (`33`) fields found on older
cards. `signed_content` excludes Buffer Length, as section 3.1.2 requires.
`TC_CHUID_PROFILE_TWIC_SIGNED` and `TC_CHUID_PROFILE_TWIC_UNSIGNED` follow the
TWIC field schema. Unsigned TWIC omits the signature and cardholder UUID
fields.

`TC_PIV_certificate_read` reads a `53` certificate container and returns
borrowed spans for the certificate, the optional secure messaging intermediate
CVC and the optional historic MSCUID. The MSCUID lies outside the signed
certificate and is unauthenticated. Pass
`TC_PIV_CERTIFICATE_RECOMMENDED_BYTES` (1856) as the certificate bound, or a
larger application limit. SP 800-73-5 treats 1856 bytes as a recommendation.

`TC_PIV_CVC_read` reads card and intermediate secure messaging CVCs as defined
in SP 800-73-5 Part 2, section 4.1.5. Its `signed_data` span contains the
original TLV bytes covered by the signature. `TC_PIV_CVC_chain_verify` checks
direct or intermediate issuer links and signatures under a validated content
signer, with suite and optional UUID binding. See [PIV CVC verification](docs/piv-cvc.md)
for trust prerequisites and workspace setup.

EAC certificates use a different schema. `<tiny_crypto/eac_cvc.h>` provides
`TC_EAC_CVC_read`, a standalone public-key reader, and an extension iterator.
The certificate reader takes `TC_TLV_limits` and a `TC_EAC_CVC_workspace`
containing caller-owned nesting frames. Returned fields borrow the input.
Its signed span includes the complete `7F4E` body, including tag and length.
Unknown extensions are preserved. Unsupported key or authorization OIDs return
`TC_TLV_UNSUPPORTED`.

Call `TC_EAC_CVC_check_encoding` with the resolved issuer key and, for an EC
subject without explicit parameters, its inherited domain parameters. It
checks coordinate and signature widths. Missing context returns
`TC_TLV_ARGUMENT`. Signature width comes from the issuer key.
The standalone reader also accepts RI-ECDH public-key templates, but these
cannot be used as certificate-signing keys.

These readers parse encodings. Applications must separately verify signatures,
key validity, certificate trust, and expiration before using a credential.

## Benchmarks

We measure flash and static RAM usage for Arduino Uno and Raspberry Pi Pico 2
(RP2350, Arm Cortex-M33) builds. [docs/benchmarks.md](docs/benchmarks.md) lists
the sizes in bytes and as percentages of each board's flash and RAM capacity.
The figures are linked firmware sizes and exclude peak runtime stack use.

Run `make benchmark-report` to regenerate the report, or
`make benchmark-report-check` to check that it is up to date. Neither command
needs a connected board. Use `make benchmark` to measure throughput on the host
with the current build configuration. PR CI uploads a fresh resource report and
enforces flash and stack budgets. The checked-in report is refreshed for releases.

## PIV secure messaging

`TINY_CRYPTO_ENABLE_PIV_SM` enables the client side of SP 800-73-5 Part 2
section 4 secure messaging for CS2 (P-256, AES-128) and CS7 (P-384, AES-256).
The library performs ECDH, session-key derivation, key confirmation, command
protection and response authentication. The application supplies the APDU
transport, the data-object framing and an X.509 content-signing certificate
accepted through its trust, policy, time and revocation checks.

The workflow in `<tiny_crypto/piv_sm.h>` follows the protocol:

1. `TC_PIV_SM_begin` starts a session and fills a `TC_PIV_SM_handshake` with the
   host identifier and ephemeral public key.
2. The application encodes them into GENERAL AUTHENTICATE and decodes the
   card's response into a `TC_PIV_SM_peer`: the exact CVC bytes, nonce,
   cryptogram and received CB_ICC byte.
3. `TC_PIV_SM_finish` takes the CVC public key after the application has
   authenticated it. `TC_PIV_SM_authenticate_response` in
   `<tiny_crypto/piv_sm_authenticate.h>` verifies the CVC chain and completes key
   confirmation in one call.
4. `TC_PIV_SM_protect` encrypts command data and tags the caller's ordered
   authenticated spans. `TC_PIV_SM_ciphertext_size` gives the padded length.
5. `TC_PIV_SM_unprotect` authenticates the response spans and then decrypts.

The caller owns the zero-initialized `TC_PIV_SM` and the `TC_PIV_SM_workspace`.
Only one command may be pending. `TC_PIV_SM_get_state` tells a retryable
unprotect error from one that ended the session. `examples/piv_sm_wire.h`
implements the `7C/81/82` and `87/97/99/8E` framing. The C++11
`tiny_crypto::piv_sm` wrapper clears its session on destruction and cannot be
copied or moved. See [PIV secure messaging](docs/piv-sm.md) for build options,
span layouts, state transitions and every result.

The underlying `TC_ECDH`, `TC_EC_public_key`, and `TC_EC_validate_public_key`
APIs take fixed-width scalars and uncompressed SEC1 public keys as spans, plus a
work budget, and return a `TC_EC_result`. They support P-256 and P-384. See
[Elliptic-curve operations](docs/ec.md). `TC_SSKDF_SHA1` through
`TC_SSKDF_SHA512` implement the SP 800-56C Rev. 2 one-step KDF, one function
per enabled SHA. They accept FixedInfo as spans, avoiding a concatenation
buffer. SP 800-108r1 KBKDF and HKDF have separate APIs.

## Testing

See [Running the tests](docs/testing.md) for full-suite commands, external
corpora, sanitizers, compiler and profile runs, and fuzzing.
The standard suites use vendored vectors without OpenSSL.
`TINY_CRYPTO_TEST_OPENSSL=ON` adds optional cross-checks.

Run the host suite with every available GCC and Clang toolchain using
`make test-compilers`. Override versioned compiler names with, for example,
`make test-compilers TOOLCHAINS='gcc-15:g++-15 clang:clang++'`.

`test_default_profile` tests the configured `tiny-crypto-c` target. The other
tests share libraries built for specific configurations: full API, AES-192/256,
weak-key rejection, runtime S-box, and GHASH profiles. Each configuration is
compiled once and reused by its tests.

The fast suite covers all C modes and C++ wrappers. C tests use [µunit][munit],
and C++ tests use [doctest]. You can filter the C++ tests with doctest's
command-line options, for example `./build/test_cpp_hash -tc="*HMAC*"`.

`make test-full` adds the tests labelled `extended`: the checked-in
[NIST CAVP][cavp] response files including the SP 800-90A DRBG answers,
FIPS 186 signature and key-generation vectors, and
[Wycheproof] vectors,
including the complete 20,000-vector SP 800-108 KBKDF corpus split across
`test_kdf` (128-bit AES and every other PRF), `test_kdf_192` and
`test_kdf_256`.
CI tests with GCC, Clang, Apple Clang, and MSVC, runs sanitizers, and checks
Arduino Uno and RP2350 build sizes. The manually triggered
[Full test suite](.github/workflows/full-tests.yml) runs the vendored cryptographic
vectors and optional external parser corpora.

TLV tests cover framing, DER values, resource limits, and split input. The
optional corpus adapter compares CVC fields with the supplied metadata and
reads ASN.1 objects without evaluating certificate trust. It runs against
`TINY_CRYPTO_TLV_CORPUS`, which defaults to the checked-in `tests/vectors`.
Point it at another directory containing `piv/` and `x509/` for an external corpus.
If `eac/cvc/` is present, the EAC tests also check certificate fields,
inherited EC parameter widths, and malformed encodings.
`TINY_CRYPTO_TLV_MBEDTLS_SUITE` selects an external, pinned ASN.1 test data file.
CI downloads that file into its temporary directory.

Clang builds can enable `TINY_CRYPTO_BUILD_FUZZERS` and run `fuzz_tlv`,
`fuzz_pki`, `fuzz_piv_sm`, and `fuzz_gzip`.
Keep its writable corpus and failure artifacts outside the source tree.

## License

Project code is licensed under [GPL-2.0-or-later](LICENSE), with an additional
permission to link substantially unmodified Espressif ESP-IDF libraries,
including by static linking. The exception text is at the top of
[LICENSE](LICENSE). Unicode normalization
tables use the [Unicode License v3](LICENSES/Unicode-3.0.txt). Bundled test
materials retain their own terms. [µunit][munit] (`tests/support/munit.h`) and
[doctest] (`tests/support/doctest.h`) use the MIT license.
[Wycheproof] vectors use Apache-2.0. [NIST CAVP][cavp] response
files are U.S. Government works. Corpus READMEs under `tests/vectors/` record
the source, license, transformations, and checksums for each collection. Test
corpora are excluded from installed packages and embedded library images.
The adapted contribution policy retains its upstream
[MIT license](LICENSES/BoundedContributionPolicy-MIT.txt).

Individuals and corporations that require alternate licensing terms may contact
[licensing@mistial.dev](mailto:licensing@mistial.dev) by email.

[cavp]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
[doctest]: https://github.com/doctest/doctest
[munit]: https://nemequ.github.io/munit/
[wycheproof]: https://github.com/C2SP/wycheproof
