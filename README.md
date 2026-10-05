<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# tiny-crypto-c

[![CI](https://github.com/mistial-dev/tiny-crypto-c/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/mistial-dev/tiny-crypto-c/actions/workflows/ci.yml)
[![License: GPL v2+](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](LICENSE)
[![CLA assistant](https://cla-assistant.io/readme/badge/mistial-dev/tiny-crypto-c)](https://cla-assistant.io/mistial-dev/tiny-crypto-c)

tiny-crypto-c provides small, portable cryptographic primitives and PIV and TWIC credential
modules for embedded C and C++. Library code is heap free, and callers supply all memory. Disabled
algorithms and modes stay out of the build, so a small device links only what its application
uses.

The default build enables AES-128 CTR and SHA-256. Options add DES and TDEA, SHA-1 through
SHA-512, MD5, HMAC, KMAC256, the SP 800-108r1, SP 800-56C and RFC 5869 KDFs,
[SP 800-90A DRBGs](docs/drbg.md), EC, RSA and the other block-cipher modes. The credential modules
parse card data, check CMS signatures and X.509 paths, apply credential policy and check
revocation. TWIC Legacy and NEXGEN cards need `TINY_CRYPTO_ENABLE_TWIC`, which adds the TWIC rules
held in the `twic_*` sources to the PIV modules.

The C++11 wrappers take `bytes` spans and C arrays, transform block-mode data in place, work
without the standard library or exceptions, and return the C result types as `[[nodiscard]]`
values. See [C++ wrappers](docs/cpp.md).

## Quick start

Build the default profile and run the quick tests:

```sh
make
make test
```

Include `<tiny_crypto/tiny_crypto.h>` and pass byte ranges as `TC_bytes` and `TC_buffer` spans:

```c
#include <tiny_crypto/tiny_crypto.h>

/* Encrypt length bytes of message in place with AES-128-CTR. */
TC_status encrypt_in_place(const uint8_t key[TC_AES_KEYLEN],
                           const uint8_t iv[TC_AES_BLOCKLEN], uint8_t* message, size_t length)
{
  struct TC_AES_ctx ctx;
  TC_status status = TC_AES_init(&ctx, (TC_bytes){key, TC_AES_KEYLEN});
  if (status == TC_OK)
    status = TC_AES_set_iv(&ctx, (TC_bytes){iv, TC_AES_BLOCKLEN});
  if (status == TC_OK)
    status = TC_AES_CTR_crypt(&ctx, (TC_buffer){message, length});
  TC_AES_ctx_clear(&ctx); /* wipes the key schedule and IV on every path */
  return status;          /* TC_ERROR leaves no usable output in message */
}
```

[Working with the API](docs/api.md) explains spans, results, failure behavior, workspaces and work
budgets. The [credential reader guide](docs/credential-reader.md) walks through a PIV and TWIC
reader.

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
make TINY_CRYPTO_ENABLE_HMAC=ON TINY_CRYPTO_AES_ENABLE_GCM=ON
```

Or build with CMake directly:

```sh
cmake -S . -B build -DTINY_CRYPTO_ENABLE_HMAC=ON -DTINY_CRYPTO_AES_ENABLE_GCM=ON
cmake --build build
```

As a CMake dependency:

```cmake
add_subdirectory(path/to/tiny-crypto-c)
target_link_libraries(firmware PRIVATE tiny-crypto-c::tiny-crypto-c)
```

`cmake --install` installs the headers, the archive, a CMake package and a generated
`tiny_crypto/build_config.h`. That header records the archive's configuration, so consumers that
use the installed headers without CMake get the same structure layouts. A `-D` definition that
contradicts it fails with "differs from the installed library configuration".

Public headers live in `src/tiny_crypto/`, following the Arduino library layout. C code includes
`<tiny_crypto/tiny_crypto.h>`. C++ code includes `<tiny_crypto/tiny_crypto.hpp>` for the wrappers
in namespace `tiny_crypto`.

## Configuration

All options are CMake cache variables. Secret wiping and public argument checks are always on.

`TINY_CRYPTO_RESOURCE_PROFILE` tunes the build for a device class. With no profile, the build
enables AES-128 CTR and SHA-256. `micro` favors small code and byte-limb EC and RSA arithmetic.
`mini` uses native arithmetic and keeps optional algorithms off. `desktop` enables the supported
capabilities, including SHA-1, DES, MD5 and both PIV secure-messaging suites.

`TINY_CRYPTO_TARGET` selects a predefined algorithm set for an application, independent of the
resource profile:

| Target    | Contents                                                                                    |
| --------- | ------------------------------------------------------------------------------------------- |
| `full`    | Every algorithm and format                                                                  |
| `piv`     | SP 800-73-5 with the SP 800-78-5 algorithms                                                 |
| `twic`    | `piv` plus SHA-1, RSA-1024, TWIC privacy keys, object encryption and the canceled card list |
| `desfire` | AES-128 CBC and DES ECB and CBC with single DES, two-key and three-key TDEA keys            |

The target overrides the profile columns below. Every switch outside its set is off, and an
explicit setting that contradicts the target stops the configuration. Leave the target empty to
choose each switch. [Application targets](docs/targets.md) lists each set and its sources.

Feature options accept `AUTO`, `ON` or `OFF`. `AUTO` follows the selected profile, and explicit
settings survive a profile change. Each option is `TINY_CRYPTO_` followed by its `config.h` macro
without the `TC_` prefix: `TINY_CRYPTO_AES_ENABLE_CBC` sets `TC_AES_ENABLE_CBC`. A sub-feature,
such as a mode, TDEA or a curve, takes effect only while its parent algorithm is on.
[`cmake/features.json`](cmake/features.json) lists every feature with its description, parent,
value set and sources.

Configuration compiles `config.h` with the selected values and stops with its `#error` text when
an option lacks a dependency, so CMake and direct-source builds accept the same combinations. It
also stops on an unknown `TINY_CRYPTO_*` name and names the replacement of a retired one. Remove
such an entry with `cmake -U <name>` or use a new build directory. Projects that compile the C
files directly define the matching `TC_*` macros documented in
[`config.h`](src/tiny_crypto/config.h) and select a profile with
`TC_RESOURCE_PROFILE=TC_RESOURCE_MICRO`, `TC_RESOURCE_MINI` or `TC_RESOURCE_DESKTOP`.

The tables give the `AUTO` value under each profile. Default is the build with no profile.

### Minimal build

With every feature option `OFF`, the archive holds only `src/common.c`: secret wiping,
constant-time comparison and the span helpers every module uses. Shared helpers, such as the hash
core, the block-mode core and the PKI storage planner, compile only while a feature that uses them
is on. Start from that build and enable the features an application needs. Configuration names
each dependency that `config.h` requires.

### Algorithms

| Option                           | Default | micro | mini | desktop | Purpose                                                            |
| -------------------------------- | ------- | ----- | ---- | ------- | ------------------------------------------------------------------ |
| `TINY_CRYPTO_ENABLE_AES`         | ON      | ON    | ON   | ON      | AES block cipher with the key size from `TINY_CRYPTO_AES_KEY_BITS` |
| `TINY_CRYPTO_AES_ENABLE_DYNAMIC` | OFF     | OFF   | OFF  | ON      | Per-context AES-128/192/256 keys, CBC and CMAC                     |
| `TINY_CRYPTO_ENABLE_DES`         | OFF     | OFF   | OFF  | ON      | DES, with TDEA and the DES modes below                             |
| `TINY_CRYPTO_DES_ENABLE_TDES`    | ON      | ON    | ON   | ON      | Two- and three-key TDEA                                            |
| `TINY_CRYPTO_ENABLE_EC`          | OFF     | OFF   | OFF  | ON      | ECDH, ECDSA and key generation on the enabled curves               |
| `TINY_CRYPTO_EC_ENABLE_P192`     | OFF     | OFF   | OFF  | OFF     | P-192                                                              |
| `TINY_CRYPTO_EC_ENABLE_P256`     | ON      | ON    | ON   | ON      | P-256                                                              |
| `TINY_CRYPTO_EC_ENABLE_P384`     | ON      | ON    | ON   | ON      | P-384                                                              |
| `TINY_CRYPTO_EC_SMALL`           | OFF     | ON    | OFF  | OFF     | Byte limbs for EC arithmetic (always used on AVR)                  |
| `TINY_CRYPTO_ENABLE_RSA`         | OFF     | OFF   | OFF  | ON      | RSA verification, signing, OAEP, key validation and key generation |
| `TINY_CRYPTO_RSA_ENABLE_1024`    | OFF     | OFF   | OFF  | OFF     | RSA-1024 keys, requires an explicit override                       |
| `TINY_CRYPTO_RSA_ENABLE_2048`    | ON      | ON    | ON   | ON      | RSA-2048                                                           |
| `TINY_CRYPTO_RSA_ENABLE_3072`    | ON      | ON    | ON   | ON      | RSA-3072                                                           |
| `TINY_CRYPTO_RSA_ENABLE_4096`    | ON      | ON    | ON   | ON      | RSA-4096                                                           |
| `TINY_CRYPTO_RSA_SMALL`          | OFF     | ON    | OFF  | OFF     | Byte limbs for RSA arithmetic (always used on AVR)                 |
| `TINY_CRYPTO_ENABLE_SHA1`        | OFF     | OFF   | OFF  | ON      | SHA-1                                                              |
| `TINY_CRYPTO_ENABLE_SHA224`      | OFF     | OFF   | OFF  | ON      | SHA-224 on the SHA-256 core                                        |
| `TINY_CRYPTO_ENABLE_SHA256`      | ON      | ON    | ON   | ON      | SHA-256                                                            |
| `TINY_CRYPTO_ENABLE_SHA384`      | OFF     | OFF   | OFF  | ON      | SHA-384 on the SHA-512 core                                        |
| `TINY_CRYPTO_ENABLE_SHA512`      | OFF     | OFF   | OFF  | ON      | SHA-512                                                            |
| `TINY_CRYPTO_ENABLE_MD5`         | OFF     | OFF   | OFF  | ON      | MD5 checksums (RFC 1321)                                           |
| `TINY_CRYPTO_ENABLE_HMAC`        | OFF     | OFF   | OFF  | ON      | HMAC over the enabled SHA algorithms                               |
| `TINY_CRYPTO_ENABLE_KMAC256`     | OFF     | OFF   | OFF  | ON      | Fixed-output KMAC256 with customization                            |
| `TINY_CRYPTO_ENABLE_KDF`         | OFF     | OFF   | OFF  | ON      | SP 800-108r1 KBKDF over the enabled HMAC and CMAC PRFs             |
| `TINY_CRYPTO_ENABLE_HKDF`        | OFF     | OFF   | OFF  | ON      | RFC 5869 HKDF over the enabled HMAC-SHA algorithms                 |
| `TINY_CRYPTO_ENABLE_SSKDF`       | OFF     | OFF   | OFF  | ON      | SP 800-56C one-step hash KDF over the enabled SHA algorithms       |
| `TINY_CRYPTO_ENABLE_DRBG`        | OFF     | OFF   | OFF  | ON      | [SP 800-90A DRBGs](docs/drbg.md)                                   |
| `TINY_CRYPTO_DRBG_ENABLE_HASH`   | OFF     | OFF   | OFF  | ON      | Hash_DRBG over the enabled SHA algorithms                          |
| `TINY_CRYPTO_DRBG_ENABLE_HMAC`   | OFF     | OFF   | OFF  | ON      | HMAC_DRBG, requires HMAC                                           |
| `TINY_CRYPTO_DRBG_ENABLE_CTR`    | OFF     | OFF   | OFF  | ON      | CTR_DRBG, requires `TINY_CRYPTO_AES_ENABLE_DYNAMIC`                |

KBKDF needs at least one PRF: HMAC with an enabled SHA digest, `TINY_CRYPTO_AES_ENABLE_CMAC` or
`TINY_CRYPTO_DES_ENABLE_CMAC`. HKDF needs HMAC and at least one enabled SHA algorithm.

### Block-cipher modes

| Option                             | Default | micro | mini | desktop | Purpose                                          |
| ---------------------------------- | ------- | ----- | ---- | ------- | ------------------------------------------------ |
| `TINY_CRYPTO_AES_ENABLE_CTR`       | ON      | ON    | ON   | ON      | AES-CTR                                          |
| `TINY_CRYPTO_AES_ENABLE_CBC`       | OFF     | OFF   | OFF  | ON      | AES-CBC                                          |
| `TINY_CRYPTO_AES_ENABLE_ECB`       | OFF     | OFF   | OFF  | ON      | AES-ECB                                          |
| `TINY_CRYPTO_AES_ENABLE_OFB`       | OFF     | OFF   | OFF  | ON      | AES-OFB                                          |
| `TINY_CRYPTO_AES_ENABLE_GCM`       | OFF     | OFF   | OFF  | ON      | AES-GCM                                          |
| `TINY_CRYPTO_AES_ENABLE_CCM`       | OFF     | OFF   | OFF  | ON      | AES-CCM                                          |
| `TINY_CRYPTO_AES_ENABLE_EAX`       | OFF     | OFF   | OFF  | ON      | AES-EAX                                          |
| `TINY_CRYPTO_AES_ENABLE_EAX_PRIME` | OFF     | OFF   | OFF  | ON      | ANSI C12.22 EAX'                                 |
| `TINY_CRYPTO_AES_ENABLE_SIV`       | OFF     | OFF   | OFF  | ON      | AES-SIV (RFC 5297)                               |
| `TINY_CRYPTO_AES_ENABLE_CMAC`      | OFF     | OFF   | OFF  | ON      | AES-CMAC                                         |
| `TINY_CRYPTO_AES_ENABLE_KW`        | OFF     | OFF   | OFF  | ON      | AES key wrap, KW and KWP (SP 800-38F)            |
| `TINY_CRYPTO_AES_WIDE_OPS`         | OFF     | OFF   | ON   | ON      | Native-width AES helpers                         |
| `TINY_CRYPTO_AES_TINY`             | OFF     | ON    | OFF  | OFF     | Reject the 256-byte `fast-table` GHASH context   |
| `TINY_CRYPTO_DES_ENABLE_CTR`       | ON      | ON    | ON   | ON      | DES-CTR                                          |
| `TINY_CRYPTO_DES_ENABLE_ECB`       | OFF     | OFF   | OFF  | ON      | DES-ECB                                          |
| `TINY_CRYPTO_DES_ENABLE_CBC`       | OFF     | OFF   | OFF  | ON      | DES-CBC                                          |
| `TINY_CRYPTO_DES_ENABLE_OFB`       | OFF     | OFF   | OFF  | ON      | DES-OFB                                          |
| `TINY_CRYPTO_DES_ENABLE_CFB1`      | OFF     | OFF   | OFF  | ON      | DES-CFB1                                         |
| `TINY_CRYPTO_DES_ENABLE_CFB8`      | OFF     | OFF   | OFF  | ON      | DES-CFB8                                         |
| `TINY_CRYPTO_DES_ENABLE_CFB64`     | OFF     | OFF   | OFF  | ON      | DES-CFB64                                        |
| `TINY_CRYPTO_DES_ENABLE_CMAC`      | OFF     | OFF   | OFF  | ON      | TDEA-CMAC                                        |
| `TINY_CRYPTO_DES_ENABLE_ISO9797`   | OFF     | OFF   | OFF  | OFF     | ISO/IEC 9797-1 MAC algorithms 1 and 3            |
| `TINY_CRYPTO_DES_REJECT_WEAK_KEYS` | OFF     | OFF   | OFF  | OFF     | Reject weak DES keys and degenerate TDEA bundles |

### Formats, compression and trust

| Option                                     | Default | micro  | mini   | desktop | Purpose                                                |
| ------------------------------------------ | ------- | ------ | ------ | ------- | ------------------------------------------------------ |
| `TINY_CRYPTO_ENABLE_TLV`                   | OFF     | OFF    | OFF    | ON      | Bounded TLV readers and tree traversal                 |
| `TINY_CRYPTO_TLV_ENABLE_BER`               | OFF     | OFF    | OFF    | ON      | ASN.1 BER, including indefinite lengths                |
| `TINY_CRYPTO_TLV_ENABLE_STREAM`            | OFF     | OFF    | OFF    | ON      | Incremental TLV reader                                 |
| `TINY_CRYPTO_ENABLE_DER`                   | OFF     | OFF    | OFF    | ON      | DER value readers, requires TLV                        |
| `TINY_CRYPTO_ENABLE_X509`                  | OFF     | OFF    | OFF    | ON      | X.509 certificate and public-key readers, requires DER |
| `TINY_CRYPTO_ENABLE_X509_PATH`             | OFF     | OFF    | OFF    | ON      | Path validation and trust stores                       |
| `TINY_CRYPTO_ENABLE_TRUST_ANCHOR_FORMAT`   | OFF     | OFF    | OFF    | ON      | RFC 5914 trust-anchor lists                            |
| `TINY_CRYPTO_TAF_ENABLE_CERTIFICATE`       | format  | format | format | format  | Certificate choice in RFC 5914 lists                   |
| `TINY_CRYPTO_TAF_ENABLE_TBS_CERTIFICATE`   | format  | format | format | format  | TBSCertificate choice in RFC 5914 lists                |
| `TINY_CRYPTO_TAF_ENABLE_TRUST_ANCHOR_INFO` | format  | format | format | format  | TrustAnchorInfo choice in RFC 5914 lists               |
| `TINY_CRYPTO_ENABLE_X509_REVOCATION`       | OFF     | OFF    | OFF    | ON      | CRL parsing and path revocation                        |
| `TINY_CRYPTO_ENABLE_X509_OCSP`             | OFF     | OFF    | OFF    | ON      | OCSP requests and responses, requires SHA-1            |
| `TINY_CRYPTO_ENABLE_KEY_CHALLENGE`         | OFF     | OFF    | OFF    | ON      | Public-key proof-of-possession challenges              |
| `TINY_CRYPTO_ENABLE_GZIP`                  | OFF     | OFF    | OFF    | ON      | Bounded GZIP decompression                             |

Under `AUTO`, the three `TINY_CRYPTO_TAF_ENABLE_*` choices follow
`TINY_CRYPTO_ENABLE_TRUST_ANCHOR_FORMAT`. At least one choice must be on while the format is on.

### PIV, TWIC and credentials

| Option                                  | Default | micro | mini | desktop | Purpose                                           |
| --------------------------------------- | ------- | ----- | ---- | ------- | ------------------------------------------------- |
| `TINY_CRYPTO_ENABLE_APDU`               | OFF     | OFF   | OFF  | ON      | ISO/IEC 7816-4 APDU encoding and exchange         |
| `TINY_CRYPTO_ENABLE_PIV_COMMAND`        | OFF     | OFF   | OFF  | ON      | PIV card commands, requires APDU and TLV          |
| `TINY_CRYPTO_ENABLE_PIV_OIDS`           | OFF     | OFF   | OFF  | ON      | PIV identifier classification                     |
| `TINY_CRYPTO_ENABLE_CMS`                | OFF     | OFF   | OFF  | ON      | CMS parsing and signer verification, requires BER |
| `TINY_CRYPTO_ENABLE_CMS_VALIDATION`     | OFF     | OFF   | OFF  | ON      | CMS signer paths and revocation                   |
| `TINY_CRYPTO_ENABLE_PIV_OBJECTS`        | OFF     | OFF   | OFF  | ON      | PIV object readers                                |
| `TINY_CRYPTO_ENABLE_CREDENTIAL`         | OFF     | OFF   | OFF  | ON      | Composed PIV credential validation                |
| `TINY_CRYPTO_ENABLE_PIV_CHUID`          | OFF     | OFF   | OFF  | ON      | PIV CHUID reader                                  |
| `TINY_CRYPTO_ENABLE_PIV_CVC`            | OFF     | OFF   | OFF  | ON      | PIV secure-messaging CVC reader                   |
| `TINY_CRYPTO_ENABLE_EAC_CVC`            | OFF     | OFF   | OFF  | ON      | BSI TR-03110 EAC CVC reader                       |
| `TINY_CRYPTO_ENABLE_PIV_SM`             | OFF     | OFF   | OFF  | ON      | Client-side PIV secure messaging                  |
| `TINY_CRYPTO_ENABLE_PIV_SM_APDU`        | OFF     | OFF   | OFF  | ON      | PIV SM framing, requires PIV command, SM and CVC  |
| `TINY_CRYPTO_ENABLE_PIV_VCI`            | OFF     | OFF   | OFF  | ON      | PIV VCI, requires SM framing and PIV objects      |
| `TINY_CRYPTO_ENABLE_PIV_CATALOG`        | OFF     | OFF   | OFF  | ON      | PIV catalogs and card inventory                   |
| `TINY_CRYPTO_ENABLE_PIV_KEY_PROOF`      | OFF     | OFF   | OFF  | ON      | PIV card key proofs                               |
| `TINY_CRYPTO_ENABLE_PIV_CARD_CHECK`     | OFF     | OFF   | OFF  | ON      | Composed PIV card check report                    |
| `TINY_CRYPTO_PIV_SM_ENABLE_CS2`         | ON      | ON    | ON   | ON      | Cipher suite 2 (P-256, AES-128)                   |
| `TINY_CRYPTO_PIV_SM_ENABLE_CS7`         | ON      | ON    | ON   | ON      | Cipher suite 7 (P-384, AES-256)                   |
| `TINY_CRYPTO_ENABLE_FASCN`              | OFF     | OFF   | OFF  | ON      | FASC-N readers and writers                        |
| `TINY_CRYPTO_ENABLE_TWIC`               | OFF     | OFF   | OFF  | ON      | TWIC Legacy and NEXGEN cards in the PIV modules   |
| `TINY_CRYPTO_ENABLE_TWIC_UUID`          | OFF     | OFF   | OFF  | ON      | TWIC NEXGEN UUID helpers                          |
| `TINY_CRYPTO_ENABLE_TWIC_CCL`           | OFF     | OFF   | OFF  | ON      | TWIC canceled card list reader                    |
| `TINY_CRYPTO_ENABLE_TWIC_TPK`           | OFF     | OFF   | OFF  | ON      | TWIC privacy-key container reader                 |
| `TINY_CRYPTO_ENABLE_TWIC_OBJECT_CRYPTO` | OFF     | OFF   | OFF  | ON      | TWIC private-object encryption                    |
| `TINY_CRYPTO_ENABLE_AAMVA`              | OFF     | OFF   | OFF  | ON      | ANSI AAMVA payload readers                        |
| `TINY_CRYPTO_AVR_PROGMEM`               | ON      | ON    | ON   | ON      | Keep constant tables in AVR flash                 |

### Value options

| Option                           | Values                                                         | Default         |
| -------------------------------- | -------------------------------------------------------------- | --------------- |
| `TINY_CRYPTO_RESOURCE_PROFILE`   | empty, `micro`, `mini`, `desktop`                              | empty           |
| `TINY_CRYPTO_TARGET`             | empty, `full`, `piv`, `twic`, `desfire`                        | empty           |
| `TINY_CRYPTO_AES_KEY_BITS`       | `128`, `192`, `256`                                            | `128`           |
| `TINY_CRYPTO_AES_SBOX_MODE`      | `constant-time`, `runtime`, `fast`                             | `constant-time` |
| `TINY_CRYPTO_AES_GCM_GHASH_MODE` | `profile`, `auto`, `bitwise`, `wide`, `fast-table`, `hardware` | `profile`       |

`TINY_CRYPTO_AES_KEY_BITS` fixes the key size of the `aes.h` API, including the AES-CMAC keys that
KBKDF uses and the key wrap KEK. `TINY_CRYPTO_AES_ENABLE_DYNAMIC` adds per-context 128, 192 and
256-bit keys and KEKs.

The S-box modes trade timing protection for speed. `constant-time` computes the S-box
algebraically. `runtime` builds it in RAM and reads it with a masked scan. `fast` uses direct
table lookups and has no cache-timing protection.

`TINY_CRYPTO_AES_GCM_GHASH_MODE=profile` selects `auto` for the default and mini builds, `bitwise`
for micro and `wide` for desktop. `fast-table` uses key-dependent table lookups and adds 256 bytes
to each GCM context. `TINY_CRYPTO_AES_TINY=ON`, the micro default, rejects `fast-table` at
configuration time. `hardware` needs a platform GHASH hook, declared in `aes.h`.

### Build and test options

| Option                         | Default                              | Purpose                                      |
| ------------------------------ | ------------------------------------ | -------------------------------------------- |
| `TINY_CRYPTO_BUILD_TESTS`      | ON at top level, OFF as a subproject | Host tests                                   |
| `TINY_CRYPTO_BUILD_BENCHMARKS` | ON at top level, OFF as a subproject | Host benchmarks for the selected profile     |
| `TINY_CRYPTO_BUILD_FUZZERS`    | OFF                                  | libFuzzer targets, Clang only                |
| `TINY_CRYPTO_SANITIZE`         | empty                                | Test sanitizers, such as `address,undefined` |
| `TINY_CRYPTO_TEST_FULL`        | OFF                                  | Run the checked-in CAVP corpora              |
| `TINY_CRYPTO_TEST_NULL_GUARD`  | OFF                                  | Repeat C test calls with NULL arguments      |
| `TINY_CRYPTO_TEST_OPENSSL`     | OFF                                  | OpenSSL 3 cross-checks                       |
| `TINY_CRYPTO_TEST_PIV_CARD`    | OFF                                  | PIV card hardware tests over PC/SC           |

[Running the tests](docs/testing.md#test-options) lists the corpus and fixture options.

## Documentation

Library-wide:

- [Working with the API](docs/api.md): results, failure and wipe rules, spans and overlap,
  workspaces, work budgets, naming and tag lengths.
- [C++ wrappers](docs/cpp.md): the C++11 layer.
- [Application targets](docs/targets.md) and [ESP32-P4 and PIV targets](docs/esp32-p4.md).
- [Running the tests](docs/testing.md) and [resource benchmarks](docs/benchmarks.md).
- [Migrating to 2.0](docs/migration-2.0.md) and the [changelog](CHANGELOG.md).

Cryptography:

- [Authenticated encryption](docs/api.md#authenticated-encryption),
  [block cipher modes](docs/api.md#block-cipher-modes), [DES and TDEA](docs/api.md#des-and-tdea)
  and [DES message authentication](docs/api.md#des-message-authentication).
- [Hashes and key derivation](docs/api.md#hashes-and-key-derivation), [HKDF](docs/hkdf.md),
  [MD5](docs/md5.md), [AES key wrap](docs/aes-kw.md) and [DRBGs](docs/drbg.md).
- [Elliptic curves](docs/ec.md), [RSA](docs/rsa.md) and
  [native signature verification](docs/x509-crypto.md).

Encodings, certificates and CMS:

- [TLV parsing](docs/tlv.md), [DER values](docs/der.md) and [GZIP decoding](docs/gzip.md).
- [Certificates and card objects](docs/api.md#parsing-signatures-and-trust),
  [path validation](docs/x509-path.md), [certificate store](docs/x509-store.md) and
  [trust anchors](docs/x509-trust-anchors.md).
- [CRL parsing](docs/x509-crl.md), [path revocation](docs/x509-revocation.md) and
  [OCSP](docs/x509-ocsp.md).
- [CMS](docs/cms.md) and [credential validation](docs/validation.md).

PIV and TWIC:

- [Smart-card APDUs](docs/apdu.md), [PIV card commands](docs/piv-card.md),
  [secure messaging](docs/piv-sm.md) and [secure-messaging CVCs](docs/piv-cvc.md).
- [PIV card check](docs/piv-card-check.md), [credential reader example](docs/credential-reader.md)
  and [composing PIV and TWIC validation](docs/credential-validation.md).
- [FASC-N](docs/fascn.md), [LDS security objects](docs/lds.md),
  [TWIC canceled card lists](docs/twic-ccl.md) and [TWIC barcodes](docs/twic-barcode.md).

## Testing

C tests use [µunit][munit] and C++ tests use [doctest]. The fast suite covers every C mode and C++
wrapper with vendored vectors and needs no OpenSSL. `TINY_CRYPTO_TEST_OPENSSL=ON` adds
cross-checks. `make test-full` adds the tests labelled `extended`: the checked-in [NIST CAVP][cavp]
response files, including the SP 800-90A DRBG answers and FIPS 186 signature and key-generation
vectors, and the [Wycheproof] vectors, including the 20,000-vector SP 800-108 KBKDF corpus.

`make test-compilers` runs the host suite with every available GCC and Clang toolchain. Override
the compiler names with, for example,
`make test-compilers TOOLCHAINS='gcc-15:g++-15 clang:clang++'`. Filter C++ tests with doctest
options, for example `./build/test_cpp_hash -tc="*HMAC*"`.

CI tests with GCC, Clang, Apple Clang and MSVC, runs sanitizers, and checks Arduino Uno and RP2350
build sizes. The manually triggered [Full test suite](.github/workflows/full-tests.yml) runs the
vendored vectors with the Unicode reference files that workflow fetches. See
[Running the tests](docs/testing.md) for corpora, fixtures, sanitizers, profile runs and fuzzing.

## Benchmarks

[Resource benchmarks](docs/benchmarks.md) lists linked flash and static RAM for Arduino Uno and
Raspberry Pi Pico 2 (RP2350, Arm Cortex-M33) builds, in bytes and as a share of each board. The
figures exclude peak runtime stack use. `make benchmark-report` regenerates the report and
`make benchmark-report-check` checks it. Both build the board firmware without a connected board
and need the toolchains in [Updating the numbers](docs/benchmarks.md#updating-the-numbers).
`make benchmark` measures host throughput for the current configuration. PR CI uploads a fresh
resource report and enforces flash and stack budgets. The checked-in report is refreshed for
releases.

## Versioning

Releases follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). A major version
can change public C or C++ calls or documented behavior in ways that require caller changes. A
minor version adds compatible functionality. A patch version contains compatible fixes.

The public API comprises the installed headers, documented behavior and status values, build
options and the installed CMake target. Rebuild the library with the application toolchain when
upgrading. Binary compatibility across toolchains is outside this policy. Callers upgrading from
1.x follow [Migrating to 2.0](docs/migration-2.0.md). The [changelog](CHANGELOG.md) lists each
release, including the interfaces renamed and removed in 2.0.0.

## License

Project code is licensed under [GPL-2.0-or-later](LICENSE), with an additional permission to link
substantially unmodified Espressif ESP-IDF libraries, including by static linking. The exception
text is at the top of [LICENSE](LICENSE). Unicode normalization tables use the
[Unicode License v3](LICENSES/Unicode-3.0.txt).

Bundled test materials keep their own terms. [µunit][munit] (`tests/support/munit.h`) and
[doctest] (`tests/support/doctest.h`) use the MIT license. [Wycheproof] vectors use Apache-2.0.
[NIST CAVP][cavp] response files are U.S. Government works. Corpus READMEs under `tests/vectors/`
record the source, license, transformations and checksums for each collection. Installed packages
and embedded library images exclude the test corpora. The adapted contribution policy keeps its
upstream [MIT license](LICENSES/BoundedContributionPolicy-MIT.txt).

For alternate licensing terms, email [licensing@mistial.dev](mailto:licensing@mistial.dev).

[cavp]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
[doctest]: https://github.com/doctest/doctest
[munit]: https://nemequ.github.io/munit/
[wycheproof]: https://github.com/C2SP/wycheproof
