<!-- SPDX-FileCopyrightText: Mistial Dev -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# tiny-crypto-c

[![CI](https://github.com/mistial-dev/tiny-crypto-c/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/mistial-dev/tiny-crypto-c/actions/workflows/ci.yml)
[![License: GPL v2+](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](LICENSE)

tiny-crypto-c provides small, portable cryptographic primitives for embedded C
and C++. Neither API allocates memory. The C++11 wrappers use pointer-length
pairs and C arrays, need no standard library or exceptions, and return the same
`TC_status` codes as the C API. Disabled algorithms and modes are left out of
the build.

The default profile enables **AES-128 CTR and SHA-256**. DES, 3DES, SHA-1,
SHA-224, SHA-384, SHA-512, HMAC, KMAC256, the NIST SP 800-108 key-based KDF,
and other block-cipher modes can be enabled as needed.

## Build

```sh
make
make test
make test-full       # NIST CAVP and Wycheproof corpora
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

Public headers are in `src/tiny_crypto/`, following the Arduino library layout:

```c
#include <tiny_crypto/tiny_crypto.h>
```

Use `<tiny_crypto/tiny_crypto.hpp>` for the C++11 wrappers in the
`tiny_crypto` namespace.

## Configuration

All options are CMake cache variables. The defaults enable AES-128 CTR and
SHA-256, with memory wiping and pointer checks turned on.

| Option | Default | Meaning |
| --- | ---: | --- |
| `TINY_CRYPTO_ENABLE_AES` | ON | AES implementation |
| `TINY_CRYPTO_ENABLE_DES` | OFF | DES and 3DES implementation |
| `TINY_CRYPTO_ENABLE_SHA1` | OFF | SHA-1 implementation |
| `TINY_CRYPTO_ENABLE_SHA224` | OFF | SHA-224 (shares the SHA-256 core) |
| `TINY_CRYPTO_ENABLE_SHA256` | ON | SHA-256 implementation |
| `TINY_CRYPTO_ENABLE_SHA384` | OFF | SHA-384 (shares the SHA-512 core) |
| `TINY_CRYPTO_ENABLE_SHA512` | OFF | SHA-512 implementation |
| `TINY_CRYPTO_ENABLE_HMAC` | OFF | HMAC for enabled hashes |
| `TINY_CRYPTO_ENABLE_KMAC256` | OFF | Fixed-output KMAC256 with customization |
| `TINY_CRYPTO_ENABLE_KDF` | OFF | SP 800-108 KBKDF over the enabled HMAC and CMAC PRFs |
| `TINY_CRYPTO_ZEROIZE` | ON | Wipe contexts and stack secrets |
| `TINY_CRYPTO_STRICT` | ON | Validate public API pointers |
| `TINY_CRYPTO_AVR_PROGMEM` | ON | Keep constant tables out of AVR SRAM |

AES uses `TINY_CRYPTO_AES_KEY_BITS=128`, constant-time S-box access, and CTR by
default. `AES_CBC`, `AES_ECB`, `AES_OFB`, `AES_GCM`, `AES_CCM`,
`AES_EAX`, `AES_EAX_PRIME`, `AES_SIV`, and `AES_CMAC` enable individual modes
when prefixed with `TINY_CRYPTO_`. The S-box choices are `constant-time`,
`runtime`, and `fast`. GCM multiplication choices are `auto`, `bitwise`,
`wide`, `fast-table`, and `hardware`.

The non-constant-time `fast-table` mode adds 256 bytes to each GCM context.
Small MCUs can keep `TINY_CRYPTO_AES_TINY=ON` or use `auto`, `bitwise`, or
`wide` to avoid that RAM cost.

Enabling `TINY_CRYPTO_ENABLE_DES` also enables CTR and 3DES. `DES_ECB`, `DES_CBC`,
`DES_OFB`, `DES_CFB1`, `DES_CFB8`, `DES_CFB64`, and `DES_CMAC` select the
remaining modes when prefixed with `TINY_CRYPTO_`.
`TINY_CRYPTO_DES_REJECT_WEAK_KEYS=ON` rejects weak or semi-weak DES component
keys and TDEA bundles that collapse to single DES. It is off by default for
legacy-vector compatibility; firmware builds may instead define
`TC_DES_REJECT_WEAK_KEYS=1` directly.

SHA-1, SHA-224, and SHA-256 are implemented in `hash.c`. SHA-384 and SHA-512
share a 64-bit core in `sha512.c`. SHA-224 and SHA-384 reuse the compression
functions of SHA-256 and SHA-512, respectively, but each hash can be enabled
independently.

`TINY_CRYPTO_ENABLE_KDF` builds the SP 800-108 key-based key derivation
function in counter, feedback and double-pipeline mode. It needs at least one
PRF: HMAC with an enabled SHA digest, `TINY_CRYPTO_AES_CMAC`, or
`TINY_CRYPTO_DES_CMAC`. Each PRF gets its own function family
(`TC_KBKDF_HMAC_SHA256_counter`, `TC_KBKDF_AES_CMAC_feedback`, ...), so unused
PRFs compile out. AES-CMAC keys follow `TINY_CRYPTO_AES_KEY_BITS`; TDEA-CMAC is
kept for legacy interoperability only.

Run the host suite with every available GCC and Clang toolchain using
`make test-compilers`. Override the pairs when compiler names are versioned,
for example `make test-compilers TOOLCHAINS='gcc-15:g++-15 clang:clang++'`.

Projects that compile the C files directly can define the corresponding
`TC_*` macros documented in [`config.h`](src/tiny_crypto/config.h).

## API behavior

Operations that can fail return a `TC_status` code:

```c
TC_OK        /* success */
TC_MISMATCH  /* valid comparison or authentication failure */
TC_ERROR     /* malformed argument or invalid state */
```

Authentication checks examine the entire tag. One-shot AEAD decryptors only
write plaintext after authentication succeeds. Streaming GCM decryption writes
plaintext before `TC_AES_GCM_decrypt_finish` checks the tag. Do not use that
plaintext until the call returns `TC_OK`, and wipe it if any other status is
returned.

CTR, CBC, ECB, OFB, and CFB provide no authentication. Pair them with a MAC or
use an authenticated mode such as GCM, CCM, EAX, or SIV. Never reuse a CTR,
GCM, CCM, EAX, or OFB nonce with the same key.

DES has only a 56-bit effective key and exists for legacy interoperability.
Its table lookups are not designed to resist cache-timing attacks. 3DES also
belongs in compatibility code rather than new protocols.

SHA-1 remains available for compatibility. Do not use it for new
collision-resistant signatures or content identity. HMAC-SHA-1 is a separate
construction whose security does not rest on collision resistance; it remains
an acceptable MAC and KBKDF PRF, and is the smallest HMAC option on AVR.

For KBKDF, include the purpose, parties, and requested length in the fixed input
to distinguish keys derived for different uses. You can construct this input
with `TC_KBKDF_fixed_input` (`Label || 0x00 || Context || [L]_32`), and never
reuse a key-derivation key as a derived key. Output lengths are in bytes; a
derivation of `n = ceil(out_len / h)` PRF blocks needs `n <= 2^r - 1` for an
`r`-bit counter. Output buffers must not overlap any input, and `TC_ERROR`
wipes the output when derivation had already started.

## Benchmarks

We measure flash and static RAM usage for Arduino Uno and Raspberry Pi Pico 2
(RP2350, Arm Cortex-M33) builds. [docs/benchmarks.md](docs/benchmarks.md) lists
the sizes in bytes and as percentages of each board's flash and RAM capacity.
These are linked firmware sizes, not peak runtime memory measurements.

Run `make benchmark-report` to regenerate the report, or
`make benchmark-report-check` to check that it is up to date. Neither command
needs a connected board. Use `make benchmark` to measure throughput on the host
with the current build configuration.

## Testing

`test_default_profile` tests the configured `tiny-crypto-c` target. The other
tests share libraries built for specific configurations: full API, AES-192/256,
weak-key rejection, runtime S-box, and GHASH profiles. Each configuration is
compiled once and reused by its tests.

The fast suite covers all C modes and C++ wrappers. C tests use [µunit][munit],
and C++ tests use [doctest][doctest]. You can filter the C++ tests with doctest's
command-line options, for example `./build/test_cpp_hash -tc="*HMAC*"`.

`make test-full` adds the checked-in [NIST CAVP][cavp] response files and
[Wycheproof][wycheproof] authentication vectors,
including the complete 20,000-vector SP 800-108 KBKDF corpus split across
`test_kdf` (128-bit AES and every other PRF), `test_kdf_192` and
`test_kdf_256`.
CI tests with GCC, Clang, Apple Clang, and MSVC, runs sanitizers and the full
vector suite, and checks Arduino Uno and RP2350 build sizes.

## License

Project code is licensed under [GPL-2.0-or-later](LICENSE). Bundled test
materials have separate licenses: [µunit][munit] (`tests/support/munit.h`) and
[doctest][doctest] (`tests/support/doctest.h`) are MIT, [Wycheproof][wycheproof]
vectors under `tests/vectors/` are Apache-2.0, and [NIST CAVP][cavp] response
files are U.S. Government works in the public domain.

[doctest]: https://github.com/doctest/doctest
[munit]: https://nemequ.github.io/munit/
[cavp]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
[wycheproof]: https://github.com/C2SP/wycheproof
