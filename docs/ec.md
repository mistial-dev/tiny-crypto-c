<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Elliptic-curve operations

`<tiny_crypto/ec.h>` provides P-192, P-256 and P-384 key generation, public-key derivation and
validation, ECDH, and ECDSA signing and verification for the curves enabled in the build. P-192 is
off by default. Enable `TINY_CRYPTO_EC_ENABLE_P192` for protocols that require it.

Public keys use SEC 1 uncompressed encoding, `04 || X || Y`. Coordinates and private scalars are
fixed-width big-endian values: 24 bytes for P-192, 32 for P-256 and 48 for P-384.
`TC_EC_coordinate_bytes(curve)` returns that width, or 0 for an unknown or disabled curve. A public
key is `1 + 2 * width` bytes, a signature `2 * width` bytes and an ECDH secret `width` bytes.
`TC_EC_MAX_BYTES` is the largest width in the build.

## Calling conventions

Every function returns a `TC_EC_result`:

| Status              | Meaning                                                                                                                                  |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `TC_EC_OK`          | The operation completed and its outputs were written.                                                                                    |
| `TC_EC_INVALID`     | A key or signature length that differs from the curve's, a private scalar outside `[1, n-1]`, a point off the curve, or a bad signature. |
| `TC_EC_LIMIT`       | An output buffer shorter than required, or the work budget or random-attempt limit ran out.                                              |
| `TC_EC_ARGUMENT`    | A NULL pointer, an empty digest or overlapping storage.                                                                                  |
| `TC_EC_UNSUPPORTED` | The curve is unknown or disabled in this build.                                                                                          |
| `TC_EC_ERROR`       | The random source failed, or a new signature failed its own verification.                                                                |

Each function reports the first problem in this order: `TC_EC_ARGUMENT`, `TC_EC_UNSUPPORTED`,
`TC_EC_INVALID` for input lengths, then `TC_EC_LIMIT` for output capacity and work. These checks
leave outputs, workspace, work budget and random source untouched.

Input spans must match the curve length exactly. Output buffers may be larger than required, and
each call writes exactly the required length, only on `TC_EC_OK`.

Every call takes a `TC_work_budget`. `TC_EC_operation_work(curve, operation)` returns the cost of
one operation, or one attempt of a randomized operation. The call checks the full cost before it
starts. See [work budgets](api.md#work-budgets) for the units.

Randomized operations take a `TC_EC_execution` that groups the random source, the maximum number
of random requests and the work budget. The source must be cryptographically secure and fill each
request completely.

## Keys and ECDH

`TC_EC_generate_key_pair` draws a private scalar, retries out-of-range draws within
`random_attempts`, and writes the scalar and its public key. `TC_EC_public_key` derives a public
key from a private scalar. `TC_EC_validate_public_key` checks that a public key is a point on the
curve (SEC 1 section 3.2.2.1).

`TC_ECDH` validates the peer key and writes the shared point's X coordinate, including leading
zero bytes. Pass it through the protocol's key derivation function before using it as a key.

## ECDSA

`TC_ECDSA_verify_digest` takes the public key, a precomputed digest and a fixed-width `r || s`
signature. Convert DER signatures to this form first. Hash the message with the algorithm the
protocol requires. A digest longer than the curve order is truncated to its leftmost bytes, and a
shorter one is zero-extended. High and low `s` values are both accepted. Verification establishes
signature validity only. Key identity and trust come from certificate validation. The verification
point multiplication branches on public signature and digest values.

`TC_ECDSA_sign_digest` takes the private scalar, matching public key, digest hash algorithm and a
retry bound. It derives each secret nonce with RFC 6979, so a repeated or restored random source
leaves the private key safe.

`TC_ECDSA_sign_digest_external_random` serves protocols that must supply nonces externally. Each
attempt draws an independent secret nonce from its execution object. Repeating a nonce across
different digests exposes the private key.

With the compile definition `TC_ECDSA_SIGN_VERIFY` set (the default, with no CMake option), both
signing functions verify the new signature against the public key before writing it. A fault
during signing, or a public key from another key pair, then returns `TC_EC_ERROR` with the output
unchanged. Set `TC_ECDSA_SIGN_VERIFY=0` only where the verification cost is unacceptable and faults
are handled another way.

Key generation, public-key derivation, ECDH and signing use constant-work multiplication for secret
scalars.

## Storage

Operations use caller-owned `TC_EC_workspace` or `TC_ECDSA_workspace` scratch, sized for the
configured curves and limb width. Keep it disjoint from inputs and outputs, and give concurrent
calls separate workspaces. Once arithmetic starts, the call wipes scratch before return. Argument
rejection leaves it untouched.

On AVR the library uses byte limbs. `tests/budgets/avr.json` records an ATmega2560 ECDSA P-256
profile with P-384 disabled and `TC_ECDSA_SIGN_VERIFY` on, covering deterministic signing and
standalone verification. It allows at most 18000 bytes of flash, 1500 bytes of static RAM
(including a static 1218-byte `TC_ECDSA_workspace`) and 1000 bytes of project stack. The
ATmega328P's 2 KiB RAM is too small for the measured static data and worst-case project call
chain. Check the budget with:

```sh
python3 tools/measure_avr_resources.py --check tests/budgets/avr.json
```

The file's `avr_gcc_version` names the toolchain used for the measurements. The check prints it
beside the version in use and accepts either.

## C++

`<tiny_crypto/ec.hpp>` provides C++11 equivalents, including `ec_coordinate_bytes`. They take
`bytes` inputs, fixed-size output arrays and references to the workspace and budget.
`ec_generate_key_pair` and `ecdsa_sign_digest_external_random` take an execution object, and
`ecdsa_sign_digest` takes its options after the workspace. They return the same `TC_EC_result`
values, use no heap and are `noexcept`.

## Tests

`test_ec_0` and `test_ec_1` cover each limb width. `test_ec_p256`, `test_ec_p384` and
`test_ec_rfc6979` check single-curve builds and the RFC 6979 answers. The extended `test_ec_cavp`,
`test_wycheproof_ec` and `test_wycheproof_ecdsa` run the NIST CAVP and Wycheproof suites.
`test_ecdsa_sign_verify_*` injects a fault between signing and self-verification, with the check
enabled and disabled.

Configure with `-DTINY_CRYPTO_TEST_OPENSSL=ON` to build the OpenSSL 3 comparison tests, which cover
both limb widths and all three curves. Set `OPENSSL_ROOT_DIR` when the default OpenSSL is older
than 3. OpenSSL is a test dependency only.

```sh
ctest --test-dir build -R '^test_ecdsa_openssl_' --output-on-failure
```
