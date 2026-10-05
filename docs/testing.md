<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Running the tests

The default suite runs offline from files in the source tree. It builds the enabled C munit tests,
C++ doctest tests, examples, package checks and configuration checks.

```sh
cmake -S . -B build -DTINY_CRYPTO_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Build an executable before selecting it with `ctest -R`. CTest reports a missing executable as
"Not Run". `ctest --test-dir build --show-only` lists the configured cases, and the test source is
the authoritative inventory. After a fix, rerun with `--rerun-failed --output-on-failure`.

## Make targets

Slow vector, oracle and packaging tests carry the `extended` CTest label. Run them after major work
and before a release.

| Target                                  | Runs                                                                         |
| --------------------------------------- | ---------------------------------------------------------------------------- |
| `make test`                             | `build`, skipping `extended` tests                                           |
| `make test-full`                        | `build-full` with `TINY_CRYPTO_TEST_FULL=ON` and every test                  |
| `make test-sanitize`                    | `build-sanitize` with ASan, UBSan and null-guard checks, skipping `extended` |
| `make test-sanitize-full`               | the sanitizer build with every test                                          |
| `make test-msan`, `make test-msan-full` | MemorySanitizer, which needs Clang on Linux                                  |
| `make test-cpp`                         | the C++ tests                                                                |
| `make test-compilers`                   | `make test` once per installed compiler pair in `TOOLCHAINS`                 |

The sanitizer targets set `TINY_CRYPTO_SANITIZE` and cover memory safety and undefined behavior.
MemorySanitizer uses a dedicated Clang build because every linked object must be instrumented.

## Profiles and feature configurations

`TINY_CRYPTO_RESOURCE_PROFILE` is empty for the default build, or `micro`, `mini` or `desktop`.
Individual `TINY_CRYPTO_*` options override the profile defaults.

```sh
cmake -S . -B build-full \
  -DTINY_CRYPTO_BUILD_TESTS=ON \
  -DTINY_CRYPTO_RESOURCE_PROFILE=desktop
cmake --build build-full --parallel
ctest --test-dir build-full --output-on-failure
```

Configuration tests compile minimal, maximal and invalid combinations and check that the installed
headers describe the library's feature set. `test_application_targets` configures, builds and runs
every [application target](targets.md) under each resource profile. RSA tests exercise each
modulus-size gate on its own. C++ header tests compile with features both on and off, so a wrapper
can only expose C operations that exist.

## Test options

Corpus, oracle, fuzzing and hardware tests are opt-in CMake options. After configuring, list the
names and defaults with `cmake -LAH -N build`.

External corpus locations: `TINY_CRYPTO_TEST_ECDSA_DSS_DIR`, `TINY_CRYPTO_TEST_RSA_DSS_DIR`,
`TINY_CRYPTO_TEST_EC_CAVP_DIR`, `TINY_CRYPTO_TEST_WYCHEPROOF_DIR`,
`TINY_CRYPTO_TEST_SM_CAPTURE_DIR`, `TINY_CRYPTO_TEST_TLV_CORPUS`,
`TINY_CRYPTO_TEST_TLV_MBEDTLS_SUITE` and `TINY_CRYPTO_TEST_UNICODE_DIR`.

Oracles and integration jobs: `TINY_CRYPTO_TEST_EC_ORACLE`, `TINY_CRYPTO_TEST_OPENSSL`,
`TINY_CRYPTO_TEST_ESP_ECDSA`, `TINY_CRYPTO_TEST_ESP_SIGNED_IMAGE`, `TINY_CRYPTO_TEST_PIV_CARD` and
`TINY_CRYPTO_TEST_FULL`.

## Vendored vectors

Checked-in known answers cover crypto regressions without OpenSSL. CAVP, ACVP and Wycheproof
adapters broaden algorithm coverage, and OpenSSL and Python `cryptography` jobs act as independent
oracles.

The CAVP, ACVP, Wycheproof, PIV, TWIC, X.509 and EAC vectors live under `tests/vectors/`, and the
tests download nothing. [`tests/vectors/README.md`](../tests/vectors/README.md) lists the
collections. Point a test at another copy of a corpus with the directory options in
[Test options](#test-options).

Each corpus root has a provenance README and a recursive `SHA256SUMS`. `test_vector_manifests`
requires every vector file to appear in a manifest. It rejects missing files, unlisted files,
entries outside their directory and digest changes. The Wycheproof subset keeps only the documents
the adapters exercise, and the runner reports the parameter groups it skips.

## AVR builds and budgets

AVR checks compile the public headers and selected operations with the AVR toolchain, then enforce
the configured flash, RAM, stack and work ceilings. The `*_compile_avr` tests run when CMake finds
`avr-gcc`. With `qemu-system-avr` also on the path, the `*_qemu_avr` tests run AES, AES key wrap
and a scripted PIV read on an emulated ATmega328P through `tests/avr/run_qemu.py`.

## ESP-IDF signed image tests

The ESP-IDF tests verify checked-in signed-image fixtures and policy behavior on the host.

## Reproducing CI sanitizer jobs

The CI workflow is the source of truth for compiler flags. Reproduce it locally with `act` and the
checked-in sanitizer workflow:

```sh
act workflow_dispatch --bind -W .github/act/cms-sanitizer.yml -j gcc
act workflow_dispatch --bind -W .github/act/cms-sanitizer.yml -j clang
act workflow_dispatch --bind -W .github/act/cms-sanitizer.yml -j msan
```

Run one sanitizer configuration at a time when builds share a directory. Save the full failing
command and seed before reducing a failure.

## Null-guard instrumentation

`TINY_CRYPTO_TEST_NULL_GUARD=ON`, set by `make test-sanitize`, checks every public C function for
missing argument checks. The build generates `null_guard_wrappers.h` from Clang's AST of the public
headers and force-includes it into the C test sources. Generating the wrappers needs Clang, even in
GCC builds. C++ tests call the library directly.

Before each public call a test makes, the wrapper repeats the call once per pointer argument with
that argument NULL, and once per span argument with NULL data and the caller's nonzero length. The
other arguments keep the test's real values, so the call gets past the library's argument checks.
AddressSanitizer or UndefinedBehaviorSanitizer then reports any unguarded dereference. A NULL call
that returns `TC_RESULT_OK` aborts the test with the function and parameter name.

- A pointer followed by an integer count becomes NULL only when the count is nonzero.
- `void*` callback contexts named `context` or `user` pass through unchanged.
- [`tests/null_guard/nullable.txt`](../tests/null_guard/nullable.txt) lists parameters that accept
  NULL by contract, each with its reason. Add an entry only when the public header documents the
  NULL behavior.
- Writable objects passed by pointer are restored after each repeated call. Span contents stay
  as they are, because an argument error must leave outputs unchanged.
- The wrappers include `<stdint.h>`, which fixes the C library's feature-test macros. A source that
  defines one, such as `_POSIX_C_SOURCE`, before its first include gets the same definition on the
  command line. A source that defines one macro with two values compiles without the wrappers.
- `tc_skip_null_guard` keeps one test executable on direct calls when the repeated calls would
  change library state the test counts, such as a fault injection counter.

`test_null_guard_coverage` runs after the other tests. It lists unreached cases that are missing
from [`tests/null_guard/uncovered.txt`](../tests/null_guard/uncovered.txt). Cover each new public
function with a C test, which also brings it under the instrumentation.

## Fuzzing

Configure the Clang fuzz build, build the targets, then run their regression tests:

```sh
cmake -S . -B build-fuzz \
  -DTINY_CRYPTO_BUILD_TESTS=ON \
  -DTINY_CRYPTO_BUILD_FUZZERS=ON \
  -DCMAKE_C_COMPILER=clang
cmake --build build-fuzz \
  --target fuzz_tlv fuzz_pki fuzz_ocsp fuzz_piv_apdu fuzz_gzip fuzz_twic
ctest --test-dir build-fuzz -R '^test_fuzz_' --output-on-failure
```

Keep minimized seeds that reach distinct parser states. New corpus files need the same provenance
and manifest checks as other vectors.

## Arduino, PlatformIO and installed packages

Package checks compile the `.ino` sketches, pack the PlatformIO library for inspection and build
CMake consumers from an installation. The archives must contain the public sources, licenses and
supported examples, and exclude external corpora. Size limits catch accidental repository-wide
exports. `library.properties` supports direct Arduino source imports and build testing.

## Hardware tests

Hardware tests are opt-in and carry the `hardware` CTest label. Configure
`TINY_CRYPTO_TEST_PIV_CARD=ON`, build the named targets, connect the intended reader and card, then
run only that label:

```sh
cmake -S . -B build-card -DTINY_CRYPTO_TEST_PIV_CARD=ON
cmake --build build-card --target test_piv_card_hardware test_piv_inspect_live
ctest --test-dir build-card -L hardware --output-on-failure
```

These tests may change card authentication state or consume retry counters. Read the target's help
and fixture requirements first. Simulator, host and link results count separately from runs on a
physical card.

### PIV card hardware tests

The tests exit with status 77 (skipped) until `TC_PIV_CARD_READER` names a substring of exactly one
reader. [`tests/piv/hardware/card_config.h`](../tests/piv/hardware/card_config.h) lists the
variables for the PIN, pairing code, retry floor, expected card, trust, revocation and evaluation
time.

## Regenerating vectors

Vector and table generators live under `tools/` and share the CAVP parser and C-array emitter.
`make regenerate-vectors` runs the hash, DES and KDF generators. Regeneration must be
deterministic: run it twice and require a clean `git diff` after the second run. Generator
dependencies are development requirements and stay out of shipped packages.

[Benchmarks](benchmarks.md) covers flash, RAM and stack measurements per board.
