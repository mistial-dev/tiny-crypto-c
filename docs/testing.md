<!-- SPDX-FileCopyrightText: Mistial Dev -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Running the tests

The ordinary suite is offline. It builds the enabled C munit tests, C++
doctest tests, examples, package checks and configuration checks from files in
the source tree.

```sh
cmake -S . -B build -DTINY_CRYPTO_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Build a named executable before selecting it with `ctest -R`; a missing test
executable usually means its target has not been built. Use
`ctest --test-dir build --show-only` to inspect the configured suite and
`--rerun-failed --output-on-failure` after correcting a failure.

## Profiles and feature configurations

`TINY_CRYPTO_RESOURCE_PROFILE` selects `default`, `micro`, `mini` or
`desktop`. Individual `TINY_CRYPTO_*` options override profile defaults.
Configuration tests compile minimal, maximal and invalid combinations and
check that installed headers describe the same feature set as the library.

```sh
cmake -S . -B build-full \
  -DTINY_CRYPTO_BUILD_TESTS=ON \
  -DTINY_CRYPTO_RESOURCE_PROFILE=desktop
cmake --build build-full --parallel
ctest --test-dir build-full --output-on-failure
```

The PIV and TWIC checks use their dedicated CMake targets and presets. RSA
tests exercise each enabled modulus-size gate independently. C++ header tests
compile with features both enabled and disabled so wrappers cannot expose
missing C operations.

## Test evidence

- Unit tests use munit for C and doctest for C++.
- Checked-in known answers cover ordinary crypto regressions without OpenSSL.
- CAVP, ACVP and Wycheproof adapters provide broader algorithm coverage.
- OpenSSL and Python `cryptography` jobs are independent supplemental oracles.
- Sanitizer jobs cover memory safety and undefined behavior. MemorySanitizer
  uses its dedicated Clang build because every linked object must be
  instrumented.
- Fuzz targets retain malformed parser inputs as regression seeds.
- AVR and other embedded jobs prove compilation, linking and static resource
  budgets. They do not claim execution on physical hardware.

The test source is the authoritative case inventory. List current cases with
CTest instead of maintaining a second list in this document.

## Test options

Corpus, oracle, fuzzing, and hardware tests are opt-in CMake options. Inspect
the current names and defaults with `cmake -LAH -N build` after configuring.
External corpus locations use `TINY_CRYPTO_TEST_ECDSA_DSS_DIR`,
`TINY_CRYPTO_TEST_RSA_DSS_DIR`, `TINY_CRYPTO_TEST_EC_CAVP_DIR`,
`TINY_CRYPTO_TEST_WYCHEPROOF_DIR`, `TINY_CRYPTO_TEST_SM_CAPTURE_DIR`,
`TINY_CRYPTO_TEST_TLV_CORPUS`, `TINY_CRYPTO_TEST_TLV_MBEDTLS_SUITE`, and
`TINY_CRYPTO_TEST_UNICODE_DIR`. Optional oracles and integration jobs use
`TINY_CRYPTO_TEST_EC_ORACLE`, `TINY_CRYPTO_TEST_OPENSSL`,
`TINY_CRYPTO_TEST_ESP_ECDSA`, `TINY_CRYPTO_TEST_ESP_SIGNED_IMAGE`,
`TINY_CRYPTO_TEST_PIV_CARD`, and `TINY_CRYPTO_TEST_FULL`.

## AVR builds and budgets

AVR checks compile the public headers and selected operations with the AVR
toolchain, then enforce the configured flash, RAM, stack, and work ceilings.

## ESP-IDF signed image tests

The ESP-IDF tests verify checked-in signed-image fixtures and policy behavior.
They do not claim execution on a physical ESP32 target.

## External vector bundle

Large public corpora are stored in a versioned archive outside source release
tags. The vector lock file records its URL, SHA-256 digest and expanded size.
Fetching is explicit and writes only to the selected build or cache directory.
Core tests never download data.

Each declared corpus root has a provenance README and recursive
`SHA256SUMS`. The manifest test requires every vector file to be covered
exactly once and rejects missing files, extra files, path traversal and digest
changes. Retained Wycheproof files may contain unsupported parameter groups;
those groups are useful rejection tests.

Run the extended suite after fetching the locked archive and pass its expanded
directory through the configured vector-directory option. CI performs this in
the full-test workflow.

## Sanitizers and local workflow reproduction

The CI workflow is the source of truth for compiler flags. Local workflow
reproduction with `act` uses the checked-in sanitizer workflow:

```sh
act workflow_dispatch --bind -W .github/act/cms-sanitizer.yml -j gcc
act workflow_dispatch --bind -W .github/act/cms-sanitizer.yml -j clang
act workflow_dispatch --bind -W .github/act/cms-sanitizer.yml -j msan
```

Run one sanitizer configuration at a time when builds share a directory.
Preserve the complete failing command and seed before reducing a failure.

## Fuzzing

Configure the Clang fuzz build, build the desired targets, then run their
regression tests:

```sh
cmake -S . -B build-fuzz \
  -DTINY_CRYPTO_BUILD_TESTS=ON \
  -DTINY_CRYPTO_BUILD_FUZZERS=ON \
  -DCMAKE_C_COMPILER=clang
cmake --build build-fuzz --target fuzz_tlv fuzz_pki fuzz_piv_apdu fuzz_gzip
ctest --test-dir build-fuzz -R '^test_fuzz_' --output-on-failure
```

Keep minimized seeds that exercise distinct parser states. Corpus growth needs
the same provenance and manifest checks as other external vectors.

## Arduino, PlatformIO and installed packages

Package checks run strict `arduino-lint`, compile the shipped `.ino` sketches,
pack the PlatformIO library, and build CMake consumers from an installation.
The inspected archives must contain public sources, licenses and supported
examples while excluding external corpora. Package size limits catch accidental
repository-wide exports.

## Hardware tests

Hardware tests are opt-in and carry the `hardware` CTest label. Configure the
explicit PC/SC or device option, build the named target, confirm the intended
reader and card are connected, then run only that label:

```sh
cmake --build build-card --target test_piv_card_hardware test_piv_inspect_live
ctest --test-dir build-card -L hardware --output-on-failure
```

Hardware tests may change card authentication state or consume retry counters.
Read the target's help and fixture requirements before running it. Simulator,
host and link evidence remain separate from physical-card execution.

### PIV card hardware tests

PIV card checks require the explicitly configured reader and card fixture.
Run their named targets under the `hardware` label only.

## Regeneration and benchmarks

Vector and table generators live under `tools/` and share the common CAVP
parser and C-array emitter. Regeneration must be deterministic: run it twice
and require a clean `git diff` after the second run. Generator dependencies are
development requirements and are absent from shipped packages.

Benchmarks report flash, RAM, stack and bounded work for the named profile.
Treat them as measurements of that compiler, configuration and target. CI
checks configured ceilings; it does not generalize one target's measurements
to another board.
