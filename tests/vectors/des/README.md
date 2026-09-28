<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# DES and TDES test corpora

The `cavp/` tree contains unmodified NIST Cryptographic Algorithm Validation
Program (CAVP) vectors. Original CRLF line endings are preserved by
`.gitattributes`. They run under `make test-full` and are split into parallel
CTest groups by test family and mode.

## NIST CAVP provenance

The files came from the NIST CAVP
[block-cipher test-vector page](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Block-Ciphers):

- [`KAT_TDES.zip`](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/KAT_TDES.zip)
- [`tdesmct.zip`](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/tdesmct.zip)
- [`tdesmmt.zip`](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/tdesmmt.zip)

The KAT and MCT files identify themselves as CAVS 11.1; the MMT files identify
themselves as CAVS 18.0. The retained files cover ECB, CBC, CFB1, CFB8, CFB64,
and OFB with DES plus two-key and three-key TDES. Unused MCT
intermediate-debug files are omitted.

`Cases` counts top-level `COUNT =` records.

| Corpus | Files | Cases |
| --- | ---: | ---: |
| Known-answer tests, `cavp/kat/` | 30 | 2,820 |
| Multi-block tests, `cavp/mmt/` | 12 | 180 |
| Monte Carlo tests, `cavp/mct/` | 12 | 7,200 |

## NIST TDES CMAC

The four `cmac/CMAC*TDES*.rsp` files are unchanged entries from NIST CAVP
`cmactestvectors.zip`, CAVS 11.0, also used for the AES CMAC tests. The archive
SHA-256 is `bdda4edade394c9a2ae74d9cd0921caa120c911a5e735e37abf39d0d5f062be1`.
The checked-in AES file `CMACGenAES128.rsp` matches its archive entry after
normalizing CRLF to LF. Tests cover 96 generation and 360 verification cases
for two-key TDES, plus 96 generation and 240 verification cases for three-key
TDES. Seventy-two two-key verification rows alter Key3, violating the two-key
bundle K3=K1; the runner checks their failure result and counts them separately.
The remaining 720 rows exercise the CMAC calculation or verification. The
test-only profile allows one-byte tags so every CAVP row runs.

## Generated edge cases

`edge_cases.json` contains 16 valid DES and TDES cases covering weak keys,
parity variants, mode boundaries, in-place operation, and non-byte-aligned
CFB1 lengths. `tools/generate_des_edge_vectors.py` generates the file with
Python `cryptography` and cross-checks applicable results with OpenSSL.
Regenerate it with `make regenerate-vectors`.

## Checksums

`SHA256SUMS` lists the SHA-256 of every file in this directory, and
`tests/test_vector_manifests.py` checks them.
