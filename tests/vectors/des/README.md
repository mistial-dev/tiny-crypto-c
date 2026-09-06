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

`Cases` counts top-level `COUNT =` records. A checksum is SHA-256 of a
path-sorted manifest whose UTF-8 lines are
`<file SHA-256><two spaces><path relative to cavp/><LF>`.

| Corpus | Files | Cases | Manifest SHA-256 |
| --- | ---: | ---: | --- |
| Known-answer tests, `cavp/kat/` | 30 | 2,820 | `38f3f223b7540a25fcb7441a621810f99e9afba413177e242ddc816cb1776c87` |
| Multi-block tests, `cavp/mmt/` | 12 | 180 | `3be1576674de35b5b58ded6302dbfefef73dc23407f0e1c622fa80bc03350a11` |
| Monte Carlo tests, `cavp/mct/` | 12 | 7,200 | `b4d66987a6fb29885b80d2396bdabae45ef9530c5df29dfce97a6601c7f4af80` |

NIST states that these vectors provide informal correctness checks and do not
replace CAVP validation.

## Generated edge cases

`edge_cases.json` contains 16 valid DES and TDES cases covering weak keys,
parity variants, mode boundaries, in-place operation, and non-byte-aligned
CFB1 lengths. `tools/generate_des_edge_vectors.py` generates the file with
Python `cryptography` and cross-checks applicable results with OpenSSL.
Regenerate it with `make regenerate-vectors`.

SHA-256: `ede35aafd5b0076759557820a7f684edaf330f05d297860db9ad0323e851ce01`
