<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# AES CAVP corpus

These files are unmodified NIST Cryptographic Algorithm Validation Program
(CAVP) vectors. Original CRLF line endings are preserved by `.gitattributes`.
They run under `make test-full`. The ordinary test suite uses smaller generated
known-answer sets.

## Provenance and retained scope

The ECB, CBC, and OFB files came from the NIST CAVP
[block-cipher test-vector page](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Block-Ciphers):

- [`KAT_AES.zip`](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip)
- [`aesmct.zip`](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmct.zip)
- [`aesmct_intermediate.zip`](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmct_intermediate.zip)
- [`aesmmt.zip`](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmmt.zip)

They are CAVS 11.1 files generated on 2011-04-22. All 128-, 192-, and
256-bit ECB, CBC, and OFB response files are retained. The nine MCT debug files
are retained because the runner checks selected intermediate iterations. CFB
files and unused intermediate files are omitted.

The authenticated-encryption files came from the NIST CAVP
[block-cipher-mode test-vector page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes):

- [`gcmtestvectors.zip`](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip)
  CAVS 14.0, generated 2012-08-31
- [`ccmtestvectors.zip`](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip)
  CAVS 11.0, generated 2011-03-15

The GCM subset contains encrypt and decrypt files for all three AES key sizes.
The CCM subset contains the VADT, VNT, VPT, VTT, and DVPT files for all three
key sizes.

## Inventory and checksums

`Cases` counts top-level `COUNT =` records, case-insensitively. `SHA256SUMS` lists the SHA-256 of every file in this directory, and `tests/test_vector_manifests.py` checks them.

| Corpus | Files | Cases |
| --- | ---: | ---: |
| AESAVS response files, `ecb/`, `cbc/`, `ofb/` | 54 | 8,214 |
| AESAVS MCT debug files, `*.txt` | 9 | 1,800 |
| GCMVS, `gcm/` | 6 | 47,250 |
| CCMVS, `ccm/` | 15 | 2,880 |
