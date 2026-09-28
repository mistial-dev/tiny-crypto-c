<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# AES-CMAC test vectors

## NIST SP 800-38B Appendix D

The four AES-128 / AES-192 / AES-256 examples for empty, one-block, multi-block
partial, and multi-block full messages are transcribed into `cmac_test.c` from
[NIST SP 800-38B](https://csrc.nist.gov/publications/detail/sp/800-38b/final)
Appendix D.

## NIST CAVP (CMAC Gen / Ver), full AES corpora

These files are the complete AES entries from the
[NIST CAVP CMAC test vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/message-authentication)
archive (`cmactestvectors.zip`, CAVS 11.0), unchanged:

| File | Cases |
| --- | ---: |
| `CMACGenAES128.rsp` | 96 |
| `CMACGenAES192.rsp` | 144 |
| `CMACGenAES256.rsp` | 96 |
| `CMACVerAES128.rsp` | 240 |
| `CMACVerAES192.rsp` | 360 |
| `CMACVerAES256.rsp` | 240 |

Includes short tags (`Tlen` 4/5) and 64 KiB messages. The TDES files from the
same archive are in `tests/vectors/des/cmac/`.

CMAC unit-test builds set `TC_AES_CMAC_MIN_TAG_LEN=4` so every CAVP row can
exercise
the public API. The **product default** remains 8 (SP 800-38B ≥ 64-bit
guidance; same floor style as EAX).

## Wycheproof

The AES-CMAC tests read `aes_cmac_test.json` (311 cases) from the shared
Wycheproof tree in `../../wycheproof/testvectors_v1/`, described in
`../../wycheproof/README.md`. Each AES key-size test binary runs the 102 cases
for its key size plus the 5 `InvalidKeySize` cases, which the fixed-length API
rejects.

## Checksums

`SHA256SUMS` lists the SHA-256 of every file here, and
`tests/test_vector_manifests.py` checks them.
