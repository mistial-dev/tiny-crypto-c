<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Vendored test corpora

Every file below is checked in unmodified, and CAVP files keep their
original CRLF line endings (see `.gitattributes`). `SHA256SUMS` lists the
SHA-256 of every file, and `tests/test_vector_manifests.py` checks them.

## NIST CAVP SHAVS (byte-oriented), `cavp/sha/`

Source: `shabytetestvectors.zip` from the
[NIST Cryptographic Algorithm Validation Program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)
(CAVS 11.0/11.1, generated 2011-05-11). The SHA-1, SHA-224, SHA-256, SHA-384
and SHA-512 files are kept. The SHA-512/224 and SHA-512/256 files are omitted
because the library does not implement those digests. Run them with `make test-full`.

| File | Cases |
| --- | ---: |
| `SHA1ShortMsg.rsp` | 65 |
| `SHA1LongMsg.rsp` | 64 |
| `SHA1Monte.rsp` | 100 |
| `SHA224ShortMsg.rsp` | 65 |
| `SHA224LongMsg.rsp` | 64 |
| `SHA224Monte.rsp` | 100 |
| `SHA256ShortMsg.rsp` | 65 |
| `SHA256LongMsg.rsp` | 64 |
| `SHA256Monte.rsp` | 100 |
| `SHA384ShortMsg.rsp` | 129 |
| `SHA384LongMsg.rsp` | 128 |
| `SHA384Monte.rsp` | 100 |
| `SHA512ShortMsg.rsp` | 129 |
| `SHA512LongMsg.rsp` | 128 |
| `SHA512Monte.rsp` | 100 |

Monte Carlo files use the SHAVS standard-mode procedure (100 checkpoints of
1000 chained digests each). `Len = 0` records carry a placeholder `Msg = 00`
that the runner treats as an empty message.

## NIST CAVP HMACVS, `cavp/hmac/`

Source: `hmactestvectors.zip` from the
[NIST CAVP message authentication page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/message-authentication)
(CAVS 11.0, generated 2011-03-16). The runner exercises every `[L=]` group
whose digest is compiled in: `L=20` (300 cases), `L=28` (375), `L=32` (225),
`L=48` (300) and `L=64` (375), 1575 in total. The file is `cavp/hmac/HMAC.rsp`.

## Wycheproof

The HMAC tests read `hmac_sha{1,224,256,384,512}_test.json` from the shared
Wycheproof tree in `../wycheproof/testvectors_v1/`, described in
`../wycheproof/README.md`. They run in `make test` when HMAC is enabled.

Wycheproof tags shorter than `TC_HMAC_MIN_TAG_LEN` are checked against the
prefix of the full streaming tag. The public one-shot and verify APIs are
exercised for the tag lengths they accept.

## Generated known-answer tests, `../../hash/test_vectors.h`

FIPS 180-4 examples, RFC 2202 / RFC 4231 HMAC cases, padding-boundary and
key-length cases for SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 are produced
by `tools/generate_hash_vectors.py` using Python's standard library and
cross-checked against the `openssl dgst` CLI. Regenerate with
`make regenerate-vectors`.
