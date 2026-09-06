<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Vendored test corpora

Every file below is checked in unmodified. Checksums are SHA-256 of the file
as vendored (CAVP files keep their original CRLF line endings; see
`.gitattributes`).

## NIST CAVP SHAVS (byte-oriented), `cavp/sha/`

Source: `shabytetestvectors.zip` from the
[NIST Cryptographic Algorithm Validation Program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)
(CAVS 11.0/11.1, generated 2011-05-11). The SHA-1, SHA-224, SHA-256, SHA-384
and SHA-512 files are kept; the SHA-512/224 and SHA-512/256 files are not
because those digests are not implemented. Run them with `make test-full`.

| File | Cases | SHA-256 |
| --- | ---: | --- |
| `SHA1ShortMsg.rsp` | 65 | `be0991ddc5372932d55804b11713c9140d10435ef4b316a0773e3506eec79cda` |
| `SHA1LongMsg.rsp` | 64 | `c765dbc1609e9046b12f60a5285a88128dab4315080c94ce9f2a57a7b0b980be` |
| `SHA1Monte.rsp` | 100 | `d458fa7e39095b4e292a75b0cd224f90b72dc801a63ad2c0d75b8f10d745ab6d` |
| `SHA224ShortMsg.rsp` | 65 | `0dad6656c08f77252f6ccb789e42284fd61fc53bba30e83162800aa3d2aa939f` |
| `SHA224LongMsg.rsp` | 64 | `d37115e5d2286dde969c5e1b2275cd83ecb066366d7a38bb6b2b3adb4a88de89` |
| `SHA224Monte.rsp` | 100 | `7854d388666ea3eb01bdaca37dc8ae0bc39d30f8731d9a5487cbd61de47d1d59` |
| `SHA256ShortMsg.rsp` | 65 | `75e1cb83994638481808e225b9eb0c1ebd0c232d952ac42b61abce6363be283c` |
| `SHA256LongMsg.rsp` | 64 | `6fac36f37360bcf74ffcf4465c18e30d6d5a04cc90885b901fc3130c16060974` |
| `SHA256Monte.rsp` | 100 | `29ea30c6bb4b84e425fb8c1d731c6bb852dac935825f2bd1143e5d3c4f10bfb9` |
| `SHA384ShortMsg.rsp` | 129 | `7ea7bcf00fadc20949fae63703e40681ddf288fea808471cb3cbc95f3ec16811` |
| `SHA384LongMsg.rsp` | 128 | `536171765a4278c000ac3c9913edb2eed0ca7ccd5a10b72ed79fdfe7901a6d6a` |
| `SHA384Monte.rsp` | 100 | `4270099431ff52ee1686dc472351e681c26c507433df8f107c7de203b771424e` |
| `SHA512ShortMsg.rsp` | 129 | `e53a36c03609e5a3e3cc4b6e117a499db7864c23ec825c6cec99503a45f40764` |
| `SHA512LongMsg.rsp` | 128 | `b1f3f05d5c209777954d49521d7ea1349447c36a0c52849e044bc397a27dd410` |
| `SHA512Monte.rsp` | 100 | `8ca78659286c2f01667a98fc7accd32fc171ae7b24ac00f1a8ce6b77770247fa` |

Monte Carlo files use the SHAVS standard-mode procedure (100 checkpoints of
1000 chained digests each). `Len = 0` records carry a placeholder `Msg = 00`
that the runner treats as an empty message.

## NIST CAVP HMACVS, `cavp/hmac/`

Source: `hmactestvectors.zip` from the
[NIST CAVP message authentication page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/message-authentication)
(CAVS 11.0, generated 2011-03-16). The runner exercises every `[L=]` group
whose digest is compiled in: `L=20` (300 cases), `L=28` (375), `L=32` (225),
`L=48` (300) and `L=64` (375), 1575 in total.

| File | SHA-256 |
| --- | --- |
| `HMAC.rsp` | `cf27b6ad24fc3d72f8d18f8cee8a2b366302395cc50f5d9e607fbce4e98001eb` |

## Wycheproof, `wycheproof/`

Source: [C2SP Project Wycheproof](https://github.com/C2SP/wycheproof),
`testvectors_v1/` (schema `mac_test_schema_v1.json`). Licensed under the
Apache License 2.0 (<https://www.apache.org/licenses/LICENSE-2.0>). Always run
by `make test` when HMAC is enabled.

| File | SHA-256 |
| --- | --- |
| `hmac_sha1_test.json` | `b521c6180a862247986392d3cb49b511fc7fe790e75bee236f84e36ca290c7c0` |
| `hmac_sha224_test.json` | `9b3a2470fe5bc8aa2d3e55f19772dc1f88fda897863ed4eaa4d8536c244c320b` |
| `hmac_sha256_test.json` | `2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f` |
| `hmac_sha384_test.json` | `28b9776e979dd755d852ca471043ea6cedce8b15f7a28abdf6ea9efd982b43c0` |
| `hmac_sha512_test.json` | `b6c90477bdb4a6fc8ee3d1f7b2c0b69a8dfffab34718abaa6cabd71cc2ba1207` |

Wycheproof tags shorter than `TC_HMAC_MIN_TAG_LEN` are checked against the
prefix of the full streaming tag; the public one-shot and verify APIs are only
exercised for tag lengths they accept.

## Generated known-answer tests, `../../hash/test_vectors.h`

FIPS 180-4 examples, RFC 2202 / RFC 4231 HMAC cases, padding-boundary and
key-length cases for SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 are produced
by `tools/generate_hash_vectors.py` using Python's standard library and
cross-checked against the `openssl dgst` CLI. Regenerate with
`make regenerate-vectors`.
