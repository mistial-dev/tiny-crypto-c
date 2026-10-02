<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# NIST CAVP DRBG vectors

Source: `drbgtestvectors.zip` from the NIST CAVP
[random number generator page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators),
for SP 800-90A Rev. 1 (DRBGVS, updated 2015-10-29). The response files are
CAVS files generated in April 2013 with CRLF line endings.

| Archive | SHA-256 |
| --- | --- |
| `drbgtestvectors.zip` | `5f7e5658ebd5b4e6785a7b12fa32333511d2acc2f2d9c5ae1ffa16b699377769` |
| `drbgvectors_pr_true.zip` | `ed9b04480392ea56413cc9753a4732314e7ad745c16b9dd5d77de1560c6e0cc2` |
| `drbgvectors_pr_false.zip` | `73f9965ca0675bc74673aaba0733283a9874f74db1fd4c15bb707a8ab446d32c` |
| `drbgvectors_no_reseed.zip` | `8f9644adc655dd651c90b73190175b1d99164dc5a4861edab16e39862ead27ad` |

Each inner archive is unpacked into its own directory under `cavp/`:
`pr_true/` (prediction resistance enabled), `pr_false/` (prediction
resistance disabled, reseed supported) and `no_reseed/` (neither). Every
directory keeps `Hash_DRBG.rsp`, `HMAC_DRBG.rsp`, `CTR_DRBG.rsp` and the NIST
`Readme.txt` unmodified. The intermediate-value `.txt` files are omitted.
`SHA256SUMS` lists every file, and `tests/test_vector_manifests.py` checks
them.

Each option has 16 parameter groups of 15 trials, 240 trials per option.
`tests/drbg/cavp.c` runs the DRBGVS procedure for each directory and checks
the returned bits of the second generate call:

| File | Options run | Trials run per directory | Options skipped |
| --- | --- | ---: | --- |
| `Hash_DRBG.rsp` | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 | 1,200 | SHA-512/224, SHA-512/256 |
| `HMAC_DRBG.rsp` | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 | 1,200 | SHA-512/224, SHA-512/256 |
| `CTR_DRBG.rsp` | AES-128, AES-192, AES-256, each with and without df | 1,440 | 3KeyTDEA with and without df |

The library implements neither SHA-512/t, and SP 800-90A Rev. 1 removed TDEA
from CTR_DRBG. The runner counts those trials as skipped and asserts both
counts, 11,520 trials run in total. A replay entropy source serves each
recorded entropy input once and checks that the DRBG requests exactly the
recorded length, which also checks the default entropy lengths.
