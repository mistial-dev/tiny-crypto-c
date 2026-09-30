<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# AES key wrap test vectors

## NIST CAVP KWVS

These files are the AES entries from the NIST CAVP key wrap test vector
archive
([`kwtestvectors.zip`](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/kwtestvectors.zip),
SHA-256
`04a4a82e4de65bca505125295003f9c75a5a815afda046dc83661b8b580dfdf3`),
unchanged. NIST publishes them as a work of the United States government.
The KW files come from CAVS 17.4 (generated 2014-12-03) and the KWP files from
CAVS 21.4 (generated 2018-04-06).

| File | Records | FAIL records |
| --- | ---: | ---: |
| `KW_AE_128.txt`, `KW_AE_192.txt`, `KW_AE_256.txt` | 500 each | 0 |
| `KW_AD_128.txt`, `KW_AD_192.txt`, `KW_AD_256.txt` | 500 each | 100 each |
| `KWP_AE_128.txt`, `KWP_AE_192.txt`, `KWP_AE_256.txt` | 500 each | 0 |
| `KWP_AD_128.txt`, `KWP_AD_192.txt`, `KWP_AD_256.txt` | 500 each | 100 each |

Each file holds five plaintext lengths with 100 records per length. KW uses
128, 192, 256, 320 and 4096-bit key data. KWP uses 8, 64, 72, 248 and
4096-bit key data. AE records give the KEK, the key data and the wrapped
result. AD records give the KEK and the wrapped input, with the key data or a
bare `FAIL`.

The archive also holds the `*_inv.txt` files, which designate the AES inverse
cipher as the wrapping function, and the TDEA `TKW_*` files. The library
implements the forward-cipher designation of RFC 3394 and RFC 5649 and has no
TKW, so those files stay out of this directory.

`test_kw` in `tests/aes/kw_test.c` runs the files in full runs
(`TINY_CRYPTO_TEST_FULL=ON`, which sets `TC_AES_CAVP`). Each AES key-size
library runs the files for its KEK size.

## Checksums

`SHA256SUMS` lists the SHA-256 of every file here, and
`tests/test_vector_manifests.py` checks them.
