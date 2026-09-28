<!-- SPDX-FileCopyrightText: Mistial Dev -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# KMAC-256 fixed-output vectors

The first row of `acvp_kmac256_aft.tsv` is the byte-aligned AFT case tgId 4,
tcId 307 from
NIST's [ACVP-Server](https://github.com/usnistgov/ACVP-Server) sample files at
commit `b633d3fd5fabd375ef572f9b4feb38cd26932596`:

- `gen-val/json-files/KMAC-256-1.0/prompt.json`, SHA-256
  `747090e5e1ff53ed06dda578da79b667eca1e2394226b8bbca1488ab24c8a14e`
- `gen-val/json-files/KMAC-256-1.0/expectedResults.json`, SHA-256
  `d19fd5ba2ccaf393e16f34cf691c7ce544e3881a2eda2010329ca1ac97e8bf92`

The NIST row has 4096-bit key, 64-bit message, and 256-bit MAC. This pinned
sample contains one fixed-output AFT case whose key, message, and MAC lengths
are all byte-aligned. The remaining NIST cases use bit-level inputs or output,
or KMACXOF. The public KMAC API operates on bytes and does not expose KMACXOF.

The other six rows are independent answers from OpenSSL 3.6.3 `KMAC256`, using
`openssl mac -macopt hexkey:<key> -macopt hexcustom:<custom> -macopt size:<bytes>
KMAC256` with the message on stdin. They cover empty and nonempty customization,
empty and multi-block messages, and 33-, 35-, 47-, 49-, 63-, and 65-byte MACs.
The TSV columns are key, message, customization, expected MAC, and case ID;
binary values are hex, and `-` represents an empty value.

## Checksums

`SHA256SUMS` lists the SHA-256 of every file here, and
`tests/test_vector_manifests.py` checks them.
