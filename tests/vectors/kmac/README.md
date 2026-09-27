<!-- SPDX-FileCopyrightText: Mistial Dev -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# ACVP KMAC-256 fixed-output vector

`acvp_kmac256_aft.tsv` is the byte-aligned AFT case tgId 4, tcId 307 from
NIST's [ACVP-Server](https://github.com/usnistgov/ACVP-Server) sample files at
commit `b633d3fd5fabd375ef572f9b4feb38cd26932596`:

- `gen-val/json-files/KMAC-256-1.0/prompt.json`, SHA-256
  `747090e5e1ff53ed06dda578da79b667eca1e2394226b8bbca1488ab24c8a14e`
- `gen-val/json-files/KMAC-256-1.0/expectedResults.json`, SHA-256
  `d19fd5ba2ccaf393e16f34cf691c7ce544e3881a2eda2010329ca1ac97e8bf92`

The TSV columns are the original key, message, hex customization, expected
MAC, and test-case ID. Lengths are 4096, 64, and 256 bits for key, message,
and MAC. This is KMAC-256 fixed-output mode with a byte-aligned input and tag.
The public KMAC API operates on bytes and does not expose KMACXOF.
