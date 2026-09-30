<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Wycheproof test vectors

Source: [C2SP/wycheproof](https://github.com/C2SP/wycheproof) at commit
`3fa63dd0344abb611f1fb1d77e119938603ea230`, licensed under Apache-2.0
(`LICENSE`). The files were taken from the GitHub source archive for that
commit, whose SHA-256 was
`5dc00fae83575135c3147bfd4a04ee8889b1f0482ac6ca21aa486a8abccf2260`.

Only the vector data is kept: `testvectors_v1/`, the JSON `schemas/` that
describe it, the upstream `LICENSE`, and the upstream README as
`UPSTREAM_README.md`. The upstream tools, generators and CI files are left
out. Every file is unmodified, and `SHA256SUMS` lists its digest.

`tests/wycheproof.py` selects the documents for the enabled algorithms and
feeds them to the C readers. It covers ECDH, ECDSA, RSA PKCS #1 v1.5 and PSS
signatures, RSA signature generation, OAEP, primality, AES-GCM/CCM/GMAC/EAX
and SIV, AES-CMAC, AES-KW/KWP, HMAC and KMAC256. The runner reports per-document verdict
counts and the out-of-scope parameters it skips.

`tests/test_vector_manifests.py` checks the digests in `SHA256SUMS`.
