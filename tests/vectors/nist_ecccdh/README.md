<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# NIST ECC CDH primitive vectors

Source: the ECCCDH Primitive Test Vectors archive on the
[CAVP component-testing page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/component-testing)
(CAVS 14.1, generated 2012-11-19, SP 800-56A section 5.7.1.2). The archive's
SHA-256 was `5fff092551f2d72e89a3d9362711878708f9a14b502f0dfae819649105b0ea39`.
Its only member, `KAS_ECC_CDH_PrimitiveTest.txt`, is kept unmodified, and
`SHA256SUMS` lists its digest.

The file has 25 trials for each of 15 curves. `tests/ec/oracle.py --cavp-dir`
checks the 50 P-256 and P-384 trials against every EC test build and fails
when that count changes. The remaining prime, Koblitz and binary curves are
outside the library's ECDH support.

`tests/test_vector_manifests.py` checks the digest in `SHA256SUMS`.
