# NIST DSS validation vectors

The optional `tests/nist_dss.py` runner reads the original NIST CAVP archives
without adding them to the library or source distribution.

- ECDSA FIPS 186-4: [NIST digital-signature test vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures), file `186-4ecdsatestvectors.zip`, SHA-256 `fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752`.
- RSA FIPS 186-3: same NIST page, file `186-3rsatestvectors.zip`, SHA-256 `8405aeb3572a4f98ed4b1a3ccb3f2f49e725462dd28ec4759d6a15d88855d19c`.

Configure with `TINY_CRYPTO_TEST_ECDSA_DSS_ARCHIVE` and
`TINY_CRYPTO_TEST_RSA_DSS_ARCHIVE` pointing to these ZIP files, then run CTest
names beginning `test_nist_dss_`. The runner verifies each archive hash before
parsing and reports unsupported curve families and malformed hex separately.

Supported ECDSA records are P-192, P-256 and P-384. P-224, P-521 and binary
curves are skipped because the library does not implement them. RSA records
use supported 1024, 2048 and 3072-bit moduli. CAVP encodes public exponents
with leading zero padding; the test adapter passes their minimal magnitude
to the public API. CAVP's `SaltVal = 00` denotes an empty PSS salt in its
3072-bit zero-salt groups.

RSA KeyGen's recorded seeds target NIST's own prime-generation methods. The
library's generator uses a different candidate stream, so exact key output
cannot be compared from those seeds. Key material in KeyGen remains a candidate
for independent key-validation coverage.
