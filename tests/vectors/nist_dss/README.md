# NIST DSS validation vectors

`tests/nist_dss.py` reads the original NIST CAVP archives kept in this test
directory. They are test data and are not linked into the library.

- ECDSA FIPS 186-4: [NIST digital-signature test vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures), file `186-4ecdsatestvectors.zip`, SHA-256 `fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752`.
- RSA FIPS 186-3: same NIST page, file `186-3rsatestvectors.zip`, SHA-256 `8405aeb3572a4f98ed4b1a3ccb3f2f49e725462dd28ec4759d6a15d88855d19c`.

CTest uses the checked-in archives by default. Set
`TINY_CRYPTO_TEST_ECDSA_DSS_ARCHIVE` or `TINY_CRYPTO_TEST_RSA_DSS_ARCHIVE` to
override their paths. The runner verifies each archive hash before parsing and
reports unsupported curve families and malformed hex separately.

Supported ECDSA records are P-192, P-256 and P-384. P-224, P-521 and binary
curves are skipped because the library does not implement them. RSA records
use supported 1024, 2048 and 3072-bit moduli. CAVP encodes public exponents
with leading zero padding; the test adapter passes their minimal magnitude
to the public API. CAVP's `SaltVal = 00` denotes an empty PSS salt in its
3072-bit zero-salt groups.

RSA KeyGen's recorded seeds target the CAVP `ProvRP`, conditioned-prime and
probable-prime methods. The library's generator samples its own random
candidates, so these tests validate the recorded private keys through the
public API rather than claim seed-to-key replay. The default test validates
two keys from each of the 14 supported size and generation-method groups:
one with CAVP's fixed public exponent and one with a varying exponent. It
reports the remaining 2,172 records as sampled out. The exhaustive mode
validates all 2,200 keys;
run `tests/nist_dss.py --rsa-archive tests/vectors/nist_dss/186-3rsatestvectors.zip
--rsa-keygen-reader BUILD/test_rsa_keygen_reader --rsa-keygen-all`. It can take
hours because each key receives full primality and private-key validation.
