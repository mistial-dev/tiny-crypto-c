<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# NIST SD 33 issuing-CA CRLs

Unmodified DER CRLs of the three issuing CAs of the NIST Special Database 33
test PIV cards, fetched from `http://smime2.nist.gov/PIVTest2/` on
2026-09-29. The CRL Distribution Points of the SD 33 card certificates name
these files. Each CRL verifies with the issuer certificate of the same CA in
`../../ocsp/sd33/`.

| File | Issuer | Verifies with | thisUpdate | nextUpdate | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `RSA3072IssuingCA.crl` | Test RSA 3072-bit CA for Test PIV Cards v2 | `card01_issuer.der` | 2026-09-29 17:02:03Z | 2026-10-01 17:02:03Z | `07ab9910e0751a4c05602fdebba526f0d6f743127ec36b2fba37d4ede3ef761f` |
| `ECCP256IssuingCA.crl` | Test ECC P-256 CA for Test PIV Cards v2 | `card03_issuer.der` | 2026-09-29 17:02:05Z | 2026-10-01 17:02:05Z | `be2ce400f916dea9862bbf67e12e8ddb9dd900631c3f17598eeefd98985b9b76` |
| `ECCP384IssuingCA.crl` | Test ECC P-384 CA for Test PIV Cards v2 | `card04_issuer.der` | 2026-09-29 17:02:06Z | 2026-10-01 17:02:06Z | `13c71b0e88ee583781521ce751e02198641d5b406aaa570973ded4b07e418ae2` |

SD 33 card 2 uses the RSA 3072 CA for its card certificates and CHUID signer
and the ECC P-384 CA for its secure messaging Certificate Signer. Card 4 uses
the ECC P-256 CA for all three. The ECC P-256 CRL lists four revoked serial
numbers. The other two list none.

The CRLs are time bound. Tests evaluate them at 2026-09-29T18:00:00Z, which
lies inside every CRL window and inside the OCSP window of
`../../ocsp/sd33/` (producedAt 2026-09-28 05:02Z to nextUpdate 2026-09-30
05:02Z). After 2026-10-01 a live check against these files finds no current
CRL, which `TC_VALIDATION_REVOCATION_REQUIRED` reports as unavailable
evidence.
