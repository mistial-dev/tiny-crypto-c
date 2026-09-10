<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# EAC card verifiable certificates (BSI TR-03110)

Card verifiable certificates in the Extended Access Control format used by
ePassports, the German eID card and eIDAS tokens: `7F21 { 7F4E body, 5F37
signature }` with CAR, 7F49 public key, CHR, 7F4C certificate holder
authorization template, BCD dates and optional 65 extensions. These are
distinct from the PIV secure-messaging CVCs in `../piv/cvc/` (SP 800-73-4
Part 2 profile). Assembled 2026-09-06. The specification is in the Reference
Library as `2016_BSI_TR-03110-3_EAC_Common_Specifications_CV_Certificates_v2.21.pdf`.

| Directory | Files | What it is |
| --- | ---: | --- |
| `cvc/eid_testbeds/` | 27 | The eID-Server conformity testbed's CVC PKI, verbatim from <https://github.com/eID-Testbeds/server> (Apache-2.0, `LICENSE` included) |
| `cvc/generated/` | 170 | 86 CVCs made with secunet's BouncyCertGenerator across 23 algorithm/curve/role combinations, plus 27 public keys, a certificate description, 54 malformed variants, the configuration and `manifest.json` |

Every certificate's signature and issuer chain was checked independently with
`tools/verify_cvc.py` (pure Python ECDSA over the explicit domain parameters,
RSA PKCS#1 v1.5 and PSS); `manifest.json` records the result per file.

## `cvc/eid_testbeds/`

`certs/*.cvcert`: two CVCA hierarchies, all brainpoolP256r1 / id-TA-ECDSA-SHA-256,
authorization type AT (eID), generated 2016 by the same tool:

| File | Role | CHR | Issuer |
| --- | --- | --- | --- |
| `CERT_ECARD_CV_CVCA_1` | CVCA | DEESTCVCA100001 | self |
| `CERT_ECARD_CV_DV_1_A` | DV domestic | DEESTDV1A00001 | CVCA_1 |
| `CERT_ECARD_CV_TERM_1_{A,B,C,D}` | Terminal | DEESTTERM1x00001 | DV_1_A (with description + sector extensions) |
| `CERT_ECARD_CV_CVCA_2_{A,B,C}` | CVCA | DEESTCVCA2x00001 | self (three generations) |
| `CERT_ECARD_CV_LINK_2_A` | CVCA link | DEESTCVCA2B00001 | CVCA_2_A |
| `CERT_ECARD_CV_LINK_2_B` | CVCA link | DEESTCVCA2C00001 | CVCA_2_B |
| `CERT_ECARD_CV_DV_2_A` | DV domestic | DEESTDV2A00001 | CVCA_2_C |
| `CERT_ECARD_CV_TERM_2_A` | Terminal | DEESTTERM2A00001 | DV_2_A |

All 13 signatures verify. `public_keys/*.x509.cv` are the 7F49 public-key
templates (with domain parameters) for the CVCAs and the two terminal sector
keys; `descriptions/*.bin` are the CertificateDescription structures whose
SHA-256 the terminal certificates reference; `CVCertificates.xml` is the
generator configuration that produced them; `GOV_TERMINAL_CERT.hex` is an
additional terminal certificate issued by `DEDVtIDGVNK00005`, from the
testbed's unit tests, as hex text (its issuer is not in the set). Private keys were not copied.

The testbed's X.509 side (CSCA, document signers, master list, black lists,
TLS test certificates) is in `../x509/eid_testbeds/`.

## `cvc/generated/`

Produced by `tools/generate_cvc_vectors.py`, which writes an XML
configuration, runs
[eID-Testbeds/common-testbed-utilities](https://github.com/eID-Testbeds/common-testbed-utilities)
BouncyCertGenerator with reference date 2026-09-01, then derives the
`malformed/` set and `manifest.json`. That tool is not vendored: it has no
licence file, targets Java 8 / BouncyCastle 1.57 / JAXB, and needs one source
patch for the NIST curves (`(ECCurve.Fp)` cast in `CVPubKeyHolder.java` to
`ECCurve.AbstractFp`, and `getQ()` to `getField().getCharacteristic()`);
build notes are in the script's docstring. Rerunning makes new keys.

`config.xml` is the configuration used. Each chain is CVCA (self-signed, with
domain parameters, every authorization bit) -> DV_DOMESTIC -> TERMINAL (90-day
validity), named `<TAG>_cvca`, `<TAG>_dv`, `<TAG>_terminal`:

| Tag | Algorithm | Notes |
| --- | --- | --- |
| `BP256` | ECDSA-SHA-256 brainpoolP256r1 | German eID profile. Also: DV_FOREIGN + terminal with no rights, link certificate CVCA1 -> CVCA2 with a DV under CVCA2, expired DV, not-yet-valid terminal, one-day terminal, 2049-12-31 to 2050-01-01 terminal, profile identifier 1, id-IS OID with an AT bitmap; the main terminal carries a certificate description and a terminal sector extension |
| `BP256IS`, `P256IS` | ECDSA-SHA-256 | Inspection-system (IS) authorization: read ePass DG3/DG4 |
| `BP384ST` | ECDSA-SHA-256 brainpoolP384r1 | Signature-terminal (ST) authorization |
| `BP384`, `BP512`, `BP320`, `BP256T`, `BP512T` | ECDSA-SHA-256 | Brainpool r and twisted curves |
| `BP224` / `P224` | ECDSA-SHA-224 | |
| `BP192` / `P192`, `BP160` / `P160` | ECDSA-SHA-1 | legacy sizes |
| `P256`, `P384`, `P521`, `K256` | ECDSA-SHA-256 | NIST P-curves and secp256k1 |
| `RPSS256`, `RPSS1` | RSA-PSS SHA-256 (2048), SHA-1 (1536) | |
| `RV15256`, `RV151` | RSA PKCS#1 v1.5 SHA-256 (3072), SHA-1 (1024) | |
| `RE3`, `R512` | RSA e=3 (2048), RSA-512 | |

`public_keys/` holds the exported 7F49 templates for every CVCA and the
sector key; `descriptions/BP256_terminal.bin` is the CertificateDescription.

**Encoding defect worth knowing about.** BouncyCertGenerator emits ECDSA `r`,
`s` and point coordinates as minimal big-endian integers, so whenever a value
has a leading zero octet the field is one byte shorter than TR-03110 D.3.3
requires. `secp160r1` (161-bit order) always hits it; other curves hit it at
random. The frozen run has 5 such certificates (`P160_*`, `P521_cvca`,
`P521_dv`); they are kept as non-conforming samples, their manifest `expect`
is `parse-only`, and the `reason` says why. The testbed's own certificates do
not have the defect.

`manifest.json` fields: `file`, `kind` (`cvc`, `cvc-public-key`,
`certificate-description`), `expect` (`parse` = well formed and verifies,
`parse-only` = well formed but semantically or cryptographically bad,
`reject` = a strict parser must refuse it), `reason`, `verify` (the
`tools/verify_cvc.py` verdict), `sha256`, `size`.

### `malformed/`

Fifty-four variants derived from `certs/BP256_terminal.cvcert`: truncations,
trailing bytes, wrong/long/short/indefinite/non-minimal outer lengths, wrong
outer tag, missing or duplicated or reordered signature, flipped/short/empty/
all-zero/DER-encoded signature; missing or oversized profile identifier; CAR
too long/short/non-ASCII/lower-case; missing CHR, CHR equal to CAR; public key
missing/empty/OID-only/compressed point/wrong length/off-curve/unknown OID/RSA
OID with EC point/domain parameters in a terminal; authorization template
missing/empty/CVCA role under a DV/wrong bitmap length/RFU bits; dates
missing/5 octets/invalid BCD/month 13/expiry before effective; element order
violated; unknown element; duplicate CAR; empty extensions; unknown extension
OID; nested length mismatch; two certificates concatenated.
