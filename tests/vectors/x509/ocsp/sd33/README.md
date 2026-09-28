<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# NIST SD 33 OCSP captures

These are unmodified DER responses from the OCSP URI in the PIV Authentication
and Card Authentication certificates captured in `nist_sd_33_vectors_v2`.
The v2 JSON contains card APDUs but no OCSP responses. Responses here were
fetched from `http://seclab7.ncsl.nist.gov` on 2026-09-28 at about 07:35 UTC,
without a nonce. The issuer certificates came from the HTTP CA Issuers URI in
each card certificate. Each issuer's responder returned the same response bytes
for both card certificates, so one response file covers both serial numbers.
These time-bound responses are historical test vectors; tests must evaluate
them at their captured `producedAt` and `thisUpdate` times.

| Physical SD 33 card | Corpus card | Issuer CA type | OCSP response SHA-256 |
| --- | --- | --- | --- |
| 2 | `card01` | RSA 3072 | `283b12d7617a05c40eab232b55294f2c9a9456da604b7ded9076f7cfd79cea91` |
| 3 | `card02` | RSA 4096 | `fce9b898fc46d2e87a4f92d7c755e1f53969035f0d891077b15456d458a79d31` |
| 4 | `card03` | ECC P-256 | `7ca4bf3e26e2b25577439e17d7812b9b46fe51dfe7ade86ed552032d81833fe4` |
| 5 | `card04` | ECC P-384 | `1439356c2c70818200c53365cc64eb451bda5b314a011d9c2b0309350b1fc832` |
| 16 | `card10` | PIV-I RSA 2048 | `3f27158df6638926ab1fddc63c6323923785b4843e783f49c5f5ee4bfa7e1e8c` |

The paired certificate files are `../../../piv/sd33/cardNN_{piv_auth,card_auth}_cert.der`.
`cardNN_issuer.der` is the issuer certificate from that card's CA Issuers URI.
OpenSSL `ocsp -respin ... -issuer ... -cert ... -CAfile <issuer> -partial_chain
-no_nonce` verified the response signature and returned `good` for each of the
ten card certificates at capture time. This pins the issuer as the trust point
for corpus verification.

`card01_request_sha1.der` and `card01_request_sha256.der` are deterministic
unsigned OCSP requests generated locally with OpenSSL from `card01`'s PIV
Authentication certificate and issuer. They are derived fixtures, not bytes
returned by the responder.
