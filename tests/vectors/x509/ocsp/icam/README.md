<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Derived GSA ICAM OCSP responses

These responses were generated locally on 2026-09-28 with OpenSSL from the
published GSA ICAM test responder key and certificates in
`gsa-icam-card-builder`. They are **derived fixtures**, not saved responses
from the GSA responder. No private key is included here.

All three responses cover the vendored
`../../icam/ca/signers/ICAM_Test_Card_PIV_Content_Signer_-_gold_gen3.crt`.
The issuer is `ICAM_Test_Card_PIV_Signing_CA_-_gold_gen3.crt`, and the
delegated signer is `ICAM_Test_Card_PIV_OCSP_Valid_Signer_gen3.crt`, both in
the same signer directory. Their signatures verify with OpenSSL `ocsp` using
the issuer certificate as a pinned trust point (`-partial_chain`).
`issuer.der` and `target.der` are DER conversions of the matching vendored PEM
certificates, for the C test harness.

The temporary OpenSSL index contained one serial, `600000000000000000CA`:

* `content_signer_good.der`: a `V` record, expiry `321230235959Z`.
* `content_signer_revoked.der`: an `R` record, expiry `321230235959Z`,
  revocation time `240101000000Z`.
* `content_signer_unknown.der`: an empty index.

OpenSSL generated the responses with `-index`, `-rsigner`, `-rkey`, `-CA`,
`-issuer`, `-cert`, `-respout`, and `-ndays 2`. Tests evaluate the captured
time range rather than the current wall clock.

## Delegated responder revocation cases

These fixtures were generated locally on 2026-09-29 with OpenSSL from the
published keys in `gsa-icam-card-builder/cards/ICAM_Card_Objects/ICAM_CA_and_Signer`.
They cover ICAM test cards 43 (`43_OCSP_revoked_w_nocheck`) and 44
(`44_OCSP_revoked_wo_nocheck`). The issuer is `issuer.der`, the ICAM Test Card
Signing CA. Every response reports `good` for its card, uses a SHA-1 CertID,
carries no nonce and was generated with `-ndays 2`.

* `card43_piv_auth_cert.der` and `card44_piv_auth_cert.der`: the PIV
  Authentication certificates of cards 43 and 44, serials
  `600000000000000000F7` and `600000000000000000FB`.
* `card43_delegate_nocheck.der`: signed by
  `ICAM_Test_Card_PIV_OCSP_Revoked_Signer_No_Check_Present_gen3`, which carries
  `id-pkix-ocsp-nocheck`. The signer certificate is embedded.
* `card44_delegate.der`: signed by
  `ICAM_Test_Card_PIV_OCSP_Revoked_Signer_No_Check_Not_Present_gen3`, which has
  no `id-pkix-ocsp-nocheck`. The signer certificate is embedded.
* `card44_delegate_no_certs.der`: the same signer with `-resp_no_certs`.
  `card44_delegate_signer.der` is that signer certificate in DER, supplied
  through a certificate store.
* `card43_issuer_by_key.der`: signed by the issuing CA itself with a byKey
  ResponderID (`-resp_key_id -resp_no_certs`).

OpenSSL `ocsp -respin ... -issuer issuer -cert card -CAfile issuer
-partial_chain -no_nonce` verified each response and returned `good`.
