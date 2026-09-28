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
