<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Locally generated OCSP responses

These fixtures were generated on 2026-09-29 with OpenSSL 1.1.1s from a
throwaway P-256 CA. The keys were discarded after generation, and no private
key is included here.

* `ca.der`: `CN=tiny-crypto-c OCSP Test CA`, a self-signed CA with keyCertSign
  and cRLSign.
* `target.der`: `CN=tiny-crypto-c OCSP Test Target`, serial `1234`, issued by
  the CA.
* `revoked_key_compromise.der`: signed by the CA itself (byName ResponderID),
  SHA-1 CertID, status `revoked` with revocationTime `20260901000000Z` and
  revocationReason `keyCompromise` (1), thisUpdate `20260929101336Z`,
  nextUpdate seven days later, no nonce.
* `good_no_next_update.der`: signed by the CA itself (byKey ResponderID),
  status `good`, thisUpdate `20260929101336Z`, no nextUpdate and no nonce.

The responses were produced with `openssl ocsp -index -rsigner -rkey -CA
-issuer -cert -respout -resp_no_certs -no_nonce`, with `-ndays 7` for the
revoked response and `-resp_key_id` for the good one. Tests evaluate a fixed
time inside the captured range.
