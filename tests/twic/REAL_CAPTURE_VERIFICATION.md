<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Private TWIC capture verification

`capture_pcsc.py` records a physical card through macOS PC/SC. It creates an
owner-only directory and writes transcripts and objects with mode `0600`.
Use the reader name shown by PC/SC, or a unique substring. On the ACR1552,
select its **PICC** reader; the separate SAM interface is not the card reader:

```sh
python3 tests/twic/capture_pcsc.py inventory --profile nexgen \
  --interface contact --reader '<reader name>' --output /tmp/<private-capture-directory>/nexgen-contact
python3 tests/twic/capture_pcsc.py card-proof --profile nexgen \
  --interface contact --reader '<reader name>' --output /tmp/<private-capture-directory>/nexgen-contact
python3 tests/twic/capture_pcsc.py pin --profile nexgen \
  --interface contact --reader '<reader name>' --output /tmp/<private-capture-directory>/nexgen-contact
```

Run `inventory` for Legacy/NEXGEN and contact/contactless as available. The
`pin` phase is contact-only, prompts without echo, checks retry status, and
submits at most one eight-digit PIN. Its APDU transcript redacts the PIN body.
Each phase uses a distinct output file and refuses to overwrite one. The
card-proof phase uses a fresh challenge and records the response for offline
verification.

`verify_real_capture.py` checks the private directory in place and prints
only pass/fail counts and labels. Keep that directory outside the repository
with owner-only permissions.

```sh
python3 tests/twic/verify_real_capture.py /tmp/<private-capture-directory>
```

The tool requires Python `cryptography`, Pillow, and OpenSSL. It checks contact APDU
framing, status/chaining, and reconstruction of every saved object; the CHUID,
certificate OIDs and EKU, and detached CMS signatures; TPK AES-128-ECB with
PKCS#7 padding; fingerprint and face CBEFF records and their CMS signatures;
and every TWIC Security Object LDS map entry and digest. If captured, it also
checks the fresh card-key challenge, the redacted PIN session, the shared
fingerprint (and NEXGEN face) across PIV/TWIC, and each PIV Security Object
signature and five LDS hashes. The Legacy PIV-only face and printed object
are also checked.
The face JPEG is decoded and its dimensions are checked against the FAC record.
When contactless captures are present, it checks every APDU and compares
readable objects with the matching contact capture. It checks the Legacy
`6A81` and NEXGEN `6982` access denials separately. Both RF captures contain
fresh card-key challenges bound to their saved CHUIDs.

If local `content-issuer-0.bin` and `card-issuer-0.bin` PKCS#7 bundles are
present in each capture directory, the tool checks issuer signatures, CA
constraints, key usage, path length, and dates. It reports incomplete or
expired chains without treating them as trusted. An alternate local bundle
root can be supplied with `--issuer-bundle-dir`; the tool never fetches AIA
URLs.

Certificate dates and anchored paths are evaluated at a fixed time, by default
2026-09-27T12:00:00Z. That instant is a synthetic evaluation time inside the
certificates' validity, since the capture date is not recorded. `--at`
selects another instant as `YYYY-MM-DDTHH:MM:SSZ`, and the anchored OpenSSL
check receives it as `-attime`.

To validate both paths to an explicitly selected trust anchor, provide a PEM
file containing the trusted root certificates:

```sh
python3 tests/twic/verify_real_capture.py /tmp/<private-capture-directory> \
  --trust-anchors /tmp/<private-trust-anchors.pem> --require-current-trust
```

The supplied anchor must match the chain terminus. An anchored path is checked
with OpenSSL. This does not establish revocation status. The Legacy signer in
the current private capture is expired, and its matching issuer is absent from
the local bundle. The NEXGEN chains have valid signatures and dates, with
trust pending an explicit anchor.

The original Legacy card-key and PIN follow-up sessions were captured while
the NEXGEN card was inserted. Their signatures verify with the NEXGEN card
certificate, and their PIN-gated objects match NEXGEN byte-for-byte. Those
misattributed traces are quarantined outside the corpus directories. The
repeat Legacy and NEXGEN contact card-key and PIN sessions, and both
contactless card-key sessions, pass with same-session identity binding. The capture tool
reads PIV CHUID in the same transaction before PIN submission or a card-key
challenge and requires an exact match with the inventory CHUID.

To check a proposed synthetic corpus against the real captures, add
`--synthetic-root tests/vectors/twic/synthetic`. This compares AIDs, object
presence, TLV shape, signer/card OIDs and EKUs, Security Object mappings, and
the encryption and hash choices. It rejects exact reuse of real identifiers,
keys, certificate public keys and signatures, hashes, encrypted objects, and
biometric payload windows in synthetic binaries and APDU text.

A missing active card proof or PIN session is reported as `not captured`. A
failed check exits nonzero and names only the failed invariant; it never prints
captured identifiers, keys, image bytes, or APDUs. The private capture files
are **not automatically deleted**. Review and remove them manually when no
longer needed.
