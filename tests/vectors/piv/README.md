<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# PIV data object and CVC corpus

Raw PIV card data objects (SP 800-73-4 Part 1) and Card Verifiable
Certificates (SP 800-73-4 Part 2, tag `7F21`) to go with the X.509 material in
`../x509/`. Everything is a byte-exact copy of what the source project holds
or what a card returned; nothing here was generated. Assembled 2026-09-06.

| Directory | Files | Source |
| --- | --- | --- |
| `icam_cards/` | 387 | GSA ICAM test cards 1-59 (`gsa-icam-card-builder/cards/ICAM_Card_Objects`), CC0 |
| `sd33/` | 95 | Objects read over VCI from NIST Special Database 33 cards (PIV Subcommittee `sm_vci_vectors`) |
| `cvc/` | 20 | 10 distinct secure-messaging CVCs from the SD 33 cards, with parsed-field JSON |
| `vci_trust_anchors/` | 27 | SM Certificate Signer objects, intermediate CVCs and VCI trust-anchor records for cards 2, 3, 4, 5, 16 |
| `piv_auto_demo/` | 7 | PIV Auto simulator payloads (CVCs, SMCS, trust anchor record, PIV status/mode payloads) |

## `icam_cards/<NN_card_name>/`

One directory per ICAM test card, gen 1-2 (cards 1-24) and gen 3 (25-59).
File names are the upstream `"N - Object"` names with `_` for `" - "` and
spaces, plus a `.bin` suffix. The files are the container *contents* as the
card builder writes them, without the outer `53 L` BER-TLV wrapper that a
card returns from GET DATA (the builder README says the same):

| File | SP 800-73-4 object | First tag |
| --- | --- | --- |
| `1_Discovery_Object.bin` | Discovery Object `7E` | `7E` |
| `2_Security_Object.bin` | Security Object `5FC106` | `BA` (mapping), then `BB` (SignedData) |
| `7_CCC.bin` | Card Capability Container `5FC107` | `F0` |
| `8_CHUID_Object.bin` | CHUID `5FC102` | `30` (FASC-N) |
| `9_Fingerprints.bin` | Cardholder Fingerprints `5FC103` | `BC` (CBEFF) |
| `10_Face_Object.bin` | Facial Image `5FC108` | `BC` (CBEFF) |
| `11_Printed_Information.bin` | Printed Information `5FC109` | `01` |
| `13_Key_History_Object.bin` | Key History `5FC10C` (card 37 only) | `C1` |

Interesting cards for a parser: `04_Tampered_CHUID`, `08_Tampered_Security_Object`,
`14_Expired_CHUID`, `15_CHUID_FASCN_mismatch`, `19_CHUID_UUID_mismatch`,
`25_Disco_Object_Not_Present` .. `28_*` (Discovery Object PIN-policy variants),
`48_T=0_with_Non-Zero_PPS_LEN_Value/1_Discovery_Object_No_Tag.bin` (Discovery
Object without its `7E` tag), `38_Bad_Hash_in_Sec_Object`,
`49`-`52` (CBEFF expiry cases), `55_FIPS_201-2_Missing_Security_Object`
(no Security Object file at all), `07_Tampered_Fingerprints` and
`06_Tampered_PHOTO` (each with an `_Untampered` sibling). Card 46 appears in
three variants (`ICI_8`, `ICI_9` issuer-identifier variants). The matching
certificates are in `../x509/icam/cards/`.

## `sd33/cardNN/`

Objects captured from physical NIST SD 33 cards (ID-One PIV 2.4) during the
PIV Subcommittee VCI test-vector work. These *do* include the outer `53`
wrapper, so they are exactly what GET DATA returned. Per card:

* `piv_auth_cert_5FC105.bin`, `card_auth_cert_5FC101.bin`: certificate
  objects whose `70` element is gzip-compressed DER (`71 01 01`). The
  decompressed certificates are in `../x509/piv/sd33/`.
* `chuid_5FC102.bin`, `security_object_5FC106.bin`, `facial_image_5FC108.bin`,
  `printed_information_5FC109.bin`, `key_history_5FC10C.bin`.
* `*_contactless.bin` where the contactless capture differed from the contact
  one. Empty responses (facial image and printed information over
  contactless on several cards) were dropped.

`card01`..`card10` are the vector labels, not SD 33 card numbers; the CVC
JSON files in `cvc/` carry the card identifiers. Nine of the ten vector cards
are distinct physical cards (card09 and card10 are the same card).

## `cvc/`

`sd33_cardNN_sm_cvc_7f21.bin` is the Secure Messaging CVC (`7F21`) returned in
the card's OPACITY GENERAL AUTHENTICATE response; the JSON beside it has the
fields the capture tool parsed (profile, IIN, GUID, public key OID and point,
role, signature). CVC bodies are ECC P-256 or P-384 (cipher suites CS2/CS7).
Duplicates across the contact, contactless and "inspect" captures were
removed; `vci-vectors-card05_sm_cvc_7f21.bin` is the one CVC only present in
the `osdp-piv-latex` corpus.

## `vci_trust_anchors/card-N-{direct,intermediate}/`

The material needed to validate a card's CVC (SP 800-73-4 §4.1.5 / FIPS 201-3
VCI): `secure-messaging-cvc-7f21.bin` (card CVC), `intermediate-cvc-7f21.bin`
(where the card CVC chains through an intermediate CVC), `smcs-5fc122.bin`
(Secure Messaging Certificate Signer data object), `content-signing-
certificate.der` (X.509), `vci-trust-anchor-record.bin` (the PD trust-anchor
record format of the OSDP-PIV draft) and `validation-report.json`.

## `piv_auto_demo/`

Deterministic simulator outputs from the PIV Subcommittee `osdp-piv-latex`
repository: `secure-card-cvc-7f21.bin`, `intermediate-cvc-7f21.bin`,
`smcs-5fc122.bin`, `loaded-intermediate-ca-trust-anchor.bin` (imported from
the card-16 capture) and the OSDP `pivmode`, `pivstatusr`, `pivvciloadta`
payloads.

## Related

The PIV CVC profile here is the SP 800-73-4 Part 2 one. EAC (BSI TR-03110)
card verifiable certificates, both the eID-Server testbed set and a generated
multi-algorithm set with malformed variants, are in `../eac/`.
