<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# PIV card commands

Enable `TINY_CRYPTO_ENABLE_PIV_COMMAND=ON` and include
`<tiny_crypto/piv_command.h>`. The module sends the PIV and TWIC card commands
of SP 800-73-5 Part 2 and TWIC Part 2 v5 section 5 over the
[APDU channel](apdu.md): SELECT, GET DATA and VERIFY. It checks the answers,
tracks the link state that access rules depend on and gives status words their
PIV or TWIC meaning. It needs the APDU codec and the TLV readers, allocates
nothing and owns no I/O, reader selection or PIN entry.

## Link

A `TC_PIV_link` is one card session over a transport. `TC_PIV_link_init` takes
`TC_PIV_link_options`:

- `channel`: the APDU channel options. The exchange budget covers every
  command of the session, including GET RESPONSE steps. The card limits may
  start at 0, since `TC_PIV_select` applies the limits the card reports.
- `interface`: `TC_PIV_CONTACT` or `TC_PIV_CONTACTLESS`. The application states
  it, because the PIN rules depend on it.
- `response_ne`: Ne for GET DATA. 0 selects 256, the Le `00` of Part 2 section
  3.1.2. An EXTENDED link may request up to 65536.

The command scratch buffer holds one encoded command and is wiped after every
transmit, since VERIFY carries PIN digits. SHORT links need
`TC_APDU_SHORT_COMMAND_MAX_BYTES` (261) bytes. EXTENDED links need
`TC_APDU_EXTENDED_COMMAND_BYTES(TC_PIV_COMMAND_MAX_NC)`, or the card limit when
smaller.

`TC_PIV_link_info_get` reports the interface, the selected application and
profile, the secure messaging suite the application announced, and whether the
link is secured, has lost its secure messaging session, has the VCI, or has a
verified PIN. `TC_PIV_link_status` returns the status word of the last command
the card completed. `TC_PIV_link_clear` wipes the scratch and the link. Call it
on every exit path.

Every function returns a `TC_PIV_result`. The first six values follow
`TC_APDU_result`. `TC_PIV_CARD_STATUS` means the card completed the command with
a status other than success, and `TC_PIV_link_status` holds that status.
`TC_PIV_REFUSED` means a safety or state rule stopped the command before it was
sent. A transport failure stops the link, and every later command returns
`TC_PIV_ERROR` until `TC_PIV_link_init`.

## SELECT and the application property template

`TC_PIV_select` selects the PIV application by its complete AID or the TWIC
application by its 9-byte AID prefix (TWIC Part 2 v5 section 5.1, TWIC Part 3
v4 Appendix D.3), with Le `00`. SELECT is always plain (Part 2 section 4.2).
`TC_PIV_application_read` checks the answer, and `TC_PIV_select` uses it:

- The data field starts with one `61` template. DO `7F66` may follow it once
  with two positive `02` integers, the card's largest command and response
  APDUs (ISO/IEC 7816-4 section 12.8.1). Other top-level DOs are skipped.
- Inside `61`: one `4F` with the expected AID prefix and two version bytes, one
  `79` holding a nonempty `4F`, and at most one `50`, `5F50` and `AC` (Part 2
  Tables 3 and 4).
- In `AC` each `80` holds one algorithm identifier, `06 01 00` appears exactly
  once, and at most one of the secure messaging suites `27` and `2E` is listed
  (Part 2 Table 5). The suite is returned in `sm_suite`.
- PIV version `01 00` is `TC_PIV_CARD`. TWIC version `01 01` is
  `TC_TWIC_LEGACY_CARD` and `01 03` is `TC_TWIC_NEXGEN_CARD` (TWIC Part 2 v5
  section 4.1). TWIC Part 3 v4 Appendix D.3 states that any sub-version of
  version `01` is backward compatible with the Legacy data model and leaves the
  decision to the reader. Pass `TC_PIV_SELECT_TWIC_SUBVERSION_COMPATIBLE` to
  accept another sub-version as Legacy. Without the flag it is
  `TC_PIV_UNSUPPORTED`.

Selecting another application sets the card's security statuses to FALSE,
and reselecting the PIV application keeps them (Part 2 section 3.1.1). The link
clears its VCI and PIN status on every SELECT, so query the PIN again with
`TC_PIV_verify_status` when the application needs it. Selecting another
application also ends a bound secure messaging session, and reselecting the
PIV application keeps it. After a successful SELECT
the link records the application and profile. It applies the `7F66` limits to the channel
and sets the GET RESPONSE flags. The PIV application uses a plain CLA `00`
(Part 2 sections 4.2.6 and A.4.1). The TWIC application also requests `FF`
after `61 00` (TWIC Part 2 v5 section 5.2 note 3a, Appendix E). A failed SELECT
leaves no application selected, so select again before the next command.

## GET DATA

`TC_PIV_get_data` reads one data object by a tag of 1 to 3 bytes (Part 2
section 3.1.2). The answer to `9000` or `6282` must be exactly one TLV that
spans the data field. `out->encoded` is that TLV and `out->value` its value,
both borrowed from the response buffer. `out->status` records `6282`, the end
of the object before Le bytes (ISO/IEC 7816-4 Table 7).

| Answer                      | PIV application                     | TWIC application   |
| --------------------------- | ----------------------------------- | ------------------ |
| `53 L value`                | object, `TC_PIV_FORM_CONTAINER`     | same               |
| `53 00`                     | empty object (Part 1 section 4.1.1) | same               |
| `TAG L value`               | `7E` and `7F61` only                | any tag            |
| `TAG 00`                    | invalid                             | empty object       |
| `TAG 02 80 00`, constructed | invalid                             | empty object       |
| `9000` without data         | invalid                             | `TC_PIV_FORM_NONE` |

The TWIC rows come from TWIC Part 2 v5 sections 3.3.6 and 4.5. Another status
returns `TC_PIV_CARD_STATUS`, such as `6982` before the PIN, `6A81` for a
contactless denial or `6A82` for a missing object.

## VERIFY

`TC_PIV_verify_status` sends VERIFY without data (Part 2 section 3.2.1) for the
PIV PIN `80`, the Global PIN `00` or the pairing code `98`. `9000` reports the
reference verified. `63CX` reports X further tries. The pairing code has no
counter (Part 2 footnote 7), so `6300` reports neither. The link keeps one PIN
flag for `80` and `00`. `9000` sets it, and any other answer for either
reference clears it, since that reference is then FALSE on the card (Part 2
section 3.2.1.1).

`TC_PIV_pin_verify` verifies the PIN or Global PIN once:

1. It queries the counter. A verified reference returns `TC_PIV_OK` with
   `submitted` 0.
1. It sends the PIN only when the query reported at least `minimum_retries`
   tries. The floor is at least 2, so the last tries stay unspent. A lower count
   or an answer without a count returns `TC_PIV_REFUSED`.
1. The PIN is 6 to 8 ASCII digits, padded with `FF` to 8 bytes (Part 2 section
   2.4.3). The padded copy lives in a stack array and the command scratch, and
   both are wiped. A failed submission returns `TC_PIV_CARD_STATUS` with `63CX`,
   `6983` or `6A80` and is never retried.

The card rejects VERIFY for `80` and `00` outside the contact interface and the
VCI, and `98` on contactless without secure messaging (Part 2 section 3.2.1).
The library refuses those commands before sending, so a PIN never crosses the
contactless interface in plaintext (Part 1 Table 4). The VCI requires a
secured link, and a secured link sends GET DATA and VERIFY under
[secure messaging](piv-sm.md#secure-messaging-on-a-card-link). On contactless the card may
answer `6983` at an issuer-defined intermediate retry value. The TWIC
application defines no VERIFY, so both functions return `TC_PIV_UNSUPPORTED`
there.

## Status words

`TC_PIV_status_classify(sw, command, application, &retries)` maps a status word
to a `TC_PIV_status` by Part 1 section 5.6 Table 7. `6A88` means a missing key
or data reference, except on TWIC GET DATA, where it reports a missing object
(TWIC Part 2 v5 section 5.2). `63CX` on VERIFY writes X to `retries`.

## Card object readers

`TINY_CRYPTO_ENABLE_PIV_OBJECTS` adds readers for the objects that drive the
card session. Pass them the `encoded` span of a `TC_PIV_data_object`. They check
one complete object against its table, return views borrowed from the input,
charge no work and write their output only on `TC_TLV_OK`.

| Object                    | Tag      | Header                             | Reader                      |
| ------------------------- | -------- | ---------------------------------- | --------------------------- |
| Discovery Object          | `7E`     | `<tiny_crypto/piv_discovery.h>`    | `TC_PIV_discovery_read`     |
| Card Capability Container | `5FC107` | `<tiny_crypto/piv_card_objects.h>` | `TC_PIV_CCC_read`           |
| Key History               | `5FC10C` | `<tiny_crypto/piv_card_objects.h>` | `TC_PIV_key_history_read`   |
| BIT group template        | `7F61`   | `<tiny_crypto/piv_card_objects.h>` | `TC_PIV_bit_group_read`     |
| Pairing Code container    | `5FC123` | `<tiny_crypto/piv_card_objects.h>` | `TC_PIV_pairing_code_read`  |
| Certificate containers    | `5FC1xx` | `<tiny_crypto/piv_certificate.h>`  | `TC_PIV_certificate_decode` |

- Discovery (Part 1 section 3.3.2 and Table 1) must be exactly
  `7E 12 {4F 0B AID} {5F2F 02 xx yy}`. `TC_PIV_DISCOVERY_PIV` requires the PIV
  AID and a Table 1 policy. `TC_PIV_DISCOVERY_TWIC` reads a TWIC card, where
  the PIV application reports `40 00` or `04 00` and the TWIC application
  `00 00` under a TWIC AID (TWIC Part 2 v5 sections 4.2 and 4.7.5).
  `TC_PIV_discovery_pin_reference` returns `00` when the Global PIN is enabled
  and preferred, and `80` otherwise. Integrity comes from the Security Object
  or from reading the object under secure messaging.
- The CCC, Key History and Pairing Code readers take `TC_PIV_CONTAINER` for the
  `53` object or `TC_PIV_CONTENTS` for its value. The CCC follows Part 1 Table
  9 and accepts the optional `E3` and `B4` elements of SP 800-73-4 Part 1 Table
  8 found on older cards. Key History checks the counts and the
  `http://<DNS name>/<SHA-256 hex>` URL of Part 1 section 3.3.3, at most 118
  bytes.
- The BIT group holds 0 to 2 finger templates of at most 28 bytes. A nonempty
  group requires the Discovery OCC bit (Part 1 section 3.3.6). Compare the two
  objects after reading both.
- The pairing code is PIN-gated secret material (Part 1 Table 2). The returned
  span borrows the response buffer, so wipe that buffer when done.
- `TC_PIV_certificate_decode` reads a certificate container and returns one
  DER certificate. A plain certificate borrows the container. A GZIP
  certificate, such as the SD 33 SMCS object with CertInfo `01`, is decoded into
  the caller's `der` buffer. Every failure after the argument checks wipes
  `der`. It needs `TINY_CRYPTO_ENABLE_GZIP`.

```c
#include <tiny_crypto/piv_card_objects.h>
#include <tiny_crypto/piv_certificate.h>
#include <tiny_crypto/piv_command.h>
#include <tiny_crypto/piv_discovery.h>

/* Choose the PIN reference from a Discovery Object and decode a certificate
 * object, both read with TC_PIV_get_data. On success, certificate borrows the
 * certificate object or der. */
int inspect_objects(const TC_PIV_data_object* discovery_object,
                    const TC_PIV_data_object* certificate_object, uint8_t* der,
                    size_t der_capacity, uint8_t* pin_reference, TC_bytes* certificate)
{
  static TC_GZIP_workspace gzip;
  TC_PIV_discovery discovery;
  TC_PIV_certificate container;
  size_t work = 200000; /* bounds the GZIP decoder */
  if (TC_PIV_discovery_read(discovery_object->encoded, TC_PIV_DISCOVERY_PIV, &discovery) !=
      TC_TLV_OK)
    return 0;
  *pin_reference = TC_PIV_discovery_pin_reference(&discovery);
  if (TC_PIV_certificate_decode(certificate_object->encoded, TC_PIV_CERTIFICATE_SLOT,
                                TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &gzip, &work,
                                (TC_buffer){der, der_capacity}, &container) != TC_TLV_OK)
    return 0; /* der is wiped */
  *certificate = container.certificate;
  return 1;
}
```

## Example

```c
#include <tiny_crypto/piv_command.h>

/* Select the PIV application and read the CHUID container 5FC102 (SP 800-73-5
 * Part 1 Table 3). On TC_PIV_OK, chuid borrows response. On
 * TC_PIV_CARD_STATUS, *status holds the card's answer. */
TC_PIV_result read_chuid(TC_APDU_transport transport, TC_PIV_interface interface,
                         uint8_t* response, size_t capacity, TC_bytes* chuid, uint16_t* status)
{
  static const uint8_t tag[] = {0x5f, 0xc1, 0x02};
  uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
  /* SELECT, GET DATA and their GET RESPONSE steps share the budget. */
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, 32, 0, 0}, interface, 0};
  TC_PIV_link link;
  TC_PIV_application application;
  TC_PIV_data_object object;
  TC_PIV_result result =
      TC_PIV_link_init(&link, transport, &options, (TC_buffer){scratch, sizeof scratch});
  if (result != TC_PIV_OK)
    return result;
  result = TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, (TC_buffer){response, capacity},
                         &application);
  if (result == TC_PIV_OK)
    result = TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag},
                             (TC_buffer){response, capacity}, &object);
  if (result == TC_PIV_OK)
    *chuid = object.value;
  *status = TC_PIV_link_status(&link);
  /* Every failure after the argument checks wiped the response buffer. */
  TC_PIV_link_clear(&link);
  return result;
}
```

The C++11 class `tiny_crypto::piv_link` in `<tiny_crypto/piv_command.hpp>` owns a
link and clears it on destruction. `piv_application_read` and
`piv_status_classify` wrap the free functions.

## Limits

- The template reader accepts at most 4096 bytes, 64 elements and 4 nesting
  levels. The card object readers accept one level and at most 16 elements.
- The card object readers check structure only. Authenticate the objects with
  the Security Object before relying on them.
- Commands travel in plaintext. Secure messaging, the VCI, CHANGE REFERENCE
  DATA, RESET RETRY COUNTER, PUT DATA, GENERATE ASYMMETRIC KEY PAIR and OCC
  VERIFY (`96`, `97`) are outside this module.
- The response buffer holds the whole answer and SW1 SW2.
  `TC_PIV_RESPONSE_BYTES(nr)` sizes a buffer for nr data bytes on any link.
