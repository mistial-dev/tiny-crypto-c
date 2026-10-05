<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# PIV card commands

Enable `TINY_CRYPTO_ENABLE_PIV_COMMAND=ON` and include `<tiny_crypto/piv_command.h>`. The module
sends SELECT, GET DATA and VERIFY (SP 800-73-5 Part 2, TWIC Part 2 v5 section 5) over the
[APDU channel](apdu.md), checks the answers and tracks the link state that access rules depend on.
It allocates nothing. The application owns I/O, reader selection and PIN entry. TWIC support needs
`TC_ENABLE_TWIC` (CMake `TINY_CRYPTO_ENABLE_TWIC`), which the `twic` and `full`
[application targets](targets.md) enable.

## Link

A `TC_PIV_link` is one card session over a transport. `TC_PIV_link_init` takes
`TC_PIV_link_options`:

- `channel`: the [APDU channel options](apdu.md#channel). One exchange budget covers the session,
  GET RESPONSE steps included. Card limits may start at 0, since `TC_PIV_select` applies the
  card's own.
- `interface`: `TC_PIV_CONTACT` or `TC_PIV_CONTACTLESS`. The PIN rules depend on it.
- `response_ne`: Ne for GET DATA. 0 selects 256 (Le `00`, Part 2 section 3.1.2), and an EXTENDED
  link may request up to 65536.

The link borrows the command scratch until `TC_PIV_link_clear`, and the channel wipes it after
every transmit. A SHORT link needs `TC_APDU_SHORT_COMMAND_MAX_BYTES` (261) bytes. An EXTENDED link
needs `TC_PIV_EXTENDED_SCRATCH_BYTES`, or the card limit when smaller. That covers one command of
`TC_PIV_COMMAND_MAX_NC` data bytes (32, or the key proof template size with
`TINY_CRYPTO_ENABLE_PIV_KEY_PROOF`) and the plain key request of `TC_PIV_SM_KEY_REQUEST_BYTES`.

`TC_PIV_link_info_get` reports the interface, application, profile, announced secure messaging
suite and the secured, session-lost, VCI and PIN flags. `TC_PIV_link_status` returns the status
word of the last command the card completed. `TC_PIV_link_clear` wipes the scratch and the link.
Call it on every exit path.

Results follow `TC_APDU_result`, plus `TC_PIV_CARD_STATUS` for a card answer other than success
(see `TC_PIV_link_status`) and `TC_PIV_REFUSED` for a command a safety or state rule stopped before
sending. After a transport failure every command returns `TC_PIV_ERROR` until `TC_PIV_link_init`.

## SELECT and the application property template

`TC_PIV_select` selects the PIV application by its complete AID or the TWIC application by its
9-byte AID prefix (TWIC Part 2 v5 section 5.1, TWIC Part 3 v4 Appendix D.3), with Le `00` and
always in plaintext (Part 2 section 4.2). `TC_PIV_application_read` checks the answer:

- One `61` template holds the complete AID and two version bytes in `4F`, a `79` with a nonempty
  `4F`, and at most one each of `50`, `5F50` and `AC` (Part 2 Tables 3 and 4, section 3.1.1, TWIC
  Part 2 v5 section 5.1.1). A YubiKey answer with only the PIX in `4F` is `TC_PIV_INVALID`.
- `AC` lists `06 01 00` exactly once and at most one secure messaging suite, `27` or `2E`
  (Part 2 Table 5), returned in `sm_suite`.
- An optional DO `7F66` gives the card's largest command and response APDUs (ISO/IEC 7816-4
  section 12.8.1), including the 32769 that TWIC NEXGEN cards send as `02 02 80 01`. Other
  top-level DOs are skipped.
- PIV version `01 00` is `TC_PIV_CARD`. TWIC `01 01` is `TC_TWIC_LEGACY_CARD` and `01 03`
  `TC_TWIC_NEXGEN_CARD` (TWIC Part 2 v5 section 4.1). Another TWIC `01` sub-version is
  `TC_PIV_UNSUPPORTED`, or Legacy with `TC_PIV_SELECT_TWIC_SUBVERSION_COMPATIBLE` (TWIC Part 3 v4
  Appendix D.3).

The link follows the card's selection state (Part 2 sections 2.4.2 and 3.1.1):

| Outcome                                    | Application | PIN, VCI and secure messaging |
| ------------------------------------------ | ----------- | ----------------------------- |
| `9000` for another application             | new         | cleared                       |
| `9000` reselecting the current application | kept        | kept                          |
| Card status such as `6A82`                 | kept        | kept                          |
| Transport failure for another application  | none        | cleared                       |

A `9000` with a malformed template for another application leaves no application selected. A
successful SELECT applies the `7F66` limits and the application's
[GET RESPONSE flags](apdu.md#get-response-flags) (Part 2 sections 4.2.6 and A.4.1, TWIC Part 2 v5
section 5.2 note 3a and Appendix E).

## GET DATA

`TC_PIV_get_data` reads one data object by a tag of 1 to 3 bytes (Part 2 section 3.1.2). A
`9000` or `6282` answer must be exactly one TLV. `out->encoded` is that TLV and `out->value` its
value, both borrowed from the response buffer. `out->status` records `6282`, the end of the object
before Le bytes (ISO/IEC 7816-4 Table 7). Only a TWIC `6282` answer may end with `00` or `FF`
padding (TWIC Part 2 v5 section 5.2, ISO/IEC 7816-4:2020 section 8.1.3), which `out->encoded`
excludes.

| Answer                      | PIV application                     | TWIC application   |
| --------------------------- | ----------------------------------- | ------------------ |
| `53 L value`                | object, `TC_PIV_FORM_CONTAINER`     | same               |
| `53 00`                     | empty object (Part 1 section 4.1.1) | same               |
| `TAG L value`               | `7E` and `7F61` only                | any tag            |
| `TAG 00`                    | invalid                             | empty object       |
| `TAG 02 80 00`, constructed | invalid                             | empty object       |
| `9000` without data         | invalid                             | `TC_PIV_FORM_NONE` |

The TWIC rows follow TWIC Part 2 v5 sections 3.3.6 and 4.5. Other statuses, such as `6982`,
`6A81` or `6A82`, return `TC_PIV_CARD_STATUS`.

## VERIFY

`TC_PIV_verify_status` sends VERIFY without data (Part 2 section 3.2.1) for the PIV PIN `80`, the
Global PIN `00` or the pairing code `98`. `9000` means verified and `63CX` reports X tries left.
The pairing code has no counter (Part 2 footnote 7). One link PIN flag covers `80` and `00`:
`9000` sets it and any other answer clears it (Part 2 section 3.2.1.1).

`TC_PIV_pin_verify` verifies the PIN or Global PIN once:

1. It queries the counter. A verified reference returns `TC_PIV_OK` with `submitted` 0.
1. It sends the PIN only when the query reported at least `minimum_retries` tries (2 or more).
   Otherwise it returns `TC_PIV_REFUSED`.
1. The PIN is 6 to 8 ASCII digits, padded with `FF` to 8 bytes (Part 2 section 2.4.3), and every
   copy is wiped. A failed submission returns `TC_PIV_CARD_STATUS` with `63CX`, `6983` or `6A80`
   and is never retried.

The library refuses VERIFY of `80` and `00` outside the contact interface and the VCI, and of
`98` on contactless without secure messaging, so a PIN never crosses the contactless interface in
plaintext (Part 1 Table 4, Part 2 section 3.2.1). The VCI requires a link under
[secure messaging](piv-sm.md#secure-messaging-on-a-card-link). On contactless the card may answer
`6983` at an issuer-defined intermediate retry value. On the TWIC application, which defines no
VERIFY, both functions return `TC_PIV_UNSUPPORTED`.

## Status words

`TC_PIV_status_classify(sw, command, application, &retries)` maps a status word to a
`TC_PIV_status` by Part 1 section 5.6 Table 7. `6A88` means a missing key or data reference,
except on TWIC GET DATA, where it reports a missing object (TWIC Part 2 v5 section 5.2). `63CX` on
VERIFY writes X to `retries`.

## Card object readers

`TINY_CRYPTO_ENABLE_PIV_OBJECTS` adds readers that take the `encoded` span of a
`TC_PIV_data_object`, check it against its table, return borrowed views, charge no work and write
output only on `TC_TLV_OK`.

| Object                    | Tag      | Header                             | Reader                      |
| ------------------------- | -------- | ---------------------------------- | --------------------------- |
| Discovery Object          | `7E`     | `<tiny_crypto/piv_discovery.h>`    | `TC_PIV_discovery_read`     |
| Card Capability Container | `5FC107` | `<tiny_crypto/piv_card_objects.h>` | `TC_PIV_CCC_read`           |
| Key History               | `5FC10C` | `<tiny_crypto/piv_card_objects.h>` | `TC_PIV_key_history_read`   |
| BIT group template        | `7F61`   | `<tiny_crypto/piv_card_objects.h>` | `TC_PIV_bit_group_read`     |
| Pairing Code container    | `5FC123` | `<tiny_crypto/piv_card_objects.h>` | `TC_PIV_pairing_code_read`  |
| Certificate containers    | `5FC1xx` | `<tiny_crypto/piv_certificate.h>`  | `TC_PIV_certificate_decode` |

- Discovery (Part 1 section 3.3.2 and Table 1) must be exactly `7E 12 {4F 0B AID} {5F2F 02 xx yy}`.
  `TC_PIV_DISCOVERY_PIV` requires the PIV AID and a Table 1 policy. `TC_PIV_DISCOVERY_TWIC` reads a
  TWIC card, where the PIV application reports `40 00` or `04 00` and the TWIC application `00 00`
  under a TWIC AID (TWIC Part 2 v5 sections 4.2 and 4.7.5). `TC_PIV_discovery_pin_reference`
  returns `00` when the Global PIN is enabled and preferred, and `80` otherwise. Integrity comes
  from the Security Object or a secured read with `TC_PIV_discovery_get`
  ([virtual contact interface](piv-sm.md#virtual-contact-interface)).
- The CCC, Key History and Pairing Code readers take `TC_PIV_CONTAINER` for the `53` object or
  `TC_PIV_CONTENTS` for its value. The CCC follows Part 1 Table 9 and accepts the optional `E3`
  and `B4` elements of SP 800-73-4 Part 1 Table 8. Key History checks the counts and the
  `http://<DNS name>/<SHA-256 hex>` URL of Part 1 section 3.3.3, at most 118 bytes.
- The BIT group holds 0 to 2 finger templates of at most 28 bytes. Compare a nonempty group with
  the Discovery OCC bit it requires (Part 1 section 3.3.6).
- The pairing code is PIN-gated secret material (Part 1 Table 2). Wipe the response buffer it
  borrows when done.
- `TC_PIV_certificate_decode` returns one DER certificate, borrowed from the container or, for
  GZIP (CertInfo `01`, needs `TINY_CRYPTO_ENABLE_GZIP`), decoded into `der`. Every failure after
  the argument checks wipes `der`.

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

## Catalog and inventory

`TINY_CRYPTO_ENABLE_PIV_CATALOG` adds `<tiny_crypto/piv_catalog.h>`. `TC_PIV_catalog_count`,
`TC_PIV_catalog_at` and `TC_PIV_catalog_find` return constant `TC_PIV_object_info` entries with
each object's tag, access rule per interface, presence, capacity and `TC_PIV_OBJECT_SECRET` flag.

| Application | Profile               | Catalog                                                  |
| ----------- | --------------------- | -------------------------------------------------------- |
| PIV         | `TC_PIV_CARD`         | 36 objects of SP 800-73-5 Part 1 Table 3, Tables 2 and 8 |
| TWIC        | `TC_TWIC_LEGACY_CARD` | `5FC102`, `5FC104`, `DFC101`, `DFC103`, `DFC10F`         |
| TWIC        | `TC_TWIC_NEXGEN_CARD` | the 12 readable objects of TWIC Part 2 v5 section 4.5    |

The secret entries are the Pairing Code `5FC123`, which needs the PIN and on contactless the VCI
(Part 1 Table 2), and the TWIC Privacy Key `DFC101`, contact only (TWIC Part 2 v5 section 4.5). On
the TWIC application only `DFC001`, `DFC002` and `DFC121` are optional. Keys and the TWIC
E-stickers are outside the catalogs.

`TC_PIV_inventory_read` reads the selected application's catalog into one caller pool. It checks
each access rule against the link state before sending, and OCC is never available:

| State        | Meaning                                                                  |
| ------------ | ------------------------------------------------------------------------ |
| `PRESENT`    | read, with a nonempty value                                              |
| `EMPTY`      | `53 00`, a TWIC empty form, or a bare TWIC `9000` for an optional object |
| `ABSENT`     | `6A82`, or `6A88` on the TWIC application                                |
| `RESTRICTED` | the rule is unmet in the link state, and nothing was sent                |
| `DENIED`     | the rule was met, and the card answered `6982` or `6A81`                 |
| `OVERSIZED`  | the answer exceeded its pool region, and the plain link stayed usable    |
| `SKIPPED`    | the pairing code without `TC_PIV_INVENTORY_PAIRING_CODE`                 |

Any other outcome aborts the read and wipes the object array and the offered pool bytes. That
includes card statuses outside the table, malformed answers, transport failures, an exhausted
exchange budget and every secure messaging failure, an oversized secured answer included.

Set `objects` and `capacity` (at least `TC_PIV_catalog_count`, else `TC_PIV_LIMIT` before sending)
before the call. `max_object_bytes` in the plan caps one object at
`TC_PIV_RESPONSE_BYTES(max_object_bytes)` pool bytes. A read goes out only when its region holds
one full answer of Ne bytes, or 256 under secure messaging, bounded by the card's `7F66` limit.
`TC_PIV_INVENTORY_POOL_BYTES` covers every PIV object at its Table 8 capacity. Those capacities are
floors, and SD 33 card 2 needs about 25 KiB. Work costs one unit per catalog entry and one per kept
pool byte.

The entries borrow the pool until `TC_PIV_inventory_clear`, which wipes the used bytes and the
array. The pool may hold PIN-gated and secret data, so clear it on every exit path. `link` records
the link state the read used.

```c
#include <tiny_crypto/piv_catalog.h>

/* Read the catalog of the application selected on link. objects holds
 * TC_PIV_CATALOG_PIV_OBJECTS entries. On TC_PIV_OK *restricted counts the
 * objects to read again after the PIN or the VCI, and the caller clears the
 * inventory when done with it. */
TC_PIV_result read_inventory(TC_PIV_link* link, TC_PIV_object* objects, uint8_t* pool,
                             size_t pool_capacity, TC_PIV_inventory* inventory,
                             size_t* restricted)
{
  /* Leave the pairing code out and cap one object at 16 KiB. */
  const TC_PIV_inventory_plan plan = {0, 16384};
  size_t work = TC_PIV_CATALOG_PIV_OBJECTS + pool_capacity;
  inventory->objects = objects;
  inventory->capacity = TC_PIV_CATALOG_PIV_OBJECTS;
  const TC_PIV_result result =
      TC_PIV_inventory_read(link, &plan, (TC_buffer){pool, pool_capacity}, &work, inventory);
  if (result != TC_PIV_OK)
    return result; /* an abort wiped the pool and the objects */
  *restricted = 0;
  for (size_t i = 0; i < inventory->count; ++i)
    *restricted += inventory->objects[i].state == TC_PIV_OBJECT_RESTRICTED;
  return TC_PIV_OK;
}
```

## Key proofs

`TINY_CRYPTO_ENABLE_PIV_KEY_PROOF` adds `<tiny_crypto/piv_key_proof.h>`. `TC_PIV_key_prove` has a
card key sign a fresh challenge and verifies the signature under its certificate's key. It proves
possession only, so validate the certificate path, revocation and identifiers first.
`TC_PIV_key_parameters_select` applies the `TC_PIV_key_policy` before anything is sent or drawn:

| Key                | Identifier (SP 800-78-5 Table 9) | Profiles                                       |
| ------------------ | -------------------------------- | ---------------------------------------------- |
| RSA-2048           | `07`                             | all, and `TC_PIV_CARD` only through 2030-12-31 |
| RSA-3072           | `05`                             | `TC_PIV_CARD` and `TC_TWIC_LEGACY_CARD`        |
| RSA-1024           | `06`                             | `TC_TWIC_LEGACY_CARD` with `allow_rsa1024`     |
| P-256 with SHA-256 | `11`                             | `TC_PIV_CARD` and `TC_TWIC_LEGACY_CARD`        |
| P-384 with SHA-384 | `14`                             | `TC_PIV_CARD` and `TC_TWIC_LEGACY_CARD`        |

The certificate must assert digitalSignature, and an RSA exponent must be 65537 to 2^256 - 1
(SP 800-78-5 section 3.1). The RSA-2048 end date of Table 10 uses the policy time.
`TC_TWIC_NEXGEN_CARD` accepts only the RSA-2048 key `9E07` (TWIC Part 2 v5 sections 4.5 and 5.3).
RSA challenges use SHA-256 with PKCS #1 v1.5, or PSS with MGF1 and a 32-byte salt. The command is
GENERAL AUTHENTICATE (Part 2 Appendix A.4.1), chained above 255 bytes, and the answer must be
exactly `7C {82 L signature}`.

| Key  | Application  | Contact    | Contactless        |
| ---- | ------------ | ---------- | ------------------ |
| `9A` | PIV          | PIN        | VCI and PIN        |
| `9C` | PIV          | PIN Always | VCI and PIN Always |
| `9E` | PIV and TWIC | Always     | Always             |

The link refuses `9A` and `9C` on contactless without the VCI (Part 1 Table 5). The card enforces
the PIN and answers `6982` (`TC_PIV_CARD_STATUS`). `TC_PIV_pin_verify` skips a reference the card
reports verified, so prove `9C` directly after the session's PIN submission.

The TWIC application proves `9E` on NEXGEN cards only, under its SELECT profile (TWIC Part 2 v5
section 5.3), and returns `TC_PIV_UNSUPPORTED` on Legacy cards. A TWIC Legacy card proves its card
key on its PIV application, with `TC_TWIC_LEGACY_CARD` in the request.

`TC_PIV_key_proof_workspace` holds the challenge, the request and the answer. Argument errors,
refusals, the Legacy TWIC application and a provider without `verify_digest` leave it unchanged,
and every other return wipes it. Keep the certificate, its key bytes, the request and the provider
outside the link buffers, which every exchange rewrites. Work covers the challenge and the
signature check.

```c
#include <tiny_crypto/piv_key_proof.h>

/* Prove the card authentication key 9E on the application selected on link.
 * certificate is the validated certificate of container 5FC101 and now the
 * policy time. On TC_PIV_CARD_STATUS the card refused, and
 * TC_PIV_link_status(link) holds its answer. */
TC_PIV_result prove_card_authentication(TC_PIV_link* link, const TC_X509_certificate* certificate,
                                        const TC_X509_time* now, TC_random_source random,
                                        const TC_X509_signature_provider* provider,
                                        TC_PIV_key_proof_workspace* workspace)
{
  const TC_PIV_key_proof_request request = {
      certificate, {TC_PIV_CARD, *now, TC_PIV_RSA_PKCS1_V15, 0}, TC_PIV_KEY_CARD_AUTHENTICATION};
  TC_work_budget work = {1000000};
  /* Only TC_PIV_OK proves possession. Every return after the argument and
   * state checks wipes the workspace. */
  return TC_PIV_key_prove(link, &request, random, provider, workspace, &work);
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

The C++11 class `tiny_crypto::PIVLink` in `<tiny_crypto/piv_command.hpp>` owns a link and clears
it on destruction, and `piv_application_read` and `piv_status_classify` wrap the free functions.
`tiny_crypto::PIVInventory` in `<tiny_crypto/piv_catalog.hpp>` clears its inventory on
destruction. `tiny_crypto::piv_key_prove` in `<tiny_crypto/piv_key_proof.hpp>` takes a `PIVLink`.

## Limits

- The template reader accepts at most 4096 bytes, 64 elements and 4 nesting levels. The card
  object readers accept one level and at most 16 elements, and check structure only. Authenticate
  the objects with the Security Object ([LDS security objects](lds.md)) before relying on them.
- CHANGE REFERENCE DATA, RESET RETRY COUNTER, PUT DATA, GENERATE ASYMMETRIC KEY PAIR, OCC VERIFY
  (`96`, `97`), the key management key, retired keys and symmetric keys are outside the library.
- The response buffer holds the whole answer and SW1 SW2. `TC_PIV_RESPONSE_BYTES(nr)` sizes it for
  nr data bytes on any link.
- Two TWIC NEXGEN behaviours await confirmation on a NEXGEN card. TWIC Part 2 v5 section 5.3
  names `9A` in its prose and `9E` in its syntax, and the library proves `9E` (TWIC Part 3 v4
  section 4.4.4). Section 4.7.5 places a TWIC AID in the PIV application's Discovery Object.

## Resource use

The card commands keep no mutable static state. `sizeof(TC_PIV_link)` is 40 bytes on AVR. The
`apdu_piv_read` profile of `tests/budgets/avr.json` measures a plain SELECT, a CHUID GET DATA and a
VERIFY query on an ATmega2560 (avr-gcc 7.3.0, `-Os`). Static RAM counts the link, 261 bytes of
SHORT scratch and a response buffer for a CHUID at its Part 1 Table 8 capacity of 2881 bytes:

| Resource   | Budget      | Largest parts                                          |
| ---------- | ----------- | ------------------------------------------------------ |
| Flash      | 13500 bytes | template reader, channel, TLV reader, GET DATA         |
| Static RAM | 3400 bytes  | 2900-byte CHUID response, scratch, link and AID tables |
| Stack      | 560 bytes   | SELECT through the template reader and TLV walk        |

The catalog, the inventory and the key proofs target ESP32-class and desktop devices. They build
for AVR in the compile checks ([AVR builds and budgets](testing.md#avr-builds-and-budgets)).
