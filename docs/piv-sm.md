<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# PIV secure messaging

The library implements the client side of PIV secure messaging (SP 800-73-5 Part 2 section 4) for
cipher suites CS2 and CS7. `<tiny_crypto/piv_sm.h>` is the session: key establishment, the
encryption counter, MAC chaining and padding. `<tiny_crypto/piv_sm_apdu.h>` runs it on a
[PIV card link](piv-card.md), where GET DATA and VERIFY are protected with no change to their
calls. `<tiny_crypto/piv_vci.h>` establishes the
[virtual contact interface](#virtual-contact-interface) (Part 1 section 5.5). The application owns
I/O, trust in the content signer and the choice of when to secure the link.

## Build configuration

| Option                           | Adds                      | Needs                                                         |
| -------------------------------- | ------------------------- | ------------------------------------------------------------- |
| `TINY_CRYPTO_ENABLE_PIV_SM`      | the session               | AES with `TINY_CRYPTO_AES_ENABLE_DYNAMIC`, SHA-256, SSKDF, EC |
| `TINY_CRYPTO_ENABLE_PIV_SM_APDU` | the link layer            | PIV card commands, the session, PIV CVC parsing               |
| `TINY_CRYPTO_ENABLE_PIV_VCI`     | virtual contact interface | the link layer, PIV object readers                            |

The desktop profile enables all three. `TC_PIV_SM_authenticate_response` also needs X.509 and PIV
CVC parsing. The suites follow Table 18:

| Suite | P1   | Curve | KDF hash | Session keys | Nonce    |
| ----- | ---- | ----- | -------- | ------------ | -------- |
| CS2   | `27` | P-256 | SHA-256  | AES-128      | 16 bytes |
| CS7   | `2E` | P-384 | SHA-384  | AES-256      | 24 bytes |

`TINY_CRYPTO_PIV_SM_ENABLE_CS2` (needs P-256) and `TINY_CRYPTO_PIV_SM_ENABLE_CS7` (needs P-384 and
SHA-384) are ON in every profile. `TINY_CRYPTO_EC_ENABLE_P256` and `TINY_CRYPTO_EC_ENABLE_P384`
remove an unused curve. `TC_PIV_SM_KEY_BYTES` and `TC_PIV_SM_COORDINATE_BYTES` size the session for
the largest enabled suite.

## Objects and storage

| Object                | Owner  | Lifetime                                              |
| --------------------- | ------ | ----------------------------------------------------- |
| `TC_PIV_SM`           | caller | One card session. Zero-initialize before first use.   |
| `TC_PIV_SM_workspace` | caller | One call. Processed calls wipe it before returning.   |
| `TC_PIV_SM_handshake` | caller | Borrows session storage until the session changes.    |
| `TC_PIV_SM_peer`      | caller | Borrows the received response for `TC_PIV_SM_finish`. |

A link borrows the session from `TC_PIV_SM_key_request`, and the workspace and a secure messaging
scratch buffer from `TC_PIV_link_secure`, until the session is unbound. Keep all three alive and
unshared meanwhile. Between calls one workspace can serve other operations.

Treat `TC_PIV_SM` members as private and read the state with `TC_PIV_SM_get_state`. Never copy a
live session, because the copy would reuse keys and counters. Sessions retain no input pointers.
Keep every writable object disjoint from the inputs. Only the ciphertext output of
`TC_PIV_SM_protect` may lie inside the authenticated spans.

| State                    | Meaning           | Accepted calls                      |
| ------------------------ | ----------------- | ----------------------------------- |
| `TC_PIV_SM_IDLE`         | No session        | `begin`, `clear`                    |
| `TC_PIV_SM_ESTABLISHING` | `begin` succeeded | `finish` or `authenticate_response` |
| `TC_PIV_SM_READY`        | Keys established  | `protect`                           |
| `TC_PIV_SM_PENDING`      | One command sent  | `unprotect`                         |

`TC_PIV_SM_begin` and `TC_PIV_SM_clear` are accepted in any state and discard the previous
session. Call `TC_PIV_SM_clear` when the card is removed or command delivery becomes uncertain.

## Secure messaging on a card link

The flow follows section 4.1.1 on a link that selected the PIV application:

1. Read the Secure Messaging Certificate Signer `5FC122` and the CHUID `5FC102` in plaintext, which
   either interface allows (Part 1 Table 2). Decode the content-signing certificate with
   `TC_PIV_certificate_decode` and validate its path, usage, policy, time and revocation status.
1. `TC_PIV_SM_key_request` starts the session with the template's suite, sends the
   [key establishment](#key-establishment) command and binds the session to the link.
1. `TC_PIV_SM_authenticate_response` verifies the card CVC under the content signer, binds the
   CHUID card UUID and completes key confirmation.
1. `TC_PIV_link_secure` protects the commands that follow. SELECT and GET RESPONSE stay plain.
1. `TC_PIV_link_unsecure`, `TC_PIV_link_clear` or a successful SELECT of another application
   clears the session.

```c
#include <tiny_crypto/piv_sm_apdu.h>
#include <tiny_crypto/piv_sm_authenticate.h>

/* The link borrows the session, workspace and scratch while it is secured. */
typedef struct {
  TC_PIV_SM session;
  TC_PIV_SM_workspace workspace;
  uint8_t sm_scratch[TC_PIV_SM_COMMAND_DATA_BYTES(TC_PIV_COMMAND_MAX_NC)];
  uint8_t response[TC_PIV_SM_KEY_RESPONSE_BYTES];
} secure_storage;

/* Secure a link that selected the PIV application. signer is the validated
 * content-signing certificate from 5FC122 and card_uuid the CHUID GUID. */
TC_PIV_result secure_link(TC_PIV_link* link, const TC_PIV_application* application,
                          secure_storage* storage, TC_random_source random,
                          const TC_X509_certificate* signer, TC_bytes card_uuid,
                          const TC_X509_signature_provider* signatures)
{
  static const uint8_t host_id[8] = {0};
  const TC_TLV_limits limits = {4096, 4096, 64, 8};
  TC_PIV_SM_peer peer;
  if (!application->sm_suite)
    return TC_PIV_UNSUPPORTED; /* the card offers no secure messaging */
  TC_PIV_result result = TC_PIV_SM_key_request(
      link, &storage->session, (TC_PIV_SM_suite)application->sm_suite, host_id, random,
      (TC_buffer){storage->response, sizeof storage->response}, &peer, &storage->workspace);
  if (result != TC_PIV_OK)
    return result; /* the session is IDLE */
  const TC_PIV_SM_authentication authentication = {peer,   {NULL, 0}, card_uuid,
                                                   signer, &limits,   signatures};
  TC_PIV_SM_authentication_workspace verification;
  size_t work = 2000000; /* bounds the CVC signature check */
  if (TC_PIV_SM_authenticate_response(&storage->session, &authentication, &work,
                                      &verification) != TC_CREDENTIAL_VALID) {
    TC_PIV_link_unsecure(link); /* unbinds the IDLE session */
    return TC_PIV_INVALID;
  }
  return TC_PIV_link_secure(link, &storage->workspace,
                            (TC_buffer){storage->sm_scratch, sizeof storage->sm_scratch});
}
```

The key establishment answer needs `TC_PIV_SM_KEY_RESPONSE_BYTES` (326) bytes, the CS7 answer with
the largest card CVC of Table 19. `TC_PIV_SM_key_request` refuses a secured link or one that lost
its session, and returns `TC_PIV_UNSUPPORTED` for a suite missing from the build or the card's
announcement, both with no change. Every later failure clears the session.

### Protected command and response format

A protected command carries CLA `0C` and `[87 L 01 ciphertext] [97 01 00] 8E 08 MAC` with Le
`00` (sections 4.2.3 and 4.2.4). An SM data field above 255 bytes goes out as `1C` fragments and a
final `0C` fragment. Secure messaging always uses SHORT length fields, because footnote 22 fixes a
one-byte Le and ISO/IEC 7816-4 5.2 never mixes short and extended fields.
`TC_PIV_SM_COMMAND_DATA_BYTES(nc)` bounds the SM data field for `nc` plain bytes, up to
`TC_PIV_SM_MAX_PLAIN_NC` (65503).

The answer must be `[87 L 01 ciphertext] 99 02 SW 8E 08 MAC` with nothing after it (sections
4.2.5 and 4.2.6). The link checks the R-MAC before it decrypts in place, so GET DATA returns spans
into the caller's response buffer. The status inside `99` becomes `TC_PIV_link_status`. An inner
status other than `9000`, such as `6982` before the PIN, returns `TC_PIV_CARD_STATUS` and keeps
the session.

### Session loss

Section 4.3 and footnote 25 end the session on any secure messaging error. Once a command is
protected, every outcome except success or an inner card status ends it:

| Outcome                                                                                              | Result               | `TC_PIV_link_status` |
| ---------------------------------------------------------------------------------------------------- | -------------------- | -------------------- |
| Outer status other than `9000`, such as `6882`, `6987`, `6988`, `6CXX`, or `6883` on a `1C` fragment | `TC_PIV_CARD_STATUS` | the outer status     |
| Malformed SM objects, `87` on a VERIFY answer, a failed R-MAC or padding                             | `TC_PIV_INVALID`     | 0                    |
| Response capacity or exchange budget exhausted during the exchange                                   | `TC_PIV_LIMIT`       | 0                    |
| Transport failure, or a protect failure such as an exhausted counter                                 | `TC_PIV_ERROR`       | 0                    |

A transport failure on a plain command, such as SELECT, also ends a bound session.

The link then clears the session, the VCI and the PIN status, wipes the response buffer and the
secure messaging scratch, and reports `sm_lost` through `TC_PIV_link_info_get`. GET DATA, VERIFY
and GENERAL AUTHENTICATE return `TC_PIV_REFUSED`, with no fallback to plaintext, until
`TC_PIV_link_unsecure`, after which the link continues in plaintext or establishes a new session.
A command too large for the remaining scratch or budget returns `TC_PIV_LIMIT` before it is
protected, and the session stays READY.

## Virtual contact interface

On contactless, the PIV PIN, the PIV Authentication key and the objects marked VCI in Part 1
Table 2 need the virtual contact interface. Part 1 section 5.5 and Table 2 footnote 9 define it:
the command travels under secure messaging, the Discovery Object has policy bit 4 set, and either
the pairing code was verified or policy bit 3 waives it.

1. Secure the link as above.
1. `TC_PIV_discovery_get` reads the Discovery Object `7E` and records `secured = 1` for a read
   under secure messaging. The object carries no signature, so the VCI and PIN-reference decisions
   rely on this protected read (Part 1 section 3.3.2).
1. `TC_PIV_vci_establish` checks the policy. With bit 3 set it sends nothing and reports
   `TC_PIV_VCI_WITHOUT_PAIRING`. Otherwise it sends VERIFY `98` with the 8-digit pairing code
   (Part 2 section 3.2.1.3 and Table 25), and `9000` gives `TC_PIV_VCI_PAIRED`.
1. `TC_PIV_link_info_get` then reports `vci = 1`, and `TC_PIV_pin_verify` may send the PIN with
   the reference from `TC_PIV_discovery_pin_reference`.

```c
#include <tiny_crypto/piv_vci.h>

/* Open the VCI on a secured link. pairing_code holds the 8 digits, or is
 * empty for a card whose policy waives pairing. discovery_response must stay
 * unchanged while discovery->aid is used. */
TC_PIV_result open_vci(TC_PIV_link* link, TC_bytes pairing_code, uint8_t* discovery_response,
                       size_t response_capacity, TC_PIV_discovery* discovery)
{
  TC_PIV_vci_mode mode;
  TC_PIV_result result =
      TC_PIV_discovery_get(link, TC_PIV_DISCOVERY_PIV,
                           (TC_buffer){discovery_response, response_capacity}, discovery);
  if (result != TC_PIV_OK)
    return result; /* CARD_STATUS 6A82: the card has no Discovery Object */
  /* TC_PIV_UNSUPPORTED: the card has no VCI. TC_PIV_CARD_STATUS with
   * TC_PIV_link_status 6300: a wrong pairing code, and the session stays
   * READY. */
  return TC_PIV_vci_establish(link, discovery, pairing_code, &mode);
}
```

`TC_PIV_DISCOVERY_RESPONSE_BYTES` sizes the Discovery Object response buffer on any link. The
results:

| Result               | Meaning                                                                                            |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| `TC_PIV_UNSUPPORTED` | the TWIC application or profile, or policy bit 4 clear                                             |
| `TC_PIV_REFUSED`     | an unsecured link, a lost session, or a Discovery Object read without secure messaging             |
| `TC_PIV_ARGUMENT`    | a code other than 8 ASCII digits, an empty code when pairing is required, or overlap with the link |
| `TC_PIV_CARD_STATUS` | a rejected code, such as `6300`, clears the VCI. An outer SM status also ends the session          |

A SELECT of another application, `TC_PIV_link_unsecure`, a session loss and a new key request all
clear the VCI. Every copy of the pairing code is wiped. On the contact interface the VCI serves no
purpose (Part 1 Table 4 footnote 11).

## Key establishment

The session calls follow the client steps of section 4.1.1. `TC_PIV_SM_key_request` runs steps 1
to 3 on a link.

1. `TC_PIV_SM_begin` sets CB_H to zero, generates the ephemeral key pair (H1, H2) and returns the
   host identifier and public key in a `TC_PIV_SM_handshake`.
1. GENERAL AUTHENTICATE (INS `87`, P1 the suite, P2 `04`) carries
   `7C { 81 { CB_H || ID_sH || Q_eH } 82 00 }` (section 4.1.8).
1. The answer `7C { 82 { CB_ICC || N_ICC || AuthCryptogram_ICC || C_ICC } }` is decoded into a
   `TC_PIV_SM_peer`. Keep `certificate` as the exact encoded CVC, which the derivation hashes into
   ID_sICC (H6).
1. The application verifies the CVC and the content-signing certificate (H5).
1. `TC_PIV_SM_finish` takes the authenticated public key and the unchanged peer fields, rejects a
   nonzero CB_ICC (H4), derives the session keys (section 4.1.6) and checks the key confirmation
   cryptogram (section 4.1.7). It wipes the ephemeral private key, shared secret and confirmation
   key.

With X.509 and PIV CVC enabled, `TC_PIV_SM_authenticate_response` in
`<tiny_crypto/piv_sm_authenticate.h>` performs steps 4 and 5, checking CB_ICC and the nonce and
cryptogram sizes before any CVC work. Pass the content-signing certificate, already validated for
path, usage, policy, time and revocation, as `signer`. [PIV CVC verification](piv-cvc.md)
describes the chain rules.

```c
TC_PIV_SM session = {0};
TC_PIV_SM_workspace workspace;
TC_PIV_SM_handshake handshake;
TC_status status = TC_PIV_SM_begin(&session, TC_PIV_SM_CS2, host_id, random,
                                   &handshake, &workspace);
if (status != TC_OK)
    return status;
/* Encode handshake.host_identifier and handshake.public_key into
 * GENERAL AUTHENTICATE, exchange it and decode the 82 object. */
TC_PIV_SM_peer peer = {
    .certificate = cvc,
    .nonce = nonce,
    .cryptogram = cryptogram,
    .card_control = cb_icc
};
TC_PIV_SM_authentication authentication = {
    .peer = peer,
    .intermediate = {NULL, 0},
    .expected_uuid = card_uuid,
    .signer = &content_signer,
    .limits = &limits,
    .signatures = &signatures
};
size_t work = PIV_SM_WORK; /* application's X.509 work allowance */
TC_PIV_SM_authentication_workspace auth_workspace;
TC_credential_status accepted = TC_PIV_SM_authenticate_response(
    &session, &authentication, &work, &auth_workspace);
if (accepted != TC_CREDENTIAL_VALID) {
    /* Every failure after argument validation leaves the session IDLE. */
    return TC_ERROR;
}
```

| Call                              | Result                                            | Session      |
| --------------------------------- | ------------------------------------------------- | ------------ |
| `TC_PIV_SM_authenticate_response` | `TC_CREDENTIAL_VALID`                             | READY        |
|                                   | `INVALID`: CB_ICC, sizes, CVC chain or cryptogram | IDLE         |
|                                   | `UNSUPPORTED`, `LIMIT` (CVC checks, `work`)       | IDLE         |
|                                   | `ERROR`: argument error                           | ESTABLISHING |
|                                   | `ERROR`: chain arguments, peer key or KDF         | IDLE         |
| `TC_PIV_SM_finish`                | `TC_MISMATCH`: the cryptogram differs             | IDLE         |
|                                   | `TC_ERROR` after validation                       | IDLE         |
|                                   | `TC_ERROR` for an argument error                  | ESTABLISHING |

Check `TC_PIV_SM_get_state` to tell the `ERROR` cases apart.

## Protected commands

This section and the next cover framing outside `<tiny_crypto/piv_sm_apdu.h>`. The command MAC
of section 4.2.3 covers the chaining value, which the session supplies, and ordered spans in
`TC_PIV_SM_protect_request.authenticated`, up to `TC_PIV_SM_AUTHENTICATED_SPANS_MAX`:

- the 16-byte header: CLA `0C`, INS, P1, P2 and the padding `80 00 ... 00`
- the `87` object header ending with the padding indicator `01`, and the ciphertext output span,
  which the call writes before the MAC, so the spans can point into the output APDU
- `97 01 00` when the plain command would carry Le

`TC_PIV_SM_ciphertext_size` returns the padded length: 1 to 16 bytes more, and empty for empty
plaintext. The call writes the ciphertext length and the 8-byte tag and moves the session to
PENDING. The application appends `8E 08 tag` and the new Le byte (section 4.2.4).

```c
uint8_t header[16] = {0x0c, ins, p1, p2, 0x80};
uint8_t object_header[] = {0x87, (uint8_t)(padded + 1), 0x01};
uint8_t le_object[] = {0x97, 0x01, 0x00};
const TC_bytes authenticated[] = {
    {header, sizeof header},
    {object_header, sizeof object_header},
    {ciphertext, padded},
    {le_object, sizeof le_object}
};
TC_PIV_SM_protect_request request = {
    .plaintext = command_data,
    .ciphertext = {ciphertext, padded},
    .authenticated = authenticated,
    .authenticated_count = 4
};
size_t ciphertext_length;
uint8_t tag[8];
if (TC_PIV_SM_protect(&session, &request, &ciphertext_length,
                      (TC_buffer){tag, sizeof tag},
                      &workspace) != TC_OK) {
    /* Argument errors leave the session unchanged. Other failures end it. */
    return TC_ERROR;
}
```

The example uses a one-byte `87` length, which covers ciphertext up to 112 bytes. Longer
ciphertext needs the `81` or `82` length forms.

## Protected responses

The response MAC of section 4.2.5 covers the chaining value, the `87` object when present and the
`99` status object. Pass those bytes as authenticated spans, the ciphertext without the padding
indicator (inside an authenticated span, a multiple of 16 bytes) and the `8E` value as `tag`.
`TC_PIV_SM_unprotect` checks the tag before it decrypts. Check the outer SW1-SW2, which is
transport status, before the call.

The plaintext buffer is either disjoint from every input or exactly `request.ciphertext.data` with
a capacity of at most `request.ciphertext.length`, which decrypts in place. Any other overlap is an
argument error. Padding failures leave the ciphertext unchanged. A capacity of
`request.ciphertext.length` always suffices.

| Result        | State   | Meaning                                                            |
| ------------- | ------- | ------------------------------------------------------------------ |
| `TC_OK`       | READY   | Plaintext and length written. The next command may follow.         |
| `TC_MISMATCH` | IDLE    | The response tag differs.                                          |
| `TC_ERROR`    | PENDING | Argument error or short plaintext buffer. Retry the same response. |
| `TC_ERROR`    | IDLE    | Malformed padding, exhausted counter or cipher failure.            |

## Error handling

Argument errors return `TC_ERROR` and leave the session, workspace and outputs unchanged: NULL
pointers, overlapping storage, a ciphertext span outside every authenticated span and calls in the
wrong state. Other failures clear the session and wipe any written ciphertext or plaintext. Check
`TC_PIV_SM_get_state` after `TC_ERROR` to tell the two apart. One protected command may be pending
at a time. The encryption counter stops the session before the low 120 bits repeat. A card error
response (section 4.2.7) carries no `8E` object. In both cases clear the session and restart key
establishment.

## C++

`tiny_crypto::PIVSM` in `<tiny_crypto/piv_sm.hpp>` wraps one session, clears it on destruction
and deletes copy and move. Its member functions match the C calls, the workspace stays outside
the object, and `native()` returns the `TC_PIV_SM`. `<tiny_crypto/piv_sm_apdu.hpp>` adds
`piv_sm_key_request`, `piv_link_secure` and `piv_link_unsecure` over a `PIVLink` and a `PIVSM`.
Declare the `PIVSM` before the `PIVLink`, so the link is destroyed first and clears the bound
session while it still exists. `<tiny_crypto/piv_vci.hpp>` adds `piv_discovery_get` and
`piv_vci_establish`.

## Resource use

The framing adds no static state and allocates nothing. The `piv_sm_cs2` profile of
`tests/budgets/avr.json` measures CS2 key establishment and a protected CHUID GET DATA on an
ATmega2560 (avr-gcc 7.3.0, `-Os`, [AVR builds and budgets](testing.md#avr-builds-and-budgets)):

| Resource   | Budget      | Contents                                                       |
| ---------- | ----------- | -------------------------------------------------------------- |
| Flash      | 36700 bytes | EC P-256, AES, CMAC, SSKDF, the CVC reader and the PIV link    |
| Static RAM | 4700 bytes  | link, session, 1090-byte workspace, scratch and CHUID response |
| Stack      | 750 bytes   | key establishment through ECDH                                 |

The link framing takes at most 3800 bytes of that flash. Secure messaging exceeds the ATmega328P
(32 KiB flash, 2 KiB RAM).

## Tests

`test_piv_sm`, `test_piv_sm_apdu`, `test_piv_vci`, `test_piv_sm_authenticate`,
`test_sm_primitives_corpus`, `test_piv_sm_synthetic`, `test_cpp_piv_vci` and `fuzz_piv_apdu` cover
this module. [Running the tests](testing.md#piv-test-fixtures) describes the card model and the
SD 33 captures they replay.
