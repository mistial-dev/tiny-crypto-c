# PIV secure messaging

`<tiny_crypto/piv_sm.h>` implements the client application side of PIV secure
messaging from SP 800-73-5 Part 2 section 4. It covers key establishment
(section 4.1) and command and response protection (section 4.2) for cipher
suites CS2 and CS7.

The library owns the cryptography: the ephemeral key pair, ECDH, session-key
derivation, key confirmation, the encryption counter, the MAC chaining values
and padding. The application owns the card protocol: APDU headers, the
`7C/81/82` key-establishment objects, the `87/97/99/8E` secure messaging
objects, command chaining, GET RESPONSE and status words.
`examples/piv_sm_wire.h` is a bounded implementation of that framing for
single-APDU commands.

## Build configuration

Enable `TINY_CRYPTO_ENABLE_PIV_SM`. The desktop profile enables it with its
dependencies. The session module needs AES with `TINY_CRYPTO_AES_DYNAMIC`,
SHA-256, SSKDF and EC. `TC_PIV_SM_authenticate_response` also needs X.509 and
PIV CVC parsing, and `examples/piv_sm_wire.c` needs TLV and PIV CVC parsing.
The suites follow Table 18.

| Suite | P1 | Curve | KDF hash | Session keys | Nonce |
|-------|----|-------|----------|--------------|-------|
| CS2 | `27` | P-256 | SHA-256 | AES-128 | 16 bytes |
| CS7 | `2E` | P-384 | SHA-384 | AES-256 | 24 bytes |

`TINY_CRYPTO_PIV_SM_CS2` and `TINY_CRYPTO_PIV_SM_CS7` select the suites. Both
are ON in every profile. CS2 needs P-256. CS7 needs P-384 and SHA-384. Disable
an unused curve separately with `TINY_CRYPTO_EC_P256` or
`TINY_CRYPTO_EC_P384`. `TC_PIV_SM_KEY_BYTES` and `TC_PIV_SM_COORDINATE_BYTES`
size the session for the largest enabled suite.

## Objects and storage

| Object | Owner | Lifetime |
|--------|-------|----------|
| `TC_PIV_SM` | caller | One card session. Zero-initialize before first use. |
| `TC_PIV_SM_workspace` | caller | One call. Processed calls wipe it before returning. |
| `TC_PIV_SM_handshake` | caller | Borrows session storage until the session changes. |
| `TC_PIV_SM_peer` | caller | Borrows the received response for `TC_PIV_SM_finish`. |

Treat `TC_PIV_SM` members as private. Read the state with `TC_PIV_SM_get_state`.
Never copy a live session, because the copy would reuse keys and counters.
Sessions retain no input pointers. Every call that passes argument validation
wipes the workspace before returning, so one workspace can serve other
operations between calls. Keep every writable object disjoint from the inputs.
`TC_PIV_SM_protect` is the one exception: its ciphertext output may lie inside
the authenticated spans.

The session moves through four states.

| State | Meaning | Accepted calls |
|-------|---------|----------------|
| `TC_PIV_SM_IDLE` | No session | `begin`, `clear` |
| `TC_PIV_SM_ESTABLISHING` | `begin` succeeded | `finish` or `authenticate_response` |
| `TC_PIV_SM_READY` | Keys established | `protect` |
| `TC_PIV_SM_PENDING` | One command sent | `unprotect` |

`TC_PIV_SM_begin` and `TC_PIV_SM_clear` are accepted in any state and discard
the previous session. Call `TC_PIV_SM_clear` when the card is removed or when
command delivery becomes uncertain.

## Key establishment

The flow maps to the client steps in section 4.1.1.

1. `TC_PIV_SM_begin` sets CB_H to zero (H1), generates the ephemeral key pair
   for the selected suite (H2) and returns the host identifier and the
   uncompressed ephemeral public key in a `TC_PIV_SM_handshake`.
2. The application sends GENERAL AUTHENTICATE with CLA `00`, INS `87`, P1 set to
   the suite and P2 `04`. The data field is
   `7C { 81 { CB_H || ID_sH || Q_eH } 82 00 }` (section 4.1.8).
3. The application checks the status word and decodes
   `7C { 82 { CB_ICC || N_ICC || AuthCryptogram_ICC || C_ICC } }` into a
   `TC_PIV_SM_peer`. `certificate` holds the exact encoded CVC, because the
   derivation hashes those bytes into ID_sICC (H6). `card_control` holds the
   received CB_ICC byte.
4. The application verifies the CVC signature and the content-signing
   certificate through its trust workflow (H5).
5. `TC_PIV_SM_finish` takes the authenticated public key and the unchanged peer
   fields. It rejects a nonzero CB_ICC (H4), derives the session keys with the
   OtherInfo layout from section 4.1.6 (H6 to H11) and checks the key
   confirmation cryptogram from section 4.1.7 (H12). The ephemeral private key,
   shared secret and confirmation key are wiped (H9, H11, H13).

With X.509 and PIV CVC enabled, `TC_PIV_SM_authenticate_response` in
`<tiny_crypto/piv_sm_authenticate.h>` performs steps 4 and 5. The application
still validates the content-signing certificate's path, usage, policy, time and
revocation status first and passes it as `signer`. See
[PIV CVC verification](piv-cvc.md) for the chain rules.

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

`TC_PIV_SM_authenticate_response` returns `TC_credential_status`.
`TC_CREDENTIAL_VALID` leaves the session READY. A nonzero CB_ICC, a wrongly
sized nonce or cryptogram, a rejected CVC chain and a differing cryptogram
return `TC_CREDENTIAL_INVALID`. `TC_CREDENTIAL_UNSUPPORTED` and
`TC_CREDENTIAL_LIMIT` come from CVC parsing and verification, and `LIMIT`
includes an exhausted `work` counter. `TC_CREDENTIAL_ERROR` reports an argument
error, which leaves the session ESTABLISHING, or a signature provider or
key-derivation failure, which leaves it IDLE. Check `TC_PIV_SM_get_state` to
tell them apart.

`TC_PIV_SM_finish` returns `TC_MISMATCH` when the cryptogram differs and
`TC_ERROR` for the other failures listed in the header. Both leave the session
IDLE. Argument errors leave it ESTABLISHING and unchanged.

## Protected commands

Section 4.2.3 computes the command MAC over the MAC chaining value, a 16-byte
encoded header, the `87` object and the `97` object. The session supplies the
chaining value. The application supplies the rest as ordered spans in
`TC_PIV_SM_protect_request.authenticated`, up to
`TC_PIV_SM_AUTHENTICATED_SPANS_MAX` spans.

- The encoded header is CLA `0C`, INS, P1, P2 and the padding `80 00 ... 00`.
- The `87` object header ends with the padding indicator `01`.
- The ciphertext output span must appear inside one authenticated span. The
  call writes the ciphertext before computing the MAC, so the spans can point
  into the output APDU.
- The `97 01 00` object follows when the plain command would carry Le.

`TC_PIV_SM_ciphertext_size` returns the padded length. Padding always adds 1 to
16 bytes, and empty plaintext has empty ciphertext. The call encrypts with
AES-CBC under the counter-derived IV from section 4.2.2, writes the ciphertext
length and the 8-byte tag, and moves the session to PENDING. The application
appends `8E 08 tag` and the new Le byte (section 4.2.4).

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
    .ciphertext = ciphertext,
    .ciphertext_capacity = padded,
    .authenticated = authenticated,
    .authenticated_count = 4
};
size_t ciphertext_length;
uint8_t tag[8];
if (TC_PIV_SM_protect(&session, &request, &ciphertext_length, tag,
                      &workspace) != TC_OK) {
    /* Argument errors leave the session unchanged. Other failures end it. */
    return TC_ERROR;
}
```

The example uses a one-byte `87` length, which covers ciphertext up to 112
bytes. `examples/piv_sm_wire.c` encodes longer BER lengths.

## Protected responses

Section 4.2.5 computes the response MAC over the chaining value, the `87`
object when present and the `99` status object. Pass those bytes as
authenticated spans, the ciphertext without the padding indicator, and the
value of the `8E` object as `tag`. The ciphertext span must lie inside an
authenticated span and its length must be a multiple of 16.

`TC_PIV_SM_unprotect` checks the tag before it decrypts, so plaintext is
released only after authentication. The status word inside the `99` object is
authenticated. The outer SW1-SW2 of the response APDU is transport status, and
the application checks it before calling unprotect.

| Result | State | Meaning |
|--------|-------|---------|
| `TC_OK` | READY | Plaintext and length written. The next command may follow. |
| `TC_MISMATCH` | IDLE | The response tag differs. |
| `TC_ERROR` | PENDING | Argument error or short plaintext buffer. Retry the same response. |
| `TC_ERROR` | IDLE | Malformed padding, exhausted counter or cipher failure. |

A plaintext capacity of `request.ciphertext.length` always suffices. Check
`TC_PIV_SM_get_state` after `TC_ERROR` to tell a retryable call from one that
ended the session.

## Error handling

- Argument errors return `TC_ERROR` and leave the session, workspace and
  outputs unchanged. They include NULL pointers, overlapping storage, a
  ciphertext span outside every authenticated span and calls in the wrong
  state.
- After validation, peer, cryptographic, padding and counter failures clear the
  session. Written ciphertext or plaintext is wiped.
- Only one protected command may be pending. Protect the next command after its
  response has been unprotected.
- The encryption counter stops the session before the low 120 bits repeat.
  Establish a new session to continue.

Section 4.2.7 lists the card's secure messaging error status words. A card
error response carries no `8E` object. Clear the session and restart key
establishment.

## C++

`tiny_crypto::piv_sm` in `<tiny_crypto/piv_sm.hpp>` wraps one session. It clears
the session on destruction and cannot be copied or moved. Its member functions
match the C calls and take the same request types through references. Workspace
stays outside the object so it can be shared with other operations.

## Tests

`test_piv_sm` covers the suites, state transitions, `TC_PIV_SM_ciphertext_size`
limits and argument errors. `test_piv_sm_synthetic` runs generated card
responses through `examples/piv_sm_wire.c`. `test_piv_sm_authenticate` checks
CVC chains through the combined helper. `fuzz_piv_sm` exercises response
parsing. See [Running the tests](testing.md).
