<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Smart-card APDUs

Enable `TINY_CRYPTO_ENABLE_APDU=ON` and include `<tiny_crypto/apdu.h>`. The module encodes
ISO/IEC 7816-4:2020 command APDUs, reads response APDUs, classifies status words and runs one
command-response exchange over a caller transport. It depends on no other module and allocates
nothing. Card application commands, such as the PIV commands of SP 800-73-5 Part 2
([PIV card commands](piv-card.md)), build on it.

## Commands and responses

A `TC_APDU_command` holds CLA, INS, P1, P2, the command data as a borrowed span (Nc bytes) and
`ne`, the expected response length Ne. `ne` 0 omits Le. `ne` 256 encodes the short Le `00`, and
65536 the extended Le `0000`, or `000000` without command data (section 5.2). `ne` is a
`uint32_t`, so 65536 fits on targets with a 16-bit `size_t`.

`TC_APDU_SHORT` uses one-byte Lc and Le and accepts Nc up to 255 and Ne up to 256.
`TC_APDU_EXTENDED` keeps the short form when both fields fit and otherwise writes a 3-byte Lc with
a 2-byte Le, or a 3-byte Le without data. Select it only for a card that states extended-length
support (sections 5.2 and 12.8.1). `TC_APDU_command_size` reports the encoded size, and
`TC_APDU_EXTENDED_COMMAND_BYTES(nc)` gives an upper bound.

The module accepts the first interindustry CLA values `00` to `1F` (section 5.4.1 Table 2), which
cover the secure messaging bits b4 b3 and logical channels 0 to 3. Other classes return
`TC_APDU_UNSUPPORTED`. The chaining bit b5 is reserved for the channel, so a command with b5 set
returns `TC_APDU_ARGUMENT`.

`TC_APDU_response_read` borrows the response data and returns SW1 SW2 as one `uint16_t`. It
rejects a response shorter than 2 bytes, a status outside `6XXX` and `9XXX`, any `60XX`, and data
with SW1 `64` to `6F` (section 5.6). `TC_APDU_status_classify` maps a status to the informational
classes of section 5.6 Table 6. Card applications assign meaning to specific values.

## Transport

The application implements `TC_APDU_transmit`. It sends one command APDU and receives one complete
response APDU, data followed by SW1 SW2. It writes at most `response.capacity` bytes, sets
`*length` on `TC_OK`, and returns `TC_ERROR` when delivery failed or is uncertain. I/O, reader
selection and timing stay with the application. A PC/SC transport maps `SCardTransmit` onto this
callback.

## Channel

`TC_APDU_channel_init` binds a transport, a scratch buffer and options. The channel borrows the
scratch and transport context until `TC_APDU_channel_clear`, and an initialized channel must stay
in place. The scratch holds one encoded command fragment and is wiped after every transmit,
because commands such as VERIFY carry PIN digits. `TC_APDU_SHORT_COMMAND_MAX_BYTES` (261) covers
every SHORT command. The options set the length format, the GET RESPONSE flags, the exchange budget
and the card's size limits from DO `7F66` (section 12.8.1). `TC_APDU_channel_restrict` tightens
the limits once the card reports them and replaces the flags. `TC_APDU_channel_clear` wipes the
scratch and the channel.

`TC_APDU_transceive` sends one logical command:

- SHORT command data above 255 bytes goes out as 255-byte fragments with CLA b5 set and no Le,
  then a last fragment with the command CLA and Le (section 5.3.3). Each intermediate answer must
  be `9000` without data. Another status without data, such as `6883`, `6884` or `6982`, ends the
  exchange with `TC_APDU_OK` and that status. Data or a `62XX` or `63XX` warning on an
  intermediate answer is `TC_APDU_INVALID`. The whole chain is checked against the scratch, the
  card limit and the exchange budget before the first fragment, so these limits never interrupt a
  chain. EXTENDED commands are sent whole.
- A final `61XX` triggers GET RESPONSE with Le = SW2, and each chunk is appended to the response
  buffer (section 5.3.4). SW2 `00` requests 256 bytes.
- A `6CXX` answer without data to a command with Le resends the same step once with Le = SW2
  (section 5.6). Each GET RESPONSE step gets its own correction. A second `6CXX` on one step, or
  `6CXX` on a chained command, a command without Le or under secure messaging, ends the exchange
  with that status and the data collected so far. A command without Le, such as a VERIFY carrying
  PIN digits, reaches the card once.
- The card may return more than Ne bytes, and TWIC Part 2 v5 section 5.2 note 2 describes cards
  that return a whole object. Each transmit offers the remaining response capacity. Object framing
  and secure messaging MACs carry the integrity checks.
- Each transmit consumes one exchange of the channel budget.

On `TC_APDU_OK`, `out->data` borrows the response buffer and `out->sw` holds the final status of
any class. A status other than success is the card's answer to the command. `TC_APDU_LIMIT`
reports a response buffer, scratch, card limit or exchange budget that ran out. It wipes the
response buffer and leaves the channel usable, and the next command ends the interrupted chain.
`TC_APDU_INVALID` reports a malformed card answer and wipes the buffer. `TC_APDU_ERROR` reports a
transport failure or a transport that broke its length contract. The channel then returns
`TC_APDU_ERROR` until the next `TC_APDU_channel_init`.

### GET RESPONSE flags

ISO/IEC 7816-4 section 5.6 permits GET RESPONSE with the command CLA. SP 800-73-5 Part 2 sections
4.2.6 and A.4.1 send it with CLA `00` after secure messaging and chained commands.
`TC_APDU_GET_RESPONSE_PLAIN_CLA` clears the secure messaging and chaining bits and keeps the
logical channel. The 6CXX rule still follows the command CLA, so a plain GET RESPONSE after a
protected command keeps the secure messaging behaviour.

After `61 00` the channel requests 256 bytes with Le `00` (ISO/IEC 7816-4 section 5.3.4, TWIC
Part 2 v5 Appendix E). A TWIC NEXGEN card answers Le `FF` after `61 00` with 255 bytes and `9000`
and drops the rest of the object, a behaviour outside TWIC Part 2 v5 section 5.2 note 3a.

### Response length

Each answer carries at most the Ne of its step (ISO/IEC 7816-4:2020 section 5.1 Table 1). Short Le
`00` is 256 and extended `0000` is 65536. A GET RESPONSE step takes Ne from SW2 and a 6CXX resend
from the corrected Le. A step without Le expects no data. A longer answer returns
`TC_APDU_INVALID` and wipes the buffer.

## Example

```c
#include <tiny_crypto/apdu.h>

/* Read the PIV Discovery Object (SP 800-73-5 Part 2 section 3.1.2) through a
 * caller transport. On TC_APDU_OK, object->sw holds the card status (9000 on
 * success) and object->data borrows response. */
TC_APDU_result read_discovery(TC_APDU_transport transport, uint8_t* response,
                              size_t capacity, TC_APDU_response* object)
{
  static const uint8_t tag_list[] = {0x5c, 0x01, 0x7e};
  uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
  const TC_APDU_channel_options options = {TC_APDU_SHORT, TC_APDU_GET_RESPONSE_PLAIN_CLA,
                                           8, 0, 0};
  const TC_APDU_command get_data = {{tag_list, sizeof tag_list}, 256, 0x00, 0xcb, 0x3f, 0xff};
  TC_APDU_channel channel;
  TC_APDU_result result = TC_APDU_channel_init(&channel, transport, &options,
                                               (TC_buffer){scratch, sizeof scratch});
  if (result != TC_APDU_OK)
    return result;
  result = TC_APDU_transceive(&channel, &get_data, (TC_buffer){response, capacity}, object);
  /* Wipe the scratch buffer on every path. LIMIT, INVALID and ERROR have
   * already wiped the response buffer. */
  TC_APDU_channel_clear(&channel);
  return result;
}
```

`<tiny_crypto/apdu.hpp>` wraps the codec as the C++11 functions `tiny_crypto::apdu_command_size`,
`apdu_command_encode`, `apdu_response_read` and `apdu_status_classify`.

## Limits

- Nc is at most 65535 and Ne at most 65536. Response data is at most the response capacity minus
  2\.
- The exchange budget bounds the number of C-RPs for the channel lifetime.
- T=0 TPDU handling, extended-length chaining, proprietary classes, logical channels above 3 and
  secure messaging belong to other layers.

## Resource use

The channel keeps no static state. The caller owns the channel, the scratch and the response
buffer. On an ATmega328P with avr-gcc 7.3.0 at `-Os`, `TC_APDU_transceive` needs about 120 bytes
of stack, excluding the transport callback. The `apdu_piv_read` profile of `tests/budgets/avr.json`
records the codec with the PIV card commands on an ATmega2560, and `test_apdu_piv_read_qemu_avr`
runs the 16-bit length cases on an emulated Arduino Uno
([AVR builds and budgets](testing.md#avr-builds-and-budgets)).
