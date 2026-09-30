# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the card simulator fixtures from the vendored SD 33 captures.

Each fixture describes one card for tests/support/card_simulator.c. Records,
one per line, with hex fields and - for an unknown value:

  card NAME
  source FILE SHA256                capture file and its digest
  select ANSWER                     APT answer data of SELECT PIV
  object TAG DATA                   GET DATA answer data (SW 9000)
  reference REF VALUE RETRIES       VERIFY reference, padded value, tries left
  authenticate ALG KEY TAG VALUE ANSWER
                                    GENERAL AUTHENTICATE: the input DO (81 or
                                    85) of the 7C template and the answer data
  session SUITE SCALAR HOST COMMAND ANSWER MATERIAL
                                    recorded key establishment: host scalar,
                                    host ID, command APDU, answer data and
                                    SK_CFRM || SK_MAC || SK_ENC || SK_RMAC
  replay NAME INTERFACE             one recorded session, contact or
                                    contactless, from card reset
  wire COMMAND ANSWER               one APDU exchange with SW1 SW2
  end                               end of the replay

Objects and GENERAL AUTHENTICATE pairs come from every event of a capture.
The v2 captures hold session keys for event 2 only, so only that event
becomes a replay. Wire exchanges use the library form: SHORT secure messaging
with 1C chaining and 256-byte chunks fetched with plain GET RESPONSE
(SP 800-73-5 Part 2 4.2.4, 4.2.6 and footnote 22).

Fixtures that hold a PIN or pairing code start with a secret test material
line. --check compares the committed fixtures with the generated text."""
import argparse
import hashlib
import json
from pathlib import Path

from sm_corpus import chunked_answer, elements, normalize_events, short_fragments

CAPTURES = Path(__file__).resolve().parents[1] / "vectors" / "piv" / "sm_captures"
FIXTURES = CAPTURES / "fixtures"
# Capture files per card. The sm_vci_vectors card01 is SD 33 card 2.
CARDS = {
    "sd33_card2": ("nist_special_database_33_card_2.json", "vci_contactless_card01.json",
                   "vci_vectors_card01.json"),
    "sd33_card4": ("nist_special_database_33_card_4.json",),
}
GET_DATA = bytes.fromhex("00cb3fff")
VERIFY_REFERENCES = (0x80, 0x00, 0x98)


def tlv(tag, value):
    """BER-TLV with a one-byte tag and a definite length of up to 3 octets."""
    if len(value) < 0x80:
        length = bytes((len(value),))
    elif len(value) < 0x100:
        length = bytes((0x81, len(value)))
    else:
        length = bytes((0x82,)) + len(value).to_bytes(2, "big")
    return bytes((tag,)) + length + value


class Card:
    """Card facts merged from several captures. A value seen twice must
    match."""

    def __init__(self, name):
        self.name = name
        self.sources = []
        self.select = None
        self.objects = {}
        self.values = {}
        self.retries = {}
        self.authenticate = {}
        self.sessions = []
        self.replays = []

    def fact(self, table, key, value, what):
        if table.setdefault(key, value) != value:
            raise AssertionError(f"{self.name}: conflicting {what} {key}")

    def set_select(self, answer):
        if self.select is not None and self.select != answer:
            raise AssertionError(f"{self.name}: conflicting SELECT answers")
        self.select = answer

    def add_object(self, tag, data):
        self.fact(self.objects, tag, data, "object")

    def add_verify(self, reference, value, status):
        if value:
            self.fact(self.values, reference, value, "reference value")
        if status >> 4 == 0x63c:
            self.fact(self.retries, reference, status & 0xf, "retry count")

    def add_authenticate(self, algorithm, key, template, answer):
        inputs = {tag: value for tag, value in elements(template).items() if tag != 0x82}
        if elements(template).get(0x82) != b"" or len(inputs) != 1:
            raise AssertionError(f"{self.name}: unexpected GENERAL AUTHENTICATE template")
        (tag, value), = inputs.items()
        self.fact(self.authenticate, (algorithm, key, tag, value), answer, "authentication")


def command_fields(command):
    """Header, data and Ne of a command APDU in any case of ISO/IEC 7816-4
    5.2. Ne is 0 without Le. extended reports extended length fields."""
    header, rest = command[:4], command[4:]
    extended = len(rest) > 1 and rest[0] == 0
    at = 3 if extended else 1
    count = int.from_bytes(rest[1:3], "big") if extended else (rest[0] if rest else 0)
    if len(rest) == (3 if extended else 1):
        count, at = 0, 0
    data, le = rest[at:at + count], rest[at + count:]
    if len(header) != 4 or len(data) != count or len(le) not in (0, 2 if extended else 1):
        raise AssertionError(f"Invalid command APDU {command.hex()}")
    ne = int.from_bytes(le, "big") or (65536 if extended else 256) if le else 0
    return header, data, ne, extended


def object_tag(command):
    """The tag of a complete GET DATA 5C L tag with Le for the whole object,
    or None."""
    header, body, ne, extended = command_fields(command)
    if header != GET_DATA or ne != (65536 if extended else 256) or len(body) < 3 or \
            body[0] != 0x5c or body[1] != len(body) - 2:
        return None
    return body[2:]


def plain_exchange(card, command, answer, inner):
    """Facts from one plaintext command and answer with its inner status."""
    header, body, _, _ = command_fields(command)
    if header[1] == 0xa4:
        card.set_select(answer)
    elif header[1] == 0xcb and inner == 0x9000 and object_tag(command) is not None:
        card.add_object(object_tag(command), answer)
    elif header[1] == 0x20 and header[3] in VERIFY_REFERENCES and header[2] == 0:
        card.add_verify(header[3], body if inner == 0x9000 else b"", inner)
    elif header[1] == 0x87 and header[3] != 0x04 and inner == 0x9000:
        card.add_authenticate(header[2], header[3], elements(body)[0x7c], answer)


def session_line(op):
    return " ".join(("session", f"{int(op['cipher_suite_id'], 16):02x}",
                     op["ephemeral_private_key_d"].lower(), op["id_sH"].lower(),
                     op["general_authenticate_command"].lower(),
                     op["general_authenticate_response"].lower(),
                     op["derived_key_material"].lower()))


def wire_exchanges(records):
    """Library-form wire exchanges for recorded (command, answer, SW)
    records. Captures merge the card's 61XX chunks, and the v2 middleware
    sent extended secure messaging, which is replayed as the SHORT chain of
    the same SM data field (4.2.3 covers the unfragmented field)."""
    exchanges, fragments = [], []
    for command, answer, status in records:
        header, body, ne, extended = command_fields(command)
        if command[0] in (0x0c, 0x1c):
            fragments.append((command, body))
            if command[0] == 0x1c:
                continue
            field = b"".join(part for _, part in fragments)
            if any(command_fields(raw)[3] for raw, _ in fragments):
                wire = short_fragments(header, field)
            else:
                wire = [raw for raw, _ in fragments]
            exchanges += [(raw, b"\x90\x00") for raw in wire[:-1]]
            exchanges += chunked_answer(wire[-1], answer, status)
            fragments.clear()
        elif fragments:
            raise AssertionError("Interrupted command chain")
        elif extended or ne != 256:
            # Extended Le, no Le or a short Le below 256: one exchange.
            exchanges.append((command, answer + status))
        else:
            exchanges += chunked_answer(command, answer, status)
    if fragments:
        raise AssertionError("Incomplete command chain")
    return exchanges


def interface_of_atr(atr):
    """PC/SC synthesizes 3B 8X 80 01 ... for contactless cards (PC/SC Part 3
    3.1.3.2.3)."""
    raw = bytes.fromhex(atr)
    return "contactless" if raw[0] == 0x3b and raw[1] >> 4 == 8 and raw[2:4] == b"\x80\x01" else "contact"


def add_event_capture(card, name, data):
    """The v2 event captures: facts from every event, the keyed event as
    the replay."""
    for record in data["apdu_exchanges"]:
        wire = bytes.fromhex(record["response"])
        inner = int(record["sw"], 16)
        if record.get("plain_command") and int.from_bytes(wire[-2:], "big") == 0x9000:
            plain_exchange(card, bytes.fromhex(record["plain_command"]),
                           bytes.fromhex(record.get("plain_response") or ""), inner)
    normalized, _ = normalize_events(data)
    card.sessions.append(session_line(normalized["opacity"]))
    records = [(bytes.fromhex(r["command"]), bytes.fromhex(r["response"]), bytes.fromhex(r["sw"]))
               for r in normalized["apdu_exchanges"]]
    interface = data["metadata"]["interface_type"].lower()
    card.replays.append((name, interface, wire_exchanges(records)))


def add_vci_capture(card, name, data):
    """The sm_vci_vectors captures: objects, credentials and signing
    operations from their summaries, and every exchange as the replay."""
    for entry in data["vci_objects"].values():
        if entry.get("data_hex"):
            card.add_object(bytes.fromhex(entry["tag"]), bytes.fromhex(entry["data_hex"]))
    records = [(bytes.fromhex(r["command"]), bytes.fromhex(r["response"]), bytes.fromhex(r["sw"]))
               for r in data["apdu_exchanges"]]
    for command, answer, status in records:
        if command[0] == 0x00 and status == b"\x90\x00":
            plain_exchange(card, command, answer, 0x9000)
    session = data["sm_session"]
    card.add_verify(int(session["pin_key_ref"], 16), bytes.fromhex(session["pin_hex"]), 0x9000)
    card.add_verify(0x98, bytes.fromhex(session["pairing_code_hex"]), 0x9000)
    for operation in data.get("signing_operations", {}).values():
        signature = bytes.fromhex(operation["signature_hex"])
        card.add_authenticate(int(operation["algorithm_id"], 16), int(operation["key_ref"], 16),
                              tlv(0x81, bytes.fromhex(operation["pkcs1_padded_block_hex"])) +
                              tlv(0x82, b""), tlv(0x7c, tlv(0x82, signature)))
    card.sessions.append(session_line(data["opacity"]))
    card.replays.append((name, interface_of_atr(data["card_info"]["atr"]), wire_exchanges(records)))


def dash(value):
    return value.hex() if value else "-"


def render(name, files):
    card = Card(name)
    for file in files:
        raw = (CAPTURES / file).read_bytes()
        card.sources.append((file, hashlib.sha256(raw).hexdigest()))
        data = json.loads(raw)
        stem = Path(file).stem
        if "events" in data:
            add_event_capture(card, stem, data)
        else:
            add_vci_capture(card, stem, data)
    if card.select is None or not card.objects or not card.sessions:
        raise AssertionError(f"{name}: incomplete card")
    lines = ["# SPDX-FileCopyrightText: Mistial Dev",
             "# SPDX-License-Identifier: GPL-2.0-or-later"]
    if card.values:
        lines.append("# Secret test material: the published SD 33 test PIN and pairing code.")
    lines += ["# Generated by tests/piv/capture_fixture.py from tests/vectors/piv/sm_captures.",
              f"card {name}"]
    lines += [f"source {file} {digest}" for file, digest in card.sources]
    lines.append(f"select {card.select.hex()}")
    lines += [f"object {tag.hex()} {dash(data)}" for tag, data in sorted(card.objects.items())]
    for reference in VERIFY_REFERENCES:
        if reference in card.values or reference in card.retries:
            retries = card.retries.get(reference)
            lines.append(f"reference {reference:02x} {dash(card.values.get(reference))} "
                         f"{'-' if retries is None else retries}")
    for (algorithm, key, tag, value), answer in sorted(card.authenticate.items()):
        lines.append(f"authenticate {algorithm:02x} {key:02x} {tag:02x} {value.hex()} {answer.hex()}")
    lines += card.sessions
    for replay, interface, exchanges in card.replays:
        lines.append(f"replay {replay} {interface}")
        lines += [f"wire {command.hex()} {answer.hex()}" for command, answer in exchanges]
        lines.append("end")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="verify the committed fixtures")
    args = parser.parse_args()
    for name, files in CARDS.items():
        path = FIXTURES / f"{name}.txt"
        expected = render(name, files)
        if args.check:
            if not path.is_file() or path.read_text() != expected:
                raise AssertionError(f"stale card fixture: {path}")
        else:
            FIXTURES.mkdir(exist_ok=True)
            path.write_text(expected)
    print(f"{'Checked' if args.check else 'Wrote'} {len(CARDS)} card fixtures")


if __name__ == "__main__":
    main()
