# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check cryptographic intermediates in PIV SM captures."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from munit_runner import run_reader


def elements(data):
    result = {}
    at = 0
    while at < len(data):
        start = at
        tag = data[at]
        at += 1
        if tag & 31 == 31:
            while True:
                if at >= len(data) or at - start >= 4:
                    raise AssertionError("Truncated or oversized capture tag")
                octet = data[at]
                at += 1
                tag = (tag << 8) | octet
                if not octet & 128:
                    break
        if at >= len(data):
            raise AssertionError("Missing capture length")
        size = data[at]
        at += 1
        if size & 128:
            width = size & 127
            if not width or width > 4 or at + width > len(data):
                raise AssertionError("Invalid capture length")
            size = int.from_bytes(data[at:at + width], "big")
            at += width
        if at + size > len(data) or tag in result:
            raise AssertionError("Truncated or duplicate capture element")
        result[tag] = data[at:at + size]
        at += size
    return result


def normalize_events(data):
    source = data["sm"]["opacity"]
    suite = int(source["CipherSuiteId"], 16)
    if suite not in (0x27, 0x2e):
        raise AssertionError(f"Unknown capture suite {suite}")
    width = 32 if suite == 0x27 else 48
    key_width = 16 if suite == 0x27 else 32
    public = bytes.fromhex("04" + source["EphemeralPublicKeyX"].zfill(width * 2) +
                           source["EphemeralPublicKeyY"].zfill(width * 2))
    exchanges = {record["exchange_id"]: record for record in data["apdu_exchanges"]}
    if len(exchanges) != len(data["apdu_exchanges"]):
        raise AssertionError("Duplicate capture exchange ID")
    selected = None
    missing = []
    for event in data["events"]:
        if not event["sm_established"]:
            continue
        ga = exchanges[event["sm_establishment_exchange_id"]]
        header, body, _ = apdu(ga["command"])
        if header != bytes((0, 0x87, suite, 4)) or ga["event_id"] != event["event_id"]:
            raise AssertionError("Invalid session establishment exchange")
        if not ga["response"].lower().endswith("9000"):
            raise AssertionError("Session establishment failed")
        request = elements(elements(body)[0x7c])[0x81]
        if len(request) != 10 + 2 * width or request[0] != 0:
            raise AssertionError("Invalid session establishment request")
        if request[9:] != public:
            missing.append(event["event_id"])
            continue
        if selected is not None:
            raise AssertionError("Derivation data matches multiple sessions")
        selected = (event, ga, request)
    if selected is None:
        raise AssertionError("Derivation data does not match a captured handshake")
    event, ga, request = selected
    op = {
        "cipher_suite_id": hex(suite), "id_sH": request[1:9].hex(),
        "ephemeral_private_key_d": source["EphemeralPrivateKeyD"].zfill(width * 2),
        "ephemeral_public_key_x": public[1:1 + width].hex(),
        "ephemeral_public_key_y": public[1 + width:].hex(),
        "shared_secret_Z": source["SharedSecretZ"].zfill(width * 2),
        "other_info": source["OtherInfo"],
        "general_authenticate_command": ga["command"],
        "general_authenticate_response": ga["response"][:-4],
        "cvc": {"public_key_raw_hex": elements(elements(elements(
            bytes.fromhex(source["CardCvc"]))[0x7f21])[0x7f49])[0x86].hex()},
    }
    for target, field in (("sk_cfrm", "SkCfrm"), ("sk_mac", "SkMac"),
                          ("sk_enc", "SkEnc"), ("sk_rmac", "SkRmac")):
        op[target] = source[field].zfill(key_width * 2)
    op["derived_key_material"] = "".join(op[key] for key in ("sk_cfrm", "sk_mac", "sk_enc", "sk_rmac"))
    records = []
    initial = None
    for original in data["apdu_exchanges"]:
        if original["event_id"] != event["event_id"]:
            continue
        record = dict(original)
        wire = bytes.fromhex(record["response"])
        if len(wire) < 2:
            raise AssertionError("Capture response lacks transport status")
        record["response"], record["sw"] = wire[:-2].hex(), wire[-2:].hex()
        for field in ("sm_state_before", "sm_state_after_wrap", "sm_state_after_unwrap"):
            if record.get(field):
                record[field] = {name: value.zfill(32) for name, value in record[field].items()}
        if record.get("sm_state_before") and initial is None:
            initial = record["sm_state_before"]
        if record.get("sm_state_after_wrap"):
            record["sm_state"] = record["sm_state_after_wrap"]
        records.append(record)
    if initial is None:
        raise AssertionError("Session has no protected exchanges")
    return {"opacity": op, "sm_session": {"initial_state": initial},
            "apdu_exchanges": records}, missing


def apdu(hex_string):
    raw = bytes.fromhex(hex_string)
    if len(raw) < 4:
        raise AssertionError("Truncated APDU header")
    if len(raw) == 4:
        return raw[:4], b"", False
    if len(raw) == 5:
        if raw[4] != 0:
            raise AssertionError("Unexpected Le")
        return raw[:4], b"", True
    if raw[4]:
        start, length = 5, raw[4]
    else:
        start, length = 7, int.from_bytes(raw[5:7], "big")
    if not length or start + length > len(raw):
        raise AssertionError("Invalid APDU Lc")
    le = raw[start + length:]
    # Extended APDUs encode Le=256 as 0100. Short-form APDUs use 00.
    allowed_le = (b"", b"\0") if start == 5 else (b"", b"\0\0", b"\x01\0")
    if le not in allowed_le:
        raise AssertionError("Unexpected APDU Le")
    return raw[:4], raw[start:start + length], bool(le)


CHUNK = 256
SHORT_FRAGMENT = 255


def short_fragments(header, field):
    """SHORT command APDUs for one SM data field: 1C fragments of 255 bytes,
    then the 0C command with the new Le 00 (SP 800-73-5 Part 2 4.2.4,
    footnote 22)."""
    commands = []
    while len(field) > SHORT_FRAGMENT:
        commands.append(bytes((0x1c,)) + header[1:] + bytes((SHORT_FRAGMENT,)) +
                        field[:SHORT_FRAGMENT])
        field = field[SHORT_FRAGMENT:]
    commands.append(bytes((0x0c,)) + header[1:] + bytes((len(field),)) + field + b"\0")
    return commands


def chunked_answer(command, response, status):
    """Wire exchanges for the final command of one SM chain. Captures merge
    the card's 61XX chunks, so the answer is split again into 256-byte chunks
    followed by plain GET RESPONSE 00 C0 00 00 XX (4.2.6)."""
    exchanges = []
    while True:
        chunk, response = response[:CHUNK], response[CHUNK:]
        if not response:
            exchanges.append((command, chunk + status))
            return exchanges
        more = min(len(response), CHUNK) & 0xff
        exchanges.append((command, chunk + bytes((0x61, more))))
        command = bytes((0, 0xc0, 0, 0, more))


def hex_or_dash(data):
    return data.hex() if data else "-"


def state_line(state, known=("counter", "cmd_mcv", "resp_mcv"), advance=False):
    fields = []
    for name in ("counter", "cmd_mcv", "resp_mcv"):
        if name not in known:
            fields.append("-")
        elif name == "counter" and advance:
            fields.append(f"{int(state[name], 16) + 1:032x}")
        else:
            fields.append(state[name].lower())
    return "state " + " ".join(fields)


def select_record(records):
    for record in records:
        if record["command"].upper().startswith("00A40400"):
            return record
    raise AssertionError("Capture has no SELECT")


def transcript(data):
    """Write the wire transcript that tests/piv/sm_apdu_replay.c replays.

    Recorded 1C and 0C fragments are replayed byte for byte. An extended
    length SM command, which SP 800-73-5 Part 2 footnote 22 excludes, is
    replayed as the SHORT chain of its SM data field, which the C-MAC covers
    unfragmented (4.2.3)."""
    op = data["opacity"]
    suite = int(op["cipher_suite_id"], 0)
    records = data["apdu_exchanges"]
    select = select_record(records)
    lines = [f"select {select['command'].lower()} "
             f"{select['response'].lower()}{select['sw'].lower()}",
             f"begin {suite:02x} {op['ephemeral_private_key_d']} {op['id_sH']} "
             f"{op['general_authenticate_command']}",
             f"finish {op['general_authenticate_response']} {op['derived_key_material']}",
             state_line(data["sm_session"]["initial_state"])]
    fragments, pending_header = [], None
    commands = 0
    for record in records:
        command = bytes.fromhex(record["command"])
        if command[0] not in (0x0c, 0x1c):
            if fragments:
                raise AssertionError("Interrupted command chain")
            continue
        header, body, le = apdu(record["command"])
        if pending_header is not None and header[1:] != pending_header:
            raise AssertionError("Command chain changed its header")
        fragments.append((command, header, body))
        if header[0] == 0x1c:
            if le or record["response"] or record["sw"] != "9000":
                raise AssertionError("Unexpected intermediate command result")
            pending_header = header[1:]
            continue
        if not le:
            raise AssertionError("Protected command is missing Le")
        plain_header, plain, plain_le = apdu(record["plain_command"])
        if plain_header[1:] != header[1:]:
            raise AssertionError("Plain/protected command headers differ")
        field = b"".join(body for _, _, body in fragments)
        extended = any(len(raw) > 5 and raw[4] == 0 for raw, _, _ in fragments)
        if extended:
            wire = short_fragments(header, field)
        else:
            wire = [raw for raw, _, _ in fragments]
        exchanges = [(raw, bytes.fromhex("9000")) for raw in wire[:-1]]
        response = bytes.fromhex(record["response"])
        exchanges += chunked_answer(wire[-1], response, bytes.fromhex(record["sw"]))
        if response[-14:-12] != b"\x99\x02" or response[-10:-8] != b"\x8e\x08":
            raise AssertionError("Missing authenticated response status")
        status = response[-12:-10].hex()
        plain_response = bytes.fromhex(record.get("plain_response") or "")
        lines.append(f"command {header[1]:02x} {header[2]:02x} {header[3]:02x} "
                     f"{256 if plain_le else 0} {hex_or_dash(plain)} "
                     f"{hex_or_dash(plain_response)} {status}")
        lines += [f"wire {raw.hex()} {answer.hex()}" for raw, answer in exchanges]
        lines.append("end")
        if record.get("sm_state_after_unwrap"):
            lines.append(state_line(record["sm_state_after_unwrap"]))
        elif record.get("sm_state"):
            # The capture records the state after protection: the counter
            # this command used and the new command MCV.
            lines.append(state_line(record["sm_state"], ("counter", "cmd_mcv"), advance=True))
        fragments.clear()
        pending_header = None
        commands += 1
    if fragments or commands == 0:
        raise AssertionError("Incomplete SM transcript")
    return "\n".join(lines) + "\n", commands


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", required=True, type=Path)
    parser.add_argument("--ec-reader", action="append", type=Path, default=[])
    parser.add_argument("--sm-reader", type=Path)
    parser.add_argument("--corpus", required=True, type=Path)
    args = parser.parse_args()
    count = commands = 0
    suites = set()
    for path in sorted(args.corpus.glob("*.json")):
        data = json.loads(path.read_text())
        if "sm" in data and "opacity" in data["sm"]:
            data, missing = normalize_events(data)
            if missing:
                # The v2 captures hold derivation data for one event. The
                # other events replay as recorded plaintext only.
                print(f"{path.name}: no derivation data for events {missing}", flush=True)
        if "opacity" not in data:
            continue
        op = data["opacity"]
        suite = int(op["cipher_suite_id"], 0)
        if suite not in (0x27, 0x2e):
            raise AssertionError(f"{path}: unknown suite {suite}")
        bits = "256" if suite == 0x27 else "384"
        material = bytes.fromhex(op["derived_key_material"])
        keys = b"".join(bytes.fromhex(op[name]) for name in
                        ("sk_cfrm", "sk_mac", "sk_enc", "sk_rmac"))
        if material != keys or len(keys) != (64 if suite == 0x27 else 128):
            raise AssertionError(f"{path}: key split")
        rounds = (b"".join(bytes.fromhex(op[f"kdf_round_{i}_hash"])
                           for i in range(1, 3 if suite == 0x27 else 4))
                  if "kdf_round_1_hash" in op else material)
        if rounds[:len(keys)] != keys:
            raise AssertionError(f"{path}: round digests")
        run_reader([str(args.reader), "--capture", bits,
                                 op["shared_secret_Z"], op["other_info"], rounds.hex()],
                   echo=False)
        for reader in args.ec_reader:
            public = "04" + op["ephemeral_public_key_x"] + op["ephemeral_public_key_y"]
            run_reader([str(reader), "--capture", bits,
                                     op["ephemeral_private_key_d"], public,
                                     op["cvc"]["public_key_raw_hex"], op["shared_secret_Z"]],
                       echo=False)
        if args.sm_reader:
            records, messages = transcript(data)
            with tempfile.TemporaryDirectory(prefix="tiny-crypto-sm-") as temporary:
                fixture = Path(temporary) / "transcript.txt"
                fixture.write_text(records)
                run_reader([str(args.sm_reader), "--transcript", str(fixture)], echo=False)
            commands += messages
        suites.add(suite)
        count += 1
    if count == 0 or suites != {0x27, 0x2e}:
        raise AssertionError(f"Expected captures for both suites, found {count} records")
    print(f"Checked {count} CS2/CS7 derivations and available round digests; "
          f"{len(args.ec_reader)} EC implementations checked; {commands} SM exchanges replayed")


if __name__ == "__main__":
    main()
