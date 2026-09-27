# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build constructed TWIC APDU replays from the synthetic object fixtures."""

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "vectors" / "twic" / "synthetic"
AID_PREFIX = bytes.fromhex("a00000036720000001")
PIV_AID_PREFIX = bytes.fromhex("a00000030800001000")
OBJECTS = (
    ("signed-chuid", "5fc102"),
    ("unsigned-chuid", "5fc104"),
    ("fingerprint", "dfc103"),
    ("face", "dfc108"),
    ("printed", "dfc109"),
    ("iris", "dfc121"),
    ("personal", "dfc001"),
    ("handwritten", "dfc002"),
)
SECURITY = ("security", "dfc10f")
TPK = ("tpk", "dfc101")


def get_data(tag):
    encoded = bytes.fromhex(tag)
    return bytes((0, 0xcb, 0x3f, 0xff, len(encoded) + 2,
                  0x5c, len(encoded))) + encoded + b"\xff"


def encoded_length(length):
    if length < 128:
        return bytes((length,))
    if length <= 255:
        return bytes((0x81,length))
    return bytes((0x82,length >> 8,length & 255))


def tlv(tag, value):
    return tag + encoded_length(len(value)) + value


def select_response(profile, application):
    if application == "twic":
        aid = AID_PREFIX + bytes((1, 1 if profile == "legacy" else 3))
        rid = AID_PREFIX[:5]
        label = b"" if profile == "legacy" else b"SYNTHETIC TWIC NG!"
    else:
        aid = PIV_AID_PREFIX + b"\x01\x00"
        rid = PIV_AID_PREFIX[:5]
        label = b"SYNTHETIC PIV  " if profile == "legacy" else b"TEST PIV 3"
    fields = tlv(b"\x4f",aid) + tlv(b"\x79",tlv(b"\x4f",rid))
    if label:
        fields += tlv(b"\x50",label)
    if profile == "legacy" and application == "piv":
        fields += tlv(b"\x5f\x50",b"test.example.org")
    fci = tlv(b"\x61",fields) + tlv(b"\x7f\x66",bytes.fromhex("8102010082020100"))
    expected = {("legacy","twic"):35, ("legacy","piv"):71,
                ("nexgen","twic"):55, ("nexgen","piv"):47}
    assert len(fci) == expected[(profile,application)]
    return fci + b"\x90\x00"


def append_general_authenticate(lines, challenge, signature):
    assert len(challenge) == len(signature) == 256
    request_value = b"\x82\x00\x81" + encoded_length(len(challenge)) + challenge
    request = b"\x7c" + encoded_length(len(request_value)) + request_value
    assert len(request) == 266
    first, final = request[:255], request[255:]
    lines.append((bytes((0x10,0x87,0x07,0x9e,len(first))) + first, b"\x90\x00"))
    response_value = b"\x82" + encoded_length(len(signature)) + signature
    response = b"\x7c" + encoded_length(len(response_value)) + response_value
    assert len(response) == 264
    lines.append((bytes((0,0x87,0x07,0x9e,len(final))) + final + b"\x00",
                  response[:256] + b"\x61\x08"))
    lines.append((b"\x00\xc0\x00\x00\x08",response[256:] + b"\x90\x00"))


def append_object(lines, tag, contents, zero_hint=False):
    command = get_data(tag)
    if zero_hint and len(contents) > 255:
        lines.append((command, b"\x61\x00"))
        command = bytes.fromhex("00c0000000")
    remaining = memoryview(contents)
    while True:
        chunk_size = 256 if zero_hint and command[1] == 0xc0 else 255
        chunk = bytes(remaining[:chunk_size])
        remaining = remaining[len(chunk):]
        if remaining:
            status = bytes((0x61, min(len(remaining), 256) & 255))
        else:
            status = b"\x90\x00"
        lines.append((command, chunk + status))
        if not remaining:
            break
        command = bytes((0, 0xc0, 0, 0, status[1]))


def render(profile, interface):
    folder = ROOT / profile
    selection = bytes.fromhex("00a4040009") + AID_PREFIX + b"\xff"
    selected = select_response(profile,"twic")
    lines = [(selection, selected)]
    inventory = OBJECTS[:3] if profile == "legacy" else OBJECTS
    for name, tag in (*inventory, SECURITY):
        object_path = folder / (name + ".bin")
        if object_path.exists():
            append_object(lines, tag, object_path.read_bytes(), True)
        elif profile == "nexgen" and name in {"iris", "personal", "handwritten"}:
            lines.append((get_data(tag), b"\x6a\x82"))
        else:
            raise FileNotFoundError(object_path)
    if interface == "contact":
        append_object(lines, TPK[1], (folder / "tpk.bin").read_bytes())
    else:
        lines.append((get_data(TPK[1]),
                      b"\x6a\x81" if profile == "legacy" else b"\x69\x82"))
    if profile == "legacy":
        for tag in ("5fc101", "dfc108", "dfc109"):
            lines.append((get_data(tag), b"\x6a\x82"))
        if interface == "contactless":
            for tag in ("7e", "dfc121", "dfc001", "dfc002"):
                lines.append((get_data(tag), b"\x6a\x82"))
            for tag in (*range(0xe1,0xeb), *range(0xfa,0xfe)):
                lines.append((get_data(f"{tag:02x}"), b"\x6a\x82"))
    else:
        for name, tag in (("card-auth-cert", "5fc101"), ("discovery", "7e")):
            append_object(lines, tag, (folder / (name + ".bin")).read_bytes(), True)
        for tag in (*range(0xe1,0xeb), *range(0xfa,0xfe)):
            lines.append((get_data(f"{tag:02x}"), b"\x6a\x82"))
    lines.append((bytes.fromhex("00a4040009") + PIV_AID_PREFIX + b"\x00",
                  select_response(profile,"piv")))
    for name, tag in (("piv-signed-chuid", "5fc102"),
                      ("piv-card-auth-cert", "5fc101")):
        append_object(lines, tag, (folder / (name + ".bin")).read_bytes(), True)
    append_general_authenticate(lines,(folder / "ga-challenge.bin").read_bytes(),
                                (folder / "ga-signature.bin").read_bytes())
    if profile == "legacy":
        if interface == "contact":
            for name, tag in (("piv-auth-cert", "5fc105"),
                              ("piv-discovery", "5fc107"),
                              ("piv-sign-cert", "5fc10a"),
                              ("piv-key-management-cert", "5fc10b")):
                append_object(lines, tag, (folder / (name + ".bin")).read_bytes(), True)
        else:
            for tag in (0x05,0x07,0x0a,0x0b):
                lines.append((get_data(f"5fc1{tag:02x}"), b"\x6a\x81"))
            for tag in (0x0c,0x0d,0x0e,0x0f):
                lines.append((get_data(f"5fc1{tag:02x}"), b"\x6a\x82"))
            lines.append((get_data("7e"), b"\x6a\x82"))
    if profile == "nexgen":
        if interface == "contact":
            for name, tag in (("piv-auth-cert", "5fc105"),
                              ("piv-discovery", "5fc107")):
                append_object(lines, tag, (folder / (name + ".bin")).read_bytes(), True)
        append_object(lines, "7e", (folder / "piv-twic-discovery.bin").read_bytes())
        if interface == "contact":
            lines.append((bytes.fromhex("00200080"), b"\x63\xc3"))
            lines.append((bytes.fromhex("0020008008") + b"31415926", b"\x90\x00"))
            for name, tag in (("piv-fingerprint", "5fc103"),
                              ("piv-face", "5fc108"),
                              ("piv-security", "5fc106"),
                              ("piv-printed", "5fc109")):
                append_object(lines, tag, (folder / (name + ".bin")).read_bytes(), True)
            for tag in range(0x0a,0x10):
                append_object(lines, f"5fc1{tag:02x}",
                              (folder / f"piv-5fc1{tag:02x}.bin").read_bytes())
        else:
            for tag in (0x05,0x07,*range(0x0a,0x10)):
                lines.append((get_data(f"5fc1{tag:02x}"), b"\x69\x82"))
    source = (f"{profile.upper()} contact status pattern observed on a real card; payload synthetic."
              if interface == "contact" else
              f"{profile.upper()} RF status pattern observed on a real card; payload synthetic.")
    return (f"# {source}\n"
            + ("# VERIFY uses an invented test PIN, unrelated to either physical card.\n"
               if profile == "nexgen" and interface == "contact" else "")
            + "# Each line is complete command and response hex, including SW1/SW2.\n"
            + "".join(f"{command.hex()} {response.hex()}\n" for command, response in lines))


def render_invalid_ga():
    folder = ROOT / "legacy"
    lines = [(bytes.fromhex("00a4040009") + PIV_AID_PREFIX + b"\x00",
              select_response("legacy","piv"))]
    signature = bytearray((folder / "ga-signature.bin").read_bytes())
    signature[-1] ^= 1
    append_general_authenticate(lines,(folder / "ga-challenge.bin").read_bytes(),signature)
    return ("# Constructed negative modeled on observed Legacy RF proof failure.\n"
            "# Signature is synthetic and must fail public-key verification.\n"
            + "".join(f"{command.hex()} {response.hex()}\n" for command, response in lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify committed replays")
    args = parser.parse_args()
    for profile in ("legacy", "nexgen"):
        for interface in ("contact", "contactless"):
            path = ROOT / profile / f"apdu-{interface}.txt"
            expected = render(profile, interface)
            if args.check:
                if path.read_text() != expected:
                    raise AssertionError(f"stale APDU replay: {path}")
            else:
                path.write_text(expected)
    invalid_path = ROOT / "legacy" / "apdu-ga-invalid.txt"
    invalid = render_invalid_ga()
    if args.check:
        if invalid_path.read_text() != invalid:
            raise AssertionError(f"stale APDU replay: {invalid_path}")
    else:
        invalid_path.write_text(invalid)


if __name__ == "__main__":
    main()
