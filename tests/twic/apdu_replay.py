# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build constructed TWIC APDU replays from the synthetic object fixtures.

The replays follow the library's command order: SELECT and GET DATA with
Le 00 (SP 800-73-5 Part 2 3.1.2), the TWIC application inventory in the
TWIC Part 2 v5 4.5 catalog order, and GET RESPONSE with Le = SW2, where
61 00 asks for FF on the TWIC application (5.2 note 3a) and 00 on the PIV
application. The AID prefixes mirror src/piv_aid.c.
"""

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "vectors" / "twic" / "synthetic"
AID_PREFIX = bytes.fromhex("a00000036720000001")
PIV_AID_PREFIX = bytes.fromhex("a00000030800001000")
PIV_AID = PIV_AID_PREFIX + b"\x01\x00"
# TWIC application catalog: (fixture name, tag, optional). Legacy reads the
# first five, NEXGEN every entry in TWIC Part 2 v5 4.5 table order.
LEGACY_CATALOG = (
    ("signed-chuid", "5fc102", False),
    ("unsigned-chuid", "5fc104", False),
    ("tpk", "dfc101", False),
    ("fingerprint", "dfc103", False),
    ("security", "dfc10f", False),
)
NEXGEN_CATALOG = (
    ("card-auth-cert", "5fc101", False),
    ("signed-chuid", "5fc102", False),
    ("unsigned-chuid", "5fc104", False),
    ("discovery", "7e", False),
    ("personal", "dfc001", True),
    ("handwritten", "dfc002", True),
    ("tpk", "dfc101", False),
    ("fingerprint", "dfc103", False),
    ("face", "dfc108", False),
    ("printed", "dfc109", False),
    ("security", "dfc10f", False),
    ("iris", "dfc121", True),
)
E_STICKERS = (*range(0xe1, 0xeb), *range(0xfa, 0xfe))


def get_data(tag):
    encoded = bytes.fromhex(tag)
    return bytes((0, 0xcb, 0x3f, 0xff, len(encoded) + 2,
                  0x5c, len(encoded))) + encoded + b"\x00"


def select(aid):
    return bytes((0, 0xa4, 4, 0, len(aid))) + aid + b"\x00"


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
        aid = PIV_AID
        rid = PIV_AID_PREFIX[:5]
        label = b"SYNTHETIC PIV  " if profile == "legacy" else b"TEST PIV 3"
    fields = tlv(b"\x4f",aid) + tlv(b"\x79",tlv(b"\x4f",rid))
    if label:
        fields += tlv(b"\x50",label)
    if profile == "legacy" and application == "piv":
        fields += tlv(b"\x5f\x50",b"test.example.org")
    # DO 7F66 (ISO/IEC 7816-4 12.8.1): 1024-byte commands, 2048-byte answers.
    limits = tlv(b"\x02", b"\x04\x00") + tlv(b"\x02", b"\x08\x00")
    fci = tlv(b"\x61",fields) + tlv(b"\x7f\x66",limits)
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
    """Append GET DATA for tag and the GET RESPONSE steps of its answer.

    Le 00 on GET DATA gets 256 bytes. With zero_hint the card answers a long
    object with 61 00 and no data first, as the observed cards did.
    """
    command = get_data(tag)
    remaining = memoryview(contents)
    if zero_hint and len(contents) > 256:
        lines.append((command, b"\x61\x00"))
        command = bytes.fromhex("00c0000000")
    while True:
        chunk = bytes(remaining[:command[-1] or 256])
        remaining = remaining[len(chunk):]
        if remaining:
            status = bytes((0x61, min(len(remaining), 256) & 255))
        else:
            status = b"\x90\x00"
        lines.append((command, chunk + status))
        if not remaining:
            break
        command = bytes((0, 0xc0, 0, 0, status[1]))


def append_twic_inventory(lines, profile, interface):
    """The TWIC application catalog as TC_PIV_inventory_read reads it. The
    TWIC Privacy Key is Never on contactless, so nothing is sent for it."""
    folder = ROOT / profile
    catalog = LEGACY_CATALOG if profile == "legacy" else NEXGEN_CATALOG
    for name, tag, optional in catalog:
        if tag == "dfc101" and interface == "contactless":
            continue
        path = folder / (name + ".bin")
        if path.exists():
            append_object(lines, tag, path.read_bytes(), tag != "dfc101")
        elif optional:
            lines.append((get_data(tag), b"\x6a\x82"))
        else:
            raise FileNotFoundError(path)


def append_piv_object(lines, folder, name, tag):
    append_object(lines, tag, (folder / (name + ".bin")).read_bytes(), True)


def render(profile, interface):
    folder = ROOT / profile
    lines = [(select(AID_PREFIX), select_response(profile,"twic"))]
    append_twic_inventory(lines, profile, interface)
    if interface == "contactless":
        lines.append((get_data("dfc101"),
                      b"\x6a\x81" if profile == "legacy" else b"\x69\x82"))
    if profile == "legacy":
        for tag in ("5fc101", "dfc108", "dfc109"):
            lines.append((get_data(tag), b"\x6a\x82"))
        if interface == "contactless":
            for tag in ("7e", "dfc121", "dfc001", "dfc002"):
                lines.append((get_data(tag), b"\x6a\x82"))
            for tag in E_STICKERS:
                lines.append((get_data(f"{tag:02x}"), b"\x6a\x82"))
    else:
        for tag in E_STICKERS:
            lines.append((get_data(f"{tag:02x}"), b"\x6a\x82"))
    lines.append((select(PIV_AID), select_response(profile,"piv")))
    for name, tag in (("piv-signed-chuid", "5fc102"),
                      ("piv-card-auth-cert", "5fc101")):
        append_piv_object(lines, folder, name, tag)
    append_general_authenticate(lines,(folder / "ga-challenge.bin").read_bytes(),
                                (folder / "ga-signature.bin").read_bytes())
    if profile == "legacy":
        if interface == "contact":
            for name, tag in (("piv-auth-cert", "5fc105"),
                              ("piv-discovery", "5fc107"),
                              ("piv-sign-cert", "5fc10a"),
                              ("piv-key-management-cert", "5fc10b")):
                append_piv_object(lines, folder, name, tag)
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
                append_piv_object(lines, folder, name, tag)
        append_piv_object(lines, folder, "piv-twic-discovery", "7e")
        if interface == "contact":
            lines.append((bytes.fromhex("00200080"), b"\x63\xc3"))
            lines.append((bytes.fromhex("0020008008") + b"31415926", b"\x90\x00"))
            for name, tag in (("piv-fingerprint", "5fc103"),
                              ("piv-face", "5fc108"),
                              ("piv-security", "5fc106"),
                              ("piv-printed", "5fc109")):
                append_piv_object(lines, folder, name, tag)
            for tag in range(0x0a,0x10):
                append_piv_object(lines, folder, f"piv-5fc1{tag:02x}", f"5fc1{tag:02x}")
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
    lines = [(select(PIV_AID), select_response("legacy","piv"))]
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
