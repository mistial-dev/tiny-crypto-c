# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check SD33 certificate containers and explicit profile mismatches."""
import argparse
from pathlib import Path
import struct
import subprocess
from corpus import fields_of


def wrap(value):
    length = len(value)
    encoded_length = bytes([length]) if length < 128 else b"\x82" + length.to_bytes(2, "big")
    return b"\x53" + encoded_length + value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    args = parser.parse_args()
    records = bytearray()
    count = 0
    for path in sorted((args.corpus / "sd33").rglob("*cert*.bin")):
        contents = path.read_bytes()
        fields = fields_of(contents)
        if list(fields) == [0x53]:
            contents = fields[0x53]
            fields = fields_of(contents)
        if list(fields) != [0x70, 0x71, 0xFE] or fields[0xFE] or fields[0x71] not in (b"\0", b"\1"):
            raise AssertionError(f"Unexpected certificate schema: {path}")
        if not contents.endswith(b"\xfe\0"):
            raise AssertionError(f"Unexpected FE encoding: {path}")
        certificate = fields[0x70]
        for value, profiles in ((contents, ((0, 0), (2, 0), (1, 1))),
                                (contents[:-2], ((1, 0), (0, 1), (2, 1))),
                                (contents + b"\x72\0", ((0, 1), (1, 1), (2, 1)))):
            encoded = wrap(value)
            for profile, invalid in profiles:
                records.extend(struct.pack(">BBBHH", profile, invalid, fields[0x71][0], len(encoded), len(certificate)))
                records.extend(encoded)
                records.extend(certificate)
        count += 1
    if count < 30:
        raise AssertionError(f"Incomplete SD33 corpus: {count} certificates")
    print(f"Checking {count} captured certificates across container profiles", flush=True)
    subprocess.run([str(args.reader)], input=records, check=True)


if __name__ == "__main__":
    main()
