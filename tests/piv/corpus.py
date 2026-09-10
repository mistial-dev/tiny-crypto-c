# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check captured PIV CVCs and their field metadata."""
import argparse
import json
from pathlib import Path
import subprocess


def fields_of(data):
    fields = {}
    offset = 0
    while offset < len(data):
        tag, length = data[offset:offset + 2]
        offset += 2
        if length & 128:
            width = length & 127
            if not 1 <= width <= 4:
                raise AssertionError("Invalid CHUID length")
            length = int.from_bytes(data[offset:offset + width], "big")
            offset += width
        if tag in fields or length > len(data) - offset:
            raise AssertionError("Invalid CHUID field")
        fields[tag] = data[offset:offset + length]
        offset += length
    return fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", required=True, type=Path)
    parser.add_argument("--corpus", required=True, type=Path)
    args = parser.parse_args()
    count = answers = 0
    for path in sorted(args.corpus.rglob("*cvc*.bin")):
        output = subprocess.check_output([str(args.reader), str(path)], text=True)
        fields = dict(line.split("=", 1) for line in output.splitlines())
        metadata = path.with_suffix(".json")
        if metadata.exists():
            expected = json.loads(metadata.read_text())
            for name, source in (("iin", "iin"), ("subject", "guid"),
                                 ("public_key_oid", "public_key_oid"),
                                 ("public_key_raw_hex", "public_key_raw_hex"),
                                 ("role", "role")):
                if fields[name] != expected[source].lower():
                    raise AssertionError(f"{path}: {name}")
            answers += 1
        count += 1
    if count < 10 or answers < 9:
        raise AssertionError(f"Incomplete CVC corpus: {count} files, {answers} answers")
    print(f"Checked {count} CVCs, {answers} field answers, and every truncated prefix")
    count = rejected = 0
    for path in sorted(args.corpus.rglob("*.bin")):
        if "chuid" not in path.name.lower():
            continue
        data = path.read_bytes()
        wrapped = data[0] == 0x53
        expected = fields_of(fields_of(data)[0x53] if wrapped else data)
        order = [0x30, 0x34, 0x35] + ([0x36] if 0x36 in expected else []) + [0x3e, 0xfe]
        conforms = list(expected) == order and bool(expected.get(0x3e))
        if not conforms:
            result = subprocess.run([str(args.reader), "get-data" if wrapped else "contents", str(path)],
                                    capture_output=True)
            if result.returncode != 1:
                raise AssertionError(f"{path}: expected PIV schema rejection, got {result.returncode}")
            rejected += 1
            count += 1
            continue
        output = subprocess.check_output([str(args.reader), "get-data" if wrapped else "contents",
                                          str(path)], text=True)
        fields = dict(line.split("=", 1) for line in output.splitlines())
        for name, tag in (("fascn", 0x30), ("card_uuid", 0x34), ("cardholder_uuid", 0x36),
                          ("expiration", 0x35), ("signature", 0x3e)):
            if fields[name] != expected.get(tag, b"").hex():
                raise AssertionError(f"{path}: {name}")
        count += 1
    if count < 50:
        raise AssertionError(f"Incomplete CHUID corpus: {count} objects")
    print(f"Checked {count} CHUIDs: {count - rejected} PIV objects with every truncated prefix, "
          f"{rejected} rejected for field layout or empty signatures")


if __name__ == "__main__":
    main()
