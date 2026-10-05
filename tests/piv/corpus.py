# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check captured PIV CVCs and their field metadata."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


# SP 800-73-4 profile: SP 800-73-4 Part 1 Table 9 order and fixed sizes of
# its optional fields, with the SP 800-73-2 Part 1 Table 8 key map.
SP800_73_4_ORDER = (0xee, 0x30, 0x32, 0x33, 0x34, 0x35, 0x36, 0x3d, 0x3e, 0xfe)
REQUIRED = (0x30, 0x34, 0x35, 0x3e, 0xfe)
FIXED_SIZES = {0xee: 2, 0x32: 4, 0x33: 9, 0x30: 25, 0x34: 16, 0x36: 16}
# SP 800-73-5 Part 1 Table 10 eliminated these fields.
SP800_73_4_ONLY = (0xee, 0x32, 0x33, 0x3d)
MESSAGE_DIGEST_OID = bytes.fromhex("06092a864886f70d010904")


def elements_of(data):
    """Return (tag, encoded, value) for each single-byte-tag field."""
    elements = []
    offset = 0
    while offset < len(data):
        start = offset
        tag, length = data[offset:offset + 2]
        offset += 2
        if length & 128:
            width = length & 127
            if not 1 <= width <= 4:
                raise AssertionError("Invalid CHUID length")
            length = int.from_bytes(data[offset:offset + width], "big")
            offset += width
        if length > len(data) - offset:
            raise AssertionError("Invalid CHUID field")
        elements.append((tag, data[start:offset + length], data[offset:offset + length]))
        offset += length
    return elements


def fields_of(data):
    fields = {}
    for tag, _, value in elements_of(data):
        if tag in fields:
            raise AssertionError("Invalid CHUID field")
        fields[tag] = value
    return fields


def sp800_73_4_conforms(fields):
    tags = list(fields)
    return (tags == [tag for tag in SP800_73_4_ORDER if tag in fields] and
            all(tag in fields for tag in REQUIRED) and bool(fields[0x3e]) and
            len(fields.get(0x3d, b"")) <= 512 and
            all(len(fields[tag]) == size for tag, size in FIXED_SIZES.items() if tag in fields))


def uuid_valid(uuid, versions):
    """RFC 4122 variant (section 4.1.1) and version (section 4.1.3)."""
    return uuid[8] & 0xc0 == 0x80 and uuid[6] >> 4 in versions


def piv_conforms(fields):
    """SP 800-73-5 Part 1 Table 10 and sections 3.4.1 and 3.4.2."""
    return (sp800_73_4_conforms(fields) and not any(tag in fields for tag in SP800_73_4_ONLY) and
            uuid_valid(fields[0x34], (1, 4, 5)) and
            (0x36 not in fields or uuid_valid(fields[0x36], (4,))))


def message_digest(cms):
    """Return the signed messageDigest attribute value, found by its OID."""
    offset = cms.find(MESSAGE_DIGEST_OID)
    if offset < 0:
        return None
    value = cms[offset + len(MESSAGE_DIGEST_OID):]
    if value[0] != 0x31 or value[2] != 0x04:
        return None
    return value[4:4 + value[3]]


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
    count = rejected = digests = buffer_lengths = strict = 0
    for path in sorted(args.corpus.rglob("*.bin")):
        if "chuid" not in path.name.lower():
            continue
        data = path.read_bytes()
        wrapped = data[0] == 0x53
        contents = fields_of(data)[0x53] if wrapped else data
        expected = fields_of(contents)
        encoding = "get-data" if wrapped else "contents"
        # The strict PIV profile accepts exactly the SP 800-73-5 objects.
        result = subprocess.run([str(args.reader), encoding, "piv", str(path)], capture_output=True)
        if result.returncode != (0 if piv_conforms(expected) else 1):
            raise AssertionError(f"{path}: PIV profile returned {result.returncode}")
        strict += result.returncode == 0
        if not sp800_73_4_conforms(expected):
            result = subprocess.run([str(args.reader), encoding, "sp800-73-4", str(path)],
                                    capture_output=True)
            if result.returncode != 1:
                raise AssertionError(f"{path}: expected SP 800-73-4 schema rejection, got {result.returncode}")
            rejected += 1
            count += 1
            continue
        output = subprocess.check_output([str(args.reader), encoding, "sp800-73-4", str(path)], text=True)
        fields = dict(line.split("=", 1) for line in output.splitlines())
        for name, tag in (("fascn", 0x30), ("card_uuid", 0x34), ("cardholder_uuid", 0x36),
                          ("expiration", 0x35), ("signature", 0x3e)):
            if fields[name] != expected.get(tag, b"").hex():
                raise AssertionError(f"{path}: {name}")
        # The signature excludes Buffer Length (SP 800-73-4 Part 1 section 3.1.2).
        signed = b"".join(encoded for tag, encoded, _ in elements_of(contents)
                          if tag not in (0xee, 0x3e))
        if bytes.fromhex(fields["signed_content_0"] + fields["signed_content_1"]) != signed:
            raise AssertionError(f"{path}: signed_content")
        digest = message_digest(expected[0x3e])
        if digest and any(hashlib.new(name, signed).digest() == digest
                          for name in ("sha256", "sha384")):
            digests += 1
            buffer_lengths += 0xee in expected
        count += 1
    if count < 50:
        raise AssertionError(f"Incomplete CHUID corpus: {count} objects")
    if digests < 50 or buffer_lengths < 2:
        raise AssertionError(f"Too few CHUID digest matches: {digests}, {buffer_lengths} with EE")
    print(f"Checked {count} CHUIDs: {count - rejected} SP 800-73-4 objects with every truncated prefix, "
          f"{strict} SP 800-73-5 PIV objects, "
          f"{rejected} rejected for field layout or empty signatures, "
          f"{digests} messageDigest matches ({buffer_lengths} with Buffer Length)")


if __name__ == "__main__":
    main()
