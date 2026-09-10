# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare captured SD33 compressed certificate bytes with Python gzip."""
import argparse
import gzip
from pathlib import Path
import subprocess
import sys

from differential import pack_record

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from piv.corpus import fields_of

MIN_CERTIFICATES = 30
MIN_COMPRESSED = 10


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    args = parser.parse_args()
    certificates = compressed = 0
    records = bytearray()
    for path in sorted((args.corpus / "sd33").rglob("*cert*.bin")):
        fields = fields_of(path.read_bytes())
        if 0x53 in fields:
            fields = fields_of(fields[0x53])
        if list(fields) != [0x70, 0x71, 0xFE] or fields[0xFE]:
            raise AssertionError(f"Unexpected certificate container: {path}")
        certificates += 1
        if fields[0x71] == b"\0":
            continue
        if fields[0x71] != b"\1":
            raise AssertionError(f"Unexpected CertInfo: {path}")
        encoded = fields[0x70]
        decoded = gzip.decompress(encoded)
        records.extend(pack_record(encoded, decoded))
        corrupt = bytearray(encoded)
        corrupt[-8] ^= 1
        try:
            gzip.decompress(corrupt)
        except OSError:
            pass
        else:
            raise AssertionError(f"Checksum mutation accepted: {path}")
        records.extend(pack_record(corrupt, decoded, 1))
        compressed += 1
    if certificates < MIN_CERTIFICATES or compressed < MIN_COMPRESSED:
        raise AssertionError(f"Incomplete SD33 corpus: {certificates} certificates, {compressed} compressed")
    print(f"Checked {compressed} captured GZIP certificates and checksum mutations "
          f"from {certificates} certificate containers", flush=True)
    subprocess.run([str(args.reader)], input=records, check=True)


if __name__ == "__main__":
    main()
