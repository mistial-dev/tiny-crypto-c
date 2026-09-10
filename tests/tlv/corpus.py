# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check corpus framing, not certificate trust or PIV authentication."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


class Reader:
    def __init__(self, executable):
        self.process = subprocess.Popen([executable], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.count = 0

    def request(self, data, profile):
        if not data or len(data) > 65535:
            raise ValueError("Fixture exceeds the corpus adapter's input limit")
        self.process.stdin.write(struct.pack(">BI", profile, len(data)) + data)
        self.process.stdin.flush()
        nodes = []
        while True:
            line = self.process.stdout.readline().decode("ascii").split()
            if not line:
                raise RuntimeError("Corpus adapter stopped unexpectedly")
            if line[0] == "R":
                self.count += 1
                return int(line[1]), nodes
            _, offset, depth, header, length, tag = line
            start, size = int(offset) + int(header), int(length)
            nodes.append((int(depth), tag, start, size))

    def read(self, data, profile=0):
        result, nodes = self.request(data, profile)
        return result, [(depth, tag, data[start:start + size]) for depth, tag, start, size in nodes]

    def close(self):
        self.process.stdin.close()
        if self.process.wait() != 0:
            raise RuntimeError("Corpus adapter failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", required=True)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--mbedtls-suite", type=Path,
                        help="External test_suite_asn1parse.data from the pinned revision")
    args = parser.parse_args()
    reader = Reader(args.reader)
    failures = []
    certificates = 0
    cvc_answers = 0
    try:
        if args.mbedtls_suite:
            external_lengths(reader, args.mbedtls_suite)
        if not args.corpus:
            if not args.mbedtls_suite:
                raise ValueError("Select --corpus or --mbedtls-suite")
            return
        # These source collections contain encoded objects, including certificates
        # with deliberately bad signatures/policies. Those are still valid TLVs.
        for directory in (args.corpus / "x509/nist/pkits", args.corpus / "x509/icam",
                          args.corpus / "piv/vci_trust_anchors"):
            if not directory.is_dir():
                raise ValueError("Missing corpus directory: " + str(directory))
            for path in sorted(directory.rglob("*")):
                if path.suffix.lower() not in (".der", ".crt", ".cer", ".crl", ".cp", ".pem"):
                    continue
                data = path.read_bytes()
                if b"-----BEGIN" in data:
                    blocks = [base64.b64decode(b, validate=True) for b in
                              (re.sub(rb"\s", b"", b) for b in re.findall(
                                  rb"-----BEGIN [^-]+-----\s*(.*?)-----END [^-]+-----", data, re.S))]
                else:
                    blocks = [data]
                for block in blocks:
                    result, _ = reader.read(block)
                    certificates += 1
                    if result != 0:
                        failures.append(f"{path}: DER framing result {result}")

        for path in sorted((args.corpus / "piv/cvc").glob("sd33_*.bin")):
            expected = json.loads(path.with_suffix(".json").read_text())
            data = path.read_bytes()
            result, nodes = reader.read(data, 1)
            if result:
                failures.append(f"{path}: ISO 7816 framing result {result}")
                continue
            fields = {(depth, tag): value.hex().upper() for depth, tag, value in nodes}
            for key, address in (("profile", (1, "5f29")), ("iin", (1, "42")),
                                 ("guid", (1, "5f20")), ("role", (1, "5f4c")),
                                 ("signature", (1, "5f37")), ("public_key_oid", (2, "06")),
                                 ("public_key_raw_hex", (2, "86"))):
                if fields.get(address) != expected[key].upper():
                    failures.append(f"{path}: wrong {key}")
            cvc_answers += 1
        if certificates < 100 or cvc_answers < 9:
            raise ValueError("Corpus is incomplete; refusing a vacuous pass")
    finally:
        reader.close()
    print(f"Checked {certificates} ASN.1 objects and {cvc_answers} CVC known answers")
    if failures:
        raise SystemExit("\n".join(failures))


def external_lengths(reader, path):
    # Mbed TLS 091fd1b18806098d74bd58ace7aacb7f171bcb42, tests/suites/test_suite_asn1parse.data.
    # Source license: Apache-2.0 OR GPL-2.0-or-later.
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != "8bd039be832dd46ebd08eb02a8ec9f72870540dfcbd15f33ae2f2bdac5f2fec4":
        raise ValueError("Unexpected Mbed TLS suite revision")
    count = 0
    for encoded, expected in re.findall(rb'^get_len:"([0-9a-fA-F]+)":([0-9]+)$', content, re.M):
        field = bytes.fromhex(encoded.decode())
        result, nodes = reader.request(b"\x04" + field, 128 | 2)
        if result != 0 or len(nodes) != 1 or nodes[0][3] != int(expected):
            raise AssertionError("Length mismatch for " + encoded.decode())
        for n in range(len(field)):
            result, _ = reader.request(b"\x04" + field[:n], 128 | 2)
            if result != 2:
                raise AssertionError("Truncated length accepted")
        count += 1
    if count != 31:
        raise ValueError("Missing external length cases")
    print(f"Checked {count} external length answers and their truncated prefixes")


if __name__ == "__main__":
    main()
