# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Original TR-03110 format fixtures with placeholder signatures and keys."""
import argparse
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from pki_fixtures import tlv


def fixture(profile=b"\x00", issuer=b"DETEST00001", holder=b"DETEST00001", role=0xc0,
            key=None, signature=b"\x01\x01", effective=bytes([2,6,0,1,0,1]),
            expiration=bytes([3,0,0,1,0,1]), extensions=b""):
    if key is None:
        key = tlv(0x7f49, tlv(6, bytes.fromhex("04007f00070202020101")) +
                  tlv(0x81, b"\x0c\xa1") + tlv(0x82, b"\x11"))
    body = tlv(0x7f4e, tlv(0x5f29, profile) + tlv(0x42, issuer) + key + tlv(0x5f20, holder) +
               tlv(0x7f4c, tlv(6, bytes.fromhex("04007f000703010202")) +
                   tlv(0x53, bytes([role,0,0,0,0]))) +
               tlv(0x5f25, effective) + tlv(0x5f24, expiration) + extensions)
    return tlv(0x7f21, body + tlv(0x5f37, signature)), body


class EAC(unittest.TestCase):
    def read(self, data):
        output = subprocess.check_output([str(READER), "-"], input=data).decode()
        return dict(line.split("=", 1) for line in output.splitlines())

    def test_rsa_fields(self):
        encoded, body = fixture()
        result = self.read(encoded)
        self.assertEqual(result["result"], "0")
        self.assertEqual(result["signed_data"], body.hex())
        self.assertEqual(result["role"], "3")
        self.assertEqual(result["self_encoding"], "0")

    def test_dates_and_references(self):
        for kwargs in ({"effective": b"260101"}, {"effective": bytes([2,6,0,2,3,0])},
                       {"expiration": bytes([2,5,1,2,3,1])}, {"issuer": b"DE\x00AB00001"},
                       {"holder": b"DETEST0000a"}, {"holder": b"DE0000"}):
            self.assertEqual(self.read(fixture(**kwargs)[0])["result"], "-1")
        self.assertEqual(self.read(fixture(holder=b"DEt\xe9st00001")[0])["result"], "0")
        self.assertEqual(self.read(fixture(effective=bytes([4,9,1,2,3,1]),
                                         expiration=bytes([5,0,0,1,0,1]))[0])["result"], "0")

    def test_unknown_extension(self):
        extension = tlv(0x65, tlv(0x73, tlv(6, b"\x2a\x03") + tlv(0x80, b"value")))
        self.assertEqual(self.read(fixture(extensions=extension)[0])["result"], "0")
        self.assertEqual(self.read(fixture(extensions=tlv(0x65, b""))[0])["result"], "-1")

    def test_invalid(self):
        self.assertEqual(self.read(fixture(profile=b"\x01")[0])["result"], "-3")
        self.assertEqual(self.read(fixture(signature=b"")[0])["result"], "-1")
        self.assertEqual(self.read(fixture()[0] + b"\x00")["result"], "-1")
        self.assertEqual(self.read(fixture(signature=b"\x01")[0])["self_encoding"], "-1")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reader", type=Path, required=True)
    args, remaining = parser.parse_known_args()
    READER = args.reader
    unittest.main(argv=[__file__] + remaining)
