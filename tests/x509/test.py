# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Original RFC 5280 encoding fixtures; signatures are placeholders."""
import argparse
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from pki_fixtures import certificate, extension, name, seq, tlv


class Schema(unittest.TestCase):
    def read(self, data, limits=()):
        output = subprocess.check_output([str(READER), "-", *map(str, limits)], input=data).decode()
        return dict(line.split("=", 1) for line in output.splitlines())

    def test_fields(self):
        result = self.read(certificate())
        self.assertEqual(result["result"], "0")
        self.assertEqual(result["version"], "3")
        self.assertEqual(result["serial"], "01")
        self.assertEqual(result["key_bits"], "12")
        self.assertEqual(result["key_oid"], "2a864886f70d010101")
        self.assertEqual(result["signature_oid"], "2a864886f70d01010b")

    def test_pss_parameters(self):
        oid = tlv(6, bytes.fromhex("2a864886f70d01010a"))
        sha1 = seq(tlv(6, bytes.fromhex("2b0e03021a")), tlv(5, b""))
        sha256 = seq(tlv(6, bytes.fromhex("608648016503040201")))
        mgf = tlv(6, bytes.fromhex("2a864886f70d010108"))
        explicit = [tlv(0xa0, sha256), tlv(0xa1, seq(mgf, sha256)), tlv(0xa2, tlv(2, b"\x20"))]
        for parameters in (seq(), seq(*explicit), seq(tlv(0xa0, sha1)),
                           seq(tlv(0xa1, seq(mgf, sha1))), seq(tlv(0xa3, tlv(2, b"\x01"))),
                           seq(tlv(0xa2, tlv(2, b"\x00")))):
            for argument in ("signature_algorithm", "public_key_algorithm"):
                with self.subTest(parameters=parameters.hex(), argument=argument):
                    self.assertEqual(self.read(certificate(**{argument: seq(oid, parameters)}))["result"], "0")
        self.assertEqual(self.read(certificate(public_key_algorithm=seq(oid)))["result"], "0")
        self.assertEqual(self.read(certificate(signature_algorithm=seq(oid)))["result"], "-1")
        for parameters in (tlv(5, b""), seq(*reversed(explicit)), seq(explicit[0], explicit[0]),
                           seq(tlv(0xa4, sha1)), seq(tlv(0x80, sha1)),
                           seq(tlv(0xa0, sha1 + sha1)), seq(tlv(0xa1, seq(mgf))),
                           seq(tlv(0xa2, tlv(2, b"\xff"))), seq(tlv(0xa2, tlv(2, b"\x00\x01"))),
                           seq(tlv(0xa3, tlv(2, b"\x02")))):
            for argument in ("signature_algorithm", "public_key_algorithm"):
                with self.subTest(parameters=parameters.hex(), argument=argument):
                    self.assertEqual(self.read(certificate(**{argument: seq(oid, parameters)}))["result"], "-1")

    def test_workspace_limits(self):
        plain = certificate()
        extended = certificate(extensions=[extension("551d13", seq()),
                                           extension("551d0f", tlv(3, b"\x07\x80"))])
        self.assertEqual(self.read(plain, (len(plain), 8192, 32, 0))["result"], "0")
        self.assertEqual(self.read(plain, (len(plain) - 1, 8192, 32, 0))["result"], "-2")
        self.assertEqual(self.read(plain, (len(plain), 8192, 0, 0))["result"], "-2")
        self.assertEqual(self.read(plain, (len(plain), 1, 32, 0))["result"], "-2")
        self.assertEqual(self.read(extended, (len(extended), 8192, 32, 2))["result"], "0")
        for capacity in (0, 1):
            self.assertEqual(self.read(extended, (len(extended), 8192, 32, capacity))["result"], "-2")

    def test_validity_encodings(self):
        for tag, date, decoded in (
                (0x17, b"500101000000Z", "19500101000000Z"),
                (0x17, b"491231235959Z", "20491231235959Z"),
                (0x18, b"19500101000000Z", "19500101000000Z"),
                (0x18, b"20300101000000Z", "20300101000000Z"),
                (0x18, b"20500101000000Z", "20500101000000Z")):
            with self.subTest(date=date):
                result = self.read(certificate(validity=seq(tlv(tag, date), tlv(0x18, b"99991231235959Z"))))
                self.assertEqual(result["result"], "0")
                self.assertEqual(result["not_before"], decoded)
        for date in (b"20300229000000Z", b"20300101240000Z", b"20300101000000+0000",
                     b"20300101000000.0Z", b"203001010000Z"):
            with self.subTest(date=date):
                self.assertEqual(self.read(certificate(validity=seq(tlv(0x18, date),
                    tlv(0x18, b"99991231235959Z"))))["result"], "-1")

    def test_large_unknown_oid(self):
        oid = b"\x2a" + b"\xff" * 12 + b"\x7f"
        result = self.read(certificate(signature_algorithm=seq(tlv(6, oid))))
        self.assertEqual(result["result"], "0")
        self.assertEqual(result["signature_oid"], oid.hex())

    def test_name_encodings(self):
        for value, tag in ((b"Example", 0x13), ("漢字".encode(), 0x0c),
                           ("Example".encode("utf-16-be"), 0x1e),
                           ("Example".encode("utf-32-be"), 0x1c), (b"Example", 0x14)):
            with self.subTest(tag=tag):
                self.assertEqual(self.read(certificate(subject=name(value, tag)))["result"], "0")

    def test_invalid_names(self):
        malformed = [seq(), seq(tlv(0x31, b"")), seq(tlv(0x31, tlv(2, b"\x01"))),
                     name(b"", 0x0c), name(b"\xc0\xaf"), name(b"\xed\xa0\x80"),
                     name(b"\xf4\x90\x80\x80"), name(b"\xe2\x82"), name(b"\xff", 0x13),
                     name(b"\x00", 0x1e), name(b"\xd8\x00", 0x1e)]
        for value in malformed:
            with self.subTest(value=value.hex()):
                self.assertEqual(self.read(certificate(issuer=value))["result"], "-1")

    def test_rdn_order(self):
        a = seq(tlv(6, bytes.fromhex("550403")), tlv(0x0c, b"A"))
        b = seq(tlv(6, bytes.fromhex("550403")), tlv(0x0c, b"B"))
        self.assertEqual(self.read(certificate(subject=seq(tlv(0x31, a + b))))["result"], "0")
        self.assertEqual(self.read(certificate(subject=seq(tlv(0x31, b + a))))["result"], "-1")

    def test_extensions(self):
        bc = extension("551d13", seq(tlv(1, b"\xff"), tlv(2, b"\x00")), 255)
        ku = extension("551d0f", tlv(3, b"\x02\x84"), 255)
        self.assertEqual(self.read(certificate(extensions=[bc, ku]))["result"], "0")
        self.assertEqual(self.read(certificate(extensions=[bc, ku, bc]))["result"], "-1")
        self.assertEqual(self.read(certificate(extensions=[]))["result"], "-1")
        for ext in [extension("551d13", seq(tlv(1, b"\x00"))),
                    extension("551d13", seq(tlv(2, b"\x01"))),
                    extension("551d13", seq(), 0), extension("551d13", seq(), 1),
                    extension("551d0f", tlv(3, b"\x00\x80")),
                    extension("551d0f", tlv(3, b"\x00"))]:
            with self.subTest(extension=ext.hex()):
                self.assertEqual(self.read(certificate(extensions=[ext]))["result"], "-1")

    def test_embedded_der_limits(self):
        value = seq(*[tlv(5, b"") for _ in range(1000)])
        extensions = [extension(f"2a03{i:02x}", value) for i in range(9)]
        self.assertEqual(self.read(certificate(extensions=extensions[:8]))["result"], "0")
        self.assertEqual(self.read(certificate(extensions=extensions))["result"], "-2")
        deep = tlv(5, b"")
        for _ in range(40):
            deep = seq(deep)
        self.assertEqual(self.read(certificate(extensions=[extension("2a0301", deep)]))["result"], "-2")
        for malformed in (b"", b"\x05\x00\x05\x00", b"\x30\x02\x04\x01"):
            self.assertEqual(self.read(certificate(extensions=[extension("2a0301", malformed)]))["result"], "-1")

    def test_subject_alt_names(self):
        san = seq(tlv(0x82, b"example.com"), tlv(0x87, bytes([192,0,2,1])))
        self.assertEqual(self.read(certificate(subject=seq(), extensions=[extension("551d11", san, 255)]))["result"], "0")
        self.assertEqual(self.read(certificate(subject=seq(), extensions=[extension("551d11", san)]))["result"], "-1")
        self.assertEqual(self.read(certificate(subject=seq()))["result"], "-1")
        for value in [seq(), seq(tlv(0x87, b"12345")), seq(tlv(0x87, b"12345678")),
                      seq(tlv(0x89, b"x")), seq(tlv(0x82, b"")), seq(tlv(0x82, b" ")),
                      seq(tlv(0x82, b"a\x00b")), seq(tlv(0x82, b"\xc3\xa9.com"))]:
            with self.subTest(value=value.hex()):
                self.assertEqual(self.read(certificate(extensions=[extension("551d11", value)]))["result"], "-1")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reader", type=Path, required=True)
    arguments, remaining = parser.parse_known_args()
    READER = arguments.reader
    unittest.main(argv=[__file__] + remaining)
