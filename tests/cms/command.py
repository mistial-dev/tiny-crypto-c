# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise the CMS executable with independently signed, temporary fixtures."""
import datetime
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

EXECUTABLE = str(Path(sys.argv.pop(1)).resolve())
DER = serialization.Encoding.DER
START = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
END = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)


class CMSCommand(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="tiny-crypto-cms-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
        names = [x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
                 for name in ("Root", "Issuer", "Signer")]
        self.certificates = []
        for i, key in enumerate(keys):
            issuer = max(0, i - 1)
            ca = i < 2
            certificate = (x509.CertificateBuilder()
                .subject_name(names[i]).issuer_name(names[issuer])
                .public_key(key.public_key()).serial_number(i + 1)
                .not_valid_before(START).not_valid_after(END)
                .add_extension(x509.BasicConstraints(ca, None), critical=True)
                .add_extension(x509.KeyUsage(not ca, False, False, False, False,
                                            ca, ca, False, False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    keys[issuer].public_key()), False)
                .sign(keys[issuer], hashes.SHA256()))
            self.certificates.append(certificate)
        for name, certificate in zip(("root.der", "issuer.der"), self.certificates):
            self.write(name, certificate.public_bytes(DER))
        self.keys = keys
        self.crl(0, False)
        self.crl(1, False)
        self.sign(False)

    def sign(self, capabilities):
        options = [pkcs7.PKCS7Options.Binary]
        if not capabilities:
            options.append(pkcs7.PKCS7Options.NoCapabilities)
        signed = (pkcs7.PKCS7SignatureBuilder().set_data(b"credential payload")
                  .add_signer(self.certificates[2], self.keys[2], hashes.SHA256())
                  .sign(DER, options))
        self.write("signed.der", signed)

    def write(self, name, data):
        (self.path / name).write_bytes(data)

    def crl(self, issuer, revoked):
        builder = (x509.CertificateRevocationListBuilder()
                   .issuer_name(self.certificates[issuer].subject)
                   .last_update(START).next_update(END)
                   .add_extension(x509.CRLNumber(1), False))
        if revoked:
            entry = (x509.RevokedCertificateBuilder()
                     .serial_number(self.certificates[issuer + 1].serial_number)
                     .revocation_date(START).build())
            builder = builder.add_revoked_certificate(entry)
        self.write(("root.crl", "issuer.crl")[issuer],
                   builder.sign(self.keys[issuer], hashes.SHA256()).public_bytes(DER))

    def check(self, code, output=None, time="20260908120000"):
        args = [str(self.path / name) for name in
                ("signed.der", "root.der", "issuer.der", "root.crl", "issuer.crl")]
        result = subprocess.run([EXECUTABLE, *args, time], capture_output=True,
                                text=True, timeout=60)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        if output is not None:
            self.assertEqual(result.stdout.strip(), output)

    def test_valid(self):
        self.check(0, "valid")

    def test_smime_capabilities(self):
        self.sign(True)
        self.check(0, "valid")

    def test_revoked_signer(self):
        self.crl(1, True)
        self.check(1, "revoked")

    def test_revoked_issuer(self):
        self.crl(0, True)
        self.check(1, "revoked")

    def test_expired(self):
        self.check(1, "invalid", "20310101000000")

    def test_malformed_cms(self):
        self.write("signed.der", b"\x30\x80")
        self.check(1)

    def test_bad_signature(self):
        data = bytearray((self.path / "signed.der").read_bytes())
        data[-1] ^= 1
        self.write("signed.der", data)
        self.check(1, "invalid")

    def test_input_errors(self):
        self.check(2, time="20260230000000")
        self.write("root.crl", b"\x30\x00")
        self.check(2)
        self.write("signed.der", b"x" * 16385)
        self.check(2)


if __name__ == "__main__":
    unittest.main()
