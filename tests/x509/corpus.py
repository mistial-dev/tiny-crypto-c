# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise DER certificate parsing with external certificate fixtures."""
import argparse
import base64
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    args = parser.parse_args()
    files = list((args.corpus / "nist/pkits/certs").glob("*.crt"))
    files += list((args.corpus / "piv/sd33").glob("*.der"))
    files += list((args.corpus / "rfc").glob("rfc5280_cert*.cer"))
    if len(files) < 400:
        raise AssertionError("Incomplete certificate corpus")
    failures = []
    # These PKITS signatures have an unused-bit count of one. RSA and DSA
    # signature encodings require whole octets (RFC 3279 sections 2.2.1/2.2.2).
    unaligned_signatures = {"BadSignedCACert.crt": 645, "InvalidDSASignatureTest6EE.crt": 789}
    for path in sorted(files):
        data = path.read_bytes()
        pem = re.search(rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", data, re.S)
        if pem:
            data = base64.b64decode(re.sub(rb"\s", b"", pem.group(1)), validate=True)
        output = subprocess.check_output([str(args.reader), "-"], input=data).decode()
        fields = dict(line.split("=", 1) for line in output.splitlines())
        expected = "0"
        if path.name in unaligned_signatures:
            if data[unaligned_signatures[path.name]] != 1:
                raise AssertionError(f"Changed PKITS signature fixture: {path}")
            expected = "-1"
        if fields["result"] != expected:
            failures.append(f"{path}: {fields['result']}")
    if failures:
        raise AssertionError("\n".join(failures))
    print(f"Checked {len(files)} RFC, PKITS, and PIV certificates, including two malformed signatures")


if __name__ == "__main__":
    main()
