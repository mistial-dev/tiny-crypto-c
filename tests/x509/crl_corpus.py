# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check frozen CRL structure and extension encodings, not revocation status."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from munit_runner import run_reader


# RFC 5280 section 5.1.2.2, independent of OpenSSL's decoding verdict.
INVALID = {
    "crl_v2_signature_from_other_issuer.der": "inner and outer algorithms differ",
}
VALID = {
    # Despite its name and manifest description, this encodes version 2.
    "crl_v1_no_extensions.pem",
    "crl_v2_bad_signature.der", "crl_v2_ec.pem", "crl_v2_ed25519.pem",
    "crl_v2_empty.der", "crl_v2_empty.pem", "crl_v2_mldsa.pem",
    "crl_v2_nextupdate_generalizedtime.pem", "crl_v2_sha1.pem",
    "crl_v2_ten_entries_all_reasons.der", "crl_v2_ten_entries_all_reasons.pem",
}

REFERENCE_GROUPS = {
    "nist/pkits/crls": (173, "754723056ab917e6e42831698648666c25105f4189103f257dfb5f87f503f398"),
    "nist/x509tests_2001": (199, "8b0e3d8b286bc1052a4f763dccb12a646a98c42e2786a1b7e167b7fcd7a1f37b"),
    "icam/ca/crls": (55, "fce2f515d55ef2bca0538e4d06480d67e42ad5651fb697ff9ab16670717d390a"),
}
# RFC 8017 section 8.2.2: an RSA signature is an octet string of length k.
REFERENCE_INVALID = {
    "nist/pkits/crls/BadCRLSignatureCACRL.crl": "RSA signature BIT STRING has one unused bit",
}


def der_bytes(data, path):
    if data.lstrip().startswith(b"-----BEGIN"):
        match = re.fullmatch(rb"\s*-----BEGIN X509 CRL-----\s*(.*?)\s*-----END X509 CRL-----\s*", data, re.S)
        if not match:
            raise AssertionError(f"Invalid CRL PEM: {path}")
        return base64.b64decode(re.sub(rb"\s", b"", match.group(1)), validate=True)
    return data


def check_case(reader, decoded, path, data, expected):
    decoded.write_bytes(der_bytes(data, path))
    environment = dict(os.environ, TC_CRL_FILE=str(decoded), TC_CRL_EXPECT=expected)
    run_reader([reader, "/x509/crl/corpus"], environment, echo=False)


def reference_cases(root):
    cases = []
    for group, (count, expected_hash) in REFERENCE_GROUPS.items():
        paths = sorted((root / group).rglob("*.crl"), key=lambda path: path.relative_to(root).as_posix())
        digest = hashlib.sha256()
        for path in paths:
            data = path.read_bytes()
            digest.update(path.relative_to(root).as_posix().encode() + b"\0")
            digest.update(hashlib.sha256(data).digest())
            cases.append((path, data))
        if len(paths) != count or digest.hexdigest() != expected_hash:
            raise AssertionError(f"Changed or incomplete CRL corpus: {group}")
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--reference-corpus", type=Path,
                        help="X.509 corpus root containing NIST and ICAM fixtures")
    args = parser.parse_args()
    entries = json.loads((args.corpus / "manifest.json").read_text())["entries"]
    entries = [entry for entry in entries if entry["kind"] == "crl"]
    names = [Path(entry["file"]).name for entry in entries]
    if len(names) != len(set(names)) or set(names) != VALID | INVALID.keys():
        raise AssertionError("CRL manifest differs from the reviewed expectation set")
    with tempfile.TemporaryDirectory(prefix="tiny-crypto-crl-") as temporary:
        decoded = Path(temporary) / "input.der"
        for entry in entries:
            path = args.corpus / entry["file"]
            data = path.read_bytes()
            if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise AssertionError(f"Changed fixture: {path}")
            try:
                check_case(args.reader, decoded, path, data, "invalid" if path.name in INVALID else "valid")
            except AssertionError as error:
                raise AssertionError(f"{path.name}: {INVALID.get(path.name, 'structurally valid')}\n{error}") from error
        if args.reference_corpus:
            cases = reference_cases(args.reference_corpus)
            case_names = {path.relative_to(args.reference_corpus).as_posix() for path, _ in cases}
            if not REFERENCE_INVALID.keys() <= case_names:
                raise AssertionError("Missing negative reference CRL case")
            failures = []
            for path, data in cases:
                name = path.relative_to(args.reference_corpus).as_posix()
                try:
                    check_case(args.reader, decoded, path, data, "invalid" if name in REFERENCE_INVALID else "valid")
                except AssertionError as error:
                    failures.append(f"{name}: {REFERENCE_INVALID.get(name, 'structurally valid')}\n{error}")
            if failures:
                raise AssertionError("\n".join(failures))
            print(f"Checked {len(cases)} NIST and ICAM CRLs, including {len(REFERENCE_INVALID)} structural rejection")
    print(f"Checked {len(VALID)} structurally valid and {len(INVALID)} invalid frozen CRLs")


if __name__ == "__main__":
    main()
