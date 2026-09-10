# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run reviewed C2SP x509-limbo and NIST PKITS path/CRL cases."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


CORPUS_SHA256 = "b9ad397ffefd3622dbf420fac3d45d156fabed69f5fabaa391c3b8bb91aae31f"
MAX_CERTIFICATES = 16
MAX_CRLS = 16
DEFAULT_VALIDATION_TIME = "2024-01-01T00:00:00+00:00"
LIMBO_CASES = {
    "crl::revoked-certificate-with-crl": ("valid", "revoked", "direct-anchor-revoked"),
    "crl::crlnumber-missing": ("valid", "unsupported", "missing-crl-number"),
    "crl::certificate-not-on-crl": ("valid", "unrevoked", "absent-serial"),
    "crl::certificate-serial-on-crl-different-issuer":
        ("valid", "unrevoked", "same-serial-different-issuer"),
    "crl::crlnumber-critical": ("valid", "invalid", "critical-crl-number"),
    "crl::issuer-missing-crlsign": ("valid", "invalid", "missing-crl-sign-usage"),
    "crl::issuer-no-keyusage-extension": ("valid", "unrevoked", "absent-key-usage"),
    "crl::issuer-valid-crlsign-and-keycertsign":
        ("valid", "unrevoked", "valid-crl-sign-usage"),
    "cve::cve-2024-0567": ("valid", None, "cross-sign-cycle"),
    "pathological::multiple-chains-expired-intermediate": ("valid", None, "alternate-expired-dead-end"),
    "pathological::intermediate-cycle-distinct-cas": ("invalid", None, "cycle-distinct-ca"),
    "pathological::intermediate-cycle-same-logical-ca": ("invalid", None, "cycle-same-name-key"),
    "invalid::invalid-issuer-key": ("invalid", None, "wrong-issuer-key"),
    "pathological::pathological-chain-same-subject-distinct-key":
        ("limit", None, "same-name-distinct-key-bounded"),
    "rfc5280::nc::nc-forbids-alternate-chain-ica": ("valid", None, "alternate-constrained-intermediate"),
}

PKITS_CASES = {
    "ValidCertificatePathTest1": {
        "target": "certs/ValidCertificatePathTest1EE.crt",
        "candidates": ["certs/GoodCACert.crt"],
        "anchors": ["certs/TrustAnchorRootCertificate.crt"],
        "crls": ["crls/TrustAnchorRootCRL.crl", "crls/GoodCACRL.crl"],
        "validation_time": "2024-01-01T00:00:00+00:00",
        "expected": ("valid", "unrevoked", "complete-root-and-ca-crls"),
        "sha256": {
            "certs/ValidCertificatePathTest1EE.crt":
                "967ed7ed2be0506b82000a377751c5525619d3b9e7fed8a0e7aa554947af5e9e",
            "certs/GoodCACert.crt":
                "86d218374763fce77d5b2b45398db48f10e553da1875be7d6103085baca0343f",
            "certs/TrustAnchorRootCertificate.crt":
                "87d1dfcc73f979bb348bb4f159d9115c40ab0a9afc4b21d77e6ddf20c7782b89",
            "crls/TrustAnchorRootCRL.crl":
                "2bd174a338a482986bf54a9f8fa36b0ec8f6e4bb49b35fa3ebbe5afd8fa4879a",
            "crls/GoodCACRL.crl":
                "d78e5eca421f082f55bf1c25ddf697111be3eeee0d395e339f1b97711ee2b496",
        },
    },
}

def der(pem, label):
    match = re.fullmatch(
        rf"\s*-----BEGIN {label}-----\s*(.*?)\s*-----END {label}-----\s*", pem, re.S)
    if not match:
        raise AssertionError(f"Invalid {label} PEM")
    return base64.b64decode(re.sub(r"\s", "", match.group(1)), validate=True)


def run_values(reader, directory, values, expected, validation_time):
    environment = dict(os.environ)
    for name in list(environment):
        if name.startswith("TC_X509_"):
            del environment[name]
    for name, data in values:
        path = directory / name
        path.write_bytes(data)
        environment[name] = str(path)
    environment["TC_X509_EXPECT_PATH"] = expected[0]
    parsed_time = datetime.fromisoformat(validation_time)
    if parsed_time.utcoffset() != timezone.utc.utcoffset(parsed_time):
        raise AssertionError("Validation time must be UTC")
    environment["TC_X509_AT"] = parsed_time.strftime("%Y%m%d%H%M%S")
    if expected[1]:
        environment["TC_X509_EXPECT_REVOCATION"] = expected[1]
    subprocess.run([str(reader), "/x509/path-corpus/case"], env=environment, check=True,
                   stdout=subprocess.DEVNULL)


def run_limbo_case(reader, directory, case, expected):
    if (expected[1] and
            len(case["untrusted_intermediates"]) + len(case["trusted_certs"]) > MAX_CERTIFICATES):
        raise AssertionError("Revocation signer inputs exceed the reader limit")
    if len(case["crls"]) > MAX_CRLS:
        raise AssertionError("CRL inputs exceed the reader limit")
    values = [("TC_X509_TARGET", der(case["peer_certificate"], "CERTIFICATE"))]
    for prefix, key, label in (
            ("TC_X509_CANDIDATE", "untrusted_intermediates", "CERTIFICATE"),
            ("TC_X509_ANCHOR", "trusted_certs", "CERTIFICATE"),
            ("TC_X509_CRL", "crls", "X509 CRL")):
        for index, pem in enumerate(case[key]):
            values.append((f"{prefix}_{index}", der(pem, label)))
    run_values(reader, directory, values, expected,
               case["validation_time"] or DEFAULT_VALIDATION_TIME)


def checked_pkits_file(root, relative, expected_hash):
    data = (root / relative).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_hash:
        raise AssertionError(f"NIST PKITS file changed: {relative}")
    return data


def run_pkits_case(reader, directory, root, case):
    if len(case["candidates"]) + len(case["anchors"]) > MAX_CERTIFICATES:
        raise AssertionError("Revocation signer inputs exceed the reader limit")
    if len(case["crls"]) > MAX_CRLS:
        raise AssertionError("CRL inputs exceed the reader limit")
    hashes = case["sha256"]
    values = [("TC_X509_TARGET", checked_pkits_file(root, case["target"], hashes[case["target"]]))]
    for prefix, key in (("TC_X509_CANDIDATE", "candidates"),
                        ("TC_X509_ANCHOR", "anchors"), ("TC_X509_CRL", "crls")):
        for index, relative in enumerate(case[key]):
            values.append((f"{prefix}_{index}", checked_pkits_file(root, relative, hashes[relative])))
    run_values(reader, directory, values, case["expected"], case["validation_time"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    args = parser.parse_args()
    source = args.corpus / "limbo" / "limbo-core.json"
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != CORPUS_SHA256:
        raise AssertionError("C2SP x509-limbo core corpus changed")
    manifest = json.loads(data)["testcases"]
    selected = {case["id"]: case for case in manifest if case["id"] in LIMBO_CASES}
    if selected.keys() != LIMBO_CASES.keys():
        raise AssertionError("Reviewed x509-limbo cases are missing")
    for case_id, expected in LIMBO_CASES.items():
        case = selected[case_id]
        combined = "invalid" if expected[0] == "limit" or expected[1] in (
            "revoked", "invalid", "unsupported") else expected[0]
        upstream = "valid" if case["expected_result"] == "SUCCESS" else "invalid"
        if upstream != combined:
            raise AssertionError(f"Changed upstream verdict: {case_id}")
        try:
            with tempfile.TemporaryDirectory(prefix="tiny-crypto-path-corpus-") as temporary:
                run_limbo_case(args.reader, Path(temporary), case, expected)
        except subprocess.CalledProcessError as error:
            raise AssertionError(f"Native corpus case failed: {case_id}") from error
    pkits_root = args.corpus / "nist" / "pkits"
    for case_id, case in PKITS_CASES.items():
        try:
            with tempfile.TemporaryDirectory(prefix="tiny-crypto-path-corpus-") as temporary:
                run_pkits_case(args.reader, Path(temporary), pkits_root, case)
        except subprocess.CalledProcessError as error:
            raise AssertionError(f"Native corpus case failed: NIST PKITS {case_id}") from error
    path_count = sum(expected[1] is None for expected in LIMBO_CASES.values())
    revocation_categories = sorted(
        [expected[2] for expected in LIMBO_CASES.values() if expected[1]] +
        [case["expected"][2] for case in PKITS_CASES.values()])
    print(f"Checked {path_count} pinned x509-limbo path cases")
    print(f"Checked {len(revocation_categories)} pinned revocation cases: "
          f"{', '.join(revocation_categories)}")


if __name__ == "__main__":
    main()
