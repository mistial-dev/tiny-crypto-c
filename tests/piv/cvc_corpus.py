# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check every captured PIV SM CVC and every complete VCI chain fixture."""
import argparse
import json
from pathlib import Path
import struct
import subprocess


PARSE_ONLY = 0
ACCEPTED = 1
REJECTED = 2


def metadata_values(metadata):
    curve_oid = metadata.get("public_key_curve_oid") or metadata.get("public_key_oid")
    curve = {"1.2.840.10045.3.1.7": 1, "2A8648CE3D030107": 1,
             "1.3.132.0.34": 2, "2B81040022": 2}[curve_oid]
    issuer = bytes.fromhex(metadata.get("iin"))
    subject = bytes.fromhex(metadata.get("subject_identifier") or metadata.get("guid"))
    role = int(metadata["role"], 16)
    if len(issuer) != 8 or len(subject) not in (8, 16) or role not in (0, 0x12):
        raise AssertionError(f"Unexpected CVC metadata: {metadata}")
    return curve, role, issuer, subject


def record(verdict, cvc, metadata, intermediate=b"", certificate=b""):
    curve, role, issuer, subject = metadata_values(metadata)
    header = struct.pack(">BBBBIII8s16s", verdict, curve, role, len(subject), len(cvc),
                         len(intermediate), len(certificate), issuer, subject.ljust(16, b"\0"))
    return header + cvc + intermediate + certificate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    args = parser.parse_args()
    cvc_root = args.corpus / "cvc"
    chain_root = args.corpus / "vci_trust_anchors"
    demo_root = args.corpus / "piv_auto_demo"
    records = bytearray()

    captures = sorted(cvc_root.glob("*.bin"))
    if len(captures) != 10:
        raise AssertionError(f"Expected 10 distinct captured CVCs, found {len(captures)}")
    for path in captures:
        metadata_path = path.with_suffix(".json")
        if not metadata_path.exists():
            metadata_path = path.with_suffix(".metadata.json")
        metadata = json.loads(metadata_path.read_text())
        metadata = metadata.get("secure_cvc", metadata)
        encoded = path.read_bytes()
        if metadata.get("length", len(encoded)) != len(encoded):
            raise AssertionError(f"Declared length changed: {path}")
        records.extend(record(PARSE_ONLY, encoded, metadata))

    reports = sorted(chain_root.glob("*/validation-report.json"))
    if len(reports) != 5:
        raise AssertionError(f"Expected five VCI chain reports, found {len(reports)}")
    direct = intermediate_count = 0
    for report_path in reports:
        report = json.loads(report_path.read_text())
        if not report["result"]["passed"] or report["summary"]["status"] != "passed":
            raise AssertionError(f"Corpus report is not accepted: {report_path}")
        directory = report_path.parent
        cvc = (directory / "secure-messaging-cvc-7f21.bin").read_bytes()
        certificate = (directory / "content-signing-certificate.der").read_bytes()
        if report["cvc"]["length"] != len(cvc):
            raise AssertionError(f"Declared CVC length changed: {report_path}")
        intermediate_path = directory / "intermediate-cvc-7f21.bin"
        intermediate = intermediate_path.read_bytes() if intermediate_path.exists() else b""
        declared_intermediate = report["intermediate_cvc"]
        if bool(intermediate) != bool(declared_intermediate):
            raise AssertionError(f"Intermediate declaration changed: {report_path}")
        if intermediate and declared_intermediate["length"] != len(intermediate):
            raise AssertionError(f"Declared intermediate length changed: {report_path}")
        # SP 800-73-5 Part 2, Table 20 requires the intermediate subject to
        # equal the first eight SHA-1 bytes of its public-key object. These
        # upstream reports omit that check, so both intermediate paths reject.
        verdict = REJECTED if intermediate else ACCEPTED
        records.extend(record(verdict,cvc,report["cvc"],intermediate,certificate))
        if intermediate:
            intermediate_count += 1
        else:
            direct += 1

    # The simulator material is byte-identical to the card-16 capture. Its own
    # directory omits the X.509 signer, so use the matching checked-in signer.
    card16 = chain_root / "card-16-intermediate"
    demo_pairs = (("secure-card-cvc-7f21.bin", "secure-messaging-cvc-7f21.bin"),
                  ("intermediate-cvc-7f21.bin", "intermediate-cvc-7f21.bin"),
                  ("loaded-intermediate-ca-trust-anchor.bin", "vci-trust-anchor-record.bin"),
                  ("smcs-5fc122.bin", "smcs-5fc122.bin"))
    for demo_name, captured_name in demo_pairs:
        if (demo_root / demo_name).read_bytes() != (card16 / captured_name).read_bytes():
            raise AssertionError(f"Simulator provenance mismatch: {demo_name}")
    card16_report = json.loads((card16 / "validation-report.json").read_text())
    records.extend(record(REJECTED,(demo_root / "secure-card-cvc-7f21.bin").read_bytes(),
        card16_report["cvc"],(demo_root / "intermediate-cvc-7f21.bin").read_bytes(),
        (card16 / "content-signing-certificate.der").read_bytes()))
    intermediate_count += 1

    print(f"Checking {len(captures)} parse-only captures, {direct} accepted direct chains, "
          f"and {intermediate_count} rejected intermediate chains", flush=True)
    subprocess.run([str(args.reader)], input=records, check=True)


if __name__ == "__main__":
    main()
