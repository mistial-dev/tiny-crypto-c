# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check frozen algorithm and malformed DER certificate fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

# These encodings are parseable. Signature validity, issuer relationships,
# policy, and curve membership require checks beyond certificate parsing.
# Name values are length-delimited, including any embedded NUL.
PARSEABLE = {
    "generalizedtime_for_2030", "resigned_generalizedtime_for_2030",
    "ext_akid_empty_keyid", "ext_akid_marked_critical", "ext_oid_single_octet",
    "resigned_cn_embedded_nul", "resigned_unique_ids", "resigned_utctime_for_2050",
    "serial_1000_bytes", "sig_last_bit_flipped", "sig_rsa_all_ff_ge_modulus",
    "sig_rsa_all_zero", "sig_rsa_one_byte_short", "sigalg_unknown_oid",
    "spki_ec_point_not_on_curve", "spki_ec_unknown_curve_oid", "subject_cn_embedded_nul",
    "subject_cn_universalstring", "tbs_serial_changed_signature_stale",
    "uids_issuer_and_subject_unique_id", "utctime_for_2050",
}
# sigalg_oid_arc_overflow changes only the outer algorithm; its inner/outer
# mismatch is rejected independently of the large OID arc.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    args = parser.parse_args()
    entries = json.loads((args.corpus / "manifest.json").read_text())["entries"]
    count = 0
    failures = []
    for entry in entries:
        path = args.corpus / entry["file"]
        if entry["kind"] != "cert" or path.suffix != ".der" or path.parent.name not in ("malformed", "algorithms"):
            continue
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise AssertionError(f"Changed fixture: {path}")
        output = subprocess.check_output([str(args.reader), "-"], input=data).decode()
        fields = dict(line.split("=", 1) for line in output.splitlines())
        parsed = fields["result"] == "0"
        expected = path.stem in PARSEABLE
        if path.parent.name == "algorithms":
            # RFC 5480 requires named curves in PKIX SubjectPublicKeyInfo.
            expected = path.stem != "root_ecp256_explicit_sha256"
        if parsed != expected:
            failures.append(f"{path.name}: result {fields['result']}; {entry['reason']}")
        count += 1
    if count < 100:
        raise AssertionError("Incomplete malformed certificate corpus")
    if failures:
        raise AssertionError("\n".join(failures))
    print(f"Checked {count} frozen algorithm and malformed DER certificates")


if __name__ == "__main__":
    main()
