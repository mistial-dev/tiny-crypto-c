#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check supported SHA-2 HKDF cases from NIST ACVP revision 1 and 2 corpora."""

import json
import subprocess
import sys
from pathlib import Path


HASHES = {
    "SHA2-224": "sha224",
    "SHA2-256": "sha256",
    "SHA2-384": "sha384",
    "SHA2-512": "sha512",
}


def fixed_info(test):
    parts = []
    for name in ("fixedInfoPartyU", "fixedInfoPartyV"):
        party = test[name]
        parts.extend((party["partyId"], party.get("ephemeralData", "")))
    parts.append(test["kdfParameter"]["l"].to_bytes(4, "big").hex())
    return "".join(parts)


def derive(reader, hash_name, params, info, length_bits):
    if length_bits <= 0 or length_bits % 8:
        raise AssertionError(f"unexpected output length: {length_bits}")
    fields = [params["z"], params["salt"], info, str(length_bits // 8)]
    if "t" in params:
        fields.append(params["t"])
    result = subprocess.run([reader, hash_name], input="\n".join(fields).encode() + b"\n",
                            capture_output=True, check=False)
    if result.returncode != 0:
        raise AssertionError(f"HKDF reader failed: {result.returncode}, {result.stderr!r}")
    return result.stdout.hex().upper()


def check_revision(reader, root, revision):
    prompt = json.loads((root / revision / "prompt.json").read_text())
    expected = json.loads((root / revision / "expectedResults.json").read_text())
    assert prompt["algorithm"] == expected["algorithm"] == "KDA"
    assert prompt["mode"] == expected["mode"] == "HKDF"
    assert prompt["revision"] == expected["revision"]
    groups = {group["tgId"]: group for group in expected["testGroups"]}
    assert len(groups) == len(prompt["testGroups"])
    counts = {"passed": 0, "rejected": 0, "skipped": 0, "multi": 0}
    for group in prompt["testGroups"]:
        answers = {test["tcId"]: test for test in groups[group["tgId"]]["tests"]}
        assert len(answers) == len(group["tests"])
        config = group.get("kdfConfiguration", group.get("kdfMultiExpansionConfiguration"))
        hash_name = HASHES.get(config["hmacAlg"])
        for test in group["tests"]:
            answer = answers[test["tcId"]]
            if hash_name is None:
                counts["skipped"] += 1
                continue
            try:
                if group.get("multiExpansion", False):
                    params = test["kdfMultiExpansionParameter"]
                    actual = [derive(reader, hash_name, params, iteration["fixedInfo"],
                                     iteration["l"])
                              for iteration in params["iterationParameters"]]
                    supplied = test.get("dkms")
                    expected_value = answer.get("dkms")
                    counts["multi"] += 1
                else:
                    params = test["kdfParameter"]
                    actual = derive(reader, hash_name, params, fixed_info(test), params["l"])
                    supplied = test.get("dkm")
                    expected_value = answer.get("dkm")
            except AssertionError as exc:
                raise AssertionError((revision, group["tgId"], test["tcId"], hash_name)) from exc
            if group["testType"] == "AFT":
                assert actual == expected_value, (revision, group["tgId"], test["tcId"])
                counts["passed"] += 1
            else:
                valid = actual == supplied
                assert valid == answer["testPassed"], (revision, group["tgId"], test["tcId"])
                counts["passed" if valid else "rejected"] += 1
    return counts


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: hkdf_acvp.py READER CORPUS_DIR")
    root = Path(sys.argv[2])
    for revision in ("r1", "r2"):
        counts = check_revision(sys.argv[1], root, revision)
        expected_counts = ({"passed": 360, "rejected": 40, "skipped": 600, "multi": 0}
                           if revision == "r1" else
                           {"passed": 720, "rejected": 80, "skipped": 1200, "multi": 400})
        assert counts == expected_counts, (revision, counts)
        print(f"{revision}: {counts}")


if __name__ == "__main__":
    main()
