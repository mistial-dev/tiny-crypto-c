#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write acvp_onestep.inc from NIST ACVP-Server KDA OneStep corpora.

Usage: extract_acvp_onestep_vectors.py <KDA-OneStep-Sp800-56Cr1> <KDA-OneStep-Sp800-56Cr2>

Each argument is a directory holding the unchanged prompt.json and
expectedResults.json. For every revision and hash-based auxiliary function,
the script keeps the three AFT cases and the three VAL cases with the shortest
Z, breaking ties by tcId. It checks every kept case against hashlib before
writing it.
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "tests/vectors/kda/acvp_onestep.inc"
HASHES = {"SHA2-224": (224, "sha224"), "SHA2-512": (512, "sha512")}
PER_TYPE = 3
PATTERNS = {"uPartyInfo||vPartyInfo||l", "t||uPartyInfo||vPartyInfo||l"}


def load(path):
    data = json.loads(path.read_text())
    return data[-1] if isinstance(data, list) else data


def one_step(hash_name, z, fixed, length):
    out = b""
    counter = 1
    while len(out) < length:
        out += hashlib.new(hash_name, counter.to_bytes(4, "big") + z + fixed).digest()
        counter += 1
    return out[:length]


def fixed_parts(test):
    """Return the fixedInfo fields in pattern order as hex strings."""
    params = test["kdfParameter"]
    u, v = test["fixedInfoPartyU"], test["fixedInfoPartyV"]
    return [params.get("t", ""), u["partyId"], u.get("ephemeralData", ""), v["partyId"],
            v.get("ephemeralData", ""), params["l"].to_bytes(4, "big").hex()]


def cases(root):
    prompt = load(root / "prompt.json")
    expected = load(root / "expectedResults.json")
    answers = {(g["tgId"], t["tcId"]): t for g in expected["testGroups"] for t in g["tests"]}
    revision = prompt["revision"]
    for aux, (bits, hash_name) in HASHES.items():
        for test_type in ("AFT", "VAL"):
            pool = []
            for group in prompt["testGroups"]:
                config = group["kdfConfiguration"]
                if config["auxFunction"] != aux or group["testType"] != test_type:
                    continue
                if config["fixedInfoPattern"] not in PATTERNS:
                    raise SystemExit(f"{revision} tgId {group['tgId']}: unexpected fixedInfo pattern")
                for test in group["tests"]:
                    pool.append((len(test["kdfParameter"]["z"]), test["tcId"], group, test))
            for _, tc_id, group, test in sorted(pool, key=lambda item: item[:2])[:PER_TYPE]:
                answer = answers[(group["tgId"], tc_id)]
                dkm = answer["dkm"] if test_type == "AFT" else test["dkm"]
                passed = True if test_type == "AFT" else answer["testPassed"]
                parts = fixed_parts(test)
                length = test["kdfParameter"]["l"] // 8
                derived = one_step(hash_name, bytes.fromhex(test["kdfParameter"]["z"]),
                                   bytes.fromhex("".join(parts)), length)
                if (derived == bytes.fromhex(dkm)) != passed:
                    raise SystemExit(f"{revision} tcId {tc_id}: oracle disagrees with ACVP")
                yield revision, tc_id, test_type, bits, test["kdfParameter"]["z"], parts, dkm, passed


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    lines = ["/* NIST ACVP KDA OneStep hash cases. See README.md. */"]
    for root in map(Path, sys.argv[1:]):
        for revision, tc_id, test_type, bits, z, parts, dkm, passed in cases(root):
            lines.append(f"/* {revision} {test_type} tcId {tc_id} */")
            fields = ", ".join(f'"{part.lower()}"' for part in parts)
            lines.append(f'{{{bits}, "{z.lower()}", {{{fields}}}, "{dkm.lower()}", {int(passed)}}},')
    OUTPUT.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
