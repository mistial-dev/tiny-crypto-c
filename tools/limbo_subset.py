#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Split the upstream x509-limbo corpus into the two files vendored here.

The full ``limbo.json`` is ~39 MB, 97 % of which is the machine-generated
``bettertls::`` name-constraint suite.  We keep every hand-written testcase
(``rfc5280::``, ``webpki::``, ``pathological::`` ...) verbatim in
``limbo-core.json`` and a deterministic, stratified sample of the
``bettertls::`` cases in ``limbo-bettertls-sample.json``.  Both files keep the
upstream schema so a runner written for ``limbo.json`` works unchanged.

Usage: tools/limbo_subset.py limbo.json OUT_DIR [--bettertls N]
"""
import argparse
import json
import pathlib
import random


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("limbo_json", type=pathlib.Path)
    ap.add_argument("out_dir", type=pathlib.Path)
    ap.add_argument("--bettertls", type=int, default=200, help="bettertls cases to sample")
    ap.add_argument("--seed", type=int, default=20260906)
    args = ap.parse_args()

    data = json.loads(args.limbo_json.read_text())
    core = [t for t in data["testcases"] if not t["id"].startswith("bettertls::")]
    bt = [t for t in data["testcases"] if t["id"].startswith("bettertls::")]

    rng = random.Random(args.seed)
    ok = sorted(t["id"] for t in bt if t["expected_result"] == "SUCCESS")
    bad = sorted(t["id"] for t in bt if t["expected_result"] != "SUCCESS")
    n_ok = args.bettertls // 2
    pick = set(rng.sample(ok, min(n_ok, len(ok))) + rng.sample(bad, min(args.bettertls - n_ok, len(bad))))
    sample = [t for t in bt if t["id"] in pick]

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for name, cases in (("limbo-core.json", core), ("limbo-bettertls-sample.json", sample)):
        out = {"version": data["version"], "testcases": cases}
        (args.out_dir / name).write_text(json.dumps(out, indent=1, sort_keys=False) + "\n")
        print(f"{name}: {len(cases)} testcases")


if __name__ == "__main__":
    main()
