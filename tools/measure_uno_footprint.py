#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Measure complete Uno firmware flash and static RAM, with capacity percentages."""
import argparse
import json
from pathlib import Path
import tempfile

from benchmark_report import collect, validate_host, validate_kmac_vectors
from benchmark_cases import FEATURES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        if args.validate_only:
            validate_kmac_vectors(directory)
            for name, body, flags in FEATURES:
                validate_host(directory, name, body, flags)
            return
        report = collect(directory, ["uno"])
    if args.json:
        output = json.dumps(report, indent=2) + "\n"
    else:
        lines = ["| Feature | Flash bytes | Flash % | Static RAM bytes | RAM % |",
                 "| --- | ---: | ---: | ---: | ---: |"]
        for row in report["boards"]["uno"]["rows"]:
            lines.append(f"| {row['feature']} | {row['flash']} | {row['flash_percent']:.2f}% | "
                         f"{row['static_ram']} | {row['static_ram_percent']:.2f}% |")
        output = "\n".join(lines) + "\n"
    if args.output:
        args.output.write_bytes(output.encode("utf-8"))
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
