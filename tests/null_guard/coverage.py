#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Report null-guard cases that no C test reached.

The inventory lists every generated case. The report lists the cases the
test processes ran. A case outside the report must appear in the uncovered
list, so a new public function needs a test before the check passes.
"""

import argparse
import sys
from pathlib import Path


def entries(path):
    if not path.exists():
        return set()
    lines = (line.split("#", 1)[0].strip() for line in path.read_text().splitlines())
    return {" ".join(line.split()) for line in lines if line}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--uncovered", type=Path, required=True)
    args = parser.parse_args()
    inventory = entries(args.inventory)
    reached = entries(args.report)
    if not reached:
        sys.exit(f"{args.report} is empty: run the C tests first")
    allowed = entries(args.uncovered)
    missing = sorted(inventory - reached - allowed)
    print(f"null guard: {len(reached & inventory)} of {len(inventory)} cases reached, "
          f"{len(allowed & (inventory - reached))} listed as uncovered")
    if missing:
        print("Cases without a test, add a test or list them in", args.uncovered)
        print("\n".join(missing))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
