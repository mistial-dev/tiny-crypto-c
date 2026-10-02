#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the text rules applied by the local pre-commit cleanup hooks."""

from pathlib import Path
import sys


def main(paths: list[str]) -> int:
    failed = False
    for name in paths:
        data = Path(name).read_bytes()
        if any(line.rstrip(b" \t") != line for line in data.splitlines()):
            print(f"{name}: trailing whitespace")
            failed = True
        if data and (not data.endswith(b"\n") or data.endswith(b"\n\n")):
            print(f"{name}: expected one final newline")
            failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
