#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Rewrite selected vector SHA256SUMS files from their current contents."""

import argparse
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests/vectors"
METADATA = {"README.md", "SHA256SUMS"}


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def update(relative):
    directory = (VECTORS / relative).resolve()
    if not directory.is_relative_to(VECTORS.resolve()) or not directory.is_dir():
        raise ValueError(f"invalid vector directory: {relative}")
    files = sorted(path for path in directory.rglob("*")
                   if path.is_file() and path.name not in METADATA)
    lines = [f"{digest(path)}  {path.relative_to(directory).as_posix()}" for path in files]
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="+", help="path below tests/vectors")
    args = parser.parse_args()
    for directory in args.directory:
        update(Path(directory))


if __name__ == "__main__":
    main()
