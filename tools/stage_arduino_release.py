#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Stage the bounded tree used for Arduino and PlatformIO releases."""

import argparse
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_FILES = (
    Path("LICENSE"),
    Path("README.md"),
    Path("library.json"),
    Path("library.properties"),
)
PACKAGE_TREES = (
    Path("LICENSES"),
    Path("src"),
    Path("examples/AESCTR"),
    Path("examples/SHA256"),
)


def package_paths(root=ROOT):
    """Return every source-tree file that belongs in an embedded package."""
    files = [root / path for path in PACKAGE_FILES]
    for relative in PACKAGE_TREES:
        files.extend(path for path in (root / relative).rglob("*") if path.is_file())
    return sorted(files)


def stage(destination, root=ROOT):
    """Copy the package allowlist into an empty destination directory."""
    destination = destination.resolve()
    if destination == root.resolve() or root.resolve() in destination.parents:
        raise ValueError("destination must be outside the source tree")
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("destination must be absent or empty")
    destination.mkdir(parents=True, exist_ok=True)
    for source in package_paths(root):
        relative = source.relative_to(root)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    stage(args.destination)


if __name__ == "__main__":
    main()
