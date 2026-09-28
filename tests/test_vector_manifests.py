# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check vendored test vectors against their SHA256SUMS manifests.

Each vector directory with a SHA256SUMS file lists every vendored file below
it in sha256sum format. The check fails when a listed file is missing or
changed, when a vector file is missing from its manifest, or when a manifest
entry escapes its directory.
"""
import hashlib
from pathlib import Path
import unittest

VECTORS = Path(__file__).resolve().parent / "vectors"
UNLISTED = {"README.md", "SHA256SUMS"}


def manifest_entries(manifest):
    """Yield (digest, relative path) pairs from one SHA256SUMS file."""
    for number, line in enumerate(manifest.read_text(encoding="ascii").splitlines(), 1):
        digest, separator, name = line.partition("  ")
        if not separator or len(digest) != 64 or not name:
            raise AssertionError(f"{manifest}:{number}: malformed entry")
        yield digest, name


class Manifests(unittest.TestCase):
    def test_manifests_present(self):
        self.assertTrue(list(VECTORS.rglob("SHA256SUMS")))

    def test_listed_files_match(self):
        for manifest in sorted(VECTORS.rglob("SHA256SUMS")):
            root = manifest.parent
            listed = set()
            for digest, name in manifest_entries(manifest):
                path = (root / name).resolve()
                with self.subTest(file=str(path.relative_to(VECTORS))):
                    self.assertTrue(path.is_relative_to(root.resolve()), "entry escapes its directory")
                    self.assertTrue(path.is_file(), "listed file is missing")
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
                listed.add(path)
            present = {path.resolve() for path in root.rglob("*")
                       if path.is_file() and path.name not in UNLISTED}
            with self.subTest(manifest=str(manifest.relative_to(VECTORS))):
                self.assertEqual(sorted(map(str, present - listed)), [], "files missing from the manifest")


if __name__ == "__main__":
    unittest.main()
