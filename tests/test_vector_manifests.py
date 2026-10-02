# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check vendored test vectors against their SHA256SUMS manifests.

Each vector directory with a SHA256SUMS file lists every vendored file below
it in sha256sum format. The check fails when a listed file is missing or
changed, when a vector file is missing from its manifest, or when a manifest
entry escapes its directory.
"""
import hashlib
import json
from pathlib import Path
import sys
import unittest

VECTORS = Path(__file__).resolve().parent / "vectors"
UNLISTED = {"README.md", "SHA256SUMS"}
sys.path.insert(0, str(Path(__file__).resolve().parent))
from wycheproof_files import supported_vector_names  # noqa: E402


def manifest_entries(manifest):
    """Yield (digest, relative path) pairs from one SHA256SUMS file."""
    for number, line in enumerate(manifest.read_text(encoding="ascii").splitlines(), 1):
        digest, separator, name = line.partition("  ")
        if not separator or len(digest) != 64 or not name:
            raise AssertionError(f"{manifest}:{number}: malformed entry")
        yield digest, name


class Manifests(unittest.TestCase):
    def test_every_vector_file_is_covered(self):
        covered = set()
        for manifest in VECTORS.rglob("SHA256SUMS"):
            root = manifest.parent
            covered.update((root / name).resolve() for _, name in manifest_entries(manifest))
        present = {path.resolve() for path in VECTORS.rglob("*")
                   if path.is_file() and path.name not in UNLISTED}
        self.assertEqual(sorted(map(str, present - covered)), [],
                         "vector files missing from every manifest")

    def test_manifest_directories_have_readmes(self):
        missing = [str(manifest.parent.relative_to(VECTORS))
                   for manifest in VECTORS.rglob("SHA256SUMS")
                   if not (manifest.parent / "README.md").is_file()]
        self.assertEqual(missing, [])

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

    def test_wycheproof_contains_only_exercised_documents(self):
        root = VECTORS / "wycheproof"
        documents = {path.name for path in (root / "testvectors_v1").glob("*.json")}
        self.assertEqual(len(documents), 174)
        self.assertEqual(documents, supported_vector_names(documents))
        referenced = {json.loads((root / "testvectors_v1" / name).read_text())["schema"]
                      for name in documents}
        schemas = {path.name for path in (root / "schemas").glob("*.json")}
        self.assertEqual(schemas, referenced)


if __name__ == "__main__":
    unittest.main()
