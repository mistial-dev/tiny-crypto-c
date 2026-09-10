# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Normalization mechanics and source-version checks."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "unicode_tables", Path(__file__).resolve().parents[1] / "tools/unicode_tables.py")
TABLES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TABLES)


class NormalizationTests(unittest.TestCase):
    def setUp(self):
        self.data = TABLES.NormalizationData.__new__(TABLES.NormalizationData)
        self.data.classes = {0x300: 230, 0x301: 230, 0x315: 232, 0x327: 202}
        self.data.decompositions = {0xe9: (0x65, 0x301), 0xfb01: (0x66, 0x69)}
        self.data.compositions = {(0x65, 0x301): 0xe9}
        self.data.folding = {0x41: (0x61,)}
        self.data.allowed = {0x41, 0x61, 0x65, 0xe9, 0xfb01}
        self.data.marks = {0x301, 0x315, 0x327}

    def test_hangul(self):
        for point in (0xac00, 0xac01, 0xd7a3):
            self.assertEqual(self.data.nfkc(self.data.decompose(point)), (point,))

    def test_compatibility(self):
        self.assertEqual(self.data.nfkc((0xfb01,)), (0x66, 0x69))

    def test_blocked_composition(self):
        self.assertEqual(self.data.nfkc((0x65, 0x300, 0x301)), (0x65, 0x300, 0x301))
        self.assertEqual(self.data.nfkc((0x65, 0x327, 0x301)), (0xe9, 0x327))

    def test_leading_nonstarters(self):
        self.assertEqual(self.data.nfkc((0x315, 0x301, 0x65)), (0x301, 0x315, 0x65))

    def test_empty(self):
        self.assertEqual(self.data.nfkc(()), ())

    def test_wrong_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "UnicodeData-3.2.0.txt").write_bytes(b"wrong version\n")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                TABLES.read_source(path, "UnicodeData-3.2.0.txt")

    def test_pool_shares_expansions(self):
        self.data.decompositions[0x1000] = (0xfb01,)
        pool, offsets, lengths = TABLES.decomposition_pool(self.data)
        keys = sorted(self.data.decompositions)
        for key, offset, length in zip(keys, offsets, lengths):
            self.assertEqual(tuple(pool[offset:offset + length]), self.data.decompose(key))
        self.assertEqual(offsets[keys.index(0xfb01)], offsets[keys.index(0x1000)])

    def test_c_field_width(self):
        for values in ([], [-1], [256]):
            with self.assertRaises(ValueError):
                TABLES.c_array("example", 8, values)

    def test_deterministic_tables(self):
        first = TABLES.render_tables(self.data, "UNICODE LICENSE V3\n")
        self.data.decompositions = dict(reversed(list(self.data.decompositions.items())))
        self.assertEqual(first, TABLES.render_tables(self.data, "UNICODE LICENSE V3\n"))
        self.assertIn("SPDX-License-Identifier: Unicode-3.0", first)

    def test_license(self):
        for license_text in ("", "UNICODE LICENSE V3 */"):
            with self.assertRaises(ValueError):
                TABLES.render_tables(self.data, license_text)

    def test_ranges(self):
        self.assertEqual(TABLES.ranges({5, 1, 2, 9, 8}), [(1, 2), (5, 5), (8, 9)])
        self.assertEqual(TABLES.ranges(set()), [])

    def test_wrong_stringprep_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rfc3454.txt"
            path.write_bytes(b"wrong reference\n")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                TABLES.check_stringprep(path, self.data)


if __name__ == "__main__":
    unittest.main()
