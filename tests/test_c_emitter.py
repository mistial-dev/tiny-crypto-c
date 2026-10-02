# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Regression tests for generated C byte-array formatting."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from c_emitter import byte_array


class ByteArrayTests(unittest.TestCase):
    def test_empty_array_keeps_addressable_storage(self):
        self.assertEqual(
            byte_array("empty", b""),
            "static const uint8_t empty[1] = { 0x00 }; /* empty, length 0 */\n",
        )

    def test_default_layout_is_stable(self):
        self.assertEqual(
            byte_array("value", bytes(range(14))),
            "static const uint8_t value[14] = {\n"
            "  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,\n"
            "  0x0c, 0x0d\n"
            "};\n",
        )


if __name__ == "__main__":
    unittest.main()
