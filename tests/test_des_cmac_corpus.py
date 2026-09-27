# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the unmodified NIST CAVP TDES CMAC response files."""
import hashlib
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent / "vectors/des/cmac"
FILES = {
    "CMACGenTDES2.rsp": ("fdadebc3a619760846872187bcf64278f7d6fe5fda201966d9e7e69c706a5146", 96),
    "CMACGenTDES3.rsp": ("d47f1aeb65ad3dd97988bb57f6d24a9524a8c60383aa81408683df199d3cdc7b", 96),
    "CMACVerTDES2.rsp": ("c44b511f1baa8b4cd8f3f9722ef57c8e4f9fc91738e68a28d0f0f9d74c65900f", 360),
    "CMACVerTDES3.rsp": ("905eef565ee9e3757873775f757cb9b5421b18c8d8d429d6db2a8a837892a5c2", 240),
}


class Corpus(unittest.TestCase):
    def test_pinned_files(self):
        for name, (digest, cases) in FILES.items():
            with self.subTest(name=name):
                content = (ROOT / name).read_bytes()
                self.assertEqual(hashlib.sha256(content).hexdigest(), digest)
                self.assertEqual(len(re.findall(rb"(?m)^Count = ", content)), cases)


if __name__ == "__main__":
    unittest.main()
