# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""TC_work_budget.remaining is 32 bits. On 16-bit targets size_t is narrower,
so RSA, EC and key-challenge code keeps work in uint32_t end to end. Copying the
budget into a size_t, or passing work as size_t*, would truncate it."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = sorted(list((ROOT / "src").glob("rsa*.[ch]")) +
                 [ROOT / "src" / "ec.c", ROOT / "src" / "key_challenge.c"])
PATTERNS = (
    re.compile(r"\bsize_t\s*\*\s*work\b"),
    re.compile(r"\bsize_t\s+\w+\s*=\s*[\w.>-]*(?:->|\.)remaining\b"),
)


class WorkBudgetWidth(unittest.TestCase):
    def test_sources_cover_every_uint32_budget_module(self):
        for name in ("ec.c", "key_challenge.c", "rsa_public.c", "rsa_private.c"):
            self.assertIn(ROOT / "src" / name, SOURCES)

    def test_asymmetric_work_is_32_bit(self):
        findings = []
        for path in SOURCES:
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if any(pattern.search(line) for pattern in PATTERNS):
                    findings.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
        self.assertEqual(findings, [], "\n".join(findings))


if __name__ == "__main__":
    unittest.main()
