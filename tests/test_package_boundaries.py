# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
import fnmatch
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PackageTests(unittest.TestCase):
    def test_platformio_exports(self):
        patterns = json.loads((ROOT / "library.json").read_text())["export"]["include"]
        for directory in ("tests", "tools"):
            for path in (ROOT / directory).rglob("*"):
                if path.is_file():
                    name = path.relative_to(ROOT).as_posix()
                    self.assertFalse(any(fnmatch.fnmatchcase(name, p) for p in patterns), name)
        for path in (ROOT / "src").rglob("*"):
            if path.is_file() and path.suffix in (".h", ".hpp", ".c", ".inc"):
                name = path.relative_to(ROOT).as_posix()
                self.assertTrue(any(fnmatch.fnmatchcase(name, p) for p in patterns), name)
        self.assertTrue(any(fnmatch.fnmatchcase("LICENSES/Unicode-3.0.txt", p)
                            for p in patterns))

    def test_git_archive_excludes_tests(self):
        result = subprocess.run(["git", "check-attr", "export-ignore", "--",
                                 "tests", "tools", "src"], cwd=ROOT,
                                check=True, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            path, _, value = line.split(": ")
            self.assertEqual(value, "unspecified" if path == "src" else "set")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--archive":
        with tarfile.open(sys.argv[2]) as archive:
            names = set(archive.getnames())
        allowed = json.loads((ROOT / "library.json").read_text())["export"]["include"]
        for name in names:
            if not any(fnmatch.fnmatchcase(name, p) for p in allowed):
                raise SystemExit("Unexpected package member: " + name)
        if not {"src/tlv.c", "src/tiny_crypto/tlv.h", "LICENSE"} <= names:
            raise SystemExit("Package is missing product files")
    else:
        unittest.main()
