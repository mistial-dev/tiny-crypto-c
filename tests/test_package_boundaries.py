# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
import fnmatch
import json
import re
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def read_match(path, pattern):
    """Return the first capture group of pattern in a repository file."""
    match = re.search(pattern, (ROOT / path).read_text(), re.MULTILINE)
    if match is None:
        raise AssertionError(path + " has no version matching " + pattern)
    return match.group(1)


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

    def test_versions_match_cmake_project(self):
        version = read_match("CMakeLists.txt",
                             r"^project\(tiny-crypto-c VERSION (\S+)")
        sources = {
            "library.json": json.loads((ROOT / "library.json").read_text())["version"],
            "library.properties": read_match("library.properties",
                                             r"^version=(\S+)$"),
            "examples/esp32-p4/CMakeLists.txt": read_match(
                "examples/esp32-p4/CMakeLists.txt",
                r'^set\(PROJECT_VER "([^"]+)"\)'),
        }
        for path, value in sources.items():
            with self.subTest(path=path):
                self.assertEqual(value, version)

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
