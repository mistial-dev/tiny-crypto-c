# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
import fnmatch
import json
import re
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from stage_embedded_package import package_paths, stage  # noqa: E402

MAX_EMBEDDED_PACKAGE_BYTES = 5 * 1024 * 1024


def repository_files():
    """Return tracked and new repository files, excluding ignored build output."""
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT, check=True, capture_output=True,
    )
    return {
        Path(name.decode()).as_posix()
        for name in result.stdout.split(b"\0") if name and (ROOT / name.decode()).is_file()
    }


def read_match(path, pattern):
    """Return the first capture group of pattern in a repository file."""
    match = re.search(pattern, (ROOT / path).read_text(), re.MULTILINE)
    if match is None:
        raise AssertionError(path + " has no version matching " + pattern)
    return match.group(1)


class PackageTests(unittest.TestCase):
    def test_platformio_exports(self):
        patterns = json.loads((ROOT / "library.json").read_text())["export"]["include"]
        expected = {path.relative_to(ROOT).as_posix() for path in package_paths()}
        exported = {
            name for name in repository_files()
            if any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)
        }
        self.assertEqual(exported, expected)

    def test_advertised_examples_are_arduino_sketches(self):
        examples = json.loads((ROOT / "library.json").read_text())["examples"]
        self.assertEqual(examples, [
            "examples/AESCTR/AESCTR.ino",
            "examples/SHA256/SHA256.ino",
        ])
        for name in examples:
            path = ROOT / name
            with self.subTest(example=name):
                self.assertTrue(path.is_file())
                self.assertEqual(path.stem, path.parent.name)

    def test_embedded_package_tree_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "tiny-crypto-c"
            stage(destination)
            staged = {
                path.relative_to(destination).as_posix()
                for path in destination.rglob("*") if path.is_file()
            }
            expected = {path.relative_to(ROOT).as_posix() for path in package_paths()}
            self.assertEqual(staged, expected)
            size = sum(path.stat().st_size for path in destination.rglob("*") if path.is_file())
            self.assertLessEqual(size, MAX_EMBEDDED_PACKAGE_BYTES)
            self.assertFalse({"tests", "tools", "benchmarks", "docs"} &
                             {path.parts[0] for path in map(Path, staged)})

    def test_workflows_do_not_publish_embedded_packages(self):
        workflows = "\n".join(
            path.read_text() for path in sorted((ROOT / ".github/workflows").glob("*.yml"))
        ).lower()
        forbidden = (
            "pio pkg publish",
            "platformio.org/publish",
            "arduino/library-registry",
            "arduino-cli lib publish",
        )
        for command in forbidden:
            with self.subTest(command=command):
                self.assertNotIn(command, workflows)

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

    def test_source_archive_excludes_development_trees(self):
        result = subprocess.run(["git", "check-attr", "export-ignore", "--",
                                 "tests", "tools", "src"], cwd=ROOT,
                                check=True, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            path, _, value = line.split(": ")
            self.assertEqual(value, "unspecified" if path == "src" else "set")

    def test_export_ignore_paths_exist(self):
        for line in (ROOT / ".gitattributes").read_text().splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1] == "export-ignore":
                with self.subTest(path=fields[0]):
                    self.assertTrue((ROOT / fields[0].lstrip("/")).exists())

    def test_commentable_sources_have_spdx_identifiers(self):
        extensions = {".c", ".h", ".cpp", ".hpp", ".py", ".cmake", ".yml", ".yaml", ".ino"}
        names = {"CMakeLists.txt", "Makefile"}
        excluded = ("ports/esp-idf/vendor/", "tests/vectors/", "tests/fuzz/")
        missing = []
        for name in sorted(repository_files()):
            path = Path(name)
            if name.startswith(excluded) or (path.suffix not in extensions and path.name not in names):
                continue
            if "SPDX-License-Identifier:" not in (ROOT / path).read_text(errors="replace"):
                missing.append(name)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--archive":
        with tarfile.open(sys.argv[2]) as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
            names = {member.name for member in members}
        allowed = json.loads((ROOT / "library.json").read_text())["export"]["include"]
        for name in names:
            if not any(fnmatch.fnmatchcase(name, p) for p in allowed):
                raise SystemExit("Unexpected package member: " + name)
        if not {"src/tlv.c", "src/tiny_crypto/tlv.h", "LICENSE",
                "examples/AESCTR/AESCTR.ino", "examples/SHA256/SHA256.ino"} <= names:
            raise SystemExit("Package is missing product files")
        if sum(member.size for member in members) > MAX_EMBEDDED_PACKAGE_BYTES:
            raise SystemExit("Package exceeds embedded release size limit")
    else:
        unittest.main()
