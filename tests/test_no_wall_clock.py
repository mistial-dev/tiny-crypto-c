# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Reject wall-clock reads in the test tree.

Tests evaluate certificates, CRLs and OCSP responses at a fixed time, so a
fixture that expires never changes a result. This check scans every C, C++,
Python and CMake file below tests/ for calls that read the current time.
The vendored munit and doctest sources and tests/vectors are skipped.
ALLOWED names each remaining use with its reason. Examples that model a
device keep the platform clock and live outside tests/."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
SUFFIXES = {".c", ".h", ".cc", ".cpp", ".hpp", ".py", ".cmake"}
CMAKE_LISTS = "CMakeLists.txt"
VENDORED = {"tests/support/munit.c", "tests/support/munit.h", "tests/support/doctest.h"}
SKIPPED_DIRECTORIES = ("tests/vectors/",)
SELF = "tests/test_no_wall_clock.py"

# File (relative to the repository root) to the reason its clock use stays.
ALLOWED: dict[str, str] = {}

WALL_CLOCK = [
    ("time(NULL)", re.compile(r"\btime\s*\(\s*(?:NULL|nullptr|0|&)")),
    ("gmtime/localtime", re.compile(r"\b(?:gmtime|localtime)(?:_r|_s)?\s*\(")),
    ("clock_gettime", re.compile(r"\bclock_gettime\s*\(")),
    ("gettimeofday", re.compile(r"\bgettimeofday\s*\(")),
    ("std::chrono::system_clock", re.compile(r"\bsystem_clock\b")),
    ("datetime.now/utcnow/today", re.compile(r"\b(?:datetime|date)\s*\.\s*(?:now|utcnow|today)\s*\(")),
    ("time.time()", re.compile(r"\btime\s*\.\s*time(?:_ns)?\s*\(")),
    ("timespec_get", re.compile(r"\btimespec_get\s*\(")),
    ("X509_cmp_current_time", re.compile(r"\bX509_cmp_current_time\s*\(")),
    # X509_gmtime_adj offsets from the current time. X509_time_adj and
    # X509_time_adj_ex read the clock when their time argument is NULL.
    ("X509_gmtime_adj", re.compile(r"\b\w*_gmtime_adj\s*\(")),
    ("X509_time_adj(..., NULL)", re.compile(r"\bX509_time_adj(?:_ex)?\s*\([^;]*?\bNULL\s*\)")),
    ("CMake TIMESTAMP", re.compile(r"\bstring\s*\(\s*TIMESTAMP\b")),
]


def strip_comments(text, suffix):
    """Blank comments and keep line numbers."""
    if suffix in (".py", ".cmake", CMAKE_LISTS):
        return re.sub(r"#[^\n]*", "", text)
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def clock_reads(text, suffix):
    """Yield (line, label) for each wall-clock read in text."""
    code = strip_comments(text, suffix)
    for label, pattern in WALL_CLOCK:
        for match in pattern.finditer(code):
            yield code.count("\n", 0, match.start()) + 1, label


def test_files():
    for path in sorted(TESTS.rglob("*")):
        relative = path.relative_to(ROOT).as_posix()
        if (path.is_file() and (path.suffix in SUFFIXES or path.name == CMAKE_LISTS)
                and relative not in VENDORED
                and relative != SELF and not relative.startswith(SKIPPED_DIRECTORIES)):
            yield path, relative


class NoWallClockTests(unittest.TestCase):
    def test_detector_finds_clock_reads(self):
        samples = [
            ("pki.at = utc_time(time(NULL));", ".c"),
            ("const time_t now = time(&seconds);", ".c"),
            ("struct tm* t = gmtime(&now);", ".c"),
            ("gmtime_r(&now, &fields);", ".c"),
            ("clock_gettime(CLOCK_REALTIME, &ts);", ".c"),
            ("gettimeofday(&tv, NULL);", ".c"),
            ("auto t = std::chrono::system_clock::now();", ".cpp"),
            ("now = datetime.datetime.now(datetime.timezone.utc)", ".py"),
            ("now = datetime.utcnow()", ".py"),
            ("start = time.time()", ".py"),
            ("start = time.time_ns()", ".py"),
            ("timespec_get(&ts, TIME_UTC);", ".c"),
            ("X509_cmp_current_time(X509_get0_notAfter(c));", ".c"),
            ("ASN1_TIME* t = X509_gmtime_adj(NULL, -3600);", ".c"),
            ("X509_gmtime_adj(X509_getm_notBefore(c), 0);", ".c"),
            ("X509_time_adj_ex(t, 1, 0, NULL);", ".c"),
            ("string(TIMESTAMP now UTC)", ".cmake"),
            ("string(TIMESTAMP now UTC)", CMAKE_LISTS),
        ]
        for sample, suffix in samples:
            self.assertTrue(list(clock_reads(sample, suffix)), sample)
        clean = [
            ("X509_time_adj_ex(t, 1, 0, &epoch);", ".c"),
            ("ASN1_TIME_adj(t, epoch, 0, -3600);", ".c"),
            ("const TC_X509_time at = {2026, 9, 29, 18, 0, 0};", ".c"),
            ("/* time(NULL) would read the clock */", ".c"),
            ("# datetime.now() would read the clock", ".py"),
            ("at = datetime.datetime(2026, 9, 27, tzinfo=datetime.timezone.utc)", ".py"),
            ("example_card_now(&at);", ".c"),
            ("t = time.monotonic()", ".py"),
        ]
        for sample, suffix in clean:
            self.assertFalse(list(clock_reads(sample, suffix)), sample)

    def test_allow_list_names_existing_files(self):
        for relative, reason in ALLOWED.items():
            self.assertTrue((ROOT / relative).is_file(), relative)
            self.assertTrue(reason.strip(), relative)

    def test_tests_use_fixed_time(self):
        found = []
        for path, relative in test_files():
            if relative in ALLOWED:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            kind = CMAKE_LISTS if path.name == CMAKE_LISTS else path.suffix
            for line, label in clock_reads(text, kind):
                found.append(f"{relative}:{line}: {label}")
        self.assertEqual(found, [], "\n" + "\n".join(found))


if __name__ == "__main__":
    unittest.main()
