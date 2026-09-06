# SPDX-License-Identifier: GPL-2.0-or-later
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import benchmark_report as report


class ResourceTests(unittest.TestCase):
    def test_uno_library_excludes_build_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src/example.c").write_text("int example;\n")
            (root / "library.json").write_text('{"name": "tiny-crypto-c"}')
            build = root / "build/uno"
            build.mkdir(parents=True)

            def run(command):
                if command[0] == "pio":
                    library = Path(command[2].removeprefix("--lib="))
                    self.assertEqual(sorted(p.name for p in library.iterdir()),
                                     ["library.json", "src"])
                    self.assertTrue((library / "src/example.c").is_file())
                    self.assertNotEqual(library, root)
                    return "framework-arduino-avr @ 5.2.0\ntoolchain-atmelavr @ 1.70300.191015"
                return ("  0 .text 00000010 00000000 00000000 00001000 2**2\n"
                        "                  CONTENTS, ALLOC, LOAD, READONLY, CODE\n")

            with patch.object(report, "ROOT", root), patch.object(report, "run", side_effect=run):
                self.assertEqual(report.measure_uno(build, "", "")["flash"], 16)

    def section(self, name, size, vma, lma, load=True):
        return dict(name=name, size=size, vma=vma, lma=lma,
                    flags={"ALLOC", "LOAD"} if load else {"ALLOC"})

    def test_sections(self):
        sections = report.sections_from_objdump(
            "  0 .text 00000010 10000000 10000000 00001000 2**2\n"
            "                  CONTENTS, ALLOC, LOAD, READONLY, CODE\n"
            "  1 .data 00000004 20000000 10000020 00002000 2**2\n"
            "                  CONTENTS, ALLOC, LOAD, DATA\n"
            "  2 .bss 00000008 20000004 20000004 00002004 2**2\n"
            "                  ALLOC\n")
        metrics = report.account(sections, "pico2")
        self.assertEqual(metrics["flash"], 36)  # Includes load-image alignment.
        self.assertEqual(metrics["static_ram"], 12)
        self.assertEqual(metrics["flash_percent"], 100 * 36 / 4194304)
        for bad in ("", "garbage", "  0 .text bad\n ALLOC\n"):
            with self.assertRaises(ValueError):
                report.sections_from_objdump(bad)

    def test_reserved_and_capacity(self):
        sections = [self.section(".text", 100, 0x10000000, 0x10000000),
                    self.section(".data", 8, 0x20000000, 0x10000064),
                    self.section(".stack_dummy", 2048, 0x20080000, 0, False),
                    self.section(".heap", 2048, 0x20000008, 0, False)]
        actual = report.account(sections, "pico2")
        self.assertEqual(actual["static_ram"], 8)
        self.assertEqual(actual["reserved_stack"], 2048)
        self.assertEqual(actual["reserved_heap"], 2048)
        sections[0]["size"] = 4194305
        with self.assertRaises(ValueError):
            report.account(sections, "pico2")
        with self.assertRaises(ValueError):
            report.account([], "pico2")
        with self.assertRaises(ValueError):
            report.account([self.section(".text", 10, 0x10400000, 0x10400000)], "pico2")
        with self.assertRaises(ValueError):
            report.account([self.section(".text", 32257, 0, 0)], "uno")

    def fixture(self):
        data = {"schema": 1, "boards": {}}
        for board in report.CAPACITIES:
            cap = report.CAPACITIES[board]
            rows = [dict(feature=n, definitions=report.definitions(f), flash=100,
                         static_ram=20, reserved_stack=0, reserved_heap=0,
                         flash_percent=10000 / cap["flash"],
                         static_ram_percent=2000 / cap["ram"])
                    for n, _, f in report.FEATURES]
            data["boards"][board] = dict(capacity=cap, toolchain="fixture",
                                         optimization="-Os", rows=rows)
        return data

    def test_render_deterministic(self):
        data = self.fixture()
        text = report.render(data)
        self.assertEqual(text, report.render(json.loads(json.dumps(data, sort_keys=True))))
        self.assertIn("100 | 0.31% | 20 | 0.98%", text)
        self.assertNotIn("\r", text)
        self.assertTrue(text.endswith("\n"))
        for field in ("flash", "static_ram", "reserved_stack", "flash_percent"):
            bad = copy.deepcopy(data)
            del bad["boards"]["uno"]["rows"][0][field]
            with self.assertRaises((KeyError, ValueError)):
                report.render(bad)
        bad = copy.deepcopy(data)
        bad["boards"]["pico2"]["rows"].pop()
        with self.assertRaises(ValueError):
            report.render(bad)

    def test_check_is_read_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, destination = directory / "report.json", directory / "document.md"
            source.write_text(json.dumps(self.fixture()))
            command = [sys.executable, str(ROOT / "tools/benchmark_report.py"),
                       "--input", str(source), "--output", str(destination),
                       "--build-dir", str(directory / "build")]
            subprocess.run(command, check=True)
            expected = destination.read_bytes()
            subprocess.run(command + ["--check"], check=True)
            destination.write_bytes(b"stale\n")
            result = subprocess.run(command + ["--check"], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(destination.read_bytes(), b"stale\n")
            self.assertEqual((directory / "build/benchmarks.md").read_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
