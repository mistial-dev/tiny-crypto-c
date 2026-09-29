# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Keep descriptor calls visible to the AVR stack budget check."""
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "tools/measure_avr_resources.py"
spec = importlib.util.spec_from_file_location("measure_avr_resources", SCRIPT)
resources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resources)


class DescriptorCallbacks(unittest.TestCase):
    def test_current_block_descriptors_are_accounted_for(self):
        self.assertEqual(resources.block_cipher_callbacks(),
                         {"tc_aes_block_encrypt", "tc_aes_block_decrypt",
                          "tc_des_block_encrypt", "tc_des_block_decrypt"})

    def test_new_block_callback_requires_stack_model_update(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "src"
            source.mkdir()
            (source / "block.h").write_text(
                "tc_block_cipher a = {16, key, tc_aes_block_encrypt, tc_aes_block_decrypt};\n"
                "tc_block_cipher b = {8, key, tc_des_block_encrypt, tc_des_block_decrypt};\n"
                "tc_block_cipher c = {16, key, tc_new_block_encrypt, NULL};\n")
            with patch.object(resources, "ROOT", Path(temporary)):
                with self.assertRaisesRegex(RuntimeError, "callbacks changed"):
                    resources.block_cipher_callbacks()


class ToolchainVersion(unittest.TestCase):
    def test_version_is_read_from_the_banner(self):
        self.assertEqual(resources.compiler_version("avr-gcc (GCC) 7.3.0"), "7.3.0")
        self.assertEqual(
            resources.compiler_version("avr-gcc (Homebrew AVR GCC 9.5.0) 9.5.0"), "9.5.0")
        self.assertIsNone(resources.compiler_version("avr-gcc"))

    def test_budget_file_records_the_measuring_toolchain(self):
        budgets = resources.json.loads(
            (SCRIPT.parents[1] / "tests/budgets/avr.json").read_text())
        self.assertRegex(budgets["avr_gcc_version"], r"^\d+\.\d+\.\d+$")

    def test_check_prints_versions_without_enforcing_them(self):
        report = {"avr_gcc_version": "9.5.0",
                  "profiles": {"aes_ctr": {"flash": 10}}}
        budgets = {"avr_gcc_version": "7.3.0",
                   "profiles": {"aes_ctr": {"flash": 20}}}
        stream = io.StringIO()
        resources.check_budgets(report, budgets, stream)
        self.assertIn("7.3.0", stream.getvalue())
        self.assertIn("9.5.0", stream.getvalue())
        budgets["profiles"]["aes_ctr"]["flash"] = 5
        with self.assertRaisesRegex(SystemExit, "aes_ctr flash: 10 exceeds 5"):
            resources.check_budgets(report, budgets, io.StringIO())


if __name__ == "__main__":
    unittest.main()
