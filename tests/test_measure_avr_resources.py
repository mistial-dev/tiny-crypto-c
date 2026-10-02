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


class PIVSecurityTable(unittest.TestCase):
    def test_current_table_members_are_positional(self):
        self.assertEqual(resources.piv_security_callbacks(),
                         {0: {"sm_transceive"}, 1: {"sm_unbind"}})
        self.assertEqual(resources.PIV_SECURITY_SITES,
                         {"tc_piv_link_transceive": 0, "tc_piv_link_unbind": 1})

    def test_each_site_reaches_only_its_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "src"
            source.mkdir()
            (source / "table.c").write_text(
                "const struct tc_piv_link_security a = {send_a, drop_a};\n"
                "const struct tc_piv_link_security b = {send_b, drop_b};\n")
            with patch.object(resources, "ROOT", Path(temporary)):
                self.assertEqual(resources.piv_security_callbacks(),
                                 {0: {"send_a", "send_b"}, 1: {"drop_a", "drop_b"}})

    def test_only_linked_tables_supply_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "src"
            source.mkdir()
            (source / "table.c").write_text(
                "const struct tc_piv_link_security a = {send_a, drop_a};\n"
                "const struct tc_piv_link_security b = {send_b, drop_b};\n")
            with patch.object(resources, "ROOT", Path(temporary)):
                self.assertEqual(resources.piv_security_callbacks({"a", "send_a", "drop_a"}),
                                 {0: {"send_a"}, 1: {"drop_a"}})
                self.assertEqual(resources.piv_security_callbacks({"send_b"}), {})

    def test_linked_table_with_unlinked_member_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "src"
            source.mkdir()
            (source / "table.c").write_text(
                "const struct tc_piv_link_security a = {.send = send_a, .drop = drop_a};\n")
            with patch.object(resources, "ROOT", Path(temporary)):
                with self.assertRaisesRegex(RuntimeError, "PIV security table member"):
                    resources.piv_security_callbacks({"a", "send_a", "drop_a"})


class ProfileBudgets(unittest.TestCase):
    def test_every_profile_has_a_budget(self):
        budgets = resources.json.loads(
            (SCRIPT.parents[1] / "tests/budgets/avr.json").read_text())
        self.assertEqual(set(budgets["profiles"]), set(resources.PROFILES))

    def test_card_profiles_record_their_storage(self):
        budgets = resources.json.loads(
            (SCRIPT.parents[1] / "tests/budgets/avr.json").read_text())["profiles"]
        self.assertIn("piv_link_bytes", budgets["apdu_piv_read"])
        self.assertIn("sm_framing_flash", budgets["piv_sm_cs2"])

    def test_budgets_name_the_measured_part(self):
        budgets = resources.json.loads(
            (SCRIPT.parents[1] / "tests/budgets/avr.json").read_text())["profiles"]
        for name, limits in budgets.items():
            self.assertEqual(limits.get("mcu", resources.DEFAULT_MCU),
                             resources.PROFILE_MCU.get(name, resources.DEFAULT_MCU), name)

    def test_check_rejects_a_budget_for_another_part(self):
        report = {"profiles": {"apdu_piv_read": {"mcu": "atmega328p", "flash": 10}}}
        budgets = {"profiles": {"apdu_piv_read": {"mcu": "atmega2560", "flash": 20}}}
        with self.assertRaisesRegex(SystemExit, "budget is for atmega2560, measured on atmega328p"):
            resources.check_budgets(report, budgets, io.StringIO())


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
                  "profiles": {"aes_ctr": {"mcu": "atmega328p", "flash": 10}}}
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
