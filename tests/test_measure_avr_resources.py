# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Keep descriptor calls visible to the AVR stack budget check."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "tools/measure_avr_resources.py"
spec = importlib.util.spec_from_file_location("measure_avr_resources", SCRIPT)
resources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resources)


class DescriptorCallbacks(unittest.TestCase):
    def test_current_mac_descriptors_are_accounted_for(self):
        self.assertEqual(resources.mac_cipher_callbacks(),
                         {"tc_aes_mac_encrypt", "tc_des_mac_encrypt"})

    def test_new_mac_callback_requires_stack_model_update(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "src"
            source.mkdir()
            (source / "mac.c").write_text(
                "tc_mac_cipher a = {16, key, tc_aes_mac_encrypt};\n"
                "tc_mac_cipher b = {8, key, tc_des_mac_encrypt};\n"
                "tc_mac_cipher c = {16, key, tc_new_mac_encrypt};\n")
            with patch.object(resources, "ROOT", Path(temporary)):
                with self.assertRaisesRegex(RuntimeError, "callbacks changed"):
                    resources.mac_cipher_callbacks()


if __name__ == "__main__":
    unittest.main()
