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


if __name__ == "__main__":
    unittest.main()
