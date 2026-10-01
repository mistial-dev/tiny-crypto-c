# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
import unittest

from tools.cavp_rsp import header_records, records


class CAVPResponseParserTests(unittest.TestCase):
    def test_records_carry_fields_and_accept_line_endings(self):
        text = "[mod = 2048]\r\nn = AA\r\nCOUNT = 0\r\nd = BB\r\n\r\nCOUNT = 1\r\nd = CC\r\n"
        parsed = list(records(text, carry=("n",)))
        self.assertEqual(parsed[0][1], {"n": "AA", "COUNT": "0", "d": "BB"})
        self.assertEqual(parsed[1][1], {"n": "AA", "COUNT": "1", "d": "CC"})

    def test_multiple_headers_and_count_boundaries(self):
        text = "[PRF=HMAC_SHA256]\n[RLEN=32_BITS]\nCOUNT=0\nKI=AA\nCOUNT=1\nKI=BB\n"
        parsed = list(header_records(text))
        self.assertEqual(parsed[0], ({"PRF": "HMAC_SHA256", "RLEN": "32_BITS"},
                                     {"COUNT": 0, "KI": "AA"}))
        self.assertEqual(parsed[1][1], {"COUNT": 1, "KI": "BB"})

    def test_prf_resets_section(self):
        text = "[PRF=A]\n[RLEN=8_BITS]\nCOUNT=0\nX=1\n[PRF=B]\nCOUNT=0\nX=2\n"
        parsed = list(header_records(text))
        self.assertEqual(parsed[1][0], {"PRF": "B"})

    def test_malformed_line_is_rejected(self):
        with self.assertRaises(ValueError):
            list(records("[section]\nmalformed\n"))


if __name__ == "__main__":
    unittest.main()
