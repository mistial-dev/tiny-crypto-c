# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
import unittest
from copy import deepcopy
from sm_corpus import apdu, elements, transcript, normalize_events


class ApduTests(unittest.TestCase):
    def test_short_and_extended_data(self):
        expected = (bytes.fromhex("00870000"), bytes.fromhex("abcd"), True)
        for encoded in ("0087000002abcd00", "00870000000002abcd0100",
                        "00870000000002abcd0000"):
            with self.subTest(encoded=encoded):
                self.assertEqual(apdu(encoded), expected)

    def test_absent_data_and_le(self):
        self.assertEqual(apdu("00200080"), (bytes.fromhex("00200080"), b"", False))
        self.assertEqual(apdu("0020008000"), (bytes.fromhex("00200080"), b"", True))
        self.assertEqual(apdu("0020008001ff"), (bytes.fromhex("00200080"), b"\xff", False))

    def test_bad_lengths(self):
        for encoded in ("", "008700", "0087000002ab", "00870000000002ab",
                        "0087000001ab1234", "0087000001ab000000",
                        "0087000001ab0000", "0087000001ab0100",
                        "00870000000001ab00"):
            with self.subTest(encoded=encoded), self.assertRaises(AssertionError):
                apdu(encoded)


class ElementTests(unittest.TestCase):
    def test_tags_and_lengths(self):
        self.assertEqual(elements(bytes.fromhex("7f4903040100")),
                         {0x7f49: bytes.fromhex("040100")})
        self.assertEqual(elements(bytes.fromhex("538103616263")), {0x53: b"abc"})

    def test_truncated_elements(self):
        encoded = bytes.fromhex("7f498103616263")
        for length in range(1, len(encoded)):
            with self.subTest(length=length), self.assertRaises(AssertionError):
                elements(encoded[:length])

    def test_invalid_elements(self):
        for encoded in ("5380", "53850000000000", "53005300", "7f8181810100"):
            with self.subTest(encoded=encoded), self.assertRaises(AssertionError):
                elements(bytes.fromhex(encoded))


class TranscriptTests(unittest.TestCase):
    def test_response_state_is_checked_after_response(self):
        initial = {"counter": "01", "cmd_mcv": "00", "resp_mcv": "00"}
        after = {"counter": "02", "cmd_mcv": "aa", "resp_mcv": "bb"}
        data = {
            "opacity": {"cipher_suite_id": "0x27", "ephemeral_private_key_d": "01",
                        "id_sH": "00", "general_authenticate_command": "00",
                        "general_authenticate_response": "00", "derived_key_material": "00"},
            "sm_session": {"initial_state": initial},
            "apdu_exchanges": [{
                "command": "0c200080018e00", "plain_command": "00200080",
                "response": "990290008e080000000000000000", "sw": "9000",
                "sm_state_after_unwrap": after,
            }],
        }
        text, count = transcript(data)
        self.assertEqual(count, 1)
        lines = text.splitlines()
        self.assertTrue(lines[-2].startswith("response 9000 "))
        self.assertEqual(lines[-1], "state 02 aa bb")


class EventTests(unittest.TestCase):
    def setUp(self):
        public = "04" + "00" * 31 + "01" + "00" * 31 + "02"
        request = "00" * 9 + public
        body = "7c4c814a" + request
        self.data = {
            "sm": {"opacity": {
                "CipherSuiteId": "27", "EphemeralPublicKeyX": "1",
                "EphemeralPublicKeyY": "2", "EphemeralPrivateKeyD": "3",
                "SharedSecretZ": "4", "OtherInfo": "00",
                "CardCvc": "7f21467f49438641" + public,
                "SkCfrm": "5", "SkMac": "6", "SkEnc": "7", "SkRmac": "8",
            }},
            "events": [{"event_id": 1, "sm_established": True,
                        "sm_establishment_exchange_id": 1}],
            "apdu_exchanges": [
                {"exchange_id": 1, "event_id": 1, "command": "008727044e" + body + "00",
                 "response": "7c009000"},
                {"exchange_id": 2, "event_id": 1, "response": "990263c79000",
                 "sw": "63c7", "sm_state_before": {
                     "counter": "1", "cmd_mcv": "0", "resp_mcv": "0"}},
            ],
        }

    def test_fixed_width_and_transport_status(self):
        normalized, missing = normalize_events(self.data)
        self.assertEqual(missing, [])
        self.assertEqual(normalized["opacity"]["ephemeral_private_key_d"], "0" * 63 + "3")
        self.assertEqual(normalized["opacity"]["sk_mac"], "0" * 31 + "6")
        record = normalized["apdu_exchanges"][1]
        self.assertEqual(record["sw"], "9000")
        self.assertEqual(record["response"], "990263c7")
        self.assertEqual(record["sm_state_before"]["counter"], "0" * 31 + "1")
        self.assertEqual(self.data["apdu_exchanges"][1]["sw"], "63c7")

    def test_invalid_session_metadata(self):
        for field, value in (("event_id", 2), ("response", "7c006a80"),
                             ("command", "00872e044e7c4c814a" + "00" * 74 + "00")):
            data = deepcopy(self.data)
            data["apdu_exchanges"][0][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                normalize_events(data)

    def test_duplicate_exchange_id(self):
        self.data["apdu_exchanges"][1]["exchange_id"] = 1
        with self.assertRaises(AssertionError):
            normalize_events(self.data)

    def test_missing_session_is_reported(self):
        event = dict(self.data["events"][0], event_id=2, sm_establishment_exchange_id=3)
        ga = dict(self.data["apdu_exchanges"][0], exchange_id=3, event_id=2)
        ga["command"] = ga["command"][:-4] + "0300"
        self.data["events"].append(event)
        self.data["apdu_exchanges"].append(ga)
        _, missing = normalize_events(self.data)
        self.assertEqual(missing, [2])


if __name__ == "__main__":
    unittest.main()
