# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Checks for the external vector runner."""
import contextlib
import copy
import io
import subprocess
import unittest
from unittest.mock import patch

import wycheproof
import munit_runner


class ReaderTests(unittest.TestCase):
    def test_signature_digest(self):
        self.assertEqual(wycheproof.signature_digest("SHAKE128", b""),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
        self.assertEqual(wycheproof.signature_digest("SHAKE256", b""),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
            "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be")
        self.assertEqual(wycheproof.signature_digest("SHA3-256", b""),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        self.assertEqual(wycheproof.signature_digest("SHA-384", b""),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da27"
            "4edebfe76f65fbd51ad2f14898b95b")
        self.assertEqual(wycheproof.signature_digest("SHA-256", b""),
            wycheproof.signature_digest("sha256", b""))
        with self.assertRaises(ValueError):
            wycheproof.signature_digest("unknown", b"")

    def test_rsa_signature_records(self):
        document = {"algorithm": "RSASSA-PSS", "numberOfTests": 2, "testGroups": [{
            "type": "RsassaPssVerify", "keySize": 2048, "sha": "SHA-384",
            "mgf": "MGF1", "mgfSha": "SHA-256", "sLen": 0,
            "publicKey": {"modulus": "00ff", "publicExponent": "0003"},
            "tests": [{"tcId": 1, "msg": "", "sig": "0001", "result": "valid"},
                      {"tcId": 2, "msg": "00", "sig": "", "result": "invalid"}]}]}
        records, counts = wycheproof.rsa_signature_records(document)
        self.assertEqual(counts, {"valid": 1, "invalid": 1})
        fields = records.splitlines()[0].split()
        self.assertEqual(len(fields[1]), 512)
        self.assertEqual(fields[2:6], ["03", "SHA-384", "SHA-256", "0"])
        self.assertEqual(fields[7:], ["0001", "valid", "1"])
        self.assertTrue(records.endswith("- invalid 2\n"))
        parameterized = copy.deepcopy(document)
        parameterized["testGroups"][0]["type"] = "RsassaPssWithParametersVerify"
        self.assertEqual(wycheproof.rsa_signature_records(parameterized), (records, counts))
        for field, value in (("type", "unknown"), ("sLen", -1), ("sLen", "32")):
            bad = copy.deepcopy(document)
            bad["testGroups"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(AssertionError):
                wycheproof.rsa_signature_records(bad)
        for field in ("modulus", "publicExponent"):
            for value in ("00", "-01", "1" + "00" * 256):
                bad = copy.deepcopy(document)
                bad["testGroups"][0]["publicKey"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(AssertionError):
                    wycheproof.rsa_signature_records(bad)
        for excluded in (False, True):
            bad = copy.deepcopy(document)
            if excluded:
                bad["testGroups"][0]["keySize"] = 4096
            bad["testGroups"][0]["tests"][0]["result"] = "unknown"
            with self.assertRaises(AssertionError):
                wycheproof.rsa_signature_records(bad, wycheproof.Counter())
        v15 = copy.deepcopy(document)
        v15["algorithm"] = "RSASSA-PKCS1-v1_5"
        group = v15["testGroups"][0]
        group["type"] = "RsassaPkcs1Verify"
        group["tests"][1].update(result="acceptable", flags=["MissingNull"])
        self.assertEqual(wycheproof.rsa_signature_records(v15)[1], {"valid": 1, "acceptable": 1})
        group["tests"][1]["flags"] = ["Unknown"]
        with self.assertRaises(AssertionError):
            wycheproof.rsa_signature_records(v15)
        for field, value in (("keySize", 4096), ("sha", "SHA-512/256"), ("mgfSha", "SHA3-256")):
            bad = copy.deepcopy(document)
            bad["testGroups"][0][field] = value
            with self.assertRaises(AssertionError):
                wycheproof.rsa_signature_records(bad)
            exclusions = wycheproof.Counter()
            self.assertEqual(wycheproof.rsa_signature_records(bad, exclusions), ("", {}))
            self.assertEqual(sum(exclusions.values()), 2)
        document["numberOfTests"] = 3
        with self.assertRaises(AssertionError):
            wycheproof.rsa_signature_records(document)

    def test_oaep_records(self):
        document = {"algorithm": "RSAES-OAEP", "numberOfTests": 2, "testGroups": [{
            "keySize": 1024, "type": "RsaesOaepDecrypt", "mgf": "MGF1",
            "sha": "SHA-256", "mgfSha": "SHA-1",
            "privateKey": {"modulus": "00ff", "publicExponent": "0003",
                           "privateExponent": "03", "prime1": "05", "prime2": "07"},
            "tests": [{"tcId": 1, "label": "", "ct": "0001", "msg": "00", "result": "valid"},
                      {"tcId": 2, "label": "00", "ct": "", "msg": "", "result": "invalid"}]}]}
        records, counts = wycheproof.oaep_records(document)
        self.assertEqual(counts, {"valid": 1, "invalid": 1})
        fields = records.splitlines()[0].split()
        self.assertEqual([len(fields[i]) for i in (0, 2, 3, 4)], [256] * 4)
        self.assertEqual(fields[1], "03")
        self.assertEqual(fields[7:], ["-", "0001", "00", "valid", "1"])
        mixed = copy.deepcopy(document)
        extra = copy.deepcopy(document["testGroups"][0])
        extra["keySize"] = 4096
        mixed["testGroups"].append(extra)
        mixed["numberOfTests"] = 4
        exclusions = wycheproof.Counter()
        self.assertEqual(wycheproof.oaep_records(mixed, exclusions), (records, counts))
        self.assertEqual(exclusions, {(4096, "SHA-256", "SHA-1"): 2})
        excluded_only = copy.deepcopy(document)
        excluded_only["testGroups"] = [extra]
        excluded_only["testGroups"][0]["tests"][0]["result"] = "acceptable"
        exclusions = wycheproof.Counter()
        self.assertEqual(wycheproof.oaep_records(excluded_only, exclusions), ("", {}))
        self.assertEqual(sum(exclusions.values()), 2)
        excluded_only["numberOfTests"] = 3
        with self.assertRaises(AssertionError):
            wycheproof.oaep_records(excluded_only, wycheproof.Counter())
        with self.assertRaises(AssertionError):
            wycheproof.oaep_records(mixed)
        for field, value in (("keySize", 4096), ("sha", "SHA-512/224"),
                             ("mgf", "other"), ("type", "other")):
            bad = copy.deepcopy(document)
            bad["testGroups"][0][field] = value
            with self.assertRaises(AssertionError):
                wycheproof.oaep_records(bad)
        bad = copy.deepcopy(document)
        bad["numberOfTests"] = 3
        with self.assertRaises(AssertionError):
            wycheproof.oaep_records(bad)
        for verdict in ("valid", "acceptable", "unknown"):
            bad = copy.deepcopy(document)
            bad["testGroups"][0]["tests"][1]["result"] = verdict
            with self.assertRaises(AssertionError):
                wycheproof.oaep_records(bad)

    def test_ecdsa_records(self):
        document = {"numberOfTests": 2, "testGroups": [{
            "publicKey": {"curve": "secp256r1", "uncompressed": "04"},
            "type": "EcdsaP1363Verify", "sha": "SHA-256", "tests": [
                {"tcId": 1, "msg": "", "sig": "aabb", "result": "valid"},
                {"tcId": 2, "msg": "", "sig": "", "result": "invalid"}]}]}
        records, counts = wycheproof.ecdsa_records(document, 256, "sha256")
        self.assertEqual(counts, {"valid": 1, "invalid": 1})
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", records)
        self.assertTrue(records.endswith("- invalid 2\n"))
        der = copy.deepcopy(document)
        der["testGroups"][0]["type"] = "EcdsaVerify"
        self.assertEqual(wycheproof.ecdsa_records(der, 256, "sha256", "der"), (records, counts))
        with self.assertRaises(AssertionError):
            wycheproof.ecdsa_records(document, 256, "sha256", "der")
        with self.assertRaises(AssertionError):
            wycheproof.ecdsa_records(document, 256, "sha256", "unknown")
        for field, value in (("sha", "SHA-512"), ("type", "EcdsaVerify")):
            bad = copy.deepcopy(document)
            bad["testGroups"][0][field] = value
            with self.assertRaises(AssertionError):
                wycheproof.ecdsa_records(bad, 256, "sha256")
        for total in (1, 3):
            bad = copy.deepcopy(document)
            bad["numberOfTests"] = total
            with self.assertRaises(AssertionError):
                wycheproof.ecdsa_records(bad, 256, "sha256")
        for verdict in ("valid", "acceptable", "unknown"):
            bad = copy.deepcopy(document)
            bad["testGroups"][0]["tests"][1]["result"] = verdict
            with self.assertRaises(AssertionError):
                wycheproof.ecdsa_records(bad, 256, "sha256")

    def test_requires_one_successful_test(self):
        summary = "1 of 1 (100%) tests successful, 0 (0%) test skipped."
        cases = ((0, summary, True),
                 (1, summary, False),
                 (0, "No tests run, 0 (100%) skipped.", False),
                 (0, "0 of 1 (0%) tests successful, 1 (100%) test skipped.", False),
                 (0, "", False))
        for code, output, accepted in cases:
            with self.subTest(code=code, output=output):
                result = subprocess.CompletedProcess(["reader"], code, output, "")
                with patch.object(munit_runner.subprocess, "run", return_value=result), \
                        contextlib.redirect_stdout(io.StringIO()):
                    if accepted:
                        wycheproof.run_reader(["reader"])
                    else:
                        with self.assertRaises(AssertionError):
                            wycheproof.run_reader(["reader"])


if __name__ == "__main__":
    unittest.main()
