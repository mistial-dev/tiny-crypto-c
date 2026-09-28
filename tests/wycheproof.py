# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run pinned Wycheproof vectors, including positive and negative cases."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import tempfile
from munit_runner import run_reader

# tests/vectors/wycheproof holds the pinned C2SP Wycheproof testvectors_v1
# tree. Its README records the source commit, and SHA256SUMS the file digests.


def ec_records(document, bits):
    counts = Counter()
    lines = []
    for group in document["testGroups"]:
        if group["curve"] != f"secp{bits}r1" or group["encoding"] not in ("ecpoint", "asn"):
            raise AssertionError("Unexpected EC group")
        for case in group["tests"]:
            verdict = case["result"]
            if verdict not in ("valid", "invalid", "acceptable"):
                raise AssertionError(f"Unknown verdict {verdict}")
            # BigInt is a scalar value, not the library's fixed-width encoding.
            scalar = int(case["private"], 16)
            width = max(bits // 8, (scalar.bit_length() + 7) // 8)
            private = scalar.to_bytes(width, "big").hex()
            # Strict DER, named curves, uncompressed points. Optional encodings
            # in the acceptable category must be rejected by these APIs.
            expected = "accept" if verdict == "valid" else "reject"
            lines.append(f"{bits} {group['encoding']} {private} {case['public'] or '-'} "
                         f"{case['shared'] or '-'} {expected} {case['tcId']}")
            counts[verdict] += 1
    if sum(counts.values()) != document["numberOfTests"] or not counts["valid"] or not counts["invalid"]:
        raise AssertionError(f"Incomplete positive/negative coverage: {counts}")
    return "\n".join(lines) + "\n", counts


def signature_digest(hash_name, message):
    name = hash_name.lower().replace("-", "")
    if name in ("shake128", "shake256"):
        # RFC 8692 section 3.2: 256-bit and 512-bit outputs respectively.
        size = 32 if name == "shake128" else 64
        return hashlib.new("shake_" + name[5:], message).hexdigest(size)
    if name in ("sha3224", "sha3256", "sha3384", "sha3512"):
        name = "sha3_" + name[4:]
    return hashlib.new(name, message).hexdigest()


def ecdsa_records(document, bits, hash_name, encoding="p1363"):
    types = {"p1363": "EcdsaP1363Verify", "der": "EcdsaVerify"}
    if encoding not in types:
        raise AssertionError("Unexpected ECDSA encoding")
    counts, records = Counter(), []
    for group in document["testGroups"]:
        if group["publicKey"]["curve"] != f"secp{bits}r1" or group["type"] != types[encoding]:
            raise AssertionError("Unexpected ECDSA group")
        if group["sha"].lower().replace("-", "") != hash_name:
            raise AssertionError("Unexpected ECDSA hash")
        for case in group["tests"]:
            if case["result"] not in ("valid", "invalid"):
                raise AssertionError("Unexpected ECDSA verdict")
            digest = signature_digest(hash_name, bytes.fromhex(case["msg"]))
            records.append(f"{bits} {group['publicKey']['uncompressed']} {digest} "
                           f"{case['sig'] or '-'} {case['result']} {case['tcId']}")
            counts[case["result"]] += 1
    if sum(counts.values()) != document["numberOfTests"] or set(counts) != {"valid", "invalid"}:
        raise AssertionError("Incomplete ECDSA coverage")
    return "\n".join(records) + "\n", counts


def oaep_records(document, exclusions=None):
    hashes = {"SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}
    if document["algorithm"] != "RSAES-OAEP":
        raise AssertionError("Unexpected OAEP algorithm")
    counts, records = Counter(), []
    excluded = 0
    for group in document["testGroups"]:
        bits = group["keySize"]
        if group["type"] != "RsaesOaepDecrypt" or group["mgf"] != "MGF1":
            raise AssertionError("Unsupported OAEP group")
        if (bits not in (1024, 2048, 3072) or group["sha"] not in hashes
                or group["mgfSha"] not in hashes):
            if exclusions is None:
                raise AssertionError("Unsupported OAEP group")
            for case in group["tests"]:
                if case["result"] not in ("valid", "invalid", "acceptable"):
                    raise AssertionError("Unexpected OAEP verdict")
            amount = len(group["tests"])
            exclusions[(bits, group["sha"], group["mgfSha"])] += amount
            excluded += amount
            continue
        key = group["privateKey"]
        components = []
        for field in ("modulus", "publicExponent", "privateExponent", "prime1", "prime2"):
            value = int(key[field], 16)
            width = max(1, (value.bit_length() + 7) // 8) if field == "publicExponent" else bits // 8
            if value <= 0 or value.bit_length() > bits:
                raise AssertionError("Invalid OAEP key component")
            components.append(value.to_bytes(width, "big").hex())
        for case in group["tests"]:
            verdict = case["result"]
            if verdict not in ("valid", "invalid"):
                raise AssertionError("Unexpected OAEP verdict")
            # Preserve ciphertext length, including leading zero bytes.
            payload = [bytes.fromhex(case[field]).hex() or "-" for field in ("label", "ct", "msg")]
            records.append(" ".join(components + [group["sha"], group["mgfSha"]]
                                    + payload + [verdict, str(case["tcId"])]))
            counts[verdict] += 1
    if (sum(counts.values()) + excluded != document["numberOfTests"]
            or (exclusions is None and set(counts) != {"valid", "invalid"})):
        raise AssertionError("Incomplete OAEP coverage")
    return "\n".join(records) + ("\n" if records else ""), counts


def rsa_signature_records(document, exclusions=None):
    schemes = {"RSASSA-PSS": ("pss", "RsassaPssVerify"),
               "RSASSA-PKCS1-v1_5": ("v15", "RsassaPkcs1Verify")}
    if document["algorithm"] not in schemes:
        raise AssertionError("Unexpected RSA signature algorithm")
    scheme, group_type = schemes[document["algorithm"]]
    hashes = {"SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}
    counts, records, excluded = Counter(), [], 0
    for group in document["testGroups"]:
        if group["type"] != group_type and not (scheme == "pss" and group["type"] == "RsassaPssWithParametersVerify"):
            raise AssertionError("Unexpected RSA signature group")
        bits, sha = group["keySize"], group["sha"]
        mgf, mgf_sha, salt = (group["mgf"], group["mgfSha"], group["sLen"]) if scheme == "pss" else ("MGF1", sha, 0)
        for case in group["tests"]:
            if case["result"] not in ("valid", "invalid", "acceptable"):
                raise AssertionError("Unexpected RSA signature verdict")
        if bits not in (1024, 2048, 3072) or sha not in hashes or mgf != "MGF1" or mgf_sha not in hashes:
            if exclusions is None:
                raise AssertionError("Unsupported RSA signature parameters")
            amount = len(group["tests"])
            exclusions[(bits, sha, mgf, mgf_sha)] += amount
            excluded += amount
            continue
        if not isinstance(salt, int) or salt < 0:
            raise AssertionError("Invalid PSS salt length")
        key = group["publicKey"]
        components = []
        for field in ("modulus", "publicExponent"):
            value = int(key[field], 16)
            if value <= 0 or value.bit_length() > bits:
                raise AssertionError("Invalid RSA public component")
            width = bits // 8 if field == "modulus" else max(1, (value.bit_length() + 7) // 8)
            components.append(value.to_bytes(width, "big").hex())
        for case in group["tests"]:
            verdict = case["result"]
            expected = verdict
            if verdict == "acceptable":
                # The strict DigestInfo verifier requires the NULL parameter.
                if scheme != "v15" or set(case["flags"]) != {"MissingNull"}:
                    raise AssertionError("Unreviewed acceptable RSA signature")
                expected = "invalid"
            digest = hashlib.new(sha.lower().replace("-", ""), bytes.fromhex(case["msg"])).hexdigest()
            signature = bytes.fromhex(case["sig"]).hex() or "-"
            records.append(" ".join([scheme] + components + [sha, mgf_sha, str(salt),
                digest, signature, expected, str(case["tcId"])]))
            counts[verdict] += 1
    if sum(counts.values()) + excluded != document["numberOfTests"]:
        raise AssertionError("Incomplete RSA signature coverage")
    return "\n".join(records) + ("\n" if records else ""), counts


def rsa_generation_records(document, exclusions=None):
    """PKCS#1 v1.5 signatures have a fixed encoded message and signature."""
    if document["algorithm"] != "RSASSA-PKCS1-v1_5" or document["schema"] != "rsassa_pkcs1_generate_schema_v1.json":
        raise AssertionError("Unexpected RSA generation document")
    hashes = {"SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}
    counts, records, excluded = Counter(), [], Counter()
    for group in document["testGroups"]:
        if group["type"] != "RsassaPkcs1Generate":
            raise AssertionError("Unexpected RSA generation group")
        bits, sha = group["keySize"], group["sha"]
        for case in group["tests"]:
            if case["result"] not in ("valid", "acceptable"):
                raise AssertionError("Unexpected RSA generation verdict")
        if bits not in (1024, 2048, 3072) or sha not in hashes:
            if exclusions is None:
                raise AssertionError("Unsupported RSA generation parameters")
            excluded[(bits,sha)] += len(group["tests"])
            continue
        key = group["privateKey"]
        values = [int(key[field],16) for field in ("modulus","publicExponent","privateExponent")]
        if any(value <= 0 or value.bit_length() > bits for value in values) or values[0].bit_length() != bits:
            raise AssertionError("Invalid RSA generation key")
        width = bits // 8
        components = [values[0].to_bytes(width,"big").hex()]
        components += [value.to_bytes((value.bit_length() + 7) // 8,"big").hex() for value in values[1:]]
        for case in group["tests"]:
            signature = bytes.fromhex(case["sig"])
            if len(signature) != width:
                raise AssertionError("Invalid RSA generation signature length")
            digest = hashlib.new(sha.lower().replace("-",""),bytes.fromhex(case["msg"])).hexdigest()
            records.append(" ".join(components + [sha,digest,signature.hex(),"match",str(case["tcId"])]))
            counts[case["result"]] += 1
    if sum(counts.values()) + sum(excluded.values()) != document["numberOfTests"]:
        raise AssertionError("Incomplete RSA generation coverage")
    if exclusions is not None:
        exclusions.update(excluded)
    return "\n".join(records) + ("\n" if records else ""), counts


def probable_prime_magnitude(value):
    """Independent deterministic test oracle for signed vector byte magnitudes."""
    n = int.from_bytes(value,"big")
    if n < 2:
        return False
    if n in (2,3):
        return True
    if n % 2 == 0:
        return False
    odd, twos = n - 1, 0
    while odd % 2 == 0:
        odd //= 2
        twos += 1
    for round_number in range(65):
        seed = hashlib.sha256(value + round_number.to_bytes(2,"big")).digest()
        base = 2 + int.from_bytes(seed,"big") % (n - 3)
        x = pow(base,odd,n)
        if x in (1,n - 1):
            continue
        for _ in range(twos - 1):
            x = pow(x,2,n)
            if x == n - 1:
                break
        else:
            return False
    return True


def primality_records(document):
    """Exercise odd RSA candidates and separately classify signed byte magnitudes."""
    if document["algorithm"] != "PrimalityTest" or document["schema"] != "primality_test_schema_v1.json":
        raise AssertionError("Unexpected primality document")
    counts, exclusions, derived, records = Counter(), Counter(), Counter(), []
    for group in document["testGroups"]:
        if group["type"] != "PrimalityTest":
            raise AssertionError("Unexpected primality group")
        for case in group["tests"]:
            verdict = case["result"]
            if verdict not in ("valid", "invalid", "acceptable"):
                raise AssertionError("Unexpected primality verdict")
            value = bytes.fromhex(case["value"])
            if not value or len(value) > 384:
                exclusions["candidate-length"] += 1
            elif value == b"\x02" and verdict == "valid":
                # RSA key generation tests odd candidate factors only.
                exclusions["even-prime"] += 1
            elif value[0] & 0x80:
                # Wycheproof interprets these as signed negatives. The RSA
                # candidate API sees their positive magnitude instead.
                result = "valid" if probable_prime_magnitude(value) else "invalid"
                records.append(f"{value.hex()} {result} {case['tcId']}")
                derived[result] += 1
            else:
                records.append(f"{value.hex()} {verdict} {case['tcId']}")
                counts[verdict] += 1
    if sum(counts.values()) + sum(derived.values()) + sum(exclusions.values()) != document["numberOfTests"]:
        raise AssertionError("Incomplete primality coverage")
    if not counts["valid"] or not counts["invalid"]:
        raise AssertionError("Missing primality positive or negative vectors")
    return "\n".join(records) + "\n", counts, derived, exclusions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", type=Path, required=True,
                        help="Wycheproof directory containing testvectors_v1")
    parser.add_argument("--ec-reader", type=Path, action="append", default=[])
    parser.add_argument("--ecdsa-reader", type=Path, action="append", default=[])
    parser.add_argument("--rsa-signature-reader", type=Path, action="append", default=[])
    parser.add_argument("--rsa-generation-reader", type=Path, action="append", default=[])
    parser.add_argument("--primality-reader", type=Path, action="append", default=[])
    parser.add_argument("--rsa-oaep-reader", type=Path, action="append", default=[])
    parser.add_argument("--kmac-reader", type=Path, action="append", default=[])
    parser.add_argument("--cmac-reader", type=Path, action="append", default=[])
    parser.add_argument("--hmac-reader", type=Path, action="append", default=[])
    parser.add_argument("--aead-reader", action="append", default=[], metavar="BITS:PATH")
    args = parser.parse_args()
    if not any((args.ec_reader, args.ecdsa_reader, args.rsa_signature_reader, args.rsa_generation_reader, args.primality_reader, args.rsa_oaep_reader,
                args.kmac_reader, args.cmac_reader, args.hmac_reader, args.aead_reader)):
        parser.error("At least one reader is required")
    vectors = args.vectors / "testvectors_v1"
    names_all = sorted(path.name for path in vectors.iterdir())

    def read(name):
        return (vectors / name).read_bytes()

    with tempfile.TemporaryDirectory(prefix="tiny-crypto-wycheproof-") as temporary:
        if args.primality_reader:
            name = "primality_test.json"
            records, counts, derived, exclusions = primality_records(json.loads(read(name)))
            fixture = Path(temporary) / "primality.txt"
            fixture.write_text(records)
            for reader in args.primality_reader:
                run_reader([reader,"--primality-vectors",fixture])
            print(f"Primality tested: {dict(counts)}; signed-byte magnitudes with derived oracle: "
                  f"{dict(derived)}; out-of-scope: {dict(exclusions)}",flush=True)
        if args.rsa_generation_reader:
            totals, exclusions = Counter(), Counter()
            prefix = "rsa_pkcs1_"
            names = [name for name in names_all
                     if name.startswith(prefix) and name.endswith("_sig_gen_test.json")]
            if not names:
                raise AssertionError("Missing RSA generation corpus")
            for name in names:
                records, counts = rsa_generation_records(json.loads(read(name)),exclusions)
                if records:
                    fixture = Path(temporary) / "rsa-generation.txt"
                    fixture.write_text(records)
                    for reader in args.rsa_generation_reader:
                        run_reader([reader,"--generation-vectors",fixture])
                totals.update(counts)
                print(f"{name}: {dict(counts)}",flush=True)
            if not totals["valid"] or not totals["acceptable"]:
                raise AssertionError("Incomplete RSA generation verdict coverage")
            print(f"RSA generation tested: {dict(totals)}; out-of-scope parameters: {dict(exclusions)}",flush=True)
        if args.rsa_signature_reader:
            totals, exclusions = Counter(), Counter()
            prefixes = ("rsa_pss_", "rsa_signature_")
            for name in names_all:
                if not name.startswith(prefixes) or not name.endswith("_test.json"):
                    continue
                records, counts = rsa_signature_records(json.loads(read(name)), exclusions)
                if records:
                    fixture = Path(temporary) / "rsa-signatures.txt"
                    fixture.write_text(records)
                    for reader in args.rsa_signature_reader:
                        run_reader([reader, "--signature-vectors", fixture])
                totals.update(counts)
                print(f"{name}: {dict(counts)}", flush=True)
            if not totals["valid"] or not totals["invalid"]:
                raise AssertionError("Incomplete RSA signature positive/negative coverage")
            print(f"RSA signatures tested: {dict(totals)}; out-of-scope parameters: {dict(exclusions)}", flush=True)
        if args.rsa_oaep_reader:
            totals, exclusions = Counter(), Counter()
            prefix = "rsa_oaep_"
            for name in names_all:
                if not name.startswith(prefix) or not name.endswith("_test.json"):
                    continue
                records, counts = oaep_records(json.loads(read(name)), exclusions)
                if records:
                    fixture = Path(temporary) / "rsa-oaep.txt"
                    fixture.write_text(records)
                    for reader in args.rsa_oaep_reader:
                        run_reader([reader, "--vectors", fixture])
                totals.update(counts)
                print(f"{name}: {dict(counts)}", flush=True)
            if not totals["valid"] or not totals["invalid"]:
                raise AssertionError("Incomplete OAEP positive/negative coverage")
            print(f"OAEP tested: {dict(totals)}; out-of-scope parameters: {dict(exclusions)}", flush=True)
        if args.ecdsa_reader:
            curves = {f"secp{bits}r1": bits for bits in (192, 256, 384)}
            totals, exclusions = Counter(), Counter()
            prefix = "ecdsa_"
            for name in names_all:
                if not name.startswith(prefix) or not name.endswith("_test.json"):
                    continue
                document = json.loads(read(name))
                groups = document["testGroups"]
                if not groups or sum(len(g["tests"]) for g in groups) != document["numberOfTests"]:
                    raise AssertionError("Incomplete ECDSA document")
                curve, sha, kind = (groups[0]["publicKey"]["curve"], groups[0]["sha"], groups[0]["type"])
                for group in groups:
                    if (group["publicKey"]["curve"], group["sha"], group["type"]) != (curve, sha, kind):
                        raise AssertionError("Mixed ECDSA document parameters")
                    if any(c["result"] not in ("valid", "invalid", "acceptable") for c in group["tests"]):
                        raise AssertionError("Unexpected ECDSA verdict")
                if curve not in curves:
                    exclusions[curve] += document["numberOfTests"]
                    continue
                encodings = {"EcdsaVerify": "der", "EcdsaP1363Verify": "p1363"}
                if kind not in encodings:
                    raise AssertionError("Unexpected ECDSA group")
                encoding = encodings[kind]
                records, counts = ecdsa_records(document, curves[curve], sha.lower().replace("-", ""), encoding)
                fixture = Path(temporary) / "ecdsa.txt"
                fixture.write_text(records)
                option = "--der-vectors" if encoding == "der" else "--vectors"
                for reader in args.ecdsa_reader:
                    run_reader([reader, option, fixture])
                totals.update(counts)
                print(f"{name}: {dict(counts)}", flush=True)
            if not totals["valid"] or not totals["invalid"]:
                raise AssertionError("Incomplete ECDSA positive/negative coverage")
            print(f"ECDSA tested: {dict(totals)}; out-of-scope curves: {dict(exclusions)}", flush=True)
        if args.aead_reader:
            readers = {int(pair.split(":", 1)[0]): Path(pair.split(":", 1)[1]) for pair in args.aead_reader}
            if set(readers) != {128, 192, 256} or len(args.aead_reader) != 3:
                raise AssertionError("AEAD coverage requires one reader for each AES key size")
            for algorithm in ("gcm", "ccm", "gmac", "eax", "siv", "siv-aead"):
                siv = algorithm in ("siv", "siv-aead")
                name = ("aes_siv_cmac_test.json" if algorithm == "siv" else
                        "aead_aes_siv_cmac_test.json" if algorithm == "siv-aead" else
                        f"aes_{algorithm}_test.json")
                document = json.loads(read(name))
                records = {bits: [] for bits in readers}
                counts = Counter()
                for group in document["testGroups"]:
                    for case in group["tests"]:
                        if case["result"] not in ("valid", "invalid"):
                            raise AssertionError("Unexpected AEAD verdict")
                        if len(bytes.fromhex(case["key"])) * 8 != group["keySize"]:
                            raise AssertionError("Unexpected AEAD key length")
                        fields = [case["key"], case.get("iv", ""), case.get("aad", ""),
                                  case["msg"], case.get("ct", ""), case.get("tag", "")]
                        if algorithm == "siv":
                            if len(fields[4]) < 32:
                                raise AssertionError("SIV ciphertext is missing its synthetic IV")
                            fields[5], fields[4] = fields[4][:32], fields[4][32:]
                        if algorithm == "gmac":
                            fields[2], fields[3] = fields[3], ""
                        for field in fields:
                            if len(bytes.fromhex(field)) > 1024:
                                raise AssertionError("AEAD field exceeds reader capacity")
                        mode = "gcm" if algorithm == "gmac" else algorithm
                        key_bits = group["keySize"] // 2 if siv else group["keySize"]
                        records[key_bits].append(
                            f"{mode} {case['tcId']} {case['result']} " +
                            " ".join(field or "-" for field in fields))
                        counts[case["result"]] += 1
                if sum(counts.values()) != document["numberOfTests"] or set(counts) != {"valid", "invalid"}:
                    raise AssertionError("Incomplete AEAD coverage")
                for bits, reader in readers.items():
                    fixture = Path(temporary) / "aead.txt"
                    fixture.write_text("\n".join(records[bits]) + "\n")
                    run_reader([reader, "--vectors", fixture])
                print(f"{name}: {counts['valid']} valid, {counts['invalid']} invalid", flush=True)
        if args.hmac_reader:
            for bits in (1, 224, 256, 384, 512):
                name = f"hmac_sha{bits}_test.json"
                document = json.loads(read(name))
                counts = Counter(case["result"] for group in document["testGroups"] for case in group["tests"])
                if set(counts) != {"valid", "invalid"} or sum(counts.values()) != document["numberOfTests"]:
                    raise AssertionError(f"Incomplete HMAC coverage: {name}")
                print(f"{name}: {counts['valid']} valid, {counts['invalid']} invalid", flush=True)
            environment = dict(os.environ, TC_TEST_HMAC_WYCHEPROOF_DIR=str(vectors))
            for reader in args.hmac_reader:
                run_reader([reader, "/tiny-crypto-c/hmac/wycheproof"], environment)
        for bits in ((256, 384) if args.ec_reader else ()):
            for suffix in ("_ecpoint", ""):
                name = f"ecdh_secp{bits}r1{suffix}_test.json"
                document = json.loads(read(name))
                records, counts = ec_records(document, bits)
                fixture = Path(temporary) / "vectors.txt"
                fixture.write_text(records)
                for reader in args.ec_reader:
                    run_reader([reader, "--vectors", fixture])
                print(f"{name}: {counts['valid']} valid, {counts['invalid']} invalid, "
                      f"{counts['acceptable']} acceptable rejected by encoding policy", flush=True)
        for name, readers in (("kmac256_no_customization_test.json", args.kmac_reader),
                              ("aes_cmac_test.json", args.cmac_reader)):
            if not readers:
                continue
            document = json.loads(read(name))
            counts = Counter()
            records = []
            for group in document["testGroups"]:
                for case in group["tests"]:
                    if case["result"] not in ("valid", "invalid"):
                        raise AssertionError("Unexpected MAC verdict")
                    for field, bound in (("key", 1024), ("msg", 8192), ("tag", 1024)):
                        value = bytes.fromhex(case[field])
                        if len(value) > bound:
                            raise AssertionError(f"MAC {field} exceeds reader capacity")
                    invalid_key = "InvalidKeySize" in case["flags"]
                    if invalid_key and (name != "aes_cmac_test.json" or case["result"] != "invalid"):
                        raise AssertionError("Unexpected invalid key case")
                    if len(case["key"]) * 4 != group["keySize"] or (not invalid_key and len(case["tag"]) * 4 != group["tagSize"]):
                        raise AssertionError("Unexpected MAC field length")
                    verdict = "invalid-key" if invalid_key else case["result"]
                    records.append(f"{case['tcId']} {case['key'] or '-'} {case['msg'] or '-'} "
                                   f"{case['tag'] or '-'} {verdict}")
                    counts[case["result"]] += 1
            if sum(counts.values()) != document["numberOfTests"] or not counts["valid"] or not counts["invalid"]:
                raise AssertionError("Incomplete MAC coverage")
            fixture = Path(temporary) / "mac.txt"
            fixture.write_text("\n".join(records) + "\n")
            for reader in readers:
                run_reader([reader, "--vectors", fixture])
            print(f"{name}: {counts['valid']} valid, {counts['invalid']} invalid keys/tags")


if __name__ == "__main__":
    main()
