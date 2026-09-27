#!/usr/bin/env python3
"""Run selected NIST DSS CAVP records through the public C test readers."""

import argparse
import hashlib
import pathlib
import subprocess
import tempfile
import zipfile

ECDSA_SHA256 = "fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752"
RSA_SHA256 = "8405aeb3572a4f98ed4b1a3ccb3f2f49e725462dd28ec4759d6a15d88855d19c"
CURVES = {"P-192": 192, "P-256": 256, "P-384": 384}
HASHES = {"SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256",
          "SHA384": "SHA-384", "SHA512": "SHA-512"}
EXPECTED = {"ecdsa pkv": 180, "ecdsa keypair": 150,
            "ecdsa siggen": 720, "ecdsa sigver": 1125,
            "rsa siggen15": 80, "rsa siggenpss": 80,
            "rsa sigver v15": 270, "rsa sigver pss": 270,
            "rsa keygen": 2200}


def records(contents):
    """Yield section, record; section and long-lived keys persist across blank lines."""
    section = ""
    context = {}
    record = {}
    for raw in contents.decode("ascii").splitlines() + [""]:
        line = raw.strip()
        if line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]") and not line.startswith("[B."):
            if record:
                yield section, context | record
                record = {}
            section = line[1:-1]
            context = {}
            continue
        if not line:
            if record:
                yield section, context | record
                context.update({key: value for key, value in record.items()
                                if key in ("n", "e", "d")})
                record = {}
            continue
        if " = " in line:
            key, value = line.split(" = ", 1)
            record[key] = value


def check_archive(path, expected):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f"{path}: SHA-256 {actual}, expected {expected}")
    return zipfile.ZipFile(path)


def fixed_hex(value, width, allow_oversize=False):
    if len(value) > 2 * width and not allow_oversize:
        raise ValueError("CAVP coordinate exceeds curve width")
    return value.zfill(max(2 * width, len(value) + len(value) % 2)).lower()


def ec_vectors(archive, kind):
    member = f"186-4ecdsatestvectors/{'PKV' if kind == 'pkv' else 'KeyPair'}.rsp"
    selected = []
    skipped = {}
    for section, item in records(archive.read(member)):
        curve = section.split(",", 1)[0]
        if not {"Qx", "Qy"} <= item.keys():
            continue
        if curve not in CURVES:
            skipped[curve] = skipped.get(curve, 0) + 1
            continue
        bits = CURVES[curve]
        width = bits // 8
        point = "04" + fixed_hex(item["Qx"], width, kind == "pkv") + fixed_hex(item["Qy"], width, kind == "pkv")
        if kind == "pkv":
            verdict = "valid" if item["Result"].startswith("P") else "invalid"
            selected.append(f"pkv {bits} {point} {verdict}")
        else:
            selected.append(f"keypair {bits} {point} {fixed_hex(item['d'], width)}")
    return selected, skipped


def rsa_siggen15_vectors(archive):
    """The .txt prompt has private d; the .rsp has matching public answers."""
    prompt = list(records(archive.read("SigGen15_186-3.txt")))
    answer = list(records(archive.read("SigGen15_186-3.rsp")))
    if len(prompt) != len(answer):
        raise ValueError("RSA prompt and answer record counts differ")
    selected = []
    skipped = {}
    for index, ((section, request), (other_section, response)) in enumerate(zip(prompt, answer)):
        if section != other_section:
            raise ValueError(f"RSA record {index}: section mismatch")
        for key in ("n", "e", "SHAAlg", "Msg"):
            if request.get(key) != response.get(key):
                raise ValueError(f"RSA record {index}: {key} mismatch")
        if "S" not in response:
            continue
        bits = int(section.removeprefix("mod = "))
        if bits not in (1024, 2048, 3072):
            skipped[str(bits)] = skipped.get(str(bits), 0) + 1
            continue
        algorithm = HASHES.get(request["SHAAlg"])
        if not algorithm:
            skipped[request["SHAAlg"]] = skipped.get(request["SHAAlg"], 0) + 1
            continue
        digest = hashlib.new(algorithm.replace("-", "").lower(),
                             bytes.fromhex(request["Msg"])).hexdigest()
        selected.append(" ".join((request["n"], request["e"], request["d"],
                                  algorithm, digest, response["S"], "match", str(index))))
    return selected, skipped


def rsa_siggenpss_vectors(archive):
    prompt = list(records(archive.read("SigGenPSS_186-3.txt")))
    answer = list(records(archive.read("SigGenPSS_186-3.rsp")))
    if len(prompt) != len(answer):
        raise ValueError("RSA PSS prompt and answer record counts differ")
    selected, skipped = [], {}
    for index, ((section, request), (other_section, response)) in enumerate(zip(prompt, answer)):
        if section != other_section:
            raise ValueError(f"RSA PSS record {index}: section mismatch")
        for key in ("n", "e", "SHAAlg", "Msg"):
            if request.get(key) != response.get(key):
                raise ValueError(f"RSA PSS record {index}: {key} mismatch")
        if "S" not in response:
            continue
        bits = int(section.removeprefix("mod = "))
        if bits not in (1024, 2048, 3072) or request["SHAAlg"] not in HASHES:
            label = str(bits) if bits not in (1024, 2048, 3072) else request["SHAAlg"]
            skipped[label] = skipped.get(label, 0) + 1
            continue
        algorithm = HASHES[request["SHAAlg"]]
        digest = hashlib.new(algorithm.replace("-", "").lower(),
                             bytes.fromhex(request["Msg"])).hexdigest()
        selected.append(" ".join((request["n"], request["e"], request["d"],
                                  algorithm, digest, response["S"], "match", str(index),
                                  request["SaltVal"])))
    return selected, skipped


def rsa_keygen_vectors(archive, exhaustive=False):
    """Validate fixed and varying exponents in each group, or every key."""
    groups = {}
    skipped = {}
    for index, (section, item) in enumerate(records(archive.read("KeyGen_186-3.rsp"))):
        if not {"e", "p", "q", "n", "d"} <= item.keys():
            raise ValueError(f"RSA KeyGen record {index}: missing key material")
        bits = len(item["n"]) * 4
        if bits not in (2048, 3072):
            skipped[str(bits)] = skipped.get(str(bits), 0) + 1
            continue
        if section not in {"hash = SHA1", "hash = SHA224", "hash = SHA256",
                           "hash = SHA384", "hash = SHA512",
                           "Table for M-R Test = C.2", "Table for M-R Test = C.3"}:
            raise ValueError(f"RSA KeyGen record {index}: unknown method {section}")
        groups.setdefault((bits, section), []).append((index, item))
    if len(groups) != 14:
        raise ValueError(f"RSA KeyGen: expected 14 supported groups, found {len(groups)}")
    selected = []
    total_supported = sum(map(len, groups.values()))
    for (bits, section), entries in groups.items():
        expected_group_size = 300 if section.startswith("Table for M-R Test") else 100
        if len(entries) != expected_group_size:
            raise ValueError(f"RSA KeyGen: {bits}, {section} has {len(entries)} records")
        if exhaustive:
            positions = range(len(entries))
        else:
            # CAVP interleaves fixed- and varying-exponent blocks.
            fixed_exponent = entries[0][1]["e"]
            if int(fixed_exponent, 16) != 0x100000001:
                raise ValueError(f"RSA KeyGen: unexpected fixed exponent in {bits}, {section}")
            varying = next((position for position, (_, item) in enumerate(entries)
                            if item["e"] != fixed_exponent), None)
            if varying is None:
                raise ValueError(f"RSA KeyGen: no varying exponent in {bits}, {section}")
            positions = (0, varying)
        for position in positions:
            index, item = entries[position]
            selected.append(" ".join((item["n"], item["e"], item["d"],
                                      item["p"], item["q"], str(index))))
    skipped["supported records sampled out"] = total_supported - len(selected)
    return selected, skipped


def ecdsa_signature_vectors(archive, kind):
    member = f"186-4ecdsatestvectors/{'SigGen' if kind == 'siggen' else 'SigVer'}.rsp"
    selected, skipped = [], {}
    for index, (section, item) in enumerate(records(archive.read(member))):
        if not {"Msg", "Qx", "Qy", "R", "S"} <= item.keys():
            continue
        curve, hash_name = section.split(",", 1)
        hash_name = hash_name.replace("-", "")
        if curve not in CURVES or hash_name not in HASHES:
            label = section if curve in CURVES else curve
            skipped[label] = skipped.get(label, 0) + 1
            continue
        bits = CURVES[curve]
        width = bits // 8
        key = "04" + fixed_hex(item["Qx"], width, True) + fixed_hex(item["Qy"], width, True)
        digest = hashlib.new(hash_name.replace("-", "").lower(),
                             bytes.fromhex(item["Msg"])).hexdigest()
        signature = fixed_hex(item["R"], width, True) + fixed_hex(item["S"], width, True)
        verdict = "valid" if kind == "siggen" or item["Result"].startswith("P") else "invalid"
        selected.append(f"{bits} {key} {digest} {signature} {verdict} nist-{kind}-{index}")
    return selected, skipped


def rsa_signature_vectors(archive, kind):
    member = "SigVer15_186-3.rsp" if kind == "v15" else "SigVerPSS_186-3.rsp"
    selected, skipped = [], {}
    for index, (section, item) in enumerate(records(archive.read(member))):
        if not {"n", "e", "SHAAlg", "Msg", "S", "Result"} <= item.keys():
            continue
        bits = int(section.removeprefix("mod = "))
        if bits not in (1024, 2048, 3072) or item["SHAAlg"] not in HASHES:
            label = str(bits) if bits not in (1024, 2048, 3072) else item["SHAAlg"]
            skipped[label] = skipped.get(label, 0) + 1
            continue
        if len(item["Msg"]) % 2 or len(item["S"]) % 2:
            skipped["odd-length hex"] = skipped.get("odd-length hex", 0) + 1
            continue
        hash_name = HASHES[item["SHAAlg"]]
        digest = hashlib.new(hash_name.replace("-", "").lower(),
                             bytes.fromhex(item["Msg"])).hexdigest()
        exponent = item["e"].lstrip("0")
        if len(exponent) % 2:
            exponent = "0" + exponent
        salt_value = item.get("SaltVal", "")
        # CAVP writes 00 for the zero-length salt in the 3072-bit groups.
        salt = (0 if bits == 3072 and salt_value == "00" else len(salt_value) // 2) if kind == "pss" else 0
        verdict = "valid" if item["Result"].startswith("P") else "invalid"
        selected.append(f"{kind} {item['n']} {exponent} {hash_name} {hash_name} {salt} "
                        f"{digest} {item['S']} {verdict} nist-{kind}-{index}")
    return selected, skipped


def run_reader(reader, lines, skip, label, mode=None):
    if not lines:
        raise ValueError(f"{label}: no supported records")
    with tempfile.TemporaryDirectory(prefix="tiny-crypto-nist-dss-") as directory:
        path = pathlib.Path(directory) / "vectors.txt"
        path.write_text("\n".join(lines) + "\n", encoding="ascii")
        subprocess.run([reader, mode or ("--vectors" if label.startswith("ecdsa") else "--generation-vectors"),
                        str(path)], check=True)
    skipped_label = "sampled out" if label == "rsa keygen" else "unsupported"
    print(f"{label}: executed {len(lines)}, {skipped_label} {sum(skip.values())}")
    if skip:
        print("  omitted:", ", ".join(f"{key}={value}" for key, value in sorted(skip.items())))


def check_count(label, lines, skip):
    actual = len(lines) + sum(skip.values())
    if actual != EXPECTED[label]:
        raise ValueError(f"{label}: parsed {actual}, expected {EXPECTED[label]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ecdsa-archive", type=pathlib.Path)
    parser.add_argument("--rsa-archive", type=pathlib.Path)
    parser.add_argument("--ecdsa-reader")
    parser.add_argument("--ecdsa-signature-reader")
    parser.add_argument("--rsa-generation-reader")
    parser.add_argument("--rsa-signature-reader")
    parser.add_argument("--rsa-keygen-reader")
    parser.add_argument("--rsa-keygen-all", action="store_true",
                        help="validate all 2,200 CAVP KeyGen private keys (takes hours)")
    args = parser.parse_args()
    if args.ecdsa_archive:
        archive = check_archive(args.ecdsa_archive, ECDSA_SHA256)
        for kind in ("pkv", "keypair"):
            lines, skip = ec_vectors(archive, kind)
            check_count(f"ecdsa {kind}", lines, skip)
            if args.ecdsa_reader:
                run_reader(args.ecdsa_reader, lines, skip, f"ecdsa {kind}")
            else:
                print(f"ecdsa {kind}: selected {len(lines)}, unsupported {sum(skip.values())}")
        for kind in ("siggen", "sigver"):
            lines, skip = ecdsa_signature_vectors(archive, kind)
            check_count(f"ecdsa {kind}", lines, skip)
            if args.ecdsa_signature_reader:
                run_reader(args.ecdsa_signature_reader, lines, skip, f"ecdsa {kind}")
            else:
                print(f"ecdsa {kind}: selected {len(lines)}, unsupported {sum(skip.values())}")
    if args.rsa_archive:
        archive = check_archive(args.rsa_archive, RSA_SHA256)
        lines, skip = rsa_siggen15_vectors(archive)
        check_count("rsa siggen15", lines, skip)
        if args.rsa_generation_reader:
            run_reader(args.rsa_generation_reader, lines, skip, "rsa siggen15")
        else:
            print(f"rsa siggen15: selected {len(lines)}, unsupported {sum(skip.values())}")
        for kind in ("v15", "pss"):
            lines, skip = rsa_signature_vectors(archive, kind)
            check_count(f"rsa sigver {kind}", lines, skip)
            if args.rsa_signature_reader:
                run_reader(args.rsa_signature_reader, lines, skip, f"rsa sigver {kind}", "--signature-vectors")
            else:
                print(f"rsa sigver {kind}: selected {len(lines)}, unsupported {sum(skip.values())}")
        lines, skip = rsa_siggenpss_vectors(archive)
        check_count("rsa siggenpss", lines, skip)
        if args.rsa_generation_reader:
            run_reader(args.rsa_generation_reader, lines, skip, "rsa siggenpss")
        else:
            print(f"rsa siggenpss: selected {len(lines)}, unsupported {sum(skip.values())}")
        lines, skip = rsa_keygen_vectors(archive, args.rsa_keygen_all)
        check_count("rsa keygen", lines, skip)
        if args.rsa_keygen_reader:
            run_reader(args.rsa_keygen_reader, lines, skip, "rsa keygen", "--vectors")
        else:
            print(f"rsa keygen: selected {len(lines)}, sampled out {sum(skip.values())}")
