# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""TR-03110 framing and encoding checks against frozen external certificates."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def fields(data):
    result = {}
    offset = 0
    while offset < len(data):
        start = offset
        tag = data[offset]
        offset += 1
        if tag & 31 == 31:
            while True:
                byte = data[offset]
                offset += 1
                tag = tag * 256 + byte
                if not byte & 128:
                    break
        length = data[offset]
        offset += 1
        if length & 128:
            width = length & 127
            if not width or width > 4:
                raise ValueError("length")
            length = int.from_bytes(data[offset:offset + width], "big")
            offset += width
        end = offset + length
        if end > len(data) or tag in result:
            raise ValueError("length or duplicate tag")
        result[tag] = (data[offset:end], data[start:end])
        offset = end
    return result


# These need signature mathematics, authorization policy, or issuer context,
# or are explicitly permitted (unknown extensions and ISO-8859-1 mnemonics).
PARSEABLE = {
    "body_car_non_ascii", "body_chat_reserved_bits_set", "body_chat_role_cvca_in_terminal",
    "body_chr_equals_car_on_terminal", "body_extension_unknown_oid", "body_pubkey_point_not_on_curve",
    "signature_all_zero", "signature_der_encoded", "signature_flipped_bit", "signature_short",
}
CERT_REJECT = {"BP256_terminal_profile_id_1", "BP256_terminal_forced_is_oid_with_at_bits", "P521_cvca"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", required=True, type=Path)
    parser.add_argument("--corpus", required=True, type=Path)
    args = parser.parse_args()

    def read(path, *extra):
        output = subprocess.check_output([str(args.reader), str(path), *map(str, extra)], text=True)
        return dict(line.split("=", 1) for line in output.splitlines())

    entries = json.loads((args.corpus / "generated/manifest.json").read_text())["entries"]
    for entry in entries:
        path = args.corpus / "generated" / entry["file"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            raise AssertionError(f"Changed fixture: {path}")
    certificates = sorted(args.corpus.glob("*/certs/*.cvcert"))
    if len(certificates) < 99:
        raise AssertionError("Incomplete certificate corpus")
    count = 0
    for source in ("eid_testbeds", "generated"):
        records = {}
        for path in certificates:
            if path.parent.parent.name != source:
                continue
            outer = fields(fields(path.read_bytes())[0x7f21][0])
            body = fields(outer[0x7f4e][0])
            records[path] = (body, fields(body[0x7f49][0]), outer)
        holders = {body[0x5f20][0]: path for path, (body, _, _) in records.items()}

        def domain(path):
            visited = set()
            while path not in visited:
                visited.add(path)
                body, key, _ = records[path]
                if 0x85 in key:
                    return key
                path = holders[body[0x42][0]]
            raise AssertionError("No inherited EC domain")

        for path, (body, key, outer) in records.items():
            expected = path.stem not in CERT_REJECT
            output = read(path)
            if (output["result"] == "0") != expected:
                raise AssertionError(f"{path}: parse result {output['result']}")
            if not expected:
                count += 1
                continue
            for name, value in (("issuer", body[0x42][0]), ("holder", body[0x5f20][0]),
                                ("signed_data", outer[0x7f4e][1]), ("signature", outer[0x5f37][0])):
                if output[name] != value.hex():
                    raise AssertionError(f"{path}: {name}")
            issuer_path = holders[body[0x42][0]]
            issuer_key = records[issuer_path][1]
            subject_width = len(domain(path)[0x81][0]) if 0x86 in key else 0
            order_width = len(domain(issuer_path)[0x85][0]) if 0x86 in issuer_key else 0
            rsa_width = len(issuer_key[0x81][0]) if not order_width else 0
            contextual = read(path, subject_width, order_width, rsa_width)
            point_ok = not subject_width or len(key[0x86][0]) == 1 + 2 * subject_width
            signature_ok = len(outer[0x5f37][0]) == (2 * order_width if order_width else rsa_width)
            expected_result = "0" if point_ok and signature_ok else "-1"
            if contextual["context_encoding"] != expected_result:
                raise AssertionError(f"{path}: context encoding {contextual['context_encoding']}")
            count += 1
    malformed = sorted((args.corpus / "generated/malformed").glob("*.cvcert"))
    if len(malformed) < 54:
        raise AssertionError("Incomplete malformed corpus")
    for path in malformed:
        output = read(path)
        if (output["result"] == "0") != (path.stem in PARSEABLE):
            raise AssertionError(f"{path}: parse result {output['result']}")
        if path.stem in ("signature_short", "signature_der_encoded"):
            outer = fields(fields(path.read_bytes())[0x7f21][0])
            body = fields(outer[0x7f4e][0])
            issuer_path = holders[body[0x42][0]]
            inherited = domain(issuer_path)
            output = read(path, len(inherited[0x81][0]), len(inherited[0x85][0]), 0)
            if output["context_encoding"] != "-1":
                raise AssertionError(f"{path}: signature width accepted")
    government = bytes.fromhex((args.corpus / "eid_testbeds/GOV_TERMINAL_CERT.hex").read_text())
    output = subprocess.check_output([str(args.reader), "-"], input=government).decode()
    output = dict(line.split("=", 1) for line in output.splitlines())
    if output["result"] != "0":
        raise AssertionError("Government terminal certificate rejected")
    count += 1
    keys = sorted(args.corpus.glob("*/public_keys/*"))
    for path in keys:
        key = fields(fields(path.read_bytes())[0x7f49][0])
        oid = key[6][0]
        # The generator's RSA exports carry RI-DH identifiers, not TA-RSA.
        expected = oid[7:9] == bytes([5, 2])
        if expected:
            width = len(key[0x81][0])
            expected = len(key[0x84][0]) == len(key[0x86][0]) == 1 + 2 * width
        output = read(path, "key")
        if (output["result"] == "0") != expected:
            raise AssertionError(f"{path}: key result {output['result']}")
    print(f"Checked {count} certificates, {len(malformed)} malformed variants, and {len(keys)} public keys")


if __name__ == "__main__":
    main()
