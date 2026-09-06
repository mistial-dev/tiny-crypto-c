#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""
generate_kdf_vectors.py
Generates the checked-in tests/kdf/test_vectors.h for tiny-crypto-c.

Selects a representative subset of the NIST CAVP SP 800-108 KBKDF response
files vendored under tests/vectors/kdf/cavp/ (one vector per PRF per file,
rotating the counter location and counter width so every combination appears)
and emits them as C arrays for the default `make test` run. Every emitted KO is
recomputed with an independent pure-Python reference (hmac/hashlib plus the
`cryptography` CMAC primitive); counter-mode vectors are additionally checked
with cryptography's KBKDFHMAC / KBKDFCMAC, which implement counter mode only.
A mismatch is a hard failure. Also emits the Kdf108 cross-check vector.

Requires the `cryptography` package. Regenerate with `make regenerate-vectors`.
"""

import hashlib
import hmac
import os
import re
import sys

from cryptography.hazmat.primitives import cmac, hashes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.kbkdf import (
    CounterLocation, KBKDFCMAC, KBKDFHMAC, Mode)

try:  # cryptography >= 43 moved TripleDES to the decrepit namespace.
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # pragma: no cover
    TripleDES = algorithms.TripleDES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTOR_DIR = os.path.join(ROOT, "tests", "vectors", "kdf", "cavp")
HEADER_PATH = os.path.join(ROOT, "tests", "kdf", "test_vectors.h")

# (file, mode, has_counter, rotation offset for section choice)
FILES = [
    ("KDFCTR_gen.rsp", "counter", True, 0),
    ("KDFFeedbackWithZeroIV_gen.rsp", "feedback", True, 3),
    ("KDFFeedbackNoZeroIV_gen.rsp", "feedback", True, 6),
    ("KDFDblPipelineWithCtr_gen.rsp", "pipeline", True, 9),
    ("KDFFeedbackNoCtr_gen.rsp", "feedback", False, 0),
    ("KDFDblPipelineWOCtr_gen.rsp", "pipeline", False, 0),
]

PRF_IDS = {
    "HMAC_SHA1": 0, "HMAC_SHA224": 1, "HMAC_SHA256": 2, "HMAC_SHA384": 3,
    "HMAC_SHA512": 4, "CMAC_AES128": 5, "CMAC_AES192": 6, "CMAC_AES256": 7,
    "CMAC_TDES2": 8, "CMAC_TDES3": 9,
}
MODE_IDS = {"counter": 0, "feedback": 1, "pipeline": 2}
# Feedback / pipeline counter locations map onto the TC_KBKDF_CTR_* values.
LOCATION_IDS = {"BEFORE_ITER": 1, "AFTER_ITER": 2, "AFTER_FIXED": 3}
HASHES = {"HMAC_SHA1": "sha1", "HMAC_SHA224": "sha224", "HMAC_SHA256": "sha256",
          "HMAC_SHA384": "sha384", "HMAC_SHA512": "sha512"}
CRYPTOGRAPHY_HASHES = {"sha1": hashes.SHA1, "sha224": hashes.SHA224, "sha256": hashes.SHA256,
                       "sha384": hashes.SHA384, "sha512": hashes.SHA512}


# --- independent reference implementation ---------------------------------

def prf(name, key, data):
    if name in HASHES:
        return hmac.new(key, data, HASHES[name]).digest()
    if name.startswith("CMAC_AES"):
        algorithm = algorithms.AES(key)
    else:
        algorithm = TripleDES(key)  # 16-byte keys are 2-key TDEA (K1, K2, K1)
    mac = cmac.CMAC(algorithm)
    mac.update(data)
    return mac.finalize()


def encode_counter(i, rlen_bits):
    return i.to_bytes(rlen_bits // 8, "big")


def kdf_counter(name, key, before, after, rlen, out_len):
    out = b""
    i = 1
    while len(out) < out_len:
        out += prf(name, key, before + encode_counter(i, rlen) + after)
        i += 1
    return out[:out_len]


def kdf_feedback(name, key, iv, fixed, rlen, location, out_len):
    out = b""
    k = iv
    i = 1
    while len(out) < out_len:
        ctr = encode_counter(i, rlen) if location else b""
        if location == "BEFORE_ITER":
            data = ctr + k + fixed
        elif location == "AFTER_ITER":
            data = k + ctr + fixed
        elif location == "AFTER_FIXED":
            data = k + fixed + ctr
        else:
            data = k + fixed
        k = prf(name, key, data)
        out += k
        i += 1
    return out[:out_len]


def kdf_pipeline(name, key, fixed, rlen, location, out_len):
    out = b""
    a = fixed
    i = 1
    while len(out) < out_len:
        a = prf(name, key, a)
        ctr = encode_counter(i, rlen) if location else b""
        if location == "BEFORE_ITER":
            data = ctr + a + fixed
        elif location == "AFTER_ITER":
            data = a + ctr + fixed
        elif location == "AFTER_FIXED":
            data = a + fixed + ctr
        else:
            data = a + fixed
        out += prf(name, key, data)
        i += 1
    return out[:out_len]


def cryptography_counter(name, key, before, after, rlen, out_len):
    """Second opinion for counter mode from the cryptography package."""
    if before and after:
        location, fixed, break_location = CounterLocation.MiddleFixed, before + after, len(before)
    elif before:
        location, fixed, break_location = CounterLocation.AfterFixed, before, None
    else:
        location, fixed, break_location = CounterLocation.BeforeFixed, after, None
    common = dict(mode=Mode.CounterMode, length=out_len, rlen=rlen // 8, llen=None,
                  location=location, label=None, context=None, fixed=fixed,
                  break_location=break_location)
    if name in HASHES:
        kdf = KBKDFHMAC(CRYPTOGRAPHY_HASHES[HASHES[name]](), **common)
    elif name.startswith("CMAC_AES"):
        kdf = KBKDFCMAC(algorithms.AES, **common)
    else:
        kdf = KBKDFCMAC(TripleDES, **common)
    return kdf.derive(key)


# --- .rsp parsing -----------------------------------------------------------

def parse_rsp(path):
    """Yield (section, record) pairs; section is a dict of the bracket headers."""
    section = {}
    record = None
    with open(path, "r", newline="") as handle:
        for raw in handle:
            line = raw.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                if record is not None:
                    yield dict(section), record
                    record = None
                key, _, value = line[1:-1].partition("=")
                if key == "PRF":
                    section = {"PRF": value}
                else:
                    section[key] = value
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key == "COUNT":
                if record is not None:
                    yield dict(section), record
                record = {"COUNT": int(value)}
            else:
                record[key] = value
        if record is not None:
            yield dict(section), record


def select_vectors(filename, mode, has_counter, offset):
    """One vector per PRF, rotating through the 12 (location, rlen) sections."""
    by_prf = {}
    order = []
    for section, record in parse_rsp(os.path.join(VECTOR_DIR, filename)):
        prf_name = section["PRF"]
        if prf_name not in by_prf:
            by_prf[prf_name] = []
            order.append(prf_name)
        by_prf[prf_name].append((section, record))
    chosen = []
    for index, prf_name in enumerate(order):
        entries = by_prf[prf_name]
        if has_counter:
            sections = len(entries) // 40  # 12 sections of 40 COUNTs
            section_index = (index + offset) % sections
            count = (index * 7) % 40
            section, record = entries[section_index * 40 + count]
        else:
            section, record = entries[(index * 7) % len(entries)]
        chosen.append((filename, mode, has_counter, section, record))
    return chosen


def check_and_convert(filename, mode, has_counter, section, record):
    prf_name = section["PRF"]
    key = bytes.fromhex(record["KI"])
    out_len = int(record["L"]) // 8
    expected = bytes.fromhex(record["KO"])
    if int(record["L"]) % 8 != 0 or len(expected) != out_len:
        raise SystemExit(f"{filename}: L is not a byte multiple or KO length mismatch")
    rlen = int(section["RLEN"].split("_")[0]) if has_counter else 0
    location = section.get("CTRLOCATION") if has_counter else None
    iv = bytes.fromhex(record.get("IV", "")) if "IV" in record else b""
    if "IVlen" in record and int(record["IVlen"]) // 8 != len(iv):
        raise SystemExit(f"{filename}: IVlen does not match IV")

    if mode == "counter":
        if location == "MIDDLE_FIXED":
            before = bytes.fromhex(record["DataBeforeCtrData"])
            after = bytes.fromhex(record["DataAfterCtrData"])
            if len(before) != int(record["DataBeforeCtrLen"]) or len(after) != int(record["DataAfterCtrLen"]):
                raise SystemExit(f"{filename}: split fixed-input lengths mismatch")
        else:
            fixed = bytes.fromhex(record["FixedInputData"])
            if len(fixed) != int(record["FixedInputDataByteLen"]):
                raise SystemExit(f"{filename}: FixedInputDataByteLen mismatch")
            before, after = (b"", fixed) if location == "BEFORE_FIXED" else (fixed, b"")
        actual = kdf_counter(prf_name, key, before, after, rlen, out_len)
        second = cryptography_counter(prf_name, key, before, after, rlen, out_len)
        if second != expected:
            raise SystemExit(f"{filename} {prf_name} COUNT={record['COUNT']}: cryptography KBKDF mismatch")
        in1, in2, loc_id = before, after, 0
    else:
        fixed = bytes.fromhex(record["FixedInputData"])
        if len(fixed) != int(record["FixedInputDataByteLen"]):
            raise SystemExit(f"{filename}: FixedInputDataByteLen mismatch")
        if mode == "feedback":
            actual = kdf_feedback(prf_name, key, iv, fixed, rlen, location, out_len)
        else:
            actual = kdf_pipeline(prf_name, key, fixed, rlen, location, out_len)
        in1, in2 = b"", fixed
        loc_id = LOCATION_IDS[location] if has_counter else 0

    if actual != expected:
        raise SystemExit(f"{filename} {prf_name} COUNT={record['COUNT']}: reference mismatch")

    headers = "".join(f"[{k}={v}]" for k, v in section.items())
    return {
        "prf": PRF_IDS[prf_name], "mode": MODE_IDS[mode],
        "use_counter": 1 if has_counter else 0, "counter_bits": rlen,
        "location": loc_id, "key": key, "iv": iv, "in1": in1, "in2": in2,
        "out": expected, "source": f"{filename} {headers} COUNT={record['COUNT']}",
    }


# --- C emission -------------------------------------------------------------

def c_array(name, data):
    if len(data) == 0:
        return f"static const uint8_t {name}[1] = {{ 0x00 }}; /* empty; length 0 */\n"
    lines = []
    for offset in range(0, len(data), 12):
        chunk = data[offset:offset + 12]
        lines.append("  " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    body = "\n".join(lines).rstrip(",")
    return f"static const uint8_t {name}[{len(data)}] = {{\n{body}\n}};\n"


def known_vector():
    """Kdf108 cross-check: label/context fixed input, HMAC-SHA-256 counter r=32."""
    key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    label = b"TestLabel"
    context = b"Vault:1|Box:2|Item:3"
    out_len = 32
    fixed = label + b"\x00" + context + (out_len * 8).to_bytes(4, "big")
    expected = bytes.fromhex("D39D601E90C9B0CB45B2E841313D0D4172A1B3C52AA8D049302B401AEB9EDFB6")
    kdf = KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, out_len, 4, 4,
                    CounterLocation.BeforeFixed, label, context, None)
    if kdf.derive(key) != expected or kdf_counter("HMAC_SHA256", key, b"", fixed, 32, out_len) != expected:
        raise SystemExit("Kdf108 known vector mismatch")
    return key, label, context, fixed, expected


def main():
    vectors = []
    for filename, mode, has_counter, offset in FILES:
        for entry in select_vectors(filename, mode, has_counter, offset):
            vectors.append(check_and_convert(*entry))

    out = []
    out.append("/*\n * SPDX-FileCopyrightText: Mistial Dev\n * SPDX-License-Identifier: GPL-2.0-or-later\n */\n\n")
    out.append("/* Auto-generated by tools/generate_kdf_vectors.py; do not edit. */\n")
    out.append("#ifndef KDF_TEST_VECTORS_H\n#define KDF_TEST_VECTORS_H\n\n#include <stdint.h>\n#include <stddef.h>\n\n")

    out.append("/* --- Kdf108 cross-check vector (HMAC-SHA-256, counter mode, r = 32) --- */\n")
    key, label, context, fixed, expected = known_vector()
    out.append(c_array("kbkdf_known_key", key))
    out.append(c_array("kbkdf_known_label", label))
    out.append(c_array("kbkdf_known_context", context))
    out.append(c_array("kbkdf_known_fixed", fixed))
    out.append(c_array("kbkdf_known_out", expected))
    out.append("\n")

    out.append("/* --- NIST CAVP KBKDFVS subset; see tests/vectors/kdf/cavp/README.md --- */\n")
    for name, value in sorted(PRF_IDS.items(), key=lambda item: item[1]):
        out.append(f"#define KBKDF_PRF_{name} {value}\n")
    for name, value in MODE_IDS.items():
        out.append(f"#define KBKDF_MODE_{name.upper()} {value}\n")
    out.append("/* location: 0 for counter mode (position is the in1/in2 split), otherwise\n"
               "   1 = BEFORE_ITER, 2 = AFTER_ITER, 3 = AFTER_FIXED (TC_KBKDF_CTR_*).\n"
               "   in1/in2: counter mode = before/after the counter; other modes = unused/fixed. */\n")
    out.append("struct kbkdf_vector {\n"
               "  uint8_t prf; uint8_t mode; uint8_t use_counter; uint8_t counter_bits; uint8_t location;\n"
               "  const uint8_t* key; size_t key_len;\n"
               "  const uint8_t* iv; size_t iv_len;\n"
               "  const uint8_t* in1; size_t in1_len;\n"
               "  const uint8_t* in2; size_t in2_len;\n"
               "  const uint8_t* out; size_t out_len;\n"
               "  const char* source;\n"
               "};\n\n")
    for index, v in enumerate(vectors):
        for field in ("key", "iv", "in1", "in2", "out"):
            out.append(c_array(f"kbkdf_{index}_{field}", v[field]))
    out.append(f"#define KBKDF_VECTOR_COUNT {len(vectors)}\n")
    out.append("static const struct kbkdf_vector kbkdf_vectors[KBKDF_VECTOR_COUNT] = {\n")
    for index, v in enumerate(vectors):
        out.append(f"  {{ {v['prf']}, {v['mode']}, {v['use_counter']}, {v['counter_bits']}, {v['location']},\n")
        for field in ("key", "iv", "in1", "in2", "out"):
            out.append(f"    kbkdf_{index}_{field}, {len(v[field])},\n")
        out.append(f"    \"{v['source']}\" }},\n")
    out.append("};\n\n")
    out.append("#endif /* KDF_TEST_VECTORS_H */\n")

    with open(HEADER_PATH, "w", newline="\n") as handle:
        handle.write("".join(out))
    print(f"Wrote {HEADER_PATH} ({len(vectors)} CAVP vectors, all cross-checked)")


if __name__ == "__main__":
    main()
