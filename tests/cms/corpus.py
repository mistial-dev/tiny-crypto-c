# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check CMS structures extracted from the captured PIV object corpus."""
import argparse
from collections import Counter
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from munit_runner import run_reader
from piv.corpus import fields_of

EMPTY_UUID_SAMPLE = (
    "icam_cards/55_FIPS_201-2_Missing_Security_Object/10_Face_Object.bin"
)
INVALID_SIGNATURE_SAMPLES = {
    "icam_cards/06_Tampered_PHOTO/10_Face_Object.bin",
    "icam_cards/07_Tampered_Fingerprints/9_Fingerprints.bin",
}
MISSING_SIGNER_SAMPLE = "icam_cards/19_CHUID_UUID_mismatch/9_Fingerprints.bin"
IDENTIFIER_MISMATCH_SAMPLES = {
    f"icam_cards/{card}/{name}.bin"
    for card, names in (
        ("04_Tampered_CHUID", ("10_Face_Object", "9_Fingerprints")),
        ("17_PHOTO_FASCN_mismatch", ("10_Face_Object",)),
        ("18_Fingerprints_FASCN_mismatch", ("9_Fingerprints",)),
        ("19_CHUID_UUID_mismatch", ("10_Face_Object", "9_Fingerprints")),
        ("21_PHOTO_UUID_mismatch", ("10_Face_Object",)),
        ("22_Fingerprints_UUID_mismatch", ("9_Fingerprints",)),
        ("46_Golden_FIPS_201-2_PIV_ICI_9", ("10_Face_Object", "9_Fingerprints")),
        ("54_Golden_FIPS_201-2_NFI_PIV-I", ("9_Fingerprints",)),
        ("54_Golden_FIPS_201-2_NFI_PIV-I-X", ("9_Fingerprints",)),
    )
    for name in names
}
HEADER_FASCN_MISMATCH_SAMPLES = IDENTIFIER_MISMATCH_SAMPLES - {
    "icam_cards/19_CHUID_UUID_mismatch/10_Face_Object.bin",
    "icam_cards/19_CHUID_UUID_mismatch/9_Fingerprints.bin",
    "icam_cards/21_PHOTO_UUID_mismatch/10_Face_Object.bin",
    "icam_cards/22_Fingerprints_UUID_mismatch/9_Fingerprints.bin",
}
INVALID_METADATA_SAMPLES = {
    "icam_cards/49_FIPS_201-2_Facial_Image_CBEFF_Expired/10_Face_Object.bin",
    "icam_cards/51_FIPS_201-2_Fingerprint_CBEFF_Expired/9_Fingerprints.bin",
}


def biometric_signature(value):
    """Locate the security block using SP 800-76-2 Table 14 lengths."""
    header_bytes = 88
    if len(value) < header_bytes:
        raise AssertionError("Truncated CBEFF header")
    record_bytes = int.from_bytes(value[2:6], "big")
    signature_bytes = int.from_bytes(value[6:8], "big")
    signature_offset = header_bytes + record_bytes
    if signature_offset + signature_bytes != len(value):
        raise AssertionError("CBEFF lengths do not match the object")
    return value[signature_offset:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    args = parser.parse_args()
    records, sources, biometric_records = [], [], []
    counts = Counter()
    for path in sorted(args.corpus.rglob("*.bin")):
        name = path.name.lower()
        if "chuid" in name:
            kind, tag = "chuid", 0x3e
        elif "security_object" in name:
            kind, tag = "security", 0xbb
        elif any(part in name for part in ("fingerprints", "face_object", "iris")):
            kind, tag = "biometric", 0xbc
        else:
            continue
        fields = fields_of(path.read_bytes())
        if 0x53 in fields:
            fields = fields_of(fields[0x53])
        value = fields[tag]
        if kind == "biometric":
            signature = biometric_signature(value)
            relative = path.relative_to(args.corpus).as_posix()
            expected = "valid"
            if relative in INVALID_SIGNATURE_SAMPLES or relative == EMPTY_UUID_SAMPLE:
                expected = "invalid"
            elif relative == MISSING_SIGNER_SAMPLE:
                expected = "missing-signer"
            chuid_fields = fields_of((path.parent / "8_CHUID_Object.bin").read_bytes())
            chuid = chuid_fields[0x3e]
            identifiers = chuid_fields[0x30] + chuid_fields[0x34]
            binding = "invalid" if relative == EMPTY_UUID_SAMPLE else (
                "mismatch" if relative in IDENTIFIER_MISMATCH_SAMPLES else "match")
            header = "mismatch" if relative in HEADER_FASCN_MISMATCH_SAMPLES else "match"
            metadata = "invalid" if relative in INVALID_METADATA_SAMPLES else "valid"
            biometric_records.append(
                f"{expected} {binding} {header} {metadata} {signature.hex()} {value.hex()} {chuid.hex()} {identifiers.hex()}\n")
            value = signature
        if not value:
            raise AssertionError(f"Empty CMS in {path}")
        # This capture encodes entryUUID as an empty OCTET STRING (RFC 4530 §2.1).
        verdict = "invalid-attributes" if path.relative_to(args.corpus).as_posix() == EMPTY_UUID_SAMPLE else "valid"
        records.append(f"{kind} {verdict} {value.hex()}\n")
        sources.append(str(path.relative_to(args.corpus)))
        counts[kind] += 1
    if counts["chuid"] < 70 or counts["security"] < 69 or counts["biometric"] < 111:
        raise AssertionError(f"Incomplete CMS corpus: {dict(counts)}")
    with tempfile.TemporaryDirectory(prefix="tiny-crypto-cms-corpus-") as directory:
        vectors = Path(directory) / "cms.txt"
        vectors.write_text("".join(records), encoding="ascii")
        try:
            run_reader([args.reader, "--cms-vectors", vectors])
        except AssertionError as error:
            listing = "\n".join(f"{index}: {path}" for index, path in enumerate(sources))
            raise AssertionError(f"{error}\nCorpus record order:\n{listing}") from error
        vectors.write_text("".join(biometric_records), encoding="ascii")
        run_reader([args.reader, "--biometric-vectors", vectors])
    print(f"CMS schema checks and truncated prefixes: {dict(counts)}")


if __name__ == "__main__":
    main()
