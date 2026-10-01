#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify a private TWIC contact capture without displaying card data.

The input directory is created by the private PC/SC capture tool. This script
never writes into it and never includes captured bytes in diagnostics. It is a
development tool; real card captures must stay outside the repository.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import re
import subprocess
import sys
import tempfile
import warnings
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.oid import ExtensionOID
from PIL import Image, UnidentifiedImageError


# The default evaluation time of certificate dates and anchored paths: the
# day the private captures were verified. --at selects another instant.
CAPTURE_TIME = datetime.datetime(2026, 9, 27, 12, 0, 0, tzinfo=datetime.timezone.utc)


def utc_time(text: str) -> datetime.datetime:
    """Parse YYYY-MM-DDTHH:MM:SSZ for --at."""
    try:
        value = datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DDTHH:MM:SSZ") from error
    return value.replace(tzinfo=datetime.timezone.utc)


class VerificationError(Exception):
    """A failed check with a label that contains no card material."""


def require(condition: bool, label: str) -> None:
    if not condition:
        raise VerificationError(label)


@dataclass(frozen=True)
class Field:
    tag: bytes
    value: bytes
    encoded: bytes


def fields(data: bytes) -> list[Field]:
    result = []
    offset = 0
    while offset < len(data):
        start = offset
        first = data[offset]
        offset += 1
        if first & 31 == 31:
            for _ in range(4):
                require(offset < len(data), "TLV tag truncated")
                more = data[offset] & 128
                offset += 1
                if not more:
                    break
            else:
                raise VerificationError("TLV tag too long")
        tag = data[start:offset]
        require(offset < len(data), "TLV length missing")
        length = data[offset]
        offset += 1
        if length & 128:
            count = length & 127
            require(0 < count <= 4 and offset + count <= len(data), "TLV length invalid")
            length = int.from_bytes(data[offset:offset + count], "big")
            offset += count
        end = offset + length
        require(end <= len(data), "TLV value truncated")
        result.append(Field(tag, data[offset:end], data[start:end]))
        offset = end
    return result


def one(data: bytes, tag: bytes) -> Field:
    parsed = fields(data)
    require(len(parsed) == 1 and parsed[0].tag == tag, "TLV outer tag")
    return parsed[0]


def object_fields(directory: Path, name: str) -> list[Field]:
    return fields(one((directory / name).read_bytes(), b"\x53").value)


def find(items: list[Field], tag: bytes) -> Field:
    matches = [item for item in items if item.tag == tag]
    require(len(matches) == 1, "TLV required field")
    return matches[0]


def oid_value(dotted: str) -> bytes:
    parts = [int(part) for part in dotted.split(".")]
    require(len(parts) >= 2 and parts[0] <= 2 and parts[1] < 40,
            "expected OID invalid")
    encoded = [40 * parts[0] + parts[1]]
    for component in parts[2:]:
        group = [component & 127]
        component >>= 7
        while component:
            group.insert(0, 128 | (component & 127))
            component >>= 7
        encoded.extend(group)
    return bytes(encoded)


def exact_certificate_oids(cert: x509.Certificate) -> None:
    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    policies = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
    expected_eku = {"2.16.840.1.101.3.6.7", "1.3.6.1.4.1.29138.6.7"}
    expected_policy = {"2.16.840.1.101.3.6.7"}
    require({item.dotted_string for item in eku} == expected_eku, "content signer EKU set")
    require({item.policy_identifier.dotted_string for item in policies} == expected_policy,
            "content signer policy set")
    encoded = cert.public_bytes(Encoding.DER)
    for dotted in expected_eku | expected_policy:
        value = oid_value(dotted)
        require(bytes((6, len(value))) + value in encoded,
                "content signer encoded OID")


def cms_verify(cms: bytes, signer: x509.Certificate, content: bytes | None) -> bytes:
    with tempfile.TemporaryDirectory(prefix="twic-private-verify-") as name:
        workspace = Path(name)
        (workspace / "cms.der").write_bytes(cms)
        (workspace / "signer.pem").write_bytes(signer.public_bytes(Encoding.PEM))
        command = ["openssl", "cms", "-verify", "-binary", "-inform", "DER",
                   "-in", str(workspace / "cms.der"), "-noverify", "-certfile",
                   str(workspace / "signer.pem"), "-out", str(workspace / "verified.bin")]
        if content is not None:
            (workspace / "content.bin").write_bytes(content)
            command.extend(("-content", str(workspace / "content.bin")))
        result = subprocess.run(command, capture_output=True, check=False)
        require(result.returncode == 0, "CMS signature")
        verified = (workspace / "verified.bin").read_bytes()
        if content is not None:
            require(verified == content, "CMS signed content")
        return verified


def verify_paths(directory: Path, bundle_dir: Path | None, anchor_file: Path | None,
                 signer: x509.Certificate, at: datetime.datetime) -> str:
    source = bundle_dir or directory
    content_bundle = source / "content-issuer-0.bin"
    card_bundle = source / "card-issuer-0.bin"
    if not content_bundle.exists() and not card_bundle.exists():
        require(anchor_file is None, "issuer bundle missing")
        return "issuer bundle not available"
    require(content_bundle.is_file() and card_bundle.is_file(), "issuer bundle incomplete")
    anchors: list[x509.Certificate] = []
    if anchor_file is not None:
        anchors = x509.load_pem_x509_certificates(anchor_file.read_bytes())
        require(len(anchors) > 0, "trust anchors empty")
    card_field = find(object_fields(directory, "PIV-5fc101.bin"), b"\x70")
    card = x509.load_der_x509_certificate(card_field.value)
    states = []
    for label, leaf, path in (("signer", signer, content_bundle),
                              ("card", card, card_bundle)):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            issuers = pkcs7.load_der_pkcs7_certificates(path.read_bytes())
        require(bool(issuers), label + " issuer bundle empty")
        candidates = issuers + anchors
        chain = [leaf]
        fingerprints = set()
        dates_valid = True
        complete = False
        while True:
            current = chain[-1]
            fingerprint = current.fingerprint(hashes.SHA256())
            require(fingerprint not in fingerprints and len(chain) <= 12,
                    label + " chain loop/depth")
            fingerprints.add(fingerprint)
            dates_valid &= current.not_valid_before_utc <= at <= current.not_valid_after_utc
            if len(chain) == 1:
                usage = current.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                require(usage.digital_signature, label + " digitalSignature usage")
            else:
                constraints = current.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS).value
                usage = current.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                require(constraints.ca and usage.key_cert_sign,
                        label + " CA constraints/usage")
                def is_ca(cert: x509.Certificate) -> bool:
                    try:
                        return cert.extensions.get_extension_for_oid(
                            ExtensionOID.BASIC_CONSTRAINTS).value.ca
                    except x509.ExtensionNotFound:
                        return False
                ca_below = sum(1 for cert in chain[:-1] if is_ca(cert))
                require(constraints.path_length is None or
                        ca_below <= constraints.path_length, label + " path length")
            if current.issuer == current.subject:
                try:
                    current.verify_directly_issued_by(current)
                except Exception as error:
                    raise VerificationError(label + " root self-signature") from error
                complete = True
                break
            matching = [item for item in candidates if item.subject == current.issuer]
            selected = None
            for candidate in matching:
                try:
                    current.verify_directly_issued_by(candidate)
                except Exception:
                    continue
                selected = candidate
                break
            if selected is None:
                require(anchor_file is None, label + " issuer signature")
                break
            chain.append(selected)
        if not complete:
            states.append(label + " issuer unavailable" +
                          (" (expired)" if not dates_valid else ""))
            continue
        if anchor_file is not None:
            require(dates_valid, label + " certificate validity")
            anchor_fingerprints = {item.fingerprint(hashes.SHA256()) for item in anchors}
            require(chain[-1].fingerprint(hashes.SHA256()) in anchor_fingerprints,
                    label + " trust anchor mismatch")
            with tempfile.TemporaryDirectory(prefix="twic-private-path-") as name:
                workspace = Path(name)
                (workspace / "leaf.pem").write_bytes(leaf.public_bytes(Encoding.PEM))
                (workspace / "issuers.pem").write_bytes(b"".join(
                    item.public_bytes(Encoding.PEM) for item in issuers))
                result = subprocess.run(["openssl", "verify", "-purpose", "any",
                                         "-attime", str(int(at.timestamp())),
                                         "-policy_check", "-CAfile", str(anchor_file),
                                         "-untrusted", str(workspace / "issuers.pem"),
                                         str(workspace / "leaf.pem")],
                                        capture_output=True, check=False)
                require(result.returncode == 0, label + " anchored path")
        states.append(label + (" anchored" if anchor_file is not None else
                               " chain signatures verified" +
                               (" (expired)" if not dates_valid else "")))
    return ", ".join(states) + ("; explicit anchors" if anchor_file is not None else
                                "; trust not established")


def verify_apdus(directory: Path, profile: str,
                 interface: str = "contact") -> dict[str, int]:
    trace = [json.loads(line) for line in (directory / "raw-apdu.jsonl").read_text().splitlines()]
    require(trace and trace[0].get("type") == "session", "APDU session")
    require(trace[0].get("interface") == interface, "APDU interface")
    expected_aids = {"legacy": bytes.fromhex("a000000367200000010101"),
                     "nexgen": bytes.fromhex("a000000367200000010103")}
    piv_aid = bytes.fromhex("a000000308000010000100")
    selected = None
    pending = None
    length_retry = None
    next_le = None
    payload = bytearray()
    count = {"select": 0, "present": 0, "absent": 0, "denied": 0, "chained": 0}
    denied = set()
    absent = set()
    for seq, record in enumerate(trace[1:], 1):
        require(record.get("type") == "exchange" and record.get("seq") == seq,
                "APDU sequence")
        require(record.get("pcsc_result") == 0, "PC/SC exchange")
        command = bytes.fromhex(record["command_hex"])
        response = bytes.fromhex(record["response_hex"])
        require(len(command) >= 5 and len(response) >= 2, "APDU framing")
        require(command[0] == 0, "APDU CLA")
        sw = int.from_bytes(response[-2:], "big")
        body = response[:-2]
        label = record["operation"]
        require(not label.startswith("VERIFY"), "PIN APDU recorded")
        if label.startswith("SELECT "):
            require(pending is None and command[:4] == bytes.fromhex("00a40400"),
                    "APDU SELECT command")
            aid = command[5:5 + command[4]]
            require(len(aid) == command[4] and len(command) == 6 + len(aid),
                    "APDU SELECT length")
            require(aid in (expected_aids[profile], piv_aid) and sw == 0x9000,
                    "APDU SELECT AID/status")
            selected = "TWIC" if aid == expected_aids[profile] else "PIV"
            count["select"] += 1
            continue
        require(selected is not None, "APDU selection")
        if label.startswith("GET DATA "):
            require((pending is None or length_retry is not None) and
                    command[:4] == bytes.fromhex("00cb3fff"),
                    "APDU GET DATA command")
            require(len(command) == command[4] + 6 and command[5] == 0x5c,
                    "APDU GET DATA selector")
            tag_len = command[6]
            tag = command[7:7 + tag_len]
            require(len(tag) == tag_len and command[4] == tag_len + 2,
                    "APDU GET DATA tag")
            object_name = f"{selected}-{tag.hex()}"
            require(pending in (None, object_name), "APDU GET DATA retry target")
            if length_retry is not None:
                original, corrected = length_retry
                require(command[:-1] == original[:-1] and command[-1] == corrected,
                        "APDU length correction command")
                length_retry = None
            pending = object_name
            require(label == f"GET DATA {pending.replace('-', ' ')}", "APDU operation label")
            if length_retry is None:
                payload.clear()
        elif label.startswith("GET RESPONSE "):
            require(pending is not None and command[:4] == bytes.fromhex("00c00000"),
                    "APDU GET RESPONSE command")
            require(len(command) == 5 and command[4] == next_le,
                    "APDU GET RESPONSE length")
            require(label == f"GET RESPONSE {pending.replace('-', ' ')}", "APDU continuation label")
            count["chained"] += 1
        else:
            raise VerificationError("unexpected APDU operation")
        if sw >> 8 == 0x6c:
            require(not body and pending is not None, "APDU length correction")
            if label.startswith("GET DATA "):
                length_retry = (command, sw & 255)
            else:
                next_le = sw & 255
            continue
        payload.extend(body)
        require(len(payload) <= 20000, "APDU object bound")
        if sw >> 8 == 0x61:
            next_le = sw & 255
            continue
        next_le = None
        path = directory / f"{pending}.bin"
        if sw in (0x9000, 0x6282) and payload:
            require(path.exists() and path.read_bytes() == bytes(payload),
                    "APDU object reconstruction")
            count["present"] += 1
        else:
            require(sw in (0x6a82, 0x6a88, 0x9000, 0x6282, 0x6982, 0x6a81) and
                    not path.exists() and not payload,
                    "APDU absent object")
            if sw in (0x6982, 0x6a81):
                require(sw == (0x6a81 if profile == "legacy" else 0x6982),
                        "contactless access status")
                denied.add(pending)
                count["denied"] += 1
            else:
                absent.add(pending)
                count["absent"] += 1
        pending = None
    require(pending is None and count["select"] == 2, "APDU completion")
    if interface == "contactless":
        sticker_absent = {f"TWIC-dfc1{index:02x}" for index in
                          (*range(0xe1, 0xeb), *range(0xfa, 0xfe))}
        if profile == "legacy":
            expected_denied = {"TWIC-dfc101", "PIV-5fc105", "PIV-5fc107",
                               "PIV-5fc10a", "PIV-5fc10b"}
            require(denied == expected_denied and sticker_absent <= absent and
                    len(absent) == 26, "Legacy contactless access/status policy")
        else:
            expected_denied = {"TWIC-dfc101", "PIV-5fc105", "PIV-5fc107"} | {
                f"PIV-5fc1{index:02x}" for index in range(0x0a, 0x10)}
            require(denied == expected_denied and absent == sticker_absent,
                    "NEXGEN contactless access/status policy")
    return count


def verify_contactless(capture_root: Path, profile: str) -> dict[str, object] | None:
    contactless = capture_root / f"{profile}-contactless"
    if not contactless.is_dir():
        return None
    contact = capture_root / f"{profile}-contact"
    counts = verify_apdus(contactless, profile, "contactless")
    files = list(contactless.glob("TWIC-*.bin")) + list(contactless.glob("PIV-*.bin"))
    require(len(files) == (6 if profile == "legacy" else 14),
            "contactless readable object count")
    for file in files:
        require((contact / file.name).is_file() and
                (contact / file.name).read_bytes() == file.read_bytes(),
                "contact/contactless object equality")
    proof = proof_status(contactless, profile)
    return {"objects": len(files), "denied": counts["denied"], "card_key_proof": proof}


def proof_status(directory: Path, profile: str) -> str:
    try:
        return verify_card_key_proof(directory)
    except VerificationError:
        if profile == "legacy":
            other = directory.parent / "nexgen-contact"
            if other.is_dir():
                try:
                    alternate = verify_card_key_proof(directory, other)
                    if alternate == "verified, session unbound":
                        return "MISATTRIBUTED TO NEXGEN"
                except VerificationError:
                    pass
        return "INVALID"


def decrypt_object(directory: Path, tag: str, key: bytes) -> tuple[bytes, bytes]:
    contents = one((directory / f"TWIC-{tag}.bin").read_bytes(), b"\x53").value
    cipher = find(fields(contents), b"\xbc").value
    require(len(cipher) and len(cipher) % 16 == 0, "AES ciphertext length")
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded = decryptor.update(cipher) + decryptor.finalize()
    amount = padded[-1]
    require(1 <= amount <= 16 and padded[-amount:] == bytes([amount]) * amount,
            "AES PKCS7 padding")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    require(encryptor.update(padded) + encryptor.finalize() == cipher,
            "AES re-encryption")
    return padded[:-amount], contents


def verify_cbeff(blob: bytes, signer: x509.Certificate, label: str) -> None:
    require(len(blob) >= 89 and blob[0] == 3 and blob[1] in (0x0d, 0x0f),
            label + " CBEFF header")
    record_len = int.from_bytes(blob[2:6], "big")
    signature_len = int.from_bytes(blob[6:8], "big")
    require(record_len > 0 and signature_len > 0 and
            len(blob) == 88 + record_len + signature_len, label + " CBEFF lengths")
    owner = int.from_bytes(blob[8:10], "big")
    fmt = int.from_bytes(blob[10:12], "big")
    biometric_type = int.from_bytes(blob[36:39], "big")
    if label == "fingerprint":
        require((owner, fmt, biometric_type) in
                ((0x001b, 0x0401, 8), (0x001b, 0x0201, 8)), "fingerprint format")
    elif label == "face":
        require((owner, fmt, biometric_type) == (0x001b, 0x0501, 2), "face format")
    record = blob[88:88 + record_len]
    if label == "fingerprint":
        verify_fingerprint_record(record)
    elif label == "face":
        verify_face_record(record)
    cms_verify(blob[88 + record_len:], signer, blob[:88 + record_len])


def verify_fingerprint_record(record: bytes) -> None:
    require(len(record) >= 26 and record[:8] == b"FMR\x00 20\x00" and
            int.from_bytes(record[8:10], "big") == len(record), "FMR header")
    width = int.from_bytes(record[16:18], "big")
    height = int.from_bytes(record[18:20], "big")
    require(width > 0 and height > 0 and record[24] == 2 and record[25] == 0,
            "FMR dimensions/views")
    offset = 26
    positions = set()
    for _ in range(2):
        require(offset + 4 <= len(record), "FMR view")
        position, impression, quality, count = record[offset:offset + 4]
        require(position <= 10 and position not in positions and impression in (0, 2) and
                quality in (20, 40, 60, 80, 100, 254, 255) and count <= 128,
                "FMR view metadata")
        positions.add(position)
        offset += 4
        require(offset + 6 * count + 2 <= len(record), "FMR minutiae length")
        for _ in range(count):
            minutia = record[offset:offset + 6]
            x = int.from_bytes(minutia[:2], "big") & 0x3fff
            y = int.from_bytes(minutia[2:4], "big") & 0x3fff
            require(x < width and y < height and minutia[4] <= 179 and minutia[5] <= 100,
                    "FMR minutia bounds")
            offset += 6
        require(record[offset:offset + 2] == b"\x00\x00", "FMR extension length")
        offset += 2
    require(offset == len(record), "FMR trailing data")


def verify_face_record(record: bytes) -> None:
    require(len(record) >= 14 and record[:8] == b"FAC\x00010\x00" and
            int.from_bytes(record[8:12], "big") == len(record), "FAC header")
    count = int.from_bytes(record[12:14], "big")
    require(count > 0, "FAC image count")
    offset = 14
    for _ in range(count):
        require(offset + 20 <= len(record), "FAC image header")
        block_len = int.from_bytes(record[offset:offset + 4], "big")
        features = int.from_bytes(record[offset + 4:offset + 6], "big")
        require(block_len >= 32 and offset + block_len <= len(record) and
                features <= (block_len - 32) // 8, "FAC image block")
        info_offset = offset + 20 + features * 8
        require(info_offset + 12 < offset + block_len, "FAC image information")
        info = record[info_offset:info_offset + 12]
        width = int.from_bytes(info[2:4], "big")
        height = int.from_bytes(info[4:6], "big")
        require(width > 0 and height > 0 and info[0] <= 1 and info[1] <= 1 and
                info[6] == 1 and info[7] in (2, 6), "FAC image format/dimensions")
        image = record[info_offset + 12:offset + block_len]
        if info[1] == 0:
            require(image.startswith(b"\xff\xd8") and image.endswith(b"\xff\xd9"),
                    "FAC JPEG markers")
            try:
                with Image.open(io.BytesIO(image)) as decoded:
                    require(decoded.format == "JPEG" and decoded.size == (width, height),
                            "FAC JPEG dimensions")
                    decoded.load()
            except (OSError, UnidentifiedImageError) as error:
                raise VerificationError("FAC JPEG decoding") from error
        else:
            require(image.startswith(b"\x00\x00\x00\x0cjP  \r\n\x87\n"),
                    "FAC JPEG2000 marker")
        offset += block_len
    require(offset == len(record), "FAC trailing data")


def verify_lds(lds: bytes, mapping: bytes, sources: dict[int, bytes],
               expected: dict[int, int]) -> str:
    outer = one(lds, b"\x30")
    top = fields(outer.value)
    require(len(top) >= 3 and [item.tag for item in top[:3]] ==
            [b"\x02", b"\x30", b"\x30"], "LDS structure")
    algorithm = fields(top[1].value)
    require(algorithm and algorithm[0].tag == b"\x06", "LDS digest algorithm")
    digest_oid = algorithm[0].value
    algorithms = {oid_value("1.3.14.3.2.26"): "sha1",
                  oid_value("2.16.840.1.101.3.4.2.1"): "sha256"}
    require(digest_oid in algorithms, "LDS digest unsupported")
    hash_name = algorithms[digest_oid]
    hashes = fields(top[2].value)
    require(len(mapping) == 3 * len(hashes) == 3 * len(expected), "LDS mapping count")
    observed = {}
    for index, entry in enumerate(hashes):
        require(entry.tag == b"\x30", "LDS group entry")
        parts = fields(entry.value)
        require(len(parts) == 2 and parts[0].tag == b"\x02" and
                parts[1].tag == b"\x04", "LDS group fields")
        group = int.from_bytes(parts[0].value, "big")
        mapped_group = mapping[3 * index]
        container = int.from_bytes(mapping[3 * index + 1:3 * index + 3], "big")
        require(group == mapped_group and group in expected and
                container == expected[group] and container in sources,
                "LDS group map")
        require(hashlib.new(hash_name, sources[container]).digest() == parts[1].value,
                "LDS group digest")
        observed[group] = container
    require(observed == expected, "LDS group coverage")
    return hash_name


def verify_session_identity(records: list[dict], start: int,
                            directory: Path) -> tuple[int, bool]:
    if start >= len(records) or records[start].get("operation") != "GET DATA PIV 5fc102":
        return start, False
    payload = bytearray()
    operation = "GET DATA PIV 5fc102"
    for index in range(start, min(len(records), start + 160)):
        entry = records[index]
        require(entry.get("operation") == operation and entry.get("pcsc_result") == 0,
                "session identity APDU order")
        command = bytes.fromhex(entry["command_hex"])
        response = bytes.fromhex(entry["response_hex"])
        require(len(response) >= 2 and
                (command[:4] == bytes.fromhex("00cb3fff") if operation.startswith("GET DATA")
                 else command[:4] == bytes.fromhex("00c00000")),
                "session identity APDU framing")
        status = int.from_bytes(response[-2:], "big")
        if status >> 8 == 0x6c:
            require(not response[:-2], "session identity length correction")
            continue
        payload.extend(response[:-2])
        require(len(payload) <= 20000, "session identity bound")
        if status >> 8 == 0x61:
            operation = "GET RESPONSE PIV 5fc102"
            continue
        require(status in (0x9000, 0x6282) and
                bytes(payload) == (directory / "PIV-5fc102.bin").read_bytes(),
                "session identity differs from inventory")
        return index + 1, True
    raise VerificationError("session identity response incomplete")


def verify_card_key_proof(directory: Path,
                          certificate_directory: Path | None = None) -> str:
    path = directory / "card-key-proof.jsonl"
    if not path.exists():
        return "not captured"
    records = [json.loads(line) for line in path.read_text().splitlines()]
    require(len(records) >= 4 and records[0]["operation"] == "SELECT PIV",
            "card proof APDU order")
    ga, bound = verify_session_identity(records, 1, directory)
    require(len(records) >= ga + 3 and len(records) - ga <= 162 and
            [entry["operation"] for entry in records[ga:ga + 2]] ==
            ["GENERAL AUTHENTICATE chain", "GENERAL AUTHENTICATE final"] and
            all(entry["operation"] == "GET RESPONSE" for entry in records[ga + 2:]),
            "card proof APDU order")
    for entry in records:
        require(entry["pcsc_result"] == 0, "card proof PC/SC status")
    select = bytes.fromhex(records[0]["command_hex"])
    require(select[:5] == bytes.fromhex("00a404000b") and
            select[5:16] == bytes.fromhex("a000000308000010000100"),
            "card proof PIV selection")
    chained = bytes.fromhex(records[ga]["command_hex"])
    final = bytes.fromhex(records[ga + 1]["command_hex"])
    require(chained[:4] == bytes.fromhex("1087079e") and
            final[:4] == bytes.fromhex("0087079e") and
            len(chained) >= 5 + chained[4] and len(final) >= 5 + final[4],
            "card proof GA commands")
    request = chained[5:5 + chained[4]] + final[5:5 + final[4]]
    template = one(request, b"\x7c")
    challenge_fields = fields(template.value)
    require([item.tag for item in challenge_fields] == [b"\x82", b"\x81"] and
            challenge_fields[0].value == b"" and len(challenge_fields[1].value) == 256,
            "card proof challenge")
    emsa = challenge_fields[1].value
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
    require(emsa[:2] == b"\x00\x01" and emsa.count(b"\xff", 2) >= 8 and
            emsa[-51:-32] == digest_info and emsa[-32:] != bytes(32),
            "card proof EMSA structure")
    delimiter = emsa.index(b"\x00", 2)
    require(emsa[2:delimiter] == b"\xff" * (delimiter - 2) and
            emsa[delimiter + 1:] == digest_info + emsa[-32:],
            "card proof EMSA padding")
    first_response = bytes.fromhex(records[ga + 1]["response_hex"])
    require(len(first_response) >= 2, "card proof first response")
    reply = bytearray(first_response[:-2])
    status = int.from_bytes(first_response[-2:], "big")
    for entry in records[ga + 2:]:
        command = bytes.fromhex(entry["command_hex"])
        fragment = bytes.fromhex(entry["response_hex"])
        require(status >> 8 == 0x61 and command ==
                b"\x00\xc0\x00\x00" + bytes((status & 255,)) and
                len(fragment) >= 2, "card proof response chain")
        reply.extend(fragment[:-2])
        status = int.from_bytes(fragment[-2:], "big")
    require(status == 0x9000 and len(reply) <= 20000, "card proof final status")
    result = one(bytes(reply), b"\x7c")
    signature = one(result.value, b"\x82").value
    certificate = find(object_fields(certificate_directory or directory,
                                     "PIV-5fc101.bin"), b"\x70")
    card_cert = x509.load_der_x509_certificate(certificate.value)
    try:
        card_cert.public_key().verify(signature, emsa[-32:], padding.PKCS1v15(),
                                      utils.Prehashed(hashes.SHA256()))
    except Exception as error:
        raise VerificationError("card key challenge signature") from error
    return "verified, identity bound" if bound else "verified, session unbound"


def verify_pin_session(directory: Path, fingerprint: bytes, face: bytes | None,
                       signer: x509.Certificate) -> str:
    path = directory / "pin-session.jsonl"
    if not path.exists():
        return "not captured"
    records = [json.loads(line) for line in path.read_text().splitlines()]
    require(len(records) >= 2 and records[0]["operation"] == "SELECT PIV",
            "PIN session order")
    status_index, identity_bound = verify_session_identity(records, 1, directory)
    require(status_index < len(records) and
            records[status_index]["operation"] == "PIN status" and
            bytes.fromhex(records[status_index]["command_hex"]) ==
            bytes.fromhex("00200080"),
            "PIN status command")
    pin_status = int.from_bytes(bytes.fromhex(records[status_index]["response_hex"])[-2:],
                                "big")
    start = status_index + 1
    if pin_status != 0x9000:
        require(pin_status & 0xfff0 == 0x63c0 and pin_status & 15 >= 2 and
                len(records) > start and records[start]["operation"] == "PIN VERIFY",
                "PIN retry guard")
        require(records[start].get("command_hex") is None and
                records[start].get("command_data_redacted") is True and
                bytes.fromhex(records[start]["response_hex"])[-2:] == b"\x90\x00",
                "PIN session redaction/status")
        start += 1
    outputs: dict[str, bytes] = {}
    pending = None
    payload = bytearray()
    next_le = None
    for item in records[start:]:
        require(item["pcsc_result"] == 0, "PIN session PC/SC result")
        command = bytes.fromhex(item["command_hex"])
        response = bytes.fromhex(item["response_hex"])
        require(len(response) >= 2 and len(command) >= 5, "PIN session APDU framing")
        operation = item["operation"]
        if operation.startswith("GET DATA "):
            require(pending is None and command[:4] == bytes.fromhex("00cb3fff"),
                    "PIN GET DATA command")
            tag = operation.rsplit(" ", 1)[1]
            require(command[7:7 + command[6]].hex() == tag, "PIN GET DATA tag")
            pending = tag
            payload.clear()
        else:
            require(operation in (f"GET RESPONSE {pending}",
                                  f"GET RESPONSE PIV {pending}") and
                    command[:4] == bytes.fromhex("00c00000") and
                    command[4] == next_le, "PIN GET RESPONSE command")
        sw = int.from_bytes(response[-2:], "big")
        payload.extend(response[:-2])
        if sw >> 8 == 0x61:
            next_le = sw & 255
            continue
        require(sw in (0x9000, 0x6282), "PIN object status")
        outputs[pending] = bytes(payload)
        require((directory / f"PIV-{pending}-after-pin.bin").read_bytes() == outputs[pending],
                "PIN object reconstruction")
        pending = None
        next_le = None
    require(pending is None, "PIN session completion")
    for tag, twic in (("5fc103", fingerprint), ("5fc108", face)):
        piv = object_fields(directory, f"PIV-{tag}-after-pin.bin")
        require([item.tag for item in piv] == [b"\xbc", b"\xfe"] and
                piv[1].value == b"", "PIV biometric structure")
        if twic is not None:
            require(piv[0].value == twic, "PIV/TWIC biometric equality")
        else:
            verify_cbeff(piv[0].value, signer, "face")
    printed = object_fields(directory, "PIV-5fc109-after-pin.bin")
    require([item.tag for item in printed] ==
            [b"\x01", b"\x02", b"\x04", b"\x05", b"\x06", b"\xfe"],
            "PIV printed TLV tree")
    piv_chuid = object_fields(directory, "PIV-5fc102.bin")
    require([item.tag for item in piv_chuid] ==
            [b"\x30", b"\x34", b"\x35", b"\x3d", b"\x3e", b"\xfe"], "PIV CHUID tree")
    piv_content = b"".join(item.encoded for item in piv_chuid if item.tag != b"\x3e")
    cms_verify(piv_chuid[4].value, signer, piv_content)
    security = object_fields(directory, "PIV-5fc106-after-pin.bin")
    require([item.tag for item in security] == [b"\xba", b"\xbb", b"\xfe"],
            "PIV Security Object tree")
    lds = cms_verify(security[1].value, signer, None)
    mapping = {2: 0x3000, 4: 0x6010, 1: 0xdb00, 7: 0x6030, 6: 0x3001}
    paths = {0x3000: "PIV-5fc102.bin", 0x6010: "PIV-5fc103-after-pin.bin",
             0xdb00: "PIV-5fc107.bin", 0x6030: "PIV-5fc108-after-pin.bin",
             0x3001: "PIV-5fc109-after-pin.bin"}
    sources = {container: one((directory / name).read_bytes(), b"\x53").value
               for container, name in paths.items()}
    profile = "legacy" if directory.name.startswith("legacy") else "nexgen"
    require(verify_lds(lds, security[0].value, sources, mapping) ==
            ("sha1" if profile == "legacy" else "sha256"),
            "PIV LDS digest")
    return "verified, identity bound" if identity_bound else "verified, session unbound"


def private_markers(directory: Path) -> tuple[set[bytes], set[bytes]]:
    """Return exact private values and high-entropy biometric data for leak scans."""
    exact = set()
    biometric = set()
    def add_certificate(cert: x509.Certificate) -> None:
        exact.add(cert.signature)
        public = cert.public_key()
        if hasattr(public, "public_numbers"):
            numbers = public.public_numbers()
            if hasattr(numbers, "n"):
                exact.add(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"))
    def signature_octets(cms: bytes) -> set[bytes]:
        found = set()
        def visit(blob: bytes, depth: int = 0) -> None:
            if depth > 16:
                return
            for item in fields(blob):
                if item.tag == b"\x04" and len(item.value) >= 128:
                    found.add(item.value)
                elif item.tag[0] & 32:
                    visit(item.value, depth + 1)
        visit(cms)
        return found
    chuid = object_fields(directory, "TWIC-5fc102.bin")
    for tag in (b"\x30", b"\x34", b"\x35"):
        exact.add(find(chuid, tag).value)
    tpk = object_fields(directory, "TWIC-dfc101.bin")
    exact.add(find(tpk, b"\xc0").value)
    for path in directory.glob("PIV-*.bin"):
        try:
            cert = x509.load_der_x509_certificate(find(object_fields(directory, path.name),
                                                     b"\x70").value)
        except (VerificationError, ValueError):
            continue
        add_certificate(cert)
    for path in directory.glob("PIV-*-after-pin.bin"):
        try:
            cert = x509.load_der_x509_certificate(find(object_fields(directory, path.name),
                                                     b"\x70").value)
        except (VerificationError, ValueError):
            continue
        add_certificate(cert)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        signer = pkcs7.load_der_pkcs7_certificates(find(chuid, b"\x3e").value)[0]
    exact.update(signature_octets(find(chuid, b"\x3e").value))
    add_certificate(signer)
    key = find(tpk, b"\xc0").value
    for tag in ("dfc103", "dfc108", "dfc109"):
        path = directory / f"TWIC-{tag}.bin"
        if not path.exists():
            continue
        contents = one(path.read_bytes(), b"\x53").value
        ciphertext = find(fields(contents), b"\xbc").value
        exact.add(ciphertext)
        plain, _ = decrypt_object(directory, tag, key)
        if tag != "dfc109":
            record_length = int.from_bytes(plain[2:6], "big")
            record = plain[88:88 + record_length]
            biometric.add(record[26:] if tag == "dfc103" else record[64:])
            exact.update(signature_octets(plain[88 + record_length:]))
    security = object_fields(directory, "TWIC-dfc10f.bin")
    exact.update(signature_octets(find(security, b"\xbb").value))
    lds = cms_verify(find(security, b"\xbb").value, signer, None)
    top = fields(one(lds, b"\x30").value)
    for group in fields(top[2].value):
        exact.add(fields(group.value)[1].value)
    piv_chuid_path = directory / "PIV-5fc102.bin"
    if piv_chuid_path.exists():
        piv_chuid = object_fields(directory, piv_chuid_path.name)
        for tag in (b"\x30", b"\x34", b"\x35"):
            exact.add(find(piv_chuid, tag).value)
        exact.update(signature_octets(find(piv_chuid, b"\x3e").value))
    for tag in ("5fc103", "5fc108"):
        path = directory / f"PIV-{tag}-after-pin.bin"
        if not path.exists():
            continue
        plain = find(object_fields(directory, path.name), b"\xbc").value
        record_length = int.from_bytes(plain[2:6], "big")
        record = plain[88:88 + record_length]
        biometric.add(record[26:] if tag == "5fc103" else record[64:])
        exact.update(signature_octets(plain[88 + record_length:]))
    piv_security = directory / "PIV-5fc106-after-pin.bin"
    if piv_security.exists():
        security_fields = object_fields(directory, piv_security.name)
        cms = find(security_fields, b"\xbb").value
        exact.update(signature_octets(cms))
        piv_lds = cms_verify(cms, signer, None)
        piv_top = fields(one(piv_lds, b"\x30").value)
        for group in fields(piv_top[2].value):
            exact.add(fields(group.value)[1].value)
    return {value for value in exact if len(value) >= 16}, \
           {value for value in biometric if len(value) >= 16}


def verify_synthetic_privacy(capture_root: Path, synthetic_root: Path) -> None:
    # A 16-byte match is long enough to catch copied identifiers and keys.
    # Biometric format headers repeat legitimately, so scan their variable
    # payload windows with at least ten distinct byte values.
    private: set[bytes] = set()
    biometric: set[bytes] = set()
    for profile in ("legacy", "nexgen"):
        markers, images = private_markers(capture_root / f"{profile}-contact")
        private.update(markers)
        biometric.update(images)
    windows = set()
    for marker in private:
        windows.update(part for i in range(len(marker) - 15)
                       if len(set(part := marker[i:i + 16])) >= 4)
    for marker in biometric:
        for i in range(len(marker) - 15):
            part = marker[i:i + 16]
            if len(set(part)) >= 10:
                windows.add(part)
    for path in synthetic_root.rglob("*"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        for i in range(len(data) - 15):
            require(data[i:i + 16] not in windows, "synthetic private-byte reuse")
        if path.suffix in (".txt", ".json", ".jsonl"):
            # APDU text stores hex, so scan the decoded byte pairs too.
            text = data.decode("ascii", errors="ignore").lower()
            for run in re.findall(r"[0-9a-f]{32,}", text):
                if len(run) % 2:
                    run = run[:-1]
                decoded = bytes.fromhex(run)
                for i in range(len(decoded) - 15):
                    require(decoded[i:i + 16] not in windows,
                            "synthetic APDU private-byte reuse")


def verify_synthetic_structure(capture_root: Path, synthetic_root: Path) -> None:
    names = {"signed-chuid": "5fc102", "unsigned-chuid": "5fc104",
             "tpk": "dfc101", "fingerprint": "dfc103", "face": "dfc108",
             "printed": "dfc109", "security": "dfc10f", "discovery": "7e",
             "card-auth-cert": "5fc101"}
    expected_aids = {"legacy": "A000000367200000010101",
                     "nexgen": "A000000367200000010103"}
    piv_sources = {"piv-signed-chuid": "PIV-5fc102.bin",
                   "piv-card-auth-cert": "PIV-5fc101.bin",
                   "piv-auth-cert": "PIV-5fc105.bin",
                   "piv-discovery": "PIV-5fc107.bin",
                   "piv-twic-discovery": "TWIC-7e.bin",
                   "piv-sign-cert": "PIV-5fc10a.bin",
                   "piv-key-management-cert": "PIV-5fc10b.bin",
                   "piv-fingerprint": "PIV-5fc103-after-pin.bin",
                   "piv-face": "PIV-5fc108-after-pin.bin",
                   "piv-printed": "PIV-5fc109-after-pin.bin",
                   "piv-security": "PIV-5fc106-after-pin.bin"}
    for profile in ("legacy", "nexgen"):
        actual = capture_root / f"{profile}-contact"
        synthetic = synthetic_root / profile
        manifest = json.loads((synthetic / "manifest.json").read_text())
        require(manifest["profile"] == profile and manifest["material"] == "synthetic" and
                manifest["twic_aid"] == expected_aids[profile] and
                manifest["piv_aid"] == "A000000308000010000100",
                "synthetic manifest AID/profile")
        object_pairs = [(name, f"TWIC-{names[name]}.bin") for name in
                        manifest["objects"]["present"] if name in names]
        object_pairs += [(name, piv_sources.get(name, name.replace("piv-", "PIV-") + ".bin"))
                         for name in manifest["objects"].get("piv_present_synthetic", [])]
        for name, source_name in object_pairs:
            source = actual / source_name
            target = synthetic / f"{name}.bin"
            require(source.is_file() and target.is_file(), "synthetic object presence")
            source_outer = fields(source.read_bytes())
            target_outer = fields(target.read_bytes())
            require(len(source_outer) == len(target_outer) == 1 and
                    source_outer[0].tag == target_outer[0].tag,
                    "synthetic outer TLV shape")
            source_tags = [item.tag for item in fields(source_outer[0].value)]
            target_tags = [item.tag for item in fields(target_outer[0].value)]
            require(source_tags == target_tags, "synthetic TLV shape")
        real_chuid = object_fields(actual, "TWIC-5fc102.bin")
        fake_chuid = object_fields(synthetic, "signed-chuid.bin")
        for tag in (b"\x30", b"\x34", b"\x35"):
            real_value = find(real_chuid, tag).value
            fake_value = find(fake_chuid, tag).value
            nil_legacy_uuid = (profile == "legacy" and tag == b"\x34" and
                               real_value == bytes(16) == fake_value)
            require(nil_legacy_uuid or real_value != fake_value,
                    "synthetic CHUID identifier reuse")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            real_signer = pkcs7.load_der_pkcs7_certificates(
                find(object_fields(actual, "TWIC-5fc102.bin"), b"\x3e").value)[0]
        for role, cert in (("signer", real_signer),
                           ("card", x509.load_der_x509_certificate(
                               find(object_fields(actual, "PIV-5fc101.bin"), b"\x70").value))):
            declared = manifest["certificates"][role]
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            policies = cert.extensions.get_extension_for_oid(
                ExtensionOID.CERTIFICATE_POLICIES).value
            require(set(declared["eku"]) == {oid.dotted_string for oid in eku} and
                    set(declared["policies"]) ==
                    {item.policy_identifier.dotted_string for item in policies},
                    "synthetic certificate OIDs")
        security = object_fields(actual, "TWIC-dfc10f.bin")
        mapping = find(security, b"\xba").value
        observed = [(mapping[i], format(int.from_bytes(mapping[i + 1:i + 3], "big"), "04X"))
                    for i in range(0, len(mapping), 3)]
        declared = [(item["group"], item["container"].upper())
                    for item in manifest["security_mapping"]]
        require(observed == declared and
                manifest["security_digest"] == ("sha1" if profile == "legacy" else "sha256") and
                manifest["encryption"] == "AES-128-ECB with PKCS#7 padding",
                "synthetic security structure")
        if "piv_security_mapping" in manifest:
            piv_security = object_fields(actual, "PIV-5fc106-after-pin.bin")
            piv_map = find(piv_security, b"\xba").value
            piv_observed = [(piv_map[i], format(int.from_bytes(piv_map[i + 1:i + 3],
                                                  "big"), "04X"))
                            for i in range(0, len(piv_map), 3)]
            piv_declared = [(item["group"], item["container"].upper())
                            for item in manifest["piv_security_mapping"]]
            require(piv_observed == piv_declared, "synthetic PIV security mapping")


def verify_profile(directory: Path, profile: str,
                   issuer_bundle_dir: Path | None = None,
                   trust_anchors: Path | None = None,
                   at: datetime.datetime = CAPTURE_TIME) -> dict[str, object]:
    apdus = verify_apdus(directory, profile)
    signed = object_fields(directory, "TWIC-5fc102.bin")
    unsigned = object_fields(directory, "TWIC-5fc104.bin")
    require([item.tag for item in signed] ==
            [b"\x30", b"\x34", b"\x35", b"\x3e", b"\xfe"], "signed CHUID tree")
    require([item.tag for item in unsigned] ==
            [b"\x30", b"\x34", b"\x35", b"\xfe"], "unsigned CHUID tree")
    require([item.value for item in signed[:3]] == [item.value for item in unsigned[:3]],
            "CHUID identifiers")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        certs = pkcs7.load_der_pkcs7_certificates(signed[3].value)
    require(len(certs) == 1, "CHUID signer count")
    signer = certs[0]
    exact_certificate_oids(signer)
    bundle_dir = issuer_bundle_dir
    if bundle_dir is not None and (bundle_dir / f"{profile}-contact").is_dir():
        bundle_dir = bundle_dir / f"{profile}-contact"
    path_status = verify_paths(directory, bundle_dir, trust_anchors, signer, at)
    # The signature covers the original TLV encodings, including the LRC.
    content = b"".join(item.encoded for item in signed if item.tag != b"\x3e")
    cms_verify(signed[3].value, signer, content)
    tpk = object_fields(directory, "TWIC-dfc101.bin")
    require([item.tag for item in tpk] == [b"\xc0", b"\xc1", b"\xc2"] and
            len(tpk[0].value) == 16 and tpk[1].value == b"\x08" and
            len(tpk[2].value) == 1, "TPK format")
    key = tpk[0].value
    fingerprint, fingerprint_stored = decrypt_object(directory, "dfc103", key)
    verify_cbeff(fingerprint, signer, "fingerprint")
    require(fingerprint[59:84] == signed[0].value, "fingerprint FASC-N")
    security = object_fields(directory, "TWIC-dfc10f.bin")
    require([item.tag for item in security] == [b"\xba", b"\xbb", b"\xfe"] and
            not security[2].value, "Security Object tree")
    lds = cms_verify(security[1].value, signer, None)
    sources = {
        0x3000: one((directory / "TWIC-5fc102.bin").read_bytes(), b"\x53").value,
        0x3002: one((directory / "TWIC-5fc104.bin").read_bytes(), b"\x53").value,
        0x2003: fingerprint_stored,
    }
    expected = {9: 0x3002, 2: 0x3000, 4: 0x2003}
    if profile == "nexgen":
        face, face_stored = decrypt_object(directory, "dfc108", key)
        verify_cbeff(face, signer, "face")
        require(face[59:84] == signed[0].value, "face FASC-N")
        printed, _ = decrypt_object(directory, "dfc109", key)
        require(len(fields(printed)) > 0, "printed TLV tree")
        sources[0x6030] = face_stored
        sources[0x3001] = printed
        expected.update({7: 0x6030, 6: 0x3001})
    digest = verify_lds(lds, security[0].value, sources, expected)
    require(digest == ("sha1" if profile == "legacy" else "sha256"),
            "LDS profile digest")
    piv_cross_check = verify_pin_session(directory, fingerprint,
                                         face if profile == "nexgen" else None, signer)
    card_proof = proof_status(directory, profile)
    return {"apdus": apdus, "signed_objects": ["CHUID", "Security Object", "fingerprint"] +
            (["face"] if profile == "nexgen" else []), "lds_groups": len(expected),
            "lds_digest": digest, "aes": "AES-128-ECB/PKCS7",
            "card_key_proof": card_proof,
            "certificate_path": path_status, "piv_cross_check": piv_cross_check}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_root", type=Path)
    parser.add_argument("--profile", choices=("legacy", "nexgen", "both"), default="both")
    parser.add_argument("--issuer-bundle-dir", type=Path,
                        help="local directory containing content-issuer-0.bin and card-issuer-0.bin")
    parser.add_argument("--trust-anchors", type=Path,
                        help="explicit PEM trust anchors; never obtained from AIA")
    parser.add_argument("--require-current-trust", action="store_true",
                        help="require both paths to validate to explicit anchors at --at")
    parser.add_argument("--at", type=utc_time, default=CAPTURE_TIME,
                        help="evaluation time YYYY-MM-DDTHH:MM:SSZ, default "
                             + CAPTURE_TIME.strftime("%Y-%m-%dT%H:%M:%SZ"))
    parser.add_argument("--synthetic-root", type=Path,
                        help="compare public fixture structure and reject copied card bytes")
    args = parser.parse_args()
    profiles = ("legacy", "nexgen") if args.profile == "both" else (args.profile,)
    try:
        require(not args.require_current_trust or args.trust_anchors is not None,
                "current trust requires explicit anchors")
        invalid_card_proof = False
        for profile in profiles:
            result = verify_profile(args.capture_root / f"{profile}-contact", profile,
                                    args.issuer_bundle_dir, args.trust_anchors, args.at)
            invalid_card_proof |= result["card_key_proof"] in (
                "INVALID", "MISATTRIBUTED TO NEXGEN")
            print(f"{profile}: verified {result['apdus']['present']} objects, "
                  f"{result['lds_groups']} LDS groups ({result['lds_digest']}), "
                  f"CMS and {result['aes']}; card key proof "
                  f"{result['card_key_proof']}; "
                  f"PIV cross-check {result['piv_cross_check']}; "
                  f"certificate path {result['certificate_path']}")
        for profile in profiles:
            rf = verify_contactless(args.capture_root, profile)
            if rf is not None:
                print(f"{profile} contactless: APDUs, {rf['objects']} shared objects, "
                      f"{rf['denied']} access denials verified; card key proof "
                      f"{rf['card_key_proof']}")
                invalid_card_proof |= rf["card_key_proof"] in (
                    "INVALID", "MISATTRIBUTED TO NEXGEN")
        if args.synthetic_root is not None:
            require(args.profile == "both", "privacy gate requires both captures")
            verify_synthetic_structure(args.capture_root, args.synthetic_root)
            verify_synthetic_privacy(args.capture_root, args.synthetic_root)
            print("synthetic structure and private-byte scan: verified")
        require(not invalid_card_proof, "captured card key proof INVALID")
    except (VerificationError, OSError, ValueError, KeyError, IndexError) as error:
        label = str(error) if isinstance(error, VerificationError) else type(error).__name__
        print(f"private TWIC verification failed: {label}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
