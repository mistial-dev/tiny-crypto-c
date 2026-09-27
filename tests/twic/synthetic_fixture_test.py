#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independently check the committed, synthetic TWIC credential corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID
from PIL import Image
import io


ROOT = Path(__file__).resolve().parents[1] / "vectors" / "twic" / "synthetic"


def oid_der(dotted: str) -> bytes:
    arcs = [int(item) for item in dotted.split(".")]
    assert 0 <= arcs[0] <= 2 and 0 <= arcs[1] < 40
    values = [40 * arcs[0] + arcs[1], *arcs[2:]]
    encoded = bytearray()
    for value in values:
        digits = [value & 0x7F]
        value >>= 7
        while value:
            digits.append(0x80 | (value & 0x7F))
            value >>= 7
        encoded.extend(reversed(digits))
    assert len(encoded) < 128
    return b"\x06" + bytes([len(encoded)]) + bytes(encoded)


def tlv(data: bytes, offset: int = 0) -> tuple[bytes, bytes, int]:
    assert offset < len(data)
    start = offset
    first = data[offset]
    offset += 1
    if first & 0x1F == 0x1F:
        while data[offset] & 0x80:
            offset += 1
        offset += 1
    tag = data[start:offset]
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        assert 0 < count <= 2
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    end = offset + length
    assert end <= len(data)
    return tag, data[offset:end], end


def children(data: bytes) -> list[tuple[bytes, bytes]]:
    result = []
    offset = 0
    while offset < len(data):
        tag, value, offset = tlv(data, offset)
        result.append((tag, value))
    return result


def envelope(path: Path) -> bytes:
    encoded = path.read_bytes()
    tag, value, end = tlv(encoded)
    assert tag == b"\x53" and end == len(encoded), path
    return value


def certificate_chain(directory: Path, manifest: dict) -> None:
    names = ("root", "issuer", "signer", "card", "piv-auth") + (
        ("piv-sign", "piv-key-management") if manifest["profile"] == "legacy" else ())
    certs = [x509.load_der_x509_certificate((directory / f"{name}.der").read_bytes())
             for name in names]
    for index, cert in enumerate(certs):
        issuer = certs[0 if index < 2 else 1]
        assert cert.issuer == issuer.subject
        issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                   padding.PKCS1v15(), cert.signature_hash_algorithm)
    trust_list = children(tlv((directory / "trust-anchors.der").read_bytes())[1])
    assert len(trust_list) == 1 and trust_list[0][0] == b"\xa2"
    information = children(tlv(trust_list[0][1])[1])
    assert [tag for tag, _ in information] == [b"\x30", b"\x04", b"\x30"]
    assert information[0][1] == tlv(certs[0].public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo))[1]
    path_fields = children(information[2][1])
    assert [tag for tag, _ in path_fields] == [b"\x30", b"\xa0"]
    assert path_fields[0][1] == tlv(certs[0].subject.public_bytes())[1]
    assert path_fields[1][1] == tlv(certs[0].public_bytes(Encoding.DER))[1]
    bad_list = children(tlv((directory / "trust-anchor-bad-keyid.der").read_bytes())[1])
    bad_info = children(tlv(bad_list[0][1])[1])
    assert bad_info[1][1] != information[1][1]
    assert bad_info[0] == information[0] and bad_info[2] == information[2]
    for name, changed in (("trust-anchor-bad-name.der", 2),
                          ("trust-anchor-bad-key.der", 0)):
        invalid = children(tlv((directory / name).read_bytes())[1])
        invalid_info = children(tlv(invalid[0][1])[1])
        assert invalid_info[changed] != information[changed]
        assert all(invalid_info[index] == information[index]
                   for index in range(3) if index != changed)
    invalid = children(tlv((directory / "trust-anchor-bad-certsign.der").read_bytes())[1])
    invalid_info = children(tlv(invalid[0][1])[1])
    assert invalid_info[:2] == information[:2]
    invalid_path = children(invalid_info[2][1])
    assert invalid_path[0] == path_fields[0]
    assert invalid_path[1] != path_fields[1]
    bad_root = x509.load_der_x509_certificate(
        b"\x30" + bytes([0x80 | 2]) + len(invalid_path[1][1]).to_bytes(2, "big")
        + invalid_path[1][1])
    bad_root.public_key().verify(bad_root.signature, bad_root.tbs_certificate_bytes,
                                 padding.PKCS1v15(), bad_root.signature_hash_algorithm)
    assert not bad_root.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.key_cert_sign
    certificate_list = children(tlv((directory / "trust-anchor-certificate.der").read_bytes())[1])
    assert len(certificate_list) == 1 and certificate_list[0][0] == b"\x30"
    assert certificate_list[0][1] == tlv(certs[0].public_bytes(Encoding.DER))[1]
    for name, cert in zip(names[2:], certs[2:]):
        expected_extensions = {
            "signer": ["2.5.29.15", "1.3.6.1.5.5.7.1.1", "2.5.29.31",
                       "2.5.29.32", "2.5.29.37", "2.5.29.16",
                       "2.5.29.35", "2.5.29.14"],
            "card": ["1.3.6.1.4.1.29138.6.9.1", "2.5.29.15", "2.5.29.32",
                     "1.3.6.1.5.5.7.1.1", "2.5.29.37", "2.5.29.17",
                     "2.5.29.31", "2.5.29.35", "2.5.29.14"],
            "piv-auth": ["1.3.6.1.4.1.29138.6.9.1", "2.5.29.15",
                         "2.5.29.32", "2.5.29.37", "1.3.6.1.5.5.7.1.1",
                         "2.5.29.17", "2.5.29.31", "2.5.29.35", "2.5.29.14"],
        }
        if name in expected_extensions:
            assert [extension.oid.dotted_string for extension in cert.extensions] == expected_extensions[name]
            assert {extension.oid.dotted_string for extension in cert.extensions
                    if extension.critical} == ({"2.5.29.15", "2.5.29.37"}
                                               if name == "card" else {"2.5.29.15"})
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        policy = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
        assert {oid.dotted_string for oid in eku} == set(manifest["certificates"][name]["eku"])
        assert {item.policy_identifier.dotted_string for item in policy} == set(
            manifest["certificates"][name]["policies"])
        encoded = cert.public_bytes(Encoding.DER)
        for dotted in manifest["certificates"][name]["eku"] + manifest["certificates"][name]["policies"]:
            assert oid_der(dotted) in encoded
        if name == "card":
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            assert len(san) == 1 and isinstance(san[0], x509.OtherName)
            assert san[0].type_id.dotted_string == "1.3.6.1.4.1.29138.6.6"
            assert oid_der("1.3.6.1.4.1.29138.6.6") in encoded
        usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if name == "piv-key-management":
            assert not usage.digital_signature and usage.key_encipherment
        else:
            assert usage.digital_signature and not usage.key_encipherment
    cert_body = envelope(directory / ("piv-card-auth-cert.bin" if manifest["profile"] == "legacy"
                                       else "card-auth-cert.bin"))
    cert_fields = children(cert_body)
    assert [tag for tag, _ in cert_fields] == [b"\x70", b"\x71", b"\xfe"]
    assert cert_fields[0][1] == (directory / "card.der").read_bytes()
    assert cert_fields[1][1] == b"\x00"
    piv_auth = children(envelope(directory / "piv-auth-cert.bin"))
    assert [tag for tag, _ in piv_auth] == [b"\x70", b"\x71", b"\xfe"]
    assert piv_auth[0][1] == (directory / "piv-auth.der").read_bytes()
    for name in names[5:]:
        object_fields = children(envelope(directory / f"{name}-cert.bin"))
        assert [tag for tag, _ in object_fields] == [b"\x70", b"\x71", b"\xfe"]
        assert object_fields[0][1] == (directory / f"{name}.der").read_bytes()


def cms_verify(cms: bytes, content: bytes | None, signer: Path) -> bytes:
    with tempfile.TemporaryDirectory(prefix="twic-synthetic-cms-") as temporary:
        folder = Path(temporary)
        (folder / "cms.der").write_bytes(cms)
        (folder / "signer.pem").write_bytes(
            x509.load_der_x509_certificate(signer.read_bytes()).public_bytes(Encoding.PEM))
        command = ["openssl", "cms", "-verify", "-binary", "-inform", "DER",
                   "-in", str(folder / "cms.der"), "-noverify", "-certfile",
                   str(folder / "signer.pem"), "-out", str(folder / "verified.bin")]
        if content is not None:
            (folder / "content.bin").write_bytes(content)
            command += ["-content", str(folder / "content.bin")]
        subprocess.run(command, check=True, capture_output=True)
        verified = (folder / "verified.bin").read_bytes()
        if content is not None:
            assert verified == content
        return verified


def assert_cms_oids(cms: bytes, econtent_type: str, certificates: int) -> None:
    outer = children(tlv(cms)[1])
    assert outer[0] == (b"\x06", oid_der("1.2.840.113549.1.7.2")[2:])
    assert outer[1][0] == b"\xa0"
    signed = children(tlv(outer[1][1])[1])
    assert signed[0][0] == b"\x02" and signed[1][0] == b"\x31"
    digest_set = children(signed[1][1])
    assert len(digest_set) == 1 and digest_set[0][0] == b"\x30"
    digest_algorithm = children(digest_set[0][1])[0]
    assert digest_algorithm == (b"\x06",oid_der("2.16.840.1.101.3.4.2.1")[2:])
    assert signed[2][0] == b"\x30"
    encap = children(signed[2][1])
    assert encap[0] == (b"\x06",oid_der(econtent_type)[2:])
    certificate_fields = [item for item in signed[3:-1] if item[0] == b"\xa0"]
    assert len(certificate_fields) == (1 if certificates else 0)
    if certificates:
        assert len(children(certificate_fields[0][1])) == certificates
    signers = signed[-1]
    assert signers[0] == b"\x31"
    signer_infos = children(signers[1])
    assert len(signer_infos) == 1 and signer_infos[0][0] == b"\x30"
    fields = children(signer_infos[0][1])
    algorithms = [item for item in fields if item[0] == b"\x30"]
    assert len(algorithms) >= 3
    assert children(algorithms[-2][1])[0] == digest_algorithm
    assert children(algorithms[-1][1])[0] == (b"\x06",oid_der("1.2.840.113549.1.1.1")[2:])


def encrypted_object(directory: Path, name: str, key: bytes) -> bytes:
    entries = children(envelope(directory / f"{name}.bin"))
    assert len(entries) == 1 and entries[0][0] == b"\xbc"
    ciphertext = entries[0][1]
    assert len(ciphertext) > 0 and len(ciphertext) % 16 == 0
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    amount = padded[-1]
    assert 1 <= amount <= 16 and padded[-amount:] == bytes([amount]) * amount
    plaintext = padded[:-amount]
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    assert encryptor.update(padded) + encryptor.finalize() == ciphertext
    return plaintext


def verify_security(directory: Path, filename: str, mapping_spec: list[dict],
                    digest: str, hashed: dict[int, bytes]) -> None:
    security = children(envelope(directory / filename))
    assert [tag for tag, _ in security] == [b"\xba", b"\xbb", b"\xfe"]
    assert security[2][1] == b""
    assert_cms_oids(security[1][1],"1.3.27.1.1.1",0)
    lds = cms_verify(security[1][1], None, directory / "signer.der")
    sequence = children(tlv(lds)[1])
    assert len(sequence) == 3 and sequence[0] == (b"\x02", b"\x00")
    digest_oid = children(sequence[1][1])[0][1]
    assert digest_oid == (b"\x2b\x0e\x03\x02\x1a" if digest == "sha1"
                          else b"\x60\x86\x48\x01\x65\x03\x04\x02\x01")
    digest_entries = children(sequence[2][1])
    mapping = security[0][1]
    assert len(mapping) == len(digest_entries) * 3
    assert len(digest_entries) == len(mapping_spec) == len(hashed)
    for index, (tag, encoded) in enumerate(digest_entries):
        assert tag == b"\x30"
        parts = children(encoded)
        expected = mapping_spec[index]
        group = expected["group"]
        assert len(parts) == 2 and parts[0] == (b"\x02", bytes([group]))
        assert parts[1][0] == b"\x04"
        assert mapping[3 * index] == group
        container = int.from_bytes(mapping[3 * index + 1:3 * index + 3], "big")
        assert container == int(expected["container"], 16)
        assert parts[1][1] == hashlib.new(digest, hashed[container]).digest()


def validate_profile(directory: Path) -> None:
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["profile"] == directory.name
    assert manifest["material"] == "synthetic"
    assert set(manifest["objects"]["synthetic_lengths"]) == set(manifest["objects"]["present"])
    for name, length in manifest["objects"]["synthetic_lengths"].items():
        assert (directory / f"{name}.bin").stat().st_size == length
    certificate_chain(directory, manifest)
    card = x509.load_der_x509_certificate((directory / "card.der").read_bytes())
    numbers = card.public_key().public_numbers()
    challenge = (directory / "ga-challenge.bin").read_bytes()
    signature = (directory / "ga-signature.bin").read_bytes()
    assert len(challenge) == len(signature) == 256
    assert int.from_bytes(signature, "big") < numbers.n
    assert pow(int.from_bytes(signature, "big"), numbers.e, numbers.n) == int.from_bytes(challenge, "big")
    tampered = bytearray(signature)
    tampered[-1] ^= 1
    assert pow(int.from_bytes(tampered, "big"), numbers.e, numbers.n) != int.from_bytes(challenge, "big")
    tpk = children(envelope(directory / "tpk.bin"))
    assert [tag for tag, _ in tpk] == [b"\xc0", b"\xc1", b"\xc2"]
    assert len(tpk[0][1]) == 16 and tpk[1][1] == b"\x08" and tpk[2][1] == b"\x00"
    key = tpk[0][1]
    signed = children(envelope(directory / "signed-chuid.bin"))
    unsigned = children(envelope(directory / "unsigned-chuid.bin"))
    assert [tag for tag, _ in signed] == [b"\x30", b"\x34", b"\x35", b"\x3e", b"\xfe"]
    assert [tag for tag, _ in unsigned] == [b"\x30", b"\x34", b"\x35", b"\xfe"]
    assert signed[:3] == unsigned[:3]
    assert len(signed[0][1]) == 25 and len(signed[1][1]) == 16
    assert len(signed[2][1]) == 8 and signed[4][1] == b""
    detached = envelope(directory / "unsigned-chuid.bin")
    assert_cms_oids(signed[3][1],"2.16.840.1.101.3.6.1",1)
    cms_verify(signed[3][1], detached, directory / "signer.der")
    corrupted = bytearray(detached)
    corrupted[2] ^= 1
    try:
        cms_verify(signed[3][1], bytes(corrupted), directory / "signer.der")
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError("CHUID signature accepted changed content")
    piv = children(envelope(directory / "piv-signed-chuid.bin"))
    assert [tag for tag, _ in piv] == [b"\x30", b"\x34", b"\x35", b"\x3d", b"\x3e", b"\xfe"]
    assert piv[3][1] == b"" and piv[:3] == signed[:3]
    piv_encoded = envelope(directory / "piv-signed-chuid.bin")
    offset = 0
    for expected in (b"\x30", b"\x34", b"\x35", b"\x3d"):
        tag, _, offset = tlv(piv_encoded, offset)
        assert tag == expected
    assert_cms_oids(piv[4][1],"2.16.840.1.101.3.6.1",1)
    cms_verify(piv[4][1], piv_encoded[:offset] + b"\xfe\x00",
               directory / "signer.der")
    fingerprint = encrypted_object(directory, "fingerprint", key)
    assert fingerprint[0] == 3 and fingerprint[1] == 0x0D
    asserted_size = int.from_bytes(fingerprint[2:6], "big")
    assert asserted_size + 88 < len(fingerprint)
    assert asserted_size == 542
    assert fingerprint[59:84] == signed[0][1]
    assert fingerprint[6:8] == len(fingerprint[88 + asserted_size:]).to_bytes(2, "big")
    assert_cms_oids(fingerprint[88 + asserted_size:],"2.16.840.1.101.3.6.2",0)
    cms_verify(fingerprint[88 + asserted_size:], fingerprint[:88 + asserted_size],
               directory / "signer.der")
    record = fingerprint[88:88 + asserted_size]
    assert record[:8] == b"FMR\x00 20\x00"
    assert int.from_bytes(record[8:10], "big") == len(record)
    assert int.from_bytes(record[16:18], "big") == 407
    assert int.from_bytes(record[18:20], "big") == 523
    assert record[24] == 2
    offset = 26
    for position, count in ((2, 39), (7, 45)):
        assert record[offset] == position and record[offset + 3] == count
        offset += 4 + count * 6
        assert record[offset:offset + 2] == b"\x00\x00"
        offset += 2
    assert offset == len(record)
    hashed = {
        0x3000: envelope(directory / "signed-chuid.bin"),
        0x3002: envelope(directory / "unsigned-chuid.bin"),
        0x2003: envelope(directory / "fingerprint.bin"),
    }
    if manifest["profile"] == "nexgen":
        face = encrypted_object(directory, "face", key)
        assert face[0] == 3 and face[1] == 0x0D
        face_record = int.from_bytes(face[2:6], "big")
        assert face_record == 9713
        record = face[88:88 + face_record]
        assert record[:8] == b"FAC\x00010\x00"
        assert int.from_bytes(record[8:12], "big") == 9713
        assert int.from_bytes(record[36:38], "big") == 274
        assert int.from_bytes(record[38:40], "big") == 364
        with Image.open(io.BytesIO(record[46:])) as image:
            image.load()
            assert image.size == (274, 364)
        assert_cms_oids(face[88 + face_record:],"2.16.840.1.101.3.6.2",0)
        cms_verify(face[88 + face_record:], face[:88 + face_record],
                   directory / "signer.der")
        hashed[0x6030] = envelope(directory / "face.bin")
        hashed[0x3001] = encrypted_object(directory, "printed", key)
    verify_security(directory,"security.bin",manifest["security_mapping"],
                    manifest["security_digest"],hashed)
    changed_hashes = dict(hashed)
    changed_hashes[0x3000] = bytes([hashed[0x3000][0] ^ 1]) + hashed[0x3000][1:]
    try:
        verify_security(directory,"security.bin",manifest["security_mapping"],
                        manifest["security_digest"],changed_hashes)
    except AssertionError:
        pass
    else:
        raise AssertionError("Security Object accepted changed CHUID")
    if manifest["profile"] == "nexgen":
        piv_fingerprint = children(envelope(directory / "piv-fingerprint.bin"))
        piv_face = children(envelope(directory / "piv-face.bin"))
        assert [tag for tag, _ in piv_fingerprint] == [b"\xbc", b"\xfe"]
        assert [tag for tag, _ in piv_face] == [b"\xbc", b"\xfe"]
        assert piv_fingerprint[0][1] == fingerprint
        assert piv_face[0][1] == face
        piv_printed = children(envelope(directory / "piv-printed.bin"))
        assert [tag for tag, _ in piv_printed] == [b"\x01", b"\x02", b"\x04",
                                                  b"\x05", b"\x06", b"\xfe"]
        assert [len(value) for _, value in piv_printed] == [10,0,9,10,15,0]
        piv_discovery = children(envelope(directory / "piv-discovery.bin"))
        assert [tag for tag, _ in piv_discovery] == [bytes([tag]) for tag in
            (0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xfa,0xfb,0xfc,0xfd,0xfe)]
        assert [len(value) for _, value in piv_discovery] == [21,1,1,0,1,1,17,0,0,0,0,0,0]
        piv_hashed = {
            0x3000: envelope(directory / "piv-signed-chuid.bin"),
            0x6010: envelope(directory / "piv-fingerprint.bin"),
            0xdb00: envelope(directory / "piv-discovery.bin"),
            0x6030: envelope(directory / "piv-face.bin"),
            0x3001: envelope(directory / "piv-printed.bin"),
        }
        verify_security(directory,"piv-security.bin",manifest["piv_security_mapping"],
                        "sha256",piv_hashed)
    else:
        piv_fingerprint = children(envelope(directory / "piv-fingerprint.bin"))
        piv_face = children(envelope(directory / "piv-face.bin"))
        assert [tag for tag, _ in piv_fingerprint] == [b"\xbc", b"\xfe"]
        assert [tag for tag, _ in piv_face] == [b"\xbc", b"\xfe"]
        assert piv_fingerprint[0][1] == fingerprint
        legacy_face = piv_face[0][1]
        assert int.from_bytes(legacy_face[2:6], "big") == 9713
        assert legacy_face[88:92] == b"FAC\x00"
        cms_verify(legacy_face[88 + 9713:], legacy_face[:88 + 9713],
                   directory / "signer.der")
        piv_printed = children(envelope(directory / "piv-printed.bin"))
        assert [tag for tag, _ in piv_printed] == [b"\x01", b"\x02", b"\x04",
                                                  b"\x05", b"\x06", b"\xfe"]
        assert [len(value) for _, value in piv_printed] == [10, 0, 9, 10, 15, 0]
        piv_hashed = {
            0x3000: envelope(directory / "piv-signed-chuid.bin"),
            0x6010: envelope(directory / "piv-fingerprint.bin"),
            0xdb00: envelope(directory / "piv-discovery.bin"),
            0x6030: envelope(directory / "piv-face.bin"),
            0x3001: envelope(directory / "piv-printed.bin"),
        }
        verify_security(directory, "piv-security.bin", manifest["piv_security_mapping"],
                        "sha1", piv_hashed)
    assert set(manifest["objects"]["present"]) == {
        name for name in ("signed-chuid", "unsigned-chuid", "tpk", "fingerprint",
                          "card-auth-cert", "face", "printed", "security", "discovery",
                          "personal", "handwritten", "iris")
        if (directory / f"{name}.bin").exists()
    }
    for name in manifest["objects"].get("empty_5300", []):
        assert (directory / f"{name}.bin").read_bytes() == b"\x53\x00"
    if manifest["profile"] == "nexgen":
        discovery = (directory / "discovery.bin").read_bytes()
        tag, value, end = tlv(discovery)
        assert tag == b"\x7e" and end == len(discovery)
        assert [tag for tag, _ in children(value)] == [b"\x4f", b"\x5f\x2f"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    for profile in ("legacy", "nexgen"):
        validate_profile(args.root / profile)
        print(f"{profile}: synthetic fixture validated")


if __name__ == "__main__":
    main()
