#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Capture TWIC/PIV APDUs in a private directory on macOS PC/SC.

This test tool uses read-only object commands and a fresh card-key challenge.
The optional PIN phase submits one supplied PIN after checking retries. Never
place a PIN on the command line or in a transcript.
"""

from __future__ import annotations

import argparse
import ctypes as c
import getpass
import json
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils


PCSC = c.CDLL("/System/Library/Frameworks/PCSC.framework/PCSC")
U32 = c.c_uint32
I32 = c.c_int32


class PCI(c.Structure):
    _fields_ = [("protocol", U32), ("length", U32)]


PCSC.SCardEstablishContext.argtypes = [U32, c.c_void_p, c.c_void_p, c.POINTER(I32)]
PCSC.SCardEstablishContext.restype = I32
PCSC.SCardListReaders.argtypes = [I32, c.c_char_p, c.c_void_p, c.POINTER(U32)]
PCSC.SCardListReaders.restype = I32
PCSC.SCardConnect.argtypes = [I32, c.c_char_p, U32, U32, c.POINTER(I32), c.POINTER(U32)]
PCSC.SCardConnect.restype = I32
PCSC.SCardBeginTransaction.argtypes = [I32]
PCSC.SCardBeginTransaction.restype = I32
PCSC.SCardTransmit.argtypes = [I32, c.POINTER(PCI), c.c_void_p, U32,
                                c.c_void_p, c.c_void_p, c.POINTER(U32)]
PCSC.SCardTransmit.restype = I32
PCSC.SCardEndTransaction.argtypes = [I32, U32]
PCSC.SCardEndTransaction.restype = I32
PCSC.SCardDisconnect.argtypes = [I32, U32]
PCSC.SCardDisconnect.restype = I32
PCSC.SCardReleaseContext.argtypes = [I32]
PCSC.SCardReleaseContext.restype = I32


PIV_AID = bytes.fromhex("a000000308000010000100")
TWIC_AID = {"legacy": bytes.fromhex("a000000367200000010101"),
            "nexgen": bytes.fromhex("a000000367200000010103")}
TWIC_TAGS = ["5fc101", "5fc102", "5fc104", "7e", "dfc101", "dfc103",
             "dfc108", "dfc109", "dfc10f", "dfc001", "dfc002", "dfc121"] + [
                 f"dfc1{item:02x}" for item in (*range(0xe1, 0xeb),
                                                  *range(0xfa, 0xfe))]
PIV_TAGS = ["5fc102", "5fc105", "5fc107", "5fc10a", "5fc10b", "5fc10c",
            "5fc10d", "5fc10e", "5fc10f", "5fc101", "7e"]
PIN_TAGS = ["5fc103", "5fc108", "5fc106", "5fc109", "5fc10a"]


def checked(status: int, operation: str) -> None:
    if status:
        raise RuntimeError(f"{operation}: PC/SC status 0x{status & 0xffffffff:08x}")


def private_file(path: Path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    return os.fdopen(os.open(path, flags, 0o600), "wb")


def prepare_output(path: Path, phase: str) -> None:
    if phase == "inventory":
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir() or path.stat().st_mode & 0o077:
        raise RuntimeError("private output directory must have mode 0700")


def tlvs(data: bytes) -> list[tuple[int, bytes]]:
    parsed = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise RuntimeError("truncated TLV")
        tag = data[offset]
        offset += 1
        length = data[offset]
        offset += 1
        if length & 128:
            count = length & 127
            if not 0 < count <= 3 or offset + count > len(data):
                raise RuntimeError("invalid TLV length")
            length = int.from_bytes(data[offset:offset + count], "big")
            offset += count
        if offset + length > len(data):
            raise RuntimeError("truncated TLV value")
        parsed.append((tag, data[offset:offset + length]))
        offset += length
    return parsed


def tagged(items: list[tuple[int, bytes]], tag: int) -> bytes:
    selected = [value for current, value in items if current == tag]
    if len(selected) != 1:
        raise RuntimeError("required TLV field missing")
    return selected[0]


def length_bytes(length: int) -> bytes:
    if length < 128:
        return bytes((length,))
    if length < 256:
        return bytes((0x81, length))
    return bytes((0x82, length >> 8, length & 255))


class Card:
    def __init__(self, reader_name: str):
        self.context = I32()
        self.card = I32()
        self.transaction = False
        checked(PCSC.SCardEstablishContext(2, None, None, c.byref(self.context)),
                "establish context")
        try:
            size = U32()
            checked(PCSC.SCardListReaders(self.context, None, None, c.byref(size)),
                    "list readers")
            names = c.create_string_buffer(size.value)
            checked(PCSC.SCardListReaders(self.context, None, names, c.byref(size)),
                    "list readers")
            readers = names.raw[:size.value].rstrip(b"\x00").split(b"\x00")
            matches = [item for item in readers if reader_name.encode() in item]
            if len(matches) != 1:
                raise RuntimeError("reader selection is absent or ambiguous")
            self.reader = matches[0]
            self.protocol = U32()
            checked(PCSC.SCardConnect(self.context, self.reader, 1, 3,
                                      c.byref(self.card), c.byref(self.protocol)),
                    "connect")
            checked(PCSC.SCardBeginTransaction(self.card), "begin transaction")
            self.transaction = True
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self.transaction:
            PCSC.SCardEndTransaction(self.card, 0)
            self.transaction = False
        if self.card.value:
            PCSC.SCardDisconnect(self.card, 0)
            self.card = I32()
        if self.context.value:
            PCSC.SCardReleaseContext(self.context)
            self.context = I32()

    def exchange(self, trace, operation: str, command: bytes,
                 sensitive: bool = False, sequence: int | None = None) -> tuple[bytes, int]:
        sent = c.create_string_buffer(command)
        received = c.create_string_buffer(65538)
        received_size = U32(len(received))
        pci = PCI(self.protocol.value, c.sizeof(PCI))
        status = PCSC.SCardTransmit(self.card, c.byref(pci), sent, len(command), None,
                                    received, c.byref(received_size))
        raw = received.raw[:received_size.value] if status == 0 else b""
        entry = {"operation": operation,
                 "command_hex": None if sensitive else command.hex(),
                 "response_hex": raw.hex(), "pcsc_result": status & 0xffffffff}
        if sensitive:
            entry["command_header_hex"] = command[:5].hex()
            entry["command_data_redacted"] = True
        if sequence is not None:
            entry = {"type": "exchange", "seq": sequence, **entry}
        trace.write((json.dumps(entry, separators=(",", ":")) + "\n").encode())
        trace.flush()
        checked(status, operation)
        if len(raw) < 2:
            raise RuntimeError("short card response")
        return raw[:-2], int.from_bytes(raw[-2:], "big")

    def select(self, trace, label: str, aid: bytes,
               sequence: int | None = None) -> int:
        _, status = self.exchange(trace, "SELECT " + label,
                                  b"\x00\xa4\x04\x00" + bytes((len(aid),)) + aid +
                                  b"\x00", sequence=sequence)
        return status

    def read_object(self, trace, app: str, tag: str, output: Path,
                    sequence: int | None = None) -> int:
        encoded_tag = bytes.fromhex(tag)
        command = b"\x00\xcb\x3f\xff" + bytes((2 + len(encoded_tag), 0x5c,
                                                len(encoded_tag))) + encoded_tag + b"\x00"
        payload = bytearray()
        corrected = False
        operation = "GET DATA"
        for part in range(160):
            label = f"{operation} {app} {tag}"
            body, status = self.exchange(trace, label, command,
                                         sequence=None if sequence is None else sequence + part)
            if status >> 8 == 0x6c:
                if corrected:
                    raise RuntimeError("repeated APDU length correction")
                command = command[:-1] + bytes((status & 255,))
                corrected = True
                continue
            payload.extend(body)
            if len(payload) > 20000:
                raise RuntimeError("card object exceeds 20 KiB bound")
            if status >> 8 == 0x61:
                command = b"\x00\xc0\x00\x00" + bytes((status & 255,))
                operation = "GET RESPONSE"
                corrected = False
                continue
            if status in (0x9000, 0x6282) and payload:
                with private_file(output) as file:
                    file.write(payload)
            return part + 1
        raise RuntimeError("card object response exceeded 160 chunks")

    def check_piv_identity(self, trace, output: Path) -> None:
        expected = (output / "PIV-5fc102.bin").read_bytes()
        command = bytes.fromhex("00cb3fff055c035fc10200")
        payload = bytearray()
        operation = "GET DATA"
        corrected = False
        for _ in range(160):
            body, status = self.exchange(trace, f"{operation} PIV 5fc102", command)
            if status >> 8 == 0x6c:
                if corrected:
                    raise RuntimeError("identity APDU length correction repeated")
                command = command[:-1] + bytes((status & 255,))
                corrected = True
                continue
            payload.extend(body)
            if len(payload) > 20000:
                raise RuntimeError("identity object exceeds bound")
            if status >> 8 == 0x61:
                command = b"\x00\xc0\x00\x00" + bytes((status & 255,))
                operation = "GET RESPONSE"
                corrected = False
                continue
            if status not in (0x9000, 0x6282) or bytes(payload) != expected:
                raise RuntimeError("card identity differs from inventory; stopped")
            return
        raise RuntimeError("identity response exceeded 160 chunks")


def capture_inventory(card: Card, output: Path, profile: str, interface: str) -> None:
    with private_file(output / "raw-apdu.jsonl") as trace:
        session = {"type": "session", "reader": card.reader.decode(),
                   "protocol": card.protocol.value, "interface": interface,
                   "card_alias": profile + "-1"}
        trace.write((json.dumps(session, separators=(",", ":")) + "\n").encode())
        sequence = 1
        if card.select(trace, f"TWIC {profile}", TWIC_AID[profile], sequence) == 0x9000:
            sequence += 1
            for tag in TWIC_TAGS:
                sequence += card.read_object(trace, "TWIC", tag,
                                             output / f"TWIC-{tag}.bin", sequence)
        else:
            raise RuntimeError("TWIC application selection failed")
        if card.select(trace, "PIV", PIV_AID, sequence) != 0x9000:
            raise RuntimeError("PIV application selection failed")
        sequence += 1
        for tag in PIV_TAGS:
            sequence += card.read_object(trace, "PIV", tag,
                                         output / f"PIV-{tag}.bin", sequence)
    print("inventory captured; private APDU and object files saved")


def capture_pin(card: Card, output: Path, interface: str) -> None:
    if interface != "contact":
        raise RuntimeError("PIN phase requires contact interface")
    with private_file(output / "pin-session.jsonl") as trace:
        if card.select(trace, "PIV", PIV_AID) != 0x9000:
            raise RuntimeError("PIV application selection failed")
        card.check_piv_identity(trace, output)
        _, status = card.exchange(trace, "PIN status", bytes.fromhex("00200080"))
        if status == 0x9000:
            print("PIN already verified; no submission")
        elif status & 0xfff0 == 0x63c0 and status & 15 >= 2:
            digits = getpass.getpass("PIV PIN (input hidden): ")
            if len(digits) != 8 or not digits.isascii() or not digits.isdigit():
                raise RuntimeError("PIN format refused; no submission")
            command = bytearray(bytes.fromhex("0020008008") + digits.encode("ascii"))
            digits = ""
            try:
                _, status = card.exchange(trace, "PIN VERIFY", bytes(command), sensitive=True)
            finally:
                command[:] = b"\x00" * len(command)
            if status != 0x9000:
                raise RuntimeError("PIN verification failed; stopped after one attempt")
            print("one PIN verification succeeded")
        else:
            raise RuntimeError("PIN retry status unsafe; no submission")
        for tag in PIN_TAGS:
            card.read_object(trace, "PIV", tag,
                             output / f"PIV-{tag}-after-pin.bin")
    print("PIN-gated inventory captured")


def capture_card_proof(card: Card, output: Path) -> None:
    envelope = tlvs((output / "PIV-5fc101.bin").read_bytes())
    cert = x509.load_der_x509_certificate(tagged(tlvs(tagged(envelope, 0x53)), 0x70))
    key = cert.public_key()
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
        raise RuntimeError("card authentication key is not RSA-2048")
    digest = os.urandom(32)
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    emsa = b"\x00\x01" + b"\xff" * (256 - 3 - len(digest_info)) + b"\x00" + digest_info
    content = b"\x82\x00\x81" + length_bytes(len(emsa)) + emsa
    request = b"\x7c" + length_bytes(len(content)) + content
    with private_file(output / "card-key-proof.jsonl") as trace:
        if card.select(trace, "PIV", PIV_AID) != 0x9000:
            raise RuntimeError("PIV application selection failed")
        card.check_piv_identity(trace, output)
        first, last = request[:255], request[255:]
        _, status = card.exchange(trace, "GENERAL AUTHENTICATE chain",
                                  bytes((0x10, 0x87, 0x07, 0x9e, len(first))) + first)
        if status != 0x9000:
            raise RuntimeError("card authentication command chain failed")
        response, status = card.exchange(trace, "GENERAL AUTHENTICATE final",
                                         bytes((0, 0x87, 0x07, 0x9e, len(last))) + last + b"\x00")
        for _ in range(160):
            if status >> 8 != 0x61:
                break
            more, status = card.exchange(trace, "GET RESPONSE",
                                         b"\x00\xc0\x00\x00" + bytes((status & 255,)))
            response += more
            if len(response) > 20000:
                raise RuntimeError("card proof response exceeds bound")
        else:
            raise RuntimeError("card proof response exceeded 160 chunks")
        if status != 0x9000:
            raise RuntimeError("card authentication failed")
        signature = tagged(tlvs(tagged(tlvs(response), 0x7c)), 0x82)
        try:
            key.verify(signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        except Exception as error:
            raise RuntimeError("card authentication signature invalid") from error
    print("fresh card-key challenge verified")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("inventory", "pin", "card-proof"))
    parser.add_argument("--profile", choices=("legacy", "nexgen"), required=True)
    parser.add_argument("--interface", choices=("contact", "contactless"), required=True)
    parser.add_argument("--reader", required=True, help="unique substring of PC/SC reader name")
    parser.add_argument("--output", type=Path, required=True,
                        help="private output directory, mode 0700")
    args = parser.parse_args()
    try:
        prepare_output(args.output, args.phase)
        card = Card(args.reader)
        try:
            if args.phase == "inventory":
                capture_inventory(card, args.output, args.profile, args.interface)
            elif args.phase == "pin":
                capture_pin(card, args.output, args.interface)
            else:
                capture_card_proof(card, args.output)
        finally:
            card.close()
    except (OSError, RuntimeError, ValueError) as error:
        # Card values and PINs are never included in errors from this tool.
        print(f"capture failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
