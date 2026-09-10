# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check C name preparation against RFC tables and Python's Unicode 3.2 normalizer."""
import argparse
import hashlib
import os
from pathlib import Path
import random
import re
import sys
import tempfile
import unicodedata

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from munit_runner import run_reader


def read_reference(path, digest):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError(f"{path}: reference digest differs")
    return raw.decode("utf-8")


def expand(text):
    points = set()
    for first, last in re.findall(r"(?<![0-9A-Za-z])([0-9A-F]{4,6})(?:-([0-9A-F]{4,6}))?(?![0-9A-Za-z])", text):
        points.update(range(int(first, 16), int(last or first, 16) + 1))
    return points


class Oracle:
    def __init__(self, stringprep, ldap):
        def table(name):
            return stringprep.split(f"----- Start Table {name} -----", 1)[1].split(
                f"----- End Table {name} -----", 1)[0]
        self.folding = {}
        for line in table("B.2").splitlines():
            match = re.fullmatch(r"\s*([0-9A-F]+); ([0-9A-F ]+);.*", line)
            if match:
                self.folding[int(match[1], 16)] = tuple(int(c, 16) for c in match[2].split())
        self.prohibited = {0xfffd}
        self.boundaries = set()
        for name in ("A.1", "C.3", "C.4", "C.5", "C.8"):
            for line in table(name).splitlines():
                body = line.split(";", 1)[0].strip()
                if re.fullmatch(r"[0-9A-F]{4,6}(?:-[0-9A-F]{4,6})?", body):
                    points = expand(body)
                    self.prohibited.update(points)
                    first, last = min(points), max(points)
                    self.boundaries.update(c for c in (first - 1, first, last, last + 1)
                                           if 0 <= c <= 0x10ffff)
        appendix = ldap.split("Appendix A.  Combining Marks", 1)[1].split("Appendix B.", 1)[0]
        self.marks = expand(appendix)
        self.removed = expand("""
            0000-0008 000E-001F 007F-0084 0086-009F 00AD 034F 06DD 070F
            1806 180B-180E 200B-200F 202A-202E 2060-2063 206A-206F
            FE00-FE0F FEFF FFF9-FFFC 1D173-1D17A E0001 E0020-E007F
        """)
        self.spaces = expand("0009-000D 0085 0020 00A0 1680 2000-200A 2028-2029 202F 205F 3000")

    def prepare(self, tag, raw):
        try:
            if tag == 0x0c:
                value = raw.decode("utf-8")
            elif tag in (0x13, 0x16):
                value = raw.decode("ascii")
                if tag == 0x13 and any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?" for c in value):
                    return None
            elif tag == 0x1e:
                if len(raw) % 2:
                    return None
                points = [int.from_bytes(raw[i:i + 2], "big") for i in range(0, len(raw), 2)]
                if any(0xd800 <= c <= 0xdfff for c in points):
                    return None
                value = "".join(map(chr, points))
            else:
                value = raw.decode("utf-32-be")
        except UnicodeError:
            return None
        mapped = []
        for c in map(ord, value):
            if c in self.removed:
                continue
            mapped.extend((0x20,) if c in self.spaces else self.folding.get(c, (c,)))
        normalized = tuple(map(ord, unicodedata.ucd_3_2_0.normalize("NFKC", "".join(map(chr, mapped)))))
        if any(c in self.prohibited for c in normalized):
            return None
        result, pending, seen = [0x20], False, False
        for i, c in enumerate(normalized):
            space = c == 0x20 and (i + 1 == len(normalized) or normalized[i + 1] not in self.marks)
            if space:
                pending = True
            else:
                if pending and seen:
                    result.extend((0x20, 0x20))
                result.append(c)
                pending, seen = False, True
        result.append(0x20)
        return result

    def cases(self):
        points = self.boundaries | self.marks | set(self.folding) | self.removed | self.spaces
        points.update(c for c in range(0x110000) if unicodedata.ucd_3_2_0.decomposition(chr(c)))
        for c in sorted(points):
            yield 0x0c, chr(c).encode("utf-8", errors="surrogatepass")
        for c in range(256):
            yield 0x13, bytes([c])
            yield 0x16, bytes([c])
        for c in sorted(points)[::7]:
            yield 0x1c, c.to_bytes(4, "big")
            if c <= 0xffff:
                yield 0x1e, c.to_bytes(2, "big")
        rng = random.Random(4518)
        population = sorted(points) + [0x20] * 1000
        for _ in range(3000):
            value = "".join(chr(rng.choice(population)) for _ in range(rng.randrange(17)))
            yield 0x0c, value.encode("utf-8", errors="surrogatepass")
        for raw in (b"\x80", b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82"):
            yield 0x0c, raw
        yield 0x1e, bytes.fromhex("d800dc00")
        yield 0x1c, bytes.fromhex("00110000")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rfc3454", required=True, type=Path)
    parser.add_argument("--rfc4518", required=True, type=Path)
    parser.add_argument("--reader", required=True, type=Path)
    args = parser.parse_args()
    oracle = Oracle(
        read_reference(args.rfc3454, "eb722fa698fb7e8823b835d9fd263e4cdb8f1c7b0d234edf7f0e3bd2ccbb2c79"),
        read_reference(args.rfc4518, "a12b9a04e49cf778f7a26e59d32a2bda02d6d4ab4d4151b6a8cc9db21070a068"))
    cases = list(oracle.cases())
    passed, rejected = 0, 0
    with tempfile.TemporaryDirectory(prefix="tiny-crypto-unicode-") as directory:
        path = Path(directory) / "preparation.txt"
        with path.open("w", encoding="ascii") as stream:
            stream.write(f"{len(cases)}\n")
            for tag, raw in cases:
                expected = oracle.prepare(tag, raw)
                if expected is None:
                    rejected += 1
                else:
                    passed += 1
                if len(raw) > 256 or (expected is not None and len(expected) > 1024):
                    raise ValueError("oracle case exceeds reader buffers")
                answer = "-" if expected is None else "".join(f"{c:08x}" for c in expected)
                stream.write(f"{tag} {0 if expected is not None else -1} {raw.hex() or '-'} {answer}\n")
        env = dict(os.environ, TC_UNICODE_ORACLE_FILE=str(path))
        run_reader([args.reader.resolve(), "/unicode/preparation-oracle"], env, echo=False)
    print(f"Unicode preparation: {passed} positive and {rejected} negative cases passed")


if __name__ == "__main__":
    main()
