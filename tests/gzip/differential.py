# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate deterministic synthetic inputs and compare decoding with zlib."""
import gzip
import random
import struct
import subprocess
import sys
import zlib


def pack_record(encoded, expected, status=0):
    return struct.pack(">BII", status, len(encoded), len(expected)) + encoded + expected


class Bits:
    """Pack RFC 1951 fields in transmission order."""
    def __init__(self):
        self.values = []

    def put(self, value, width):
        self.values.extend((value >> bit) & 1 for bit in range(width))

    def bytes(self):
        return bytes(sum(bit << j for j, bit in enumerate(self.values[i:i + 8]))
                     for i in range(0, len(self.values), 8))


def dynamic_header(code_lengths):
    bits = Bits()
    bits.put(1, 1)  # Final block.
    bits.put(2, 2)  # Dynamic Huffman codes.
    bits.put(0, 5)  # 257 literal/length codes.
    bits.put(0, 5)  # One distance code.
    bits.put(15, 4)  # All 19 code-length symbols.
    order = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15)
    for symbol in order:
        bits.put(code_lengths.get(symbol, 0), 3)
    return bits


def tree_cases():
    yield "oversubscribed code-length tree", dynamic_header({0: 1, 1: 1, 16: 1}), False
    yield "incomplete code-length tree", dynamic_header({0: 2, 1: 2}), False
    bits = dynamic_header({0: 1, 16: 1})
    bits.put(1, 1)  # Repeat previous length before any length exists.
    bits.put(0, 2)
    yield "repeat without predecessor", bits, False
    bits = dynamic_header({0: 1, 18: 1})
    for _ in range(2):
        bits.put(1, 1)
        bits.put(127, 7)  # Two runs of 138 exceed the 258 declared lengths.
    yield "length repeat overflow", bits, False
    bits = dynamic_header({0: 1, 1: 1})
    for _ in range(258):
        bits.put(0, 1)
    yield "missing end-of-block code", bits, False
    bits = dynamic_header({0: 1, 1: 1})
    for symbol in range(258):
        bits.put(int(symbol == 256), 1)
    bits.put(0, 1)  # The sole literal code is end-of-block; distance is unused.
    yield "empty distance alphabet", bits, True


def main():
    rng = random.Random(1952)
    random_block = bytes(rng.randrange(256) for _ in range(32768))
    payloads = [b"", b"a", b"a" * 1000, b"abc" * 22000,
                bytes(range(256)) * 256, random_block, random_block * 2,
                b"The quick brown fox jumps over the lazy dog. " * 100,
                random_block[:4096] + b"\0" * 4096 + random_block[:4096]]
    records = bytearray()
    count = 0

    def add(encoded, expected, status=0):
        nonlocal count
        records.extend(pack_record(encoded, expected, status))
        count += 1

    for data in payloads:
        for level in (0, 1, 6, 9):
            for strategy in (zlib.Z_DEFAULT_STRATEGY, zlib.Z_FILTERED,
                             zlib.Z_HUFFMAN_ONLY, zlib.Z_RLE, zlib.Z_FIXED):
                compressor = zlib.compressobj(level, zlib.DEFLATED, 31, 8, strategy)
                encoded = compressor.compress(data) + compressor.flush()
                assert gzip.decompress(encoded) == data
                add(encoded, data)
                corrupt = bytearray(encoded)
                corrupt[-8] ^= 1
                try:
                    gzip.decompress(corrupt)
                except (OSError, zlib.error):
                    pass
                else:
                    raise AssertionError("Checksum mutation accepted by oracle")
                add(corrupt, data, 1)
        midpoint = len(data) // 2
        members = gzip.compress(data[:midpoint], mtime=0) + gzip.compress(data[midpoint:], mtime=0)
        assert gzip.decompress(members) == data
        add(members, data)
    for name, bits, valid in tree_cases():
        encoded = bytes.fromhex("1f8b08000000000000ff") + bits.bytes() + bytes(8)
        try:
            decoded = gzip.decompress(encoded)
        except (OSError, EOFError, zlib.error):
            if valid:
                raise AssertionError(f"Oracle rejected {name}")
        else:
            if not valid or decoded:
                raise AssertionError(f"Unexpected oracle result for {name}")
        add(encoded, b"", 0 if valid else 1)
    print(f"Generated {count} positive/negative GZIP cases", flush=True)
    subprocess.run([sys.argv[1]], input=records, check=True)


if __name__ == "__main__":
    main()
