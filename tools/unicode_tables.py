# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Read pinned Unicode 3.2 normalization data for X.509 name preparation."""

import argparse
import hashlib
import re
from pathlib import Path


SOURCES = {
    "UnicodeData-3.2.0.txt": "5e444028b6e76d96f9dc509609c5e3222bf609056f35e5fcde7e6fb8a58cd446",
    "CompositionExclusions-3.2.0.txt": "1d3a450d0f39902710df4972ac4a60ec31fbcb54ffd4d53cd812fc1200c732cb",
    "NormalizationTest-3.2.0.txt": "c4513869bb7098d19838be4a1fd5d760843c5804bfe03bd6bbb20623ceb6e57d",
    "CaseFolding-3.2.0.txt": "370f3d1e79a52791c42065946711f4eddb6d9820726afd0e436a3c50360475a9",
}


def read_source(directory, name):
    data = (directory / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCES[name]:
        raise ValueError(f"{name}: SHA-256 does not match Unicode 3.2 data")
    return data.decode("latin-1" if name.startswith("CaseFolding-") else "utf-8")


class NormalizationData:
    def __init__(self, directory):
        self.classes = {}
        self.decompositions = {}
        self.compositions = {}
        self.allowed = set()
        self.marks = set()
        exclusions = {
            int(line.split("#", 1)[0].strip(), 16)
            for line in read_source(directory, "CompositionExclusions-3.2.0.txt").splitlines()
            if line.split("#", 1)[0].strip()
        }
        canonical = {}
        range_start = None
        for line in read_source(directory, "UnicodeData-3.2.0.txt").splitlines():
            fields = line.split(";")
            point, combining = int(fields[0], 16), int(fields[3])
            if fields[1].endswith(", First>"):
                range_start = point
                continue
            points = range(range_start, point + 1) if fields[1].endswith(", Last>") else (point,)
            range_start = None
            if fields[2] not in ("Co", "Cs", "Cn"):
                self.allowed.update(points)
            if fields[2] in ("Mn", "Mc", "Me"):
                self.marks.update(points)
            if combining:
                self.classes[point] = combining
            mapping = fields[5].split()
            if not mapping:
                continue
            compatible = mapping[0].startswith("<")
            if compatible:
                mapping = mapping[1:]
            parts = tuple(int(value, 16) for value in mapping)
            self.decompositions[point] = parts
            if not compatible:
                canonical[point] = parts
        for point, parts in canonical.items():
            # Singleton and non-starter decompositions cannot be recomposed.
            if (point not in exclusions and len(parts) == 2
                    and not self.classes.get(parts[0], 0)):
                if parts in self.compositions:
                    raise ValueError("ambiguous canonical composition")
                self.compositions[parts] = point
        self.allowed.difference_update({0x340, 0x341, 0x200e, 0x200f, 0xfffd},
                                       range(0x202a, 0x202f), range(0x206a, 0x2070))
        self.folding = {}
        for line in read_source(directory, "CaseFolding-3.2.0.txt").splitlines():
            body = line.split("#", 1)[0].strip()
            if not body:
                continue
            point, status, mapping, _ = (field.strip() for field in body.split(";"))
            if status in ("C", "F"):
                self.folding[int(point, 16)] = tuple(int(value, 16) for value in mapping.split())
        # RFC 3454 section 3.2 adds folds exposed by compatibility normalization.
        additional = {}
        for point in self.decompositions.keys() | self.folding.keys():
            first = self.nfkc(self.folding.get(point, (point,)))
            second = self.nfkc(child for part in first for child in self.folding.get(part, (part,)))
            if first != second:
                additional[point] = second
        self.folding.update(additional)

    def decompose(self, point):
        if 0xac00 <= point < 0xd7a4:
            index = point - 0xac00
            parts = (0x1100 + index // 588, 0x1161 + index % 588 // 28)
            return parts + ((0x11a7 + index % 28,) if index % 28 else ())
        parts = self.decompositions.get(point)
        if parts is None:
            return (point,)
        return tuple(child for part in parts for child in self.decompose(part))

    def compose(self, first, second):
        if 0x1100 <= first < 0x1113 and 0x1161 <= second < 0x1176:
            return 0xac00 + (first - 0x1100) * 588 + (second - 0x1161) * 28
        if (0xac00 <= first < 0xd7a4 and (first - 0xac00) % 28 == 0
                and 0x11a8 <= second < 0x11c3):
            return first + second - 0x11a7
        return self.compositions.get((first, second))

    def nfkc(self, points):
        ordered = []
        for point in points:
            for child in self.decompose(point):
                combining = self.classes.get(child, 0)
                offset = len(ordered)
                if combining:
                    while offset and self.classes.get(ordered[offset - 1], 0) > combining:
                        offset -= 1
                ordered.insert(offset, child)
        result = []
        starter = None
        previous_class = 0
        for point in ordered:
            combining = self.classes.get(point, 0)
            composite = None
            if starter is not None and (previous_class == 0 or previous_class < combining):
                composite = self.compose(result[starter], point)
            if composite is not None:
                result[starter] = composite
            else:
                if combining == 0:
                    starter = len(result)
                result.append(point)
                previous_class = combining
        return tuple(result)


def check_normalization(directory, data):
    count = 0
    for line in read_source(directory, "NormalizationTest-3.2.0.txt").splitlines():
        body = line.split("#", 1)[0].strip()
        if not body or body.startswith("@"):
            continue
        columns = [tuple(int(point, 16) for point in field.split())
                   for field in body.split(";")[:5]]
        for index, column in enumerate(columns):
            if data.nfkc(column) != columns[3]:
                raise ValueError(f"normalization case {count + 1}, column {index + 1}")
        count += 1
    return count


def mapping_pool(mappings):
    pool, offsets, lengths = [], [], []
    known = {}
    for point in sorted(mappings):
        parts = mappings[point]
        if parts not in known:
            known[parts] = len(pool)
            pool.extend(parts)
        offsets.append(known[parts])
        lengths.append(len(parts))
    if len(pool) > 65535 or max(lengths, default=0) > 255:
        raise ValueError("decomposition data exceeds table field widths")
    return pool, offsets, lengths


def decomposition_pool(data):
    return mapping_pool({point: data.decompose(point) for point in data.decompositions})


def ranges(points):
    result = []
    for point in sorted(points):
        if result and point == result[-1][1] + 1:
            result[-1] = (result[-1][0], point)
        else:
            result.append((point, point))
    return result


def check_stringprep(path, data):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != "eb722fa698fb7e8823b835d9fd263e4cdb8f1c7b0d234edf7f0e3bd2ccbb2c79":
        raise ValueError("RFC 3454: SHA-256 does not match")
    text = raw.decode("utf-8")

    def table(name):
        return text.split(f"----- Start Table {name} -----", 1)[1].split(
            f"----- End Table {name} -----", 1)[0]

    folding = {}
    for line in table("B.2").splitlines():
        match = re.fullmatch(r"\s*([0-9A-F]+); ([0-9A-F ]+);.*", line)
        if match:
            folding[int(match[1], 16)] = tuple(int(point, 16) for point in match[2].split())
    if folding != data.folding:
        differences = [point for point in folding.keys() | data.folding.keys()
                       if folding.get(point) != data.folding.get(point)]
        raise ValueError(f"RFC 3454 B.2: {len(differences)} differing mappings: {differences[:8]}")
    prohibited = {0xfffd}
    for name in ("A.1", "C.3", "C.4", "C.5", "C.8"):
        for line in table(name).splitlines():
            match = re.fullmatch(r"\s*([0-9A-F]+)(?:-([0-9A-F]+))?(?:;.*)?", line)
            if match:
                prohibited.update(range(int(match[1], 16), int(match[2] or match[1], 16) + 1))
    allowed = set(range(0x110000)) - prohibited
    if allowed != data.allowed:
        raise ValueError(f"RFC 4518 prohibited values differ: {sorted(allowed ^ data.allowed)[:8]}")


def c_array(name, width, values):
    values = list(values)
    if not values:
        raise ValueError(f"{name}: empty C table")
    if any(value < 0 or value >= 1 << width for value in values):
        raise ValueError(f"{name}: value exceeds uint{width}_t")
    lines = [f"static const uint{width}_t {name}[] TC_UNICODE_STORAGE = {{"]
    for start in range(0, len(values), 8):
        lines.append("  " + ", ".join(f"0x{value:x}" for value in values[start:start + 8]) + ",")
    return "\n".join(lines + ["};"])


def render_tables(data, license_text):
    if "*/" in license_text or "UNICODE LICENSE V3" not in license_text:
        raise ValueError("expected Unicode License v3 text")
    pool, offsets, lengths = decomposition_pool(data)
    classes = sorted(data.classes)
    pairs = sorted(data.compositions)
    arrays = [
        ("tc_unicode_decomposition_keys", 32, sorted(data.decompositions)),
        ("tc_unicode_decomposition_offsets", 16, offsets),
        ("tc_unicode_decomposition_lengths", 8, lengths),
        ("tc_unicode_decomposition_pool", 32, pool),
        ("tc_unicode_class_keys", 32, classes),
        ("tc_unicode_class_values", 8, [data.classes[point] for point in classes]),
        ("tc_unicode_composition_first", 32, [pair[0] for pair in pairs]),
        ("tc_unicode_composition_second", 32, [pair[1] for pair in pairs]),
        ("tc_unicode_composition_values", 32, [data.compositions[pair] for pair in pairs]),
    ]
    folding_pool, folding_offsets, folding_lengths = mapping_pool(data.folding)
    if max(folding_lengths) > 4:
        raise ValueError("case folding exceeds the four-scalar runtime buffer")
    arrays.extend([
        ("tc_unicode_folding_keys", 32, sorted(data.folding)),
        ("tc_unicode_folding_offsets", 16, folding_offsets),
        ("tc_unicode_folding_lengths", 8, folding_lengths),
        ("tc_unicode_folding_pool", 32, folding_pool),
    ])
    for name, points in (("allowed", data.allowed), ("marks", data.marks)):
        intervals = ranges(points)
        arrays.extend([
            (f"tc_unicode_{name}_starts", 32, [start for start, _ in intervals]),
            (f"tc_unicode_{name}_ends", 32, [end for _, end in intervals]),
        ])
    header = ("/* SPDX-FileCopyrightText: 1991-2026 Unicode, Inc.\n"
              " * SPDX-License-Identifier: Unicode-3.0\n"
              " * Generated by tools/unicode_tables.py from Unicode 3.2 data.\n */\n"
              "/*\n" + license_text.rstrip() + "\n*/\n#include <stdint.h>\n")
    return header + "\n\n".join(c_array(*array) for array in arrays) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--license", type=Path)
    parser.add_argument("--check", action="store_true", help="compare the generated table with --output")
    parser.add_argument("--stringprep", type=Path, help="verify the derived tables against RFC 3454")
    args = parser.parse_args()
    if bool(args.output) != bool(args.license) or (args.check and not args.output):
        parser.error("--output and --license are required together; --check needs --output")
    data = NormalizationData(args.data_dir)
    if args.stringprep:
        check_stringprep(args.stringprep, data)
        print("RFC 3454: case folding and RFC 4518 prohibited values match")
    count = check_normalization(args.data_dir, data)
    print(f"Unicode 3.2: {count} normalization cases passed (five columns each)")
    if args.output:
        rendered = render_tables(data, args.license.read_text(encoding="utf-8"))
        if args.check:
            if args.output.read_bytes() != rendered.encode("utf-8"):
                parser.error(f"{args.output}: generated tables differ")
        else:
            args.output.write_bytes(rendered.encode("utf-8"))


if __name__ == "__main__":
    main()
