#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Measure linked AVR flash and conservative project stack call chains.

Uses compiler stack reports and emitted assembly, including possible indirect
callees whose addresses are taken in each translation unit. Tail calls are
counted as nested calls, so the estimate can overcount. libc/compiler helpers,
interrupts and the application caller are excluded and listed explicitly.
This is a regression measurement, not a whole-firmware stack-safety proof.
"""
import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CC = os.environ.get("AVR_CC", "avr-gcc")
SIZE = os.environ.get("AVR_SIZE", "avr-size")
BASE = ["-std=c99", "-Os", "-mmcu=atmega328p", "-ffunction-sections",
        "-fdata-sections", "-fstack-usage", "-I" + str(ROOT / "src")]
PROFILES = {
    "aes_ctr": ([], """
      struct TC_AES_ctx ctx;
      if (TC_AES_init_ctx_iv(&ctx, key, iv) != TC_OK) return 1;
      return TC_AES_CTR_crypt(&ctx, out, sizeof(out)) != TC_OK;
    """, "TC_AES_CTR_crypt"),
    "kdf_sha256": (["TC_ENABLE_HMAC=1", "TC_ENABLE_KDF=1"], """
      struct TC_KBKDF_params p = {32, 1, 0};
      return TC_KBKDF_HMAC_SHA256_counter(key, sizeof(key), &p,
          0, 0, iv, sizeof(iv), out, sizeof(out)) != TC_OK;
    """, "TC_KBKDF_HMAC_SHA256_counter"),
    "kdf_mixed": ([
        "TC_ENABLE_HMAC=1", "TC_ENABLE_KDF=1", "TC_ENABLE_SHA1=1",
        "TC_ENABLE_SHA224=1", "TC_ENABLE_SHA384=1", "TC_ENABLE_SHA512=1",
        "TC_ENABLE_DES=1", "TC_DES_ENABLE_CMAC=1", "TC_AES_ENABLE_CMAC=1",
    ], """
      struct TC_KBKDF_params p = {32, 1, 0};
      return TC_KBKDF_HMAC_SHA256_counter(key, sizeof(key), &p,
          0, 0, iv, sizeof(iv), out, sizeof(out)) != TC_OK;
    """, "TC_KBKDF_HMAC_SHA256_counter"),
}
SOURCE = """
#include <tiny_crypto/tiny_crypto.h>
static uint8_t key[32], iv[16], out[32];
static volatile uint8_t sink;
static int feature(void) { %s }
int main(void) { int status = feature(); sink = out[0]; return status; }
"""


def run(command):
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)


def normalize(name):
    return re.sub(r"\.(?:constprop|isra|part)(?:\.\d+)?", "", name)


def measure(directory, definitions, body, entry):
    flags = BASE + ["-D" + item for item in definitions]
    frames, edges, objects, unknown_indirect = {}, {}, [], []
    for source in sorted((ROOT / "src").glob("*.c")):
        assembly = directory / (source.stem + ".s")
        run([CC, *flags, "-S", str(source), "-o", str(assembly)])
        for line in assembly.with_suffix(".su").read_text().splitlines():
            location, size, kind = line.split("\t")
            if kind not in ("static", "dynamic,bounded"):
                raise RuntimeError("Unbounded frame: " + line)
            name = normalize(location.rsplit(":", 1)[-1])
            frames[name] = max(frames.get(name, 0), int(size))
        text = assembly.read_text()
        address_taken = {normalize(x) for x in
                         re.findall(r"gs\(([A-Za-z_]\w*(?:\.\w+)*)\)", text)}
        current = None
        for line in text.splitlines():
            match = re.search(r"\.type\s+([^,]+),\s*@function", line)
            if match:
                current = normalize(match[1])
                edges.setdefault(current, set())
            if current is None:
                continue
            match = re.match(r"\s*(?:call|rcall|jmp|rjmp)\s+([A-Za-z_]\w*(?:\.\w+)*)", line)
            if match:
                edges[current].add(normalize(match[1]))
            if re.match(r"\s*(?:icall|eicall|ijmp|eijmp)\s*$", line):
                if not address_taken:
                    unknown_indirect.append(current)
                edges[current].update(address_taken)
            if re.match(r"\s*\.size\s", line):
                current = None
        obj = assembly.with_suffix(".o")
        run([CC, "-mmcu=atmega328p", "-c", str(assembly), "-o", str(obj)])
        objects.append(str(obj))
    source = directory / "main.c"
    source.write_text(SOURCE % body)
    main_object = directory / "main.o"
    run([CC, *flags, "-c", str(source), "-o", str(main_object)])
    elf = directory / "profile.elf"
    run([CC, "-mmcu=atmega328p", str(main_object), *objects, "-Wl,--gc-sections",
         "-o", str(elf)])
    sections = {}
    for line in run([SIZE, "-A", str(elf)]).splitlines():
        match = re.match(r"(\.\w+)\s+(\d+)", line)
        if match:
            sections[match[1]] = int(match[2])
    if ".text" not in sections:
        raise RuntimeError("Missing linked .text section")
    unknown = set()

    def chain(name, active):
        if name in active:
            raise RuntimeError("Recursive stack path: " + name)
        if name not in frames:
            if name == entry or name.startswith(("TC_", "tc_")):
                raise RuntimeError("Missing project stack frame: " + name)
            unknown.add(name)
            return 0, []
        if name in unknown_indirect:
            raise RuntimeError("Unresolved indirect call: " + name)
        children = [chain(child, active | {name})
                    for child in sorted(edges.get(name, ()))]
        size, path = max(children, default=(0, []), key=lambda item: item[0])
        return frames[name] + size, [name] + path

    stack, path = chain(entry, set())
    return {
        "flash": sections.get(".text", 0) + sections.get(".data", 0),
        "static_ram": sections.get(".data", 0) + sections.get(".bss", 0),
        "project_stack_estimate": stack,
        "stack_path": [{"function": name, "frame": frames[name]} for name in path],
        "excluded_external_callees": sorted(unknown),
        "kdf_workspace_frame": frames.get("tc_kdf_HMAC_SHA256"),
        "flags": [flag.replace(str(ROOT) + "/", "") for flag in flags],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    report = {"compiler": run([CC, "--version"]).splitlines()[0],
              "stack_scope": __doc__, "profiles": {}}
    with tempfile.TemporaryDirectory() as temporary:
        for name, (definitions, body, entry) in PROFILES.items():
            directory = Path(temporary) / name
            directory.mkdir()
            report["profiles"][name] = measure(directory, definitions, body, entry)
    if args.check:
        budgets = json.loads(args.check.read_text())
        for name, limits in budgets["profiles"].items():
            for metric, limit in limits.items():
                actual = report["profiles"][name][metric]
                if actual is None or actual > limit:
                    raise SystemExit(f"{name} {metric}: {actual} exceeds {limit}")
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
