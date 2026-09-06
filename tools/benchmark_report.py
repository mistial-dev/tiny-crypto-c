#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Uno and Pico 2 examples and write their memory usage to Markdown.

PICO_SDK_PATH selects Pico SDK 2.3.1; PICO_TOOLCHAIN_PATH selects the bin
directory (or its parent) of Arm GCC 12.3.Rel1. Neither is needed for host tests.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

from benchmark_cases import FEATURES, SKETCH, definitions

ROOT = Path(__file__).resolve().parents[1]
SDK_REVISION = "079c6f39023649b154152db30f1d781e884879bc"
PLATFORM = "platformio/atmelavr@5.1.0"
CAPACITIES = {
    "uno": {"flash": 32768, "ram": 2048, "application_flash": 32256},
    "pico2": {"flash": 4194304, "ram": 532480, "application_flash": 4194304},
}


def run(command, **kwargs):
    result = subprocess.run([str(x) for x in command], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stdout + "\nFailed: " + str(command))
    return result.stdout


def host_source(body):
    return (SKETCH % body).replace('extern "C" ', '') + '\nint main(void) { return feature(); }\n'


def validate_host(directory, name, body, flags):
    source = directory / "validate.c"
    source.write_text(host_source(body), encoding="utf-8")
    executable = directory / "validate"
    command = shlex.split(os.environ.get("CC", "cc"))
    command += ["-std=c99", "-O1", "-g", "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer", "-I" + str(ROOT / "src")]
    command += ["-D" + k + "=" + v for k, v in definitions(flags).items()]
    command += [source, *sorted((ROOT / "src").glob("*.c")), "-o", executable]
    run(command)
    run([executable])
    print("Validated " + name, file=sys.stderr)


def validate_kmac_vectors(directory):
    executable = directory / "validate-kmac"
    command = shlex.split(os.environ.get("CC", "cc"))
    run([*command, "-std=c99", "-O1", "-g", "-fsanitize=address,undefined",
         "-fno-omit-frame-pointer", "-DTC_ENABLE_KMAC256=1", "-I" + str(ROOT / "src"),
         ROOT / "tests/kmac/test.c", ROOT / "src/kmac.c", ROOT / "src/common.c",
         "-o", executable])
    run([executable])
    print("Validated NIST and PIV Auto KMAC256 vectors", file=sys.stderr)


def sections_from_objdump(text):
    sections = []
    lines = text.splitlines()
    for i, line in enumerate(lines[:-1]):
        match = re.match(r"\s*\d+\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+", line)
        if match:
            name, size, vma, lma = match.groups()
            flags = set(lines[i+1].strip().split(", "))
            sections.append({"name": name, "size": int(size, 16),
                             "vma": int(vma, 16), "lma": int(lma, 16),
                             "flags": flags})
    if not sections or not any("ALLOC" in s["flags"] for s in sections):
        raise ValueError("Missing allocated ELF sections")
    return sections


def account(sections, board):
    capacity = CAPACITIES[board]
    flash_base, ram_base = (0, 0x800100) if board == "uno" else (0x10000000, 0x20000000)
    flash_end = flash_base
    static_ram = stack = heap = 0
    for section in sections:
        size, vma, lma = (section[k] for k in ("size", "vma", "lma"))
        if "ALLOC" not in section["flags"] or not size:
            continue
        flash_address = (0 <= lma < 0x800000 if board == "uno" else
                         0x10000000 <= lma < 0x20000000)
        if "LOAD" in section["flags"] and flash_address:
            if lma + size > flash_base + capacity["application_flash"]:
                raise ValueError("Flash section exceeds application capacity")
            flash_end = max(flash_end, lma + size)
        if ram_base <= vma < ram_base + capacity["ram"]:
            if vma + size > ram_base + capacity["ram"]:
                raise ValueError("RAM section exceeds capacity")
            if section["name"].startswith(".stack"):
                stack += size
            elif section["name"] == ".heap":
                heap += size
            else:
                static_ram += size
    flash = flash_end - flash_base
    if not flash:
        raise ValueError("Missing flash load image")
    if flash > capacity["application_flash"] or static_ram + stack + heap > capacity["ram"]:
        raise ValueError("Firmware exceeds target capacity")
    return {"flash": flash, "static_ram": static_ram,
            "reserved_stack": stack, "reserved_heap": heap,
            "flash_percent": 100 * flash / capacity["flash"],
            "static_ram_percent": 100 * static_ram / capacity["ram"]}


def measure_uno(directory, body, flags):
    source = directory / "fixture.cpp"
    source.write_text(SKETCH % body, encoding="utf-8")
    build = directory / "pio"
    normalized = " ".join("-D" + k + "=" + v for k, v in definitions(flags).items())
    # PlatformIO copies --lib recursively, so keep build output out of its input.
    with tempfile.TemporaryDirectory() as temporary:
        library = Path(temporary) / "tiny-crypto-c"
        shutil.copytree(ROOT / "src", library / "src")
        shutil.copy2(ROOT / "library.json", library / "library.json")
        output = run(["pio", "ci", "--lib=" + str(library), "--board=uno", source,
                      "--keep-build-dir", "--build-dir", build,
                      "--project-option=platform=" + PLATFORM,
                      "--project-option=platform_packages=platformio/framework-arduino-avr@5.2.0, platformio/toolchain-atmelavr@1.70300.191015",
                      "--project-option=build_flags=" + normalized])
    for package in ("framework-arduino-avr @ 5.2.0", "toolchain-atmelavr @ 1.70300.191015"):
        if package not in output:
            raise ValueError("Unexpected Uno toolchain: " + package)
    core = Path(os.environ.get("PLATFORMIO_CORE_DIR", Path.home() / ".platformio"))
    objdump = core / "packages/toolchain-atmelavr/bin/avr-objdump"
    return account(sections_from_objdump(run([objdump, "-h", build / ".pio/build/uno/firmware.elf"])), "uno")


def pico_environment():
    sdk = Path(os.environ.get("PICO_SDK_PATH", ""))
    if not (sdk / "pico_sdk_init.cmake").is_file():
        raise ValueError("Set PICO_SDK_PATH to Pico SDK 2.3.1")
    if run(["git", "-C", sdk, "rev-parse", "HEAD"]).strip() != SDK_REVISION:
        raise ValueError("Pico SDK must be pinned to " + SDK_REVISION)
    if run(["git", "-C", sdk, "status", "--porcelain", "--untracked-files=no"]).strip():
        raise ValueError("Pico SDK has modified tracked files")
    toolchain = Path(os.environ.get("PICO_TOOLCHAIN_PATH", ""))
    if (toolchain / "bin/arm-none-eabi-gcc").is_file():
        toolchain = toolchain / "bin"
    compiler = toolchain / "arm-none-eabi-gcc"
    if not compiler.is_file() or run([compiler, "-dumpfullversion"]).strip() != "12.3.1":
        raise ValueError("Set PICO_TOOLCHAIN_PATH to Arm GCC 12.3.Rel1")
    env = dict(os.environ, PICO_SDK_PATH=str(sdk.resolve()),
               PICO_TOOLCHAIN_PATH=str(toolchain.resolve()))
    for variable in ("CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS"):
        env.pop(variable, None)
    return toolchain, env


def measure_pico(directory, body, flags, toolchain, env):
    source = directory / "fixture.c"
    source.write_text(host_source(body), encoding="utf-8")
    # Read the option names from CMake rather than maintaining a second list.
    mapping = {macro: option for option, macro in re.findall(
        r'"(TINY_CRYPTO_\w+);(TC_\w+)"', (ROOT / "CMakeLists.txt").read_text())}
    options = []
    for macro, value in definitions(flags).items():
        if macro == "TC_AES_GCM_GHASH_MODE":
            options.append("-DTINY_CRYPTO_AES_GHASH=" + ["auto", "bitwise", "wide", "fast-table", "hardware"][int(value)])
        else:
            options.append("-D" + mapping[macro] + "=" + ("ON" if value == "1" else "OFF"))
    build = directory / "build"
    run(["cmake", "-S", ROOT / "benchmarks/pico", "-B", build,
         "-DCMAKE_BUILD_TYPE=Release", "-DTC_MEASUREMENT_SOURCE=" + str(source),
         *options], env=env)
    cache = (build / "CMakeCache.txt").read_text()
    expected_flags = ("-mcpu=cortex-m33 -mthumb -march=armv8-m.main+fp+dsp "
                      "-mcmse -mfloat-abi=softfp -ftls-model=local-exec")
    if "CMAKE_C_FLAGS:STRING=" + expected_flags + "\n" not in cache:
        raise ValueError("Unexpected cached compiler flags; use a fresh build directory")
    run(["cmake", "--build", build, "--target", "resource_firmware", "--parallel", "4"], env=env)
    return account(sections_from_objdump(run([toolchain / "arm-none-eabi-objdump", "-h",
                                             build / "resource_firmware.elf"])), "pico2")


def collect(directory, boards):
    directory.mkdir(parents=True, exist_ok=True)
    validate_kmac_vectors(directory)
    if "uno" in boards and run(["pio", "--version"]).strip() != "PlatformIO Core, version 6.1.19":
        raise ValueError("Resource reports require PlatformIO 6.1.19")
    if "pico2" in boards:
        toolchain, env = pico_environment()
    report = {"schema": 1, "boards": {}}
    for board in boards:
        report["boards"][board] = {
            "capacity": CAPACITIES[board],
            "toolchain": ("PlatformIO 6.1.19; atmelavr 5.1.0; Arduino AVR 5.2.0; AVR GCC 7.3.0"
                          if board == "uno" else "Pico SDK 2.3.1; Arm GCC 12.3.Rel1; pico2; rp2350-arm-s"),
            "optimization": "-Os; section GC; " + ("LTO enabled" if board == "uno" else "LTO disabled"),
            "rows": []}
    for index, (name, body, flags) in enumerate(FEATURES):
        validation = directory / "host" / str(index)
        validation.mkdir(parents=True, exist_ok=True)
        validate_host(validation, name, body, flags)
        for board in boards:
            build = directory / board / str(index)
            build.mkdir(parents=True, exist_ok=True)
            print("Measuring " + board + ": " + name, file=sys.stderr)
            metrics = (measure_uno(build, body, flags) if board == "uno" else
                       measure_pico(build, body, flags, toolchain, env))
            report["boards"][board]["rows"].append(
                {"feature": name, "definitions": definitions(flags), **metrics})
    return report


def render(report):
    if report["schema"] != 1 or set(report["boards"]) != set(CAPACITIES):
        raise ValueError("Report must contain Uno and Pico 2 measurements")
    lines = ["<!-- Generated by make benchmark-report. Do not edit by hand. -->",
             "# Embedded resource benchmarks", "",
             "Each row shows the flash and static RAM used by a small program that",
             "calls the named function. The totals include startup code and the test",
             "program, not just the library. Percentages are of the board's total memory.", "",
             "Leave room for the stack and your application: the RAM column counts",
             "static allocations only. Reserved stack and heap sizes come from the",
             "linker; they don't tell you how much memory a running program will use.", "",
             "The Pico 2 builds use one Cortex-M33 core and run code from flash,",
             "without an RTOS or USB/UART output. These are size measurements, not",
             "speed tests.", "",
             "## Updating the numbers", "",
             "Run `make benchmark-report` to rebuild this page, or",
             "`make benchmark-report-check` to check that it's up to date.",
             "Both run the tests on your computer and build for each board.",
             "You don't need either board connected.", "",
             "Install PlatformIO 6.1.19 and Arm GCC 12.3.Rel1. Set",
             "`PICO_SDK_PATH` to an unmodified Pico SDK 2.3.1 checkout and",
             "`PICO_TOOLCHAIN_PATH` to the Arm compiler's `bin` directory.",
             "The script installs the required Uno platform and packages.", ""]
    for board, title in (("uno", "Arduino Uno"), ("pico2", "Raspberry Pi Pico 2")):
        data = report["boards"][board]
        cap = data["capacity"]
        if cap != CAPACITIES[board]:
            raise ValueError("Unexpected board capacity")
        if [row["feature"] for row in data["rows"]] != [case[0] for case in FEATURES]:
            raise ValueError("Missing or reordered measurement profiles")
        lines += ["## " + title, "", data["toolchain"] + ".", "",
                  "Build: " + data["optimization"] + ".", "",
                  f"Physical flash: {cap['flash']:,} bytes. SRAM: {cap['ram']:,} bytes.",
                  f"Application flash limit: {cap['application_flash']:,} bytes.", ""]
        if board == "uno":
            lines += ["The bootloader takes another 512 bytes, not included in the table.", ""]
        lines += ["| Feature | Flash bytes | Flash % | Static RAM bytes | RAM % | Reserved stack / heap bytes |",
                  "| --- | ---: | ---: | ---: | ---: | ---: |"]
        for row in data["rows"]:
            case = next(case for case in FEATURES if case[0] == row["feature"])
            if row["definitions"] != definitions(case[2]):
                raise ValueError("Unexpected feature definitions")
            for field in ("flash", "static_ram", "reserved_stack", "reserved_heap"):
                if type(row[field]) is not int or row[field] < 0:
                    raise ValueError("Invalid measurement: " + field)
            if not row["flash"] or row["flash"] > cap["application_flash"] or sum(row[k] for k in
                    ("static_ram", "reserved_stack", "reserved_heap")) > cap["ram"]:
                raise ValueError("Firmware exceeds capacity")
            fp, rp = 100 * row["flash"] / cap["flash"], 100 * row["static_ram"] / cap["ram"]
            if row["flash_percent"] != fp or row["static_ram_percent"] != rp:
                raise ValueError("Inconsistent resource percentages")
            lines.append(f"| {row['feature']} | {row['flash']:,} | {fp:.2f}% | "
                         f"{row['static_ram']:,} | {rp:.2f}% | "
                         f"{row['reserved_stack']:,} / {row['reserved_heap']:,} |")
        lines += [""]
    lines += ["## Feature definitions", "",
              "These are the build settings for each row. Options not listed use the",
              "library defaults.", ""]
    for row in report["boards"]["uno"]["rows"]:
        lines += ["### " + row["feature"], "", "```text"]
        lines += [k + "=" + v for k, v in sorted(row["definitions"].items())]
        lines += ["```", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build-benchmark-report")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/benchmarks.md")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--input", type=Path, help="Render existing measurement JSON")
    args = parser.parse_args()
    args.build_dir.mkdir(parents=True, exist_ok=True)
    if args.input:
        report = json.loads(args.input.read_text(encoding="utf-8"))
    else:
        report = collect(args.build_dir.resolve(), ["uno", "pico2"])
        (args.build_dir / "resources.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    output = render(report).encode("utf-8")
    if args.check:
        (args.build_dir / "benchmarks.md").write_bytes(output)
        if not args.output.exists() or args.output.read_bytes() != output:
            raise SystemExit("Benchmark document is stale. Run make benchmark-report.")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(output)


if __name__ == "__main__":
    main()
