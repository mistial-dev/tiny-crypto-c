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

from benchmark_cases import FEATURES, RP2350_FEATURES, SKETCH, definitions, features_for_board

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
    if definitions(flags).get("TC_ENABLE_PIV_SM") == "1":
        command += ["-I" + str(ROOT / "examples"), ROOT / "examples/piv_sm_wire.c"]
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
         "-I" + str(ROOT / "tests/support"), ROOT / "tests/support/munit.c",
         ROOT / "tests/support/test_util.c",
         ROOT / "tests/support/cavp.c",
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
    normalized = " ".join("-D" + k + "=" + v for k, v in definitions(flags).items())
    # pio ci keeps old configuration and library copies in a reused project.
    with tempfile.TemporaryDirectory(dir=directory, prefix="pio-") as project, tempfile.TemporaryDirectory() as temporary:
        build = Path(project)
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
    report = {"schema": 5, "boards": {}}
    for board in boards:
        report["boards"][board] = {
            "capacity": CAPACITIES[board],
            "toolchain": ("PlatformIO 6.1.19; atmelavr 5.1.0; Arduino AVR 5.2.0; AVR GCC 7.3.0"
                          if board == "uno" else "Pico SDK 2.3.1; Arm GCC 12.3.Rel1; pico2; rp2350-arm-s"),
            "optimization": "-Os; section GC; " + ("LTO enabled" if board == "uno" else "LTO disabled"),
            "rows": []}
        if board == "uno":
            core = Path(os.environ.get("PLATFORMIO_CORE_DIR", Path.home() / ".platformio"))
            compiler = core / "packages/toolchain-atmelavr/bin/avr-gcc"
            nm = compiler.with_name("avr-nm")
            flags = ["-mmcu=atmega328p"]
        else:
            compiler = toolchain / "arm-none-eabi-gcc"
            nm = toolchain / "arm-none-eabi-nm"
            flags = ["-mcpu=cortex-m33", "-mthumb"]
        report["boards"][board]["tlv"] = tlv_storage(directory / board / "layout", compiler, nm, flags)
        report["boards"][board]["pki"] = pki_storage(directory / board / "pki-layout", compiler, nm, flags)
    cases = FEATURES + (RP2350_FEATURES if "pico2" in boards else [])
    for index, (name, body, flags) in enumerate(cases):
        validation = directory / "host" / str(index)
        validation.mkdir(parents=True, exist_ok=True)
        validate_host(validation, name, body, flags)
    for index, (name, body, flags) in enumerate(cases):
        for board in boards:
            if (name, body, flags) not in features_for_board(board):
                continue
            build = directory / board / str(index)
            build.mkdir(parents=True, exist_ok=True)
            print("Measuring " + board + ": " + name, file=sys.stderr)
            metrics = (measure_uno(build, body, flags) if board == "uno" else
                       measure_pico(build, body, flags, toolchain, env))
            report["boards"][board]["rows"].append(
                {"feature": name, "definitions": definitions(flags), **metrics})
    return report


def tlv_storage(directory, compiler, nm, flags):
    return parser_storage(directory, compiler, nm, flags,
        (("reader", "TC_TLV_reader"), ("stream", "TC_TLV_stream"),
         ("frame", "TC_TLV_frame"), ("element", "TC_TLV_element")),
        ("tlv", "tlv_walk", "der"))


def pki_storage(directory, compiler, nm, flags):
    return parser_storage(directory, compiler, nm, flags,
        (("certificate", "TC_X509_certificate"), ("public_key", "TC_X509_public_key"),
         ("chuid", "TC_PIV_CHUID"), ("cvc", "TC_PIV_CVC"), ("extension_slot", "TC_bytes"),
         ("eac_certificate", "TC_EAC_CVC"), ("eac_key", "TC_EAC_CVC_public_key"),
         ("path_workspace", "TC_X509_path_workspace"),
         ("policy_node", "TC_X509_policy_node"), ("policy_edge", "TC_X509_policy_edge"),
         ("policy_expected", "TC_X509_policy_expected"),
         ("policy_mapping", "TC_X509_policy_mapping")),
        ("x509", "x509_time", "x509_key", "x509_ext", "x509_name", "x509_path", "x509_policy",
         "asn1_string", "unicode", "piv_chuid", "piv_cvc", "eac_cvc", "der"))


def stack_frame_size(line):
    function, size, kind = line.rsplit("\t", 2)
    # GCC's bounded qualifier makes the reported size a reliable maximum.
    if kind not in ("static", "dynamic,bounded"):
        raise ValueError(f"Unbounded or unknown stack frame: {function} ({kind})")
    if not size.isdecimal():
        raise ValueError(f"Invalid stack frame size: {function} ({size})")
    return int(size)


def parser_storage(directory, compiler, nm, flags, types, sources):
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / "layout.c"
    source.write_text('#include <tiny_crypto/tiny_crypto.h>\n' + "".join(
        f"unsigned char tc_size_{name}[sizeof({kind})];\n" for name, kind in
        types), encoding="utf-8")
    command = [compiler, *flags, "-std=c99", "-Os", "-fno-common", "-I" + str(ROOT / "src"),
               "-DTC_ENABLE_TLV=1", "-DTC_ENABLE_DER=1", "-DTC_TLV_ENABLE_BER=1",
               "-DTC_TLV_ENABLE_STREAM=1", "-DTC_ENABLE_X509=1",
               "-DTC_ENABLE_X509_PATH=1",
               "-DTC_ENABLE_PIV_CVC=1", "-DTC_ENABLE_PIV_CHUID=1", "-DTC_ENABLE_EAC_CVC=1"]
    run([*command, "-c", source, "-o", directory / "layout.o"])
    symbols = run([nm, "-S", directory / "layout.o"])
    sizes = {name: int(size, 16) for size, name in re.findall(
        r"[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+\w\s+tc_size_(\w+)", symbols)}
    if set(sizes) != {name for name, _ in types}:
        raise ValueError("Missing parser layout symbols")
    stack = []
    for name in sources:
        run([*command, "-fstack-usage", "-c", ROOT / f"src/{name}.c",
             "-o", directory / f"{name}.o"])
        for line in (directory / f"{name}.su").read_text().splitlines():
            stack.append(stack_frame_size(line))
    sizes["largest_stack_frame"] = max(stack)
    return sizes


def render(report):
    if report["schema"] != 5 or set(report["boards"]) != set(CAPACITIES):
        raise ValueError("Report must contain Uno and Pico 2 measurements")
    lines = ["<!-- SPDX-FileCopyrightText: Mistial Dev -->",
             "<!-- SPDX-License-Identifier: GPL-2.0-or-later -->", "",
             "<!-- Generated by make benchmark-report. Do not edit by hand. -->",
             "# Embedded resource benchmarks", "",
             "Each row shows the flash and static RAM used by a small program that",
             "calls the named function. Totals include the library, startup code and",
             "test program. Percentages use the board's physical memory capacity.", "",
             "Leave room for the stack and your application: the RAM column counts",
             "static allocations only. Reserved stack and heap sizes come from the",
             "linker. Measure peak runtime use in your application.", "",
             "The Pico 2 builds use one Cortex-M33 core and run code from flash,",
             "with the RTOS and USB/UART output disabled. The report measures memory",
             "use; run host throughput tests with `make benchmark`.", "",
             "## Updating the numbers", "",
             "Run `make benchmark-report` to rebuild this page, or",
             "`make benchmark-report-check` to check that it's up to date.",
             "Both validate fixtures on the host and cross-compile for each board.",
             "Boards can remain disconnected.", "",
             "Install PlatformIO 6.1.19 and Arm GCC 12.3.Rel1. Set",
             "`PICO_SDK_PATH` to an unmodified Pico SDK 2.3.1 checkout and",
             "`PICO_TOOLCHAIN_PATH` to the Arm compiler's `bin` directory.",
             "The script installs the required Uno platform and packages.", ""]
    for board, title in (("uno", "Arduino Uno"), ("pico2", "Raspberry Pi Pico 2")):
        data = report["boards"][board]
        cap = data["capacity"]
        if cap != CAPACITIES[board]:
            raise ValueError("Unexpected board capacity")
        if [row["feature"] for row in data["rows"]] != [case[0] for case in features_for_board(board)]:
            raise ValueError("Missing or reordered measurement profiles")
        lines += ["## " + title, "", data["toolchain"] + ".", "",
                  "Build: " + data["optimization"] + ".", "",
                  f"Physical flash: {cap['flash']:,} bytes. SRAM: {cap['ram']:,} bytes.",
                  f"Application flash limit: {cap['application_flash']:,} bytes.", ""]
        if board == "uno":
            lines += ["The bootloader takes another 512 bytes, not included in the table.", ""]
        storage = data["tlv"]
        for field in ("reader", "stream", "frame", "element", "largest_stack_frame"):
            if type(storage[field]) is not int or storage[field] <= 0:
                raise ValueError("Invalid TLV storage measurement")
        lines += [f"TLV object sizes: reader {storage['reader']}, stream {storage['stream']},",
                  f"element {storage['element']}, and nesting frame {storage['frame']} bytes.",
                  "Frame storage is caller-owned; multiply its size by the allowed depth.",
                  f"The largest compiler-reported TLV/DER stack frame is {storage['largest_stack_frame']} bytes",
                  "at `-Os` without LTO. Called functions and callbacks need additional stack.", ""]
        pki = data["pki"]
        for field in ("certificate", "public_key", "chuid", "cvc", "extension_slot", "eac_certificate", "eac_key",
                      "path_workspace", "policy_node", "policy_edge", "policy_expected", "policy_mapping",
                      "largest_stack_frame"):
            if type(pki[field]) is not int or pki[field] <= 0:
                raise ValueError("Invalid PKI storage measurement")
        lines += [f"Parsed object sizes: X.509 certificate {pki['certificate']}, public key {pki['public_key']},",
                  f"CHUID {pki['chuid']}, and CVC {pki['cvc']} bytes.",
                  f"EAC certificate and public-key objects use {pki['eac_certificate']} and {pki['eac_key']} bytes.",
                  f"X.509 needs another {pki['extension_slot']} bytes of scratch space per extension,",
                  "plus the nesting frames above. Input buffers must remain available while",
                  "using the parsed fields.",
                  f"The path workspace descriptor uses {pki['path_workspace']} bytes, excluding its arrays.",
                  f"Policy array entries use {pki['policy_node']} bytes per node, {pki['policy_edge']} per edge,",
                  f"{pki['policy_expected']} per expected policy, and {pki['policy_mapping']} per mapping.",
                  "Name comparison also needs two caller-sized Unicode scalar arrays (4 bytes per scalar)",
                  "and an attribute-match array (1 byte per entry). See [path validation](x509-path.md)",
                  "for workspace setup and buffer lifetimes.",
                  f"The largest compiler-reported PKI stack frame is {pki['largest_stack_frame']} bytes",
                  "at `-Os` without LTO. This includes name and path processing, but excludes",
                  "called functions and the application's signature verifier. Object and frame sizes",
                  "alone do not establish that a complete validation fits on the board.", ""]
        lines += ["| Feature | Flash bytes | Flash % | Static RAM bytes | RAM % | Reserved stack / heap bytes |",
                  "| --- | ---: | ---: | ---: | ---: | ---: |"]
        for row in data["rows"]:
            case = next(case for case in features_for_board(board) if case[0] == row["feature"])
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
