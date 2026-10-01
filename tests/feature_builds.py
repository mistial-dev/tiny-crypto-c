#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build each top-level feature alone with only the dependencies config.h requires.

The features come from cmake/features.json. For each one, every other switch is
turned off, with its sub-features, in reverse registry order while config.h
still accepts the combination. That leaves a minimal set that config.h
requires. The library is then configured with exactly that set and built with
warnings as errors. Its archive must define every library symbol it
references. Value options keep their defaults.

Usage: feature_builds.py --cc CC --nm NM --binary-dir DIR [--feature MACRO ...]
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import feature_registry  # noqa: E402

CONFIG_PROBE = "#include <tiny_crypto/config.h>\n"
# Library symbols. Some object formats prefix C names with an underscore.
LIBRARY_SYMBOL = re.compile(r"^_?(tc_|TC_)")


def switch_macros():
    return [macro for macro, feature in feature_registry.features().items()
            if feature_registry.is_switch(feature)]


def config_accepts(compiler, values):
    """Preprocess config.h under values (macro to 0 or 1)."""
    definitions = ["-D%s=%d" % item for item in sorted(values.items())]
    result = subprocess.run([compiler, "-E", "-x", "c", "-I", str(ROOT / "src"), *definitions,
                             "-o", "/dev/null", "-"], input=CONFIG_PROBE, text=True,
                            capture_output=True)
    return result.returncode == 0


def subtree(features, macro):
    """macro and every switch below it."""
    members = [macro]
    for name, feature in features.items():
        if feature.get("parent") in members and feature_registry.is_switch(feature):
            members.append(name)
    return members


def minimal_selection(compiler, macros, target):
    """Turn off every switch except target that config.h does not require.

    Switching off a feature switches off its sub-features with it, since
    config.h may require a parent and one of its choices together."""
    features = feature_registry.features()
    values = {macro: 1 for macro in macros}
    if not config_accepts(compiler, values):
        raise RuntimeError("config.h rejects every switch on")
    # Dependents follow their dependencies in the registry, so removing from
    # the end drops a dependent before the features it needs.
    for macro in reversed(macros):
        if macro == target or not values[macro]:
            continue
        removed = [name for name in subtree(features, macro) if name != target and values[name]]
        trial = dict(values, **{name: 0 for name in removed})
        if config_accepts(compiler, trial):
            values = trial
    return values


def undefined_library_symbols(nm, archive):
    defined, undefined = set(), set()
    listing = subprocess.run([nm, "-g", str(archive)], capture_output=True, text=True,
                             check=True).stdout
    for line in listing.split("\n"):
        fields = line.split()
        if len(fields) < 2 or not LIBRARY_SYMBOL.match(fields[-1]):
            continue
        (undefined if fields[-2] == "U" else defined).add(fields[-1])
    return sorted(undefined - defined)


def build(arguments, target, values, directory):
    if directory.exists():
        shutil.rmtree(directory)
    options = [feature_registry.cmake_definition(macro, str(value))
               for macro, value in values.items()]
    configure = subprocess.run(
        ["cmake", "-S", str(ROOT), "-B", str(directory), "-DCMAKE_C_COMPILER=" + arguments.cc,
         "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_COMPILE_WARNING_AS_ERROR=ON",
         "-DTINY_CRYPTO_BUILD_TESTS=OFF", "-DTINY_CRYPTO_BUILD_BENCHMARKS=OFF", *options],
        capture_output=True, text=True)
    if configure.returncode:
        return "%s: configure failed\n%s" % (target, configure.stderr)
    compiled = subprocess.run(["cmake", "--build", str(directory), "--target", "tiny-crypto-c",
                               "--parallel", "2"], capture_output=True, text=True)
    if compiled.returncode or "warning:" in compiled.stdout + compiled.stderr:
        return "%s: build failed or warned\n%s%s" % (target, compiled.stdout, compiled.stderr)
    archives = list(directory.glob("**/*tiny-crypto-c.a"))
    if len(archives) != 1:
        return "%s: expected one archive, found %s" % (target, archives)
    missing = undefined_library_symbols(arguments.nm, archives[0])
    if missing:
        return "%s: archive references undefined %s" % (target, ", ".join(missing))
    shutil.rmtree(directory)
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cc", required=True)
    parser.add_argument("--nm", required=True)
    parser.add_argument("--binary-dir", required=True, type=Path)
    parser.add_argument("--feature", action="append", help="limit the run to these macros")
    arguments = parser.parse_args()

    features = feature_registry.features()
    macros = switch_macros()
    targets = arguments.feature or [macro for macro in macros if not features[macro].get("parent")]
    with ThreadPoolExecutor(max_workers=4) as pool:
        selections = list(pool.map(lambda target: minimal_selection(arguments.cc, macros, target),
                                   targets))
    jobs = [(target, values, arguments.binary_dir / target)
            for target, values in zip(targets, selections)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        failures = [failure for failure in
                    pool.map(lambda job: build(arguments, *job), jobs) if failure]
    for target, values in zip(targets, selections):
        enabled = [macro for macro, value in values.items() if value]
        print("%s: %s" % (target, " ".join(enabled)))
    for failure in failures:
        print(failure, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
