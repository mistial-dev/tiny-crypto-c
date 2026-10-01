# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check cmake/features.json against the source tree.

The registry is the one list of build features. These checks fail when a
feature macro breaks the option naming rule, a library source has no owner,
a config.h feature macro has no option, a CMake file declares a feature option
outside the registry, a retired option maps to an unknown replacement, or a
document, workflow, script or build file names an option that does not exist.
"""
from collections import Counter
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import feature_registry  # noqa: E402

CONFIG = ROOT / "src" / "tiny_crypto" / "config.h"
CMAKE_FILES = [ROOT / "CMakeLists.txt"] + sorted((ROOT / "cmake").glob("*.cmake"))
# Cache options that are not features: build, test and profile selection.
NON_FEATURE_OPTION = re.compile(
    r"TINY_CRYPTO_(BUILD_\w+|TEST_\w+|SANITIZE|RESOURCE_PROFILE|TARGET)$")
# CMake and Make variables that hold option lists.
INTERNAL_NAMES = {"TINY_CRYPTO_PUBLIC_DEFINITIONS", "TINY_CRYPTO_PUBLIC_MACROS",
                  "TINY_CRYPTO_VARIABLES", "TINY_CRYPTO_CACHE_ARGS"}
# An option name, also directly after -D. A trailing underscore names a family.
OPTION_TOKEN = re.compile(r"(?:(?<=-D)|(?<![A-Za-z0-9_]))(TINY_CRYPTO_[A-Za-z0-9_]*)")
HEADER_GUARD = re.compile(r"_(H|HPP)_?$")
# Files that name invalid options on purpose: the retired-option map, checked by
# test_retired_options_name_their_replacements, and the configure check test.
INVALID_NAME_FILES = {"cmake/features.json", "tests/cmake/option_names.cmake"}
# Option names are read from every tracked file outside the library sources and
# the third-party corpora.
SCANNED_EXCLUDE = re.compile(r"^(src/|tests/vectors/|tests/fuzz/|ports/esp-idf/vendor/)")


def config_defaults():
    """Map each macro with an #ifndef default in config.h to its default text."""
    text = CONFIG.read_text()
    return dict(re.findall(r"^#ifndef (TC_\w+)\n#define \1 (.+)$", text, re.M))


def declared_cache_options():
    names = set()
    for path in CMAKE_FILES:
        text = path.read_text()
        names.update(re.findall(r"\boption\((TINY_CRYPTO_\w+)", text))
        names.update(re.findall(r"\bset\((TINY_CRYPTO_\w+)\s[^)]*?\bCACHE\b", text))
    return names


def tracked_files():
    listing = subprocess.run(["git", "-C", str(ROOT), "ls-files"], capture_output=True,
                             text=True)
    if listing.returncode:
        return [path for path in ROOT.rglob("*") if path.is_file() and ".git" not in path.parts]
    return [ROOT / name for name in listing.stdout.split("\n")
            if name and not SCANNED_EXCLUDE.match(name)]


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = feature_registry.load()
        self.features = self.registry["features"]
        self.options = {feature_registry.option_name(f["macro"]) for f in self.features}
        self.retired = self.registry["retired_options"]

    def test_macros_follow_the_naming_rule(self):
        macros = [feature["macro"] for feature in self.features]
        self.assertEqual([m for m, n in Counter(macros).items() if n > 1], [])
        seen = set()
        for feature in self.features:
            macro = feature["macro"]
            self.assertRegex(macro, r"^TC_[A-Z0-9_]+$")
            self.assertEqual(feature_registry.option_name(macro), "TINY_CRYPTO_" + macro[3:])
            self.assertTrue(feature["description"], macro + " lacks a description")
            parent = feature.get("parent")
            if parent:
                self.assertIn(parent, seen, macro + " must follow its parent " + parent)
            seen.add(macro)
        with self.assertRaises(ValueError):
            feature_registry.option_name("TINY_CRYPTO_ENABLE_AES")

    def test_cmake_declares_feature_options_only_through_the_registry(self):
        for name in sorted(declared_cache_options()):
            self.assertRegex(name, NON_FEATURE_OPTION,
                             name + " is declared outside cmake/features.json")
            self.assertNotIn(name, self.options)

    def test_every_source_has_one_owner(self):
        owned = list(self.registry["core_sources"])
        for feature in self.features:
            owned += feature.get("sources", [])
        for entry in self.registry["shared_sources"]:
            owned += entry["sources"]
            self.assertGreater(len(entry["features"]), 1, "single-feature shared entry")
            for macro in entry["features"]:
                self.assertIn(macro, {f["macro"] for f in self.features})
        repeated = sorted(name for name, count in Counter(owned).items() if count > 1)
        self.assertEqual(repeated, [], "sources with several owners")
        library = sorted("src/" + path.name for path in (ROOT / "src").glob("*.c"))
        self.assertEqual(sorted(set(library) - set(owned)), [], "sources without an owner")
        self.assertEqual(sorted(set(owned) - set(library)), [], "registered sources missing")

    def test_config_feature_macros_have_options(self):
        defaults = config_defaults()
        registered = {feature["macro"] for feature in self.features}
        for macro, default in sorted(defaults.items()):
            if "ENABLE" in macro or default.startswith("TC_PROFILE_VALUE"):
                self.assertIn(macro, registered, "config.h " + macro + " has no option")
        for macro in sorted(registered):
            self.assertIn(macro, defaults, macro + " has no config.h default")

    def test_value_defaults_match_config(self):
        """A value option defaults to the config.h default, or follows the profile."""
        text = CONFIG.read_text()
        defaults = config_defaults()
        for feature in self.features:
            if feature_registry.is_switch(feature):
                continue
            macro = feature["macro"]
            names = [entry["name"] for entry in feature["values"]]
            self.assertIn(feature["default"], names, macro)
            chosen = [e for e in feature["values"] if e["name"] == feature["default"]][0]
            default = defaults[macro]
            if "value" not in chosen:
                self.assertTrue(default.startswith("TC_PROFILE_VALUE"), macro)
                continue
            symbol = re.search(r"^#define %s (\d+)$" % re.escape(default), text, re.M)
            self.assertEqual(int(symbol.group(1)) if symbol else int(default), chosen["value"],
                             macro + " default differs from config.h")

    def test_named_options_exist(self):
        for path in tracked_files():
            if path.resolve() == Path(__file__).resolve() or \
                    path.relative_to(ROOT).as_posix() in INVALID_NAME_FILES:
                continue
            try:
                text = path.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            for name in sorted(set(OPTION_TOKEN.findall(text))):
                if HEADER_GUARD.search(name) or name in INTERNAL_NAMES:
                    continue
                if name.endswith("_"):
                    known = any(option.startswith(name) for option in self.options) or \
                        name == "TINY_CRYPTO_"
                else:
                    known = name in self.options or NON_FEATURE_OPTION.match(name)
                self.assertTrue(known, "%s names unknown option %s"
                                % (path.relative_to(ROOT), name))

    def test_retired_options_name_their_replacements(self):
        for name, replacement in self.retired.items():
            self.assertNotIn(name, self.options, name + " is retired and registered")
            self.assertFalse(NON_FEATURE_OPTION.match(name), name + " is retired and in use")
            if replacement:
                self.assertTrue(replacement in self.options or
                                NON_FEATURE_OPTION.match(replacement),
                                "%s names unknown replacement %s" % (name, replacement))


if __name__ == "__main__":
    unittest.main()
