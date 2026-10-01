# SPDX-License-Identifier: GPL-2.0-or-later
"""Read the feature registry, cmake/features.json.

cmake/Features.cmake declares the CMake options from the same file. The option
for a macro is TINY_CRYPTO_ followed by the macro name without TC_, so tools
map macros to options with option_name() and need no lookup table.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "cmake" / "features.json"


def load():
    return json.loads(REGISTRY.read_text())


def option_name(macro):
    if not macro.startswith("TC_"):
        raise ValueError(macro + " is not a TC_ macro")
    return "TINY_CRYPTO_" + macro[3:]


def features():
    """Map each feature macro to its registry entry, in registry order."""
    return {feature["macro"]: feature for feature in load()["features"]}


def is_switch(feature):
    """An AUTO/ON/OFF feature. A feature with values takes one of their names."""
    return "values" not in feature


def cmake_definition(macro, value):
    """Return the -D argument that selects a resolved macro value."""
    feature = features()[macro]
    if is_switch(feature):
        if value not in ("0", "1"):
            raise ValueError("%s must be 0 or 1, not %s" % (macro, value))
        choice = "ON" if value == "1" else "OFF"
    else:
        names = [entry["name"] for entry in feature["values"]
                 if entry.get("value") is not None and str(entry["value"]) == value]
        if not names:
            raise ValueError("%s has no named value %s" % (macro, value))
        choice = names[0]
    return "-D%s=%s" % (option_name(macro), choice)
