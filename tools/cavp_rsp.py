#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared parser for NIST CAVP response files."""


def _lines(text):
    """Yield normalized, non-comment lines and preserve record separators."""
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("#"):
            continue
        yield number, line
    yield len(text.splitlines()) + 1, ""


def records(text, carry=(), is_header=lambda header: True, ignore_preamble=False):
    """Yield ``(section, record)`` pairs for single-header CAVP files.

    ``carry`` names fields that persist into later records in the same
    section. Bracketed annotations rejected by ``is_header`` are ignored.
    """
    section = ""
    context = {}
    record = {}
    for number, line in _lines(text):
        if line.startswith("[") and line.endswith("]"):
            header = line[1:-1].strip()
            if not is_header(header):
                continue
            if record:
                yield section, {**context, **record}
                record = {}
            section = header
            context = {}
            continue
        if not line:
            if record:
                yield section, {**context, **record}
                context.update({key: value for key, value in record.items() if key in carry})
                record = {}
            continue
        if "=" not in line:
            if ignore_preamble and not section and not record:
                continue
            raise ValueError(f"line {number}: expected NAME = VALUE")
        key, value = (part.strip() for part in line.split("=", 1))
        if not key:
            raise ValueError(f"line {number}: empty field name")
        record[key] = value


def header_records(text, reset_header="PRF"):
    """Yield records with an accumulated dictionary of bracket headers.

    A header named ``reset_header`` starts a new section. Other bracket
    headers refine that section. ``COUNT`` starts a record even when the CAVP
    file omits blank separators between records.
    """
    section = {}
    record = {}
    for number, line in _lines(text):
        if line.startswith("[") and line.endswith("]"):
            if record:
                yield dict(section), record
                record = {}
            body = line[1:-1]
            if "=" not in body:
                raise ValueError(f"line {number}: malformed header")
            key, value = (part.strip() for part in body.split("=", 1))
            if not key:
                raise ValueError(f"line {number}: empty header name")
            if key == reset_header:
                section = {key: value}
            else:
                section[key] = value
            continue
        if not line:
            if record:
                yield dict(section), record
                record = {}
            continue
        if "=" not in line:
            raise ValueError(f"line {number}: expected NAME = VALUE")
        key, value = (part.strip() for part in line.split("=", 1))
        if not key:
            raise ValueError(f"line {number}: empty field name")
        if key == "COUNT" and record:
            yield dict(section), record
            record = {}
        record[key] = int(value) if key == "COUNT" else value
