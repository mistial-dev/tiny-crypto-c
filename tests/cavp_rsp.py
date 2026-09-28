# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared reader for NIST CAVP response files, used by the Python adapters.

It follows the same line rules as tests/support/cavp.c. Lines starting with
'#' are comments, a bracketed line is a header, NAME = VALUE lines are fields,
and a blank line or the end of the text closes a record.
"""


def records(text, carry=(), is_header=lambda header: True):
    """Yield (section, record) pairs.

    section is the text of the most recent header, without brackets. record
    maps field names to values. Keys named in carry persist into the
    following records of the same section, as RSA n, e and d do. is_header
    filters bracketed lines that are annotations rather than headers.
    """
    section = ""
    context = {}
    record = {}
    for raw in text.splitlines() + [""]:
        line = raw.strip()
        if line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]") and is_header(line[1:-1]):
            if record:
                yield section, {**context, **record}
                record = {}
            section = line[1:-1].strip()
            context = {}
            continue
        if not line:
            if record:
                yield section, {**context, **record}
                context.update({key: value for key, value in record.items() if key in carry})
                record = {}
            continue
        if "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            record[key] = value
