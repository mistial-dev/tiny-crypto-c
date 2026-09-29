# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check README.md and docs/*.md against the source tree.

The checks catch documentation that names removed identifiers, links to
missing files, or initializes public structures with the wrong fields.
"""
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = [ROOT / "README.md"] + sorted((ROOT / "docs").glob("*.md"))
# Documented identifiers must appear in one of these trees. tests and tools
# hold the environment variables and generators that docs/testing.md names.
DEFINITION_TREES = ("src", "examples", "cmake", "tests", "tools", "CMakeLists.txt")
IDENTIFIER = re.compile(r"\b(?:TC_|TINY_CRYPTO_|example_)\w+")
CODE_BLOCK = re.compile(r"```(?:c|cpp|c\+\+)\n(.*?)```", re.S)
STRUCT_INIT = re.compile(r"(?:const\s+)?(TC_\w+)\s+(\w+)(\[\w*\])?\s*=\s*\{")
LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")


def strip_c_comments(text):
    """Remove comments and preprocessor lines from C source text."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("#"))


def matching_brace(text, start):
    """Return the index just past the brace that closes the one before start."""
    depth = 1
    index = start
    while depth:
        depth += {"{": 1, "}": -1}.get(text[index], 0)
        index += 1
    return index


def top_level(text):
    """Return text with nested brace contents removed."""
    output = []
    depth = 0
    for character in text:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
        elif depth == 0:
            output.append(character)
    return "".join(output)


def member_names(body):
    """Return the direct member names of a struct body, in order."""
    names = []
    for declaration in top_level(body).split(";"):
        function_pointer = re.search(r"\(\s*\*\s*(\w+)\s*\)", declaration)
        if function_pointer:
            names.append(function_pointer.group(1))
            continue
        declaration = re.sub(r"\[[^\]]*\]", "", declaration)
        for declarator in declaration.split(","):
            words = re.findall(r"\w+", declarator)
            if words:
                names.append(words[-1])
    return names


def public_structs():
    """Map each typedef struct name in the public headers to its members."""
    structs = {}
    for header in (ROOT / "src").rglob("*.h"):
        text = strip_c_comments(header.read_text())
        for match in re.finditer(r"typedef\s+struct\s*\w*\s*\{", text):
            end = matching_brace(text, match.end())
            name = re.match(r"\s*(\w+)\s*;", text[end:])
            if name:
                structs[name.group(1)] = member_names(text[match.end():end - 1])
    return structs


def initializer_items(body):
    """Split an initializer list at its top-level commas."""
    items = []
    depth = 0
    current = ""
    for character in strip_c_comments(body):
        if character in "{([":
            depth += 1
        elif character in "})]":
            depth -= 1
        if character == "," and depth == 0:
            items.append(current.strip())
            current = ""
        else:
            current += character
    items.append(current.strip())
    return [item for item in items if item]


def defined_identifiers():
    names = set()
    for tree in DEFINITION_TREES:
        path = ROOT / tree
        files = [path] if path.is_file() else [f for f in path.rglob("*") if f.is_file()]
        for source in files:
            # This checker's own text defines nothing.
            if source.resolve() == Path(__file__).resolve():
                continue
            try:
                names.update(IDENTIFIER.findall(source.read_text()))
            except (UnicodeDecodeError, OSError):
                pass
    return names


class DocumentationTests(unittest.TestCase):
    def test_named_identifiers_exist(self):
        defined = defined_identifiers()
        for document in DOCUMENTS:
            for name in sorted(set(IDENTIFIER.findall(document.read_text()))):
                # A trailing underscore names a family, such as TC_RSA_.
                if name.endswith("_"):
                    found = any(known.startswith(name) for known in defined)
                else:
                    found = name in defined
                self.assertTrue(found, document.name + " names missing " + name)

    def test_relative_links_resolve(self):
        for document in DOCUMENTS:
            for target in LINK.findall(document.read_text()):
                if re.match(r"[a-z]+:", target):
                    continue
                path = (document.parent / target).resolve()
                self.assertTrue(path.exists(), document.name + " links missing " + target)

    def test_struct_initializers_match_headers(self):
        """Positional initializers set every member. Designated ones name real members."""
        structs = public_structs()
        for document in DOCUMENTS:
            text = document.read_text()
            for block in CODE_BLOCK.finditer(text):
                code = block.group(1)
                for match in STRUCT_INIT.finditer(code):
                    type_name, variable, array = match.groups()
                    fields = structs.get(type_name)
                    if array or fields is None:
                        continue
                    end = matching_brace(code, match.end())
                    items = initializer_items(code[match.end():end - 1])
                    line = text[:block.start()].count("\n") + code[:match.start()].count("\n") + 2
                    where = "%s:%d %s %s" % (document.name, line, type_name, variable)
                    if items == ["0"]:
                        continue
                    designated = [item for item in items if item.startswith(".")]
                    if designated:
                        self.assertEqual(len(designated), len(items), where + " mixes styles")
                        for item in designated:
                            field = re.match(r"\.(\w+)", item).group(1)
                            self.assertIn(field, fields, where + " has no member " + field)
                    else:
                        self.assertEqual(len(items), len(fields),
                                         where + " must initialize " + ", ".join(fields))


if __name__ == "__main__":
    unittest.main()
