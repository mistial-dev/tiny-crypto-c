# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check README.md, docs/*.md and the public headers against the source tree.

The checks catch documentation that names removed identifiers, links to
missing files or headings, calls functions with the wrong argument count,
initializes public structures with the wrong fields, or misstates the CMake
options. Public headers must open with a module block that links docs/api.md,
and no public function may take more than eight parameters.

TC_DOC_SYNC_CC and TC_DOC_SYNC_CXX name GCC-compatible compilers. When set,
every self-contained code block, one that includes a tiny_crypto header, is
compiled with -fsyntax-only and warnings as errors against the desktop profile.
"""
import os
import re
from pathlib import Path
import subprocess
import tempfile
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
ANCHOR_LINK = re.compile(r"\]\(([^)#\s]*)#([^)\s]+)\)")
HEADERS = sorted((ROOT / "src" / "tiny_crypto").glob("*.h")) + sorted(
    (ROOT / "src" / "tiny_crypto").glob("*.hpp"))
# Prose wraps at this column. Link targets do not count, since they cannot be
# wrapped. Tables, code blocks, badges and a line holding one code span are
# exempt.
MAX_PROSE_COLUMNS = 100
# Definitions for compiling code blocks: the desktop profile plus the options
# it leaves off.
SNIPPET_DEFINITIONS = ("-DTC_RESOURCE_PROFILE=3", "-DTC_DES_ENABLE_ISO9797=1")
# Code blocks meet the library's own warning flags.
SNIPPET_WARNINGS = ("-Wall", "-Wextra", "-Wpedantic", "-Werror")


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


def slug(heading):
    """Return the GitHub anchor for a Markdown heading."""
    text = re.sub(r"[`*_]", "", heading.strip().lower())
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(document):
    """Return the heading anchors of a Markdown document."""
    names = set()
    in_code = False
    for line in document.read_text().split("\n"):
        if line.startswith("```"):
            in_code = not in_code
        elif not in_code and line.startswith("#"):
            names.add(slug(line.lstrip("#")))
    return names


def prose_lines(document):
    """Yield (line number, text) for lines outside code blocks and tables."""
    in_code = False
    for number, line in enumerate(document.read_text().split("\n"), 1):
        if line.startswith("```"):
            in_code = not in_code
            continue
        if not in_code and not line.startswith("|"):
            yield number, line


def split_arguments(text):
    """Split a call's argument text at its top-level commas."""
    arguments = []
    depth = 0
    current = ""
    for character in text:
        if character in "{([":
            depth += 1
        elif character in "})]":
            depth -= 1
        if character == "," and depth == 0:
            arguments.append(current.strip())
            current = ""
        else:
            current += character
    if current.strip():
        arguments.append(current.strip())
    return arguments


def closing_paren(text, start):
    """Return the index of the parenthesis closing the one before start."""
    depth = 1
    index = start
    while depth and index < len(text):
        depth += {"(": 1, ")": -1}.get(text[index], 0)
        index += 1
    return index - 1 if depth == 0 else None


def public_arities(macros=True):
    """Map each public function, and optionally each function-like macro, to
    its parameter counts."""
    arities = {}
    for header in HEADERS:
        raw = re.sub(r"/\*.*?\*/", " ", header.read_text(), flags=re.S)
        raw = re.sub(r"//[^\n]*", "", raw)
        for match in re.finditer(r"#define\s+(TC_\w+)\(([^)]*)\)", raw) if macros else ():
            count = len([p for p in match.group(2).split(",") if p.strip()])
            arities.setdefault(match.group(1), set()).add(count)
        code = strip_c_comments(raw)
        for match in re.finditer(r"[\w\*]\s+\**(TC_\w+)\s*\(", code):
            end = closing_paren(code, match.end())
            if end is None or not re.match(r"\s*[;{]", code[end + 1:]):
                continue
            parameters = split_arguments(code[match.end():end])
            count = 0 if parameters in ([], ["void"]) else len(parameters)
            arities.setdefault(match.group(1), set()).add(count)
    return arities


def cmake_sources():
    return (ROOT / "CMakeLists.txt").read_text() + "".join(
        path.read_text() for path in sorted((ROOT / "cmake").glob("*.cmake")))


def profile_options():
    """Map each profile-driven option to (macro, default, micro, mini, desktop)."""
    config = (ROOT / "src" / "tiny_crypto" / "config.h").read_text()
    values = {m.group(1): tuple("ON" if v == "1" else "OFF" for v in m.groups()[1:])
              for m in re.finditer(r"#define (TC_\w+) TC_PROFILE_VALUE\((\d+), (\d+), (\d+), (\d+)\)",
                                   config)}
    options = {}
    for match in re.finditer(r"tc_(profile_option|module_feature)\((\w+)\s+(\w+)", cmake_sources()):
        options[match.group(2)] = values[match.group(3)]
    return options


def readme_option_rows():
    """Map each option in a README table to its cells after the name."""
    rows = {}
    for line in (ROOT / "README.md").read_text().split("\n"):
        match = re.match(r"\|\s*`(TINY_CRYPTO_\w+)`\s*\|(.*)\|\s*$", line)
        if match:
            rows[match.group(1)] = [cell.strip() for cell in match.group(2).split("|")]
    return rows


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

    def test_heading_anchors_resolve(self):
        for document in DOCUMENTS:
            for target, anchor in ANCHOR_LINK.findall(document.read_text()):
                if re.match(r"[a-z]+:", target) or not (target or document.suffix == ".md"):
                    continue
                path = (document.parent / target).resolve() if target else document
                if path.suffix != ".md":
                    continue
                self.assertIn(anchor, anchors(path),
                              "%s links missing heading %s#%s" % (document.name, target, anchor))

    def test_documents_carry_spdx_headers(self):
        for document in DOCUMENTS:
            head = document.read_text().split("\n")[:5]
            self.assertTrue(head[0].startswith("<!-- SPDX-FileCopyrightText:"),
                            document.name + " lacks an SPDX copyright line")
            self.assertTrue(any("SPDX-License-Identifier:" in line for line in head),
                            document.name + " lacks an SPDX license line")

    def test_prose_is_wrapped(self):
        for document in DOCUMENTS:
            for number, line in prose_lines(document):
                single_span = line.startswith("`") and line.endswith("`") and line.count("`") == 2
                badge = line.startswith("[![")
                visible = re.sub(r"\]\([^)\s]*\)", "]()", line)
                self.assertFalse(len(visible) > MAX_PROSE_COLUMNS and not (single_span or badge),
                                 "%s:%d exceeds %d columns" % (document.name, number,
                                                               MAX_PROSE_COLUMNS))

    def test_calls_match_header_arity(self):
        arities = public_arities()
        for document in DOCUMENTS:
            text = document.read_text()
            for block in CODE_BLOCK.finditer(text):
                code = strip_c_comments(block.group(1))
                for match in re.finditer(r"\b(TC_\w+)\s*\(", code):
                    if match.group(1) not in arities:
                        continue
                    end = closing_paren(code, match.end())
                    self.assertIsNotNone(end, document.name + " has an unclosed call")
                    count = len(split_arguments(code[match.end():end]))
                    line = text[:block.start()].count("\n") + code[:match.start()].count("\n") + 2
                    self.assertIn(count, arities[match.group(1)],
                                  "%s:%d calls %s with %d arguments" % (document.name, line,
                                                                        match.group(1), count))

    def test_public_functions_take_at_most_eight_parameters(self):
        """docs/api.md: calls with more inputs take a request structure."""
        for name, counts in sorted(public_arities(macros=False).items()):
            self.assertLessEqual(max(counts), 8, name + " takes more than eight parameters")

    def test_headers_open_with_module_block(self):
        """Each public header opens with a block that links the API contracts."""
        for header in HEADERS:
            text = header.read_text()
            first_declaration = re.search(
                r"^(typedef|struct|enum|namespace|class|extern|TC_\w+ |void |size_t |uint)", text,
                re.M)
            comments = re.findall(r"/\*.*?\*/", text[:first_declaration.start()] if
                                  first_declaration else text, re.S)
            blocks = [c for c in comments if "SPDX-License-Identifier" not in c or "docs/" in c]
            self.assertTrue(blocks and "docs/api.md" in blocks[0],
                            header.name + " lacks a module block linking docs/api.md")
            for guide in re.findall(r"docs/[\w.-]+\.md", text):
                self.assertTrue((ROOT / guide).exists(), header.name + " names missing " + guide)

    def test_readme_lists_every_option(self):
        rows = readme_option_rows()
        profiles = profile_options()
        for name, values in sorted(profiles.items()):
            self.assertIn(name, rows, "README.md lacks option " + name)
            self.assertEqual(tuple(rows[name][:4]), values,
                             "README.md %s defaults must be default, micro, mini, desktop %s"
                             % (name, "/".join(values)))
        documented = (ROOT / "README.md").read_text() + (ROOT / "docs" / "testing.md").read_text()
        sources = cmake_sources()
        declared = re.findall(r"(?:option|tc_taf_choice_option)\((TINY_CRYPTO_\w+)", sources)
        declared += re.findall(r"set\((TINY_CRYPTO_\w+)\s[^)]*?\bCACHE\b", sources)
        for name in sorted(set(declared)):
            self.assertTrue("`" + name in documented, "README.md and docs/testing.md lack " + name)

    def test_code_blocks_compile(self):
        compilers = {"c": os.environ.get("TC_DOC_SYNC_CC"), "cpp": os.environ.get("TC_DOC_SYNC_CXX")}
        if not any(compilers.values()):
            self.skipTest("TC_DOC_SYNC_CC and TC_DOC_SYNC_CXX are unset")
        pattern = re.compile(r"```(c|cpp)\n(.*?)```", re.S)
        with tempfile.TemporaryDirectory() as directory:
            for document in DOCUMENTS:
                text = document.read_text()
                for index, block in enumerate(pattern.finditer(text)):
                    language, code = block.groups()
                    compiler = compilers[language]
                    if not compiler or "#include <tiny_crypto/" not in code:
                        continue
                    source = Path(directory) / ("%s_%d.%s" % (document.stem, index, language))
                    source.write_text(code)
                    standard = "-std=c99" if language == "c" else "-std=c++11"
                    result = subprocess.run(
                        [compiler, "-fsyntax-only", standard, *SNIPPET_WARNINGS, *SNIPPET_DEFINITIONS,
                         "-I" + str(ROOT / "src"), "-I" + str(ROOT / "examples"), str(source)],
                        capture_output=True, text=True)
                    line = text[:block.start()].count("\n") + 1
                    self.assertEqual(result.returncode, 0, "%s:%d does not compile:\n%s"
                                     % (document.name, line, result.stderr))


if __name__ == "__main__":
    unittest.main()
