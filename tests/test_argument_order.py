# SPDX-License-Identifier: GPL-2.0-or-later
"""Reject calls whose arguments write and read the same local.

C leaves the evaluation order of function arguments unspecified (C99
6.5.2.2p10). A call such as f(g(&x), x) reads x before or after g writes it,
depending on the compiler and target: GCC on x86-64 reads it first. The
library had two such bugs, in the RSA work helpers and the X.509 path
phases, and neither compiler warns. Sequence the inner call in its own
statement first."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
IDENTIFIER = re.compile(r"[A-Za-z_]\w*")


def strip_comments_and_strings(text):
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', text)


def top_level_arguments(text, open_index):
    """Split the argument list that starts after text[open_index] == '('."""
    depth, start, arguments = 0, open_index + 1, []
    for index in range(open_index + 1, len(text)):
        char = text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                arguments.append(text[start:index])
                return arguments, index
            depth -= 1
        elif char == "," and depth == 0:
            arguments.append(text[start:index])
            start = index + 1
    return None, len(text)


def conflicts(text):
    """Yield (line, callee, variable) for calls that write &v in one argument
    through a nested call and read plain v as another argument."""
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text):
        if match.group(1) in ("if", "while", "for", "switch", "return", "sizeof"):
            continue
        arguments, _ = top_level_arguments(text, match.end() - 1)
        if not arguments or len(arguments) < 2:
            continue
        for i, argument in enumerate(arguments):
            if "(" not in argument:
                continue
            # Out-parameters written by a nested call: &name not followed by
            # a member, index or call, so &s.field or F(&s, 1) views are ignored.
            for written in re.findall(r"&\s*([A-Za-z_]\w*)\b(?!\s*(?:\.|->|\[|\())", argument):
                for j, other in enumerate(arguments):
                    if j != i and other.strip() == written:
                        line = text.count("\n", 0, match.start()) + 1
                        yield line, match.group(1), written


class ArgumentOrderTests(unittest.TestCase):
    def test_detector_finds_the_known_shapes(self):
        samples = [
            "x = tc_rsa_work_value(tc_rsa_oaep_cost(n, h, &cost), cost);",
            "s = path_pass_status(tc_x509_path_names(&v->input, w, &accepted), accepted);",
        ]
        for sample in samples:
            self.assertTrue(list(conflicts(sample)), sample)
        clean = [
            "r = tc_rsa_oaep_cost(n, h, &cost); x = tc_rsa_work_value(r, cost);",
            "tc_mp_reduce(F(&s, 0), F(&s, 0), s.words);",
            "f(g(&s.field), s.field);",
        ]
        for sample in clean:
            self.assertFalse(list(conflicts(sample)), sample)

    def test_library_sources(self):
        found = []
        for path in sorted((ROOT / "src").glob("*.[ch]")) + sorted((ROOT / "src/tiny_crypto").glob("*.h*")):
            text = strip_comments_and_strings(path.read_text(encoding="utf-8", errors="replace"))
            for line, callee, variable in conflicts(text):
                found.append(f"{path.relative_to(ROOT)}:{line}: {callee}(... &{variable} ..., {variable})")
        self.assertEqual(found, [], "\n" + "\n".join(found))


if __name__ == "__main__":
    unittest.main()
