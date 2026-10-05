#!/usr/bin/env python3
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the null-guard wrapper header for the C tests.

Every public TC_ function becomes a static inline wrapper and an object-like
macro of the same name, so calls and function pointers both reach it. Before the real call, the wrapper repeats it once per
pointer argument with that argument NULL, and once per span argument with
NULL data and the caller's nonzero length. The other arguments are the
caller's real values, so the library reaches the code after its argument
checks, where AddressSanitizer and UndefinedBehaviorSanitizer report a
missing guard. Writable arguments are restored after each repeated call.

The declarations come from Clang's JSON AST of every public C header with
every feature on. Each wrapper keeps the preprocessor condition of its
declaration, so one header serves every test configuration.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEADERS = ROOT / "src" / "tiny_crypto"
FEATURES = ROOT / "cmake" / "features.json"
RESULT_TYPE = "TC_result"
SIZE_TYPES = {"size_t", "uint64_t", "uint32_t", "uint16_t", "unsigned int", "unsigned long",
              "unsigned long long"}


def public_headers():
    return sorted(path for path in HEADERS.glob("*.h"))


def feature_definitions():
    registry = json.loads(FEATURES.read_text())
    return [f"-D{f['macro']}=1" for f in registry["features"] if "values" not in f]


def clang_ast(clang):
    source = "".join(f"#include <tiny_crypto/{path.name}>\n" for path in public_headers())
    command = [clang, "-x", "c", "-std=c99", "-fsyntax-only", "-Xclang", "-ast-dump=json",
               f"-I{ROOT / 'src'}", *feature_definitions(), "-"]
    result = subprocess.run(command, input=source, capture_output=True, text=True, check=False)
    if result.returncode:
        sys.exit(f"clang failed:\n{result.stderr}")
    return json.loads(result.stdout)


class Types:
    """Typedef and record tables from the AST."""

    def __init__(self, ast):
        self.typedefs = {}
        self.records = {}
        for node in ast.get("inner", []):
            if node.get("kind") == "TypedefDecl":
                self.typedefs[node["name"]] = node["type"]["qualType"]
            elif node.get("kind") == "RecordDecl" and node.get("completeDefinition"):
                fields = [(f["name"], f["type"]["qualType"]) for f in node.get("inner", [])
                          if f.get("kind") == "FieldDecl"]
                self.records[node["id"]] = fields
                if node.get("name"):
                    self.records["struct " + node["name"]] = fields
        for node in ast.get("inner", []):
            if node.get("kind") == "TypedefDecl":
                record = self._record_id(node)
                if record in self.records:
                    self.records[node["name"]] = self.records[record]

    @staticmethod
    def _record_id(node):
        """The RecordDecl named by a typedef. Clang releases differ in how
        they wrap it: a RecordType, or an ElaboratedType with ownedTagDecl."""
        for inner in node.get("inner", []):
            if inner.get("kind") == "RecordType":
                return inner.get("decl", {}).get("id")
            owned = inner.get("ownedTagDecl", {})
            if owned.get("kind") == "RecordDecl":
                return owned.get("id")
            found = Types._record_id(inner)
            if found:
                return found
        return None

    def resolve(self, qual):
        """Follow typedefs of the whole type, keeping qualifiers."""
        seen = set()
        const = qual.startswith("const ")
        base = qual[6:] if const else qual
        while base in self.typedefs and base not in seen and base != RESULT_TYPE:
            seen.add(base)
            base = self.typedefs[base]
        return ("const " if const else "") + base

    def complete(self, pointer):
        """True unless the pointee is a struct without a definition here."""
        name = re.sub(r"\s*\*$", "", pointer).replace("const ", "").strip()
        pointee = self.resolve(name)
        return not pointee.startswith("struct ") or name in self.records or pointee in self.records

    def fields(self, qual):
        base = qual.replace("const ", "").strip()
        return self.records.get(base)


def is_pointer(resolved):
    return resolved.endswith("*") or "(*)" in resolved or "[" in resolved


def is_function_pointer(resolved):
    return "(*)" in resolved


def pointee_writable(resolved):
    """A pointer whose pointee has a size and is not const."""
    if is_function_pointer(resolved) or "[" in resolved:
        return not resolved.startswith("const ") and "void" not in resolved
    pointee = resolved[:-1].strip()
    return not pointee.startswith("const ") and pointee not in ("void",) and \
        not pointee.endswith("*const")


def opaque_context(resolved, name):
    """A void pointer handed back to a caller's callback, which may be NULL."""
    return resolved.replace("const ", "").strip() == "void *" and \
        re.search(r"(^|_)(context|user)$", name) is not None


def span_members(types, qual):
    """Pointer members of a by-value struct, each with its length member if
    the next member is an integer count."""
    fields = types.fields(qual)
    if not fields:
        return []
    members = []
    for index, (name, field_type) in enumerate(fields):
        resolved = types.resolve(field_type)
        if not is_pointer(resolved):
            continue
        length = None
        if index + 1 < len(fields) and fields[index + 1][1] in SIZE_TYPES:
            length = fields[index + 1][0]
        members.append((name, resolved, length))
    return members


def declaration_type(qual, name):
    """Render a parameter declaration from a Clang type spelling."""
    if "(*)" in qual:
        return qual.replace("(*)", f"(*{name})", 1)
    match = re.fullmatch(r"(.*?)\s*\[[^\]]*\]", qual)
    if match:
        return f"{match.group(1)} *{name}"
    return f"{qual} {name}"


def return_type(function_type):
    depth = 0
    for index, char in enumerate(function_type):
        if char == "(":
            if depth == 0 and function_type[index + 1:index + 2] != "*":
                return function_type[:index].strip()
            depth += 1
        elif char == ")":
            depth -= 1
    raise ValueError(function_type)


class Conditions:
    """Preprocessor condition of each declaration line in the public headers."""

    def __init__(self):
        self.lines = {}
        for path in public_headers():
            self._scan(path)

    def _scan(self, path):
        stack = []
        # Blank out comments but keep line breaks, so mentions in prose are
        # not taken for declarations.
        text = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)),
                      path.read_text(), flags=re.S)
        text = re.sub(r"//[^\n]*", "", text)
        raw = text.split("\n")
        joined, numbers = [], []
        index = 0
        while index < len(raw):
            line, start = raw[index], index
            while line.endswith("\\") and index + 1 < len(raw):
                index += 1
                line = line[:-1] + " " + raw[index].strip()
            joined.append(line)
            numbers.append(start)
            index += 1
        # The include guard is the first #ifndef followed by #define of the
        # same macro. It applies to the whole header and adds no condition.
        guard = None
        for first, second in zip(joined, joined[1:]):
            start = re.match(r"#\s*ifndef\s+(\w+)", first.strip())
            if start:
                if re.match(rf"#\s*define\s+{start.group(1)}\b", second.strip()):
                    guard = start.group(1)
                break
        guard_seen = False
        macros = {}
        for line in joined:
            definition = re.match(r"#\s*define\s+(\w+)\((\w+)\)(.*)", line.strip())
            if definition:
                macros[definition.group(1)] = (definition.group(2), definition.group(3))
        for line, number in zip(joined, numbers):
            text = re.sub(r"/\*.*?\*/", "", line).strip()
            directive = re.match(r"#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)", text)
            if directive:
                word, rest = directive.group(1), directive.group(2).strip()
                if word == "ifndef" and not guard_seen and rest == guard:
                    guard_seen = True
                    stack.append(("1", []))
                elif word == "if":
                    stack.append((f"({rest})", []))
                elif word == "ifdef":
                    stack.append((f"defined({rest})", []))
                elif word == "ifndef":
                    stack.append((f"!defined({rest})", []))
                elif word in ("elif", "else"):
                    current, previous = stack.pop()
                    previous = previous + [current]
                    negated = " && ".join(f"!{c}" for c in previous)
                    if word == "elif":
                        stack.append((f"({negated} && ({rest}))", previous))
                    else:
                        stack.append((f"({negated})", previous))
                elif word == "endif":
                    stack.pop()
                continue
            if text.startswith("#"):
                continue
            active = [c for c, _ in stack if c != "1" and "__cplusplus" not in c]
            condition = " && ".join(active) if active else "1"
            for name in re.findall(r"\b(TC_[A-Za-z0-9_]+)\s*\(", text):
                self.lines.setdefault(name, condition)
                # A declaration macro such as TC_HKDF_DECLARE(256) declares the
                # names its body pastes together with the argument.
                if name in macros:
                    parameter, body = macros[name]
                    argument = re.search(rf"\b{name}\s*\(\s*(\w+)\s*\)", text)
                    if argument:
                        expanded = body.replace(f"##{parameter}##", argument.group(1))
                        expanded = expanded.replace(f"##{parameter}", argument.group(1))
                        for declared in re.findall(r"\b(TC_[A-Za-z0-9_]+)\s*\(", expanded):
                            self.lines.setdefault(declared, condition)

    def condition(self, name):
        return self.lines.get(name)


def load_nullable(path):
    nullable = set()
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            function, parameter = line.split()
            nullable.add((function, parameter))
    return nullable


def functions(ast):
    for node in ast.get("inner", []):
        if node.get("kind") != "FunctionDecl" or not node["name"].startswith("TC_"):
            continue
        if node.get("storageClass") == "static" or node.get("isImplicit"):
            continue
        params = [p for p in node.get("inner", []) if p.get("kind") == "ParmVarDecl"]
        yield node["name"], node["type"]["qualType"], params


class Case:
    def __init__(self, label, setup, call_arg, index):
        self.label, self.setup, self.call_arg, self.index = label, setup, call_arg, index


def wrapper(types, name, function_type, params, nullable):
    ret = return_type(function_type)
    resolved_ret = types.resolve(ret)
    checks_result = resolved_ret == RESULT_TYPE
    names = [f"p{i}" for i in range(len(params))]
    labels = [p.get("name") or f"argument{i}" for i, p in enumerate(params)]
    quals = [p["type"]["qualType"] for p in params]
    resolved = [types.resolve(q) for q in quals]

    saves, cases = [], []
    for i, (qual, res) in enumerate(zip(quals, resolved)):
        arg, label = names[i], labels[i]
        if is_pointer(res):
            if pointee_writable(res) and not is_function_pointer(res) and types.complete(res):
                saves.append(f"tc_null_guard_save(&saved, {arg}, sizeof *{arg});")
            # An opaque callback context is passed through unchanged.
            if opaque_context(res, label):
                continue
            if (name, label) in nullable:
                continue
            present = f"{arg} != NULL"
            # An array followed by its count may be NULL when the count is 0.
            if i + 1 < len(quals) and quals[i + 1] in SIZE_TYPES:
                present += f" && {names[i + 1]} != 0"
            cases.append((label, present, "NULL", i, None))
            continue
        members = span_members(types, qual)
        # Span contents are not saved: a test may pass a capacity larger than
        # its storage, and an argument error must leave outputs unchanged.
        for member, member_type, length in members:
            if opaque_context(member_type, member):
                continue
            case_label = f"{label}.{member}"
            if (name, case_label) in nullable or (name, label) in nullable:
                continue
            present = f"{arg}.{member} != NULL" + (f" && {arg}.{length} != 0" if length else "")
            cases.append((case_label, present, member, i, qual))

    lines = []
    decl = ", ".join(declaration_type(q, n) for q, n in zip(quals, names)) or "void"
    lines.append(f"static inline {ret} tc_null_guard_{name}({decl})")
    lines.append("{")
    if cases:
        lines.append(f"  if (tc_null_guard_enter()) {{")
        lines.append("    tc_null_guard_snapshot saved;")
        lines.append("    tc_null_guard_snapshot_init(&saved);")
        for save in saves:
            lines.append(f"    {save}")
        for label, present, replacement, index, qual in cases:
            args = list(names)
            prefix = ""
            if qual is not None:
                prefix = f"{qual} changed = {names[index]};\n      changed.{replacement} = NULL;\n      "
                args[index] = "changed"
            else:
                args[index] = "NULL"
            call = f"{name}({', '.join(args)})"
            lines.append(f"    if ({present}) {{")
            lines.append(f'      tc_null_guard_hit("{name}", "{label}");')
            if prefix:
                lines.append(f"      {prefix.rstrip()}")
            if checks_result:
                lines.append(f"      if ({call} == TC_RESULT_OK)")
                lines.append(f'        tc_null_guard_accepted("{name}", "{label}");')
            elif ret == "void":
                lines.append(f"      {call};")
            else:
                lines.append(f"      (void){call};")
            lines.append("      tc_null_guard_restore(&saved);")
            lines.append("    }")
        lines.append("    tc_null_guard_leave(&saved);")
        lines.append("  }")
    call = f"{name}({', '.join(names)})"
    lines.append(f"  {'return ' if ret != 'void' else ''}{call};")
    lines.append("}")
    return "\n".join(lines), [c[0] for c in cases]


def generate(ast, nullable):
    types = Types(ast)
    conditions = Conditions()
    out = [
        "/* Generated by tests/null_guard/generate.py. Do not edit. */",
        "#ifndef TC_NULL_GUARD_WRAPPERS_H_",
        "#define TC_NULL_GUARD_WRAPPERS_H_",
        "#if !defined(__cplusplus) && !defined(TC_NULL_GUARD_LIBRARY_SOURCE) && \\",
        "    !defined(TC_NULL_GUARD_DISABLE)",
    ]
    out += [f"#include <tiny_crypto/{path.name}>" for path in public_headers()]
    out.append('#include "null_guard.h"')
    inventory = []
    macros = []
    seen = set()
    for name, function_type, params in functions(ast):
        if name in seen:
            continue
        seen.add(name)
        condition = conditions.condition(name)
        if condition is None:
            sys.exit(f"no declaration line found for {name}")
        if "TINY_CRYPTO_" in condition:
            sys.exit(f"{name} condition includes an include guard: {condition}")
        body, labels = wrapper(types, name, function_type, params, nullable)
        out.append(f"#if {condition}")
        out.append(body)
        out.append("#endif")
        macros += [f"#if {condition}", f"#define {name} tc_null_guard_{name}", "#endif"]
        inventory += [f"{name} {label}" for label in labels]
    # Object-like macros follow every wrapper, so the wrappers call the real
    # functions and test code reaches the wrappers through calls and function
    # pointers alike.
    out += macros
    out += ["#endif", "#endif", ""]
    return "\n".join(out), inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--nullable", type=Path, default=Path(__file__).with_name("nullable.txt"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inventory", type=Path)
    args = parser.parse_args()
    header, inventory = generate(clang_ast(args.clang), load_nullable(args.nullable))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if not args.output.exists() or args.output.read_text() != header:
        args.output.write_text(header)
    if args.inventory:
        args.inventory.write_text("\n".join(inventory) + "\n")


if __name__ == "__main__":
    main()
