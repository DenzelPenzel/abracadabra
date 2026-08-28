#!/usr/bin/env python3
"""Regenerate or verify vmp-demangle fixtures with the bundled C parsers.

This is a maintainer-only tool. It compiles a temporary native oracle from the
bundled demanglers; it is not invoked by Cargo or by normal tests.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[4]
CRATE = HERE.parents[1]
FIXTURES = CRATE / "tests" / "fixtures"
TEST1 = ROOT / "unit-tests" / "test1.cc"
FILES_CC = ROOT / "core" / "files.cc"
DEMANGLE_DIR = ROOT / "third-party" / "demangle"
UNDNAME_C = DEMANGLE_DIR / "undname.c"
CP_DEMANGLE_C = DEMANGLE_DIR / "cp-demangle.c"
UNMANGLE_C = DEMANGLE_DIR / "unmangle.c"
MAPS = [ROOT / "test-binaries" / "msvc-map", ROOT / "test-binaries" / "msvc-x64-map-2"]

EXPECTED_MAP_ROWS = {"msvc-map": 2060, "msvc-x64-map-2": 735}
EXPECTED_TOTAL_MAP_ROWS = 2795
EXPECTED_MSVC_CANDIDATES = 1540
EXPECTED_ACCEPTED_MSVC_ROWS = 1539
EXPECTED_REJECTED_MSVC = {"??_B?1??make@DNameStatusNode@@SAPAV1@W4DNameStatus@@@Z@51"}
COMPILE_TIMEOUT_SECONDS = 60
ORACLE_TIMEOUT_SECONDS = 30

C_STRING = r'"(?:\\[^\r\n]|[^"\\\r\n])*"'
TRIVIA = r"(?:\s|//[^\r\n]*(?:\r?\n|$)|/\*.*?\*/)"
STRING_SEQUENCE = rf"{C_STRING}(?:{TRIVIA}*{C_STRING})*"
ENTRY_RE = re.compile(
    rf"\{{\s*(?P<mangled>{STRING_SEQUENCE})\s*,\s*(?P<expected>{STRING_SEQUENCE})\s*\}}",
    re.DOTALL,
)


def decode_c_strings(source: str) -> str:
    """Decode adjacent ordinary C string literals without Python-eval semantics."""
    simple_escapes = {
        "'": "'",
        '"': '"',
        "?": "?",
        "\\": "\\",
        "a": "\a",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
    }

    def skip_trivia(pos: int) -> int:
        while pos < len(source):
            if source[pos].isspace():
                pos += 1
            elif source.startswith("//", pos):
                newline = source.find("\n", pos + 2)
                pos = len(source) if newline < 0 else newline + 1
            elif source.startswith("/*", pos):
                end = source.find("*/", pos + 2)
                if end < 0:
                    raise ValueError("unterminated comment between C string literals")
                pos = end + 2
            else:
                break
        return pos

    decoded: list[str] = []
    pos = skip_trivia(0)
    literal_count = 0
    while pos < len(source):
        for prefix in ('u8"', 'u"', 'U"', 'L"'):
            if source.startswith(prefix, pos):
                raise ValueError(f"unsupported C string prefix {prefix[:-1]!r} at offset {pos}")
        if source[pos] != '"':
            raise ValueError(f"expected ordinary C string literal at offset {pos}")
        literal_count += 1
        pos += 1
        while True:
            if pos >= len(source):
                raise ValueError("unterminated C string literal")
            char = source[pos]
            if char == '"':
                pos += 1
                break
            if char in "\r\n":
                raise ValueError(f"unescaped newline in C string literal at offset {pos}")
            if char != "\\":
                decoded.append(char)
                pos += 1
                continue

            escape_offset = pos
            pos += 1
            if pos >= len(source):
                raise ValueError(f"trailing backslash in C string literal at offset {escape_offset}")
            escape = source[pos]
            if escape in simple_escapes:
                decoded.append(simple_escapes[escape])
                pos += 1
            elif escape in "01234567":
                end = pos + 1
                while end < len(source) and end < pos + 3 and source[end] in "01234567":
                    end += 1
                value = int(source[pos:end], 8)
                if value > 0xFF:
                    raise ValueError(
                        f"octal escape value {value:#o} is outside one byte at offset {escape_offset}"
                    )
                decoded.append(chr(value))
                pos = end
            elif escape == "x":
                end = pos + 1
                while end < len(source) and source[end] in "0123456789abcdefABCDEF":
                    end += 1
                if end == pos + 1:
                    raise ValueError(f"hex escape has no digits at offset {escape_offset}")
                value = int(source[pos + 1 : end], 16)
                if value > 0xFF:
                    raise ValueError(
                        f"hex escape value {value:#x} is outside one byte at offset {escape_offset}"
                    )
                decoded.append(chr(value))
                pos = end
            elif escape in "uU":
                raise ValueError(f"unsupported universal escape at offset {escape_offset}")
            else:
                raise ValueError(f"unsupported C escape \\{escape} at offset {escape_offset}")
        pos = skip_trivia(pos)

    if literal_count == 0:
        raise ValueError("expected at least one ordinary C string literal")
    return "".join(decoded)


def cpp_pairs() -> list[tuple[str, str]]:
    text = TEST1.read_text(encoding="utf-8")
    start = text.index("TEST(Demangle, Demangle_Test)")
    end = text.index("\n}\n", start)
    pairs = [
        (decode_c_strings(m.group("mangled")), decode_c_strings(m.group("expected")))
        for m in ENTRY_RE.finditer(text[start:end])
    ]
    if len(pairs) != 107:
        raise RuntimeError(f"expected 107 C++ golden pairs, extracted {len(pairs)}")
    conflicts: dict[str, str] = {}
    for raw, expected in pairs:
        if raw in conflicts and conflicts[raw] != expected:
            raise RuntimeError(f"conflicting C++ expectations for {raw!r}")
        conflicts[raw] = expected
    return pairs


def split_map_columns(line: str) -> list[str]:
    """Mirror core/files.cc MapFile::Parse whitespace/bracket tokenization."""
    columns: list[str] = []
    pos = 0
    while pos < len(line):
        while pos < len(line) and line[pos].isspace():
            pos += 1
        begin = pos
        in_block = False
        while pos < len(line):
            if line[pos] == "[":
                in_block = True
            elif line[pos] == "]":
                in_block = False
            elif not in_block and line[pos].isspace():
                break
            pos += 1
        if pos != begin:
            columns.append(line[begin:pos])
    return columns


def map_symbols(path: Path) -> list[str]:
    """Extract columns[1] in the MSVC public/static-symbol parser states."""
    state = "begin"
    symbols: list[str] = []
    for line in path.read_text(encoding="ascii").splitlines():
        stripped = line.lstrip()
        normalized = " ".join(stripped.split())
        if state == "begin":
            if normalized == "Start Length Name Class":
                state = "sections"
            continue
        if state == "sections":
            if normalized == "Address Publics by Value Rva+Base Lib:Object":
                state = "address_vc"
            continue
        if state == "address_vc" and stripped.startswith("Static symbols"):
            state = "static_symbols"
            continue
        if state not in ("address_vc", "static_symbols"):
            continue

        columns = split_map_columns(stripped)
        # Match the stAddressVC/stStaticSymbols acceptance checks in files.cc:
        # at least two columns, and when a third exists it must be hex.
        if len(columns) < 2:
            continue
        if len(columns) >= 3:
            try:
                int(columns[2], 16)
            except ValueError:
                continue
        symbols.append(columns[1])
    return symbols


HARNESS = r'''#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "undname.h"
#include "demangle.h"
#include "unmangle.h"

/* Minimal libiberty/project shims required by standalone cp-demangle.c. */
void *xmalloc(size_t size) {
    void *result = malloc(size);
    if (!result) abort();
    return result;
}
void *xrealloc(void *ptr, size_t size) {
    void *result = realloc(ptr, size);
    if (!result) abort();
    return result;
}
void *xcalloc(size_t count, size_t size) {
    void *result = calloc(count, size);
    if (!result) abort();
    return result;
}
void *C_alloca(size_t size) { return malloc(size); }

static void print_hex(const char *text) {
    const unsigned char *p = (const unsigned char *)text;
    while (*p) printf("%02x", *p++);
}

static char *try_msvc(const char *raw, size_t *name_pos) {
    enum { FLAGS =
        UNDNAME_NO_LEADING_UNDERSCORES |
        UNDNAME_NO_MS_KEYWORDS |
        UNDNAME_NO_ALLOCATION_MODEL |
        UNDNAME_NO_ALLOCATION_LANGUAGE |
        UNDNAME_NO_MS_THISTYPE |
        UNDNAME_NO_CV_THISTYPE |
        UNDNAME_NO_THISTYPE |
        UNDNAME_NO_ACCESS_SPECIFIERS |
        UNDNAME_NO_THROW_SIGNATURES |
        UNDNAME_NO_MEMBER_TYPE |
        UNDNAME_NO_RETURN_UDT_MODEL |
        UNDNAME_32_BIT_DECODE
    };
    return undname(raw, FLAGS, name_pos);
}

static void classify(const char *raw) {
    size_t raw_len = strlen(raw);
    size_t name_pos = 0;
    char *result = try_msvc(raw, &name_pos);
    if (result) {
        printf("msvc\t%zu\t", name_pos);
        print_hex(result);
        free(result);
        putchar('\n');
        return;
    }

    /* Match the Apple double-underscore rule in core/files.cc exactly. */
    const char *gnu_raw = raw;
    if (raw_len >= 2 && raw[0] == '_' && raw[1] == '_') ++gnu_raw;
    result = cplus_demangle_v3(gnu_raw, DMGL_PARAMS | DMGL_ANSI | DMGL_TYPES);
    if (result) {
        printf("gnu-v3\t0\t");
        print_hex(result);
        free(result);
        putchar('\n');
        return;
    }

    char mutable_raw[8192];
    char borland_result[1024];
    if (raw_len >= sizeof(mutable_raw)) abort();
    memcpy(mutable_raw, raw, raw_len + 1);
    borland_result[0] = '\0';
    int code = unmangle(mutable_raw, borland_result, sizeof(borland_result), NULL, NULL, 1);
    if ((code & (UM_BUFOVRFLW | UM_ERROR | UM_NOT_MANGLED)) == 0) {
        printf("borland\t0\t");
        print_hex(borland_result);
        putchar('\n');
        return;
    }

    printf("fallback\t0\t");
    print_hex(raw);
    putchar('\n');
}

static void msvc_only(const char *raw) {
    size_t name_pos = 0;
    char *result = try_msvc(raw, &name_pos);
    if (!result) {
        puts("reject");
        return;
    }
    printf("accept\t%zu\t", name_pos);
    print_hex(result);
    free(result);
    putchar('\n');
}

int main(void) {
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    while ((length = getline(&line, &capacity, stdin)) >= 0) {
        if (length && line[length - 1] == '\n') line[--length] = '\0';
        if (length < 2 || line[1] != '\t') return 4;
        if (line[0] == 'C') classify(line + 2);
        else if (line[0] == 'M') msvc_only(line + 2);
        else return 5;
    }
    free(line);
    return ferror(stdin) ? 2 : 0;
}
'''


class BundledOracle:
    def __init__(self, tmp_path: Path) -> None:
        harness = tmp_path / "oracle.c"
        self.binary = tmp_path / "oracle"
        harness.write_text(HARNESS, encoding="ascii")
        command = [
            "cc",
            "-std=c11",
            "-D_GNU_SOURCE",
            "-DVMP_GNU",
            "-DBOOL=int",
            "-DNDEBUG",
            "-DHAVE_STDLIB_H",
            "-DHAVE_STRING_H",
            "-DHAVE_LIMITS_H",
            "-include",
            "stddef.h",
            "-include",
            "stdio.h",
            "-include",
            "stdlib.h",
            "-include",
            "string.h",
            "-include",
            "stdarg.h",
            "-include",
            "assert.h",
            "-include",
            "ctype.h",
            "-include",
            "setjmp.h",
            "-I",
            str(DEMANGLE_DIR),
            str(harness),
            str(UNDNAME_C),
            str(CP_DEMANGLE_C),
            str(UNMANGLE_C),
            "-o",
            str(self.binary),
        ]
        try:
            subprocess.run(command, check=True, timeout=COMPILE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"oracle compile timed out after {COMPILE_TIMEOUT_SECONDS} seconds"
            ) from error

    def run(self, operation: str, candidates: list[str]) -> list[str]:
        try:
            proc = subprocess.run(
                [str(self.binary)],
                input="".join(f"{operation}\t{name}\n" for name in candidates),
                text=True,
                stdout=subprocess.PIPE,
                check=True,
                timeout=ORACLE_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"oracle run timed out after {ORACLE_TIMEOUT_SECONDS} seconds: "
                f"operation={operation!r}, candidates={len(candidates)}"
            ) from error
        lines = proc.stdout.splitlines()
        if len(lines) != len(candidates):
            raise RuntimeError(
                f"oracle output line count mismatch: expected {len(candidates)}, got {len(lines)}"
            )
        return lines


def decode_oracle_text(raw: str, hex_text: str) -> str:
    try:
        return bytes.fromhex(hex_text).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise RuntimeError(f"invalid oracle output for {raw!r}: {hex_text!r}") from error


def classify_cpp(
    oracle: BundledOracle, pairs: list[tuple[str, str]]
) -> list[tuple[str, str, str]]:
    results = oracle.run("C", [raw for raw, _ in pairs])
    rows: list[tuple[str, str, str]] = []
    for row_number, ((raw, expected), result) in enumerate(zip(pairs, results), 1):
        try:
            route, pos_text, output_hex = result.split("\t", 2)
            name_pos = int(pos_text)
        except ValueError as error:
            raise RuntimeError(f"malformed classification output for row {row_number}: {result!r}") from error
        full = decode_oracle_text(raw, output_hex)
        full_bytes = full.encode("utf-8")
        if route == "msvc":
            if name_pos > len(full_bytes):
                raise RuntimeError(f"invalid MSVC name_pos {name_pos} for row {row_number} {raw!r}")
            output = full_bytes[name_pos:].decode("utf-8")
        elif route in ("gnu-v3", "borland", "fallback"):
            if name_pos != 0:
                raise RuntimeError(f"unexpected name_pos {name_pos} for {route} row {row_number}")
            output = full
        else:
            raise RuntimeError(f"unknown route {route!r} for row {row_number} {raw!r}")
        if output != expected:
            raise RuntimeError(
                f"C++ golden mismatch at row {row_number}: parser={route}, raw={raw!r}, "
                f"oracle={output!r}, expected={expected!r}"
            )
        rows.append((raw, route, expected))
    return rows


def msvc_oracle(
    oracle: BundledOracle, candidates: list[str]
) -> tuple[list[tuple[str, str, int, str]], set[str]]:
    results = oracle.run("M", candidates)
    rows: list[tuple[str, str, int, str]] = []
    rejected: set[str] = set()
    for raw, result in zip(candidates, results):
        if result == "reject":
            rejected.add(raw)
            continue
        try:
            accepted, pos_text, full_hex = result.split("\t", 2)
            if accepted != "accept":
                raise ValueError
            name_pos = int(pos_text)
        except ValueError as error:
            raise RuntimeError(f"malformed MSVC oracle output for {raw!r}: {result!r}") from error
        full = decode_oracle_text(raw, full_hex)
        full_bytes = full.encode("utf-8")
        if name_pos > len(full_bytes):
            raise RuntimeError(f"invalid name_pos {name_pos} for {raw!r}")
        selector = full_bytes[name_pos:].decode("utf-8")
        rows.append((raw, full, name_pos, selector))
    return rows, rejected


def js(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def generate() -> tuple[dict[Path, bytes], Counter[str], int, int, int]:
    pairs = cpp_pairs()
    parsed_by_map = [(path, map_symbols(path)) for path in MAPS]
    for path, symbols in parsed_by_map:
        expected = EXPECTED_MAP_ROWS[path.name]
        if len(symbols) != expected:
            raise RuntimeError(
                f"MAP row-count invariant for {path.name}: expected {expected}, current {len(symbols)}"
            )
    parsed = [symbol for _, symbols in parsed_by_map for symbol in symbols]
    if len(parsed) != EXPECTED_TOTAL_MAP_ROWS:
        raise RuntimeError(
            f"total MAP row-count invariant: expected {EXPECTED_TOTAL_MAP_ROWS}, current {len(parsed)}"
        )
    # MSVC C++ decorated names begin with '?'. Sorting a set defines both the
    # duplicate policy and deterministic oracle invocation/output order.
    candidates = sorted({symbol for symbol in parsed if symbol.startswith("?")})
    if len(candidates) != EXPECTED_MSVC_CANDIDATES:
        raise RuntimeError(
            f"unique decorated candidate-count invariant: expected {EXPECTED_MSVC_CANDIDATES}, "
            f"current {len(candidates)}"
        )

    with tempfile.TemporaryDirectory(prefix="vmp-demangle-oracle-") as tmp:
        oracle = BundledOracle(Path(tmp))
        cpp_rows = classify_cpp(oracle, pairs)
        msvc_rows, rejected = msvc_oracle(oracle, candidates)

    if rejected != EXPECTED_REJECTED_MSVC:
        raise RuntimeError(
            f"rejected MSVC symbol-set invariant: expected {sorted(EXPECTED_REJECTED_MSVC)!r}, "
            f"current {sorted(rejected)!r}"
        )
    if len(msvc_rows) != EXPECTED_ACCEPTED_MSVC_ROWS:
        raise RuntimeError(
            f"accepted undname row-count invariant: expected {EXPECTED_ACCEPTED_MSVC_ROWS}, "
            f"current {len(msvc_rows)}"
        )

    cpp_text = (
        "# vmp-demangle C++ golden fixture v2\n"
        "# Non-comment rows: JSON_STRING(mangled) TAB route TAB JSON_STRING(expected selector name).\n"
        "# Routes are msvc, gnu-v3, borland, or fallback in exact core/files.cc order.\n"
        "# JSON escaping is authoritative; row order and duplicates preserve unit-tests/test1.cc.\n"
        + "".join(f"{js(raw)}\t{route}\t{js(expected)}\n" for raw, route, expected in cpp_rows)
    )
    msvc_text = (
        "# vmp-demangle bundled MSVC MAP oracle v1\n"
        "# Non-comment rows: JSON_STRING(raw) TAB JSON_STRING(full) TAB name_pos_bytes TAB JSON_STRING(selector).\n"
        "# selector is the UTF-8 byte suffix full[name_pos_bytes:]; rows are sorted by unique raw name.\n"
        + "".join(
            f"{js(raw)}\t{js(full)}\t{pos}\t{js(selector)}\n"
            for raw, full, pos, selector in msvc_rows
        )
    )
    outputs = {
        FIXTURES / "cpp_demangle.tsv": cpp_text.encode("utf-8"),
        FIXTURES / "msvc_corpus.tsv": msvc_text.encode("utf-8"),
    }
    return outputs, Counter(route for _, route, _ in cpp_rows), len(parsed), len(candidates), len(msvc_rows)


def verify(outputs: dict[Path, bytes]) -> None:
    mismatches: list[str] = []
    for path, generated in outputs.items():
        try:
            checked_in = path.read_bytes()
        except FileNotFoundError:
            mismatches.append(f"missing: {path.relative_to(ROOT)}")
            continue
        if generated != checked_in:
            mismatches.append(
                f"mismatch: {path.relative_to(ROOT)} "
                f"(checked-in sha256={hashlib.sha256(checked_in).hexdigest()}, "
                f"generated sha256={hashlib.sha256(generated).hexdigest()})"
            )
    if mismatches:
        raise RuntimeError("fixture verification failed:\n" + "\n".join(mismatches))


def main(argv: list[str]) -> None:
    if not argv:
        verify_only = False
    elif argv == ["--verify"]:
        verify_only = True
    else:
        raise SystemExit("usage: generate_fixtures.py [--verify]")

    outputs, routes, parsed_count, candidate_count, accepted_count = generate()
    if verify_only:
        verify(outputs)
        action = "Verified"
    else:
        FIXTURES.mkdir(parents=True, exist_ok=True)
        for path, content in outputs.items():
            path.write_bytes(content)
        action = "Wrote"

    route_summary = ", ".join(f"{route}={routes[route]}" for route in ("msvc", "gnu-v3", "borland", "fallback"))
    print(f"{action} C++ rows: {sum(routes.values())} ({route_summary})")
    print(f"MAP parser symbol rows: {parsed_count}")
    print(f"Unique MSVC-decorated candidates: {candidate_count}")
    print(f"Accepted by undname: {accepted_count}")


if __name__ == "__main__":
    main(sys.argv[1:])
