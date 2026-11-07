#!/usr/bin/env python3
"""fuzz_dictionary.py — Extract string literals and extreme numeric boundary tokens for fuzzing.

Generates libFuzzer and AFL-compatible dictionary files containing:
1. 8-bit, 16-bit, 32-bit, and 64-bit integer boundary limits and off-by-ones.
2. Hexadecimal representation strings.
3. Escaped byte sequence tokens (single bytes and 16/32/64-bit words).
4. String literals extracted from C source files.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# Add scripts directory to path if run standalone
SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

try:
    from acsl_ast import AcslSyntaxError, tokenize_c_acsl
except ImportError:
    AcslSyntaxError = Exception  # type: ignore
    tokenize_c_acsl = None  # type: ignore

# Fallback regex for string literals if ACSL tokenizer is unavailable or encounters syntax error
_STRING_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\])*)"')

# Extreme integer boundary limits and off-by-ones (decimal strings)
EXTREME_DECIMAL_LIMITS: list[str] = [
    # Zero and small integers
    "0",
    "1",
    "-1",
    # 8-bit signed/unsigned boundaries
    "126",
    "127",
    "128",
    "-127",
    "-128",
    "-129",
    "254",
    "255",
    "256",
    # 16-bit signed/unsigned boundaries
    "32766",
    "32767",
    "32768",
    "-32767",
    "-32768",
    "-32769",
    "65534",
    "65535",
    "65536",
    # 32-bit signed/unsigned boundaries
    "2147483646",
    "2147483647",
    "2147483648",
    "-2147483647",
    "-2147483648",
    "-2147483649",
    "4294967294",
    "4294967295",
    "4294967296",
    # 64-bit signed/unsigned boundaries
    "9223372036854775806",
    "9223372036854775807",
    "9223372036854775808",
    "-9223372036854775807",
    "-9223372036854775808",
    "-9223372036854775809",
    "18446744073709551614",
    "18446744073709551615",
    "18446744073709551616",
]

# Extreme hexadecimal representation strings
EXTREME_HEX_STRINGS: list[str] = [
    "0x0",
    "0x1",
    "0x7f",
    "0x80",
    "0xff",
    "0x7fff",
    "0x8000",
    "0xffff",
    "0x7fffffff",
    "0x80000000",
    "0xffffffff",
    "0x7fffffffffffffff",
    "0x8000000000000000",
    "0xffffffffffffffff",
]

# Escaped byte representations (single bytes and multi-byte words)
EXTREME_BYTE_TOKENS: list[str] = [
    # Single byte boundaries
    r"\x00",
    r"\x01",
    r"\x7f",
    r"\x80",
    r"\xfe",
    r"\xff",
    # 16-bit words (little & big endian)
    r"\x00\x00",
    r"\xff\xff",
    r"\x7f\xff",
    r"\xff\x7f",
    r"\x80\x00",
    r"\x00\x80",
    r"\x01\x00",
    r"\x00\x01",
    # 32-bit words (little & big endian)
    r"\x00\x00\x00\x00",
    r"\xff\xff\xff\xff",
    r"\x7f\xff\xff\xff",
    r"\xff\xff\xff\x7f",
    r"\x80\x00\x00\x00",
    r"\x00\x00\x00\x80",
    # 64-bit words (little & big endian)
    r"\x00\x00\x00\x00\x00\x00\x00\x00",
    r"\xff\xff\xff\xff\xff\xff\xff\xff",
    r"\x7f\xff\xff\xff\xff\xff\xff\xff",
    r"\xff\xff\xff\xff\xff\xff\xff\x7f",
    r"\x80\x00\x00\x00\x00\x00\x00\x00",
    r"\x00\x00\x00\x00\x00\x00\x00\x80",
]


def generate_extreme_numeric_tokens() -> list[str]:
    """Generate ordered list of extreme numeric boundary tokens (decimal, hex, and escaped bytes)."""
    tokens: list[str] = []
    seen: set[str] = set()
    for tok in EXTREME_DECIMAL_LIMITS + EXTREME_HEX_STRINGS + EXTREME_BYTE_TOKENS:
        if tok not in seen:
            seen.add(tok)
            tokens.append(tok)
    return tokens


def extract_string_literals(source_code: str, path: str = "<input>") -> list[str]:
    """Extract unique string literal tokens from C source code.

    Preserves C escape sequences and filters empty or overly long tokens.
    """
    raw_literals: list[str] = []

    if tokenize_c_acsl is not None:
        try:
            tokens = tokenize_c_acsl(source_code, path=path)
            for t in tokens:
                if t.kind == "string" and len(t.text) >= 2:
                    raw_literals.append(t.text[1:-1])
        except (AcslSyntaxError, Exception):
            raw_literals = _STRING_LITERAL_RE.findall(source_code)
    else:
        raw_literals = _STRING_LITERAL_RE.findall(source_code)

    results: list[str] = []
    seen: set[str] = set()

    for lit in raw_literals:
        # Normalize newlines to prevent multi-line dictionary lines
        clean = lit.replace("\r\n", "\\r\\n").replace("\n", "\\n").replace("\r", "\\r")
        # Filter empty strings or overly long strings (libFuzzer/AFL limit tokens to <= 128 bytes)
        if 1 <= len(clean) <= 128 and clean not in seen:
            seen.add(clean)
            results.append(clean)

    return sorted(results)


def collect_source_files(paths: list[Path | str]) -> list[Path]:
    """Resolve paths to a sorted list of unique C/C++ source and header files."""
    files: list[Path] = []
    seen: set[Path] = set()

    for p_raw in paths:
        p = Path(p_raw).resolve()
        if p.is_file():
            if p not in seen:
                seen.add(p)
                files.append(p)
        elif p.is_dir():
            for root, dirs, filenames in os.walk(p):
                # Skip dot-directories and build directories
                dirs[:] = [
                    d
                    for d in dirs
                    if not d.startswith(".") and d not in {"build", "CMakeFiles", "__pycache__", "node_modules"}
                ]
                for fn in sorted(filenames):
                    if fn.endswith((".c", ".h", ".cpp", ".cc", ".cxx")):
                        fp = Path(root) / fn
                        if fp not in seen:
                            seen.add(fp)
                            files.append(fp)

    return sorted(files)


def build_dictionary(
    sources: list[Path | str] | None = None,
    include_numeric: bool = True,
    include_strings: bool = True,
) -> list[str]:
    """Build unified fuzzer dictionary tokens from numeric boundaries and sources."""
    tokens: list[str] = []
    seen: set[str] = set()

    def add_token(t: str) -> None:
        if t not in seen:
            seen.add(t)
            tokens.append(t)

    if include_numeric:
        for num_tok in generate_extreme_numeric_tokens():
            add_token(num_tok)

    if include_strings and sources:
        files = collect_source_files(sources)
        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                for str_tok in extract_string_literals(content, path=str(f)):
                    add_token(str_tok)
            except OSError:
                continue

    return tokens


def render_dictionary(tokens: list[str]) -> str:
    """Render tokens in standard libFuzzer/AFL dictionary syntax (deterministic: no timestamps or paths)."""
    lines = [
        "# Frama-C Pipeline Fuzzer Dictionary",
        "# Auto-generated with extreme numeric boundaries and extracted string literals",
        "",
    ]
    for tok in tokens:
        # Wrap token in quotes
        lines.append(f'"{tok}"')

    lines.append("")
    return "\n".join(lines)


def write_dictionary(out_path: Path | str, tokens: list[str]) -> None:
    """Write tokens to a file in standard libFuzzer/AFL dictionary syntax."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_dictionary(tokens), encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract string literals and extreme numeric boundary tokens into a fuzzer dictionary."
    )
    parser.add_argument(
        "--sources",
        nargs="*",
        default=[],
        help="C source files or directories to extract string literals from.",
    )
    parser.add_argument(
        "files",
        nargs="*",
        default=[],
        help="Positional C source files or directories.",
    )
    parser.add_argument(
        "--out-dict",
        "-o",
        type=Path,
        required=True,
        help="Output dictionary file path.",
    )
    parser.add_argument(
        "--no-numeric",
        action="store_true",
        help="Omit extreme numeric boundary tokens.",
    )
    parser.add_argument(
        "--no-strings",
        action="store_true",
        help="Omit extracted string literals from sources.",
    )

    args = parser.parse_args()
    all_sources = list(args.sources) + list(args.files)

    tokens = build_dictionary(
        sources=all_sources,
        include_numeric=not args.no_numeric,
        include_strings=not args.no_strings,
    )

    write_dictionary(args.out_dict, tokens)
    return 0


if __name__ == "__main__":
    sys.exit(main())
