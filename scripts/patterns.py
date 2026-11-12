"""Canonical shared regular expressions and basic parsing routines for the Frama-C pipeline.

Pure standard library only: ZERO internal pipeline imports.
"""

from __future__ import annotations

import posixpath
import re

# ---------------------------------------------------------------------------
# Canonical Regular Expressions
# ---------------------------------------------------------------------------

# C identifier: ASCII letters and underscore, followed by letters, digits, underscore.
C_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Slug sanitiser: sequences of disallowed characters to replace with underscore.
SLUG_RE = re.compile(r"[^A-Za-z0-9_.-]+")

# Kernel / compiler location: file:line, file:line-end, file:line:col, file:line:col-end:col.
LOCATION_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+)"
    r"(?:-(?P<end>\d+)(?::\d+(?:-\d+)?)?|:\d+-(?P<end2>\d+):\d+|:\d+(?:-\d+)?)?$"
)

# Pipeline module name.
MODULE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}$")

# Call site: function name immediately preceding an open parenthesis.
CALL_SITE_RE = re.compile(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")

# Frama-C kernel renamed static function: e.g. foo_0, bar_12.
KERNEL_RENAME_RE = re.compile(r"(.+)_\d+")

# LibFuzzer entry point definitions in C source.
FUZZER_INIT_DEF_RE = re.compile(r"\bLLVMFuzzerInitialize\s*\([^;{)]*\)\s*\{")
FUZZER_ENTRY_DEF_RE = re.compile(r"\bLLVMFuzzerTestOneInput\s*\(([^;{)]*)\)\s*\{")

# Eva domain name.
DOMAIN_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

# ACSL assigns clause keyword (word boundary anchored).
ASSIGNS_RE = re.compile(r"(?<![A-Za-z0-9_])assigns\b")

# Work tree prefixes and paths.
TREE_TAIL_RE = re.compile(r"^(?:workspace/work|agents/[^/]+/scratch/work)/(.+)$")
WORK_PREFIX_RE = re.compile(r"^(?:.*/)?workspace/(?:work|baseline)/")


# ---------------------------------------------------------------------------
# Memory and Size Parsing
# ---------------------------------------------------------------------------


def parse_mem(value: str | int | None, *, as_bytes: bool = False) -> int | None:
    """Parse a memory size string.

    By default (as_bytes=False), returns value in MiB (matching resources.py).
    When as_bytes=True, returns value in bytes (matching cache.py).
    Supports: integers, bare byte suffix ('1048576b'), k/K/Ki/KiB, m/M/Mi/MiB, g/G/Gi/GiB, t/T/Ti/TiB.
    """
    if value is None:
        return None
    if isinstance(value, int):
        return value
    m = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([kKmMgGtT]?)([iI]?)([bB]?)\s*", str(value))
    if not m:
        return None
    num = float(m.group(1))
    unit = m.group(2).lower()
    has_i = bool(m.group(3))
    has_b = bool(m.group(4))

    if not unit and has_i:
        return None  # 'i' without a unit letter

    if as_bytes:
        factors = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}
        return int(num * factors[unit])

    if not unit and has_b:
        return int(num // (1024 * 1024))  # plain bytes converted to MiB

    factors_mib = {"": 1, "k": 1 / 1024, "m": 1, "g": 1024, "t": 1024 * 1024}
    return int(num * factors_mib[unit])


def parse_size(raw: str) -> int | None:
    """Parse size string to bytes (alias for parse_mem with as_bytes=True)."""
    return parse_mem(raw, as_bytes=True)


# ---------------------------------------------------------------------------
# Makefile Dependency Parsing
# ---------------------------------------------------------------------------

_RULE_RE = re.compile(r"^((?:[^:\\]|\\.)+?):(?=\s|$)(.*)$")


def _split_make_words(text: str) -> list[str]:
    """Split Makefile dependency words, handling escaped spaces, #, backslashes, and $$."""
    words: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text) and text[i + 1] in " #\\":
            cur.append(text[i + 1])
            i += 2
            continue
        if c == "$" and text[i + 1 : i + 2] == "$":
            cur.append("$")
            i += 2
            continue
        if c.isspace():
            if cur:
                words.append("".join(cur))
                cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if cur:
        words.append("".join(cur))
    return words


def parse_make_deps(text: str, cwd: str | None = None) -> list[str]:
    """Prerequisites of every rule in `gcc -M` / `clang -M` output.

    If `cwd` is provided, returns normalized absolute paths (for build_capture.py).
    Otherwise returns parsed tokens directly (for cache.py).
    """
    deps: list[str] = []
    joined = re.sub(r"\\\r?\n", " ", text or "")
    for line in joined.splitlines():
        m = _RULE_RE.match(line.strip())
        if m:
            deps.extend(_split_make_words(m.group(2)))
    if cwd is not None:
        return [posixpath.normpath(d if posixpath.isabs(d) else posixpath.join(cwd, d)) for d in deps]
    return deps
