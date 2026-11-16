#!/usr/bin/env python3
"""fuzz_dictionary.py — Extract string literals and extreme numeric boundary tokens for fuzzing.

Generates libFuzzer and AFL-compatible dictionary files containing:
1. 8-bit, 16-bit, 32-bit, and 64-bit integer boundary limits and off-by-ones.
2. Hexadecimal representation strings.
3. Escaped byte sequence tokens (single bytes and 16/32/64-bit words).
4. String literals extracted from C source files.
5. The values of object-like macros the project defines, read from the preprocessed sources
   (`cc -E -dD` with the unit's flags, so only the macros the build actually sees): integers as
   decimal text and as little- and big-endian bytes of the smallest width that holds them, strings
   as their content (step I6). Macros from system headers and the compiler are left out.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
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


MAX_MACRO_TOKENS = 1000
MACRO_TIMEOUT_S = 60
_LINEMARK_RE = re.compile(r'^#\s*(?:line\s+)?\d+\s+"((?:\\.|[^"\\])*)"')
_DEFINE_RE = re.compile(r"^#\s*define\s+([A-Za-z_]\w*)(?:[ \t]+(.*))?$")
_INT_RE = re.compile(r"^([+-]?)(0[xX][0-9a-fA-F]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*)[uUlL]*$")
_CAST_RE = re.compile(r"^\(\s*(?:(?:const|unsigned|signed|long|short|int|char|struct|enum)\s+)*[A-Za-z_]\w*\s*\)\s*")
_C_STRING_RE = re.compile(r'^"((?:\\.|[^"\\])*)"$')


def parse_dd_output(text: str, cwd: str | None = None) -> list[tuple[str, str, str]]:
    """(name, value, file) of each object-like #define in `cc -E -dD` output, file from the line markers."""
    current = ""
    out: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        if not line.startswith("#"):
            continue
        m = _LINEMARK_RE.match(line)
        if m:
            current = m.group(1)
            continue
        d = _DEFINE_RE.match(line)
        if d and not line[d.end(1) :].startswith("("):
            out.append((d.group(1), (d.group(2) or "").strip(), current))
    return out


def is_project_file(path: str, cwd: str) -> bool:
    """A macro's file is the project's: relative, or under the run directory; never <built-in> or /usr."""
    if not path or path.startswith("<"):
        return False
    if not posixpath.isabs(path) and not os.path.isabs(path):  # container paths are POSIX, on any host
        return True
    root = cwd.rstrip("/") + "/"
    return path.startswith(root) and "/frama-c/" not in path and "/workspace/snapshot/" not in path


def _strip_value(value: str) -> str:
    v = value.strip()
    for _ in range(4):
        v = _CAST_RE.sub("", v).strip()
        if v.startswith("(") and v.endswith(")") and v.count("(") == 1:
            v = v[1:-1].strip()
    return v


def _int_bytes(n: int) -> list[str]:
    """Little- and big-endian byte tokens of the smallest width holding n (two's complement when negative)."""
    for width in (1, 2, 4, 8):
        lo, hi = -(1 << (8 * width - 1)), (1 << (8 * width)) - 1
        if lo <= n <= hi:
            raw = (n & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
            le = "".join(f"\\x{b:02x}" for b in raw)
            be = "".join(f"\\x{b:02x}" for b in reversed(raw))
            return [le] if width == 1 else [le, be]
    return []


def macro_value_tokens(defs: list[tuple[str, str, str]], cwd: str) -> list[str]:
    """Dictionary tokens from macro values defined in project files."""
    tokens: list[str] = []
    seen: set[str] = set()
    for _name, value, file in defs:
        if not is_project_file(file, cwd):
            continue
        v = _strip_value(value)
        found: list[str] = []
        m = _INT_RE.match(v)
        if m:
            sign, digits = m.groups()
            low = digits.lower()
            base = (
                16
                if low.startswith("0x")
                else 2
                if low.startswith("0b")
                else 8
                if low.startswith("0") and len(low) > 1
                else 10
            )
            n = int(low[2:] if base in (16, 2) else low, base) * (-1 if sign == "-" else 1)
            found = [str(n), *_int_bytes(n)]
        else:
            s = _C_STRING_RE.match(v)
            if s and 1 <= len(s.group(1)) <= 128:
                found = [s.group(1)]
        for tok in found:
            if tok not in seen:
                seen.add(tok)
                tokens.append(tok)
        if len(tokens) >= MAX_MACRO_TOKENS:
            break
    return tokens[:MAX_MACRO_TOKENS]


def preprocessed_macro_tokens(sources: Sequence[Path | str], cppflags: str, compiler: str | None = None) -> list[str]:
    """Macro value tokens of each C source preprocessed with the unit's flags; a source that fails is skipped."""
    cc = compiler or shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    if not cc:
        return []
    try:
        flags = shlex.split(cppflags or "")
    except ValueError:
        return []
    cwd = os.getcwd()
    defs: list[tuple[str, str, str]] = []
    for src in sources:
        if not str(src).endswith(".c"):
            continue
        try:
            p = subprocess.run(
                [cc, "-E", "-dD", *flags, str(src)],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=MACRO_TIMEOUT_S,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if p.returncode == 0:
            defs += parse_dd_output(p.stdout, cwd)
    return macro_value_tokens(defs, cwd)


def build_dictionary(
    sources: list[Path | str] | None = None,
    include_numeric: bool = True,
    include_strings: bool = True,
    cppflags: str | None = None,
) -> list[str]:
    """Build unified fuzzer dictionary tokens from numeric boundaries and sources (and, with
    `cppflags`, the project's macro values from the preprocessed sources)."""
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

    if cppflags is not None and sources:
        for macro_tok in preprocessed_macro_tokens(collect_source_files(sources), cppflags):
            add_token(macro_tok)

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


_DICT_LINE_RE = re.compile(r'^(?P<prefix>(?:[A-Za-z0-9_]+\s*=\s*)?)"(?P<val>.*)"(?P<suffix>\s*(?:#.*)?)$')


def sanitize_dictionary_token(raw_val: str) -> str:
    """
    Sanitize the string inside a dictionary entry's quotes for LibFuzzer.
    Converts raw backslashes and invalid escapes to valid hex escapes (\\xHH) or \\\\,
    and converts non-printable / control bytes to \\xHH.
    """
    out: list[str] = []
    i = 0
    n = len(raw_val)
    while i < n:
        c = raw_val[i]
        # Check for escape sequences
        if c == "\\":
            if i + 1 >= n:
                # Trailing backslash -> escape it
                out.append("\\\\")
                i += 1
                continue
            nxt = raw_val[i + 1]
            if nxt == "\\" or nxt == '"':
                out.append(c + nxt)
                i += 2
                continue
            if nxt in ("x", "X") and i + 3 < n and all(raw_val[i + k] in "0123456789abcdefABCDEF" for k in (2, 3)):
                out.append(f"\\x{raw_val[i + 2 : i + 4].lower()}")
                i += 4
                continue
            if nxt == "n":
                out.append("\\x0a")
                i += 2
                continue
            if nxt == "r":
                out.append("\\x0d")
                i += 2
                continue
            if nxt == "t":
                out.append("\\x09")
                i += 2
                continue
            if nxt == "0":
                out.append("\\x00")
                i += 2
                continue
            # Unknown escape like \a, \b, \p -> escape the backslash
            out.append("\\\\")
            i += 1
            continue

        # Check for non-printable or non-ASCII characters
        code = ord(c)
        if code < 32 or code >= 127:
            out.append(f"\\x{code & 0xFF:02x}")
        elif c == '"':
            out.append('\\"')
        else:
            out.append(c)
        i += 1

    return "".join(out)


def sanitize_dictionary_line(line: str) -> str:
    """Sanitize a single line in a LibFuzzer dictionary."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return line

    m = _DICT_LINE_RE.match(line)
    if m:
        prefix = m.group("prefix")
        val = m.group("val")
        suffix = m.group("suffix")
        return f'{prefix}"{sanitize_dictionary_token(val)}"{suffix}'

    # Line is not in standard `"..."` format; if it has `name = val` or just `val`
    if "=" in line:
        name, _, rest = line.partition("=")
        rest_val = rest.strip().strip('"')
        return f'{name.strip()} = "{sanitize_dictionary_token(rest_val)}"'
    else:
        rest_val = stripped.strip('"')
        return f'"{sanitize_dictionary_token(rest_val)}"'


def sanitize_dictionary_content(content: str) -> str:
    """Sanitize all entries in LibFuzzer dictionary content."""
    lines = content.splitlines(keepends=True)
    out: list[str] = []
    for line in lines:
        ending = "\n" if line.endswith("\n") else ""
        raw_line = line[:-1] if ending else line
        out.append(sanitize_dictionary_line(raw_line) + ending)
    return "".join(out)


def sanitize_fuzzer_dictionary(dict_path: Path, out_path: Path | None = None) -> Path:
    """Read a LibFuzzer dictionary, sanitize entries by escaping backslashes and non-printables, and write out."""
    dict_path = Path(dict_path)
    if not dict_path.is_file():
        return dict_path
    text = dict_path.read_text(encoding="utf-8", errors="replace")
    sanitized = sanitize_dictionary_content(text)
    if out_path is None:
        out_path = dict_path.with_name(f"{dict_path.stem}.sanitized{dict_path.suffix}")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(sanitized, encoding="utf-8")
    return out_path


AUTO_DICT_DIR = Path("workspace/dicts")


def _dict_stem(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._") or "module"


def auto_dictionary_path(module: str, corpus_dir: Path) -> Path:
    """Where `campaign` writes its auto-dictionary: workspace/dicts/<module>.dict, else next to the corpus."""
    if module:
        return AUTO_DICT_DIR / f"{_dict_stem(module)}.dict"
    corpus_dir = Path(corpus_dir)
    return corpus_dir.parent / f"{_dict_stem(corpus_dir.name)}.auto.dict"


def dictionary_target_sources(sources: list[str] | list[Path]) -> list[Path]:
    """The campaign's target sources for literal extraction: existing files, the harness excluded, sorted."""
    out: set[Path] = set()
    for s in sources or []:
        p = Path(s)
        if p.name.startswith("harness_") or not p.is_file():
            continue
        out.add(p)
    return sorted(out, key=lambda p: p.as_posix())


def build_auto_dictionary(sources: list[str] | list[Path], out_path: Path, cppflags: str | None = None) -> dict:
    """
    Extract a libFuzzer dictionary from the campaign's target sources (scripts/fuzz_dictionary.py, in-process)
    and write it atomically to `out_path`. Never raises: an empty or failed extraction returns
    `path: None` and a `reason`, and the campaign proceeds without a dictionary. The content depends only on
    the target sources' text (files sorted, tokens in a fixed order), so the same slice gives the same file.
    """
    out_path = Path(out_path)
    info: dict = {"path": None, "auto": True, "entries": 0}
    targets = dictionary_target_sources(sources)
    info["source_files"] = len(targets)
    if not targets:
        info["reason"] = "no readable target sources besides the harness"
        return info
    try:
        tokens = build_dictionary(sources=list(targets), cppflags=cppflags)
    except Exception as exc:  # never fail the campaign over a dictionary
        info["reason"] = f"extraction failed: {type(exc).__name__}: {exc}"
        return info
    if not tokens:
        info["reason"] = "extraction produced no tokens"
        return info
    content = render_dictionary(tokens)
    tmp: Path | None = None
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(out_path.parent), prefix=".tmp_", suffix=".dict")
        tmp = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        os.replace(tmp, out_path)
        tmp = None
    except OSError as exc:
        info["reason"] = f"could not write {out_path.as_posix()}: {exc}"
        return info
    finally:
        if tmp is not None:
            with contextlib.suppress(OSError):
                tmp.unlink()
    info.update(
        {
            "path": out_path.as_posix(),
            "entries": len(tokens),
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        }
    )
    return info


def resolve_campaign_dictionary(
    explicit: Path | None,
    sources: list[str],
    module: str,
    corpus_dir: Path,
    auto: bool = True,
    cppflags: str | None = None,
) -> tuple[Path | None, dict]:
    """The dictionary a campaign passes to libFuzzer as -dict=, and the report's `dictionary` record."""
    if explicit is not None:
        p = Path(explicit)
        return p, {"path": p.as_posix(), "auto": False, "exists": p.is_file()}
    if not auto:
        return None, {"path": None, "auto": False, "reason": "disabled by --no-auto-dict"}
    info = build_auto_dictionary(sources, auto_dictionary_path(module, corpus_dir), cppflags)
    extra = extra_dictionary_path(module)
    if extra is not None and extra.is_file():
        info = merge_extra_dictionary(info, extra)
    return (Path(info["path"]) if info.get("path") else None), info


def extra_dictionary_path(module: str) -> Path | None:
    """The target's shipped dictionary for `module` (workspace/dicts/<module>.extra.dict, scripts/fuzz_assets.py)."""
    return AUTO_DICT_DIR / f"{_dict_stem(module)}.extra.dict" if module else None


def _dictionary_entry_lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def merge_extra_dictionary(info: dict, extra: Path) -> dict:
    """
    Append the entries of the target's shipped dictionary `extra` to the auto-dictionary `info` describes
    (identical lines once) and record `extra_entries`. Without an auto-dictionary, `extra` is used alone.
    Never raises: an unreadable `extra` leaves `info` as it was, with an `extra_reason`.
    """
    info = dict(info)
    try:
        extra_lines = list(dict.fromkeys(_dictionary_entry_lines(extra.read_text(encoding="utf-8", errors="replace"))))
    except OSError as exc:
        info["extra_reason"] = f"could not read {extra.as_posix()}: {exc}"
        return info
    auto_path = Path(info["path"]) if info.get("path") else None
    if auto_path is None:
        info.update({"path": extra.as_posix(), "entries": len(extra_lines), "extra_entries": len(extra_lines)})
        return info
    try:
        auto_text = auto_path.read_text(encoding="utf-8", errors="replace")
        seen = set(_dictionary_entry_lines(auto_text))
        added = [ln for ln in extra_lines if ln not in seen]
        content = auto_text if auto_text.endswith("\n") or not auto_text else auto_text + "\n"
        content += "".join(f"{ln}\n" for ln in added)
        fd, tmp_name = tempfile.mkstemp(dir=str(auto_path.parent), prefix=".tmp_", suffix=".dict")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        os.replace(tmp_name, auto_path)
    except OSError as exc:
        info["extra_reason"] = f"could not merge {extra.as_posix()}: {exc}"
        return info
    info["entries"] = int(info.get("entries") or 0) + len(added)
    info["extra_entries"] = len(added)
    info["sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return info


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
        "--cppflags",
        default=None,
        help="Preprocess the C sources with these flags and add the project's macro values.",
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
        cppflags=args.cppflags,
    )

    write_dictionary(args.out_dict, tokens)
    return 0


if __name__ == "__main__":
    sys.exit(main())
