"""Parsing of E-ACSL, ASan, UBSan runtime failures and their fingerprints."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from acsl_ast import tokenize_c_acsl
from c_definitions import TYPE_MODIFIERS_AND_PRIMITIVES, extract_functions_from_code
from fingerprint import (
    detect_alarm_kind,
    detect_predicate_alarm_kind,
    make_fingerprint,
    normalize_file,
)
from generate_harness import DISPATCH_SKIP_FN, TARGET_EMBEDDED_PREFIX

# Frama-C >= 26 style:
#   foo.c: In function 'parse'
#   foo.c:42: Error: Assertion failed:
#           The failing predicate is:
#           mem_access: \valid_read(p + i).
# Frama-C 33 puts the label on its own line and the predicate one level deeper:
#           The failing predicate is:
#           rte/index_bound:
#               i < 8.
#           With values at failure point:
_FN_RE = re.compile(r"(?P<file>(?:[A-Za-z]:)?[^\s:'\"]+):\s*In function '(?P<function>[^']+)'")


_ERR_RE = re.compile(
    r"(?P<file>(?:[A-Za-z]:)?[^\s:'\"]+):(?P<line>\d+)(?::\d+)?:\s*Error:\s*(?P<kind>[A-Za-z][A-Za-z _-]*?)\s+failed:?",
    re.IGNORECASE,
)


# Older style: "Assertion failed at line 42 in file foo.c." / "... in function parse."
_OLD_RE = re.compile(
    r"(?P<kind>[A-Za-z][A-Za-z _-]*?)\s+failed at line (?P<line>\d+)"
    r"(?:\s+in\s+file\s+(?P<file>(?:[A-Za-z]:)?[^\s:'\"]+?)(?:\.?(?=\s+in\s+function)|\.(?=\s|$)|(?=\s|$)))?"
    r"(?:\s+in\s+function\s+(?P<function>\w+))?",
    re.IGNORECASE,
)


_PRED_HEAD_RE = re.compile(r"The failing predicate is:[ \t]*", re.IGNORECASE)


# E-ACSL segment memory model runtime messages, e.g.
#   Use of invalid address 0x7f... in unsafe_initialize
_SEGMENT_RE = re.compile(
    r"(?P<msg>Use of invalid address|Invalid (?:read|write|access)|Out of bounds access)[^\n]*?"
    r"(?:\bin\s+(?:function\s+)?'?(?P<function>[A-Za-z_]\w*)'?)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)


# Functions that belong to the E-ACSL runtime or sanitizer runtimes, never to the target.
_RUNTIME_FN_PREFIXES = (
    "__e_acsl",
    "eacsl_",
    "__eacsl",
    "e_acsl_",
    "unsafe_",
    "__asan",
    "__ubsan",
    "__sanitizer",
    "__interceptor",
    "__lsan",
    "fuzzer::",
)


_RUNTIME_FILE_MARKERS = ("e-acsl/", "e_acsl", "/share/frama-c/", "compiler-rt", "libsanitizer", "libfuzzer")


def is_runtime_function(name: str | None, file_: str | None = None) -> bool:
    """True if `name`/`file_` belongs to the E-ACSL RTL or a sanitizer runtime."""
    if name and name.startswith(_RUNTIME_FN_PREFIXES):
        return True
    low = (file_ or "").replace("\\", "/").lower()
    return any(marker in low for marker in _RUNTIME_FILE_MARKERS)


# UBSan format:
#   SyncMem.c:819:9: runtime error: index 1025 out of bounds for type 'char[1024]'
_UBSAN_RE = re.compile(
    r"(?P<file>(?:[A-Za-z]:)?[^\s:'\"]+):(?P<line>\d+)(?::\d+)?:\s*runtime error:\s*(?P<pred>[^\n]+)",
    re.IGNORECASE,
)


# A runtime value in a UBSan message: an integer, a hex address, a float. Not inside a quoted type.
_UBSAN_VALUE_RE = re.compile(r"(?<![\w.])[-+]?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)(?![\w.])")


def stable_ubsan_message(message: str) -> str:
    """
    A UBSan message with its runtime values replaced by `N`: `left shift of negative value -2806`
    and `... -19345` are one defect, and the predicate feeds the fingerprint. Quoted type names
    (`'char[1024]'`) are static and stay.
    """
    parts = re.split(r"('[^']*')", message)
    return "".join(p if p.startswith("'") else _UBSAN_VALUE_RE.sub("N", p) for p in parts)


# ASan header:
#   ==123==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...
_ASAN_ERR_RE = re.compile(
    r"ERROR:\s*AddressSanitizer:\s*(?P<kind>"
    r"attempting double-free"
    r"|attempting free on address which was not malloc\(\)-ed"
    r"|requested allocation size"
    r"|[A-Za-z0-9_-]+)",
    re.IGNORECASE,
)


_ASAN_OP_RE = re.compile(
    r"^(?P<op>READ|WRITE)(?:\s+of\s+size\s+\d+)?",
    re.MULTILINE,
)

# UBSan standalone deadly-signal header (printed when ASan is absent, e.g. E-ACSL builds):
#   UndefinedBehaviorSanitizer:DEADLYSIGNAL
#   ==7==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x... (pc 0x... T7)
#   ==7==The signal is caused by a READ memory access.
_UBSAN_ERR_RE = re.compile(
    r"ERROR:\s*UndefinedBehaviorSanitizer:\s*(?P<kind>[A-Za-z0-9_-]+)(?P<rest>[^\n]*)",
    re.IGNORECASE,
)

_SIGNAL_OP_RE = re.compile(
    r"The signal is caused by a (?P<op>READ|WRITE) memory access\.",
    re.IGNORECASE,
)

_UBSAN_SUMMARY_RE = re.compile(
    r"^SUMMARY:\s*UndefinedBehaviorSanitizer:\s*(?P<kind>(?!undefined-behavior\b)[A-Za-z0-9_-]+)"
    r"(?:\s+(?P<file>(?:[A-Za-z]:)?[^\s():]+):(?P<line>\d+)(?::\d+)?)?"
    r"(?:\s+in\s+(?P<function>[A-Za-z_][A-Za-z0-9_]*))?",
    re.IGNORECASE | re.MULTILINE,
)


# Sanitizer stack frame:
#   #0 0x555555 in UpdateSyncMem /path/to/SyncMem.c:827:5
# C++ names keep their scope (`fuzzer::PrintStackTrace()`, libFuzzer's own frames in a deadly-signal
# stack), so `fuzzer::` matches _RUNTIME_FN_PREFIXES instead of leaving a function named `fuzzer`.
_STACK_FRAME_RE = re.compile(
    r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(?P<function>[A-Za-z_][A-Za-z0-9_]*(?:::~?[A-Za-z_][A-Za-z0-9_]*)*)"
    r"(?:\s+(?P<file>(?:[A-Za-z]:)?[^\s():]+):(?P<line>\d+)(?::\d+)?)?"
)


def _map_sanitizer_alarm_kind(kind_or_msg: str) -> str:
    low = (kind_or_msg or "").lower()
    if "out of bounds" in low:
        return "index_bound"
    if "signed integer overflow" in low or "cannot be represented in type" in low:
        return "signed_overflow"
    if "unsigned integer overflow" in low:
        return "unsigned_overflow"
    if "shift" in low:
        return "shift"
    if "division by zero" in low or "divide by zero" in low or "fpe" in low:
        return "division_by_zero"
    if "overlap" in low:
        return "separation"
    if "use-after-free" in low or "use-after-scope" in low or "use-after-return" in low:
        return "dangling_pointer"
    if "bad-free" in low or "attempting free" in low or "double-free" in low:
        return "freeable"
    if "bool" in low:
        return "bool_value"
    if "nan" in low or "inf" in low:
        return "is_nan_or_infinite"
    return "mem_access"


def _resolve_source_candidates(file_path: str) -> list[Path]:
    """Return existing source file paths matching `file_path` in the workspace or current directory."""
    if not file_path:
        return []
    norm = normalize_file(file_path)
    candidates: list[Path] = []
    for cand in (
        Path(file_path),
        Path(norm),
        Path("workspace/work") / norm,
        Path("workspace/baseline") / norm,
    ):
        if cand.is_file() and cand not in candidates:
            candidates.append(cand)
    if not candidates and Path("workspace/work").is_dir():
        bname = Path(norm).name
        matches = list(Path("workspace/work").rglob(bname))
        if len(matches) == 1:
            candidates.append(matches[0])
    return candidates


def _is_acsl_annotation_line(file_path: str, line: int) -> bool:
    """
    True if `file_path:line` resolves to a source line containing only ACSL annotations
    (`/*@ ... */` or `//@ ...`) and no executable C tokens.

    Frama-C `-rte` attaches synthesized runtime assertions in-memory to executable C AST
    statements without modifying the source file on disk, so a true C-code RTE always points
    to a line with executable C tokens, whereas a user/agent-written `/*@ assert ... */` or
    contract clause points to an ACSL annotation line (or an `.acsl` specification file).
    """
    if not file_path or line <= 0:
        return False
    if file_path.lower().endswith(".acsl"):
        return True
    for cpath in _resolve_source_candidates(file_path):
        try:
            raw = cpath.read_text(encoding="utf-8", errors="replace")
            has_acsl = False
            has_c_code = False
            for tok in tokenize_c_acsl(raw):
                tok_start = tok.line
                tok_end = tok.line + tok.text.count("\n")
                if tok_start <= line <= tok_end:
                    if tok.kind in ("acsl_block", "acsl_line"):
                        has_acsl = True
                    elif tok.kind in ("c_token", "string", "char"):
                        has_c_code = True
            return has_acsl and not has_c_code
        except Exception:
            continue
    return False


def _resolve_function_at_line(file_path: str, line: int) -> str:
    """Resolve the enclosing C function at `file_path:line` using token-based span extraction."""
    if not file_path or line <= 0:
        return "unknown_function"
    for cpath in _resolve_source_candidates(file_path):
        try:
            raw = cpath.read_text(encoding="utf-8", errors="replace")
            for fn in extract_functions_from_code(raw, path=str(cpath)):
                name = fn.get("name") or ""
                if name in TYPE_MODIFIERS_AND_PRIMITIVES:
                    continue
                if int(fn.get("line", 0)) <= line <= int(fn.get("end_line", 0)):
                    return name or "unknown_function"
        except Exception:
            continue
    return "unknown_function"


def normalized_source_line(file_path: str, line: int) -> str | None:
    """
    The text of line `line` of the first source file `file_path` resolves to, stripped, with each run
    of whitespace replaced by one space. None when `line` is not positive, no file resolves, or the
    file is shorter than `line`.
    """
    if line <= 0:
        return None
    candidates = _resolve_source_candidates(file_path)
    if not candidates:
        return None
    try:
        lines = candidates[0].read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if line > len(lines):
        return None
    return " ".join(lines[line - 1].split())


def line_text_hash(file_path: str, line: int) -> str | None:
    """The first 10 hex digits of the sha256 of the normalized text of `file_path:line`, or None."""
    text = normalized_source_line(file_path, line)
    if text is None:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]


def site_key(
    file: str,
    function: str,
    line: int,
    fn_range: tuple[int, int] | None = None,
) -> str | None:
    """
    The statement site of a failure (D1a): `<file>#<function>@<h>`, `<h>` the line text hash, so that
    inserting lines above keeps it. When `fn_range` (first and last line of the function) is given and
    the same normalized text occurs more than once in that range, `#<n>` counts the occurrences from
    the first line of the range down to `line` (so two identical lines in one function are two sites).
    None when the line text cannot be read.
    """
    text = normalized_source_line(file, line)
    if text is None:
        return None
    key = f"{normalize_file(file)}#{function}@{line_text_hash(file, line)}"
    if fn_range is None:
        return key
    first, last = fn_range
    source = _normalized_source_lines(file)
    if source is None:
        return key
    in_range = [i for i in range(max(first, 1), min(last, len(source)) + 1) if source[i - 1] == text]
    if len(in_range) <= 1 or line not in in_range:
        return key
    return f"{key}#{in_range.index(line) + 1}"


def _normalized_source_lines(file_path: str) -> list[str] | None:
    """Every line of the first source file `file_path` resolves to, normalized as `normalized_source_line`."""
    candidates = _resolve_source_candidates(file_path)
    if not candidates:
        return None
    try:
        lines = candidates[0].read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    return [" ".join(raw.split()) for raw in lines]


def is_harness_fuzz_function(name: str) -> bool:
    """
    The harness's own fuzz entry, runtime dispatch-skip helper, or a target fuzzer's hook it calls
    (renamed with the `__framac_target_embedded_` prefix by generate_harness.py --target-fuzzer):
    harness code, so never selected for RTE/E-ACSL and never a crash location.
    """
    return name in ("LLVMFuzzerTestOneInput", DISPATCH_SKIP_FN) or name.startswith(TARGET_EMBEDDED_PREFIX)


def _parse_segment_failure(text: str) -> dict | None:
    """E-ACSL segment-model runtime message; location from the first non-runtime stack frame, if any."""
    seg = _SEGMENT_RE.search(text)
    if not seg:
        return None
    msg = seg.group("msg").strip()
    reported_fn = seg.group("function") or ""
    file_, line_, function = "unknown", 0, "unknown_function"
    for m in _STACK_FRAME_RE.finditer(text):
        fn, fpath = m.group("function"), m.group("file")
        if (
            is_runtime_function(fn, fpath)
            or (fpath and Path(fpath).name.startswith("harness_"))
            or is_harness_fuzz_function(fn)
        ):
            continue
        file_, line_, function = fpath or "unknown", int(m.group("line")) if m.group("line") else 0, fn
        break
    if function == "unknown_function" and reported_fn and not is_runtime_function(reported_fn):
        function = reported_fn
    detail = f" in {reported_fn}" if reported_fn else ""
    return {
        "file": file_,
        "line": line_,
        "function": function,
        "kind": "eacsl_runtime_error",
        "alarm_kind": "mem_access",
        "is_rte": True,
        "predicate": f"rte: mem_access: {msg}{detail}",
    }


# Reports of E-ACSL's libc replacements (--libc-replacements, share/e-acsl/libc_replacements/e_acsl_string.c)
# and format-string checks (--validate-format-strings, e_acsl_stdio.c). The runtime prints one bare line,
# `<function>: <message>` or `Format error: <message>`, then aborts: no file, line or failing predicate.
# A closed list of the runtime's templates, anchored at a line start, so target output of the same shape
# is not read as one. Each entry: (template, alarm kind or None, failure kind, stable predicate). The stable
# predicate drops sizes, directive numbers and the format string, which vary from input to input and feed
# the fingerprint; type names in a mismatch stay.
_LIBC_FN = r"(?P<func>[A-Za-z_]\w*): "


_LIBC_TEMPLATES: tuple[tuple[re.Pattern[str], str | None, str, str], ...] = tuple(
    (re.compile(r"^" + rx + r"\s*$", re.MULTILINE), alarm, kind, stable)
    for rx, alarm, kind, stable in (
        (
            _LIBC_FN + r"(?P<desc>(?:\w+ )*)string unallocated",
            "mem_access",
            "eacsl_libc_error",
            "{func}: {desc}string unallocated",
        ),
        (
            _LIBC_FN + r"(?P<desc>(?:\w+ )*)string is not writable",
            "mem_access",
            "eacsl_libc_error",
            "{func}: {desc}string is not writable",
        ),
        (
            _LIBC_FN + r"(?P<desc>(?:\w+ )*)string has insufficient length",
            "mem_access",
            "eacsl_libc_error",
            "{func}: {desc}string has insufficient length",
        ),
        (
            _LIBC_FN + r"(?P<desc>(?:\w+ )*)string not NUL-terminated",
            "valid_string",
            "eacsl_libc_error",
            "{func}: {desc}string not NUL-terminated",
        ),
        (
            _LIBC_FN + r"unallocated \(or insufficient\) space in (?P<space>.+?)",
            "mem_access",
            "eacsl_libc_error",
            "{func}: unallocated (or insufficient) space in {space}",
        ),
        (
            _LIBC_FN + r"insufficient space in (?P<space>.+?)\s*, at least \d+ bytes required",
            "mem_access",
            "eacsl_libc_error",
            "{func}: insufficient space in {space}",
        ),
        (
            _LIBC_FN + r"insufficient space in destination string, available: \d+ bytes, requires at least \d+ bytes",
            "mem_access",
            "eacsl_libc_error",
            "{func}: insufficient space in destination string",
        ),
        (
            _LIBC_FN + r"(?P<space>.+?) space unallocated or cannot be written",
            "mem_access",
            "eacsl_libc_error",
            "{func}: {space} space unallocated or cannot be written",
        ),
        (_LIBC_FN + r"overlapping memory areas", "separation", "eacsl_libc_error", "{func}: overlapping memory areas"),
        (
            _LIBC_FN
            + r"directive \d+ \(.*\) expects argument of type '(?P<exp>[^']*)' but the corresponding argument has type '(?P<act>[^']*)'",
            None,
            "eacsl_format_error",
            "{func}: directive expects argument of type '{exp}' but the corresponding argument has type '{act}'",
        ),
        (
            _LIBC_FN + r"attempt to access (?P<part>(?:partially )?)unallocated memory via directive \d+ \(.*\)",
            "mem_access",
            "eacsl_format_error",
            "{func}: attempt to access {part}unallocated memory via a directive",
        ),
        (
            _LIBC_FN + r"unterminated string in directive \d+ \(.*\)",
            "valid_string",
            "eacsl_format_error",
            "{func}: unterminated string in a directive",
        ),
        (
            _LIBC_FN + r"output buffer overlaps with argument \d+ \(.*\)",
            "separation",
            "eacsl_format_error",
            "{func}: output buffer overlaps with an argument",
        ),
        (
            _LIBC_FN + r"invalid format string \(unallocated or unterminated\)",
            "valid_string",
            "eacsl_format_error",
            "{func}: invalid format string (unallocated or unterminated)",
        ),
        (
            _LIBC_FN + r"directive \d+ \(.*\) in format \".*\" has no argument",
            None,
            "eacsl_format_error",
            "{func}: directive in format has no argument",
        ),
        (
            _LIBC_FN + r"argument \d+ of directive \S+ not allocated(?P<w>(?: or writeable)?)",
            "mem_access",
            "eacsl_format_error",
            "{func}: argument of a directive not allocated{w}",
        ),
        (
            _LIBC_FN
            + r"attempt to write to (?P<what>an invalid stream|a closed stream|a closed file descriptor)(?: -?\d+)?",
            None,
            "eacsl_format_error",
            "{func}: attempt to write to {what}",
        ),
        (
            _LIBC_FN + r"output buffer is unallocated or has insufficient length to store \d+ characters.*",
            "mem_access",
            "eacsl_format_error",
            "{func}: output buffer is unallocated or has insufficient length",
        ),
        (r"(?P<func>)Format error: (?P<msg>.+?)", None, "eacsl_format_error", "Format error: {msg}"),
    )
)


# A quoted directive, format string or flag in a `Format error:` message, and the numbers in it.
_LIBC_QUOTED_RE = re.compile(r"\"[^\"]*\"|'[^']*'|\([^)]*\)")


_EACSL_GEN_PREFIX = "__gen_e_acsl_"


def _caller_of_eacsl_runtime(text: str) -> tuple[str, str]:
    """
    (function, `file:line`) of the first stack frame after the innermost E-ACSL runtime frame: the
    target code that called the checked libc function. libFuzzer and libc frames come first in a
    deadly-signal stack (`fuzzer::PrintStackTrace`, `raise`), so the first non-runtime frame is not it.
    The file is the instrumented source, whose line numbers mean nothing in the target's sources.
    """
    frames = list(_STACK_FRAME_RE.finditer(text))
    last_rt = -1
    for i, m in enumerate(frames):
        fn, fpath = m.group("function"), m.group("file") or ""
        if fn.startswith(("__e_acsl", "private_abort", "raise_abort", "vabort")) or "e-acsl/" in fpath.replace(
            "\\", "/"
        ):
            last_rt = i
    if last_rt < 0:
        return "", ""
    for m in frames[last_rt + 1 :]:
        fn = m.group("function")
        if is_runtime_function(fn, m.group("file")) or is_harness_fuzz_function(fn):
            continue
        where = f"{m.group('file')}:{m.group('line')}" if m.group("file") and m.group("line") else ""
        return fn.removeprefix(_EACSL_GEN_PREFIX), where
    return "", ""


def _parse_libc_failure(text: str) -> dict | None:
    """
    A report of E-ACSL's libc replacements or format-string checks. It has no location: `file` is
    `unknown` and `line` 0, so the campaign replays the input on its sanitizer build for one (ASan
    locates the memory errors, not the format errors). `function` is the caller found in the stack,
    when libFuzzer printed one.
    """
    best: tuple[int, re.Match[str], str | None, str, str] | None = None
    for rx, alarm, kind, stable in _LIBC_TEMPLATES:
        m = rx.search(text)
        if m and (best is None or m.start() < best[0]):
            best = (m.start(), m, alarm, kind, stable)
    if best is None:
        return None
    _, m, alarm, kind, stable = best
    groups = {k: (v or "") for k, v in m.groupdict().items()}
    if "msg" in groups:
        groups["msg"] = re.sub(r"\d+", "N", _LIBC_QUOTED_RE.sub("…", groups["msg"]))
    message = m.group(0).strip()
    function, where = _caller_of_eacsl_runtime(text)
    res: dict = {
        "file": "unknown",
        "line": 0,
        "function": function or "unknown_function",
        "kind": kind,
        "alarm_kind": alarm,
        "is_rte": True,
        "label": "",
        "predicate": stable.format(**groups),
        "message": message,
    }
    if where:
        res["instrumented_location"] = where
    if frozenset((groups.get("exp", ""), groups.get("act", ""))) in _SIGNEDNESS_PAIRS:
        # A signed/unsigned pair of one rank. The patched runtime (EACSL_FORMAT_RUNTIME_PATCH) lets it
        # through when the value fits both types, so this abort means it did not (a negative int for %u),
        # or the build ran without the patch (`runtime_patches` in the compile report). Informational only.
        res["format_mismatch"] = "signedness"
    return res


_SIGNEDNESS_PAIRS = frozenset(frozenset((t, f"unsigned {t}")) for t in ("int", "long", "long long"))


def _failing_predicate(text: str, start: int) -> tuple[str, str]:
    """
    (label, predicate) of the first "The failing predicate is:" block after `start`. The label is
    the property name or RTE kind (`rte/index_bound`, `range`); the predicate is the expression
    alone, as Eva and WP print it, so the same property fingerprints the same in every tool.
    """
    head = _PRED_HEAD_RE.search(text, start)
    if not head:
        return "", ""
    first, _, rest = text[head.end() :].partition("\n")
    lines = rest.split("\n")
    if not first.strip() and lines and lines[0].strip():
        first, lines = lines[0], lines[1:]  # the line after the header, indented or not (older releases)
    block = [first.strip()] if first.strip() and not first.strip().lower().startswith("with values") else []
    for line in lines if block else []:
        # Continuation lines are indented; the values section or unindented runtime output ends the block.
        if not line[:1].isspace() or not line.strip() or line.strip().lower().startswith("with values"):
            break
        block.append(line.strip())
    if len(block) >= 2 and block[0].endswith(":"):
        return block[0][:-1].strip(), " ".join(block[1:]).rstrip(".").strip()
    joined = " ".join(block).rstrip(".").strip()
    m = re.match(r"^(?P<label>[A-Za-z_][\w/-]*)\s*:\s*(?P<pred>.+)$", joined)
    if m and not m.group("pred").startswith(":"):  # one-line `label: predicate` (older releases)
        return m.group("label"), m.group("pred").strip()
    return "", joined


# A check of an annotation MetAcsl generated from a meta-property of the run (scripts/security_props.py,
# loaded into the E-ACSL build by fuzz_build.resolve_security_meta): E-ACSL names it `<property>/meta`
# and locates it in the meta file, at the property's line:
#   out/fuzz_m.security_meta.c: In function 'backdoor'
#   out/fuzz_m.security_meta.c:9: Error: Assertion failed:
#           The failing predicate is:
#           L4_auth_state_login/meta:
#               \separated(state, &auth_ok).
_META_LABEL_RE = re.compile(r"^(?P<name>[A-Za-z_]\w*)/meta$")
# The meta file of an E-ACSL build, next to its binary: `<out>.security_meta.c`.
SECURITY_META_SUFFIX = ".security_meta.c"


def meta_sidecar_path(meta_file: str | Path) -> Path:
    """
    `<out>.security_meta.json`, which the build writes next to its meta file `<out>.security_meta.c`:
    {props, meta_file, properties: {name: {obligation_class, instances}}, functions: {name: [file]},
    harness_functions: [name], line_names}. `functions` maps each function the module's sources
    define to its file, as the ledger names it; `harness_functions` are the ones the harness defines.
    """
    return Path(meta_file).with_suffix(".json")


_META_SIDECARS: dict[str, tuple[int, dict]] = {}


def _meta_sidecar(meta_file: str, binary: str | Path | None = None) -> dict:
    """
    The sidecar of a meta file, {} when there is none to read (a report parsed away from its build).
    The binary prints the meta file's path as its build was given it, relative to the build's working
    directory. With `binary`, the binary that printed it, the sidecar is first looked for next to that
    binary, where its build wrote it: a replay started in another directory (`replay --binary
    <run>/workspace/harnesses/fuzz_m.e-acsl`) finds it there and nowhere else. The path as printed is
    the fallback (a binary copied away from its build).
    """
    if not meta_file.endswith(SECURITY_META_SUFFIX):
        return {}
    printed = meta_sidecar_path(meta_file)
    places = [Path(binary).parent / printed.name, printed] if binary is not None else [printed]
    for path in places:
        try:
            stamp = path.stat().st_mtime_ns
        except OSError:
            continue
        break
    else:
        return {}
    cached = _META_SIDECARS.get(str(path))
    if cached is not None and cached[0] == stamp:
        return cached[1]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    _META_SIDECARS[str(path)] = (stamp, data)
    return data


def _meta_guarded_property(file_: str, line_: int, binary: str | Path | None = None) -> str:
    """The property written at `line_` of meta file `file_` (the sidecar's `line_names`), '' when unknown."""
    names = _meta_sidecar(file_, binary).get("line_names")
    name = names.get(str(line_)) if isinstance(names, dict) else None
    return name if isinstance(name, str) else ""


def _meta_class(name: str) -> str | None:
    """The obligation class a property's name spells (run_wp_function.goal_obligation_class), or None."""
    from run_wp_function import goal_obligation_class  # here: run_wp_function is not needed to parse anything else

    cls = goal_obligation_class({"kind": "", "annotation": f"{name}: meta:"})
    return None if cls == "rte" else cls


def _wrapper_caller(text: str, function: str) -> str:
    """
    The function that called `function` when its `requires` failed: the frame after E-ACSL's contract
    wrapper `__gen_e_acsl_<function>` in the stack libFuzzer prints, '' without one.
    """
    frames = list(_STACK_FRAME_RE.finditer(text))
    for i, m in enumerate(frames[:-1]):
        if m.group("function") == _EACSL_GEN_PREFIX + function:
            return frames[i + 1].group("function").removeprefix(_EACSL_GEN_PREFIX)
    return ""


def _meta_failure(
    text: str,
    name: str,
    meta_file: str,
    meta_line: int,
    function: str,
    kind: str,
    predicate: str,
    binary: str | Path | None = None,
) -> dict:
    """
    The failure of a run-time check of meta-property `name`. Its identity is the property and the
    function it failed in, never the meta file (a path of the build, another one in a replay):
      file         the source file of `function` (the build's sidecar), `unknown` when it cannot be told;
      line         0: the reported line is the property's, in the meta file (`meta_location`);
      kind         as E-ACSL reports it (assertion, precondition, postcondition);
      alarm_kind   `meta_<property>`, the kind slot of the fingerprint: it names the property, whose
                   name starts with its class (`L4_auth_state_login`); a class the name does not
                   spell is written in front (`meta_<class>_<property>`);
      predicate    `<property>: meta: <predicate>`, the form of a WP goal of the same property
                   (run_wp_function.name_meta_goal), which goal_obligation_class maps to the class;
      meta_property, obligation_class   for the ledger.
    A failed `requires` is reported in the function that has it. `caller` is the function that
    called it, and `harness_induced` says the caller is harness code: the harness reached a
    protected function without what its callers in the target establish, which is no defect of the
    target (the build leaves such a property out when it can tell: fuzz_build.resolve_security_meta).
    `binary` is the binary whose output `text` is, when the caller knows it (`_meta_sidecar`).
    """
    side = _meta_sidecar(meta_file, binary)
    props = side.get("properties")
    prop = props.get(name) if isinstance(props, dict) else None
    cls = (prop.get("obligation_class") if isinstance(prop, dict) else None) or _meta_class(name)
    functions = side.get("functions")
    files = functions.get(function) if isinstance(functions, dict) else None
    files = files if isinstance(files, list) else []
    harness = side.get("harness_functions")
    res: dict = {
        "file": str(files[0]) if len(files) == 1 else "unknown",
        "line": 0,
        "function": function,
        "kind": kind,
        "alarm_kind": f"meta_{name}" if not cls or str(cls) in name.lower() else f"meta_{cls}_{name}",
        "is_rte": False,
        "label": f"{name}/meta",
        "predicate": f"{name}: meta: {predicate}",
        "meta_property": name,
        "obligation_class": cls,
        "meta_location": f"{meta_file}:{meta_line}",
    }
    if kind == "precondition":
        caller = _wrapper_caller(text, function)
        if caller:
            res["caller"] = caller
            res["harness_induced"] = is_harness_fuzz_function(caller) or (
                isinstance(harness, list) and caller in harness
            )
    return res


def parse_eacsl_failure(text: str, *, binary: str | Path | None = None) -> dict | None:
    """
    Extract the first E-ACSL failure (file, line, function, kind, label, predicate) from runtime output.
    A failed check of a MetAcsl property is described by `_meta_failure`; `binary`, the binary that
    printed `text`, lets it find the build's sidecar when the output is parsed in another directory
    than the build's.
    """
    if not text:
        return None
    err = _ERR_RE.search(text)
    old = None if err else _OLD_RE.search(text)
    hit = err or old
    if not hit:
        return _parse_libc_failure(text) or _parse_segment_failure(text)
    file_ = (hit.group("file") or "").rstrip(".")
    line_ = int(hit.group("line"))
    function = hit.groupdict().get("function") or ""
    if not function:
        fns = [m for m in _FN_RE.finditer(text) if m.start() <= hit.start()]
        if fns:
            function = fns[-1].group("function")
            file_ = file_ or fns[-1].group("file")
    if not function or function == "unknown_function":
        function = _resolve_function_at_line(file_, line_)
    label, predicate = _failing_predicate(text, hit.end())
    kind = hit.group("kind").strip().lower().replace(" ", "_")
    meta = _META_LABEL_RE.match(label)
    if meta:
        return _meta_failure(
            text, meta.group("name"), file_ or "unknown", line_, function or "unknown_function", kind, predicate, binary
        )
    guarded = _meta_guarded_property(file_, line_, binary)
    if guarded:
        # A guard E-ACSL puts on the evaluation of a property's predicate (`\valid_read` of what it
        # reads, an index of its quantifier) failed: it has the property's line and no `/meta` label.
        guard = _meta_failure(
            text, guarded, file_, line_, function or "unknown_function", kind, f"guard {label}: {predicate}", binary
        )
        guard["meta_guard"] = label
        return guard
    # A label names the alarm; inside the predicate only a label-like use counts, never an identifier.
    alarm = detect_alarm_kind(label) or detect_predicate_alarm_kind(predicate)
    explicit_rte_prefix = label.lower().startswith("rte") or predicate.lower().startswith("rte")
    has_rte_marker = bool(alarm) or explicit_rte_prefix
    on_acsl_line = _is_acsl_annotation_line(file_, line_)
    annotation_rte = (
        (kind == "rte") or (on_acsl_line and has_rte_marker) or (kind != "assertion" and explicit_rte_prefix)
    )
    is_rte = (kind == "assertion") and has_rte_marker and not on_acsl_line
    res: dict = {
        "file": file_ or "unknown",
        "line": line_,
        "function": function or "unknown_function",
        "kind": kind,
        "alarm_kind": alarm or None,
        "is_rte": is_rte,
        "label": label,
        "predicate": predicate,
    }
    if annotation_rte:
        res["annotation_rte"] = True
    return res


# LeakSanitizer, at exit of a run that leaked:
#   ==1==ERROR: LeakSanitizer: detected memory leaks
#   Direct leak of 16 byte(s) in 1 object(s) allocated from:
#       #0 0x... in malloc ...
#       #1 0x... in make_buf src/demo.c:5:14
_LSAN_ERR_RE = re.compile(r"ERROR:\s*LeakSanitizer:\s*detected memory leaks")
_LSAN_BLOCK_RE = re.compile(
    r"^(?P<kind>Direct|Indirect) leak of \d+ byte\(s\) in \d+ object\(s\) allocated from:", re.M
)

# The allocators a leak's stack starts in: the defect is the caller that kept the object.
_LSAN_ALLOCATORS = frozenset(
    (
        "malloc",
        "calloc",
        "realloc",
        "reallocarray",
        "strdup",
        "strndup",
        "aligned_alloc",
        "posix_memalign",
        "memalign",
        "valloc",
    )
)


def _is_target_frame(frame: re.Match[str]) -> bool:
    """
    A frame of the target's own code. A libc call the sanitizer intercepts prints under its plain name
    and without a source location (`#0 0x1 in free (/tmp/prog+0xcdefa)`), at times behind the runtime's
    helpers (`#0 0x1 in StrstrCheck(...) asan_interceptors.cpp.o`). The source location is what tells it
    from a function of the target that has the same name.
    """
    fn, file_ = frame.group("function"), frame.group("file")
    if not file_:
        return False
    return not (
        is_runtime_function(fn, file_) or Path(file_).name.startswith("harness_") or is_harness_fuzz_function(fn)
    )


def _first_stack(frames: list[re.Match[str]], start: int) -> list[re.Match[str]]:
    """The frames of the first stack printed after offset `start`: a report's later stacks start at `#0` again."""
    stack: list[re.Match[str]] = []
    for frame in frames:
        if frame.start() < start:
            continue
        if stack and frame.group(0).split()[0] == "#0":
            break
        stack.append(frame)
    return stack


def _parse_leak_failure(text: str) -> dict | None:
    """
    The first LeakSanitizer block of a report: the first `Direct leak`, else the first `Indirect leak`.
    Its location is the first frame of its allocation stack that is no runtime, harness or allocator
    frame and has a source location, else the first such frame without one (a libc call that allocates,
    such as `realpath`, is no location while its caller is on the stack). A leak links no obligation
    class (`alarm_kind` memory_leak, CWE-401 in the verifier brief).
    """
    blocks = list(_LSAN_BLOCK_RE.finditer(text))
    if not blocks or not _LSAN_ERR_RE.search(text):
        return None
    block = next((b for b in blocks if b.group("kind") == "Direct"), blocks[0])
    stack_lines: list[str] = []
    for line in text[block.end() :].split("\n")[1:]:  # [0] is the rest of the header line
        if not line.strip():
            break
        stack_lines.append(line)
    usable: list[re.Match[str]] = []
    for m in _STACK_FRAME_RE.finditer("\n".join(stack_lines)):
        fn, fpath = m.group("function"), m.group("file") or ""
        base = re.sub(r"^__interceptor_", "", fn)
        if (
            is_runtime_function(fn, fpath)
            or Path(fpath).name.startswith("harness_")
            or is_harness_fuzz_function(fn)
            or base in _LSAN_ALLOCATORS
        ):
            continue
        usable.append(m)
    frame = next((m for m in usable if m.group("file")), usable[0] if usable else None)
    file_ = (frame.group("file") or "unknown") if frame else "unknown"
    line_ = int(frame.group("line") or 0) if frame else 0
    fn = frame.group("function") if frame else "unknown_function"
    which = block.group("kind").lower()
    pred = f"memory_leak: LeakSanitizer: {which} leak allocated in {fn}"
    line_hash = line_text_hash(file_, line_)
    if line_hash is not None:
        pred += f" [line {line_hash}]"
    return {
        "file": file_,
        "line": line_,
        "function": fn,
        "kind": f"lsan_{which}_leak",
        "alarm_kind": "memory_leak",
        "is_rte": False,
        "predicate": pred,
    }


def parse_sanitizer_failure(text: str) -> dict | None:
    """Extract the first UBSan or ASan runtime failure from LibFuzzer/sanitizer output."""
    if not text:
        return None

    frames = list(_STACK_FRAME_RE.finditer(text))
    non_harness_frames = [
        m
        for m in frames
        if (not m.group("file") or not Path(m.group("file")).name.startswith("harness_"))
        and not m.group("function").startswith(
            (
                "__interceptor_",
                "__asan_",
                "__ubsan_",
                "__sanitizer_",
                "fuzzer::",
                "LLVMFuzzerTestOneInput",
                TARGET_EMBEDDED_PREFIX,
            )
        )
    ]
    candidates = non_harness_frames or frames
    best_frame: re.Match[str] | None = candidates[0] if candidates else None

    ub = _UBSAN_RE.search(text)
    if ub:
        file_ = ub.group("file")
        line_ = int(ub.group("line"))
        pred = ub.group("pred").strip().rstrip(".")
        fn = "unknown_function"
        for m in frames:
            f = m.group("file")
            line_str = m.group("line")
            if f and line_str and Path(f).name == Path(file_).name and int(line_str) == line_:
                fn = m.group("function")
                break
        if fn == "unknown_function" and best_frame is not None:
            fn = best_frame.group("function")
        if fn == "unknown_function":
            fn = _resolve_function_at_line(file_, line_)
        alarm = _map_sanitizer_alarm_kind(pred)
        return {
            "file": file_,
            "line": line_,
            "function": fn,
            "kind": "ubsan_runtime_error",
            "alarm_kind": alarm,
            "is_rte": True,
            # Values out of the predicate (it is fingerprinted); the message as printed stays apart.
            "predicate": f"rte: {alarm}: {stable_ubsan_message(pred)}",
            "message": pred,
        }

    asan = _ASAN_ERR_RE.search(text)
    if asan:
        asan_kind = asan.group("kind").strip()
        op_m = _ASAN_OP_RE.search(text, asan.end()) or _SIGNAL_OP_RE.search(text, asan.end())
        op_txt = f" ({op_m.group('op').upper()})" if op_m else ""
        alarm = _map_sanitizer_alarm_kind(asan_kind)
        # The site is on the stack of the failure itself: the `freed by` and `allocated by` stacks that
        # follow it name other statements. Without a target frame there, the first usable frame stays.
        stack = _first_stack(frames, asan.end())
        site = next((i for i, m in enumerate(stack) if _is_target_frame(m)), None)
        frame = stack[site] if site is not None else best_frame
        file_ = (frame.group("file") if frame and frame.group("file") else "") or "unknown"
        line_ = int(frame.group("line")) if frame and frame.group("line") else 0
        fn = frame.group("function") if frame else "unknown_function"
        if fn == "unknown_function" and file_ != "unknown" and line_ > 0:
            fn = _resolve_function_at_line(file_, line_)
        pred = f"AddressSanitizer: {asan_kind}{op_txt}"
        # A libc call (memcpy, free, strlen ...) reports the defect in its own frame: the caller is the site,
        # and the call it made is the frame next to it, whatever runtime helpers that call went through.
        called = None
        if site is not None:
            called = next(
                (
                    m
                    for m in reversed(stack[:site])
                    if not m.group("file") or is_runtime_function(m.group("function"), m.group("file"))
                ),
                None,
            )
        elif (
            frames and frame is not frames[0] and frames[0].group("function").startswith(("__interceptor_", "__asan_"))
        ):
            called = frames[0]
        if called is not None:
            pred += f" in {re.sub(r'^_+(?:interceptor|asan)_', '', called.group('function'))} from {fn}"
        line_hash = line_text_hash(file_, line_)
        if line_hash is not None:
            pred += f" [line {line_hash}]"
        kind_slug = re.sub(r"[^a-z0-9_]+", "_", asan_kind.lower()).strip("_")
        return {
            "file": file_,
            "line": line_,
            "function": fn,
            "kind": "asan_" + kind_slug,
            "alarm_kind": alarm,
            "is_rte": True,
            "predicate": f"rte: {alarm}: {pred}",
        }

    ub_err = _UBSAN_ERR_RE.search(text)
    ub_sum = _UBSAN_SUMMARY_RE.search(text, ub_err.end() if ub_err else 0)
    if ub_err or ub_sum:
        if ub_err:
            ub_kind = ub_err.group("kind").strip()
            rest = ub_err.group("rest").strip()
            message = f"UndefinedBehaviorSanitizer: {ub_kind}" + (f" {rest}" if rest else "")
            search_from = ub_err.end()
            op_m = _SIGNAL_OP_RE.search(text, search_from)
        else:
            assert ub_sum is not None
            ub_kind = ub_sum.group("kind").strip()
            message = f"UndefinedBehaviorSanitizer: {ub_kind}"
            search_from = 0
            op_m = _SIGNAL_OP_RE.search(text)
        op_txt = f" ({op_m.group('op').upper()})" if op_m else ""
        alarm = _map_sanitizer_alarm_kind(ub_kind)
        stack = _first_stack(frames, search_from)
        site = next((i for i, m in enumerate(stack) if _is_target_frame(m)), None)
        if site is not None:
            frame = stack[site]
        else:
            stack_non_rt = [
                m
                for m in stack
                if not is_runtime_function(m.group("function"), m.group("file"))
                and not (m.group("file") and Path(m.group("file")).name.startswith("harness_"))
                and not is_harness_fuzz_function(m.group("function"))
            ]
            frame = stack_non_rt[0] if stack_non_rt else (stack[0] if stack else best_frame)
        file_ = (frame.group("file") if frame and frame.group("file") else "") or "unknown"
        line_ = int(frame.group("line")) if frame and frame.group("line") else 0
        fn = frame.group("function") if frame else "unknown_function"
        if frame is None and ub_sum is not None:
            sum_file = ub_sum.group("file") or ""
            sum_line = int(ub_sum.group("line")) if ub_sum.group("line") else 0
            sum_fn = ub_sum.group("function") or ""
            if (
                sum_fn
                and not is_runtime_function(sum_fn, sum_file)
                and not is_harness_fuzz_function(sum_fn)
                and not (sum_file and Path(sum_file).name.startswith("harness_"))
            ):
                file_ = sum_file or "unknown"
                line_ = sum_line
                fn = sum_fn
        if fn == "unknown_function" and file_ != "unknown" and line_ > 0:
            fn = _resolve_function_at_line(file_, line_)
        pred = f"UndefinedBehaviorSanitizer: {ub_kind}{op_txt}"
        called = None
        if site is not None:
            called = next(
                (
                    m
                    for m in reversed(stack[:site])
                    if not m.group("file") or is_runtime_function(m.group("function"), m.group("file"))
                ),
                None,
            )
        if called is not None:
            called_name = re.sub(r"^_+(?:interceptor|asan|ubsan)_", "", called.group("function"))
            pred += f" in {called_name} from {fn}"
        line_hash = line_text_hash(file_, line_)
        if line_hash is not None:
            pred += f" [line {line_hash}]"
        kind_slug = re.sub(r"[^a-z0-9_]+", "_", ub_kind.lower()).strip("_")
        return {
            "file": file_,
            "line": line_,
            "function": fn,
            "kind": "ubsan_" + kind_slug,
            "alarm_kind": alarm,
            "is_rte": True,
            "predicate": f"rte: {alarm}: {pred}",
            "message": message,
        }

    return _parse_leak_failure(text)


# Address-flow link-stub abort (scripts/fuzz_build.py `link_stubs_source`): an aborting stub
# emitted for a function outside the cluster's address-flow reach was reached at runtime.
# Always a pipeline reach defect, never a target finding.
_LINK_STUB_ABORT_RE = re.compile(
    r"^FRAMAC_LINK_STUB_CALLED:\s+(?P<symbol>[A-Za-z_]\w*)(?P<rest>[^\r\n]*)",
    re.MULTILINE,
)

_LINK_STUB_SKIP_FNS = frozenset(
    {
        "raise",
        "abort",
        "gsignal",
        "__pthread_kill_implementation",
        "pthread_kill",
        "__framac_link_stub_called",
        "__framac_write_all",
    }
)


def parse_link_stub_abort(text: str) -> dict | None:
    """
    An address-flow link-stub abort (`FRAMAC_LINK_STUB_CALLED: <symbol> ...`): returns
    `{symbol, message, caller}` or None. `caller` is the first non-runtime, non-stub,
    non-harness target frame in the printed stack, or None when no stack was printed.
    """
    if not text:
        return None
    m = _LINK_STUB_ABORT_RE.search(text)
    if not m:
        return None
    symbol = m.group("symbol")
    message = m.group(0).strip()
    caller: str | None = None
    for frame in _STACK_FRAME_RE.finditer(text):
        fn, fpath = frame.group("function"), frame.group("file") or ""
        if (
            is_runtime_function(fn, fpath)
            or fn in _LINK_STUB_SKIP_FNS
            or fn == symbol
            or "::" in fn
            or is_harness_fuzz_function(fn)
            or fn in _PROCESS_FRAME_FNS
            or (fpath and Path(fpath).name.startswith("harness_"))
        ):
            continue
        cleaned = fn.removeprefix(_EACSL_GEN_PREFIX)
        if cleaned == symbol:
            continue
        caller = cleaned
        break
    return {"symbol": symbol, "message": message, "caller": caller}


def parse_runtime_failure(text: str, *, binary: str | Path | None = None) -> dict | None:
    """
    Parse an E-ACSL failure report, falling back to ASan/UBSan runtime failure parsing. `binary` is
    the binary that printed `text`, when the caller ran it (parse_eacsl_failure). Returns None when
    `parse_link_stub_abort(text)` matches so a link-stub abort never produces a target failure.
    """
    if parse_link_stub_abort(text) is not None:
        return None
    return parse_eacsl_failure(text, binary=binary) or parse_sanitizer_failure(text)


# E-ACSL runtime aborts on its own resource limits, not on a target check (share/e-acsl/observation_model/
# segment_model/e_acsl_segment_tracking.c). Its private_assert prints `<runtime file>:<line>: <message>` and
# raises SIGABRT. set_heap_segment asserts twice that a new block lies inside the tracked heap zone
# (E_ACSL_HEAP_SIZE MiB, `e-acsl-gcc --zone-sizes heap:<N>`, eacsl_toolchain.EACSL_HEAP_ZONE_MB), and
# shadow_copy that its internal allocation succeeded. A closed list anchored at a line start behind the
# runtime's own path, so target output of the same words is not read as one.
_EACSL_RESOURCE_TEMPLATES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (
        re.compile(r"^(?:[^\s:]*e[-_]acsl[^\s:]*\.c:\d+: )" + rx + r"[ \t]*$", re.MULTILINE),
        resource,
    )
    for rx, resource in (
        (r"(?P<msg>Exceeded heap allocation limit of (?P<mb>\d+)MB(?: -- heap memory space moved\.)?)", "heap"),
        (r"(?P<msg>Shadow copy failed)", "heap"),
    )
)

# The same aborts when the message is gone (a replay tail cut mid-stack): the runtime's assert called
# straight from the function whose only asserts are these limits.
_EACSL_RESOURCE_FRAMES = {"set_heap_segment": "heap", "shadow_copy": "heap"}


def parse_eacsl_resource_abort(text: str) -> dict | None:
    """
    An E-ACSL runtime abort on its own resource limit: `{resource, limit_mb, message, caller}`, or None.
    It is no target failure: no check failed, so it never gets a fingerprint or a candidate. `limit_mb`
    is None when only the stack shows it; `caller` is the first target frame above the runtime's.
    """
    if not text:
        return None
    resource = message = None
    limit_mb: int | None = None
    for rx, res in _EACSL_RESOURCE_TEMPLATES:
        m = rx.search(text)
        if m:
            resource, message = res, m.group("msg")
            mb = m.groupdict().get("mb")
            limit_mb = int(mb) if mb else None
            break
    frames = list(_STACK_FRAME_RE.finditer(text))
    if resource is None:
        for prev, cur in zip(frames, frames[1:], strict=False):
            if prev.group("function") == "private_assert_fail" and cur.group("function") in _EACSL_RESOURCE_FRAMES:
                resource = _EACSL_RESOURCE_FRAMES[cur.group("function")]
                message = f"E-ACSL runtime assertion in {cur.group('function')}"
                break
    if resource is None:
        return None
    caller, _ = _caller_of_eacsl_runtime(text)
    if not caller:
        # Runtime frames named by function only (`unsafe_malloc`, `malloc` in the runtime's files).
        for m in frames:
            fn, fpath = m.group("function"), m.group("file") or ""
            if is_runtime_function(fn, fpath) or fn in ("raise", "abort", "private_assert_fail", "raise_abort"):
                continue
            if "::" in fn or is_harness_fuzz_function(fn) or fn in _PROCESS_FRAME_FNS:
                continue
            caller = fn
            break
    return {"resource": resource, "limit_mb": limit_mb, "message": message, "caller": caller or None}


# libFuzzer's own out-of-memory report: its RSS thread (`used: <N>Mb; exceeds: <M>Mb`) or its malloc hook
# (`malloc(<N>)`, sanitizer builds only). It writes the input as an `oom-` artifact.
_LIBFUZZER_OOM_RE = re.compile(r"^(?:==\d+==\s*ERROR|SUMMARY): libFuzzer: out-of-memory\b", re.MULTILINE)


def is_libfuzzer_out_of_memory(text: str) -> bool:
    """True when the output holds libFuzzer's own out-of-memory report (no parsed failure: it has no check)."""
    return bool(text) and _LIBFUZZER_OOM_RE.search(text) is not None


def is_sanitizer_allocation_cap(failure: dict | None) -> bool:
    """
    ASan refusing a request past its own allocator maximum (`requested allocation size ... exceeds maximum
    supported size`, allocation-size-too-big): a tool limit like the E-ACSL heap zone, no target defect,
    whichever statement made the request. Campaigns and replays now run with allocator_may_return_null=1
    (fuzz_common.SANITIZER_RUNTIME_ENV), which turns it into a NULL return; reports written before keep it.
    """
    return isinstance(failure, dict) and failure.get("kind") == "asan_requested_allocation_size"


def needs_attribution(failure: dict | None) -> bool:
    """
    True when a failure has no usable target location (missing, line 0, unknown or runtime-internal function).
    ASan's allocation cap counts as such wherever the request was made: it is a tool limit, so it never
    gives an artifact its identity. Never for a failed check of a MetAcsl property (`meta_property`): it has
    no line by construction, and a sanitizer replay cannot see it (the attribution would give it the identity
    of whatever the sanitizers report on that input, or none).
    """
    if not failure or is_sanitizer_allocation_cap(failure):
        return True
    if failure.get("meta_property"):
        return False
    fn = failure.get("function") or ""
    file_ = str(failure.get("file") or "")
    return (
        int(failure.get("line") or 0) <= 0
        or fn in ("", "unknown_function")
        or is_runtime_function(fn, file_)
        or file_.endswith(".instrumented.c")
    )


STACK_FRAMES_MAX = 64


_PROCESS_FRAME_FNS = ("main", "_start", "__libc_start_main", "__libc_start_call_main")


def stack_frames(text: str, limit: int = STACK_FRAMES_MAX) -> list[dict]:
    """
    The distinct stack frames (`{function, file, line}`, in the order printed) of a replay's output,
    without sanitizer, E-ACSL or libFuzzer runtime frames, harness entry frames and process start-up.
    Every stack the output prints counts (an ASan report adds the allocation and free stacks): each
    function in one ran on that input. `harness_reach.py dynamic` credits an entry point found here;
    names stay exact, so E-ACSL's `__gen_e_acsl_<fn>` wrapper is not `<fn>`.
    """
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for m in _STACK_FRAME_RE.finditer(text or ""):
        fn = m.group("function")
        if "::" in fn or is_runtime_function(fn) or is_harness_fuzz_function(fn) or fn in _PROCESS_FRAME_FNS:
            continue
        key = (fn, m.group("file") or "")
        if key in seen:
            continue
        seen.add(key)
        out.append({"function": fn, "file": key[1], "line": int(m.group("line") or 0)})
        if len(out) >= limit:
            break
    return out


def failure_fingerprint(failure: dict | None) -> str | None:
    if not failure:
        return None
    return make_fingerprint(
        failure.get("file") or "unknown",
        failure.get("function") or "unknown_function",
        failure.get("alarm_kind") or failure.get("kind") or "crash",
        failure.get("predicate") or "",
    )


# ---------------------------------------------------------------------------
# Startup failure & standalone harness smoke failure classification (P3)
# ---------------------------------------------------------------------------

STARTUP_FAILURE_FUNCTIONS = frozenset(
    {
        "LLVMFuzzerInitialize",
        "__e_acsl_globals_init",
        "__e_acsl_memory_init",
        "__e_acsl_argv_alloca",
        "shadow_alloca",
    }
)

_STARTUP_ONLY_INIT_FRAMES = frozenset(
    {
        "_dl_init",
        "call_init",
        "__libc_csu_init",
        "__do_global_ctors_aux",
    }
)

_FUZZ_ENTRY_FRAMES = frozenset(
    {
        "LLVMFuzzerTestOneInput",
        "fuzzer::Fuzzer::ExecuteCallback",
        "fuzzer::Fuzzer::RunOne",
    }
)

_SIGNAL_OR_ABORT_FRAMES = frozenset(
    {
        "raise",
        "abort",
        "gsignal",
        "__pthread_kill_implementation",
        "pthread_kill",
        "private_abort",
        "raise_abort",
        "vabort",
        "private_assert_fail",
    }
)

_STARTUP_LOADER_ERR_RE = re.compile(
    r"error while loading shared libraries"
    r"|symbol lookup error"
    r"|undefined symbol:"
    r"|Shadow memory range interleaves"
    r"|AddressSanitizer failed to allocate"
    r"|ERROR:\s*Failed to mmap",
    re.IGNORECASE,
)

_FUZZ_STARTED_INPUT_RE = re.compile(
    r"(?:^Running:\s+\S|^Executed\s+\S|^#\d+(?:\t|:\s)|LLVMFuzzerTestOneInput)",
    re.MULTILINE,
)

_CRASH_OR_ABORT_RE = re.compile(
    r"ERROR:\s*(?:AddressSanitizer|UndefinedBehaviorSanitizer|libFuzzer)"
    r"|UndefinedBehaviorSanitizer:DEADLYSIGNAL"
    r"|SUMMARY:\s*(?:AddressSanitizer|UndefinedBehaviorSanitizer|libFuzzer)"
    r"|Segmentation fault"
    r"|Aborted\b"
    r"|\bSIG(?:ABRT|SEGV|BUS|ILL|FPE)\b"
    r"|Assertion\s+.+\s+failed"
    r"|:\s*Error:\s*Assertion failed",
    re.IGNORECASE,
)

_LIBFUZZER_BANNER_RE = re.compile(
    r"^INFO:\s*(?:Running with entropic|Seed:|Loaded \d+ modules)",
    re.MULTILINE,
)

_HARNESS_STACK_VAR_RE = re.compile(r"(?:'c\d+a\d+(?:_[A-Za-z0-9_]+)?'|\bc\d+a\d+\b)")
_NON_MALLOC_FREE_RE = re.compile(r"attempting free on address which was not malloc\(\)-ed", re.IGNORECASE)
_NULL_DEREF_RE = re.compile(
    r"null\s+pointer|member access within null pointer|load of null pointer|store to null pointer|null-deref|\bnullptr\b",
    re.IGNORECASE,
)
_SEGV_NULL_ADDR_RE = re.compile(
    r"(?:SEGV on unknown address 0x0*[0-9a-fA-F]{1,3}(?![0-9a-fA-F])|address points to the zero page)",
    re.IGNORECASE,
)
_ARITH_OR_BUFFER_ALARMS = frozenset(
    {
        "index_bound",
        "signed_overflow",
        "unsigned_overflow",
        "shift",
        "division_by_zero",
        "dangling_pointer",
        "separation",
        "valid_string",
        "is_nan_or_infinite",
        "bool_value",
    }
)
_BUFFER_OVERFLOW_KINDS = (
    "heap_buffer_overflow",
    "global_buffer_overflow",
    "stack_buffer_overflow",
    "heap_use_after_free",
    "stack_use_after_scope",
    "stack_use_after_return",
    "container_overflow",
    "negative_size_param",
)


def _is_startup_function(name: str | None) -> bool:
    if not name:
        return False
    return (
        name in STARTUP_FAILURE_FUNCTIONS
        or name.endswith("LLVMFuzzerInitialize")
        or name.startswith(("__e_acsl_globals_init", "__e_acsl_memory_init", "__e_acsl_argv_alloca"))
    )


def _is_always_startup_frame(name: str) -> bool:
    return (
        (name in STARTUP_FAILURE_FUNCTIONS and name != "shadow_alloca")
        or name.endswith("LLVMFuzzerInitialize")
        or name.startswith(("__e_acsl_globals_init", "__e_acsl_memory_init", "__e_acsl_argv_alloca"))
        or name in _STARTUP_ONLY_INIT_FRAMES
        or name.startswith("_GLOBAL__sub_I_")
    )


def _is_fuzz_init_file(file_path: str | None) -> bool:
    if not file_path:
        return False
    norm = file_path.replace("\\", "/")
    return norm == "fuzz_init.c" or norm.endswith("/fuzz_init.c")


def _has_non_startup_target_site(failure: dict | None) -> bool:
    """True when `failure` identifies a concrete, non-startup, non-runtime function or source file."""
    if not isinstance(failure, dict):
        return False
    fn = str(failure.get("function") or "").strip()
    file_ = str(failure.get("file") or "").strip()
    if _is_startup_function(fn) or _is_fuzz_init_file(file_):
        return False
    if is_runtime_function(fn, file_):
        return False
    has_fn = bool(fn) and fn not in ("unknown", "unknown_function")
    has_file = bool(file_) and file_ not in ("unknown", "<unknown>")
    return has_fn or has_file


def is_startup_failure(failure: dict | None, log_text: str = "") -> tuple[bool, str | None]:
    """
    Detect a crash or abort occurring during binary/runtime startup before `LLVMFuzzerTestOneInput`
    is entered (for example in `LLVMFuzzerInitialize`, `__e_acsl_globals_init`, `__e_acsl_memory_init`,
    `__e_acsl_argv_alloca`, `shadow_alloca`, global constructors, or dynamic loader initialization).
    """
    if isinstance(failure, dict):
        fn = str(failure.get("function") or "")
        if _is_startup_function(fn):
            return True, f"startup failure in {fn}"
        file_ = str(failure.get("file") or "")
        if _is_fuzz_init_file(file_):
            return True, f"startup failure in {Path(file_).name}"

    if not log_text:
        return False, None

    started_input = _FUZZ_STARTED_INPUT_RE.search(log_text) is not None
    loader_m = _STARTUP_LOADER_ERR_RE.search(log_text)
    if loader_m and not started_input:
        return True, f"startup loader/runtime error: {loader_m.group(0)}"

    frames = list(_STACK_FRAME_RE.finditer(log_text))
    first_stack = _first_stack(frames, 0) if frames else []
    entered_fuzz = any(
        m.group("function") in _FUZZ_ENTRY_FRAMES
        or m.group("function").startswith(("fuzzer::Fuzzer::ExecuteCallback", "fuzzer::Fuzzer::RunOne"))
        for m in first_stack
    )

    # Top non-signal / non-sanitizer-wrapper frame in the crash stack.
    for m in first_stack:
        fn = m.group("function")
        if fn in _SIGNAL_OR_ABORT_FRAMES or fn.startswith(
            (
                "__asan",
                "__ubsan",
                "__sanitizer",
                "__interceptor",
                "fuzzer::PrintStackTrace",
                "fuzzer::Fuzzer::Crash",
                "fuzzer::Fuzzer::Static",
            )
        ):
            continue
        if _is_startup_function(fn):
            return True, f"startup failure in {fn}"
        break

    for m in first_stack:
        fn, fpath = m.group("function"), m.group("file") or ""
        if _is_always_startup_frame(fn):
            return True, f"startup failure in {fn}"
        if _is_fuzz_init_file(fpath):
            return True, f"startup failure in fuzz_init.c ({fn})"
        if fn == "shadow_alloca" and not entered_fuzz:
            return True, "startup failure in shadow_alloca before LLVMFuzzerTestOneInput"

    is_lsan = _LSAN_ERR_RE.search(log_text) is not None
    if first_stack and not entered_fuzz and not is_lsan:
        if any(m.group("function").startswith("fuzzer::FuzzerDriver") for m in first_stack):
            return True, "crash/abort in libFuzzer startup before LLVMFuzzerTestOneInput"
        has_process_entry = any(
            m.group("function") in ("_start", "__libc_start_main", "__libc_start_call_main") for m in first_stack
        )
        has_target_main = any(
            m.group("function") == "main" and m.group("file") and not is_runtime_function("main", m.group("file"))
            for m in first_stack
        )
        if has_process_entry and not has_target_main and not started_input:
            return True, "crash/abort during process startup before LLVMFuzzerTestOneInput"

    if not started_input and not is_lsan and _CRASH_OR_ABORT_RE.search(log_text):
        for sfn in (
            "LLVMFuzzerInitialize",
            "__e_acsl_globals_init",
            "__e_acsl_memory_init",
            "__e_acsl_argv_alloca",
            "shadow_alloca",
        ):
            if re.search(rf"\b{re.escape(sfn)}\b", log_text):
                return True, f"startup failure referencing {sfn}"
        if _LIBFUZZER_BANNER_RE.search(log_text):
            eff_failure = failure if isinstance(failure, dict) else parse_runtime_failure(log_text)
            if not _has_non_startup_target_site(eff_failure):
                return True, "crash/abort before LLVMFuzzerTestOneInput was entered"

    return False, None


def _is_harness_stack_overflow(kind: str, pred: str, replay_log: str) -> bool:
    if "stack_buffer_overflow" not in kind and "stack-buffer-overflow" not in replay_log.lower():
        return False
    arrow_lines = [line for line in replay_log.splitlines() if "<==" in line]
    if arrow_lines:
        return any(_HARNESS_STACK_VAR_RE.search(line) is not None for line in arrow_lines)
    return bool(_HARNESS_STACK_VAR_RE.search(replay_log) or _HARNESS_STACK_VAR_RE.search(pred))


def _is_harness_site(failure: dict | None) -> bool:
    if not isinstance(failure, dict):
        return False
    file_ = str(failure.get("file") or "")
    fn = str(failure.get("function") or "")
    if file_ and Path(file_).name.startswith("harness_"):
        return True
    return bool(fn and is_harness_fuzz_function(fn))


def _is_lsan_direct_caller_harness(replay_log: str) -> bool:
    m = _LSAN_BLOCK_RE.search(replay_log)
    if not m:
        return False
    stack_lines: list[str] = []
    for line in replay_log[m.end() :].split("\n")[1:]:
        if not line.strip():
            break
        stack_lines.append(line)
    for frame in _STACK_FRAME_RE.finditer("\n".join(stack_lines)):
        fn, fpath = frame.group("function"), frame.group("file") or ""
        base = re.sub(r"^_+(?:interceptor_)?", "", fn)
        if is_runtime_function(fn, fpath) or base in _LSAN_ALLOCATORS:
            continue
        return (bool(fpath) and Path(fpath).name.startswith("harness_")) or is_harness_fuzz_function(fn)
    return False


def classify_smoke_failure(failure: dict | None, payload_len: int, replay_log: str = "") -> str:
    """
    Classify a failure observed during standalone harness smoke execution:
      - "startup_error": failure during binary/runtime initialization before LLVMFuzzerTestOneInput.
      - "harness_setup_fault": unambiguous harness-side contract breach (non-malloc free,
        stack-buffer-overflow on harness frame variable `c<N>a<M>`, `lsan_direct_leak` on setup,
        crash site inside harness code, or NULL pointer deref / NULL member access on `payload_len == 0`
        with no target-parsing arithmetic/buffer bug).
      - "empty_input_candidate": `payload_len == 0` target parsing/arithmetic/buffer/logic bug
        without harness-side markers (kept active, never quarantined).
      - "target_crash_candidate": `payload_len > 0` target crash without harness-side markers
        (kept active, never quarantined).
    """
    eff_failure = failure if failure is not None else (parse_runtime_failure(replay_log) if replay_log else None)
    startup, _ = is_startup_failure(eff_failure, replay_log)
    if startup:
        return "startup_error"

    kind = str((eff_failure or {}).get("kind") or "").lower()
    alarm = str((eff_failure or {}).get("alarm_kind") or "").lower()
    pred = str((eff_failure or {}).get("predicate") or "")
    msg = str((eff_failure or {}).get("message") or "")
    combined_text = "\n".join(part for part in (pred, msg, replay_log) if part)

    if "attempting_free_on_address_which_was_not_malloc_ed" in kind or _NON_MALLOC_FREE_RE.search(combined_text):
        return "harness_setup_fault"

    if _is_harness_stack_overflow(kind, pred, replay_log):
        return "harness_setup_fault"

    if kind == "lsan_direct_leak" and (
        payload_len == 0 or _is_harness_site(eff_failure) or _is_lsan_direct_caller_harness(replay_log)
    ):
        return "harness_setup_fault"

    if _is_harness_site(eff_failure):
        return "harness_setup_fault"

    is_arith_or_buf = alarm in _ARITH_OR_BUFFER_ALARMS or any(bk in kind for bk in _BUFFER_OVERFLOW_KINDS)
    if payload_len == 0 and not is_arith_or_buf:
        if _NULL_DEREF_RE.search(combined_text) or _SEGV_NULL_ADDR_RE.search(combined_text):
            return "harness_setup_fault"

    if payload_len == 0:
        return "empty_input_candidate"
    return "target_crash_candidate"
