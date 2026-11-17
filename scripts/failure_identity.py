"""Parsing of E-ACSL, ASan, UBSan runtime failures and their fingerprints."""

from __future__ import annotations

import hashlib
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


_RUNTIME_FILE_MARKERS = ("e-acsl/", "e_acsl", "/share/frama-c/", "compiler-rt", "libfuzzer")


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


def parse_eacsl_failure(text: str) -> dict | None:
    """Extract the first E-ACSL failure (file, line, function, kind, label, predicate) from runtime output."""
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


def _parse_leak_failure(text: str) -> dict | None:
    """
    The first LeakSanitizer block of a report: the first `Direct leak`, else the first `Indirect leak`.
    Its location is the first frame of its allocation stack that is no runtime, harness or allocator
    frame. A leak links no obligation class (`alarm_kind` memory_leak, CWE-401 in the verifier brief).
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
    frame = None
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
        frame = m
        break
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
            ("__interceptor_", "__asan_", "LLVMFuzzerTestOneInput", TARGET_EMBEDDED_PREFIX)
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
        op_m = _ASAN_OP_RE.search(text, asan.end())
        op_txt = f" ({op_m.group('op')})" if op_m else ""
        alarm = _map_sanitizer_alarm_kind(asan_kind)
        file_ = (best_frame.group("file") if best_frame and best_frame.group("file") else "") or "unknown"
        line_ = int(best_frame.group("line")) if best_frame and best_frame.group("line") else 0
        fn = best_frame.group("function") if best_frame else "unknown_function"
        if fn == "unknown_function" and file_ != "unknown" and line_ > 0:
            fn = _resolve_function_at_line(file_, line_)
        pred = f"AddressSanitizer: {asan_kind}{op_txt}"
        top = frames[0] if frames else None
        if (
            top is not None
            and best_frame is not top
            and top.group("function").startswith(("__interceptor_", "__asan_"))
        ):
            # An interceptor (memcpy, strcpy ...) reports the defect in its own frame: the caller is the site.
            pred += f" in {re.sub(r'^__(?:interceptor|asan)_', '', top.group('function'))} from {fn}"
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

    return _parse_leak_failure(text)


def parse_runtime_failure(text: str) -> dict | None:
    """Parse an E-ACSL failure report, falling back to ASan/UBSan runtime failure parsing."""
    return parse_eacsl_failure(text) or parse_sanitizer_failure(text)


def needs_attribution(failure: dict | None) -> bool:
    """True when a failure has no usable target location (missing, line 0, unknown or runtime-internal function)."""
    if not failure:
        return True
    fn = failure.get("function") or ""
    return (
        int(failure.get("line") or 0) <= 0
        or fn in ("", "unknown_function")
        or is_runtime_function(fn, failure.get("file"))
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
