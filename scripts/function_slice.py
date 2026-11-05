#!/usr/bin/env python3
"""
Deterministic per-function reading slice for a Function Prover subagent (stdlib only).

A slice holds what proving one C function needs to read: its contract and body, callee prototypes
with their CURRENT contracts, and only the macros, types, globals and ACSL logic declarations the
function reaches. It is reading context only: the proof target stays the real file.

How it works:
  1. Preprocess the real file with the prover's flags, preferring Frama-C's own view (Frama-C's
     command from `-print-cpp-commands`, with `-dD`, no `-C`). Fallbacks, each recorded in `reason`:
     plain `gcc -E -dD`; then a lexical slice from the real files (`status: "degraded"`).
  2. Index the preprocessed tokens into top-level items. Line markers map every surviving token
     back to (file, line), so a declaration in an inactive `#if` branch is never picked up. `-dD`
     gives the macro table in definition order, so `#undef` and redefinition resolve by position.
  3. Close over identifiers from the target (real contract and body, plus the expanded body, which
     shows callees hidden in macros and token pasting). Everything printed is REAL source text from
     the origin line range, never expanded text. Only in-tree files print. Include directories of
     the shared tree get a snapshot twin first, so those lines and contracts are the snapshot's.

The parsed index is cached by content in namespace `slice-index`. Its key ignores line markers and
whitespace, and its positions count non-whitespace characters instead of lines, so one entry serves
all provers of a file even after ACSL-only merges shift line numbers. Origin lines come from the
current text on every run. The slice text itself is never cached: it must show the snapshot's
current contracts.

CLI (from the run directory):
  function_slice.py --work-dir agents/<id>/scratch/work --file a.c --function f --cppflags=-I. --out-dir D
"""

from __future__ import annotations

import argparse
import atexit
import bisect
import contextlib
import hashlib
import json
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cache  # noqa: E402
from acsl_ast import (  # noqa: E402
    _CONTRACT_KWS,
    AcslSyntaxError,
    Token,
    _find_body_brace_offset,
    _is_top_level_acsl_token,
    _parse_acsl_inner_segments,
    extract_top_level_acsl_declarations,
    locate_function_span,
    tokenize_c_acsl,
)
from build_callgraph_dag import (  # noqa: E402
    _DEFINE_RE,
    _find_matching_backward,
    _find_matching_forward,
    _is_ident,
    _resolve_declarator,
    _strip_trailing_attributes,
)
from framac_common import (  # noqa: E402
    ArtifactError,
    augment_framac_cppflags,
    is_safe_relative_path,
    load_json_optional,
    normalize_flag_args,
    scratch_first_flags,
    to_run_relative,
)

CACHE_NAMESPACE = "slice-index"
INDEX_FILE = "index.json"
PREPROCESS_TIMEOUT_S = cache.DEPS_TIMEOUT_S

# Output bounds (reading comfort, not machine sizes).
GLOBAL_MAX_LINES = 16
GLOBAL_MAX_CHARS = 2000
GLOBAL_HEAD_LINES = 6
GLOBAL_HEAD_LINE_CHARS = 160
TYPE_MAX_LINES_WITH_COMMENTS = 30
CALLEE_BODY_MAX_LINES = 150
CALLEE_BODIES_MAX_LINES = 1000
OMITTED_NAMES_SHOWN = 40
UNRESOLVED_DECLS_SHOWN = 4

_FLAGS_SENTINEL = "-D__FC_SLICE_FLAGS__"
_SOURCE_SLOT = "\0source"
_CPP_COMMAND_RE = re.compile(r"Preprocessing command:\s*\n\s*(\S.*)")
_MARKER_RE = re.compile(r'^#\s*(?:line\s+)?(\d+)\s+"((?:[^"\\]|\\.)*)"')
_UNDEF_RE = re.compile(r"^\s*#\s*undef\s+([A-Za-z_]\w*)")
_DIRECTIVE_WORD_RE = re.compile(r"^\s*#\s*([A-Za-z_]\w*)")
_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*(?:"([^"\n]+)"|<([^>\n]+)>)')
_AGENT_PREFIX_RE = re.compile(r"agents/[^/\s\"]+/scratch/work/")
_TREE_TAIL_RE = re.compile(r"^(?:workspace/work|agents/[^/]+/scratch/work)/(.+)$")
_REL_PREFIX_RE = re.compile(r"^(?:\./|/framac-run/)+")
_ABSOLUTE_RE = re.compile(r"^(?:/|[A-Za-z]:/)")
_SYNTAX_LINE_RE = re.compile(r":(\d+): unclosed (.*)$")
_NAME_RE = re.compile(r"^[A-Za-z_]\w*$")
_IDENT_FIND_RE = re.compile(r"[A-Za-z_]\w*")
_ACSL_IDENT_RE = re.compile(r"(?<![\\\w])[A-Za-z_]\w*")
_ACSL_NOISE_RE = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n]){1,4}\'|//[^\n]*')
_PADDED_CONTINUATION_RE = re.compile(r"[ \t]{2,}\\$", re.MULTILINE)

_ACSL_KINDS = frozenset({"acsl_block", "acsl_line"})
_C_KINDS = frozenset({"c_token", "string", "char"})
_OPENERS = {"(": ")", "[": "]", "{": "}"}
_TAG_WORDS = frozenset({"struct", "union", "enum"})
_ATTRIBUTE_WORDS = frozenset(
    {"__attribute__", "__attribute", "__declspec", "_declspec", "__asm__", "__asm", "asm", "_Alignas"}
)
_TYPE_GROUP_WORDS = frozenset({"typeof", "__typeof__", "__typeof", "_Atomic"})
# Words that are never a declared name or a reference. C_KEYWORDS (build_callgraph_dag) holds the
# statement keywords; TYPE_MODIFIERS_AND_PRIMITIVES cannot serve here because it lists size_t and
# u8, which projects really do declare with typedef.
_C_WORDS = frozenset(
    {
        "void",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "signed",
        "unsigned",
        "_Bool",
        "_Complex",
        "__complex__",
        "__signed__",
        "__signed",
        "__int128",
        "const",
        "__const",
        "__const__",
        "volatile",
        "__volatile",
        "__volatile__",
        "restrict",
        "__restrict",
        "__restrict__",
        "struct",
        "union",
        "enum",
        "typedef",
        "extern",
        "static",
        "inline",
        "__inline",
        "__inline__",
        "register",
        "auto",
        "_Noreturn",
        "_Thread_local",
        "__thread",
        "__extension__",
        "_Atomic",
        "_Generic",
        "__alignof__",
        "__alignof",
        "__real__",
        "__imag__",
        "__label__",
        "__auto_type",
        "__typeof",
    }
)
_PLACEHOLDER_TYPE = Token("c_token", "int", 0, 0, 0)


class _ToolFailure(RuntimeError):
    """A preprocessing step could not produce output; the message goes into `reason`."""


# ---------------------------------------------------------------------------
# Tolerant tokenizing
# ---------------------------------------------------------------------------


def _tokenize_tolerant(text: str) -> tuple[str, list[Token]]:
    """
    Tokenize `text`, blanking lines the tokenizer rejects (prose with an apostrophe in an `#if 0`
    block, say). Line numbers stay valid. Returns the text that tokenized, and its tokens.
    """
    for _ in range(64):
        try:
            return text, tokenize_c_acsl(text)
        except AcslSyntaxError as exc:
            m = _SYNTAX_LINE_RE.search(str(exc))
            if not m:
                break
            if "block comment" in m.group(2):
                text += "\n*/"
                continue
            lines = text.split("\n")
            idx = int(m.group(1)) - 1
            if not 0 <= idx < len(lines) or not lines[idx]:
                break
            lines[idx] = ""
            text = "\n".join(lines)
    return text, []


def _is_name(text: str) -> bool:
    return text not in _C_WORDS and _is_ident(text)


def _squeezed_len(text: str) -> int:
    return sum(map(len, text.split()))


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------

_framac_lock = threading.Lock()
_framac_templates: dict[str, list[str]] = {}


def _run_tool(cmd: list[str], cwd: Path, runner: Callable | None):
    run = runner or subprocess.run
    return run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=PREPROCESS_TIMEOUT_S,
        cwd=str(cwd),
    )


def _failure_text(proc) -> str:
    """The exit code and the most telling line of a failed tool run."""
    lines = [
        line.strip() for stream in (proc.stderr, proc.stdout) for line in (stream or "").splitlines() if line.strip()
    ]
    chosen = next((line for line in lines if "error" in line.lower()), lines[0] if lines else "")
    return f"exit {proc.returncode}: {chosen[:200]}" if chosen else f"exit {proc.returncode}"


def _materialize_machdep(machdep: str, run_dir: Path, runner: Callable | None) -> str:
    """
    Frama-C's temporary machdep directory is deleted when `-print-cpp-commands` exits, so write the
    same two files, byte for byte, to a directory that lives as long as this process.
    """
    path = tempfile.mkdtemp(prefix="fc_slice_machdep_")
    atexit.register(shutil.rmtree, path, True)
    for option, name in (
        ("-print-machdep-builtin-macros", "__fc_builtin_macros.h"),
        ("-print-machdep-header", "__fc_machdep.h"),
    ):
        proc = _run_tool(["frama-c", "-machdep", machdep, option], run_dir, runner)
        if proc.returncode != 0 or not proc.stdout:
            raise _ToolFailure(f"frama-c {option}: {_failure_text(proc)}")
        with open(Path(path) / name, "w", encoding="utf-8", newline="\n") as f:
            f.write(proc.stdout)
    return path


def _probe_framac_template(machdep: str, source: str, run_dir: Path, runner: Callable | None) -> list[str]:
    """Frama-C's preprocessing argv: no `-C`, to stdout, user flags and source left as slots."""
    probe = ["frama-c", "-machdep", machdep, f"-cpp-extra-args={_FLAGS_SENTINEL}", "-print-cpp-commands", source]
    proc = _run_tool(probe, run_dir, runner)
    m = _CPP_COMMAND_RE.search(f"{proc.stdout or ''}\n{proc.stderr or ''}")
    if proc.returncode != 0 or not m:
        raise _ToolFailure(f"frama-c -print-cpp-commands: {_failure_text(proc) if proc.returncode else 'no command'}")
    words = shlex.split(m.group(1))
    if _FLAGS_SENTINEL not in words:
        raise _ToolFailure("frama-c -print-cpp-commands: extra arguments not in the printed command")
    argv: list[str] = []
    skip_next = False
    for word in words:
        if skip_next:
            skip_next = False
        elif word == "-o":
            skip_next = True
        elif word != "-C":
            argv.append(word)
    source_idx = max((i for i, w in enumerate(argv) if i and not w.startswith("-")), default=-1)
    if source_idx < 0 or Path(argv[source_idx]).name != Path(source).name:
        raise _ToolFailure("frama-c -print-cpp-commands: source file not in the printed command")
    argv[source_idx] = _SOURCE_SLOT
    if "-dD" not in argv:
        argv.insert(1, "-dD")
    for i, word in enumerate(argv):
        if "__fc_machdep" in word and word.startswith("-I"):
            argv[i] = f"-I{_materialize_machdep(machdep, run_dir, runner)}"
    return argv


def _framac_template(machdep: str, source: str, run_dir: Path, runner: Callable | None) -> list[str]:
    if runner is not None:
        return _probe_framac_template(machdep, source, run_dir, runner)
    with _framac_lock:
        template = _framac_templates.get(machdep)
        if template is None:
            template = _probe_framac_template(machdep, source, run_dir, runner)
            _framac_templates[machdep] = template
        return template


def _preprocess_framac(flags: list[str], source: str, machdep: str, run_dir: Path, runner: Callable | None) -> str:
    template = _framac_template(machdep, source, run_dir, runner)
    cmd: list[str] = []
    for word in template:
        if word == _FLAGS_SENTINEL:
            cmd.extend(flags)
        else:
            cmd.append(source if word == _SOURCE_SLOT else word)
    proc = _run_tool(cmd, run_dir, runner)
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        raise _ToolFailure(_failure_text(proc))
    return proc.stdout


def _preprocess_gcc(flags: list[str], source: str, run_dir: Path, runner: Callable | None) -> str:
    proc = _run_tool(["gcc", "-E", "-dD", *cache.FRAMAC_DEP_DEFINES, *flags, source], run_dir, runner)
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        raise _ToolFailure(_failure_text(proc))
    return proc.stdout


def _tool_error(exc: BaseException) -> str:
    if isinstance(exc, FileNotFoundError):
        return "not found"
    return str(exc)[:200] or type(exc).__name__


def _preprocess(
    flags: list[str] | None, source: str, machdep: str, run_dir: Path, runner: Callable | None, notes: list[str]
) -> tuple[str | None, str]:
    """(text, preprocessor): `framac`, `gcc`, or (None, `lexical`) after recording why in `notes`."""
    if flags is None:
        return None, "lexical"
    errors = (OSError, subprocess.SubprocessError, ValueError, _ToolFailure)
    try:
        return _preprocess_framac(flags, source, machdep, run_dir, runner), "framac"
    except errors as exc:
        notes.append(f"Frama-C preprocessor failed ({_tool_error(exc)})")
    try:
        text = _preprocess_gcc(flags, source, run_dir, runner)
        notes.append("used plain gcc -E: host macros can differ from Frama-C's machdep")
        return text, "gcc"
    except errors as exc:
        notes.append(f"gcc -E failed ({_tool_error(exc)})")
    return None, "lexical"


def _effective_flags(cppflags: str, tree: _Tree, notes: list[str]) -> list[str] | None:
    """The prover's flags: augmented like a real Frama-C run, reduced to preprocessor options."""
    try:
        words = shlex.split(augment_framac_cppflags(cppflags))
    except ValueError as exc:
        notes.append(f"unparsable cppflags ({exc})")
        return None
    return _snapshot_first(cache.preprocessor_args(words), tree)


def _snapshot_first(flags: list[str], tree: _Tree) -> list[str]:
    """
    Give each include directory of the shared tree a snapshot twin just before it. Both copies hold
    the same C, but only the snapshot's line numbers and contracts are the ones this slice reports.
    """
    return scratch_first_flags(flags, tree.run_dir, tree.work_dir)


# ---------------------------------------------------------------------------
# Scanning preprocessed text: origin of each line, macro table, cache key
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _MacroEvent:
    name: str
    is_define: bool
    pos: int
    file: str
    line: int
    params: str = ""
    body: str = ""


@dataclass(slots=True)
class _Scan:
    """
    One entry per output line. `pos` counts non-whitespace characters of the text without line
    markers, the unit of every cached position: it survives ACSL-only edits, which change only
    whitespace and markers.
    """

    blanked: list[str] = field(default_factory=list)
    pos: list[int] = field(default_factory=list)
    file_id: list[int] = field(default_factory=list)
    line: list[int] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    macros: dict[str, list[_MacroEvent]] = field(default_factory=dict)
    digest: str = ""

    def origin(self, pos: int) -> tuple[str, int]:
        idx = max(0, bisect.bisect_right(self.pos, pos) - 1)
        return self.files[self.file_id[idx]], self.line[idx]

    def live_lines(self, origin: str) -> list[int]:
        """Sorted lines of `origin` that left C text in the preprocessed output."""
        if origin not in self.files:
            return []
        wanted = self.files.index(origin)
        return sorted(
            {self.line[i] for i, text in enumerate(self.blanked) if self.file_id[i] == wanted and text.strip()}
        )


def _scan_text(text: str) -> _Scan:
    scan = _Scan()
    file_ids: dict[str, int] = {"": 0}
    scan.files.append("")
    kept: list[str] = []
    pos = 0
    file_id = 0
    line_no = 1
    for raw in text.split("\n"):
        scan.pos.append(pos)
        scan.file_id.append(file_id)
        scan.line.append(line_no)
        is_directive = raw.startswith("#")
        m = _MARKER_RE.match(raw) if is_directive else None
        if m:
            scan.blanked.append("")
            line_no = int(m.group(1))
            name = m.group(2)
            file_id = file_ids.setdefault(name, len(scan.files))
            if file_id == len(scan.files):
                scan.files.append(name)
            continue
        if "scratch/work/" in raw:  # a __FILE__ expansion, say: one entry for all agents
            raw = _AGENT_PREFIX_RE.sub("workspace/work/", raw)
        if is_directive:
            scan.blanked.append("")
            _scan_macro_event(raw, pos, scan.files[file_id], line_no, scan.macros)
        else:
            scan.blanked.append(raw)
        kept.append(raw)
        pos += _squeezed_len(raw)
        line_no += 1
    scan.digest = hashlib.sha256(" ".join(" ".join(kept).split()).encode("utf-8", "replace")).hexdigest()
    return scan


def _scan_macro_event(raw: str, pos: int, file: str, line: int, macros: dict[str, list[_MacroEvent]]) -> None:
    m = _DEFINE_RE.match(raw)
    if m:
        name = m.group(1)
        event = _MacroEvent(name, True, pos, file, line, m.group(2) or "", (m.group(3) or "").strip())
    else:
        m = _UNDEF_RE.match(raw)
        if not m:
            return
        name = m.group(1)
        event = _MacroEvent(name, False, pos, file, line)
    macros.setdefault(name, []).append(event)


# ---------------------------------------------------------------------------
# Declaration index
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Item:
    """A top-level function definition (`kind == "def"`) or declaration."""

    kind: str = "decl"
    functions: list[str] = field(default_factory=list)
    objects: list[str] = field(default_factory=list)
    typedefs: list[str] = field(default_factory=list)
    enumerators: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    fwd_tags: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    static: bool = False
    extern: bool = False
    has_init: bool = False
    start: int = 0
    end: int = 0
    # Origin in the current text. Filled on every run, never cached.
    file: str = ""
    start_line: int = 0
    end_line: int = 0

    def declares(self) -> bool:
        return any((self.functions, self.objects, self.typedefs, self.enumerators, self.tags, self.fwd_tags))


_CACHED_FIELDS = (
    "kind",
    "functions",
    "objects",
    "typedefs",
    "enumerators",
    "tags",
    "fwd_tags",
    "refs",
    "calls",
    "static",
    "extern",
    "has_init",
    "start",
    "end",
)


def _token_refs(tokens: Iterable[Token]) -> tuple[set[str], set[str]]:
    """(identifiers, identifiers in member position, which can only be macros)."""
    refs: set[str] = set()
    fields: set[str] = set()
    prev = prev2 = ""
    for tok in tokens:
        text = tok.text
        if tok.kind == "c_token" and _is_name(text):
            if prev == "." or (prev == ">" and prev2 == "-"):
                fields.add(text)
            else:
                refs.add(text)
        prev2, prev = prev, text
    return refs, fields


def _skip_attributes(tokens: list[Token], i: int) -> int:
    """Index just after the attribute-like groups (`__attribute__((...))`, `asm volatile (...)`) starting at `i`."""
    while i < len(tokens) and tokens[i].text in _ATTRIBUTE_WORDS:
        i += 1
        while i < len(tokens) and tokens[i].text in ("volatile", "__volatile__", "goto", "inline"):
            i += 1
        if i < len(tokens) and tokens[i].text == "(":
            close = _find_matching_forward(tokens, i, "(", ")")
            if close == -1:
                return len(tokens)
            i = close + 1
    return i


def _enumerators(body: list[Token]) -> list[str]:
    names: list[str] = []
    depth = 0
    expect = True
    for tok in body:
        text = tok.text
        if text in _OPENERS:
            depth += 1
        elif text in (")", "]", "}"):
            depth -= 1
        elif depth == 0:
            if text == ",":
                expect = True
            elif expect and _NAME_RE.match(text):
                names.append(text)
                expect = False
    return names


def _collect_tags(stmt: list[Token], item: _Item) -> list[str]:
    """Record tags defined anywhere in `stmt` and their enumerators; return tags only mentioned at top level."""
    mentions: list[str] = []
    depth = 0
    n = len(stmt)
    for i, tok in enumerate(stmt):
        text = tok.text
        if text in _OPENERS:
            depth += 1
        elif text in (")", "]", "}"):
            depth -= 1
        elif text in _TAG_WORDS:
            j = _skip_attributes(stmt, i + 1)
            tag = None
            if j < n and _is_name(stmt[j].text):
                tag = stmt[j].text
                j = _skip_attributes(stmt, j + 1)
            if j < n and stmt[j].text == "{":
                if tag:
                    item.tags.append(tag)
                if text == "enum":
                    close = _find_matching_forward(stmt, j, "{", "}")
                    if close != -1:
                        item.enumerators.extend(_enumerators(stmt[j + 1 : close]))
            elif tag and depth == 0:
                mentions.append(tag)
    return mentions


def _skip_tag_specifier(stmt: list[Token], i: int) -> int:
    """Index just after `struct [tag] [{ ... }]` starting at `i`."""
    j = _skip_attributes(stmt, i + 1)
    if j < len(stmt) and _is_name(stmt[j].text):
        j = _skip_attributes(stmt, j + 1)
    if j < len(stmt) and stmt[j].text == "{":
        close = _find_matching_forward(stmt, j, "{", "}")
        j = len(stmt) if close == -1 else _skip_attributes(stmt, close + 1)
    return j


def _skip_initializer(stmt: list[Token], i: int) -> int:
    """Index of the top-level comma ending the initializer that starts at `i`, or the end of `stmt`."""
    depth = 0
    while i < len(stmt):
        text = stmt[i].text
        if text in _OPENERS:
            depth += 1
        elif text in (")", "]", "}"):
            depth -= 1
        elif text == "," and depth == 0:
            return i
        i += 1
    return i


def _without_attributes(tokens: list[Token]) -> list[Token]:
    out: list[Token] = []
    i = 0
    while i < len(tokens):
        if tokens[i].text in _ATTRIBUTE_WORDS:
            i = _skip_attributes(tokens, i)
        else:
            out.append(tokens[i])
            i += 1
    return out


def _split_declarators(stmt: list[Token], item: _Item) -> list[list[Token]]:
    """Split a declaration at top-level commas, without tag bodies, attributes and initializers."""
    parts: list[list[Token]] = [[]]
    i = 0
    n = len(stmt)
    while i < n:
        text = stmt[i].text
        if text in _TAG_WORDS:
            i = _skip_tag_specifier(stmt, i)
            parts[-1].append(_PLACEHOLDER_TYPE)
        elif text in _ATTRIBUTE_WORDS:
            i = _skip_attributes(stmt, i)
        elif text in _TYPE_GROUP_WORDS and i + 1 < n and stmt[i + 1].text == "(":
            close = _find_matching_forward(stmt, i + 1, "(", ")")
            i = n if close == -1 else close + 1
            parts[-1].append(_PLACEHOLDER_TYPE)
        elif text == "=":
            item.has_init = True
            i = _skip_initializer(stmt, i + 1)
        elif text in _OPENERS:
            close = _find_matching_forward(stmt, i, text, _OPENERS[text])
            if close == -1:
                break
            if text != "{":
                parts[-1].extend(_without_attributes(stmt[i : close + 1]))
            i = close + 1
        elif text == ",":
            parts.append([])
            i += 1
        else:
            parts[-1].append(stmt[i])
            i += 1
    return parts


def _declarator(tokens: list[Token], continuation: bool = False) -> tuple[str | None, bool]:
    """
    (declared name, is a function) for specifiers plus one declarator: `int *x[3]`, `foo_t (*fp)(int)`,
    `void (*signal(int, void (*)(int)))(int)`, `int (f)(void)`. A bare `foo_t` declares nothing.
    """
    idents: list[str] = []
    has_specifier = continuation
    for idx, tok in enumerate(tokens):
        text = tok.text
        if text == "[":
            break
        if text == "(":
            close = _find_matching_forward(tokens, idx, "(", ")")
            if close == -1:
                break
            inner = tokens[idx + 1 : close]
            after = tokens[close + 1].text if close + 1 < len(tokens) else ""
            if inner and inner[0].text in ("*", "^"):
                return _declarator(inner[1:], continuation=True)
            if len(inner) == 1 and _is_name(inner[0].text) and (not idents or after in ("(", "[")):
                return inner[0].text, after == "("
            return (idents[-1], True) if idents else (None, False)
        if text in _C_WORDS:
            has_specifier = True
        elif _is_name(text):
            idents.append(text)
    if not idents or (len(idents) == 1 and not has_specifier):
        return None, False
    return idents[-1], False


def _parse_declaration(stmt: list[Token]) -> _Item | None:
    item = _Item()
    mentions = _collect_tags(stmt, item)
    parts = _split_declarators(stmt, item)
    first = {tok.text for tok in parts[0]}
    is_typedef = "typedef" in first
    item.static = "static" in first
    item.extern = "extern" in first
    for idx, part in enumerate(parts):
        name, is_function = _declarator(part, continuation=idx > 0)
        if not name:
            continue
        if is_typedef:
            item.typedefs.append(name)
        elif is_function:
            item.functions.append(name)
        else:
            item.objects.append(name)
    named = item.typedefs or item.functions or item.objects
    if is_typedef or not named:
        item.fwd_tags = [t for t in mentions if t not in item.tags]
    if not item.declares():
        return None
    refs, _ = _token_refs(stmt)
    declared = {*item.typedefs, *item.functions, *item.objects, *item.enumerators}
    item.refs = sorted(refs - declared)
    return item


def _function_header(c: list[Token], stmt: int, brace: int) -> tuple[str, list[Token], list[Token]] | None:
    """(name, parameter tokens, declaration prefix) when the tokens before `{` head a function definition."""
    depth = 0
    for tok in c[stmt:brace]:
        if tok.text == "(":
            depth += 1
        elif tok.text == ")":
            depth -= 1
        elif tok.text == "=" and depth == 0:
            return None
    before = _strip_trailing_attributes(c, brace, stmt - 1)
    # Without a preprocessor, an attribute macro can follow the parameter list: `int f(void) NORETURN {`.
    while before > stmt and _is_name(c[before].text):
        before -= 1
    if before < stmt or c[before].text != ")":
        return None
    open_params = _find_matching_backward(c, before, "(", ")")
    if open_params <= stmt - 1:
        return None
    name, params, prefix = _resolve_declarator(c, stmt - 1, open_params, before)
    if not name or not _is_ident(name):
        return None
    return name, params, prefix


def _call_names(body: list[Token], params: list[Token]) -> list[str]:
    """Identifiers called in `body`, without parameters and locals that hold function pointers."""
    body = _without_attributes(body)
    calls: set[str] = set()
    locals_: set[str] = {tok.text for tok in params if _is_name(tok.text)}
    n = len(body)
    for i, tok in enumerate(body):
        if tok.kind != "c_token" or not _is_name(tok.text):
            continue
        prev = body[i - 1].text if i else ""
        prev2 = body[i - 2].text if i > 1 else ""
        nxt = body[i + 1].text if i + 1 < n else ""
        if prev == "." or (prev == ">" and prev2 == "-"):
            continue
        if prev == "*" and prev2 == "(" and nxt == ")":
            locals_.add(tok.text)
        elif (prev in _C_WORDS or _is_name(prev)) and nxt in ("=", ";", ",", "["):
            locals_.add(tok.text)
        elif nxt == "(":
            calls.add(tok.text)
    return sorted(calls - locals_)


def _is_linkage_block(header: list[Token]) -> bool:
    return (len(header) >= 2 and header[-2].text == "extern" and header[-1].text in ('"C"', '"C++"')) or (
        len(header) == 1 and header[-1].text == "extern"
    )


def _parse_items(scan: _Scan) -> list[_Item]:
    """Split the preprocessed token stream into top-level items, positioned in `pos` units."""
    _, tokens = _tokenize_tolerant("\n".join(scan.blanked))
    c = [t for t in tokens if t.kind in ("c_token", "string")]

    char_starts: list[int] = []
    offset = 0
    for line in scan.blanked:
        char_starts.append(offset)
        offset += len(line) + 1

    def position(tok: Token) -> int:
        idx = tok.line - 1
        return scan.pos[idx] + _squeezed_len(scan.blanked[idx][: tok.start - char_starts[idx]])

    def add(item: _Item | None, first: Token, last: Token) -> None:
        if item is not None:
            item.start = position(first)
            item.end = position(last)
            items.append(item)

    items: list[_Item] = []
    n = len(c)
    i = stmt = 0
    while i < n:
        text = c[i].text
        if text == "(":
            close = _find_matching_forward(c, i, "(", ")")
            if close == -1:
                break
            i = close + 1
        elif text == "{":
            if _is_linkage_block(c[stmt:i]):
                i += 1
                stmt = i
                continue
            close = _find_matching_forward(c, i, "{", "}")
            if close == -1:
                break
            header = _function_header(c, stmt, i) if i > stmt else None
            if header is None:
                i = close + 1
                continue
            name, params, prefix = header
            prefix_words = {tok.text for tok in prefix}
            refs, _ = _token_refs(c[stmt : close + 1])
            item = _Item(
                kind="def",
                functions=[name],
                refs=sorted(refs - {name}),
                calls=_call_names(c[i + 1 : close], params),
                static="static" in prefix_words,
                extern="extern" in prefix_words,
            )
            add(item, c[stmt], c[close])
            i = close + 1
            stmt = i
        elif text == "}":
            i += 1
            stmt = i
        elif text == ";":
            if i > stmt:
                add(_parse_declaration(c[stmt:i]), c[stmt], c[i])
            i += 1
            stmt = i
        else:
            i += 1
    return items


def _load_index(scan: _Scan, mode: str, run_dir: Path) -> tuple[list[_Item], str]:
    """The items of this text, from the content-addressed cache when it is on. Second value: hit, miss or off."""
    if not cache.enabled(run_dir):
        return _parse_items(scan), "off"
    material = {"text_sha256": scan.digest, "mode": mode}
    try:
        key = cache.make_key(CACHE_NAMESPACE, material)
        entry = cache.lookup(CACHE_NAMESPACE, key, run_dir)
    except OSError:
        return _parse_items(scan), "off"
    if entry is not None:
        try:
            raw = json.loads((entry.path / "files" / INDEX_FILE).read_text(encoding="utf-8"))
            return [_Item(**row) for row in raw], "hit"
        except (OSError, ValueError, TypeError):
            pass
    items = _parse_items(scan)
    _publish_index(key, material, items, run_dir)
    return items, "miss"


def _publish_index(key: str, material: dict, items: list[_Item], run_dir: Path) -> None:
    rows = [{name: getattr(it, name) for name in _CACHED_FIELDS if getattr(it, name)} for it in items]
    tmp: str | None = None
    try:
        fd, tmp = tempfile.mkstemp(prefix="fc_slice_index_", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rows, f, separators=(",", ":"))
        cache.publish(CACHE_NAMESPACE, key, {INDEX_FILE: Path(tmp)}, {"items": len(rows)}, material, cwd=run_dir)
    except OSError:
        pass
    finally:
        if tmp:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


# ---------------------------------------------------------------------------
# Lexical fallback: the real files rendered as if preprocessed, with every branch active
# ---------------------------------------------------------------------------


def _clean_directive(text: str) -> str:
    unfolded = re.sub(r"\\\r?\n", " ", text)
    unfolded = re.sub(r"/\*.*?\*/", " ", unfolded, flags=re.DOTALL)
    if '"' not in unfolded:
        unfolded = re.sub(r"//.*", "", unfolded)
    return unfolded.strip()


def _trivial_condition(word: str, rest: str) -> bool | None:
    """The value of a conditional that needs no preprocessor (`#if 0`, `__cplusplus` guards), else None."""
    expr = " ".join(rest.split())
    if word == "if":
        if expr in ("0", "(0)"):
            return False
        if expr in ("1", "(1)"):
            return True
        if expr in ("defined(__cplusplus)", "defined __cplusplus"):
            return False
        if expr in ("!defined(__cplusplus)", "!defined __cplusplus"):
            return True
    elif word == "ifdef" and expr == "__cplusplus":
        return False
    elif word == "ifndef" and expr == "__cplusplus":
        return True
    return None


@dataclass(slots=True)
class _CondFrame:
    skipping: bool
    parent_skipping: bool
    settled: bool  # no later branch of this chain is emitted
    brace_delta: int = 0


def _lexical_text(tree: _Tree, source: Path, flags: list[str] | None) -> str:
    """
    Render `source` and the in-tree headers it includes like `gcc -E -dD` output, without evaluating
    conditionals beyond trivial ones. A first branch with unbalanced braces hides the other branches,
    because keeping both would swallow the rest of the file.
    """
    out: list[str] = []
    seen: set[str] = set()
    include_dirs: list[Path] = []
    forced: list[str] = []
    words = flags or []
    i = 0
    while i < len(words):
        word = words[i]
        if word in ("-I", "-iquote", "-isystem", "-idirafter", "-include") and i + 1 < len(words):
            if word == "-include":
                forced.append(words[i + 1])
            else:
                include_dirs.append(tree.run_dir / words[i + 1])
            i += 2
            continue
        if word.startswith("-I") and len(word) > 2:
            include_dirs.append(tree.run_dir / word[2:])
        i += 1
    include_dirs.append(tree.work_dir)

    def find_include(name: str, includer: Path | None) -> Path | None:
        for directory in ([includer] if includer is not None else []) + include_dirs:
            cand = directory / name
            if cand.is_file():
                rel = tree.rel(posixpath.normpath(cand.as_posix()))
                if rel is not None:
                    return cand
        return None

    def emit(path: Path) -> None:
        key = posixpath.normpath(path.as_posix())
        if key in seen:
            return
        seen.add(key)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        _, tokens = _tokenize_tolerant(text)
        out.append(f'# 1 "{key}"')
        next_line = 1
        buf: list[str] = []
        buf_line = 0
        frames: list[_CondFrame] = []

        def flush() -> None:
            nonlocal buf, next_line
            if buf:
                if buf_line != next_line:
                    out.append(f'# {buf_line} "{key}"')
                out.append(" ".join(buf))
                next_line = buf_line + 1
                buf = []

        def write_directive(line: int, text: str) -> None:
            nonlocal next_line
            if line != next_line:
                out.append(f'# {line} "{key}"')
            out.append(text)
            next_line = line + 1

        for tok in tokens:
            if tok.kind in ("whitespace", "c_comment") or tok.kind in _ACSL_KINDS:
                continue
            skipping = bool(frames) and frames[-1].skipping
            if tok.kind == "pp_directive":
                flush()
                m = _DIRECTIVE_WORD_RE.match(tok.text)
                word = m.group(1) if m else ""
                if m and word in ("if", "ifdef", "ifndef"):
                    known = _trivial_condition(word, _clean_directive(tok.text)[m.end() :])
                    frames.append(_CondFrame(skipping or known is False, skipping, known is True))
                elif word in ("elif", "else") and frames:
                    frame = frames[-1]
                    frame.settled = frame.settled or frame.brace_delta != 0
                    frame.skipping = frame.parent_skipping or frame.settled
                elif word == "endif" and frames:
                    frame = frames.pop()
                    if frames:
                        frames[-1].brace_delta += frame.brace_delta
                elif skipping:
                    pass
                elif word in ("define", "undef"):
                    write_directive(tok.line, _clean_directive(tok.text))
                elif word == "include":
                    inc = _INCLUDE_RE.match(tok.text)
                    if inc:
                        found = find_include(inc.group(1) or inc.group(2), path.parent if inc.group(1) else None)
                        if found is not None:
                            emit(found)
                            next_line = -1
                continue
            if skipping:
                continue
            if tok.text in ("{", "}") and tok.kind == "c_token" and frames:
                frames[-1].brace_delta += 1 if tok.text == "{" else -1
            if buf and tok.line != buf_line:
                flush()
            buf_line = tok.line
            buf.append(re.sub(r"\\\r?\n", "", tok.text))
        flush()

    for name in forced:
        found = find_include(name, tree.run_dir)
        if found is not None:
            emit(found)
    emit(source)
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# The real files
# ---------------------------------------------------------------------------


class _Tree:
    """Maps preprocessor origins to the source tree: `work_dir`, `workspace/work` or `/target`."""

    def __init__(self, run_dir: Path, work_dir: Path) -> None:
        self.run_dir = run_dir
        self.work_dir = work_dir
        self._run_posix = run_dir.as_posix().rstrip("/")
        self._work_posix = work_dir.as_posix().rstrip("/")

    def absolute(self, origin: str) -> str:
        path = origin.replace("\\", "/")
        if not _ABSOLUTE_RE.match(path):
            path = f"{self._run_posix}/{path}"
        return posixpath.normpath(path)

    def rel(self, origin: str) -> str | None:
        """Tree-relative path of `origin`, or None when it is outside the tree (libc, tool headers)."""
        if origin.startswith("<") or not origin:
            return None
        path = self.absolute(origin)
        if path.startswith(f"{self._work_posix}/"):
            return path[len(self._work_posix) + 1 :]
        for root in (self._run_posix, "/framac-run"):
            if path.startswith(f"{root}/"):
                m = _TREE_TAIL_RE.match(path[len(root) + 1 :])
                if m:
                    return m.group(1)
        if path.startswith("/target/"):
            return path[len("/target/") :]
        return None

    def normalize_rel(self, value: str) -> str:
        """A caller's path (c_file, header_file, a DAG `file`) as a path relative to the tree."""
        path = _REL_PREFIX_RE.sub("", (value or "").replace("\\", "/").strip())
        rel = self.rel(path) if (_ABSOLUTE_RE.match(path) or path.startswith(("agents/", "workspace/work/"))) else None
        return rel if rel is not None else path

    def candidates(self, origin: str) -> list[Path]:
        """
        Where to read `origin`. The file the preprocessor read comes first because origin line
        numbers are only valid for it; `_snapshot_first` makes that the snapshot's copy.
        """
        rel = self.rel(origin)
        found = [Path(self.absolute(origin))]
        if rel is not None:
            found.extend([self.work_dir / rel, self.run_dir / "workspace" / "work" / rel, Path("/target") / rel])
        return found


class _RealFile:
    def __init__(self, display: str, text: str) -> None:
        self.display = display
        self.lines = [line.rstrip("\r") for line in text.split("\n")]
        self.clean_text, tokens = _tokenize_tolerant(text)
        self.tokens = [t for t in tokens if t.kind != "whitespace"]
        self.token_lines = [t.line for t in self.tokens]

    def first_token_index(self, line: int) -> int:
        return bisect.bisect_left(self.token_lines, line)

    def directive_at(self, line: int) -> str | None:
        idx = self.first_token_index(line)
        while idx < len(self.tokens) and self.tokens[idx].line == line:
            if self.tokens[idx].kind == "pp_directive":
                return self.tokens[idx].text.replace("\r", "")
            idx += 1
        return None


@dataclass(slots=True)
class _Span:
    """Lines of a real file holding a declaration or definition, contract included."""

    file: str
    start: int
    end: int
    text: str
    head: str
    has_contract: bool = False
    is_definition: bool = False


def _text_has_contract(text: str) -> bool:
    _, tokens = _tokenize_tolerant(text)
    for tok in tokens:
        if tok.kind in _ACSL_KINDS:
            inner = tok.text[3:-2] if tok.kind == "acsl_block" else tok.text[3:]
            if any(seg.kind in _CONTRACT_KWS for seg in _parse_acsl_inner_segments(inner, tok.line)):
                return True
    return False


def _split_head(text: str) -> str:
    """The contract and signature of a definition: everything before the body's `{`."""
    try:
        offset = _find_body_brace_offset(text)
    except AcslSyntaxError:
        offset = None
    return text if offset is None else text[:offset].rstrip()


def _make_span(rf: _RealFile, start: int, end: int, is_definition: bool) -> _Span:
    text = "\n".join(rf.lines[start - 1 : end])
    head = _split_head(text) if is_definition else text
    return _Span(rf.display, start, end, text, head, _text_has_contract(head), is_definition)


def _locate_span(rf: _RealFile, name: str, is_header: bool) -> _Span | None:
    """`name` by lexical search: the first match, active or not, so only for when origins cannot tell."""
    try:
        found = locate_function_span(rf.clean_text, name, is_header=is_header, path=rf.display)
    except AcslSyntaxError:
        return None
    return None if found is None else _make_span(rf, found.start_line, found.end_line, not is_header)


def _walk_back(rf: _RealFile, start_line: int, with_contract: bool, floor_line: int = 0) -> int:
    """
    First line of the declaration whose first surviving token is on `start_line`: earlier lines can
    hold specifier macros that expanded to nothing and, for functions, its ACSL contract. C tokens
    on or before `floor_line` belong to the previous item, even if a macro hides its terminator.
    """
    tokens = rf.tokens
    first = start_line
    cursor = rf.first_token_index(start_line) - 1
    while cursor >= 0:
        tok = tokens[cursor]
        if tok.kind in _ACSL_KINDS:
            if not with_contract or tok.line < floor_line or _is_top_level_acsl_token(tok):
                break
            first = tok.line
            cursor -= 1
        elif tok.kind == "c_comment":
            j = cursor - 1
            while j >= 0 and tokens[j].kind == "c_comment":
                j -= 1
            if not (
                with_contract and j >= 0 and tokens[j].kind in _ACSL_KINDS and not _is_top_level_acsl_token(tokens[j])
            ):
                break
            cursor = j
        elif tok.kind in _C_KINDS and tok.text not in (";", "}", "{") and tok.line > floor_line:
            first = tok.line
            cursor -= 1
        else:
            break
    return first


def _extend_end(rf: _RealFile, start_line: int, end_line: int, limit_line: int) -> int:
    """
    gcc attributes a macro expansion to the invocation's first line, so an item ending in a multi-line
    invocation looks too short. Walk to its real terminator, never past the next item.
    """
    depth = 0
    for tok in rf.tokens[rf.first_token_index(start_line) :]:
        if tok.line > limit_line:
            break
        if tok.kind != "c_token":
            continue
        text = tok.text
        if text in _OPENERS:
            depth += 1
        elif text in (")", "]", "}"):
            depth = max(0, depth - 1)
            if text == "}" and depth == 0 and tok.line >= end_line:
                return tok.line
        elif text == ";" and depth == 0 and tok.line >= end_line:
            return tok.line
    return end_line


def _in_ranges(line: int, ranges: list[tuple[int, int]]) -> bool:
    return any(a <= line <= b for a, b in ranges)


def _inactive_ranges(rf: _RealFile, start: int, end: int, live: list[int]) -> list[tuple[int, int]]:
    """Merged `#if` branches inside lines start..end that hold C tokens but left nothing in the preprocessed text."""
    found: list[tuple[int, int]] = []
    stack: list[list] = []  # [first line of the branch, holds C tokens]

    def close_branch(last: int) -> None:
        first, has_code = stack[-1]
        if has_code and first <= last and bisect.bisect_left(live, first) == bisect.bisect_right(live, last):
            found.append((first, last))

    idx = rf.first_token_index(start)
    while idx < len(rf.tokens) and rf.tokens[idx].line <= end:
        tok = rf.tokens[idx]
        idx += 1
        if tok.kind == "pp_directive":
            m = _DIRECTIVE_WORD_RE.match(tok.text)
            word = m.group(1) if m else ""
            directive_end = tok.line + tok.text.count("\n")
            if word in ("if", "ifdef", "ifndef"):
                stack.append([directive_end + 1, False])
            elif word in ("elif", "else") and stack:
                close_branch(tok.line - 1)
                stack[-1] = [directive_end + 1, False]
            elif word == "endif" and stack:
                close_branch(tok.line - 1)
                stack.pop()
        elif tok.kind in _C_KINDS:
            for frame in stack:
                frame[1] = True
    merged: list[tuple[int, int]] = []
    for a, b in sorted(found):
        if merged and a <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def _acsl_refs(text: str) -> tuple[set[str], set[str]]:
    clean = _ACSL_NOISE_RE.sub(" ", text)
    refs: set[str] = set()
    fields: set[str] = set()
    for m in _ACSL_IDENT_RE.finditer(clean):
        before = clean[max(0, m.start() - 4) : m.start()].rstrip()
        if before.endswith("->") or (before.endswith(".") and not before.endswith("..")):
            fields.add(m.group(0))
        else:
            refs.add(m.group(0))
    return refs, fields


def _text_refs(
    text: str, inactive: list[tuple[int, int]] | None = None, first_line: int = 1
) -> tuple[set[str], set[str]]:
    """(identifiers, macro-only identifiers) of real source: C tokens, ACSL and conditional directives."""
    _, tokens = _tokenize_tolerant(text)
    c_tokens: list[Token] = []
    refs: set[str] = set()
    fields: set[str] = set()
    for tok in tokens:
        if tok.kind in ("whitespace", "c_comment"):
            continue
        if inactive and _in_ranges(first_line + tok.line - 1, inactive):
            continue
        if tok.kind in _ACSL_KINDS:
            acsl, members = _acsl_refs(tok.text)
            refs |= acsl
            fields |= members
        elif tok.kind == "pp_directive":
            m = _DIRECTIVE_WORD_RE.match(tok.text)
            if m and m.group(1) in ("if", "ifdef", "ifndef", "elif"):
                fields |= set(_IDENT_FIND_RE.findall(_clean_directive(tok.text)[m.end() :])) - {"defined"}
        elif tok.kind in _C_KINDS:
            c_tokens.append(tok)
    plain, members = _token_refs(c_tokens)
    return refs | plain, fields | members


def _macro_refs(event: _MacroEvent) -> tuple[set[str], set[str]]:
    # The leading number keeps a body that starts with `#` (stringify) from reading as a directive.
    _, tokens = _tokenize_tolerant(f"0 {event.body}")
    refs, fields = _token_refs(t for t in tokens if t.kind in _C_KINDS)
    params = set(_IDENT_FIND_RE.findall(event.params)) if event.params else set()
    return refs - params - {event.name}, fields - params


def _strip_normal_comments(text: str) -> str:
    """`text` without its non-ACSL comments and the blank lines that leaves. ACSL stays."""
    clean, tokens = _tokenize_tolerant(text)
    parts: list[str] = []
    last = 0
    for tok in tokens:
        if tok.kind == "c_comment":
            parts.append(clean[last : tok.start])
            last = tok.end
    parts.append(clean[last:])
    lines = (line.rstrip() for line in "".join(parts).split("\n"))
    return "\n".join(line for line in lines if line)


def _abbreviate_global(text: str, where: str) -> tuple[str, bool]:
    """Shorten a long initializer for reading. The declaration keeps its meaning; a note points at the rest."""
    lines = text.split("\n")
    if "=" not in text or (len(lines) <= GLOBAL_MAX_LINES and len(text) <= GLOBAL_MAX_CHARS):
        return text, False
    head = [
        line if len(line) <= GLOBAL_HEAD_LINE_CHARS else f"{line[:GLOBAL_HEAD_LINE_CHARS]} ..."
        for line in lines[:GLOBAL_HEAD_LINES]
    ]
    head.append(
        f"/* ... initializer abbreviated here ({len(lines)} lines, {len(text)} characters); full text: {where} */"
    )
    return "\n".join(head), True


# ---------------------------------------------------------------------------
# Closure
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Entry:
    section: str
    order: tuple
    depth: int
    text: str
    label: str


@dataclass(slots=True)
class _LogicDecl:
    kind: str
    names: set[str]
    text: str
    file: str
    line: int
    order: tuple


@dataclass(slots=True)
class _FunctionInfo:
    name: str
    shown: list[_Span] = field(default_factory=list)
    body: _Span | None = None
    file: str | None = None
    line: int = 0
    has_contract: bool = False
    kind: str = "libc_or_external"
    is_static: bool = False
    order: tuple = (1 << 62,)
    scope: tuple[int, int] = (0, 0)
    declared: bool = False


class _Slicer:
    """One translation unit's index plus the real files, for one target."""

    def __init__(
        self,
        tree: _Tree,
        scan: _Scan,
        items: list[_Item],
        function: str,
        c_rel: str,
        resolved: bool,
        dag_functions: dict | None,
    ) -> None:
        self.tree = tree
        self.scan = scan
        self.function = function
        self.c_rel = c_rel
        self.resolved = resolved
        self.dag = dag_functions if isinstance(dag_functions, dict) else {}
        self.files: dict[str, _RealFile | None] = {}
        self.functions: dict[str, list[_Item]] = {}
        self.names: dict[str, list[_Item]] = {}
        self.tags: dict[str, list[_Item]] = {}
        self.starts: dict[str, list[int]] = {}
        self.ends: dict[str, list[int]] = {}
        self.fn_info: dict[str, _FunctionInfo] = {}
        self.entries: list[_Entry] = []
        self.logic_by_name: dict[str, list[_LogicDecl]] = {}
        self.added: set = set()
        self.ranges_printed: dict[str, list[tuple[int, int]]] = {}
        self.target_scope: tuple[int, int] = (0, 0)
        self.target_range: tuple[str, int, int] = ("", 0, 0)
        self.external_names: set[str] = set()
        self.reached_functions: dict[str, int] = {}
        self.live_cache: dict[str, list[int]] = {}

        for item in items:
            item.file, item.start_line = scan.origin(item.start)
            end_file, end_line = scan.origin(item.end)
            item.end_line = end_line if end_file == item.file else item.start_line
            self.starts.setdefault(item.file, []).append(item.start_line)
            self.ends.setdefault(item.file, []).append(item.end_line)
            for name in item.functions:
                self.functions.setdefault(name, []).append(item)
            for name in (*item.objects, *item.typedefs, *item.enumerators):
                self.names.setdefault(name, []).append(item)
            for tag in (*item.tags, *item.fwd_tags):
                self.tags.setdefault(tag, []).append(item)
        for lines in (*self.starts.values(), *self.ends.values()):
            lines.sort()

    # -- real files ---------------------------------------------------------

    def real_file(self, origin: str) -> _RealFile | None:
        if origin in self.files:
            return self.files[origin]
        rel = self.tree.rel(origin)
        loaded: _RealFile | None = None
        for path in self.tree.candidates(origin):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            loaded = _RealFile(rel if rel is not None else origin, text)
            break
        self.files[origin] = loaded
        return loaded

    def live_lines(self, origin: str) -> list[int]:
        if origin not in self.live_cache:
            self.live_cache[origin] = self.scan.live_lines(origin)
        return self.live_cache[origin]

    def inactive(self, origin: str, rf: _RealFile, start: int, end: int) -> list[tuple[int, int]]:
        return _inactive_ranges(rf, start, end, self.live_lines(origin)) if self.resolved else []

    def item_span(self, item: _Item, with_contract: bool) -> _Span | None:
        rf = self.real_file(item.file)
        if rf is None:
            return None
        starts = self.starts.get(item.file, [])
        next_idx = bisect.bisect_right(starts, item.end_line)
        limit = starts[next_idx] - 1 if next_idx < len(starts) else len(rf.lines)
        ends = self.ends.get(item.file, [])
        prev_idx = bisect.bisect_left(ends, item.start_line) - 1
        first = _walk_back(rf, item.start_line, with_contract, ends[prev_idx] if prev_idx >= 0 else 0)
        last = _extend_end(rf, item.start_line, item.end_line, limit)
        if first > len(rf.lines):
            return None
        return _make_span(rf, first, last, item.kind == "def")

    def in_tree(self, item: _Item) -> bool:
        return self.tree.rel(item.file) is not None

    # -- logic declarations -------------------------------------------------

    def index_logic(self) -> None:
        """ACSL logic declarations of every in-tree file of this translation unit."""
        for file_order, origin in enumerate(self.scan.files):
            if self.tree.rel(origin) is None:
                continue
            rf = self.real_file(origin)
            if rf is None or ("/*@" not in rf.clean_text and "//@" not in rf.clean_text):
                continue
            if not any(tok.kind in _ACSL_KINDS and _is_top_level_acsl_token(tok) for tok in rf.tokens):
                continue
            inactive = self.inactive(origin, rf, 1, len(rf.lines))
            try:
                decls = extract_top_level_acsl_declarations(rf.clean_text, path=rf.display)
            except AcslSyntaxError:
                continue
            for decl in decls:
                if decl["kind"] == "lemma" or _in_ranges(decl["line"], inactive):
                    continue
                names = {decl["name"]}
                if decl["kind"] == "axiomatic":
                    names |= self._axiomatic_names(decl["text"])
                logic = _LogicDecl(
                    decl["kind"], names, decl["text"], rf.display, decl["line"], (file_order, decl["line"])
                )
                for name in names:
                    self.logic_by_name.setdefault(name, []).append(logic)

    @staticmethod
    def _axiomatic_names(text: str) -> set[str]:
        open_brace, close_brace = text.find("{"), text.rfind("}")
        if open_brace == -1 or close_brace <= open_brace:
            return set()
        try:
            inner = extract_top_level_acsl_declarations(f"/*@ {text[open_brace + 1 : close_brace]} */")
        except AcslSyntaxError:
            return set()
        return {d["name"] for d in inner}

    # -- macros -------------------------------------------------------------

    def macro_defs(self, name: str, scope: tuple[int, int]) -> list[_MacroEvent]:
        """The definition active at the start of `scope`, plus any made inside it. Unresolved: every definition."""
        events = self.scan.macros.get(name)
        if not events:
            return []
        if not self.resolved:
            return [e for e in events if e.is_define]
        active: _MacroEvent | None = None
        inside: list[_MacroEvent] = []
        for event in events:
            if event.pos <= scope[0]:
                active = event if event.is_define else None
            elif event.pos <= scope[1] and event.is_define:
                inside.append(event)
        return ([active] if active is not None else []) + inside

    def macro_text(self, event: _MacroEvent) -> str:
        rf = self.real_file(event.file)
        directive = rf.directive_at(event.line) if rf is not None else None
        if directive and re.search(rf"\b{re.escape(event.name)}\b", directive):
            return _PADDED_CONTINUATION_RE.sub(" \\\\", directive)
        return f"#define {event.name}{event.params} {event.body}".rstrip()

    # -- functions ----------------------------------------------------------

    def dag_definition(self, name: str) -> _Span | None:
        """A non-static definition in another translation unit, only when that file really holds it."""
        metas = [self.dag.get(name)]
        metas.extend(meta for key, meta in self.dag.items() if isinstance(key, str) and key.endswith(f"#{name}"))
        for meta in metas:
            if not isinstance(meta, dict) or meta.get("is_static") or not isinstance(meta.get("file"), str):
                continue
            rel = self.tree.normalize_rel(meta["file"])
            if rel == self.c_rel or not is_safe_relative_path(rel):
                continue
            rf = self.real_file(self.tree.work_dir.joinpath(rel).as_posix())
            if rf is None:
                continue
            found = _locate_span(rf, name, is_header=False)
            if found is None:
                continue
            signature = found.head[: found.head.rfind(name)] if name in found.head else ""
            if re.search(r"\bstatic\b", _strip_comments(signature)):
                continue
            return found
        return None

    def resolve_function(self, name: str) -> _FunctionInfo:
        info = self.fn_info.get(name)
        if info is not None:
            return info
        info = _FunctionInfo(name, scope=self.target_scope)
        self.fn_info[name] = info
        candidates = self.functions.get(name, [])
        info.declared = bool(candidates)
        spans: list[_Span] = []
        external: _Item | None = None
        definition: _Span | None = None
        for item in candidates:
            if not self.in_tree(item):
                external = external or item
                continue
            span = self.item_span(item, with_contract=True)
            if span is None:
                continue
            if not spans:
                info.order = (item.start,)
                info.scope = (item.start, item.end)
            spans.append(span)
            info.is_static = info.is_static or item.static
            if item.kind == "def" and definition is None:
                definition = span
        if definition is None:
            from_dag = self.dag_definition(name)
            if from_dag is not None:
                definition = from_dag
                if from_dag.has_contract or not spans:
                    spans.append(from_dag)
        info.body = definition
        if spans:
            with_contract = [s for s in spans if s.has_contract]
            prototypes_first = sorted(with_contract or spans, key=lambda s: s.is_definition)
            info.shown = prototypes_first if with_contract else prototypes_first[:1]
            if not self.resolved and len(info.shown) > UNRESOLVED_DECLS_SHOWN:
                info.shown = info.shown[:UNRESOLVED_DECLS_SHOWN]
            info.kind = "in_tree"
            info.file = info.shown[0].file
            info.line = info.shown[0].start
            info.has_contract = bool(with_contract)
        elif external is not None:
            info.file = external.file
            info.line = external.start_line
            span = self.item_span(external, with_contract=True)
            info.has_contract = bool(span and span.has_contract)
        return info

    def function_entry(self, info: _FunctionInfo, section: str, depth: int) -> _Entry:
        parts: list[str] = []
        for span in info.shown:
            where = f"{span.file}:{span.start}-{span.end}"
            if span.is_definition:
                storage = "static " if info.is_static and span.file == info.file else ""
                parts.append(f"/* {where} ({storage}definition; body not shown) */")
            else:
                parts.append(f"/* {where} */")
            if not span.has_contract:
                parts.append("/* no contract yet */")
            parts.append(f"{span.head};" if span.is_definition else span.text)
        return _Entry(section, info.order, depth, "\n".join(parts), info.name)

    # -- worklist -----------------------------------------------------------

    def close_over(
        self, refs: set[str], fields: set[str], scope: tuple[int, int], functions: Iterable[str] = ()
    ) -> None:
        """Worklist over identifiers. `functions` are callees no declaration in this unit names."""
        queue: deque[tuple[str, tuple[int, int], int, bool]] = deque()

        def push(names: Iterable[str], where: tuple[int, int], depth: int, macro_only: bool = False) -> None:
            queue.extend((name, where, depth, macro_only) for name in sorted(names))

        push(refs, scope, 0)
        push(fields, scope, 0, macro_only=True)
        for name in functions:
            self.add_function(name, 0, push)
        visited: set[tuple[str, tuple[int, int], bool]] = set()
        while queue:
            name, where, depth, macro_only = queue.popleft()
            key = (name, where, macro_only)
            if key in visited:
                continue
            visited.add(key)
            for event in self.macro_defs(name, where):
                self.add_macro(event, where, depth, push)
            if macro_only:
                continue
            for decl in self.logic_by_name.get(name, []):
                self.add_logic(decl, where, depth, push)
            for item in self.best_items(self.names.get(name, []), name, depth):
                self.add_item(item, depth, push)
            for item in self.best_tag_items(name, depth):
                self.add_item(item, depth, push)
            if name != self.function and name in self.functions:
                self.add_function(name, depth, push)

    def best_items(self, candidates: list[_Item], name: str, depth: int) -> list[_Item]:
        in_tree = [c for c in candidates if self.in_tree(c)]
        if not in_tree:
            if depth == 0 and candidates:
                self.external_names.add(name)
            return []
        if not self.resolved:
            return in_tree[:UNRESOLVED_DECLS_SHOWN]
        objects = [c for c in in_tree if name in c.objects]
        if objects:
            # First of the strongest: a definition with its value says more than `extern int x;`.
            return [max(objects, key=lambda c: (c.has_init, not c.extern))]
        return in_tree[:1]

    def best_tag_items(self, name: str, depth: int) -> list[_Item]:
        candidates = self.tags.get(name, [])
        definitions = [c for c in candidates if name in c.tags]
        return self.best_items(definitions or candidates, name, depth)

    def add_macro(self, event: _MacroEvent, where: tuple[int, int], depth: int, push: Callable) -> None:
        key = ("macro", event.name, event.pos)
        if key in self.added:
            return
        self.added.add(key)
        rel = self.tree.rel(event.file)
        if rel is None:
            if depth == 0:
                self.external_names.add(event.name)
            return
        refs, fields = _macro_refs(event)
        push(refs, where, depth + 1)
        push(fields, where, depth + 1, macro_only=True)
        # A macro defined inside the target is already on screen, in the target's own text.
        target_file, target_start, target_end = self.target_range
        if rel == target_file and target_start <= event.line <= target_end:
            return
        rf = self.real_file(event.file)
        display = rf.display if rf is not None else rel
        text = f"/* {display}:{event.line} */\n{self.macro_text(event)}"
        self.entries.append(_Entry("macros", (event.pos,), depth, text, event.name))

    def add_logic(self, decl: _LogicDecl, where: tuple[int, int], depth: int, push: Callable) -> None:
        key = ("logic", decl.file, decl.line, decl.kind, tuple(sorted(decl.names)))
        if key in self.added:
            return
        self.added.add(key)
        text = f"/* {decl.file}:{decl.line} */\n/*@ {decl.text} */"
        self.entries.append(_Entry("logic", decl.order, depth, text, sorted(decl.names)[0]))
        refs, fields = _acsl_refs(decl.text)
        push(refs - decl.names, where, depth + 1)
        push(fields, where, depth + 1, macro_only=True)

    def add_item(self, item: _Item, depth: int, push: Callable) -> None:
        key = ("item", item.start)
        if key in self.added:
            return
        self.added.add(key)
        span = self.item_span(item, with_contract=False)
        if span is None:
            return
        where = (item.start, item.end)
        is_type = bool(item.typedefs or item.tags or item.fwd_tags or item.enumerators)
        location = f"{span.file}:{span.start}-{span.end}"
        text = span.text
        abbreviated = False
        attribution = location
        if not is_type:
            text, abbreviated = _abbreviate_global(text, location)
        elif _line_count(text) > TYPE_MAX_LINES_WITH_COMMENTS:
            text = _strip_normal_comments(text)
            attribution = f"{location}, comments removed for size"
        refs, fields = _text_refs(text)
        if not abbreviated:
            refs |= set(item.refs)
        push(refs, where, depth + 1)
        push(fields, where, depth + 1, macro_only=True)
        printed = self.ranges_printed.setdefault(span.file, [])
        if any(a <= span.start and span.end <= b for a, b in printed):
            return
        printed.append((span.start, span.end))
        labels = (*item.typedefs, *item.tags, *item.objects, *item.enumerators, *item.fwd_tags, "?")
        section = "types" if is_type else "globals"
        self.entries.append(_Entry(section, (item.start,), depth, f"/* {attribution} */\n{text}", labels[0]))

    def add_function(self, name: str, depth: int, push: Callable) -> None:
        previous = self.reached_functions.get(name)
        if previous is not None and previous <= depth:
            return
        self.reached_functions[name] = depth
        if previous is not None:
            return
        info = self.resolve_function(name)
        if info.kind != "in_tree":
            if depth == 0:
                self.external_names.add(name)
            return
        for span in info.shown:
            refs, fields = _text_refs(span.head)
            push(refs - {name}, info.scope, depth + 1)
            push(fields, info.scope, depth + 1, macro_only=True)


def _strip_comments(text: str) -> str:
    return re.sub(r"//[^\n]*", " ", re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_SECTION_ORDER = ("macros", "types", "globals", "logic", "callees", "referenced")
# When cutting: callee contracts first, then logic, then whatever is closest to the target.
_CUT_RANK = {"callees": 0, "logic": 1, "macros": 2, "types": 2, "globals": 2, "referenced": 3}


def _section_titles(resolved: bool) -> dict[str, str]:
    macro_note = "active at the target" if resolved else "every definition found: conditionals are NOT resolved"
    return {
        "macros": f"Macros ({macro_note})",
        "types": "Types (translation-unit order)",
        "globals": "Globals",
        "logic": "ACSL logic declarations",
        "callees": "Callee prototypes with their current contracts (the only thing WP uses of a callee)",
        "referenced": "Other functions the declarations above refer to",
    }


def _assemble(header: str, entries: list[_Entry], target_block: str, titles: dict[str, str], note: str = "") -> str:
    blocks = [header]
    if note:
        blocks.append(note)
    by_section: dict[str, list[_Entry]] = {}
    for entry in entries:
        by_section.setdefault(entry.section, []).append(entry)
    for section in _SECTION_ORDER:
        rows = sorted(by_section.get(section, []), key=lambda e: e.order)
        if rows:
            blocks.append(f"/* ======== {titles[section]} ======== */")
            blocks.extend(row.text for row in rows)
    blocks.append(target_block)
    return "\n\n".join(blocks) + "\n"


def _line_count(text: str) -> int:
    return text.count("\n") + 1


def _fit_entries(entries: list[_Entry], budget: int) -> tuple[list[_Entry], list[_Entry]]:
    """Keep entries by rank, then closeness to the target, until the line budget is spent."""
    kept: list[_Entry] = []
    omitted: list[_Entry] = []
    opened: set[str] = set()
    for entry in sorted(
        entries, key=lambda e: (_CUT_RANK[e.section], e.depth, _SECTION_ORDER.index(e.section), e.order)
    ):
        cost = _line_count(entry.text) + 1 + (0 if entry.section in opened else 2)
        if cost <= budget:
            budget -= cost
            kept.append(entry)
            opened.add(entry.section)
        else:
            omitted.append(entry)
    return kept, omitted


def _omission_note(omitted: list[_Entry], slice_file: str | None) -> str:
    by_section: dict[str, list[str]] = {}
    for entry in omitted:
        by_section.setdefault(entry.section, []).append(entry.label)
    shown = 0
    details: list[str] = []
    for section in _SECTION_ORDER:
        labels = sorted(set(by_section.get(section, [])))
        if not labels:
            continue
        room = max(0, OMITTED_NAMES_SHOWN - shown)
        listed = ", ".join(labels[:room])
        more = len(labels) - min(room, len(labels))
        shown += min(room, len(labels))
        tail = f"{', ' if listed else ''}and {more} more" if more else ""
        details.append(f"{section}: {listed}{tail}")
    where = f"Read {slice_file} for the rest." if slice_file else "The full slice was not written to a file."
    return f"/* TRUNCATED to fit the brief; the target below is complete. {where}\n * Omitted: {'; '.join(details)}. */"


def _name_list(names: list[str]) -> str:
    shown = ", ".join(names[:OMITTED_NAMES_SHOWN])
    return f"{shown}, and {len(names) - OMITTED_NAMES_SHOWN} more" if len(names) > OMITTED_NAMES_SHOWN else shown


def _render_bodies(function: str, infos: list[_FunctionInfo]) -> str:
    blocks = [
        "/*\n"
        f" * OPTIONAL READING: bodies of the in-tree callees of `{function}`.\n"
        " * WP only ever uses callee contracts: a fact visible here is not available to the proof until the\n"
        " * callee's contract states it. Ask for that with a strengthening request.\n"
        " * Reading context only: do not compile, include or edit this file.\n"
        " */"
    ]
    total = 0
    omitted: list[str] = []
    for info in infos:
        span = info.body
        if span is None:
            continue
        lines = span.text.split("\n")
        cost = min(len(lines), CALLEE_BODY_MAX_LINES)
        if total + cost > CALLEE_BODIES_MAX_LINES:
            omitted.append(f"{info.name} ({span.file}:{span.start}-{span.end})")
            continue
        total += cost
        shown = "\n".join(lines[:CALLEE_BODY_MAX_LINES])
        if len(lines) > CALLEE_BODY_MAX_LINES:
            shown += f"\n/* ... {len(lines) - CALLEE_BODY_MAX_LINES} more lines omitted; see {span.file}:{span.start}-{span.end} */"
        blocks.append(f"/* {span.file}:{span.start}-{span.end} */\n{shown}")
    if omitted:
        blocks.append(f"/* Omitted for size, read the real files: {', '.join(omitted)} */")
    return "\n\n".join(blocks) + "\n"


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


# ---------------------------------------------------------------------------
# build_slice
# ---------------------------------------------------------------------------


def _result_skeleton(function: str, c_file: str) -> dict:
    return {
        "status": "not_found",
        "reason": None,
        "function": function,
        "file": c_file,
        "conditionals": "unresolved",
        "slice_file": None,
        "callee_bodies_file": None,
        "text": "",
        "truncated": False,
        "target": None,
        "header_prototype": None,
        "callees": [],
        "stats": {"lines": 0, "macros": 0, "types": 0, "globals": 0, "callees": 0, "logic_decls": 0},
        "preprocessor": None,
        "index_cache": "off",
    }


def _locate_target(slicer: _Slicer, source: Path, notes: list[str]) -> tuple[_Item, _Span] | None:
    """The target's item and real span; None, with the reason first in `notes`, when it has no active definition."""
    function, c_rel = slicer.function, slicer.c_rel
    definitions = [it for it in slicer.functions.get(function, []) if it.kind == "def"]
    chosen = [it for it in definitions if slicer.tree.rel(it.file) == c_rel] or [
        it for it in definitions if slicer.in_tree(it)
    ]
    if chosen:
        span = slicer.item_span(chosen[0], with_contract=True)
        if span is not None:
            if not slicer.resolved and len(definitions) > 1:
                notes.append(f"several definitions of `{function}` under unresolved conditionals: showing the first")
            return chosen[0], span
    # Not in the index: inactive code, or a definition the lexical fallback could not parse.
    rf = _RealFile(c_rel, source.read_text(encoding="utf-8", errors="replace"))
    span = _locate_span(rf, function, is_header=False)
    if span is None:
        notes.insert(0, f"no definition of `{function}` in {c_rel}")
        return None
    if slicer.resolved:
        notes.insert(0, f"`{function}` is defined only in an inactive #if branch of {c_rel} under these flags")
        return None
    origin = source.as_posix()
    slicer.files[origin] = rf
    return _Item(kind="def", functions=[function], file=origin, start_line=span.start, end_line=span.end), span


def _header_prototype(slicer: _Slicer, header_rel: str | None, target_span: _Span) -> _Span | None:
    """The target's prototype outside its definition: the wanted header, else one holding a contract."""
    function = slicer.function
    spans: list[_Span] = []
    for item in slicer.functions.get(function, []):
        if item.kind == "decl" and slicer.in_tree(item):
            span = slicer.item_span(item, with_contract=True)
            if span is not None and (span.file, span.start) != (target_span.file, target_span.start):
                spans.append(span)
    if header_rel:
        for span in spans:
            if span.file == header_rel:
                return span
        rf = slicer.real_file(slicer.tree.work_dir.joinpath(header_rel).as_posix())
        located = _locate_span(rf, function, is_header=True) if rf is not None else None
        if located is not None:
            return located
    with_contract = [s for s in spans if s.has_contract]
    if with_contract:
        return with_contract[0]
    others = [s for s in spans if s.file != slicer.c_rel]
    return others[0] if others else None


def _called_names(slicer: _Slicer, target: _Item, refs: set[str], fields: set[str]) -> set[str]:
    """What the target calls. Without a preprocessor its macros are not expanded, so read their bodies too."""
    calls = set(target.calls)
    if slicer.resolved:
        return calls
    pending = deque(sorted(refs | fields))
    seen: set[str] = set()
    while pending:
        name = pending.popleft()
        if name in seen:
            continue
        seen.add(name)
        for event in slicer.scan.macros.get(name, []):
            if event.is_define:
                macro_refs, macro_fields = _macro_refs(event)
                pending.extend(sorted(macro_refs | macro_fields))
                _, tokens = _tokenize_tolerant(f"0 {event.body}")
                calls.update(_call_names([t for t in tokens if t.kind in _C_KINDS], []))
    return calls


def _collect_callees(slicer: _Slicer, names: set[str]) -> tuple[list[dict], list[_FunctionInfo]]:
    """The `callees` rows and the in-tree callees, leaving out names that turned out not to be functions."""
    rows: list[dict] = []
    in_tree: list[_FunctionInfo] = []
    for name in sorted(names):
        if name == slicer.function or name.startswith("__builtin"):
            continue
        info = slicer.resolve_function(name)
        is_other = name in slicer.scan.macros or name in slicer.names or name in slicer.tags
        if info.kind != "in_tree" and not info.declared and is_other:
            continue
        rows.append(
            {
                "name": name,
                "file": info.file,
                "line": info.line,
                "has_contract": info.has_contract,
                "kind": info.kind,
            }
        )
        if info.kind == "in_tree":
            in_tree.append(info)
    return rows, in_tree


def _slice_header(
    function: str, proof_path: str, span: _Span, preprocessor: str, externals: list[str], outside: list[str]
) -> str:
    lines = [
        "/*",
        f" * READING CONTEXT ONLY: slice of `{function}` for its Function Prover.",
        " * Do not compile, include or edit this file; it can differ from the compiled program.",
        f" * Proof target (edit and prove there): {proof_path}, lines {span.start}-{span.end}.",
        " * Contracts shown are those of the snapshot this agent was prepared from.",
    ]
    if preprocessor == "framac":
        lines.append(" * Conditionals resolved by Frama-C's preprocessor with the prover's flags.")
    elif preprocessor == "gcc":
        lines.append(" * Conditionals resolved by plain gcc, not Frama-C's preprocessor, with the prover's flags.")
    else:
        lines.append(" * WARNING: NO PREPROCESSOR RAN. #if conditionals are NOT resolved: declarations from inactive")
        lines.append(" * branches may appear below and libc declarations are absent. Check against the real file.")
    if externals:
        lines.append(f" * Libc or external callees, not shown: {_name_list(externals)}.")
    if outside:
        lines.append(f" * Other names from libc or tool headers, not shown: {_name_list(outside)}.")
    lines.append(" */")
    return "\n".join(lines)


def _target_block(function: str, span: _Span, header_span: _Span | None, inactive: list[tuple[int, int]]) -> str:
    parts = [f"/* ======== Target: {function} ======== */"]
    if header_span is not None:
        parts.append(f"/* Its prototype: {header_span.file}:{header_span.start}-{header_span.end} */")
        parts.append(header_span.text)
        parts.append("")
    if inactive:
        ranges = ", ".join(f"{a}-{b}" for a, b in inactive)
        parts.append(
            f"/* Lines {ranges} are in inactive #if branches under these flags: Frama-C sees neither that code "
            "nor annotations in it. */"
        )
    parts.append(f"/* {span.file}:{span.start}-{span.end} */")
    parts.append(span.text)
    return "\n".join(parts)


def _write_outputs(
    out_dir: Path, run_dir: Path, function: str, full_text: str, bodies: str | None, result: dict, notes: list[str]
) -> None:
    out_path = out_dir if out_dir.is_absolute() else run_dir / out_dir
    slice_path = out_path / f"{function}.slice.c"
    bodies_path = out_path / f"{function}.callee_bodies.c"
    try:
        _write_text(slice_path, full_text)
        result["slice_file"] = to_run_relative(slice_path, run_dir)
        if bodies is not None:
            _write_text(bodies_path, bodies)
            result["callee_bodies_file"] = to_run_relative(bodies_path, run_dir)
        else:
            bodies_path.unlink(missing_ok=True)  # an earlier agent's file must not pass for this one's
    except OSError as exc:
        notes.append(f"could not write the slice files ({exc})")


def _build(
    run_dir: Path,
    work_dir: Path,
    c_file: str,
    function: str,
    cppflags: str,
    out_dir: Path | None,
    header_file: str | None,
    dag_functions: dict | None,
    machdep: str,
    max_inline_lines: int,
    callee_bodies: bool,
    runner: Callable | None,
) -> dict:
    run_dir = Path(run_dir).resolve()
    work_path = Path(work_dir)
    work_path = (work_path if work_path.is_absolute() else run_dir / work_path).resolve()
    tree = _Tree(run_dir, work_path)

    function = (function or "").rsplit("#", 1)[-1].strip()
    c_rel = tree.normalize_rel(c_file)
    result = _result_skeleton(function, c_rel)
    source = work_path / c_rel
    if not _NAME_RE.match(function):
        result["reason"] = f"not a C identifier: {function!r}"
        return result
    if not is_safe_relative_path(c_rel):
        result["reason"] = f"unsafe source path: {c_file!r}"
        return result
    if not source.is_file():
        result["reason"] = f"source file not found: {source.as_posix()}"
        return result
    header_rel = tree.normalize_rel(header_file) if header_file else None
    if header_rel and not is_safe_relative_path(header_rel):
        header_rel = None

    # Preprocess and index the translation unit.
    notes: list[str] = []
    flags = _effective_flags(cppflags, tree, notes)
    proof_path = to_run_relative(source, run_dir)
    text, preprocessor = _preprocess(flags, proof_path, machdep, run_dir, runner, notes)
    resolved = text is not None
    if text is None:
        text = _lexical_text(tree, source, flags)
        notes.append("lexical slice from the real files, conditionals unresolved")
    result["preprocessor"] = preprocessor
    result["conditionals"] = "resolved" if resolved else "unresolved"
    scan = _scan_text(text)
    items, result["index_cache"] = _load_index(scan, "cpp" if resolved else "lexical", run_dir)
    slicer = _Slicer(tree, scan, items, function, c_rel, resolved, dag_functions)

    # The target.
    located = _locate_target(slicer, source, notes)
    if located is None:
        result["reason"] = "; ".join(notes)
        return result
    target, span = located
    result["status"] = "ok" if resolved else "degraded"
    result["target"] = {"file": span.file, "start_line": span.start, "end_line": span.end}
    slicer.target_scope = (target.start, target.end)
    slicer.target_range = (span.file, span.start, span.end)
    target_rf = slicer.real_file(target.file)
    inactive = slicer.inactive(target.file, target_rf, span.start, span.end) if target_rf is not None else []

    # Close over its identifiers: the real text (minus inactive code), and the expanded body.
    refs, fields = _text_refs(span.text, inactive, span.start)
    if resolved:
        refs |= set(target.refs)
    header_span = _header_prototype(slicer, header_rel, span)
    if header_span is not None:
        result["header_prototype"] = {
            "file": header_span.file,
            "start_line": header_span.start,
            "end_line": header_span.end,
        }
        header_refs, header_fields = _text_refs(header_span.text)
        refs |= header_refs
        fields |= header_fields
    refs.discard(function)
    called = _called_names(slicer, target, refs, fields)
    slicer.index_logic()
    only_in_dag = [
        n for n in sorted(called) if n != function and n not in slicer.functions and slicer.dag_definition(n)
    ]
    slicer.close_over(refs, fields, slicer.target_scope, only_in_dag)

    result["callees"], callee_infos = _collect_callees(slicer, called)
    direct = {info.name for info in callee_infos}
    for name, depth in slicer.reached_functions.items():
        info = slicer.resolve_function(name)
        if info.kind == "in_tree" and info.shown:
            slicer.entries.append(slicer.function_entry(info, "callees" if name in direct else "referenced", depth))

    # Render.
    entries = slicer.entries
    externals = [row["name"] for row in result["callees"] if row["kind"] != "in_tree"]
    outside = sorted(slicer.external_names - set(externals) - {function})
    header = _slice_header(function, proof_path, span, preprocessor, externals, outside)
    target_block = _target_block(function, span, header_span, inactive)
    titles = _section_titles(resolved)
    full_text = _assemble(header, entries, target_block, titles)
    if out_dir is not None:
        has_bodies = callee_bodies and any(info.body is not None for info in callee_infos)
        bodies = _render_bodies(function, callee_infos) if has_bodies else None
        _write_outputs(Path(out_dir), run_dir, function, full_text, bodies, result, notes)

    full_lines = full_text.count("\n")
    if full_lines <= max_inline_lines:
        result["text"] = full_text
    else:
        # What cannot be cut: the header, the target and the omission note, with the blank lines between them.
        budget = max_inline_lines - _line_count(header) - _line_count(target_block) - 1 - 3
        kept, omitted = _fit_entries(entries, budget)
        note = _omission_note(omitted, result["slice_file"]) if omitted else ""
        result["text"] = _assemble(header, kept, target_block, titles, note)
        result["truncated"] = bool(omitted)

    sections = [entry.section for entry in entries]
    result["stats"] = {
        "lines": full_lines,
        "macros": sections.count("macros"),
        "types": sections.count("types"),
        "globals": sections.count("globals"),
        "callees": len(result["callees"]),
        "logic_decls": sections.count("logic"),
    }
    result["reason"] = "; ".join(notes) or None
    return result


def build_slice(
    run_dir: Path,
    work_dir: Path,
    c_file: str,
    function: str,
    cppflags: str,
    out_dir: Path | None = None,
    header_file: str | None = None,
    dag_functions: dict | None = None,
    machdep: str = "gcc_x86_64",
    max_inline_lines: int = 220,
    callee_bodies: bool = True,
    runner: Callable | None = None,
) -> dict:
    """
    Build the reading slice of `function`, defined in `c_file` under `work_dir`. Never raises on bad
    input: a failure is a `status` with a `reason`, and only means a brief without a slice. Safe in a
    thread pool: paths are explicit and the process-wide memo of Frama-C's command is locked.
    """
    try:
        return _build(
            run_dir,
            work_dir,
            c_file,
            function,
            cppflags,
            out_dir,
            header_file,
            dag_functions,
            machdep,
            max_inline_lines,
            callee_bodies,
            runner,
        )
    except Exception as exc:  # A reading aid must never take agent preparation down with it.
        failed = _result_skeleton(str(function), str(c_file))
        failed["reason"] = f"slice failed: {type(exc).__name__}: {exc}"
        return failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the reading slice of one C function for its Function Prover.")
    parser.add_argument("--run-dir", default=".", help="Preprocessor cwd; other relative paths resolve against it")
    parser.add_argument("--work-dir", required=True, help="Tree holding the current contracts")
    parser.add_argument("--file", required=True, help="File defining the function, relative to --work-dir")
    parser.add_argument("--function", required=True)
    parser.add_argument("--cppflags", default="-I.", help="The prover's real flags (use --cppflags=...)")
    parser.add_argument("--out-dir", default=None, help="Where to write <function>.slice.c and .callee_bodies.c")
    parser.add_argument("--header", default=None, help="Header holding the target's prototype contract")
    parser.add_argument("--dag", default=None, help="workspace/reports/callgraph_dag.json")
    parser.add_argument("--machdep", default="gcc_x86_64")
    parser.add_argument("--max-inline-lines", type=int, default=220)
    parser.add_argument("--no-callee-bodies", action="store_true")
    raw = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(normalize_flag_args(raw, ("--cppflags",)))

    dag_functions = None
    if args.dag:
        dag_path = Path(args.dag)
        try:
            dag = load_json_optional(dag_path if dag_path.is_absolute() else Path(args.run_dir) / dag_path, {})
        except ArtifactError:
            dag = {}
        dag_functions = dag.get("functions") if isinstance(dag, dict) else None
    result = build_slice(
        Path(args.run_dir),
        Path(args.work_dir),
        args.file,
        args.function,
        args.cppflags,
        out_dir=Path(args.out_dir) if args.out_dir else None,
        header_file=args.header,
        dag_functions=dag_functions,
        machdep=args.machdep,
        max_inline_lines=args.max_inline_lines,
        callee_bodies=not args.no_callee_bodies,
    )
    print(json.dumps({k: v for k, v in result.items() if k != "text"}, indent=2))
    return 0 if result["status"] in ("ok", "degraded") else 1


if __name__ == "__main__":
    sys.exit(main())
