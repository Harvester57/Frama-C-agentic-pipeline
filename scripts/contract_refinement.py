#!/usr/bin/env python3
"""
Contract refinement probe (docs/plans/caller-sufficient-contracts-plan.md, step 1).

Compares two ACSL contracts of one C function by meaning, not by text. For a function `f` it writes a
probe translation unit outside the work tree:

- `#include "<f's source file>"`, so every type, macro and logic definition the contracts use is in scope;
- a declaration `f__given` carrying contract A, with no body;
- a definition `f__probe` carrying contract B, whose body is the single call `f__given(<its parameters>)`.

It then runs WP on `f__probe` only, without RTE. If every goal is proved, A refines B: B's `requires`
imply A's, and A's `ensures` and `assigns` give B's under B's `requires`.

Two uses:

1. **Not weaker than before** (`refinement_check`): A is the new contract, B the previous one. A goal left
   unproved names the previous clause the new contract no longer gives (or the new `requires` the old
   precondition does not imply).
2. **Postconditions that say nothing** (`frame_only_ensures`): A is the contract with its `ensures` clauses
   deleted, B the full contract. An `ensures` of B proved here follows from the `requires` and the frame
   alone: it holds for any body, so it tells a caller nothing about this one.

Verdicts: `refines`, `weaker` (with the clauses left unproved: file, line, kind, text) and `undecided`. A
clause counts as not implied only when WP reports a counter-example model for its goal
(`-wp-counter-examples`); a goal left unproved without a model (a timeout on a hard but true implication
looks the same as one on a false one) is undecided. `undecided` is also the verdict when the probe cannot
be built (variadic prototype, unnamed formal, empty or malformed parameter list, A without `assigns`, whose frame the
kernel would generate), when Frama-C does not parse it, when the run times out, when an unproved goal is
not one of the probe's clauses, or when no goal at all is proved. `undecided` is never read as `refines`
or `weaker`. A model is the solver's candidate counter-example, which WP does not check: a `weaker` verdict
can still be wrong on a quantified goal, and is recorded, never used to reject a proof.

Limits that decide a verdict are fixed whatever the machine: the per-goal prover timeout
(`PROBE_GOAL_TIMEOUT_S`) and the provers. Only `-wp-par` follows the job budget.

The probe never changes a target file: it is written to a temporary directory (or `--keep-dir`), which
may not lie under `workspace/work/`.

Usage:
  python scripts/contract_refinement.py frame-only --file F.c --function f [--cppflags ...] [--out-json r.json]
  python scripts/contract_refinement.py compare --file NEW.c --previous-file OLD.c --function f [...]
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acsl_ast import (  # noqa: E402
    AcslError,
    DeclSpan,
    Token,
    contract_declaration_spans,
    declaration_param_names,
    iter_clauses,
    mask_comments_and_literals,
    tokenize_c_acsl,
)

REFINES = "refines"
WEAKER = "weaker"
UNDECIDED = "undecided"
VERDICTS = (REFINES, WEAKER, UNDECIDED)

# Fixed, never derived from the machine: they decide verdicts.
PROBE_GOAL_TIMEOUT_S = 3
PROBE_PROVERS = ("alt-ergo", "z3", "cvc5")
PROBE_WALL_TIMEOUT_S = 180
PROBE_MODEL = "Typed"

GIVEN_SUFFIX = "__given"
PROBE_SUFFIX = "__probe"
LABEL_PREFIX = "fcprobe_"
PROBE_FILE = "contract_probe.c"

_INCLUDE_RE = re.compile(r'^[ \t]*#[ \t]*include[ \t]*["<]([^">\n]+)[">]', re.MULTILINE)
_INCLUDE_DIR_RE = re.compile(r"(?:^|\s)-I\s*(\S+)")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_STORAGE_CLASS_TOKENS = frozenset({"static", "inline", "__inline", "__inline__", "extern", "_Noreturn"})
_DECL_SUFFIX_KWS = frozenset({"__attribute__", "__attribute", "__asm__", "__asm", "asm"})
_PTR_QUAL_TOKENS = frozenset({"*", "const", "volatile", "restrict", "__restrict", "__restrict__", "_Atomic"})
_TYPE_QUAL_TOKENS = frozenset({"const", "volatile", "restrict", "__restrict", "__restrict__", "__extension__"})
_BUILTIN_TYPE_TOKENS = frozenset(
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
        "bool",
        "_Complex",
        "_Imaginary",
        "__int128",
        "__int128_t",
        "__uint128_t",
    }
)
_TAG_KEYWORDS = frozenset({"struct", "union", "enum"})
_TYPEOF_KEYWORDS = frozenset({"typeof", "__typeof__", "__typeof"})
_KR_FORBIDDEN_DECL_TOKENS = frozenset(
    {
        "typedef",
        "extern",
        "static",
        "inline",
        "__inline",
        "__inline__",
        "auto",
        "_Noreturn",
        "return",
        "if",
        "else",
        "while",
        "for",
        "switch",
        "do",
        "case",
        "default",
        "goto",
        "break",
        "continue",
    }
)
_C_NON_PARAM_KEYWORDS = (
    _STORAGE_CLASS_TOKENS
    | _TYPE_QUAL_TOKENS
    | _BUILTIN_TYPE_TOKENS
    | _TAG_KEYWORDS
    | _TYPEOF_KEYWORDS
    | _KR_FORBIDDEN_DECL_TOKENS
    | frozenset({"register", "_Atomic", "sizeof"})
)
_BEHAVIOR_HEAD_RE = re.compile(r"(?<![\\\w])behavior\s+[A-Za-z_][A-Za-z0-9_]*\s*:")
_SECTION_END_RE = re.compile(r"(?<![\\\w])(?:behavior\s+[A-Za-z_]\w*\s*:|complete\s+behaviors|disjoint\s+behaviors)")
_LABEL_RE = re.compile(rf"(?:^|_){LABEL_PREFIX}(\d+)(?:_|$)")
_MODEL_GOAL_RE = re.compile(
    r"^\[wp\] \[(?:Unsuccess|Unknown|Failed|Timeout|Stepout)\] ([A-Za-z_]\w*)(?: \([^)\n]*\))*? \(Model\)",
    re.MULTILINE,
)
_KIND_PROPERTY_RE = {
    "assigns": re.compile(r"(?:^|_)assigns(?:_|$)"),
    "terminates": re.compile(r"(?:^|_)terminates(?:_|$)"),
    "exits": re.compile(r"(?:^|_)exits(?:_|$)"),
}


class ProbeError(RuntimeError):
    """The probe cannot be built for this function: the comparison is `undecided`."""


@dataclass(frozen=True)
class Piece:
    """The ACSL contract in front of one declaration of the function, with that declaration's C head."""

    file: str
    line: int
    acsl: str  # the annotation comment(s) as written, `/*@ ... */` or `//@ ...`
    declarator: str  # the C declaration head (no ACSL, no comments, no `;` or body)
    params: list[str] | None  # named formals, None when one is unnamed
    variadic: bool = False


@dataclass
class FunctionContract:
    """Every contract piece of a function the pipeline reads (source definition, header declarations)."""

    function: str
    pieces: list[Piece] = field(default_factory=list)
    definition: Piece | None = None  # the declaration the probe body is written on
    returns_void: bool | None = None
    source: str = ""

    def text(self) -> str:
        return "\n".join(p.acsl for p in self.pieces)

    def to_dict(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "pieces": [asdict(p) for p in self.pieces],
            "definition": asdict(self.definition) if self.definition else None,
            "returns_void": self.returns_void,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FunctionContract:
        def piece(raw: Any) -> Piece | None:
            if not isinstance(raw, dict):
                return None
            return Piece(
                file=str(raw.get("file") or ""),
                line=int(raw.get("line") or 0),
                acsl=str(raw.get("acsl") or ""),
                declarator=str(raw.get("declarator") or ""),
                params=list(raw["params"]) if isinstance(raw.get("params"), list) else None,
                variadic=bool(raw.get("variadic")),
            )

        pieces = [p for p in (piece(r) for r in data.get("pieces") or []) if p is not None]
        rv = data.get("returns_void")
        return cls(
            function=str(data.get("function") or ""),
            pieces=pieces,
            definition=piece(data.get("definition")),
            returns_void=rv if isinstance(rv, bool) else None,
            source=str(data.get("source") or ""),
        )


# ---------------------------------------------------------------------------
# Reading a function's contract
# ---------------------------------------------------------------------------


def contract_sources(c_file: Path, source: str, cppflags: str = "") -> list[Path]:
    """
    The headers whose declarations of a function in `c_file` carry contract pieces Frama-C merges: the
    sibling `<stem>.h` and the headers `source` includes directly, looked up beside `c_file` and in the
    `-I` directories of `cppflags` (a relative one against the working directory, as the preprocessor
    does, and against `c_file`'s directory). A header found nowhere (a system header, the Frama-C libc)
    is skipped; a contract on a header reached only through another header is not read.
    """
    dirs = [c_file.parent]
    for d in map(Path, _INCLUDE_DIR_RE.findall(cppflags)):
        dirs += [d] if d.is_absolute() else [Path.cwd() / d, c_file.parent / d]
    seen: set[Path] = set()
    out: list[Path] = []
    for name in [c_file.with_suffix(".h").name, *_INCLUDE_RE.findall(source)]:
        header = next((d / name for d in dirs if (d / name).is_file()), None)
        if header is None or header.resolve() in seen or header.resolve() == c_file.resolve():
            continue
        seen.add(header.resolve())
        out.append(header)
    return out


def _tokenize_code(text: str, path: str = "<input>") -> list[Token]:
    """Non-trivia tokens of C text (comments, whitespace, and preprocessor directives omitted)."""
    return [
        t
        for t in tokenize_c_acsl(text, path=path)
        if t.kind not in ("whitespace", "c_comment", "acsl_block", "acsl_line", "pp_directive")
    ]


def _matching_token(toks: list[Token], open_idx: int, open_ch: str, close_ch: str) -> int:
    """Index in `toks` of the closing delimiter matching `toks[open_idx]`, or -1 if unclosed."""
    depth = 0
    for idx in range(open_idx, len(toks)):
        tok = toks[idx]
        if tok.kind != "c_token":
            continue
        if tok.text == open_ch:
            depth += 1
        elif tok.text == close_ch:
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _skip_decl_suffixes(toks: list[Token], idx: int) -> int:
    """Advance past consecutive GCC attribute / asm suffixes starting at `idx`, or -1 if malformed."""
    n = len(toks)
    while idx < n and toks[idx].kind == "c_token" and toks[idx].text in _DECL_SUFFIX_KWS:
        if idx + 1 >= n or toks[idx + 1].kind != "c_token" or toks[idx + 1].text != "(":
            return -1
        close_idx = _matching_token(toks, idx + 1, "(", ")")
        if close_idx == -1:
            return -1
        idx = close_idx + 1
    return idx


def _is_nested_decl_prefix(toks: list[Token], open_parens: list[int], fn_idx: int) -> bool:
    """Whether `open_parens` wraps a nested pointer declarator around `toks[fn_idx]` (e.g. `int (*f(int))(int)`)."""
    if not any(toks[k].kind == "c_token" for k in range(open_parens[0])):
        return False
    boundaries = [*open_parens, fn_idx]
    for p_idx, next_idx in zip(boundaries, boundaries[1:], strict=False):
        saw_star = False
        k = p_idx + 1
        while k < next_idx:
            if toks[k].kind == "c_token" and toks[k].text in _DECL_SUFFIX_KWS:
                nxt = _skip_decl_suffixes(toks, k)
                if nxt < 0 or nxt > next_idx:
                    return False
                k = nxt
                continue
            if toks[k].kind != "c_token" or toks[k].text not in _PTR_QUAL_TOKENS:
                return False
            if toks[k].text == "*":
                saw_star = True
            k += 1
        if not saw_star:
            return False
    return True


def _find_function_declarator(toks: list[Token], function: str) -> tuple[int, int, int, list[int]] | None:
    """
    Locate `(fn_idx, open_paren_idx, close_paren_idx, open_parens)` for `function`'s declarator in `toks`.
    `open_parens` holds the enclosing `(` indices of a nested return declarator (`int (*f(int))(int)`).
    """
    n = len(toks)
    brace_depth = 0
    bracket_depth = 0
    open_parens: list[int] = []
    i = 0
    while i < n:
        tok = toks[i]
        if tok.kind != "c_token":
            i += 1
            continue
        text = tok.text
        if brace_depth == 0 and bracket_depth == 0:
            if (
                (text in _DECL_SUFFIX_KWS or text in _TYPEOF_KEYWORDS or text == "_Atomic")
                and i + 1 < n
                and toks[i + 1].kind == "c_token"
                and toks[i + 1].text == "("
            ):
                close_idx = _matching_token(toks, i + 1, "(", ")")
                if close_idx == -1:
                    return None
                i = close_idx + 1
                continue
            if (
                text == function
                and i + 1 < n
                and toks[i + 1].kind == "c_token"
                and toks[i + 1].text == "("
                and (not open_parens or _is_nested_decl_prefix(toks, open_parens, i))
            ):
                close_idx = _matching_token(toks, i + 1, "(", ")")
                if close_idx == -1:
                    return None
                return i, i + 1, close_idx, list(open_parens)
            if text == "(":
                open_parens.append(i)
            elif text == ")" and open_parens:
                open_parens.pop()
        if text == "{":
            brace_depth += 1
        elif text == "}":
            brace_depth = max(0, brace_depth - 1)
        elif text == "[":
            bracket_depth += 1
        elif text == "]":
            bracket_depth = max(0, bracket_depth - 1)
        i += 1
    return None


def _unwind_nested_declarator(toks: list[Token], pos: int, depth: int) -> int:
    """Close `depth` nested declarator `)` levels, each followed by `(...)` or `[...]` return suffixes, or -1."""
    n = len(toks)
    for _ in range(depth):
        pos = _skip_decl_suffixes(toks, pos)
        if pos < 0 or pos >= n or toks[pos].kind != "c_token" or toks[pos].text != ")":
            return -1
        pos = _skip_decl_suffixes(toks, pos + 1)
        if pos < 0:
            return -1
        saw_suffix = False
        while pos < n and toks[pos].kind == "c_token" and toks[pos].text in ("(", "["):
            open_ch = toks[pos].text
            close_ch = ")" if open_ch == "(" else "]"
            close_idx = _matching_token(toks, pos, open_ch, close_ch)
            if close_idx == -1:
                return -1
            saw_suffix = True
            pos = _skip_decl_suffixes(toks, close_idx + 1)
            if pos < 0:
                return -1
        if not saw_suffix:
            return -1
    return pos


def _split_token_list(toks: list[Token], sep: str) -> list[list[Token]] | None:
    """Split `toks` at top-level `sep` tokens (preserving empty slices), or None on unbalanced delimiters."""
    parts: list[list[Token]] = [[]]
    p_depth = 0
    b_depth = 0
    c_depth = 0
    for tok in toks:
        if tok.kind == "c_token":
            t = tok.text
            if t == "(":
                p_depth += 1
            elif t == ")":
                p_depth -= 1
            elif t == "[":
                b_depth += 1
            elif t == "]":
                b_depth -= 1
            elif t == "{":
                c_depth += 1
            elif t == "}":
                c_depth -= 1
            elif t == sep and p_depth == 0 and b_depth == 0 and c_depth == 0:
                parts.append([])
                continue
            if p_depth < 0 or b_depth < 0 or c_depth < 0:
                return None
        parts[-1].append(tok)
    if p_depth != 0 or b_depth != 0 or c_depth != 0:
        return None
    return parts


def _body_brace_offset(text: str, function: str, path: str = "<input>") -> int | None:
    """Byte offset of the function body's opening `{` in `text`, skipping `struct/union/enum { ... }` in the head."""
    toks = _tokenize_code(text, path=path)
    found = _find_function_declarator(toks, function)
    if found is not None:
        _fn_idx, _open_p, close_p, open_parens = found
        pos = _unwind_nested_declarator(toks, close_p + 1, len(open_parens))
        if pos >= 0:
            p_depth = 0
            tag_state = 0  # 1 right after struct/union/enum, 2 right after tag identifier
            n = len(toks)
            while pos < n:
                tok = toks[pos]
                if tok.kind != "c_token":
                    tag_state = 0
                    pos += 1
                    continue
                t = tok.text
                if p_depth == 0 and t in _DECL_SUFFIX_KWS:
                    nxt = _skip_decl_suffixes(toks, pos)
                    if nxt >= 0:
                        pos = nxt
                        continue
                if t == "(":
                    p_depth += 1
                    tag_state = 0
                elif t == ")":
                    p_depth = max(0, p_depth - 1)
                    tag_state = 0
                elif t == "{" and p_depth == 0:
                    if tag_state in (1, 2):
                        close_b = _matching_token(toks, pos, "{", "}")
                        if close_b == -1:
                            break
                        pos = close_b + 1
                        tag_state = 0
                        continue
                    return tok.start
                elif p_depth == 0:
                    if t in _TAG_KEYWORDS:
                        tag_state = 1
                    elif tag_state == 1 and _IDENT_RE.fullmatch(t):
                        tag_state = 2
                    else:
                        tag_state = 0
                pos += 1
    p_depth = 0
    b_depth = 0
    last_top_brace: int | None = None
    for tok in toks:
        if tok.kind != "c_token":
            continue
        if tok.text == "(":
            p_depth += 1
        elif tok.text == ")":
            p_depth = max(0, p_depth - 1)
        elif tok.text == "{":
            if p_depth == 0 and b_depth == 0:
                last_top_brace = tok.start
            b_depth += 1
        elif tok.text == "}":
            b_depth = max(0, b_depth - 1)
    return last_top_brace


def _decl_head(decl: DeclSpan, path: str) -> str:
    """The C head of a declaration: no ACSL, no comments, no body, no trailing `;` on prototypes."""
    text = decl.span.text
    if decl.kind == "definition":
        brace = _body_brace_offset(text, decl.span.function, path=path)
        text = text[:brace] if brace is not None else text
    masked = mask_comments_and_literals(text, acsl="blank", literals=False, on_error="mask", path=path)
    head = " ".join(masked.split()).strip()
    if decl.kind != "definition":
        head = head.rstrip(";").strip()
    return head


def _piece(decl: DeclSpan, function: str, path: str, file_label: str) -> Piece:
    part = decl.span.text
    if decl.kind == "definition":
        brace = _body_brace_offset(part, function, path=path)
        part = part[:brace] if brace is not None else part
    tokens = [t for t in tokenize_c_acsl(part, path=path) if t.kind in ("acsl_block", "acsl_line")]
    acsl = "\n".join(t.text for t in tokens)
    line = decl.span.start_line + (tokens[0].line - 1 if tokens else 0)
    head = _decl_head(decl, path)
    head_toks = _tokenize_code(head, path=path)
    found = _find_function_declarator(head_toks, function)
    names = declaration_param_names(decl, path=path)
    params: list[str] | None = names
    variadic = False
    if found is None:
        params = None
    else:
        _fn_idx, open_p, close_p, _open_parens = found
        param_toks = head_toks[open_p + 1 : close_p]
        if not param_toks:
            params = None
        else:
            param_parts = _split_token_list(param_toks, ",")
            if param_parts is None or any(not p for p in param_parts):
                params = None
            else:
                variadic = any(len(p) == 3 and [t.text for t in p] == [".", ".", "."] for p in param_parts)
                has_bad_void = any(len(p) == 1 and p[0].text == "void" for p in param_parts) and len(param_parts) > 1
                declared = [
                    p
                    for p in param_parts
                    if not (len(p) == 1 and p[0].text == "void")
                    and not (len(p) == 3 and [t.text for t in p] == [".", ".", "."])
                ]
                if has_bad_void or len(declared) != len(names):
                    params = None
    return Piece(file=file_label, line=line, acsl=acsl, declarator=head, params=params, variadic=variadic)


def read_function_contract(c_file: Path, function: str, cppflags: str = "") -> FunctionContract:
    """
    The contract of `function` where Frama-C takes it from: in front of its definition in `c_file`, and on
    its declarations in the headers `c_file` includes directly (`contract_sources`), merged in that order.
    Raises OSError when `c_file` cannot be read and AcslError when it does not tokenize.
    """
    from acsl_ast import function_returns_void

    source = c_file.read_text(encoding="utf-8", errors="replace")
    contract = FunctionContract(function=function, source=str(c_file))
    files: list[tuple[Path, str, bool]] = [(c_file, source, False)]
    for header in contract_sources(c_file, source, cppflags):
        try:
            files.append((header, header.read_text(encoding="utf-8", errors="replace"), True))
        except OSError:
            continue
    for path, text, is_header in files:
        try:
            decls = contract_declaration_spans(text, function, is_header=is_header, path=str(path))
        except AcslError:
            if not is_header:
                raise
            continue
        for decl in decls:
            piece = _piece(decl, function, str(path), str(path))
            if piece.acsl.strip():
                contract.pieces.append(piece)
            if decl.kind == "definition" and contract.definition is None:
                contract.definition = piece
        if contract.returns_void is None:
            try:
                contract.returns_void = function_returns_void(text, function, is_header=is_header, path=str(path))
            except AcslError:
                pass
    if contract.definition is None:
        protos = [p for p in contract.pieces if p.params is not None]
        contract.definition = protos[0] if protos else None
    return contract


# ---------------------------------------------------------------------------
# Building the probe
# ---------------------------------------------------------------------------


def acsl_body(acsl: str) -> str:
    """
    The inside of annotation comment(s), of the same length: `/*@`, `*/`, `//@` and the `@` margins become
    spaces, so offsets and line numbers stay those of `acsl`.
    """
    out = re.sub(r"/\*@", "   ", acsl)
    out = re.sub(r"\*/", "  ", out)
    out = re.sub(r"//@", "   ", out)
    return re.sub(r"(^|\n)([ \t]*)@", lambda m: m.group(1) + m.group(2) + " ", out)


@dataclass
class ClauseRef:
    contract: str  # "given" (A) or "probe" (B)
    kind: str
    file: str
    line: int
    text: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProbeUnit:
    """The probe translation unit and the map from its goals back to the clauses."""

    text: str
    function: str
    labels: dict[int, ClauseRef] = field(default_factory=dict)
    by_kind: dict[str, list[ClauseRef]] = field(default_factory=dict)  # B's unlabelled clauses
    ensures_labels: list[int] = field(default_factory=list)  # B's ensures, in order


def strip_ensures(body: str) -> str:
    """
    `body` (an `acsl_body`) without its `ensures` clauses. A named behavior left empty gets `assumes \\true;`
    (Frama-C rejects an empty named behavior), which is what a behavior without `assumes` means.
    """
    spans = [span for kind, _label, _pred, span in iter_clauses(body) if kind == "ensures"]
    out = body
    for start, end in reversed(spans):
        out = out[:start] + " " * (end - start) + out[end:]
    masked = mask_comments_and_literals(out, acsl="mask", on_error="mask")
    heads = list(_BEHAVIOR_HEAD_RE.finditer(masked))
    for m in reversed(heads):
        nxt = _SECTION_END_RE.search(masked, m.end())
        stop = nxt.start() if nxt else len(masked)
        if not masked[m.end() : stop].strip():
            out = out[: m.end()] + " assumes \\true;" + out[m.end() :]
    return out


def _labelled(body: str, piece: Piece, role: str, unit: ProbeUnit, next_label: list[int]) -> str:
    """`body` with a `fcprobe_<k>:` name on every `requires` / `ensures`, the clauses recorded in `unit`."""
    inserts: list[tuple[int, str]] = []
    for kind, _label, pred, span in iter_clauses(body):
        ref = ClauseRef(
            contract=role,
            kind=kind,
            file=piece.file,
            line=piece.line + body[: span[0]].count("\n"),
            text=" ".join(pred.split()),
        )
        if kind in ("requires", "ensures"):
            k = next_label[0]
            next_label[0] += 1
            unit.labels[k] = ref
            if role == "probe" and kind == "ensures":
                unit.ensures_labels.append(k)
            inserts.append((span[0] + len(kind), f" {LABEL_PREFIX}{k}:"))
        elif role == "probe":
            unit.by_kind.setdefault(kind, []).append(ref)
    out = body
    for pos, text in sorted(inserts, reverse=True):
        out = out[:pos] + text + out[pos:]
    return out


@dataclass(frozen=True)
class _ParsedDecl:
    """Validated declarator normalized to ANSI form, split around the function identifier for renaming."""

    before_name: str
    after_name: str

    def render(self, name: str) -> str:
        return f"{self.before_name}{name}{self.after_name}"


def _valid_decl_suffixes(toks: list[Token], start: int) -> bool:
    """Whether `toks[start:]` consists solely of valid declarator suffixes (`[...]`, `(...)`, attributes)."""
    idx = start
    n = len(toks)
    while idx < n:
        idx = _skip_decl_suffixes(toks, idx)
        if idx < 0:
            return False
        if idx >= n:
            return True
        tok = toks[idx]
        if tok.kind == "c_token" and tok.text in ("(", "["):
            close_ch = ")" if tok.text == "(" else "]"
            close_idx = _matching_token(toks, idx, tok.text, close_ch)
            if close_idx == -1:
                return False
            idx = close_idx + 1
            continue
        return False
    return True


def _declarator_name(toks: list[Token]) -> str | None:
    """Extract the declared identifier from a C declarator token sequence, or None if unnamed/malformed."""
    idx = 0
    n = len(toks)
    while idx < n:
        idx = _skip_decl_suffixes(toks, idx)
        if idx < 0 or idx >= n:
            return None
        tok = toks[idx]
        if tok.kind == "c_token" and tok.text in _PTR_QUAL_TOKENS:
            idx += 1
            continue
        break
    if idx >= n:
        return None
    tok = toks[idx]
    if tok.kind == "c_token" and tok.text == "(":
        close_idx = _matching_token(toks, idx, "(", ")")
        if close_idx == -1 or not _valid_decl_suffixes(toks, close_idx + 1):
            return None
        return _declarator_name(toks[idx + 1 : close_idx])
    if tok.kind == "c_token" and _IDENT_RE.fullmatch(tok.text) and tok.text not in _C_NON_PARAM_KEYWORDS:
        if not _valid_decl_suffixes(toks, idx + 1):
            return None
        return tok.text
    return None


def _remove_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """`text` with the given `(start, end)` spans removed."""
    out = text
    for start, end in sorted(spans, reverse=True):
        out = out[:start] + out[end:]
    return out


def _has_forbidden_top_level_kr_token(toks: list[Token]) -> bool:
    """Whether `toks` contains `=` or a storage-class/control-flow keyword forbidden in K&R parameter declarations."""
    p_depth = 0
    b_depth = 0
    c_depth = 0
    for tok in toks:
        if tok.kind != "c_token":
            continue
        t = tok.text
        if t == "(":
            p_depth += 1
        elif t == ")":
            p_depth -= 1
        elif t == "[":
            b_depth += 1
        elif t == "]":
            b_depth -= 1
        elif t == "{":
            c_depth += 1
        elif t == "}":
            c_depth -= 1
        elif p_depth == 0 and b_depth == 0 and c_depth == 0 and (t == "=" or t in _KR_FORBIDDEN_DECL_TOKENS):
            return True
    return False


def _split_kr_spec_and_decl(head: str, part_toks: list[Token], param_set: set[str]) -> tuple[str, list[Token]] | None:
    """
    Split the first comma-element of a K&R parameter declaration into `(specifiers_text, declarator_tokens)`.
    Strips `register` and inserts default `int` when only `register`/qualifiers are present. Returns None if malformed.
    """
    has_type_spec = False
    i = 0
    n = len(part_toks)
    while i < n:
        tok = part_toks[i]
        if tok.kind != "c_token":
            break
        t = tok.text
        if t == "register" or t in _TYPE_QUAL_TOKENS:
            i += 1
            continue
        if t == "_Atomic":
            if i + 1 < n and part_toks[i + 1].kind == "c_token" and part_toks[i + 1].text == "(":
                close_p = _matching_token(part_toks, i + 1, "(", ")")
                if close_p == -1:
                    return None
                i = close_p + 1
                has_type_spec = True
            else:
                i += 1
            continue
        if t in _BUILTIN_TYPE_TOKENS:
            has_type_spec = True
            i += 1
            continue
        if t in _TAG_KEYWORDS:
            i += 1
            i = _skip_decl_suffixes(part_toks, i)
            if i < 0:
                return None
            saw_tag_or_body = False
            if (
                i < n
                and part_toks[i].kind == "c_token"
                and _IDENT_RE.fullmatch(part_toks[i].text)
                and part_toks[i].text not in _C_NON_PARAM_KEYWORDS
            ):
                saw_tag_or_body = True
                i += 1
                i = _skip_decl_suffixes(part_toks, i)
                if i < 0:
                    return None
            if i < n and part_toks[i].kind == "c_token" and part_toks[i].text == "{":
                close_b = _matching_token(part_toks, i, "{", "}")
                if close_b == -1:
                    return None
                saw_tag_or_body = True
                i = close_b + 1
            if not saw_tag_or_body:
                return None
            has_type_spec = True
            continue
        if t in _TYPEOF_KEYWORDS:
            if i + 1 < n and part_toks[i + 1].kind == "c_token" and part_toks[i + 1].text == "(":
                close_p = _matching_token(part_toks, i + 1, "(", ")")
                if close_p == -1:
                    return None
                i = close_p + 1
                has_type_spec = True
                continue
            break
        if t in ("__attribute__", "__attribute"):
            if i + 1 < n and part_toks[i + 1].kind == "c_token" and part_toks[i + 1].text == "(":
                close_p = _matching_token(part_toks, i + 1, "(", ")")
                if close_p == -1:
                    return None
                i = close_p + 1
                continue
            break
        if not has_type_spec and _IDENT_RE.fullmatch(t) and t not in _C_NON_PARAM_KEYWORDS:
            # Distinguish a typedef-name (`size_t a`, `my_t (*cb)(int)`) from a parameter declarator with
            # implicit `int` (`register a;`, `register a[4];`, `const a;`).
            if i + 1 == n:
                break
            is_ptr_paren = (
                i + 2 < n
                and part_toks[i + 1].kind == "c_token"
                and part_toks[i + 1].text == "("
                and part_toks[i + 2].kind == "c_token"
                and part_toks[i + 2].text == "*"
            )
            if i > 0 and t in param_set and not is_ptr_paren and _declarator_name(part_toks[i:]) == t:
                break
            has_type_spec = True
            i += 1
            continue
        break
    if i == 0 or i >= n:
        return None
    spec_toks = part_toks[:i]
    base = spec_toks[0].start
    spec_slice = head[base : spec_toks[-1].end]
    reg_spans = [(t.start - base, t.end - base) for t in spec_toks if t.kind == "c_token" and t.text == "register"]
    spec_text = " ".join(_remove_spans(spec_slice, reg_spans).split())
    if not has_type_spec:
        spec_text = f"{spec_text} int".strip()
    return spec_text, part_toks[i:]


def _parse_kr_declarations(
    head: str, tail_toks: list[Token], param_order: list[str], what: str, function: str
) -> list[str]:
    """
    Parse K&R parameter declarations (`int a; char *b;`, including `register`, multi-declarator items,
    structs/function-pointers, and default-`int` for omitted parameters) into ordered ANSI parameters.
    """
    decls = _split_token_list(tail_toks, ";")
    if decls is None:
        raise ProbeError(f"{what} of {function}: unbalanced K&R parameter declarations in `{head}`")
    if decls and not decls[-1]:
        decls = decls[:-1]
    if not decls or any(not d for d in decls):
        raise ProbeError(f"{what} of {function}: malformed K&R parameter declarations in `{head}`")
    param_set = set(param_order)
    declared: dict[str, str] = {}
    for decl_toks in decls:
        if _has_forbidden_top_level_kr_token(decl_toks):
            raise ProbeError(f"{what} of {function}: invalid K&R parameter declaration in `{head}`")
        items = _split_token_list(decl_toks, ",")
        if items is None or any(not item for item in items):
            raise ProbeError(f"{what} of {function}: malformed K&R parameter declaration in `{head}`")
        split = _split_kr_spec_and_decl(head, items[0], param_set)
        if split is None:
            raise ProbeError(f"{what} of {function}: unrecognized K&R parameter declaration in `{head}`")
        spec_text, first_decl = split
        for decl_item in (first_decl, *items[1:]):
            name = _declarator_name(decl_item)
            if name is None or name not in param_set:
                raise ProbeError(
                    f"{what} of {function}: K&R parameter declaration does not match parameter list in `{head}`"
                )
            if name in declared:
                raise ProbeError(f"{what} of {function}: duplicate K&R declaration for parameter `{name}` in `{head}`")
            decl_text = " ".join(head[decl_item[0].start : decl_item[-1].end].split())
            declared[name] = f"{spec_text} {decl_text}"
    return [declared.get(name, f"int {name}") for name in param_order]


def _top_level_storage_spans(toks: list[Token], limit: int) -> list[tuple[int, int]]:
    """Byte spans of top-level storage-class specifiers in `toks[:limit]`."""
    spans: list[tuple[int, int]] = []
    p_depth = 0
    b_depth = 0
    c_depth = 0
    for tok in toks[:limit]:
        if tok.kind != "c_token":
            continue
        t = tok.text
        if t == "(":
            p_depth += 1
        elif t == ")":
            p_depth = max(0, p_depth - 1)
        elif t == "[":
            b_depth += 1
        elif t == "]":
            b_depth = max(0, b_depth - 1)
        elif t == "{":
            c_depth += 1
        elif t == "}":
            c_depth = max(0, c_depth - 1)
        elif p_depth == 0 and b_depth == 0 and c_depth == 0 and t in _STORAGE_CLASS_TOKENS:
            spans.append((tok.start, tok.end))
    return spans


def _check_piece(piece: Piece, function: str, what: str) -> _ParsedDecl:
    """Validate and normalize a piece's declarator (ANSI, K&R, or nested); ProbeError if the probe cannot carry it."""
    if piece.variadic:
        raise ProbeError(f"{what} of {function} is variadic: the probe cannot forward its arguments")
    head = piece.declarator
    toks = _tokenize_code(head)
    found = _find_function_declarator(toks, function)
    if found is None:
        raise ProbeError(f"{what} of {function}: parameter list not found in `{head}`")
    fn_idx, open_p, close_p, open_parens = found
    decl_end = _unwind_nested_declarator(toks, close_p + 1, len(open_parens))
    if decl_end == -1:
        raise ProbeError(f"{what} of {function}: malformed nested declarator in `{head}`")
    tail_pos = _skip_decl_suffixes(toks, decl_end)
    if tail_pos == -1:
        raise ProbeError(f"{what} of {function}: malformed attribute after parameter list in `{head}`")
    param_toks = toks[open_p + 1 : close_p]
    if not param_toks:
        raise ProbeError(f"{what} of {function}: empty parameter list in `{head}`")
    param_parts = _split_token_list(param_toks, ",")
    if param_parts is None or any(not p for p in param_parts):
        raise ProbeError(f"{what} of {function}: malformed parameter list in `{head}`")
    if any(len(p) == 3 and [t.text for t in p] == [".", ".", "."] for p in param_parts):
        raise ProbeError(f"{what} of {function} is variadic: the probe cannot forward its arguments")
    if any(len(p) == 1 and p[0].text == "void" for p in param_parts) and len(param_parts) > 1:
        raise ProbeError(f"{what} of {function}: malformed parameter list in `{head}`")

    decl_anchor = open_parens[0] if open_parens else fn_idx
    storage_spans = _top_level_storage_spans(toks, decl_anchor)
    prefix_before_anchor = re.sub(r"\s+", " ", _remove_spans(head[: toks[decl_anchor].start], storage_spans)).lstrip()
    if not prefix_before_anchor.strip():
        prefix_before_anchor = "int "
    before_name = prefix_before_anchor + head[toks[decl_anchor].start : toks[fn_idx].start]

    if tail_pos == len(toks):
        after_name = head[toks[fn_idx].end :].rstrip()
        return _ParsedDecl(before_name=before_name, after_name=after_name)

    # Non-empty tail after the declarator (and its attributes): must be a K&R parameter declaration list.
    param_order: list[str] = []
    for p in param_parts:
        if (
            len(p) != 1
            or p[0].kind != "c_token"
            or not _IDENT_RE.fullmatch(p[0].text)
            or p[0].text in _C_NON_PARAM_KEYWORDS
        ):
            raise ProbeError(f"{what} of {function}: unexpected text after the parameter list in `{head}`")
        param_order.append(p[0].text)
    if len(set(param_order)) != len(param_order):
        raise ProbeError(f"{what} of {function}: duplicate parameter name in K&R parameter list in `{head}`")
    ansi_params = _parse_kr_declarations(head, toks[tail_pos:], param_order, what, function)
    outer_suffix = head[toks[close_p].end : toks[tail_pos - 1].end] if tail_pos > close_p + 1 else ""
    after_name = f"({', '.join(ansi_params)}){outer_suffix}"
    return _ParsedDecl(before_name=before_name, after_name=after_name)


def _annotated(body: str) -> list[str]:
    """
    The annotation comment for one contract piece, or nothing when the piece has no clause left. A contract
    split between a header prototype and the definition leaves a piece that holds only `ensures`; once those
    are stripped the comment would be empty, which Frama-C refuses (`unexpected token ''`).
    """
    return ["/*@", body, "*/"] if body.strip() else []


def build_probe(
    given: list[Piece],
    probe: list[Piece],
    definition: Piece,
    returns_void: bool,
    include: Path,
    function: str,
    *,
    strip_given_ensures: bool = False,
) -> ProbeUnit:
    """
    The probe translation unit: `include` (the function's source, absolute), `f__given` declared once per
    piece of A, `f__probe` declared once per piece of B, then defined on `definition`'s declarator with the
    single call `f__given(<parameters>)`. One declaration per piece, because concatenating pieces would put a
    later top-level clause into an earlier piece's last behavior; Frama-C merges them as it merges the
    contracts of a header prototype and a definition.
    """
    if not given or not probe:
        raise ProbeError(f"{function}: nothing to compare (a contract is empty)")
    def_decl = _check_piece(definition, function, "the definition")
    if definition.params is None:
        raise ProbeError(f"{function}: a formal parameter of the definition is unnamed")
    unit = ProbeUnit(text="", function=function)
    label = [1]
    lines = [f'#include "{include.as_posix()}"', ""]
    given_text: list[str] = []
    for p in given:
        decl = _check_piece(p, function, f"the declaration at {p.file}:{p.line}")
        body = acsl_body(p.acsl)
        if strip_given_ensures:
            body = strip_ensures(body)
        given_text.append(body)
        lines += _annotated(_labelled(body, p, "given", unit, label))
        lines += [decl.render(function + GIVEN_SUFFIX) + ";", ""]
    if not any(kind == "assigns" for body in given_text for kind, *_ in iter_clauses(body)):
        raise ProbeError(
            f"{function}: the contract compared against has no `assigns` clause, so the kernel would "
            "generate the frame the probe relies on"
        )
    for p in probe:
        decl = _check_piece(p, function, f"the declaration at {p.file}:{p.line}")
        body = _labelled(acsl_body(p.acsl), p, "probe", unit, label)
        lines += _annotated(body)
        lines += [decl.render(function + PROBE_SUFFIX) + ";", ""]
    args = ", ".join(definition.params)
    call = f"{function}{GIVEN_SUFFIX}({args});"
    lines += [
        def_decl.render(function + PROBE_SUFFIX),
        "{",
        f"  {call}" if returns_void else f"  return {call}",
        "}",
        "",
    ]
    unit.text = "\n".join(lines)
    return unit


# ---------------------------------------------------------------------------
# Running the probe and reading its goals
# ---------------------------------------------------------------------------


def _under_work_tree(path: Path) -> bool:
    """Under `workspace/work/` or an agent's `scratch/work/`: trees a merge diffs against their baseline."""
    parts = path.resolve().as_posix().split("/")
    return any(a in ("workspace", "scratch") and b == "work" for a, b in zip(parts, parts[1:], strict=False))


_PATH_FLAGS = ("-I", "-iquote", "-isystem", "-idirafter", "-include", "-imacros")


def absolute_path_flags(cppflags: str, base: Path) -> str:
    """
    `cppflags` with the relative paths of its include options made absolute against `base`: the probe runs
    the preprocessor from its own directory, so `-I.` or `-Iwork/include` must keep naming the caller's.
    """
    try:
        tokens = shlex.split(cppflags)
    except ValueError:
        return cppflags
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        flag = next((f for f in _PATH_FLAGS if tok.startswith(f)), None)
        if flag is None or (tok == flag and i + 1 >= len(tokens)):
            out.append(tok)
            i += 1
            continue
        if tok == flag:
            value, i = tokens[i + 1], i + 2
        else:
            value, i = tok[len(flag) :], i + 1
        if not value.startswith("/") and not Path(value).is_absolute():
            value = (base / value).as_posix()
        out += [flag + value] if flag == "-I" else [flag, value]
    return " ".join(shlex.quote(t) for t in out)


def probe_command(
    probe_path: Path, function: str, cppflags: str, machdep: str, wp_par: int, json_path: Path, goals_dir: Path
) -> list[str]:
    from framac_common import augment_framac_cppflags
    from resources import WP_MEMLIMIT_MB

    cmd = [
        "frama-c",
        "-pp-annot",
        "-no-unicode",
        "-machdep",
        machdep,
        "-kernel-warn-key",
        "annot-error=abort",
        f"-cpp-extra-args={augment_framac_cppflags(cppflags)}",
        str(probe_path),
        "-wp",
        "-wp-fct",
        function + PROBE_SUFFIX,
        "-wp-model",
        PROBE_MODEL,
    ]
    for prover in PROBE_PROVERS:
        cmd += ["-wp-prover", prover]
    cmd += [
        "-wp-par",
        str(wp_par),
        "-wp-timeout",
        str(PROBE_GOAL_TIMEOUT_S),
        "-wp-memlimit",
        str(WP_MEMLIMIT_MB),
        "-wp-out",
        str(goals_dir),
        "-wp-cache",
        "none",
        # A goal is counted as not implied only with a model: a timeout without one is undecided.
        "-wp-counter-examples",
        "-wp-report-json",
        str(json_path),
    ]
    return cmd


def run_probe(
    unit: ProbeUnit,
    cppflags: str = "",
    machdep: str = "gcc_x86_64",
    *,
    wp_par: int | None = None,
    keep_dir: Path | None = None,
    work_dir: Path | None = None,
) -> dict[str, Any]:
    """
    Run WP on `unit`. Returns {ok, reason, entries, models, elapsed_ms}: `entries` are the `-wp-report-json`
    goals of `f__probe`, `models` the goal names WP printed a model for. The probe is written to `keep_dir`
    when given (it is then kept), else to a temporary directory under `work_dir` (default: the system's).
    """
    if wp_par is None:
        from resources import wp_parallelism

        wp_par = wp_parallelism()
    started = time.monotonic()
    tmp: tempfile.TemporaryDirectory[str] | None = None
    if keep_dir is not None:
        keep_dir.mkdir(parents=True, exist_ok=True)
        directory = keep_dir
    else:
        if work_dir is not None:
            work_dir.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.TemporaryDirectory(prefix="contract_probe_", dir=str(work_dir) if work_dir else None)
        directory = Path(tmp.name)
    try:
        if _under_work_tree(directory):
            return {"ok": False, "reason": f"refusing to write the probe under workspace/work/ ({directory})"}
        probe_path = directory / PROBE_FILE
        json_path = directory / "contract_probe.wp-report-json"
        goals_dir = directory / "goals"
        probe_path.write_text(unit.text, encoding="utf-8", newline="\n")
        if json_path.exists():
            json_path.unlink()
        flags = absolute_path_flags(cppflags, Path.cwd())
        cmd = probe_command(probe_path, unit.function, flags, machdep, wp_par, json_path, goals_dir)
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(directory),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=PROBE_WALL_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "reason": f"the probe run timed out after {PROBE_WALL_TIMEOUT_S}s"}
        except OSError as exc:
            return {"ok": False, "reason": f"frama-c could not be started: {exc}"}
        log = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if keep_dir is not None:
            (directory / "contract_probe.log").write_text(log, encoding="utf-8", newline="\n")
        elapsed_ms = round((time.monotonic() - started) * 1000)
        if proc.returncode != 0 or not json_path.is_file():
            first = next((ln.strip() for ln in log.splitlines() if "rror" in ln or "Failure" in ln), "")
            return {
                "ok": False,
                "reason": f"the probe did not run to the end (rc={proc.returncode}){': ' + first[:300] if first else ''}",
                "elapsed_ms": elapsed_ms,
            }
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
        except ValueError:
            return {"ok": False, "reason": "the probe's WP report is not JSON", "elapsed_ms": elapsed_ms}
        entries = [
            e
            for e in (raw if isinstance(raw, list) else [])
            if isinstance(e, dict) and e.get("function") == unit.function + PROBE_SUFFIX and e.get("smoke") is not True
        ]
        return {
            "ok": True,
            "entries": entries,
            "models": sorted(set(_MODEL_GOAL_RE.findall(log))),
            "elapsed_ms": elapsed_ms,
        }
    finally:
        if tmp is not None:
            tmp.cleanup()


def goal_clauses(unit: ProbeUnit, entry: dict) -> list[ClauseRef]:
    """The clauses a WP goal of the probe checks; empty when it is none of them."""
    prop = str(entry.get("property") or entry.get("goal") or "")
    m = _LABEL_RE.search(prop)
    if m is not None:
        ref = unit.labels.get(int(m.group(1)))
        return [ref] if ref is not None else []
    for kind, pattern in _KIND_PROPERTY_RE.items():
        if pattern.search(prop):
            return list(unit.by_kind.get(kind) or [])
    return []


@dataclass
class GoalOutcome:
    proved: bool
    model: bool
    verdict: str
    clauses: list[ClauseRef]
    label: int | None


def classify_goals(unit: ProbeUnit, run: dict) -> list[GoalOutcome]:
    models = set(run.get("models") or [])
    out: list[GoalOutcome] = []
    for e in run.get("entries") or []:
        prop = str(e.get("property") or e.get("goal") or "")
        m = _LABEL_RE.search(prop)
        out.append(
            GoalOutcome(
                proved=e.get("passed") is True,
                model=str(e.get("goal") or "") in models,
                verdict=str(e.get("verdict") or ""),
                clauses=goal_clauses(unit, e),
                label=int(m.group(1)) if m else None,
            )
        )
    return out


def _clause_rows(outcomes: list[GoalOutcome]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for o in outcomes:
        for ref in o.clauses:
            row = {**ref.to_dict(), "verdict_kind": o.verdict, "model": o.model}
            if row not in rows:
                rows.append(row)
    return rows


def decide(unit: ProbeUnit, run: dict) -> dict[str, Any]:
    """The verdict of a finished probe run (`run_probe`): refines, weaker or undecided."""
    base: dict[str, Any] = {"goal_timeout_s": PROBE_GOAL_TIMEOUT_S, "elapsed_ms": run.get("elapsed_ms")}
    if not run.get("ok"):
        return {**base, "verdict": UNDECIDED, "reason": run.get("reason") or "the probe did not run"}
    outcomes = classify_goals(unit, run)
    base.update(goals=len(outcomes), proved=sum(o.proved for o in outcomes))
    if not outcomes:
        return {**base, "verdict": UNDECIDED, "reason": "WP generated no goal for the probe"}
    unproved = [o for o in outcomes if not o.proved]
    if not unproved:
        return {**base, "verdict": REFINES}
    if len(unproved) == len(outcomes):
        return {**base, "verdict": UNDECIDED, "reason": "no goal of the probe was proved"}
    if any(not o.clauses for o in unproved):
        return {
            **base,
            "verdict": UNDECIDED,
            "reason": "a goal left unproved is none of the compared clauses",
            "undecided_clauses": _clause_rows([o for o in unproved if o.clauses]),
        }
    refuted = [o for o in unproved if o.model]
    open_goals = [o for o in unproved if not o.model]
    if refuted:
        out = {**base, "verdict": WEAKER, "clauses": _clause_rows(refuted)}
        if open_goals:
            out["undecided_clauses"] = _clause_rows(open_goals)
        return out
    return {
        **base,
        "verdict": UNDECIDED,
        "reason": "goals left unproved without a counter-example model (a timeout or a prover giving up)",
        "undecided_clauses": _clause_rows(open_goals),
    }


# ---------------------------------------------------------------------------
# The two uses
# ---------------------------------------------------------------------------


def _undecided(reason: str) -> dict[str, Any]:
    return {"verdict": UNDECIDED, "reason": reason, "goal_timeout_s": PROBE_GOAL_TIMEOUT_S}


def compare(
    given: FunctionContract,
    probe: FunctionContract,
    include: Path,
    cppflags: str = "",
    machdep: str = "gcc_x86_64",
    *,
    strip_given_ensures: bool = False,
    wp_par: int | None = None,
    keep_dir: Path | None = None,
    work_dir: Path | None = None,
) -> tuple[ProbeUnit | None, dict[str, Any], dict[str, Any]]:
    """
    Whether contract `given` (A) refines `probe` (B), by one probe run: (the probe, the run, the verdict).
    The probe body is written on `probe`'s definition. No probe and an empty run when it cannot be built.
    """
    definition = probe.definition or given.definition
    if definition is None:
        reason = f"{probe.function}: no declaration with named parameters to write the probe on"
        return None, {}, _undecided(reason)
    try:
        unit = build_probe(
            given.pieces,
            probe.pieces,
            definition,
            bool(probe.returns_void if probe.returns_void is not None else given.returns_void),
            include.resolve(),
            probe.function,
            strip_given_ensures=strip_given_ensures,
        )
    except (ProbeError, AcslError) as exc:
        return None, {}, _undecided(str(exc))
    run = run_probe(unit, cppflags, machdep, wp_par=wp_par, keep_dir=keep_dir, work_dir=work_dir)
    return unit, run, decide(unit, run)


def _rename_sides(rows: list[dict[str, Any]], names: dict[str, str]) -> list[dict[str, Any]]:
    return [{**r, "contract": names.get(str(r.get("contract")), r.get("contract"))} for r in rows]


def refinement_check(
    new: FunctionContract,
    previous: FunctionContract,
    include: Path,
    cppflags: str = "",
    machdep: str = "gcc_x86_64",
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Use 1: whether the `new` contract gives everything the `previous` one did. `weaker` lists the clauses of
    the previous contract it no longer gives, and the `requires` of the new one the previous precondition
    does not imply (`contract`: `previous` / `new`). An unchanged contract refines without a run; a new
    contract where there was none has nothing to compare.
    """
    if not previous.pieces:
        return {"verdict": REFINES, "reason": "no previous contract", "probe_run": False}
    if " ".join(new.text().split()) == " ".join(previous.text().split()):
        return {"verdict": REFINES, "reason": "contract unchanged", "probe_run": False}
    unit, _run, res = compare(new, previous, include, cppflags, machdep, **kwargs)
    names = {"given": "new", "probe": "previous"}
    for key in ("clauses", "undecided_clauses"):
        if key in res:
            res[key] = _rename_sides(res[key], names)
    res["probe_run"] = unit is not None
    return res


FRAME_DECIDED = "decided"
FRAME_UNDECIDED = "undecided"
FRAME_NOT_APPLICABLE = "not_applicable"


def frame_only_ensures(
    contract: FunctionContract,
    include: Path,
    cppflags: str = "",
    machdep: str = "gcc_x86_64",
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Use 2: which `ensures` clauses of `contract` follow from its `requires` and `assigns` alone. Returns
    {status, ensures, frame_only, not_frame_only, undecided, all_frame_only, ...}. `status` is `decided` when
    the probe either proved every `ensures` or refuted one with a model (then not every `ensures` is
    frame-only, whatever the others are); `not_applicable` when the contract has no `ensures`.
    `all_frame_only` is true only when decided and every `ensures` was proved.
    """
    n_ensures = sum(1 for p in contract.pieces for kind, *_ in iter_clauses(acsl_body(p.acsl)) if kind == "ensures")
    base: dict[str, Any] = {"ensures": n_ensures, "goal_timeout_s": PROBE_GOAL_TIMEOUT_S}
    if n_ensures == 0:
        return {**base, "status": FRAME_NOT_APPLICABLE, "all_frame_only": False}
    unit, run, res = compare(contract, contract, include, cppflags, machdep, strip_given_ensures=True, **kwargs)
    base["elapsed_ms"] = res.get("elapsed_ms")
    if unit is None or not run.get("ok") or not res.get("goals"):
        return {**base, "status": FRAME_UNDECIDED, "reason": res.get("reason"), "all_frame_only": False}
    return {**base, **frame_summary(unit, classify_goals(unit, run))}


def frame_summary(unit: ProbeUnit, outcomes: list[GoalOutcome]) -> dict[str, Any]:
    """The use-2 reading of a probe's goals: each `ensures` of B is frame-only, not, or undecided."""
    by_label: dict[int, list[GoalOutcome]] = {}
    other_unproved = False
    for o in outcomes:
        if o.label is not None and o.label in unit.ensures_labels:
            by_label.setdefault(o.label, []).append(o)
        elif not o.proved:
            other_unproved = True
    frame_only: list[dict[str, Any]] = []
    not_frame: list[dict[str, Any]] = []
    open_rows: list[dict[str, Any]] = []
    for k in unit.ensures_labels:
        ref = unit.labels[k].to_dict()
        ref.pop("contract", None)
        goals = by_label.get(k) or []
        if goals and all(o.proved for o in goals):
            frame_only.append(ref)
        elif any(not o.proved and o.model for o in goals):
            not_frame.append(ref)
        else:
            open_rows.append(ref)
    out: dict[str, Any] = {"frame_only": frame_only, "not_frame_only": not_frame, "undecided": open_rows}
    if other_unproved:
        out.update(status=FRAME_UNDECIDED, reason="a goal other than an ensures was not proved", all_frame_only=False)
    elif not open_rows or not_frame:
        out.update(status=FRAME_DECIDED, all_frame_only=not not_frame and not open_rows)
    else:
        out.update(
            status=FRAME_UNDECIDED,
            reason="ensures left unproved without a counter-example model",
            all_frame_only=False,
        )
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two ACSL contracts of a C function by a WP probe.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, help_text in (
        ("frame-only", "which ensures of the function's contract follow from its requires and assigns alone"),
        ("compare", "whether the contract in --file refines the one in --previous-file"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--file", type=Path, required=True, help="C source defining the function")
        p.add_argument("--function", required=True)
        p.add_argument("--cppflags", default="-I.")
        p.add_argument("--machdep", default="gcc_x86_64")
        p.add_argument("--wp-par", type=int, default=None, help="concurrent provers (default: from the job budget)")
        p.add_argument("--keep-dir", type=Path, default=None, help="write and keep the probe and its log here")
        p.add_argument("--out-json", type=Path, default=None, help="write the result here (default: stdout)")
        if name == "compare":
            p.add_argument("--previous-file", type=Path, required=True, help="C source with the previous contract")
    from framac_common import normalize_flag_args

    # `--cppflags -I.`: argparse rejects a separate value that starts with '-'.
    args = parser.parse_args(normalize_flag_args(list(argv) if argv is not None else sys.argv[1:], ("--cppflags",)))
    if args.keep_dir is not None and _under_work_tree(args.keep_dir):
        parser.error("--keep-dir may not lie under workspace/work/")
    try:
        contract = read_function_contract(args.file, args.function, args.cppflags)
        kwargs: dict[str, Any] = {"wp_par": args.wp_par, "keep_dir": args.keep_dir}
        if args.cmd == "frame-only":
            res = frame_only_ensures(contract, args.file, args.cppflags, args.machdep, **kwargs)
        else:
            previous = read_function_contract(args.previous_file, args.function, args.cppflags)
            res = refinement_check(contract, previous, args.file, args.cppflags, args.machdep, **kwargs)
    except (OSError, AcslError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    res = {"function": args.function, "file": args.file.as_posix(), **res}
    text = json.dumps(res, indent=2) + "\n"
    if args.out_json is not None:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
