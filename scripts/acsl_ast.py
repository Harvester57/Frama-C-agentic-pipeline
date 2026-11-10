#!/usr/bin/env python3
"""
Deterministic C/ACSL lexical analyzer, annotation-only verifier, and function span splicer.

Used by scripts/workspace_overlay.py to enforce Milestone 2 isolation guarantees:
1. Subagents may only add or modify ACSL comments (/*@ ... */ and //@ ...);
   every executable C token, literal, normal comment, and preprocessor directive
   must match workspace/baseline/ identically.
2. Unsound ACSL directives (admit, axiom, axiomatic) are rejected in agent patches.
3. A Function Prover assigned to function F may only modify ACSL within F's
   contract+body span in its .c file and F's contract+prototype span in its .h file,
   enabling conflict-free structural splicing when same-wave provers annotate
   different functions in the same file.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


class AcslError(RuntimeError):
    """Base exception for ACSL lexical, annotation-only, or scope errors."""


class AcslSyntaxError(AcslError):
    """Raised when a C/H file contains an unclosed comment or string/char literal."""


class ScopeViolationError(AcslError):
    """Raised when an agent modifies tokens outside its assigned function or header scope."""


class ConflictingProfileError(AcslError):
    """Raised when an ACSL predicate or logic declaration conflicts with an existing declaration profile."""


@dataclass(slots=True, frozen=True)
class Token:
    """A single lexical token in a C/ACSL source file."""

    kind: str  # whitespace | acsl_block | acsl_line | c_comment | pp_directive | string | char | c_token
    text: str
    start: int
    end: int
    line: int


@dataclass(slots=True, frozen=True)
class Span:
    """Byte and line span of a function definition or prototype declaration (including its ACSL contract)."""

    function: str
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int
    text: str


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER_RE = re.compile(r"[0-9][A-Za-z0-9_.]*")
_UNSOUND_ACSL_RE = re.compile(r"\b(admit|axiom|axiomatic|inductive)\b")
_LOGIC_C_INT_RE = re.compile(
    r"\blogic\s+(?:(?:unsigned|signed)\s+)?(?:int|long|short|char|size_t|ssize_t|u?int(?:8|16|32|64)_t)\b"
)
_LOGIC_DECL_RE = re.compile(r"\blogic\s+[A-Za-z_][A-Za-z0-9_*\s]*?\b[A-Za-z_][A-Za-z0-9_]*\s*\(([^)]*)\)")
_C_INT_PARAM_RE = re.compile(
    r"^\s*(?:(?:const|unsigned|signed)\s+)*(?:int|long|short|char|size_t|ssize_t|u?int(?:8|16|32|64)_t)\s+[A-Za-z_][A-Za-z0-9_]*\s*$"
)
_INVARIANT_CLAUSE_RE = re.compile(r"(?:(loop|type|global|strong)\s+)?\binvariant\b(?!\s*:)")
_VACUOUS_FALSE_CLAUSE_RE = re.compile(
    r"\b(requires|assumes|loop\s+invariant)\s+(?:[A-Za-z_][A-Za-z0-9_]*\s*:\s*)*(?:\\false|0)\s*;"
)
_EMPTY_BEHAVIOR_RE = re.compile(r"\bbehavior\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*;")
_STRING_IN_ACSL_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_COMMENT_IN_ACSL_RE = re.compile(r"//(?![@])[^\n]*")
# A ghost function's own contract, written `/@ ... @/` inside a `/*@ ghost ... */` block.
_GHOST_CONTRACT_RE = re.compile(r"/@.*?@/", re.DOTALL)
_ESCAPED_CTRL_IN_ACSL_RE = re.compile(r"[\x07\x08\x0c]")


def tokenize_c_acsl(source: str, path: str = "<input>") -> list[Token]:
    """Tokenize C source with ACSL annotations into a complete, lossless token stream."""
    tokens: list[Token] = []
    n = len(source)
    i = 0
    line = 1
    at_line_start = True

    while i < n:
        ch = source[i]

        # 1. Whitespace
        if ch in " \t\r\n\f\v":
            start = i
            start_line = line
            while i < n and source[i] in " \t\r\n\f\v":
                if source[i] == "\n":
                    line += 1
                    at_line_start = True
                elif source[i] not in " \t\r":
                    at_line_start = False
                i += 1
            tokens.append(Token("whitespace", source[start:i], start, i, start_line))
            continue

        # 2. Block comments: /*@ ... */ (ACSL) vs /* ... */ (normal C comment)
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            start = i
            start_line = line
            is_acsl = i + 2 < n and source[i + 2] == "@" and (i + 3 >= n or source[i + 3] != "/")
            i += 2
            closed = False
            while i < n:
                if source[i] == "\n":
                    line += 1
                if source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    i += 2
                    closed = True
                    break
                i += 1
            if not closed:
                raise AcslSyntaxError(f"{path}:{start_line}: unclosed {'ACSL' if is_acsl else 'C'} block comment")
            at_line_start = False
            tokens.append(Token("acsl_block" if is_acsl else "c_comment", source[start:i], start, i, start_line))
            continue

        # 3. Line comments: //@ ... (ACSL) vs // ... (normal C comment)
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            start = i
            start_line = line
            is_acsl = i + 2 < n and source[i + 2] == "@"
            i += 2
            while i < n and source[i] != "\n":
                i += 1
            at_line_start = False
            tokens.append(Token("acsl_line" if is_acsl else "c_comment", source[start:i], start, i, start_line))
            continue

        # 4. Preprocessor directive (# at start of logical line)
        if ch == "#" and at_line_start:
            start = i
            start_line = line
            while i < n:
                if source[i] == "\\" and i + 1 < n and source[i + 1] == "\n":
                    line += 1
                    i += 2
                    continue
                if source[i] == "\\" and i + 2 < n and source[i + 1] == "\r" and source[i + 2] == "\n":
                    line += 1
                    i += 3
                    continue
                if source[i] == "\n":
                    break
                i += 1
            at_line_start = False
            tokens.append(Token("pp_directive", source[start:i], start, i, start_line))
            continue

        at_line_start = False

        # 5. String or character literal
        if ch in ('"', "'"):
            quote = ch
            start = i
            start_line = line
            i += 1
            closed = False
            while i < n:
                c = source[i]
                if c == "\\":
                    if i + 1 < n and source[i + 1] == "\n":
                        line += 1
                    i += 2
                    continue
                if c == "\n":
                    break
                if c == quote:
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                lit_kind = "string" if quote == '"' else "character"
                raise AcslSyntaxError(f"{path}:{start_line}: unclosed {lit_kind} literal")
            tokens.append(Token("string" if quote == '"' else "char", source[start:i], start, i, start_line))
            continue

        # 6. Identifier
        m_id = _IDENT_RE.match(source, i)
        if m_id:
            end = m_id.end()
            tokens.append(Token("c_token", source[i:end], i, end, line))
            i = end
            continue

        # 7. Number
        m_num = _NUMBER_RE.match(source, i)
        if m_num:
            end = m_num.end()
            tokens.append(Token("c_token", source[i:end], i, end, line))
            i = end
            continue

        # 8. Single punctuation / operator character
        tokens.append(Token("c_token", ch, i, i + 1, line))
        i += 1

    return tokens


def _check_unsound_acsl(tokens: list[Token], baseline_acsl_texts: set[str], path: str) -> list[str]:
    """
    Flag newly added ACSL annotations that introduce unsound or silently dropped constructs:
    - admit, axiom, axiomatic, inductive (unverified trust anchors / no consistency check)
    - C integer types in logic signatures (e.g. `logic int f(...)` instead of `logic integer`)
    - statement-level `invariant` without `loop`/`type`/`global`/`strong` (silently dropped by WP)
    """
    errors: list[str] = []
    for tok in tokens:
        if tok.kind not in ("acsl_block", "acsl_line"):
            continue
        if tok.text in baseline_acsl_texts:
            continue
        m_ctrl = _ESCAPED_CTRL_IN_ACSL_RE.search(tok.text)
        if m_ctrl:
            ctrl_map = {"\x07": r"\a", "\x08": r"\b", "\x0c": r"\f"}
            esc = ctrl_map.get(m_ctrl.group(0), repr(m_ctrl.group(0)))
            errors.append(
                f"{path}:{tok.line}: syntax hazard: control character {m_ctrl.group(0)!r} ({esc}) found in ACSL "
                "annotation (likely caused by unescaped \\false, \\forall, \\at, or \\base_addr in a Python/shell string)"
            )
        scrubbed = _COMMENT_IN_ACSL_RE.sub("", _STRING_IN_ACSL_RE.sub('""', tok.text))
        m = _UNSOUND_ACSL_RE.search(scrubbed)
        if m:
            errors.append(
                f"{path}:{tok.line}: forbidden unsound ACSL construct '{m.group(1)}' introduced in annotation"
            )
        m_logic = _LOGIC_C_INT_RE.search(scrubbed)
        if m_logic:
            errors.append(
                f"{path}:{tok.line}: forbidden C integer type in ACSL logic signature '{m_logic.group(0)}' "
                "(use unbounded 'integer' or 'real'; C integer types introduce wraparound into logic)"
            )
        else:
            for m_decl in _LOGIC_DECL_RE.finditer(scrubbed):
                for param in m_decl.group(1).split(","):
                    if "*" not in param and "[" not in param and _C_INT_PARAM_RE.match(param):
                        errors.append(
                            f"{path}:{tok.line}: forbidden C integer parameter '{param.strip()}' in ACSL logic signature "
                            "(use unbounded 'integer' instead of C integer types)"
                        )
                        break
        for m_inv in _INVARIANT_CLAUSE_RE.finditer(scrubbed):
            if m_inv.group(1) is None:
                errors.append(
                    f"{path}:{tok.line}: forbidden statement-level 'invariant' in annotation "
                    "(WP silently drops statement invariants; use 'loop invariant' or 'assert')"
                )
                break
        m_vac = _VACUOUS_FALSE_CLAUSE_RE.search(scrubbed)
        if m_vac:
            errors.append(
                f"{path}:{tok.line}: forbidden vacuous '{m_vac.group(0).strip()}' in annotation "
                "(assuming \\false or 0 makes all WP obligations vacuously true)"
            )
    return errors


def find_empty_named_behaviors(tokens: list[Token], path: str = "<input>") -> list[str]:
    """
    Frama-C 34+ forbids empty named behaviors (`behavior b: ;`) in function and statement
    contracts: the kernel aborts with a fatal annot-error ("unexpected token ';'"). Flag them
    before splicing so a candidate fails the mechanical check instead of the kernel parse.
    """
    errors: list[str] = []
    for tok in tokens:
        if tok.kind not in ("acsl_block", "acsl_line"):
            continue
        scrubbed = _COMMENT_IN_ACSL_RE.sub("", _STRING_IN_ACSL_RE.sub('""', tok.text))
        for m in _EMPTY_BEHAVIOR_RE.finditer(scrubbed):
            errors.append(
                f"{path}:{tok.line}: empty named behavior '{m.group(0).strip()}' is forbidden since Frama-C 34 "
                "(fatal annot-error: unexpected token ';'); give the behavior at least one clause or remove it"
            )
    return errors


def find_unsound_acsl_keywords(tokens: list[Token], path: str = "<input>") -> list[str]:
    """Check all ACSL tokens in `tokens` for unsound or hazardous ACSL constructs."""
    return _check_unsound_acsl(tokens, set(), path) + find_empty_named_behaviors(tokens, path)


def verify_acsl_only(
    baseline_text: str,
    work_text: str,
    path: str = "<input>",
    check_unsound: bool = True,
) -> list[str]:
    """Verify that work_text differs from baseline_text only in ACSL comments (/*@ ... */ and //@ ...)."""
    try:
        base_tokens = tokenize_c_acsl(baseline_text, path=path)
        work_tokens = tokenize_c_acsl(work_text, path=path)
    except AcslSyntaxError as exc:
        return [str(exc)]

    errors: list[str] = []
    errors.extend(find_empty_named_behaviors(work_tokens, path))
    if check_unsound:
        base_acsl = {t.text for t in base_tokens if t.kind in ("acsl_block", "acsl_line")}
        errors.extend(_check_unsound_acsl(work_tokens, base_acsl, path))

    base_c = [t for t in base_tokens if t.kind not in ("whitespace", "acsl_block", "acsl_line")]
    work_c = [t for t in work_tokens if t.kind not in ("whitespace", "acsl_block", "acsl_line")]

    _pp_hint = (
        " (Preprocessor directives are C tokens and cannot be added by ACSL overlays; "
        "shared ACSL logic/predicate declarations across headers are deduplicated automatically by merge-agent.)"
    )
    limit = min(len(base_c), len(work_c))
    for idx in range(limit):
        bt = base_c[idx]
        wt = work_c[idx]
        if bt.kind != wt.kind or bt.text != wt.text:
            hint = _pp_hint if wt.kind == "pp_directive" or bt.kind == "pp_directive" else ""
            errors.append(
                f"{path}:{wt.line}: non-ACSL token modified: expected {bt.text!r} "
                f"(baseline line {bt.line}), got {wt.text!r}{hint}"
            )
            return errors

    if len(work_c) > len(base_c):
        extra = work_c[limit]
        hint = _pp_hint if extra.kind == "pp_directive" else ""
        errors.append(f"{path}:{extra.line}: non-ACSL token added: {extra.text!r}{hint}")
    elif len(base_c) > len(work_c):
        missing = base_c[limit]
        hint = _pp_hint if missing.kind == "pp_directive" else ""
        errors.append(f"{path}:{missing.line}: non-ACSL token removed: {missing.text!r}{hint}")

    return errors


def _next_meaningful(tokens: list[Token], idx: int, include_acsl: bool = False) -> int:
    """Return index of next token at or after idx that is not whitespace/comment."""
    skip = {"whitespace", "c_comment"} if include_acsl else {"whitespace", "c_comment", "acsl_block", "acsl_line"}
    while idx < len(tokens) and tokens[idx].kind in skip:
        idx += 1
    return idx


def _find_matching_delim(tokens: list[Token], open_idx: int, open_ch: str, close_ch: str) -> int:
    """Find the token index of the matching closing delimiter starting at open_idx."""
    depth = 0
    for idx in range(open_idx, len(tokens)):
        tok = tokens[idx]
        if tok.kind == "c_token":
            if tok.text == open_ch:
                depth += 1
            elif tok.text == close_ch:
                depth -= 1
                if depth == 0:
                    return idx
    return -1


def _linkage_block_braces(tokens: list[Token]) -> frozenset[int]:
    """
    Indices of the `{` and `}` of every `extern "C" { ... }` block.

    The braces of a linkage specification only group declarations: a C library header wraps its whole
    API in one under `#ifdef __cplusplus`, and counting it as nesting would hide every prototype
    and top-level ACSL declaration in the file.
    """
    skip: set[int] = set()
    for i, tok in enumerate(tokens):
        if tok.kind != "c_token" or tok.text != "{":
            continue
        j = i - 1
        while j >= 0 and tokens[j].kind in ("whitespace", "c_comment"):
            j -= 1
        if j < 0 or tokens[j].kind != "string" or tokens[j].text not in ('"C"', '"C++"'):
            continue
        j -= 1
        while j >= 0 and tokens[j].kind in ("whitespace", "c_comment"):
            j -= 1
        if j < 0 or tokens[j].kind != "c_token" or tokens[j].text != "extern":
            continue
        close = _find_matching_delim(tokens, i, "{", "}")
        skip.add(i)
        if close != -1:
            skip.add(close)
    return frozenset(skip)


def locate_function_span(
    source: str, function_name: str, is_header: bool = False, path: str = "<input>"
) -> Span | None:
    """
    Locate the byte and line span of `function_name` (including any immediately preceding
    ACSL contract block) in a C source file (`is_header=False`) or header file (`is_header=True`).
    """
    tokens = tokenize_c_acsl(source, path=path)
    linkage = _linkage_block_braces(tokens)
    brace_depth = 0
    paren_depth = 0
    last_top_boundary_idx = -1  # index of last top-level ';', '}', or 'pp_directive'

    idx = 0
    n = len(tokens)
    while idx < n:
        tok = tokens[idx]
        if idx in linkage:
            idx += 1
            continue
        if tok.kind == "pp_directive" and brace_depth == 0 and paren_depth == 0:
            last_top_boundary_idx = idx
            idx += 1
            continue

        if tok.kind == "c_token":
            if tok.text == "{":
                brace_depth += 1
                idx += 1
                continue
            if tok.text == "}":
                brace_depth = max(0, brace_depth - 1)
                if brace_depth == 0 and paren_depth == 0:
                    last_top_boundary_idx = idx
                idx += 1
                continue
            if tok.text == "(":
                paren_depth += 1
                idx += 1
                continue
            if tok.text == ")":
                paren_depth = max(0, paren_depth - 1)
                idx += 1
                continue
            if tok.text == ";" and brace_depth == 0 and paren_depth == 0:
                last_top_boundary_idx = idx
                idx += 1
                continue

            # Candidate function name at top level
            if brace_depth == 0 and paren_depth == 0 and tok.text == function_name:
                open_paren_idx = _next_meaningful(tokens, idx + 1)
                if (
                    open_paren_idx < n
                    and tokens[open_paren_idx].kind == "c_token"
                    and tokens[open_paren_idx].text == "("
                ):
                    close_paren_idx = _find_matching_delim(tokens, open_paren_idx, "(", ")")
                    if close_paren_idx != -1:
                        after_paren_idx = _next_meaningful(tokens, close_paren_idx + 1)
                        if after_paren_idx < n and tokens[after_paren_idx].kind == "c_token":
                            next_tok = tokens[after_paren_idx]
                            if not is_header and next_tok.text == "{":
                                close_brace_idx = _find_matching_delim(tokens, after_paren_idx, "{", "}")
                                if close_brace_idx != -1:
                                    start_idx = _compute_span_start(tokens, last_top_boundary_idx, idx)
                                    start_tok = tokens[start_idx]
                                    end_tok = tokens[close_brace_idx]
                                    return Span(
                                        function=function_name,
                                        start_byte=start_tok.start,
                                        end_byte=end_tok.end,
                                        start_line=start_tok.line,
                                        end_line=end_tok.line,
                                        text=source[start_tok.start : end_tok.end],
                                    )
                            elif is_header and next_tok.text == ";":
                                start_idx = _compute_span_start(tokens, last_top_boundary_idx, idx)
                                start_tok = tokens[start_idx]
                                end_tok = tokens[after_paren_idx]
                                return Span(
                                    function=function_name,
                                    start_byte=start_tok.start,
                                    end_byte=end_tok.end,
                                    start_line=start_tok.line,
                                    end_line=end_tok.line,
                                    text=source[start_tok.start : end_tok.end],
                                )
        idx += 1

    return None


def _is_top_level_acsl_token(tok: Token) -> bool:
    """Return True if an ACSL block or line token contains a top-level logic declaration keyword."""
    if tok.kind not in ("acsl_block", "acsl_line"):
        return False
    inner = tok.text[3:-2] if tok.kind == "acsl_block" else tok.text[3:]
    for seg in _parse_acsl_inner_segments(inner, tok.line):
        if seg.kind in _TOP_DECL_KWS:
            return True
    return False


def _compute_span_start(tokens: list[Token], last_top_boundary_idx: int, fn_name_idx: int) -> int:
    """
    Walk backward from fn_name_idx (stopping after last_top_boundary_idx) to include
    the return type/declarator tokens and any immediately preceding ACSL contract comments,
    while leaving normal C comments and top-level ACSL declarations outside the span.
    """
    # Step 1: walk back across the return type / storage class / pointer tokens of this declaration
    start_idx = fn_name_idx
    cursor = fn_name_idx - 1
    while cursor > last_top_boundary_idx:
        t = tokens[cursor]
        if t.kind in ("acsl_block", "acsl_line"):
            if _is_top_level_acsl_token(t):
                # Stop: this is a top-level logic declaration (predicate, logic, etc.), not a function contract
                break
            start_idx = cursor
            cursor -= 1
            continue
        if t.kind == "c_token":
            start_idx = cursor
            cursor -= 1
            continue
        if t.kind == "whitespace":
            cursor -= 1
            continue
        # Stop at a normal C comment (e.g., /* Parse header magic */) before the contract/declarator
        break
    return start_idx


def locate_all_prototype_spans(source: str, path: str = "<input>") -> list[Span]:
    """Locate all function prototype spans in a header source file in source order."""
    tokens = tokenize_c_acsl(source, path=path)
    linkage = _linkage_block_braces(tokens)
    brace_depth = 0
    paren_depth = 0
    last_top_boundary_idx = -1
    spans: list[Span] = []

    idx = 0
    n = len(tokens)
    while idx < n:
        tok = tokens[idx]
        if idx in linkage:
            idx += 1
            continue
        if tok.kind == "pp_directive" and brace_depth == 0 and paren_depth == 0:
            last_top_boundary_idx = idx
            idx += 1
            continue

        if tok.kind == "c_token":
            if tok.text == "{":
                brace_depth += 1
                idx += 1
                continue
            if tok.text == "}":
                brace_depth = max(0, brace_depth - 1)
                if brace_depth == 0 and paren_depth == 0:
                    last_top_boundary_idx = idx
                idx += 1
                continue
            if tok.text == "(":
                paren_depth += 1
                idx += 1
                continue
            if tok.text == ")":
                paren_depth = max(0, paren_depth - 1)
                idx += 1
                continue
            if tok.text == ";" and brace_depth == 0 and paren_depth == 0:
                last_top_boundary_idx = idx
                idx += 1
                continue

            # Candidate function name at top level
            if brace_depth == 0 and paren_depth == 0 and _IDENT_RE.match(tok.text):
                if tok.text not in (
                    "typedef",
                    "extern",
                    "static",
                    "inline",
                    "struct",
                    "enum",
                    "union",
                    "__attribute__",
                ):
                    open_paren_idx = _next_meaningful(tokens, idx + 1)
                    if (
                        open_paren_idx < n
                        and tokens[open_paren_idx].kind == "c_token"
                        and tokens[open_paren_idx].text == "("
                    ):
                        close_paren_idx = _find_matching_delim(tokens, open_paren_idx, "(", ")")
                        if close_paren_idx != -1:
                            after_paren_idx = _next_meaningful(tokens, close_paren_idx + 1)
                            if (
                                after_paren_idx < n
                                and tokens[after_paren_idx].kind == "c_token"
                                and tokens[after_paren_idx].text == ";"
                            ):
                                has_typedef = any(
                                    tokens[k].kind == "c_token" and tokens[k].text == "typedef"
                                    for k in range(max(0, last_top_boundary_idx + 1), idx)
                                )
                                if not has_typedef:
                                    start_idx = _compute_span_start(tokens, last_top_boundary_idx, idx)
                                    start_tok = tokens[start_idx]
                                    end_tok = tokens[after_paren_idx]
                                    spans.append(
                                        Span(
                                            function=tok.text,
                                            start_byte=start_tok.start,
                                            end_byte=end_tok.end,
                                            start_line=start_tok.line,
                                            end_line=end_tok.line,
                                            text=source[start_tok.start : end_tok.end],
                                        )
                                    )
                                    last_top_boundary_idx = after_paren_idx
                                    idx = after_paren_idx + 1
                                    continue
        idx += 1
    return spans


def locate_all_definition_spans(source: str, path: str = "<input>") -> dict[str, Span]:
    """Spans of every function definition in `source`, in one pass; the first one when a name repeats."""
    tokens = tokenize_c_acsl(source, path=path)
    linkage = _linkage_block_braces(tokens)
    spans: dict[str, Span] = {}
    brace_depth = 0
    paren_depth = 0
    last_top_boundary_idx = -1
    idx = 0
    n = len(tokens)
    while idx < n:
        tok = tokens[idx]
        if idx in linkage:
            idx += 1
            continue
        if tok.kind == "pp_directive" and brace_depth == 0 and paren_depth == 0:
            last_top_boundary_idx = idx
        elif tok.kind == "c_token":
            if tok.text == "{":
                brace_depth += 1
            elif tok.text == "}":
                brace_depth = max(0, brace_depth - 1)
                if brace_depth == 0 and paren_depth == 0:
                    last_top_boundary_idx = idx
            elif tok.text == "(":
                paren_depth += 1
            elif tok.text == ")":
                paren_depth = max(0, paren_depth - 1)
            elif tok.text == ";" and brace_depth == 0 and paren_depth == 0:
                last_top_boundary_idx = idx
            elif brace_depth == 0 and paren_depth == 0 and _IDENT_RE.fullmatch(tok.text):
                open_paren_idx = _next_meaningful(tokens, idx + 1)
                if (
                    open_paren_idx < n
                    and tokens[open_paren_idx].kind == "c_token"
                    and tokens[open_paren_idx].text == "("
                ):
                    close_paren_idx = _find_matching_delim(tokens, open_paren_idx, "(", ")")
                    after_paren_idx = _next_meaningful(tokens, close_paren_idx + 1) if close_paren_idx != -1 else n
                    if after_paren_idx < n and tokens[after_paren_idx].text == "{":
                        close_brace_idx = _find_matching_delim(tokens, after_paren_idx, "{", "}")
                        if close_brace_idx != -1:
                            start_tok = tokens[_compute_span_start(tokens, last_top_boundary_idx, idx)]
                            end_tok = tokens[close_brace_idx]
                            spans.setdefault(
                                tok.text,
                                Span(
                                    function=tok.text,
                                    start_byte=start_tok.start,
                                    end_byte=end_tok.end,
                                    start_line=start_tok.line,
                                    end_line=end_tok.line,
                                    text=source[start_tok.start : end_tok.end],
                                ),
                            )
                            last_top_boundary_idx = close_brace_idx
                            idx = close_brace_idx + 1
                            continue
        idx += 1
    return spans


def _find_body_brace_offset(span_text: str, path: str = "<input>") -> int | None:
    """Return the byte offset of the function body's opening `{` inside `span_text`, or None."""
    tokens = tokenize_c_acsl(span_text, path=path)
    paren_depth = 0
    for tok in tokens:
        if tok.kind == "c_token":
            if tok.text == "(":
                paren_depth += 1
            elif tok.text == ")":
                paren_depth = max(0, paren_depth - 1)
            elif tok.text == "{" and paren_depth == 0:
                return tok.start
    return None


def has_function_contract(
    source: str,
    function_name: str,
    is_header: bool = False,
    path: str = "<input>",
) -> bool:
    """
    Return True when `function_name`'s span in `source` has at least one function-level ACSL
    contract clause (`requires`, `terminates`, `decreases`, `exits`, `assigns`, `ensures`,
    `behavior`, `assumes`, `allocates`, `frees`, `complete`, `disjoint`) before its body `{`
    (or `;` for a prototype).
    """
    span = locate_function_span(source, function_name, is_header=is_header, path=path)
    if span is None:
        return False
    header_part = span.text
    if not is_header:
        brace_off = _find_body_brace_offset(span.text, path=path)
        if brace_off is not None:
            header_part = span.text[:brace_off]
    tokens = tokenize_c_acsl(header_part, path=path)
    for tok in tokens:
        if tok.kind in ("acsl_block", "acsl_line"):
            inner = tok.text[3:-2] if tok.kind == "acsl_block" else tok.text[3:]
            for seg in _parse_acsl_inner_segments(inner, tok.line):
                if seg.kind in _CONTRACT_KWS:
                    return True
    return False


def splice_prover_changes(
    base_work_text: str,
    agent_work_text: str,
    current_work_text: str,
    function_name: str,
    is_header: bool = False,
    path: str = "<input>",
    contract_only: bool = False,
) -> str:
    """
    Validate that the prover only modified ACSL annotations inside `function_name`'s span
    (comparing `agent_work_text` against `base_work_text`), then splice `function_name`'s
    updated span into `current_work_text`. When `contract_only=True` and `not is_header`,
    only the function-level contract before `{` is taken from `agent_work_text` while the
    body `{ ... }` is preserved from `base_work_text`.
    """
    acsl_errors = verify_acsl_only(base_work_text, agent_work_text, path=path)
    if acsl_errors:
        raise AcslError(f"ACSL-only check failed on {path}:\n  " + "\n  ".join(acsl_errors))

    base_span = locate_function_span(base_work_text, function_name, is_header=is_header, path=path)
    agent_span = locate_function_span(agent_work_text, function_name, is_header=is_header, path=path)
    curr_span = locate_function_span(current_work_text, function_name, is_header=is_header, path=path)

    if base_span is None or agent_span is None or curr_span is None:
        raise ScopeViolationError(
            f"{path}: could not locate {'prototype' if is_header else 'definition'} of function '{function_name}'"
        )

    # Verify the agent did not modify anything before or after function_name's span
    base_prefix = base_work_text[: base_span.start_byte]
    agent_prefix = agent_work_text[: agent_span.start_byte]
    base_suffix = base_work_text[base_span.end_byte :]
    agent_suffix = agent_work_text[agent_span.end_byte :]

    if base_prefix != agent_prefix or base_suffix != agent_suffix:
        added = added_top_level_acsl_declarations(base_work_text, agent_work_text, path=path)
        if added:
            raise ScopeViolationError(
                f"{path}: agent added top-level ACSL declaration(s) outside '{function_name}': "
                f"{', '.join(added)}; file-scope ghost functions, predicates and lemmas are not "
                "mergeable by a prover (see the prover brief, Step B: Inductive Lemmas)"
            )
        raise ScopeViolationError(f"{path}: agent modified content outside assigned function '{function_name}'")

    # Verify that in current_work_text, function_name's span hasn't been concurrently altered
    if curr_span.text != base_span.text:
        raise ScopeViolationError(
            f"{path}: function '{function_name}' in workspace/work/ diverged from agent base snapshot"
        )

    replacement_span = agent_span.text
    if contract_only and not is_header:
        agent_brace = _find_body_brace_offset(agent_span.text, path=path)
        base_brace = _find_body_brace_offset(base_span.text, path=path)
        if agent_brace is not None and base_brace is not None:
            replacement_span = agent_span.text[:agent_brace] + base_span.text[base_brace:]

    spliced = current_work_text[: curr_span.start_byte] + replacement_span + current_work_text[curr_span.end_byte :]
    post_errors = verify_acsl_only(current_work_text, spliced, path=path)
    if post_errors:
        raise AcslError(f"Post-splice ACSL-only check failed on {path}:\n  " + "\n  ".join(post_errors))
    return spliced


# ---------------------------------------------------------------------------
# Comment- & quantifier-aware ACSL top-level declaration parser & deduplicator
# ---------------------------------------------------------------------------

_TOP_DECL_KWS = frozenset({"predicate", "logic", "lemma", "type", "axiomatic", "inductive", "ghost"})
_CONTRACT_KWS = frozenset(
    {
        "requires",
        "terminates",
        "decreases",
        "exits",
        "assigns",
        "ensures",
        "behavior",
        "assumes",
        "allocates",
        "frees",
        "complete",
        "disjoint",
    }
)
_C_TYPE_KEYWORDS = frozenset(
    {
        "int",
        "char",
        "short",
        "long",
        "float",
        "double",
        "void",
        "signed",
        "unsigned",
        "bool",
        "_bool",
        "integer",
        "real",
        "boolean",
        "size_t",
        "ssize_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uintptr_t",
        "intptr_t",
        "ptrdiff_t",
    }
)
_CHAR_LIT_RE = re.compile(r"'(?:\\.|[^'\\\n]){1,4}'")
_STR_LIT_RE = re.compile(r'"(?:\\.|[^"\\\n])*"')


@dataclass(slots=True, frozen=True)
class _AcslSegment:
    kind: str | None  # top-level declaration keyword, contract keyword, or None for trailing trivia
    name: str | None  # declared identifier name when kind in _TOP_DECL_KWS
    raw_text: str
    line: int
    arity: int | None = None
    param_types: tuple[str, ...] | None = None


def _normalize_acsl_type(type_str: str) -> str:
    """Normalize whitespace and type aliases in ACSL parameter type strings."""
    t = _COMMENT_IN_ACSL_RE.sub(" ", type_str).strip()
    t = re.sub(r"/\*.*?\*/", " ", t, flags=re.DOTALL)
    t = re.sub(r"\s*\*\s*", " *", t)
    t = re.sub(r"\s+", " ", t).strip()
    t = re.sub(r"\buint8_t\b", "unsigned char", t)
    t = re.sub(r"\bint8_t\b", "signed char", t)
    t = re.sub(r"\buint16_t\b", "unsigned short", t)
    t = re.sub(r"\bint16_t\b", "short", t)
    t = re.sub(r"\buint32_t\b", "unsigned int", t)
    t = re.sub(r"\bint32_t\b", "int", t)
    t = re.sub(r"\buint64_t\b", "unsigned long", t)
    t = re.sub(r"\bint64_t\b", "long", t)
    return t


def _extract_decl_param_types(
    kind: str,
    body_after_kw: str,
    decl_name: str | None,
) -> tuple[str, ...] | None:
    """Return the normalized parameter types for `predicate`/`logic`/`inductive` declarations, or None."""
    if kind not in ("predicate", "logic", "inductive") or not decl_name:
        return None
    scrubbed = _COMMENT_IN_ACSL_RE.sub(" ", body_after_kw)
    pos = -1
    for m in re.finditer(rf"\b{re.escape(decl_name)}\b", scrubbed):
        pos = m.end()
        tail_preview = scrubbed[pos:].lstrip()
        if not tail_preview or tail_preview[0] in "({=;":
            break
    if pos == -1:
        return None
    i = pos
    n = len(scrubbed)
    # Skip optional `{L1, L2}` label list after the declaration name
    while i < n and scrubbed[i].isspace():
        i += 1
    if i < n and scrubbed[i] == "{":
        b_depth = 1
        i += 1
        while i < n and b_depth > 0:
            if scrubbed[i] == "{":
                b_depth += 1
            elif scrubbed[i] == "}":
                b_depth -= 1
            i += 1
    while i < n and scrubbed[i].isspace():
        i += 1
    if i >= n or scrubbed[i] != "(":
        return ()

    # Scan parameter list `( ... )`
    p_depth = 1
    i += 1
    param_start = i
    raw_params: list[str] = []
    while i < n and p_depth > 0:
        ch = scrubbed[i]
        if ch in "([<":
            p_depth += 1
        elif ch in ")]>":
            p_depth -= 1
            if p_depth == 0:
                raw_params.append(scrubbed[param_start:i])
                break
        elif ch == "," and p_depth == 1:
            raw_params.append(scrubbed[param_start:i])
            param_start = i + 1
        i += 1

    parsed_types: list[str] = []
    for raw in raw_params:
        cleaned = raw.strip()
        if not cleaned or cleaned == "void":
            continue
        star_pos = cleaned.rfind("*")
        if star_pos != -1:
            after = cleaned[star_pos + 1 :].strip()
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", after):
                type_part = cleaned[: star_pos + 1]
            else:
                type_part = cleaned
        else:
            words = cleaned.split()
            if len(words) > 1:
                # Disambiguate anonymous parameter from named parameter:
                # If the last word is a known type keyword, or if the declaration
                # is an anonymous struct/union/enum (e.g. "struct token", "const struct token"),
                # the last word is part of the type, not a variable name.
                has_tag = False
                for tag_kw in ("struct", "union", "enum"):
                    if tag_kw in words:
                        idx = words.index(tag_kw)
                        if idx == len(words) - 2:
                            has_tag = True
                        break

                if words[-1].lower() in _C_TYPE_KEYWORDS or has_tag:
                    type_part = cleaned
                elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", words[-1]):
                    type_part = " ".join(words[:-1])
                else:
                    type_part = cleaned
            else:
                type_part = cleaned
        parsed_types.append(_normalize_acsl_type(type_part))

    return tuple(parsed_types)


def _is_acsl_comment_or_whitespace_only(inner: str) -> bool:
    """Return True if the ACSL annotation interior contains only whitespace and/or comments."""
    no_comments = _COMMENT_IN_ACSL_RE.sub(" ", inner)
    no_comments = re.sub(r"/\*.*?\*/", " ", no_comments, flags=re.DOTALL)
    remainder = re.sub(r"[\s*@]", "", no_comments)
    return len(remainder) == 0


def _extract_decl_arity(kind: str, body_after_kw: str, decl_name: str | None) -> int | None:
    """Return the parameter count for `predicate`/`logic`/`inductive` declarations, or None."""
    if kind not in ("predicate", "logic", "inductive") or not decl_name:
        return None
    scrubbed = _COMMENT_IN_ACSL_RE.sub(" ", body_after_kw)
    # Find the last occurrence of decl_name before `(`, `=`, `;`, or `reads`
    pos = -1
    for m in re.finditer(rf"\b{re.escape(decl_name)}\b", scrubbed):
        pos = m.end()
        tail_preview = scrubbed[pos:].lstrip()
        if not tail_preview or tail_preview[0] in "({=;":
            break
    if pos == -1:
        return None
    i = pos
    n = len(scrubbed)
    # Skip optional `{L1, L2}` label list after the declaration name
    while i < n and scrubbed[i].isspace():
        i += 1
    if i < n and scrubbed[i] == "{":
        b_depth = 1
        i += 1
        while i < n and b_depth > 0:
            if scrubbed[i] == "{":
                b_depth += 1
            elif scrubbed[i] == "}":
                b_depth -= 1
            i += 1
    while i < n and scrubbed[i].isspace():
        i += 1
    if i >= n or scrubbed[i] != "(":
        return 0
    # Scan parameter list `( ... )` and count top-level commas
    p_depth = 1
    i += 1
    param_start = i
    commas = 0
    while i < n and p_depth > 0:
        ch = scrubbed[i]
        if ch in "([<":
            p_depth += 1
        elif ch in ")]>":
            p_depth -= 1
            if p_depth == 0:
                break
        elif ch == "," and p_depth == 1:
            commas += 1
        i += 1
    inner_params = scrubbed[param_start:i].strip()
    if not inner_params:
        return 0
    return commas + 1


def _extract_decl_name(kind: str, body_after_kw: str) -> str | None:
    """Extract the declared identifier name from the body following `kind`."""
    scrubbed = _COMMENT_IN_ACSL_RE.sub(" ", body_after_kw)
    if kind in ("predicate", "lemma", "axiomatic", "inductive"):
        m = _IDENT_RE.search(scrubbed)
        return m.group(0) if m else None
    if kind == "type":
        ids = _IDENT_RE.findall(scrubbed)
        if not ids:
            return None
        if ids[0] == "invariant" and len(ids) >= 2:
            return ids[1]
        return ids[0]
    if kind in ("logic", "ghost"):
        # Scan up to the parameter list `(`, label `{`, array `[`, initializer `=`, `;`, or `reads`
        angle_depth = 0
        last_id: str | None = None
        i = 0
        n = len(scrubbed)
        while i < n:
            ch = scrubbed[i]
            if ch == "<":
                angle_depth += 1
                i += 1
                continue
            if ch == ">":
                angle_depth = max(0, angle_depth - 1)
                i += 1
                continue
            if angle_depth == 0 and ch in "({=[;":
                break
            if ch == "\\":
                m_bs = _IDENT_RE.match(scrubbed, i + 1)
                i = m_bs.end() if m_bs else (i + 1)
                continue
            m_id = _IDENT_RE.match(scrubbed, i)
            if m_id:
                word = m_id.group(0)
                if angle_depth == 0:
                    if word == "reads" and last_id is not None:
                        break
                    last_id = word
                i = m_id.end()
                continue
            i += 1
        return last_id
    return None


def _consume_line_tail(inner: str, pos: int) -> tuple[int, int]:
    """Consume trailing horizontal whitespace, optional inline `//...` comment, and one newline."""
    n = len(inner)
    i = pos
    while i < n and inner[i] in " \t\r":
        i += 1
    if i + 1 < n and inner[i] == "/" and inner[i + 1] == "/":
        while i < n and inner[i] != "\n":
            i += 1
    if i < n and inner[i] == "\n":
        return i + 1, 1
    return pos, 0


def _parse_acsl_inner_segments(inner: str, base_line: int) -> list[_AcslSegment]:
    """
    Partition the interior of a top-level `/*@ ... */` or `//@ ...` token into
    clauses/declarations while tracking `//` comments, string/char literals,
    `(...)`/`{...}`/`[...]` nesting, and `\\forall`/`\\exists`/`\\let` binder semicolons.
    """
    segments: list[_AcslSegment] = []
    n = len(inner)
    i = 0
    seg_start = 0
    line = base_line
    seg_line = base_line
    line_start_offset = 0
    at_line_start = True

    p_depth = 0
    b_depth = 0
    k_depth = 0
    binder_stack: list[tuple[int, int, int]] = []
    current_kw: str | None = None
    kw_end_offset: int = -1
    seen_paren_after_kw = False

    def _flush(end_pos: int) -> None:
        nonlocal seg_start, current_kw, kw_end_offset, seen_paren_after_kw
        if end_pos <= seg_start:
            return
        decl_name: str | None = None
        decl_arity: int | None = None
        decl_param_types: tuple[str, ...] | None = None
        if current_kw in _TOP_DECL_KWS and kw_end_offset != -1 and kw_end_offset <= end_pos:
            body_slice = inner[kw_end_offset:end_pos]
            if current_kw == "ghost":
                body_slice = _GHOST_CONTRACT_RE.sub(" ", body_slice)
            decl_name = _extract_decl_name(current_kw, body_slice)
            decl_arity = _extract_decl_arity(current_kw, body_slice, decl_name)
            decl_param_types = _extract_decl_param_types(current_kw, body_slice, decl_name)
        segments.append(
            _AcslSegment(
                kind=current_kw,
                name=decl_name,
                raw_text=inner[seg_start:end_pos],
                line=seg_line,
                arity=decl_arity,
                param_types=decl_param_types,
            )
        )
        seg_start = end_pos
        current_kw = None
        kw_end_offset = -1
        seen_paren_after_kw = False
        binder_stack.clear()

    while i < n:
        ch = inner[i]

        if ch == "\n":
            line += 1
            i += 1
            line_start_offset = i
            at_line_start = True
            continue

        if ch in " \t\r\f\v":
            i += 1
            continue

        # Single-line comment inside ACSL block: skip completely
        if ch == "/" and i + 1 < n and inner[i + 1] == "/":
            i += 2
            while i < n and inner[i] != "\n":
                i += 1
            at_line_start = False
            continue

        # A ghost function's `/@ ... @/` contract: its `;` and keywords belong to the ghost
        # declaration, not to new top-level segments
        if current_kw == "ghost" and ch == "/" and i + 1 < n and inner[i + 1] == "@":
            close = inner.find("@/", i + 2)
            end = n if close == -1 else close + 2
            nl = inner.count("\n", i, end)
            if nl:
                line += nl
                line_start_offset = inner.rfind("\n", i, end) + 1
            at_line_start = False
            i = end
            continue

        # Leading `*` bullet on continuation line inside /*@ ... */
        if at_line_start and ch == "*":
            at_line_start = False
            i += 1
            continue

        # String or character literal
        if ch == '"':
            m_str = _STR_LIT_RE.match(inner, i)
            at_line_start = False
            i = m_str.end() if m_str else (i + 1)
            continue
        if ch == "'":
            m_chr = _CHAR_LIT_RE.match(inner, i)
            at_line_start = False
            i = m_chr.end() if m_chr else (i + 1)
            continue

        # Backslash ACSL keyword (\forall, \exists, \let, etc.)
        if ch == "\\":
            at_line_start = False
            m_bs = _IDENT_RE.match(inner, i + 1)
            if m_bs:
                bs_word = m_bs.group(0)
                if bs_word in ("forall", "exists", "let"):
                    binder_stack.append((p_depth, b_depth, k_depth))
                i = m_bs.end()
                continue
            i += 1
            continue

        # Identifier
        m_id = _IDENT_RE.match(inner, i)
        if m_id:
            word = m_id.group(0)
            if p_depth == 0 and b_depth == 0 and k_depth == 0:
                if current_kw is None:
                    current_kw = word
                    kw_end_offset = m_id.end()
                    seg_line = line
                elif at_line_start and (word in _TOP_DECL_KWS or word in _CONTRACT_KWS):
                    # A new top-level declaration/clause keyword started at line start at depth 0
                    if line_start_offset > seg_start:
                        _flush(line_start_offset)
                    current_kw = word
                    kw_end_offset = m_id.end()
                    seg_line = line
            at_line_start = False
            i = m_id.end()
            continue

        at_line_start = False

        if ch == "(":
            if current_kw is not None and b_depth == 0:
                seen_paren_after_kw = True
            p_depth += 1
            i += 1
            continue
        if ch == ")":
            p_depth = max(0, p_depth - 1)
            while binder_stack and binder_stack[-1][0] > p_depth:
                binder_stack.pop()
            i += 1
            continue
        if ch == "{":
            b_depth += 1
            i += 1
            continue
        if ch == "}":
            b_depth = max(0, b_depth - 1)
            while binder_stack and binder_stack[-1][1] > b_depth:
                binder_stack.pop()
            i += 1
            if b_depth == 0 and p_depth == 0 and k_depth == 0:
                if current_kw in ("axiomatic", "inductive") or (current_kw == "ghost" and seen_paren_after_kw):
                    while i < n and inner[i] in " \t":
                        i += 1
                    if i < n and inner[i] == ";":
                        i += 1
                    next_i, nl_inc = _consume_line_tail(inner, i)
                    _flush(next_i)
                    if nl_inc:
                        line += nl_inc
                        line_start_offset = next_i
                        at_line_start = True
                    i = next_i
            continue
        if ch == "[":
            k_depth += 1
            i += 1
            continue
        if ch == "]":
            k_depth = max(0, k_depth - 1)
            while binder_stack and binder_stack[-1][2] > k_depth:
                binder_stack.pop()
            i += 1
            continue
        if ch == ";":
            i += 1
            if binder_stack and binder_stack[-1] == (p_depth, b_depth, k_depth):
                binder_stack.pop()
            elif p_depth == 0 and b_depth == 0 and k_depth == 0 and current_kw is not None:
                next_i, nl_inc = _consume_line_tail(inner, i)
                _flush(next_i)
                if nl_inc:
                    line += nl_inc
                    line_start_offset = next_i
                    at_line_start = True
                i = next_i
            continue

        i += 1

    if seg_start < n:
        _flush(n)

    return segments


def extract_top_level_acsl_declarations(source: str, path: str = "<input>") -> list[dict]:
    """
    Return all top-level ACSL declarations (`predicate`, `logic`, `lemma`, `type`,
    `axiomatic`, `inductive`, `ghost`) outside C `{ ... }` blocks in `source`.
    """
    tokens = tokenize_c_acsl(source, path=path)
    linkage = _linkage_block_braces(tokens)
    brace_depth = 0
    paren_depth = 0
    decls: list[dict] = []

    for tok_idx, tok in enumerate(tokens):
        if tok_idx in linkage:
            continue
        if tok.kind == "c_token":
            if tok.text == "{":
                brace_depth += 1
            elif tok.text == "}":
                brace_depth = max(0, brace_depth - 1)
            elif tok.text == "(":
                paren_depth += 1
            elif tok.text == ")":
                paren_depth = max(0, paren_depth - 1)
            continue

        if brace_depth == 0 and paren_depth == 0 and tok.kind in ("acsl_block", "acsl_line"):
            inner = tok.text[3:-2] if tok.kind == "acsl_block" else tok.text[3:]
            for seg in _parse_acsl_inner_segments(inner, tok.line):
                if seg.kind in _TOP_DECL_KWS and seg.name:
                    profile_key = f"{seg.name}/{seg.arity}" if seg.arity is not None else seg.name
                    param_types = seg.param_types
                    full_profile = (
                        f"{seg.name}(" + ", ".join(param_types) + ")" if param_types is not None else profile_key
                    )
                    decls.append(
                        {
                            "kind": seg.kind,
                            "name": seg.name,
                            "arity": seg.arity,
                            "param_types": param_types,
                            "profile_key": profile_key,
                            "full_profile": full_profile,
                            "text": seg.raw_text.strip(),
                            "line": seg.line,
                        }
                    )

    return decls


def added_top_level_acsl_declarations(base_text: str, agent_text: str, path: str = "<input>") -> list[str]:
    """
    Return `"<kind> <name>"` for each top-level ACSL declaration present in `agent_text`
    but not in `base_text`, in source order (compared on `(kind, name)`, counting repeats).
    """
    remaining = Counter((d["kind"], d["name"]) for d in extract_top_level_acsl_declarations(base_text, path=path))
    added: list[str] = []
    for d in extract_top_level_acsl_declarations(agent_text, path=path):
        key = (d["kind"], d["name"])
        if remaining[key] > 0:
            remaining[key] -= 1
        else:
            added.append(f"{d['kind']} {d['name']}")
    return added


def dedup_acsl_declarations(
    target_text: str,
    existing_names: set[str],
    baseline_text: str | None = None,
    path: str = "<input>",
) -> tuple[str, list[str]]:
    """
    Remove duplicate top-level ACSL declarations (`predicate`, `logic`, `lemma`, `type`,
    `axiomatic`, `inductive`, `ghost`) from `target_text` whose identifier name,
    `name/arity` profile, or full signature is already in `existing_names` (or duplicated
    earlier in `target_text`), while preserving overloaded declarations with different
    signatures and any declarations already present in `baseline_text`. Strips ACSL
    annotation blocks that contain only whitespace and/or comments to prevent empty-annotation
    errors.
    """
    baseline_profiles: set[str] = set()
    if baseline_text:
        for d in extract_top_level_acsl_declarations(baseline_text, path=path):
            baseline_profiles.add(d["profile_key"])
            baseline_profiles.add(d["name"])
            if d.get("full_profile"):
                baseline_profiles.add(d["full_profile"])

    seen: set[str] = set(existing_names)
    removed: list[str] = []

    tokens = tokenize_c_acsl(target_text, path=path)
    linkage = _linkage_block_braces(tokens)
    brace_depth = 0
    paren_depth = 0
    out_parts: list[str] = []
    idx = 0
    total = len(tokens)

    while idx < total:
        tok = tokens[idx]
        if idx in linkage:
            out_parts.append(tok.text)
            idx += 1
            continue
        if tok.kind == "c_token":
            if tok.text == "{":
                brace_depth += 1
            elif tok.text == "}":
                brace_depth = max(0, brace_depth - 1)
            elif tok.text == "(":
                paren_depth += 1
            elif tok.text == ")":
                paren_depth = max(0, paren_depth - 1)
            out_parts.append(tok.text)
            idx += 1
            continue

        if brace_depth == 0 and paren_depth == 0 and tok.kind in ("acsl_block", "acsl_line"):
            inner = tok.text[3:-2] if tok.kind == "acsl_block" else tok.text[3:]
            segments = _parse_acsl_inner_segments(inner, tok.line)
            kept_segments: list[_AcslSegment] = []
            removed_in_block = False

            for seg in segments:
                if seg.kind in _TOP_DECL_KWS and seg.name:
                    profile_key = f"{seg.name}/{seg.arity}" if seg.arity is not None else seg.name
                    full_profile = (
                        f"{seg.name}(" + ", ".join(seg.param_types) + ")"
                        if seg.param_types is not None
                        else profile_key
                    )
                    if (
                        full_profile in baseline_profiles
                        or profile_key in baseline_profiles
                        or seg.name in baseline_profiles
                    ):
                        seen.add(full_profile)
                        seen.add(profile_key)
                        kept_segments.append(seg)
                    elif full_profile in seen or profile_key in seen or seg.name in seen:
                        removed.append(seg.name)
                        removed_in_block = True
                    else:
                        seen.add(full_profile)
                        kept_segments.append(seg)
                else:
                    kept_segments.append(seg)

            is_empty_or_comments = False
            rebuilt_inner: str = ""
            if not removed_in_block:
                if _is_acsl_comment_or_whitespace_only(inner):
                    is_empty_or_comments = True
                else:
                    out_parts.append(tok.text)
            else:
                rebuilt_inner = "".join(s.raw_text for s in kept_segments)
                if _is_acsl_comment_or_whitespace_only(rebuilt_inner):
                    is_empty_or_comments = True
                else:
                    if tok.kind == "acsl_block":
                        out_parts.append(f"/*@{rebuilt_inner}*/")
                    else:
                        out_parts.append(f"//@{rebuilt_inner}")

            if is_empty_or_comments:
                if out_parts and out_parts[-1].isspace() and "\n" not in out_parts[-1]:
                    if len(out_parts) == 1 or "\n" in out_parts[-2]:
                        out_parts.pop()
                if idx + 1 < total and tokens[idx + 1].kind == "whitespace":
                    ws_text = tokens[idx + 1].text
                    if ws_text.startswith("\r\n"):
                        tokens[idx + 1] = Token(
                            "whitespace",
                            ws_text[2:],
                            tokens[idx + 1].start + 2,
                            tokens[idx + 1].end,
                            tokens[idx + 1].line + 1,
                        )
                    elif ws_text.startswith("\n"):
                        tokens[idx + 1] = Token(
                            "whitespace",
                            ws_text[1:],
                            tokens[idx + 1].start + 1,
                            tokens[idx + 1].end,
                            tokens[idx + 1].line + 1,
                        )
            idx += 1
            continue

        out_parts.append(tok.text)
        idx += 1

    return "".join(out_parts), removed


def _normalize_text_whitespace(text: str) -> str:
    """Normalize whitespace within code or contract snippets for equality checking."""
    return " ".join(text.split())


def splice_architect_header(
    base_text: str,
    agent_text: str,
    current_text: str,
    path: str = "<input>",
) -> str:
    """
    Tolerantly merge an Interface Architect's header modifications into current_text
    when current_text was concurrently updated by a leaf/static prover or peer architect.
    """
    acsl_errors = verify_acsl_only(base_text, agent_text, path=path)
    if acsl_errors:
        raise AcslError(f"ACSL-only check failed on {path}:\n  " + "\n  ".join(acsl_errors))

    curr_errors = verify_acsl_only(base_text, current_text, path=path)
    if curr_errors:
        raise AcslError(f"Current workspace has ACSL-only check errors on {path}:\n  " + "\n  ".join(curr_errors))

    if current_text == base_text:
        return agent_text
    if agent_text == base_text or agent_text == current_text:
        return current_text

    base_proto_spans = locate_all_prototype_spans(base_text, path=path)
    agent_proto_spans = locate_all_prototype_spans(agent_text, path=path)
    curr_proto_spans = locate_all_prototype_spans(current_text, path=path)

    base_spans = {s.function: s for s in base_proto_spans}
    agent_spans = {s.function: s for s in agent_proto_spans}
    curr_spans = {s.function: s for s in curr_proto_spans}

    if set(base_spans.keys()) != set(agent_spans.keys()) or set(base_spans.keys()) != set(curr_spans.keys()):
        raise ScopeViolationError(f"{path}: function prototype mismatch between base, agent, and current")

    # Step 1: Detect prototype contract conflicts and record replacements
    replacements: list[tuple[int, int, str]] = []  # (start_byte, end_byte, replacement_text)
    for fn, b_s in base_spans.items():
        a_s = agent_spans[fn]
        c_s = curr_spans[fn]
        a_mod = _normalize_text_whitespace(a_s.text) != _normalize_text_whitespace(b_s.text)
        c_mod = _normalize_text_whitespace(c_s.text) != _normalize_text_whitespace(b_s.text)

        if a_mod and c_mod:
            if _normalize_text_whitespace(a_s.text) != _normalize_text_whitespace(c_s.text):
                raise ScopeViolationError(
                    f"{path}: conflicting concurrent modification to prototype contract of '{fn}'"
                )
        elif a_mod and not c_mod:
            replacements.append((c_s.start_byte, c_s.end_byte, a_s.text))

    # Step 2: Extract and reconcile top-level ACSL declarations
    b_decls = {d["profile_key"]: d for d in extract_top_level_acsl_declarations(base_text, path=path)}
    a_decls = {d["profile_key"]: d for d in extract_top_level_acsl_declarations(agent_text, path=path)}
    c_decls = {d["profile_key"]: d for d in extract_top_level_acsl_declarations(current_text, path=path)}

    for k, a_d in a_decls.items():
        if k in c_decls:
            if _normalize_text_whitespace(a_d["text"]) != _normalize_text_whitespace(c_decls[k]["text"]):
                raise ScopeViolationError(f"{path}: conflicting concurrent declaration of '{a_d['name']}'")

    for k, b_d in b_decls.items():
        if k not in a_decls and k in c_decls:
            if _normalize_text_whitespace(c_decls[k]["text"]) != _normalize_text_whitespace(b_d["text"]):
                raise ScopeViolationError(
                    f"{path}: conflicting concurrent modification/deletion of declaration '{b_d['name']}'"
                )

    # Step 3: Apply prototype replacements in current_text in reverse order
    spliced = current_text
    for start, end, rep in sorted(replacements, key=lambda x: x[0], reverse=True):
        spliced = spliced[:start] + rep + spliced[end:]

    # Step 4: Splice new top-level ACSL declarations introduced by the architect
    new_decls = [d for k, d in a_decls.items() if k not in b_decls and k not in c_decls]
    if new_decls:
        agent_tokens = tokenize_c_acsl(agent_text, path=path)
        blocks_to_insert: list[tuple[str | None, str]] = []  # (anchor_fn, block_text)
        for t in agent_tokens:
            if t.kind in ("acsl_block", "acsl_line"):
                inner = t.text[3:-2] if t.kind == "acsl_block" else t.text[3:]
                segs = _parse_acsl_inner_segments(inner, t.line)
                if any(s.name and any(d["name"] == s.name for d in new_decls) for s in segs):
                    # Identify anchor: find next function prototype in agent_proto_spans
                    anchor_fn = None
                    for span in agent_proto_spans:
                        if span.start_byte >= t.end:
                            anchor_fn = span.function
                            break
                    blocks_to_insert.append((anchor_fn, t.text))

        for anchor_fn, blk_text in blocks_to_insert:
            fresh_spans = {s.function: s for s in locate_all_prototype_spans(spliced, path=path)}
            if anchor_fn and anchor_fn in fresh_spans:
                pos = fresh_spans[anchor_fn].start_byte
                spliced = spliced[:pos] + blk_text + "\n\n" + spliced[pos:]
            else:
                pos = spliced.rfind("#endif")
                if pos == -1:
                    pos = len(spliced)
                spliced = spliced[:pos] + blk_text + "\n\n" + spliced[pos:]

    # Deduplicate intra-file declarations
    spliced, _ = dedup_acsl_declarations(spliced, set(), baseline_text=base_text, path=path)

    # Step 5: Post-splice verification
    post_errors = verify_acsl_only(base_text, spliced, path=path)
    if post_errors:
        raise AcslError(f"Post-splice ACSL-only check failed on {path}:\n  " + "\n  ".join(post_errors))

    return spliced


_INT_LITERAL_RE = re.compile(r"^[0-9]+$")
_RELATION_RE = re.compile(r"==|!=|<=|>=|<|(?<!-)>")


def find_named_clause(source: str, name: str) -> str | None:
    """Predicate of the ACSL clause labelled `name` (`ensures L5_x: <predicate>;`), or None if absent."""
    m = re.search(rf"\b{re.escape(name)}\s*:(.*?)(?:;|\*/)", source, re.DOTALL)
    if m is None:
        return None
    return " ".join(m.group(1).replace("@", " ").split())


def _top_level_positions(text: str) -> list[bool]:
    """For each character of `text`, whether it sits outside every bracket."""
    depth = 0
    out = []
    for ch in text:
        if ch in ")]}":
            depth -= 1
        out.append(depth == 0)
        if ch in "([{":
            depth += 1
    return out


def _split_top_level(text: str, op: str) -> list[str]:
    top = _top_level_positions(text)
    parts: list[str] = []
    start = i = 0
    while i < len(text):
        # `<==>` contains `==>`: it is split on first and must not read as an implication here.
        if top[i] and text.startswith(op, i) and not (op == "==>" and i > 0 and text[i - 1] == "<"):
            parts.append(text[start:i])
            i += len(op)
            start = i
        else:
            i += 1
    parts.append(text[start:])
    return [p.strip() for p in parts]


def _strip_outer_parens(text: str) -> str:
    text = text.strip()
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        for i, ch in enumerate(text):
            depth += (ch == "(") - (ch == ")")
            if depth == 0 and i < len(text) - 1:
                return text
        text = text[1:-1].strip()
    return text


def _is_trivial_relation(text: str) -> bool:
    top = _top_level_positions(text)
    found = [m for m in _RELATION_RE.finditer(text) if top[m.start()]]
    if len(found) != 1:
        return False
    op = found[0].group(0)
    lhs = _strip_outer_parens(text[: found[0].start()])
    rhs = _strip_outer_parens(text[found[0].end() :])
    if lhs == rhs:
        return op in ("==", "<=", ">=")
    if _INT_LITERAL_RE.match(lhs) and _INT_LITERAL_RE.match(rhs):
        a, b = int(lhs), int(rhs)
        return {"==": a == b, "!=": a != b, "<=": a <= b, ">=": a >= b, "<": a < b, ">": a > b}[op]
    return False


def is_trivial_predicate(text: str) -> bool:
    """
    True when an ACSL predicate holds whatever the program does: `\\true`, a nonzero literal, `x == x`,
    `1 <= 2`, or a connective built from those. Conservative and syntactic: it answers False for
    anything it cannot see through, such as a predicate call or a quantifier.
    """
    text = _strip_outer_parens(" ".join(text.split()))
    if text == "\\true" or (_INT_LITERAL_RE.match(text) and int(text) != 0):
        return True
    if len(parts := _split_top_level(text, "<==>")) > 1:
        return len({_strip_outer_parens(p) for p in parts}) == 1
    if len(parts := _split_top_level(text, "==>")) > 1:
        lhs, rhs = _strip_outer_parens(parts[0]), _strip_outer_parens(" ==> ".join(parts[1:]))
        return is_trivial_predicate(rhs) or lhs == rhs or lhs == "\\false"
    if len(parts := _split_top_level(text, "||")) > 1:
        return any(is_trivial_predicate(p) for p in parts)
    if len(parts := _split_top_level(text, "&&")) > 1:
        return all(is_trivial_predicate(p) for p in parts)
    return _is_trivial_relation(text)


# ---------------------------------------------------------------------------
# Frame-skeleton preservation (AutoFraming-style projected frame clauses)
# ---------------------------------------------------------------------------

_SEPARATED_RE = re.compile(r"\\separated\s*\(")
_ASSIGNS_RE = re.compile(r"\bassigns\b")
_LOOP_ASSIGNS_PREFIX_RE = re.compile(r"\bloop\s*$")
_FROM_RE = re.compile(r"\\from\b")
_LEADING_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _paren_group_at(text: str, open_idx: int) -> tuple[str, int]:
    """Inner text of the paren group opening at `open_idx`, and the index after its close."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i], i + 1
    return text[open_idx + 1 :], len(text)


def _scan_to_semicolon(text: str, start: int) -> int:
    """Index of the first top-level `;` at or after `start` (ACSL clauses end there)."""
    top = _top_level_positions(text)
    for i in range(start, len(text)):
        if top[i] and text[i] == ";":
            return i
    return len(text)


def extract_frame_clauses(acsl_text: str) -> dict:
    """
    Parse the frame clauses of one ACSL contract text:
    `\\separated(...)` argument lists and function-level `assigns ... [\\from ...];` clauses
    (`loop assigns` is not a function frame clause and is skipped). Purely syntactic.
    """
    separated: list[list[str]] = []
    for m in _SEPARATED_RE.finditer(acsl_text):
        inner, _ = _paren_group_at(acsl_text, m.end() - 1)
        separated.append(_split_top_level(inner, ","))
    assigns: list[dict] = []
    for m in _ASSIGNS_RE.finditer(acsl_text):
        prefix = acsl_text[max(0, m.start() - 6) : m.start()]
        if _LOOP_ASSIGNS_PREFIX_RE.search(prefix):
            continue
        end = _scan_to_semicolon(acsl_text, m.end())
        clause = acsl_text[m.end() : end]
        from_m = _FROM_RE.search(clause)
        if from_m:
            locs_text, from_text = clause[: from_m.start()], clause[from_m.end() :]
        else:
            locs_text, from_text = clause, ""
        from_parts = _split_top_level(from_text, ",") if from_text.strip() else []
        assigns.append(
            {
                "locs": _split_top_level(locs_text, ","),
                "from": from_parts,
                "from_nothing": bool(from_parts) and all(p == "\\nothing" for p in from_parts),
            }
        )
    return {"separated": separated, "assigns": assigns}


def _norm_clause(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


def check_frame_preserved(skeleton: dict, acsl_text: str, path: str = "<input>") -> list[str]:
    """
    Verify that a candidate contract preserves a projected frame skeleton
    (frame_skeleton.compute output): every `\\separated` pair must appear in some
    `\\separated` clause of the candidate (matched on the roots, so a stronger region is
    accepted), and every skeleton `assigns L \\from S` must be covered by a candidate
    `assigns` clause listing L with a `\\from` superset of S. Strengthening is allowed;
    deleting or weakening a projected clause is an error. A disabled/missing skeleton
    checks nothing (fail-open).
    """
    if not isinstance(skeleton, dict) or skeleton.get("status") not in ("ok", "partial"):
        return []
    errors: list[str] = []
    clauses = extract_frame_clauses(acsl_text)
    for sep in skeleton.get("separated") or []:
        want = {_norm_clause(r) for r in sep.get("roots") or []}
        if not want:
            continue
        covered = False
        for args in clauses["separated"]:
            leading = set()
            for arg in args:
                m = _LEADING_IDENT_RE.match(arg.strip())
                if m:
                    leading.add(_norm_clause(m.group(0)))
            if want <= leading:
                covered = True
                break
        if not covered:
            errors.append(
                f"{path}: projected frame clause missing or weakened: {sep.get('clause')!r} "
                f"(no \\separated clause over roots {sorted(sep.get('roots') or [])})"
            )
    for a in skeleton.get("assigns") or []:
        loc = _norm_clause(a.get("loc") or "")
        want_from = {_norm_clause(f) for f in a.get("from") or []}
        if not loc:
            continue
        covered = False
        for cl in clauses["assigns"]:
            locs = {_norm_clause(x) for x in cl["locs"]}
            if loc not in locs:
                continue
            if loc == "\\nothing":
                covered = True
                break
            have = {_norm_clause(x) for x in cl["from"]}
            if cl["from_nothing"] and not want_from:
                covered = True
                break
            if want_from <= have:
                covered = True
                break
        if not covered:
            errors.append(
                f"{path}: projected frame clause missing or weakened: {a.get('clause')!r} "
                f"(no assigns clause covering location {a.get('loc')!r} with \\from superset of {sorted(a.get('from') or [])})"
            )
    return errors


_CANONICAL_OVERLOADS_CACHE: dict[tuple[str, str, int], set[tuple[str, ...]]] | None = None


def _get_canonical_vocabulary_overloads() -> dict[tuple[str, str, int], set[tuple[str, ...]]]:
    """Return map of (kind, name, arity) -> set of normalized param_types tuples for canonical ACSL overloads."""
    global _CANONICAL_OVERLOADS_CACHE
    if _CANONICAL_OVERLOADS_CACHE is not None:
        return _CANONICAL_OVERLOADS_CACHE

    overloads: dict[tuple[str, str, int], set[tuple[str, ...]]] = {}
    fallback: dict[tuple[str, str, int], set[tuple[str, ...]]] = {
        ("predicate", "valid_read_buffer", 2): {
            ("char *", "integer"),
            ("unsigned char *", "integer"),
        },
        ("predicate", "valid_write_buffer", 2): {
            ("char *", "integer"),
            ("unsigned char *", "integer"),
        },
    }

    vocab_paths = [
        Path("/opt/framac-pipeline/templates/acsl/acsl_vocabulary.h"),
        Path(__file__).resolve().parent.parent / "templates" / "acsl" / "acsl_vocabulary.h",
    ]
    extracted = False
    for vp in vocab_paths:
        if vp.is_file():
            try:
                content = vp.read_text(encoding="utf-8", errors="replace")
                decls = extract_top_level_acsl_declarations(content, path=vp.name)
                grouped: dict[tuple[str, str, int], set[tuple[str, ...]]] = {}
                for d in decls:
                    k = d.get("kind")
                    n = d.get("name")
                    a = d.get("arity")
                    pt = d.get("param_types")
                    if k and n and a is not None and pt is not None:
                        key = (k, n, a)
                        grouped.setdefault(key, set()).add(pt)
                for key, sig_set in grouped.items():
                    if len(sig_set) > 1:
                        overloads[key] = sig_set
                extracted = True
                break
            except Exception:
                pass

    if not extracted or not overloads:
        overloads = fallback
    else:
        for key, sigs in fallback.items():
            overloads.setdefault(key, set()).update(sigs)

    _CANONICAL_OVERLOADS_CACHE = overloads
    return _CANONICAL_OVERLOADS_CACHE


def check_conflicting_acsl_profiles(
    new_decls: list[dict],
    existing_decls: list[dict],
    source_path: str = "<input>",
) -> list[str]:
    """
    Detect conflicting predicate or logic function profiles (e.g. `char*` vs `unsigned char*`).
    Returns a list of diagnostic error strings if conflicts are found.
    """
    conflicts: list[str] = []
    canonical_overloads = _get_canonical_vocabulary_overloads()

    # 1. Compare new declarations against existing declarations
    for new_d in new_decls:
        kind = new_d.get("kind")
        name = new_d.get("name")
        arity = new_d.get("arity")
        param_types = new_d.get("param_types")
        if kind not in ("predicate", "logic", "inductive") or not name or arity is None or param_types is None:
            continue

        matching_existing = [
            d
            for d in existing_decls
            if d.get("name") == name
            and d.get("kind") == kind
            and d.get("arity") == arity
            and d.get("param_types") is not None
        ]
        if matching_existing:
            if not any(d["param_types"] == param_types for d in matching_existing):
                canon_key = (kind, name, arity)
                if canon_key in canonical_overloads:
                    valid_sigs = canonical_overloads[canon_key]
                    if param_types in valid_sigs and all(d["param_types"] in valid_sigs for d in matching_existing):
                        continue

                first = matching_existing[0]
                first_loc = f"{first.get('path', '<existing>')}:{first.get('line', '?')}"
                new_loc = f"{source_path}:{new_d.get('line', '?')}"
                first_prof = first.get("full_profile") or f"{name}/{arity}"
                new_prof = new_d.get("full_profile") or f"{name}/{arity}"
                conflicts.append(
                    f"Conflicting profile for {kind} '{name}': '{new_prof}' at {new_loc} "
                    f"conflicts with existing declaration '{first_prof}' at {first_loc}"
                )

    # 2. Compare declarations within new_decls themselves
    existing_sigs: set[tuple[str, str, int, tuple[str, ...]]] = {
        (d["kind"], d["name"], d["arity"], d["param_types"])
        for d in existing_decls
        if d.get("kind") and d.get("name") and d.get("arity") is not None and d.get("param_types") is not None
    }

    n = len(new_decls)
    for i in range(n):
        d1 = new_decls[i]
        kind1 = d1.get("kind")
        name1 = d1.get("name")
        arity1 = d1.get("arity")
        param_types1 = d1.get("param_types")
        if kind1 not in ("predicate", "logic", "inductive") or not name1 or arity1 is None or param_types1 is None:
            continue
        for j in range(i + 1, n):
            d2 = new_decls[j]
            if (
                d2.get("name") == name1
                and d2.get("kind") == kind1
                and d2.get("arity") == arity1
                and d2.get("param_types") is not None
            ):
                param_types2 = d2["param_types"]
                if param_types2 != param_types1:
                    sig1 = (kind1, name1, arity1, param_types1)
                    sig2 = (kind1, name1, arity1, param_types2)
                    # Do not flag as conflict if both are known overloads in existing_decls:
                    if sig1 in existing_sigs and sig2 in existing_sigs:
                        continue
                    # Do not flag as conflict if both match canonical vocabulary overloads:
                    canon_key = (kind1, name1, arity1)
                    if canon_key in canonical_overloads:
                        valid_sigs = canonical_overloads[canon_key]
                        if param_types1 in valid_sigs and param_types2 in valid_sigs:
                            continue

                    loc1 = f"{source_path}:{d1.get('line', '?')}"
                    loc2 = f"{source_path}:{d2.get('line', '?')}"
                    prof1 = d1.get("full_profile") or f"{name1}/{arity1}"
                    prof2 = d2.get("full_profile") or f"{name1}/{arity1}"
                    conflicts.append(
                        f"Conflicting profile for {kind1} '{name1}': '{prof1}' at {loc1} "
                        f"conflicts with '{prof2}' at {loc2}"
                    )

    return conflicts


# ---------------------------------------------------------------------------
# Trust boundary: preconditions of an untrusted_surface entry function
# ---------------------------------------------------------------------------


class TrustBoundaryError(AcslError):
    """Raised when an untrusted_surface entry contract constrains attacker-controlled values."""


# Built-ins that state memory shape only. Anything inside their argument list is a location, not a value.
_SHAPE_BUILTINS = (
    "valid",
    "valid_read",
    "separated",
    "initialized",
    "freeable",
    "allocable",
    "block_length",
    "offset",
    "base_addr",
    "valid_function",
)
# Predicates of templates/acsl/acsl_vocabulary.h that state shape only (validity of a range, with
# the `len >= 0` / `len == 0` guards that come with it). The others (is_printable_ascii,
# no_crlf_or_nul, buffer_is_zeroed, c_strlen) constrain byte values.
SHAPE_VOCABULARY_PREDICATES = frozenset({"valid_read_buffer", "valid_write_buffer"})
# valid_c_string(s) also says that s holds a NUL: a recorded environment fact only when the harness
# NUL-terminates the input (entry_style c_string / argv, or null_terminate).
_NUL_TERMINATION_PREDICATES = frozenset({"valid_c_string"})
_SHAPE_CALL_RE = re.compile(
    r"\\(?:" + "|".join(_SHAPE_BUILTINS) + r")\b(?:\{[^}]*\})?\s*\(|\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\{[^}]*\})?\s*\("
)
_BINDER_RE = re.compile(r"\\(?:forall|exists|let)\b")
_REQUIRES_RE = re.compile(r"(?<![\\\w])requires\b")
_CLAUSE_LABEL_RE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*:(?!:)")
_NULL_CMP_RE = re.compile(r"^(?:([A-Za-z_][A-Za-z0-9_]*)\s*!=\s*\\null|\\null\s*!=\s*([A-Za-z_][A-Za-z0-9_]*))$")
_NONNEG_RE = re.compile(r"^(?:([A-Za-z_][A-Za-z0-9_]*)\s*>=\s*0|0\s*<=\s*([A-Za-z_][A-Za-z0-9_]*))$")
_CAPACITY_RE = re.compile(r"\\(?:block_length|offset)\b")
_C_PARAM_KEYWORDS = frozenset(
    {
        "const",
        "volatile",
        "restrict",
        "__restrict",
        "__restrict__",
        "unsigned",
        "signed",
        "int",
        "long",
        "short",
        "char",
        "void",
        "float",
        "double",
        "struct",
        "union",
        "enum",
        "register",
        "_Bool",
        "bool",
    }
)


def _acsl_comment_body(text: str) -> str:
    """The inside of an ACSL comment: no `/*@`, `*/`, `//@`, leading `@` margins or `//` comments."""
    if text.startswith("/*@"):
        text = text[3:]
        if text.endswith("*/"):
            text = text[:-2]
    elif text.startswith("//@"):
        text = text[3:]
    text = _COMMENT_IN_ACSL_RE.sub(" ", text)
    return re.sub(r"(^|\n)\s*@", r"\1 ", text)


def _first_top_level_binder(text: str) -> int:
    top = _top_level_positions(text)
    for m in _BINDER_RE.finditer(text):
        if top[m.start()]:
            return m.start()
    return len(text)


def _scan_clause_end(text: str, start: int) -> int:
    """End of the ACSL clause starting at `start`: the first top-level `;` not closing a binder."""
    top = _top_level_positions(text)
    binders = {m.start() for m in _BINDER_RE.finditer(text, start) if top[m.start()]}
    pending = 0
    for i in range(start, len(text)):
        if i in binders:
            pending += 1
        elif top[i] and text[i] == ";":
            if pending:
                pending -= 1
            else:
                return i
    return len(text)


def extract_requires_clauses(contract_text: str) -> list[str]:
    """The predicates of every `requires` clause (function and behavior level) in ACSL contract text."""
    body = " ".join(_acsl_comment_body(contract_text).split())
    out: list[str] = []
    top = _top_level_positions(body)
    for m in _REQUIRES_RE.finditer(body):
        if not top[m.start()]:
            continue
        end = _scan_clause_end(body, m.end())
        pred = body[m.end() : end]
        while (lab := _CLAUSE_LABEL_RE.match(pred)) is not None:
            pred = pred[lab.end() :]
        pred = pred.strip()
        if pred:
            out.append(pred)
    return out


def _split_unbound(text: str, op: str) -> list[str]:
    """`_split_top_level`, but a top-level binder (`\\forall`, `\\exists`, `\\let`) extends to the end."""
    limit = _first_top_level_binder(text)
    parts = _split_top_level(text[:limit], op)
    if limit < len(text):
        parts[-1] = (parts[-1] + " " + text[limit:]).strip()
    return parts


def _strip_shape_calls(text: str, shape_names: frozenset[str]) -> str:
    """`text` with every shape built-in / shape predicate call (name and arguments) removed."""
    out: list[str] = []
    i = 0
    while i < len(text):
        m = _SHAPE_CALL_RE.search(text, i)
        if m is None:
            out.append(text[i:])
            break
        name = m.group(1)
        if name is not None and name not in shape_names:
            out.append(text[i : m.end()])
            i = m.end()
            continue
        out.append(text[i : m.start()])
        _, i = _paren_group_at(text, m.end() - 1)
        out.append(" ")
    return "".join(out).replace("\\null", " ")


def _value_refs(text: str, attackers: frozenset[str], shape_names: frozenset[str]) -> set[str]:
    """Attacker parameters `text` reads as values (outside shape calls, not as `s.field` / `p->field`)."""
    rest = _strip_shape_calls(text, shape_names)
    refs: set[str] = set()
    for m in _IDENT_RE.finditer(rest):
        before = rest[: m.start()].rstrip()
        member = before.endswith(("->", "\\")) or (before.endswith(".") and not before.endswith(".."))
        if m.group(0) in attackers and not member:
            refs.add(m.group(0))
    return refs


def _is_single_shape_call(text: str, shape_names: frozenset[str]) -> bool:
    m = _SHAPE_CALL_RE.match(text)
    if m is None or (m.group(1) is not None and m.group(1) not in shape_names):
        return False
    _, end = _paren_group_at(text, m.end() - 1)
    return end == len(text)


def _constrained_params(pred: str, attackers: frozenset[str], shape_names: frozenset[str]) -> set[str]:
    """Attacker parameters whose value `pred` constrains (empty when it states memory shape only)."""
    text = _strip_outer_parens(" ".join(pred.split()))
    if not text:
        return set()
    binder = _BINDER_RE.match(text)
    if binder is not None:
        if text.startswith("\\let"):
            return _value_refs(text, attackers, shape_names)  # a bound name can carry an attacker value
        end = _scan_clause_end(text, binder.end())
        return _constrained_params(text[end + 1 :], attackers, shape_names)
    for op in ("<==>", "^^"):
        if len(_split_unbound(text, op)) > 1:
            return _value_refs(text, attackers, shape_names)
    parts = _split_unbound(text, "==>")
    if len(parts) > 1:
        # The antecedents only guard: `len > 0 ==> \valid_read(buf + (0 .. len - 1))` states shape.
        return _constrained_params(parts[-1], attackers, shape_names)
    parts = _split_unbound(text, "||")
    if len(parts) > 1:
        per_part = [_constrained_params(p, attackers, shape_names) for p in parts]
        # `len == 0 || \valid_read(...)` states shape: a disjunction constrains only if every disjunct does.
        return set().union(*per_part) if all(per_part) else set()
    parts = _split_unbound(text, "&&")
    if len(parts) > 1:
        return set().union(*(_constrained_params(p, attackers, shape_names) for p in parts))
    if _is_single_shape_call(text, shape_names) or text == "\\true":
        return set()
    m = _NULL_CMP_RE.match(text) or _NONNEG_RE.match(text)
    if m is not None:
        return set()
    if _CAPACITY_RE.search(text) and _RELATION_RE.search(text):
        # `\block_length(buf) >= len`: the capacity of a block, a shape fact.
        return set()
    return _value_refs(text, attackers, shape_names)


def function_trust_records(workspace: Path | str) -> dict:
    """
    The run's function records carrying `trust` (scripts/trust.py, plan step I7): the DAG's
    (`<workspace>/reports/callgraph_dag.json`, keyed by plain name, or `file#name` when the name
    collides), else the Phase 0 model's (keyed `file#name`). Each record has its `name` and `file`, so
    same-named functions keep their own trust. Empty when neither has trust.
    """
    import json

    reports = Path(workspace) / "reports"
    for path in (reports / "callgraph_dag.json", reports / "phase0_model.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        records = data.get("functions") if isinstance(data, dict) else None
        if isinstance(records, dict) and any(isinstance(r, dict) and "trust" in r for r in records.values()):
            return records
    return {}


def is_trust_boundary(records: dict, function: str, file: str | None = None) -> bool | None:
    """
    Whether attacker data reaches `function`'s parameters directly (its trust is `untrusted` with
    `boundary`): then its `requires` may state memory shape only (`entry_requires_violations`).
    With `file`, the record of `function` in that file decides, so a same-named static elsewhere
    keeps its own trust; a file no record names falls back to every same-named record (untrusted
    wins). None when the run has no trust for it.
    """
    from trust import function_trust

    trust = function_trust(records, function, file) if file else None
    if trust is None:
        trust = function_trust(records, function)
    if trust is None:
        return None
    return trust.get("value") == "untrusted" and bool(trust.get("boundary"))


def entry_requires_violations(
    contract_text: str,
    attacker_params: list[str] | set[str] | frozenset[str],
    *,
    nul_terminated: bool = False,
) -> list[str]:
    """
    Trust-boundary check of an untrusted_surface entry function's contract (docs/v2-design.md §6):
    its `requires` may state memory shape only (`\\valid`, `\\valid_read`, `\\separated`,
    `\\initialized`, `p != \\null`, `\\block_length`, shape-only vocabulary predicates) and facts
    that do not involve attacker-controlled parameters. A clause that constrains the value of an
    attacker parameter or of the bytes it points to (`len <= 64`, `buf[0] == 0x30`,
    `\\forall integer i; ... ==> buf[i] != 0`, an unknown predicate over `buf`) is a violation.

    Lexical and conservative: what it cannot classify as shape is flagged. Implication antecedents
    only guard and are not checked; a disjunction violates only if each disjunct does.
    `nul_terminated`: the harness NUL-terminates the input, so `valid_c_string` is shape here.
    """
    attackers = frozenset(p for p in attacker_params if p)
    if not attackers:
        return []
    shape_names = SHAPE_VOCABULARY_PREDICATES | (_NUL_TERMINATION_PREDICATES if nul_terminated else frozenset())
    out: list[str] = []
    for pred in extract_requires_clauses(contract_text):
        params = _constrained_params(pred, attackers, shape_names)
        if params:
            out.append(
                f"requires {pred}; constrains attacker-controlled {', '.join(sorted(params))} "
                "(an untrusted_surface entry may only state memory shape)"
            )
    return out


def function_param_names(source: str, function: str, is_header: bool = False, path: str = "<input>") -> list[str]:
    """Parameter names of `function`'s definition (or prototype, `is_header`); unnamed parameters are skipped."""
    span = locate_function_span(source, function, is_header=is_header, path=path)
    if span is None:
        return []
    toks = [t for t in tokenize_c_acsl(span.text, path=path) if t.kind == "c_token"]
    for k, tok in enumerate(toks):
        if tok.text != function or k + 1 >= len(toks) or toks[k + 1].text != "(":
            continue
        depth = 0
        params: list[list[str]] = [[]]
        for t in toks[k + 1 :]:
            if t.text in "([":
                depth += 1
                if depth == 1 and t.text == "(":
                    continue
            elif t.text in ")]":
                depth -= 1
                if depth == 0:
                    break
            if depth == 1 and t.text == ",":
                params.append([])
                continue
            params[-1].append(t.text)
        names: list[str] = []
        for p in params:
            if not p or p in (["void"], ["..."]):
                continue
            ptr = [i for i in range(len(p) - 2) if p[i] == "(" and p[i + 1] == "*" and _IDENT_RE.fullmatch(p[i + 2])]
            if ptr:
                names.append(p[ptr[0] + 2])
                continue
            while p and p[-1] == "]" and "[" in p:
                p = p[: len(p) - 1 - p[::-1].index("[")]
            if len(p) >= 2 and _IDENT_RE.fullmatch(p[-1]) and p[-1] not in _C_PARAM_KEYWORDS:
                names.append(p[-1])
        return names
    return []


def function_contract_text(source: str, function: str, is_header: bool = False, path: str = "<input>") -> str:
    """The ACSL contract in front of `function`'s definition (or prototype), without body annotations."""
    span = locate_function_span(source, function, is_header=is_header, path=path)
    if span is None:
        return ""
    parts: list[str] = []
    for t in tokenize_c_acsl(span.text, path=path):
        if t.kind == "c_token" and t.text == "{":
            break
        if t.kind in ("acsl_block", "acsl_line"):
            parts.append(t.text)
    return "\n".join(parts)
