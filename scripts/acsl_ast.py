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
from dataclasses import dataclass


class AcslError(RuntimeError):
    """Base exception for ACSL lexical, annotation-only, or scope errors."""


class AcslSyntaxError(AcslError):
    """Raised when a C/H file contains an unclosed comment or string/char literal."""


class ScopeViolationError(AcslError):
    """Raised when an agent modifies tokens outside its assigned function or header scope."""


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
_STRING_IN_ACSL_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_COMMENT_IN_ACSL_RE = re.compile(r"//(?![@])[^\n]*")
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
    return errors


def find_unsound_acsl_keywords(tokens: list[Token], path: str = "<input>") -> list[str]:
    """Check all ACSL tokens in `tokens` for unsound or hazardous ACSL constructs."""
    return _check_unsound_acsl(tokens, set(), path)


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


def locate_function_span(source: str, function_name: str, is_header: bool = False, path: str = "<input>") -> Span | None:
    """
    Locate the byte and line span of `function_name` (including any immediately preceding
    ACSL contract block) in a C source file (`is_header=False`) or header file (`is_header=True`).
    """
    tokens = tokenize_c_acsl(source, path=path)
    brace_depth = 0
    paren_depth = 0
    last_top_boundary_idx = -1  # index of last top-level ';', '}', or 'pp_directive'

    idx = 0
    n = len(tokens)
    while idx < n:
        tok = tokens[idx]
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
                if open_paren_idx < n and tokens[open_paren_idx].kind == "c_token" and tokens[open_paren_idx].text == "(":
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
                                        text=source[start_tok.start:end_tok.end],
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
                                    text=source[start_tok.start:end_tok.end],
                                )
        idx += 1

    return None


def _compute_span_start(tokens: list[Token], last_top_boundary_idx: int, fn_name_idx: int) -> int:
    """
    Walk backward from fn_name_idx (stopping after last_top_boundary_idx) to include
    the return type/declarator tokens and any immediately preceding ACSL contract comments,
    while leaving normal C comments above the contract outside the span.
    """
    # Step 1: walk back across the return type / storage class / pointer tokens of this declaration
    start_idx = fn_name_idx
    cursor = fn_name_idx - 1
    while cursor > last_top_boundary_idx:
        t = tokens[cursor]
        if t.kind in ("c_token", "acsl_block", "acsl_line"):
            start_idx = cursor
            cursor -= 1
            continue
        if t.kind == "whitespace":
            cursor -= 1
            continue
        # Stop at a normal C comment (e.g., /* Parse header magic */) before the contract/declarator
        break
    return start_idx


def splice_prover_changes(
    base_work_text: str,
    agent_work_text: str,
    current_work_text: str,
    function_name: str,
    is_header: bool = False,
    path: str = "<input>",
) -> str:
    """
    Validate that the prover only modified ACSL annotations inside `function_name`'s span
    (comparing `agent_work_text` against `base_work_text`), then splice `function_name`'s
    updated span into `current_work_text`.
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
    base_prefix = base_work_text[:base_span.start_byte]
    agent_prefix = agent_work_text[:agent_span.start_byte]
    base_suffix = base_work_text[base_span.end_byte:]
    agent_suffix = agent_work_text[agent_span.end_byte:]

    if base_prefix != agent_prefix or base_suffix != agent_suffix:
        raise ScopeViolationError(
            f"{path}: agent modified content outside assigned function '{function_name}'"
        )

    # Verify that in current_work_text, function_name's span hasn't been concurrently altered
    if curr_span.text != base_span.text:
        raise ScopeViolationError(
            f"{path}: function '{function_name}' in workspace/work/ diverged from agent base snapshot"
        )

    spliced = (
        current_work_text[:curr_span.start_byte]
        + agent_span.text
        + current_work_text[curr_span.end_byte:]
    )
    post_errors = verify_acsl_only(current_work_text, spliced, path=path)
    if post_errors:
        raise AcslError(f"Post-splice ACSL-only check failed on {path}:\n  " + "\n  ".join(post_errors))
    return spliced


# ---------------------------------------------------------------------------
# Comment- & quantifier-aware ACSL top-level declaration parser & deduplicator
# ---------------------------------------------------------------------------

_TOP_DECL_KWS = frozenset({"predicate", "logic", "lemma", "type", "axiomatic", "inductive", "ghost"})
_CONTRACT_KWS = frozenset({
    "requires", "terminates", "decreases", "exits", "assigns", "ensures",
    "behavior", "assumes", "allocates", "frees", "complete", "disjoint",
})
_CHAR_LIT_RE = re.compile(r"'(?:\\.|[^'\\\n]){1,4}'")
_STR_LIT_RE = re.compile(r'"(?:\\.|[^"\\\n])*"')


@dataclass(slots=True, frozen=True)
class _AcslSegment:
    kind: str | None  # top-level declaration keyword, contract keyword, or None for trailing trivia
    name: str | None  # declared identifier name when kind in _TOP_DECL_KWS
    raw_text: str
    line: int
    arity: int | None = None


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
        if current_kw in _TOP_DECL_KWS and kw_end_offset != -1 and kw_end_offset <= end_pos:
            body_slice = inner[kw_end_offset:end_pos]
            decl_name = _extract_decl_name(current_kw, body_slice)
            decl_arity = _extract_decl_arity(current_kw, body_slice, decl_name)
        segments.append(
            _AcslSegment(
                kind=current_kw,
                name=decl_name,
                raw_text=inner[seg_start:end_pos],
                line=seg_line,
                arity=decl_arity,
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
    brace_depth = 0
    paren_depth = 0
    decls: list[dict] = []

    for tok in tokens:
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
                    decls.append({
                        "kind": seg.kind,
                        "name": seg.name,
                        "arity": seg.arity,
                        "profile_key": profile_key,
                        "text": seg.raw_text.strip(),
                        "line": seg.line,
                    })

    return decls


def dedup_acsl_declarations(
    target_text: str,
    existing_names: set[str],
    baseline_text: str | None = None,
    path: str = "<input>",
) -> tuple[str, list[str]]:
    """
    Remove duplicate top-level ACSL declarations (`predicate`, `logic`, `lemma`, `type`,
    `axiomatic`, `inductive`, `ghost`) from `target_text` whose identifier name or
    `name/arity` profile is already in `existing_names` (or duplicated with the same
    profile earlier in `target_text`), while preserving overloaded declarations with
    different parameter arities and any declarations already present in `baseline_text`.
    """
    baseline_profiles: set[str] = set()
    if baseline_text:
        for d in extract_top_level_acsl_declarations(baseline_text, path=path):
            baseline_profiles.add(d["profile_key"])
            baseline_profiles.add(d["name"])

    seen: set[str] = set(existing_names)
    removed: list[str] = []

    tokens = tokenize_c_acsl(target_text, path=path)
    brace_depth = 0
    paren_depth = 0
    out_parts: list[str] = []
    idx = 0
    total = len(tokens)

    while idx < total:
        tok = tokens[idx]
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
                    if profile_key in baseline_profiles:
                        seen.add(profile_key)
                        kept_segments.append(seg)
                    elif seg.name in seen or profile_key in seen:
                        removed.append(seg.name)
                        removed_in_block = True
                    else:
                        seen.add(profile_key)
                        kept_segments.append(seg)
                else:
                    kept_segments.append(seg)

            if not removed_in_block:
                out_parts.append(tok.text)
            else:
                has_active = any(s.kind is not None for s in kept_segments)
                if has_active:
                    rebuilt_inner = "".join(s.raw_text for s in kept_segments)
                    if tok.kind == "acsl_block":
                        out_parts.append(f"/*@{rebuilt_inner}*/")
                    else:
                        out_parts.append(f"//@{rebuilt_inner}")
                else:
                    # Entire ACSL block became empty: also trim a single leading newline on the next whitespace token
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

