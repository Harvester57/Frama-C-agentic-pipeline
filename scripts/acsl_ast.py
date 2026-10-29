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
                raise AcslSyntaxError(f"{path}:{start_line}: unclosed {'string' if quote == '\"' else 'character'} literal")
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

    limit = min(len(base_c), len(work_c))
    for idx in range(limit):
        bt = base_c[idx]
        wt = work_c[idx]
        if bt.kind != wt.kind or bt.text != wt.text:
            errors.append(
                f"{path}:{wt.line}: non-ACSL token modified: expected {bt.text!r} "
                f"(baseline line {bt.line}), got {wt.text!r}"
            )
            return errors

    if len(work_c) > len(base_c):
        extra = work_c[limit]
        errors.append(f"{path}:{extra.line}: non-ACSL token added: {extra.text!r}")
    elif len(base_c) > len(work_c):
        missing = base_c[limit]
        errors.append(f"{path}:{missing.line}: non-ACSL token removed: {missing.text!r}")

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
