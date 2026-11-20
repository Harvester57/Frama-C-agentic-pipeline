#!/usr/bin/env python3
"""
Specification-quality measurement by mutation testing (COINS 2608.13077v1 /
KBSpec's C@All, 2606.21339v2), complementing WP pass/fail:

- completeness (C@All-style): mutate the ACSL *contract* of a proved function
  (drop an ensures clause, flip <= to <, replace an ensures with \\true). If WP
  still proves the mutant contract against the unchanged code, the mutant is
  equivalent and the original spec is incomplete. completeness = 1 - equivalent/total.
- precision (REJECT-style): mutate the *implementation* (flip < to <= in a guard,
  change a return constant). If WP then leaves a non-RTE goal (ensures, behavior,
  assert, assigns) unproven, the spec rejects the wrong code.
  precision = rejected/total.
- trivial stub (Shirobokov et al., Appendix I.1): replace the body with one that
  does nothing (`{ }` for void, `{ return 0; }` for scalar and pointer returns),
  plus up to 2 `{ return <param>; }` stubs for parameters whose normalized C type
  matches the return type (also valid for by-value struct/union returns; skips
  stubs token-identical to the original body before applying the cap). A contract
  that still proves against any applicable trivial stub constrains too little of
  the result (`trivial_body_rejected` is True iff every applicable stub is
  rejected, False if any survives, None when none are applicable). Trivial stubs
  are prepended to the implementation mutants (outside max_mutants);
  FRAMAC_MUTATION_STUB=off disables all of them for A/B runs.

Rejection criterion. The original function is all_proven with the same solver
budget, so a mutant goal the solvers can no longer prove is evidence that the
spec distinguishes the mutant: Invalid (a counter-model was found) and Unknown
(none was found; a false postcondition usually ends there) both count as
rejected. A timeout at equal budget is possible but rare; the per-mutant
`verdict` (`invalid` / `unknown`) keeps the two cases apart for anyone auditing
the number. A mutant whose WP run yields no goal results (analysis_error,
acsl_syntax_error, wp_aborted, a runner exception) is `not_applicable` and is
left out of the denominator instead of counting as accepted. Its detail carries a
`failure`: `preprocessing_failed` when the C preprocessor stopped the run (a
missing header, wrong include flags: the setup is at fault, not the mutant; run_wp
reports it as analysis_error with a `preprocessing_failed` reason, older reports as
acsl_syntax_error), else the WP status. A function whose every
mutant failed to preprocess gets an `error` instead of a score.

Runs only on functions whose WP report (workspace/reports/wp/<fn>.json or
workspace/reports/wp/work/<slug>_<fn>.json) is all_proven, judges every mutant
under the WP model and checks that proof used
(workspace_overlay.infer_prover_wp_flags, recorded per function as `wp_flags` /
`wp_options`), writes workspace/reports/mutation.json, and generate_report.py
renders it as a "Specification quality" section. Purely evaluative: it never
touches workspace/work/ (mutants are written to a temp dir).

CLI: mutation-check --run-dir D [--max-functions N] [--max-mutants M]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_wp_function  # noqa: E402
from acsl_ast import (  # noqa: E402
    AcslError,
    DeclSpan,
    Span,
    _find_body_brace_offset,
    declaration_contract_text,
    iter_clauses,
    locate_function_span,
    tokenize_c_acsl,
)
from fingerprint import normalize_file  # noqa: E402
from framac_common import (  # noqa: E402
    _CPP_ERROR_RE,
    ArtifactError,
    atomic_write_json,
    load_json_optional,
    utc_now,
)

MUTATION_SCHEMA = 1
DEFAULT_MAX_FUNCTIONS = 20
DEFAULT_MAX_MUTANTS = 6
DEFAULT_MAX_PARAM_STUBS = 2

_REL_OP_FLIP = [("<=", "<"), (">=", ">"), ("<", "<="), (">", ">=")]
_C_PUNCT = frozenset("-+*/%&|^!~<>=?:")
# Longest first, so `->`, `<<=` and `<=` are never read as `>` or `<`.
_C_OPERATOR_RE = re.compile(r"->|<<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\||\+\+|--|[-+*/%&|^]=|[-+*/%&|^!~<>=?:]")
_ACSL_REL_FLIP_RE = re.compile(r"<==>|==>|<=|>=")
_DEC_INT_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
# WP report statuses that carry goal results; any other status is a failed run.
_ANALYSED_STATUSES = ("all_proven", "unproven_goals_remain")
_DECL_DROP = frozenset({"static", "inline", "__inline", "__inline__", "extern", "_Noreturn", "__extension__"})
_TYPE_STRIP = _DECL_DROP | frozenset(
    {
        "const",
        "__const",
        "__const__",
        "volatile",
        "__volatile",
        "__volatile__",
        "restrict",
        "__restrict",
        "__restrict__",
        "_Atomic",
        "register",
        "auto",
        "_Thread_local",
        "__thread",
    }
)
_INT_SPECIFIERS = frozenset({"signed", "__signed", "__signed__", "unsigned", "char", "short", "int", "long"})
_FLOAT_SPECIFIERS = frozenset({"float", "double", "long", "_Complex", "__complex__"})
_C_DECL_KEYWORDS = _TYPE_STRIP | frozenset(
    {
        "void",
        "char",
        "short",
        "int",
        "long",
        "signed",
        "__signed",
        "__signed__",
        "unsigned",
        "float",
        "double",
        "_Bool",
        "bool",
        "_Complex",
        "__complex__",
        "_Imaginary",
        "struct",
        "union",
        "enum",
        "typedef",
        "typeof",
        "__typeof__",
    }
)
_ATTRIBUTE_KEYWORDS = frozenset({"__attribute__", "__attribute", "__declspec", "__asm__", "__asm", "asm"})
_OPEN_TO_CLOSE = {"(": ")", "[": "]", "{": "}"}
_CLOSE_DELIMS = frozenset(")]}")
_PARAM_HEAD_FORBIDDEN = frozenset("()[]{}=;")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")

_NormalizedType = tuple[tuple[str, ...], int]


@dataclass(frozen=True)
class _ParsedDeclarator:
    """Header of a C function definition split into return type and typed parameters."""

    ret_tokens: list[str]
    ret_norm_type: _NormalizedType | None
    params: tuple[tuple[str, _NormalizedType], ...]
    is_kr: bool


def _flip_rel_ops(clause_text: str) -> str:
    """Flip `<=` to `<` and `>=` to `>`, preserving `<==>` and `==>`."""

    def repl(m: re.Match) -> str:
        s = m.group(0)
        if s == "<=":
            return "<"
        if s == ">=":
            return ">"
        return s

    return _ACSL_REL_FLIP_RE.sub(repl, clause_text)


def stub_enabled() -> bool:
    """The trivial-stub mutant runs unless FRAMAC_MUTATION_STUB=off (A/B switch)."""
    return os.environ.get("FRAMAC_MUTATION_STUB", "on").strip().lower() != "off"


def _acsl_text_of_span(span: Span | DeclSpan) -> str:
    """The ACSL contract in front of a function declaration span, without body annotations."""
    if isinstance(span, DeclSpan):
        decl = span
    else:
        kind = "prototype" if span.text.rstrip().endswith(";") else "definition"
        decl = DeclSpan(kind=kind, span=span)
    try:
        return declaration_contract_text(decl, path=decl.span.function)
    except AcslError:
        return ""


def spec_mutants(contract_acsl: str, max_mutants: int) -> list[tuple[str, str]]:
    """Contract mutants: drop each ensures clause, flip <=/>= in ensures, \\true-ify one."""
    out: list[tuple[str, str]] = []
    ensures = [
        (span, contract_acsl[span[0] : span[1]])
        for kind, _label, _pred, span in iter_clauses(contract_acsl)
        if kind == "ensures"
    ]
    for i, (span, _clause) in enumerate(ensures[:max_mutants]):
        out.append((f"drop-ensures-{i}", contract_acsl[: span[0]] + contract_acsl[span[1] :]))
    for i, (span, clause) in enumerate(ensures[: max_mutants - len(out)]):
        flipped = _flip_rel_ops(clause)
        if flipped != clause:
            out.append((f"weaken-ensures-{i}", contract_acsl[: span[0]] + flipped + contract_acsl[span[1] :]))
    if ensures and len(out) < max_mutants:
        first_span, _ = ensures[0]
        out.append(
            ("ensures-true", contract_acsl[: first_span[0]] + r"ensures \true;" + contract_acsl[first_span[1] :])
        )
    return out[:max_mutants]


def _c_operators(body_text: str) -> list[tuple[int, int, str]]:
    """
    C operators of the code (not comments, strings or ACSL), as (start, end, text), by maximal munch.

    tokenize_c_acsl emits one token per punctuation character, so adjacent characters are regrouped here: without
    that, `>` matches inside `->` and `>>`, and `<` inside `<=`.
    """
    out: list[tuple[int, int, str]] = []
    run_start = run_end = -1

    def flush() -> None:
        if run_start < 0:
            return
        for m in _C_OPERATOR_RE.finditer(body_text, run_start, run_end):
            out.append((m.start(), m.end(), m.group(0)))

    for tok in tokenize_c_acsl(body_text):
        if tok.kind == "c_token" and len(tok.text) == 1 and tok.text in _C_PUNCT:
            if tok.start != run_end:
                flush()
                run_start = tok.start
            run_end = tok.end
        else:
            flush()
            run_start = run_end = -1
    flush()
    return out


def _c_return_constants(body_text: str) -> list[tuple[int, int, int]]:
    """Find return constant statements `return [-]N;` in code tokens as (start, end, val)."""
    out: list[tuple[int, int, int]] = []
    try:
        tokens = tokenize_c_acsl(body_text)
    except Exception:
        return out
    code_toks = [t for t in tokens if t.kind not in ("whitespace", "c_comment", "acsl_block", "acsl_line")]
    i = 0
    while i < len(code_toks):
        tok = code_toks[i]
        if tok.kind == "c_token" and tok.text == "return":
            start = tok.start
            i += 1
            sign = 1
            if i < len(code_toks) and code_toks[i].kind == "c_token" and code_toks[i].text == "-":
                sign = -1
                i += 1
            if i < len(code_toks) and code_toks[i].kind == "c_token" and _DEC_INT_RE.match(code_toks[i].text):
                val = sign * int(code_toks[i].text)
                i += 1
                if i < len(code_toks) and code_toks[i].kind == "c_token" and code_toks[i].text == ";":
                    end = code_toks[i].end
                    out.append((start, end, val))
                    i += 1
                    continue
        else:
            i += 1
    return out


def impl_mutants(body_text: str, max_mutants: int) -> list[tuple[str, str]]:
    """Implementation mutants: flip relational operators, change return constants."""
    out: list[tuple[str, str]] = []
    ops = _c_operators(body_text)
    for op, flipped in _REL_OP_FLIP:
        hit = next(((s, e) for s, e, text in ops if text == op), None)
        if hit is not None:
            out.append((f"flip-{op}", body_text[: hit[0]] + flipped + body_text[hit[1] :]))
        if len(out) >= max_mutants:
            break
    for start, end, val in _c_return_constants(body_text):
        if len(out) >= max_mutants:
            break
        out.append((f"return-{val}-to-{val + 1}", body_text[:start] + f"return {val + 1};" + body_text[end:]))
    return out[:max_mutants]


def _strip_attributes(toks: list[str]) -> list[str] | None:
    """Drop `__attribute__((...))`-style groups; None when a group is unbalanced."""
    out: list[str] = []
    i = 0
    while i < len(toks):
        if toks[i] not in _ATTRIBUTE_KEYWORDS:
            out.append(toks[i])
            i += 1
            continue
        i += 1
        if i < len(toks) and toks[i] in ("volatile", "__volatile__"):
            i += 1
        if i >= len(toks) or toks[i] != "(":
            continue
        depth = 0
        while i < len(toks):
            if toks[i] == "(":
                depth += 1
            elif toks[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if depth != 0:
            return None
        i += 1
    return out


def _normalize_type(tokens: Sequence[str], *, extra_ptr_depth: int = 0) -> _NormalizedType | None:
    """
    Canonicalize a C type specifier + pointer stars to `(canonical_base_tokens, ptr_depth)`,
    or None when the token sequence is not a supported concrete C type.

    Qualifiers (`const`, `volatile`, `restrict`, `_Atomic`) and storage/function specifiers
    are stripped (Frama-C 34 accepts returning `const T *` from `T *`, so `strchr`-style
    functions still get parameter stubs). Integer specifier order and redundant `int`/`signed`
    are canonicalized, while `char`, `signed char`, and `unsigned char` stay distinct.
    """
    kept = [t for t in tokens if t not in _TYPE_STRIP]
    if not kept:
        return None
    first_star = kept.index("*") if "*" in kept else len(kept)
    base = kept[:first_star]
    stars = kept[first_star:]
    if not base or any(t != "*" for t in stars):
        return None
    if not all(_IDENT_RE.fullmatch(t) for t in base):
        return None
    ptr_depth = len(stars) + extra_ptr_depth

    if "void" in base:
        return (("void",), ptr_depth) if base == ["void"] else None

    if base[0] in ("struct", "union", "enum"):
        if len(base) == 2 and base[1] not in _C_DECL_KEYWORDS:
            return ((base[0], base[1]), ptr_depth)
        return None
    if any(t in ("struct", "union", "enum") for t in base):
        return None

    if base in (["_Bool"], ["bool"]):
        return (("_Bool",), ptr_depth)

    if any(t in ("float", "double", "_Complex", "__complex__") for t in base):
        if not all(t in _FLOAT_SPECIFIERS for t in base):
            return None
        norm_f = ["_Complex" if t == "__complex__" else t for t in base]
        n_complex = norm_f.count("_Complex")
        n_float = norm_f.count("float")
        n_double = norm_f.count("double")
        n_long = norm_f.count("long")
        if n_complex > 1:
            return None
        if (n_float, n_double, n_long) == (1, 0, 0):
            canon: tuple[str, ...] = ("float",)
        elif (n_float, n_double, n_long) == (0, 1, 0):
            canon = ("double",)
        elif (n_float, n_double, n_long) == (0, 1, 1):
            canon = ("long", "double")
        else:
            return None
        if n_complex == 1:
            canon = (*canon, "_Complex")
        return (canon, ptr_depth)

    if all(t in _INT_SPECIFIERS for t in base):
        norm_i = ["signed" if t in ("__signed", "__signed__") else t for t in base]
        n_signed = norm_i.count("signed")
        n_unsigned = norm_i.count("unsigned")
        n_char = norm_i.count("char")
        n_short = norm_i.count("short")
        n_int = norm_i.count("int")
        n_long = norm_i.count("long")
        if n_signed + n_unsigned > 1 or n_char > 1 or n_short > 1 or n_int > 1 or n_long > 2:
            return None
        if n_char and (n_short or n_int or n_long):
            return None
        if n_short and n_long:
            return None
        if n_char:
            if n_signed:
                return (("signed", "char"), ptr_depth)
            if n_unsigned:
                return (("unsigned", "char"), ptr_depth)
            return (("char",), ptr_depth)
        if n_short:
            return (("unsigned", "short"), ptr_depth) if n_unsigned else (("short",), ptr_depth)
        if n_long == 2:
            return (("unsigned", "long", "long"), ptr_depth) if n_unsigned else (("long", "long"), ptr_depth)
        if n_long == 1:
            return (("unsigned", "long"), ptr_depth) if n_unsigned else (("long",), ptr_depth)
        return (("unsigned", "int"), ptr_depth) if n_unsigned else (("int",), ptr_depth)

    if len(base) == 1 and base[0] not in _C_DECL_KEYWORDS:
        return ((base[0],), ptr_depth)
    return None


def _parse_params(param_toks: Sequence[str]) -> tuple[tuple[str, _NormalizedType], ...]:
    """
    Parse a prototype parameter token list into `((name, normalized_type), ...)`.
    Skips unnamed parameters, variadics (`...`), function-pointer and pointer-to-array
    parameters, multi-dimensional arrays (>= 2 dims), and inline anonymous structs/unions.
    Decays 1D array parameters (`T a[]`, `T a[N]`) to `T *`.
    """
    if not param_toks or list(param_toks) == ["void"]:
        return ()
    parts: list[list[str]] = []
    cur: list[str] = []
    stack: list[str] = []
    for tok in param_toks:
        if tok in _OPEN_TO_CLOSE:
            stack.append(_OPEN_TO_CLOSE[tok])
            cur.append(tok)
        elif tok in _CLOSE_DELIMS:
            if not stack or stack[-1] != tok:
                return ()
            stack.pop()
            cur.append(tok)
        elif tok == "," and not stack:
            parts.append(cur)
            cur = []
        else:
            cur.append(tok)
    if stack:
        return ()
    parts.append(cur)

    out: list[tuple[str, _NormalizedType]] = []
    for p in parts:
        if not p or p == [".", ".", "."] or "..." in p:
            continue
        array_dims = 0
        end = len(p)
        unbalanced = False
        while end > 0 and p[end - 1] == "]":
            depth = 0
            idx = end - 1
            while idx >= 0:
                if p[idx] == "]":
                    depth += 1
                elif p[idx] == "[":
                    depth -= 1
                    if depth == 0:
                        break
                idx -= 1
            if depth != 0:
                unbalanced = True
                break
            array_dims += 1
            end = idx
        if unbalanced or array_dims > 1:
            continue
        head = p[:end]
        if any(t in _PARAM_HEAD_FORBIDDEN for t in head):
            continue
        if len(head) < 2 or not _IDENT_RE.fullmatch(head[-1]) or head[-1] in _C_DECL_KEYWORDS:
            continue
        name = head[-1]
        norm = _normalize_type(head[:-1], extra_ptr_depth=array_dims)
        if norm is None:
            continue
        out.append((name, norm))
    return tuple(out)


def _parse_declarator(span_text: str, brace_offset: int | None) -> _ParsedDeclarator | None:
    """Parse a C function definition header before `{`, returning None if unparseable or nested."""
    if brace_offset is None or brace_offset <= 0:
        return None
    try:
        tokens = tokenize_c_acsl(span_text[:brace_offset], path="<declarator>")
    except Exception:
        return None
    toks = _strip_attributes([t.text for t in tokens if t.kind == "c_token"])
    if not toks or "(" not in toks:
        return None
    paren = toks.index("(")
    if paren == 0 or not _IDENT_RE.fullmatch(toks[paren - 1]) or toks[paren - 1] in _C_DECL_KEYWORDS:
        return None
    depth = 0
    close_paren: int | None = None
    for idx in range(paren, len(toks)):
        if toks[idx] == "(":
            depth += 1
        elif toks[idx] == ")":
            depth -= 1
            if depth == 0:
                close_paren = idx
                break
    if close_paren is None:
        return None
    trailing = toks[close_paren + 1 :]
    if trailing and trailing[0] in ("(", "["):
        return None
    ret_tokens = [t for t in toks[: paren - 1] if t not in _DECL_DROP]
    if not ret_tokens:
        return None
    is_kr = ";" in trailing
    ret_norm_type = _normalize_type(ret_tokens)
    params = () if is_kr else _parse_params(toks[paren + 1 : close_paren])
    return _ParsedDeclarator(
        ret_tokens=ret_tokens,
        ret_norm_type=ret_norm_type,
        params=params,
        is_kr=is_kr,
    )


def _body_is_return_param(body_text: str, param_name: str) -> bool:
    """Whether `body_text` is `{ return <param_name>; }` (ignoring comments, ACSL, and outer parens)."""
    try:
        tokens = tokenize_c_acsl(body_text, path="<body>")
    except Exception:
        return False
    code_toks = [t for t in tokens if t.kind not in ("whitespace", "c_comment", "acsl_block", "acsl_line")]
    if len(code_toks) < 5 or any(t.kind != "c_token" for t in code_toks):
        return False
    texts = [t.text for t in code_toks]
    if texts[:2] != ["{", "return"] or texts[-2:] != [";", "}"]:
        return False
    expr = texts[2:-2]
    while len(expr) >= 3 and expr[0] == "(" and expr[-1] == ")":
        expr = expr[1:-1]
    return expr == [param_name]


def _base_stub_from_decl(decl: _ParsedDeclarator | None) -> tuple[str, str] | None:
    if decl is None or not decl.ret_tokens:
        return None
    ret = decl.ret_tokens
    pointer = "*" in ret
    if not pointer and ("struct" in ret or "union" in ret):
        return None
    if not pointer and "void" in ret:
        return ("trivial-noop-body", "{ }")
    return ("trivial-zero-body", "{ return 0; }")


def _param_stubs_from_decl(
    decl: _ParsedDeclarator | None,
    *,
    body_text: str | None = None,
    max_stubs: int = DEFAULT_MAX_PARAM_STUBS,
) -> list[tuple[str, str]]:
    if max_stubs <= 0 or decl is None or decl.ret_norm_type is None or decl.is_kr:
        return []
    if decl.ret_norm_type == (("void",), 0):
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, param_type in decl.params:
        if name in seen or param_type != decl.ret_norm_type:
            continue
        if body_text is not None and _body_is_return_param(body_text, name):
            continue
        seen.add(name)
        out.append((f"trivial-param-{name}-body", f"{{ return {name}; }}"))
        if len(out) >= max_stubs:
            break
    return out


def trivial_stub_mutant(span_text: str, brace_offset: int | None) -> tuple[str, str] | None:
    """
    The body that does nothing for this function: ("trivial-noop-body", "{ }") for
    a `void` return, ("trivial-zero-body", "{ return 0; }") for integer, floating,
    enum, _Bool and pointer returns. None for a by-value struct/union return (a
    scalar `return 0;` does not compile) and for a declarator that cannot be
    parsed. A typedef'd struct return is not recognisable from the declarator; its
    stub fails to compile and the WP run is recorded as not_applicable.
    """
    return _base_stub_from_decl(_parse_declarator(span_text, brace_offset))


def param_stub_mutants(
    span_text: str,
    brace_offset: int | None,
    *,
    body_text: str | None = None,
    max_stubs: int = DEFAULT_MAX_PARAM_STUBS,
) -> list[tuple[str, str]]:
    """
    Up to `max_stubs` `{ return <param>; }` stub mutants for parameters whose normalized
    C type matches the normalized return type, in left-to-right declaration order.
    Skips parameter stubs token-identical to `body_text` (defaulting to
    `span_text[brace_offset:]` when `body_text` is None) before applying the cap.
    """
    decl = _parse_declarator(span_text, brace_offset)
    effective_body = body_text
    if effective_body is None and brace_offset is not None and brace_offset < len(span_text):
        effective_body = span_text[brace_offset:]
    return _param_stubs_from_decl(decl, body_text=effective_body, max_stubs=max_stubs)


def trivial_stub_mutants(
    span_text: str,
    brace_offset: int | None,
    *,
    body_text: str | None = None,
    max_param_stubs: int = DEFAULT_MAX_PARAM_STUBS,
) -> list[tuple[str, str]]:
    """
    All trivial-body stubs for this function: the base zero/noop stub (when applicable)
    followed by up to `max_param_stubs` `{ return <param>; }` parameter stubs.
    """
    decl = _parse_declarator(span_text, brace_offset)
    base = _base_stub_from_decl(decl)
    effective_body = body_text
    if effective_body is None and brace_offset is not None and brace_offset < len(span_text):
        effective_body = span_text[brace_offset:]
    params = _param_stubs_from_decl(decl, body_text=effective_body, max_stubs=max_param_stubs)
    return ([base] if base is not None else []) + params


def _is_rejection(report: dict) -> tuple[bool, str]:
    """
    Does the spec reject the mutant? Returns (rejected, verdict), verdict one of
    `invalid` (a non-RTE goal came back Invalid), `unknown` (a non-RTE goal is
    otherwise unproven: Unknown, Timeout, Never tried), `proved` (all_proven),
    `rte_only` (only RTE guards are unproven: the contract itself accepts the
    mutant) or `not_applicable` (the WP run yielded no goal results).
    """
    status = report.get("status")
    if status not in _ANALYSED_STATUSES:
        return False, "not_applicable"
    if status == "all_proven":
        return False, "proved"
    verdict = ""
    for g in report.get("unproven_goals") or []:
        goal_status = str(g.get("status") or "").lower()
        kind = str(g.get("kind") or "")
        if not kind or kind.startswith("rte"):
            continue
        if "invalid" in goal_status:
            return True, "invalid"
        verdict = "unknown"
    if verdict:
        return True, verdict
    return False, "rte_only"


_PREPROCESS_HINT_RE = re.compile(r"failed to run: .*-E\b|preprocess", re.IGNORECASE)


def _failure_kind(report: dict) -> str:
    """Why a mutant's WP run yielded no goal results: `preprocessing_failed`, or its status."""
    status = str(report.get("status") or "error")
    if status == "analysis_error" and str(report.get("reason") or "").startswith("preprocessing_failed"):
        return "preprocessing_failed"
    if status == "acsl_syntax_error":  # reports written before run_wp_function.py named the case
        errors = (report.get("syntax_check") or {}).get("errors") or []
        if any(_CPP_ERROR_RE.match(str(e)) or _PREPROCESS_HINT_RE.search(str(e)) for e in errors):
            return "preprocessing_failed"
    return status


def _is_equivalent(report: dict) -> bool:
    """The mutant contract still proves against the unchanged code."""
    return report.get("status") == "all_proven"


def _default_runner(wp_options: dict[str, Any] | None = None):
    """
    run_wp_on_function with the proof's model and checks (`wp_options`, from wp_options_from_flags). No
    counter-examples: nothing here reads the models, and each failing mutant would pay a second WP pass.
    """
    options = dict(wp_options or {})

    def runner(c_file: Path, fn: str, out_dir: Path, cppflags: str = "-I.") -> dict:
        return run_wp_function.run_wp_on_function(c_file, fn, out_dir, cppflags=cppflags, **options)

    return runner


# run_wp_function.py CLI flags (as workspace_overlay.infer_prover_wp_flags replays them for the parent check
# and the sweep) -> run_wp_on_function keyword arguments.
_SWITCH_OPTIONS = {
    "--no-warn-unsigned": ("unsigned_reduced", True),
    "--no-warn-unsigned-downcast": ("warn_unsigned_downcast", False),
    "--no-warn-invalid-pointer": ("warn_invalid_pointer", False),
    "--waive-signed-downcast": ("warn_signed_downcast", False),
}


def wp_options_from_flags(flags: list[str]) -> tuple[dict[str, Any], list[str]]:
    """
    (run_wp_on_function options, flags not replayed) for the proof's run_wp_function.py flags. The declared
    wrap lines (`--wrap-code-lines`) are not replayed: they only feed the separate check run, and a mutant is
    judged by the proof run's configuration (the unsigned checks off for the whole function).
    """
    options: dict[str, Any] = {}
    ignored: list[str] = []
    i = 0
    while i < len(flags):
        flag = flags[i]
        if flag in _SWITCH_OPTIONS:
            key, value = _SWITCH_OPTIONS[flag]
            options[key] = value
        elif flag == "--wp-model" and i + 1 < len(flags):
            options["wp_model"] = flags[i + 1]
            i += 1
        elif flag.startswith("--wp-model="):
            options["wp_model"] = flag.split("=", 1)[1]
        else:
            ignored.append(flag)
        i += 1
    return options, ignored


def _proof_wp_flags(run_dir: Path, rel: str, fn: str) -> list[str]:
    """The flags the parent check and the sweep prove `fn` with (workspace_overlay.infer_prover_wp_flags)."""
    import workspace_overlay

    return workspace_overlay.infer_prover_wp_flags(run_dir, c_file=rel, function=fn)


def check_function(
    c_file: Path,
    fn: str,
    cppflags: str,
    out_dir: Path,
    wp_runner=None,
    max_mutants: int = DEFAULT_MAX_MUTANTS,
) -> dict:
    """
    Mutate the contract and the body of `fn` in `c_file`, run WP per mutant, and
    return {function, file, spec_mutants, spec_not_applicable, equivalent,
    impl_mutants, impl_not_applicable, rejected, completeness, precision,
    trivial_body_rejected (only with the stub on), details}. When the stub switch
    is on, prepends the base zero/noop stub (when applicable) and up to
    DEFAULT_MAX_PARAM_STUBS `{ return <param>; }` stubs outside `max_mutants`;
    `trivial_body_rejected` is True iff every applicable trivial stub is rejected,
    False if any applicable trivial stub survives, and None when no trivial stub
    is applicable. Mutants whose WP run yields no goal results are counted in the
    *_not_applicable fields and left out of the denominators. `wp_runner` defaults
    to run_wp_function.run_wp_on_function with default options (run_mutation_check
    passes one with the proof's model and checks) and is injectable for tests.
    """
    runner = wp_runner or _default_runner()
    text = c_file.read_text(encoding="utf-8", errors="replace")
    span = locate_function_span(text, fn, is_header=False, path=str(c_file))
    if span is None:
        return {"function": fn, "file": str(c_file), "error": "function span not found"}
    contract = _acsl_text_of_span(span)
    brace = _find_body_brace_offset(span.text, path=str(c_file))
    body = span.text[brace:] if brace is not None else span.text
    result: dict[str, Any] = {
        "function": fn,
        "file": str(c_file),
        "spec_mutants": 0,
        "spec_not_applicable": 0,
        "equivalent": 0,
        "impl_mutants": 0,
        "impl_not_applicable": 0,
        "rejected": 0,
        "completeness": None,
        "precision": None,
        "preprocessing_failed": 0,
        "details": [],
    }
    impl = impl_mutants(body, max_mutants)
    stub_names: set[str] = set()
    stub_results: list[bool] = []
    if stub_enabled():
        result["trivial_body_rejected"] = None
        stubs = trivial_stub_mutants(span.text, brace, body_text=body)
        if not stubs:
            result["details"].append(
                {
                    "mutant": "trivial-stub",
                    "kind": "impl",
                    "rejected": False,
                    "verdict": "not_applicable",
                    "status": None,
                    "reason": "no stub body for this return type (struct/union by value, or unparsed declarator)",
                }
            )
        else:
            stub_names = {name for name, _ in stubs}
            impl = [*stubs, *impl]  # trivial stubs do not count against max_mutants
    first_preprocess_error = ""
    with tempfile.TemporaryDirectory(prefix="framac-mutation-") as tmp:
        tmp_path = Path(tmp)
        for kind, mutants in (
            ("spec", spec_mutants(contract, max_mutants)),
            ("impl", impl),
        ):
            for name, mutated in mutants:
                if kind == "spec":
                    # Replace the contract ACSL inside the span, keep the body.
                    new_span = _replace_contract_in_span(span.text, contract, mutated)
                else:
                    # Mutate the C body only; keep the contract in front of it.
                    new_span = span.text[:brace] + mutated if brace is not None else mutated
                mut_file = tmp_path / c_file.name
                mut_file.write_text(text[: span.start_byte] + new_span + text[span.end_byte :], encoding="utf-8")
                try:
                    report: Any = runner(mut_file, fn, tmp_path / f"wp-{kind}-{name}", cppflags=cppflags)
                except Exception as exc:
                    report = {"status": "error", "reason": str(exc)}
                if not isinstance(report, dict):
                    report = {"status": "error", "reason": "runner returned no report"}
                if kind == "spec":
                    if report.get("status") not in _ANALYSED_STATUSES:
                        result["spec_not_applicable"] += 1
                        eq, verdict = False, "not_applicable"
                    else:
                        result["spec_mutants"] += 1
                        eq = _is_equivalent(report)
                        result["equivalent"] += int(eq)
                        verdict = "equivalent" if eq else "distinguished"
                    detail = {
                        "mutant": name,
                        "kind": "spec",
                        "equivalent": eq,
                        "verdict": verdict,
                        "status": report.get("status"),
                    }
                else:
                    rej, verdict = _is_rejection(report)
                    if verdict == "not_applicable":
                        result["impl_not_applicable"] += 1
                    else:
                        result["impl_mutants"] += 1
                        result["rejected"] += int(rej)
                        if name in stub_names:
                            stub_results.append(rej)
                    detail = {
                        "mutant": name,
                        "kind": "impl",
                        "rejected": rej,
                        "verdict": verdict,
                        "status": report.get("status"),
                    }
                if verdict == "not_applicable":
                    detail["failure"] = _failure_kind(report)
                    if detail["failure"] == "preprocessing_failed":
                        result["preprocessing_failed"] += 1
                        first_preprocess_error = first_preprocess_error or next(
                            iter(
                                report.get("preprocess_errors")
                                or (report.get("syntax_check") or {}).get("errors")
                                or []
                            ),
                            "",
                        )
                result["details"].append(detail)
    if stub_enabled():
        result["trivial_body_rejected"] = all(stub_results) if stub_results else None
    if result["spec_mutants"]:
        result["completeness"] = round(1 - result["equivalent"] / result["spec_mutants"], 4)
    if result["impl_mutants"]:
        result["precision"] = round(result["rejected"] / result["impl_mutants"], 4)
    tried = result["preprocessing_failed"] + result["spec_mutants"] + result["impl_mutants"]
    if result["preprocessing_failed"] and result["preprocessing_failed"] == tried:
        # Not a score of zero: the check never ran (missing header, wrong include flags).
        result["error"] = f"preprocessing failed for every mutant: {str(first_preprocess_error)[:300]}"
    return result


def _replace_contract_in_span(span_text: str, old_contract: str, new_contract: str) -> str:
    """Swap the ACSL contract text in front of the declaration, leaving C code and body annotations untouched."""
    brace = _find_body_brace_offset(span_text, path="<span>")
    header, body = (span_text[:brace], span_text[brace:]) if brace is not None else (span_text, "")
    if old_contract and old_contract in header:
        return header.replace(old_contract, new_contract, 1) + body
    # Fallback: replace the contract ACSL block(s)/line(s) before the body `{`.
    tokens = tokenize_c_acsl(header, path="<span>")
    out = []
    replaced = False
    for t in tokens:
        if not replaced and t.kind in ("acsl_block", "acsl_line"):
            out.append(new_contract)
            replaced = True
        elif t.kind in ("acsl_block", "acsl_line"):
            continue
        else:
            out.append(t.text)
    return "".join(out) + body if replaced else span_text


def classify_open_unit(wp_report: dict | None) -> str:
    """COINS evaluation duality: is an open unit prover-limited or spec-limited?"""
    if not isinstance(wp_report, dict):
        return "unknown"
    if wp_report.get("status") == "analysis_error":
        # A setup error (missing header, wrong include flags, a failed wrap check) says nothing about the
        # prover or the contract; generate_report.py lists `unknown` units. Memory and time limits are prover limits.
        reason = str(wp_report.get("reason") or "")
        if reason.startswith(run_wp_function.PREPROCESSING_FAILED) or reason == "unsigned_wrap_check_failed":
            return "unknown"
        return "prover_limited"
    if wp_report.get("wp_allocation_limitation") or wp_report.get("wp_macro_loop_limitation"):
        return "prover_limited"
    frame = wp_report.get("frame_summary") or {}
    if frame.get("missing_assigns_warning"):
        return "spec_limited"
    unproven = wp_report.get("unproven_goals") or []
    if unproven and all("timeout" in str(g.get("status") or "").lower() for g in unproven):
        return "prover_limited"
    return "spec_limited"


_DRIVE_ABS_RE = re.compile(r"^[A-Za-z]:/")


def _is_absolute_raw_path(raw: Any) -> bool:
    text = str(raw or "").replace("\\", "/").strip()
    return text.startswith("/") or bool(_DRIVE_ABS_RE.match(text))


def _normalize_wp_file(raw_file: str | None, run_dir: Path | None = None) -> str:
    """Repository-relative posix path of a WP report's `file`, or '' when absent."""
    raw = str(raw_file or "").strip()
    if not raw:
        return ""
    if run_dir is not None:
        raw_path = Path(raw)
        if raw_path.is_absolute():
            for base in (run_dir / "workspace" / "work", run_dir / "workspace" / "baseline", run_dir):
                try:
                    return normalize_file(raw_path.resolve().relative_to(base.resolve()).as_posix())
                except (OSError, ValueError):
                    continue
    norm = normalize_file(raw)
    return "" if norm == "unknown" and raw.lower() != "unknown" else norm


def _load_json_safe(path: Path) -> Any:
    try:
        return load_json_optional(path, None)
    except (ArtifactError, OSError, ValueError):
        return None


@dataclass(frozen=True)
class DiscoveredWpReport:
    """One deduplicated per-function WP verdict report under `workspace/reports/wp/`."""

    file: str
    function: str
    path: Path
    report: dict[str, Any]
    canonical: bool


def _wp_report_rank(path: Path, canonical: bool, norm_file: str, fn: str) -> tuple[int, int, int, str]:
    try:
        mtime_ns = path.stat().st_mtime_ns
    except OSError:
        mtime_ns = 0
    if canonical:
        exact_name = int(path.name == f"{fn}.json")
    else:
        exact_name = 0
        if norm_file:
            import workspace_overlay

            exact_name = int(path.name == f"{workspace_overlay.wp_work_slug(norm_file)}_{fn}.json")
    return (int(canonical), exact_name, mtime_ns, path.as_posix())


def discover_wp_reports(run_dir: Path) -> list[DiscoveredWpReport]:
    """
    Discover valid per-function WP verdict reports in both `workspace/reports/wp/*.json`
    (canonical top-level reports) and `workspace/reports/wp/work/*.json` (per-file baseline
    reports, including same-named static functions that have no name-only canonical copy).

    Deduplicates by `(normalized_file, function)`, preferring the canonical top-level
    `reports/wp/<fn>.json` over an older `reports/wp/work/<slug>_<fn>.json` for the same
    `(file, function)`. Ignores non-report artifacts (`*.wp-report-json`, guardrail reports,
    subdirectories under `work/`, corrupt JSON, and objects missing `status`/`function`).
    """
    run_dir = Path(run_dir)
    wp_dir = run_dir / "workspace" / "reports" / "wp"
    if not wp_dir.is_dir():
        return []
    sources: list[tuple[Path, bool]] = [(wp_dir, True)]
    work_wp_dir = wp_dir / "work"
    if work_wp_dir.is_dir():
        sources.append((work_wp_dir, False))
    best: dict[tuple[str, str], tuple[tuple[int, int, int, str], DiscoveredWpReport]] = {}
    for directory, canonical in sources:
        for path in sorted(directory.glob("*.json")):
            if not path.is_file():
                continue
            raw = _load_json_safe(path)
            if not isinstance(raw, dict) or raw.get("mode") == "guardrail":
                continue
            status = raw.get("status")
            fn = raw.get("function")
            if not isinstance(status, str) or not status.strip() or not isinstance(fn, str) or not fn.strip():
                continue
            raw_file = raw.get("file")
            if raw_file is not None and not isinstance(raw_file, str):
                continue
            norm_file = _normalize_wp_file(raw_file, run_dir)
            if not canonical and not norm_file:
                continue
            key = (norm_file, fn.strip())
            rank = _wp_report_rank(path, canonical, norm_file, key[1])
            existing = best.get(key)
            if existing is None or rank > existing[0]:
                best[key] = (
                    rank,
                    DiscoveredWpReport(
                        file=norm_file,
                        function=key[1],
                        path=path,
                        report=raw,
                        canonical=canonical,
                    ),
                )
    return sorted((item for _, item in best.values()), key=lambda r: (r.file, r.function))


class WpReportIndex:
    """Lookup over deduplicated WP reports by `(normalized_file, function)`."""

    def __init__(self, reports: Sequence[DiscoveredWpReport], run_dir: Path | None = None) -> None:
        self.reports = list(reports)
        self._run_dir = run_dir
        self._by_key: dict[tuple[str, str], DiscoveredWpReport] = {(r.file, r.function): r for r in self.reports}
        self._by_fn: dict[str, list[DiscoveredWpReport]] = {}
        for r in self.reports:
            self._by_fn.setdefault(r.function, []).append(r)

    def get(self, c_file: str | None, function: str) -> dict[str, Any] | None:
        if not function:
            return None
        want_file = _normalize_wp_file(c_file, self._run_dir)
        if want_file:
            exact = self._by_key.get((want_file, function))
            if exact is not None:
                return exact.report
            suffix_hits = [
                r
                for r in self._by_fn.get(function, ())
                if r.file and _is_absolute_raw_path(r.report.get("file")) and r.file.endswith("/" + want_file)
            ]
            if len(suffix_hits) == 1:
                return suffix_hits[0].report
        legacy = self._by_key.get(("", function))
        if legacy is not None:
            return legacy.report
        if not want_file:
            matches = self._by_fn.get(function, ())
            if len(matches) == 1:
                return matches[0].report
        return None


def _resolve_work_c_file(work: Path, norm_file: str, raw_file: str) -> Path | None:
    if norm_file:
        cand = work / norm_file
        if cand.is_file():
            return cand
    if raw_file:
        raw_path = Path(raw_file)
        if raw_path.is_file():
            return raw_path
        if not raw_path.is_absolute():
            cand = work / raw_path
            if cand.is_file():
                return cand
        # The report's file path may be agent-scratch relative; try workspace/work by name.
        cand = work / raw_path.name
        if cand.is_file():
            return cand
    return None


def _module_cppflags_resolver(run_dir: Path):
    """
    (work-relative file, function) -> (cppflags, source) with the module's WP cppflags, as wp-sweep proves with.

    A hard-coded `-I.` made every mutant of a target with include paths fail to preprocess (libmnl:
    `libmnl/libmnl.h: No such file or directory`), so every function scored `not_applicable`. Without a ledger or a
    build plan (a bare directory, unit tests) the old `-I.` default stays, labelled `default`. A module whose flags
    cannot be resolved returns (None, reason), and the function is skipped rather than checked with wrong flags.
    """
    try:
        import shlex

        import pipeline_make

        ledger = load_json_optional(run_dir / pipeline_make.LEDGER_JSON, [])
        modules: dict[tuple[str, str], str] = {}
        by_fn: dict[str, set[str]] = {}
        for unit in ledger if isinstance(ledger, list) else []:
            if isinstance(unit, dict) and unit.get("module") and unit.get("function"):
                unit_file = _normalize_wp_file(str(unit.get("file") or ""), run_dir)
                modules[(unit_file, str(unit["function"]))] = str(unit["module"])
                by_fn.setdefault(str(unit["function"]), set()).add(str(unit["module"]))
        plan = pipeline_make.build_plan(run_dir) if modules else None
    except Exception as exc:  # no build plan: keep the old default, but say so
        reason = f"default (no build plan: {type(exc).__name__})"
        return lambda _file, _fn: ("-I.", reason)
    if plan is None:
        return lambda _file, _fn: ("-I.", "default (no ledger modules)")

    def resolve(file: str, fn: str) -> tuple[str | None, str]:
        module = modules.get((file, fn))
        if module is None and len(by_fn.get(fn, ())) == 1:
            module = next(iter(by_fn[fn]))
        if module is None:
            return None, f"no ledger module for {file}#{fn}"
        flags, reason = plan.wp_cppflags_for(module)
        if flags is None:
            return None, f"module {module}: {reason}"
        return shlex.join(flags), f"module {module}"

    return resolve


def run_mutation_check(
    run_dir: Path,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_mutants: int = DEFAULT_MAX_MUTANTS,
    wp_runner=None,
    out_path: Path | None = None,
) -> dict:
    """Run the mutation check over all all_proven functions of a run directory."""
    run_dir = Path(run_dir)
    work = run_dir / "workspace" / "work"
    out_path = out_path or run_dir / "workspace" / "reports" / "mutation.json"
    doc: dict[str, Any] = {"schema": MUTATION_SCHEMA, "generated_at": utc_now(), "functions": {}}
    skipped: list[dict] = []
    flags_for = _module_cppflags_resolver(run_dir)
    discovered = discover_wp_reports(run_dir)
    files_by_fn: dict[str, set[str]] = {}
    for item in discovered:
        if item.file:
            files_by_fn.setdefault(item.function, set()).add(item.file)
    ledger_data = _load_json_safe(run_dir / "coverage-ledger.json")
    if isinstance(ledger_data, list):
        for unit in ledger_data:
            if isinstance(unit, dict) and unit.get("function") and unit.get("file"):
                norm_u = _normalize_wp_file(str(unit["file"]), run_dir)
                if norm_u:
                    files_by_fn.setdefault(str(unit["function"]), set()).add(norm_u)
    shared_names = {fn for fn, files in files_by_fn.items() if len(files) > 1}
    proven = [item for item in discovered if item.report.get("status") == "all_proven"]
    for item in proven[:max_functions]:
        fn = item.function
        c_file = _resolve_work_c_file(work, item.file, str(item.report.get("file") or ""))
        if c_file is None:
            continue
        try:
            rel = c_file.resolve().relative_to(work.resolve()).as_posix()
        except ValueError:
            rel = item.file or c_file.name
        cppflags, source = flags_for(rel, fn)
        if cppflags is None:
            skipped.append({"function": fn, "file": rel, "reason": source})
            continue
        # The mutants are judged under the model and checks the original contract was proved with (a
        # proof under Bytes or with the unsigned checks off does not hold under the defaults).
        wp_flags = _proof_wp_flags(run_dir, rel, fn)
        wp_options, _ = wp_options_from_flags(wp_flags)
        result = check_function(
            c_file,
            fn,
            cppflags,
            run_dir / "workspace" / "reports" / "mutation-wp",
            wp_runner=wp_runner or _default_runner(wp_options),
            max_mutants=max_mutants,
        )
        result["cppflags_source"] = source
        result["wp_flags"] = wp_flags
        result["wp_options"] = wp_options
        entry_key = f"{rel}#{fn}" if fn in shared_names or fn in doc["functions"] else fn
        doc["functions"][entry_key] = result
    if skipped:
        doc["skipped"] = skipped
    totals: dict[str, Any] = {
        "functions": len(doc["functions"]),
        "spec_mutants": sum(f.get("spec_mutants", 0) for f in doc["functions"].values()),
        "equivalent": sum(f.get("equivalent", 0) for f in doc["functions"].values()),
        "impl_mutants": sum(f.get("impl_mutants", 0) for f in doc["functions"].values()),
        "rejected": sum(f.get("rejected", 0) for f in doc["functions"].values()),
        "spec_not_applicable": sum(f.get("spec_not_applicable", 0) for f in doc["functions"].values()),
        "impl_not_applicable": sum(f.get("impl_not_applicable", 0) for f in doc["functions"].values()),
        "preprocessing_failed": sum(f.get("preprocessing_failed", 0) for f in doc["functions"].values()),
    }
    if stub_enabled():
        checked = [fn for fn, f in doc["functions"].items() if f.get("trivial_body_rejected") is not None]
        accepted = sorted(fn for fn in checked if doc["functions"][fn]["trivial_body_rejected"] is False)
        totals["trivial_body_checked"] = len(checked)
        totals["trivial_body_accepted"] = len(accepted)
        totals["trivial_body_accepted_functions"] = accepted
    comps = [f["completeness"] for f in doc["functions"].values() if f.get("completeness") is not None]
    precs = [f["precision"] for f in doc["functions"].values() if f.get("precision") is not None]
    totals["completeness"] = round(sum(comps) / len(comps), 4) if comps else None
    totals["precision"] = round(sum(precs) / len(precs), 4) if precs else None
    doc["totals"] = totals
    atomic_write_json(out_path, doc)
    return doc


def summarize_mutation(path: Path) -> dict:
    """The benchmark-facing summary of a mutation.json report."""
    doc = load_json_optional(path, {})
    return doc.get("totals") or {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mutation-based specification quality check.")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--max-functions", type=int, default=DEFAULT_MAX_FUNCTIONS)
    parser.add_argument("--max-mutants", type=int, default=DEFAULT_MAX_MUTANTS)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    doc = run_mutation_check(args.run_dir, args.max_functions, args.max_mutants, out_path=args.out)
    print(json.dumps(doc.get("totals") or {}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
