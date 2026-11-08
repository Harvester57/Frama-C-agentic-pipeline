#!/usr/bin/env python3
"""
C function definitions and `#define` macros found with the C/ACSL tokenizer (scripts/acsl_ast.py),
without preprocessing or a build. Stdlib only.

What used to be the token "lexer" of build_callgraph_dag.py is gone: Phase 0's inventory, call graph
and per-function facts come from the Frama-C model (scripts/phase0_model.py, step I10). These helpers
remain for tools that look at one source file at a time: the WP runner (macro loops, variadic
definitions), the fuzz harness linker, the function slicer and the benchmark briefs.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acsl_ast import AcslSyntaxError, Token, tokenize_c_acsl  # noqa: E402

C_KEYWORDS = {
    "if",
    "else",
    "for",
    "while",
    "do",
    "switch",
    "case",
    "default",
    "sizeof",
    "Alignof",
    "_Alignof",
    "_Alignas",
    "typeof",
    "__typeof__",
    "return",
    "goto",
    "break",
    "continue",
    "__attribute__",
    "__attribute",
    "__declspec",
    "__builtin_expect",
    "__builtin_choose_expr",
    "__builtin_typescompatible_p",
    "__builtin_offsetof",
    "defined",
    "offsetof",
    "assert",
    "_Static_assert",
    "static_assert",
    "asm",
    "__asm",
    "__asm__",
}

TYPE_MODIFIERS_AND_PRIMITIVES = {
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
    "size_t",
    "ssize_t",
    "ptrdiff_t",
    "intptr_t",
    "uintptr_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "u8",
    "u16",
    "u32",
    "u64",
    "s8",
    "s16",
    "s32",
    "s64",
    "const",
    "volatile",
    "restrict",
    "__restrict",
    "__restrict__",
    "struct",
    "union",
    "enum",
}

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _is_ident(text: str) -> bool:
    return bool(_IDENT_RE.match(text)) and text not in C_KEYWORDS


def _find_matching_forward(tokens: list[Token], open_idx: int, open_tok: str, close_tok: str) -> int:
    depth = 0
    for idx in range(open_idx, len(tokens)):
        t = tokens[idx].text
        if t == open_tok:
            depth += 1
        elif t == close_tok:
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _find_matching_backward(tokens: list[Token], close_idx: int, open_tok: str, close_tok: str) -> int:
    depth = 0
    for idx in range(close_idx, -1, -1):
        t = tokens[idx].text
        if t == close_tok:
            depth += 1
        elif t == open_tok:
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _strip_trailing_attributes(c_tokens: list[Token], end_idx: int, min_idx: int) -> int:
    """
    Walk backward from end_idx (exclusive) skipping trailing `__attribute__((...))`,
    `__declspec(...)`, or `asm(...)` qualifiers between `)` and `{`.
    Returns the index of the token immediately before any such qualifiers.
    """
    cursor = end_idx - 1
    while cursor > min_idx:
        if c_tokens[cursor].text == ")":
            open_p = _find_matching_backward(c_tokens, cursor, "(", ")")
            if open_p > min_idx and c_tokens[open_p - 1].text in {
                "__attribute__",
                "__attribute",
                "__declspec",
                "asm",
                "__asm",
                "__asm__",
            }:
                cursor = open_p - 2
                continue
        break
    return cursor


_DEFINE_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)(\([^)]*\))?(.*)$", re.DOTALL)


def extract_macro_definitions(raw_code: str, path: str = "<input>") -> dict[str, dict]:
    """
    Extract file-scope `#define` macros from `raw_code`, computing each macro's transitive
    callees and embedded non-trivial loop count (`for` and `while` excluding `while (0)`).
    """
    try:
        all_tokens = tokenize_c_acsl(raw_code, path=path)
    except AcslSyntaxError:
        cleaned = re.sub(r"/\*.*?\*/", " ", raw_code, flags=re.DOTALL)
        cleaned = re.sub(r"//[^\n]*", " ", cleaned)
        all_tokens = tokenize_c_acsl(cleaned, path=path)

    raw_macros: dict[str, dict] = {}
    for tok in all_tokens:
        if tok.kind != "pp_directive":
            continue
        unfolded = re.sub(r"\\\r?\n", " ", tok.text)
        m = _DEFINE_RE.match(unfolded)
        if not m:
            continue
        m_name = m.group(1)
        if not _is_ident(m_name):
            continue
        param_str = m.group(2) or ""
        param_names = {p for p in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", param_str) if _is_ident(p)}
        body_str = m.group(3) or ""
        try:
            b_tokens = [t for t in tokenize_c_acsl(body_str, path=path) if t.kind in ("c_token", "string")]
        except AcslSyntaxError:
            continue

        direct_calls: set[str] = set()
        ident_refs: set[str] = set()
        direct_loops = 0
        nb = len(b_tokens)
        for idx, bt in enumerate(b_tokens):
            txt = bt.text
            if txt == "for":
                direct_loops += 1
            elif txt == "while":
                is_trivial_false = False
                if idx + 1 < nb and b_tokens[idx + 1].text == "(":
                    close_w = _find_matching_forward(b_tokens, idx + 1, "(", ")")
                    if close_w != -1:
                        cond_toks = [ct.text.lower() for ct in b_tokens[idx + 2 : close_w] if ct.text not in ("(", ")")]
                        if len(cond_toks) == 1 and cond_toks[0] in ("0", "0u", "0l", "0ul", "0ull", "false"):
                            is_trivial_false = True
                if not is_trivial_false:
                    direct_loops += 1
            elif txt == "(" and idx > 0:
                prev = b_tokens[idx - 1].text
                if _is_ident(prev) and prev not in param_names and prev != m_name:
                    direct_calls.add(prev)
            elif _is_ident(txt) and txt not in param_names and txt != m_name:
                ident_refs.add(txt)

        raw_macros[m_name] = {
            "name": m_name,
            "line": tok.line,
            "direct_calls": direct_calls,
            "ident_refs": ident_refs | direct_calls,
            "direct_loops": direct_loops,
            "params": sorted(param_names),
            "body_text": body_str,
        }

    macro_names = set(raw_macros.keys())
    resolved: dict[str, dict] = {}
    for m_name, info in raw_macros.items():
        visited: set[str] = {m_name}
        queue = [ref for ref in sorted(info["ident_refs"]) if ref in macro_names and ref != m_name]
        callees = {c for c in info["direct_calls"] if c not in macro_names}
        ident_refs = {r for r in info["ident_refs"] if r not in macro_names}
        total_loops = info["direct_loops"]
        while queue:
            cur = queue.pop(0)
            if cur in visited:
                continue
            visited.add(cur)
            sub = raw_macros[cur]
            callees |= {c for c in sub["direct_calls"] if c not in macro_names}
            ident_refs |= {r for r in sub["ident_refs"] if r not in macro_names}
            total_loops += sub["direct_loops"]
            for ref in sorted(sub["ident_refs"]):
                if ref in macro_names and ref not in visited:
                    queue.append(ref)
        resolved[m_name] = {
            "name": m_name,
            "line": info["line"],
            "callees": callees,
            "ident_refs": ident_refs | callees,
            "loop_count": total_loops,
            "params": info.get("params", []),
            "body_text": info.get("body_text", ""),
        }
    return resolved


def extract_functions_from_code(raw_code: str, path: str = "<input>") -> list[dict]:
    """
    Deterministically extract all C function definitions from `raw_code` using
    the lossless C/ACSL tokenizer.
    """
    try:
        all_tokens = tokenize_c_acsl(raw_code, path=path)
    except AcslSyntaxError:
        # Fallback if a file has an unclosed comment/literal: strip comments/strings conservatively
        cleaned = re.sub(r"/\*.*?\*/", " ", raw_code, flags=re.DOTALL)
        cleaned = re.sub(r"//[^\n]*", " ", cleaned)
        all_tokens = tokenize_c_acsl(cleaned, path=path)

    c_tokens = [t for t in all_tokens if t.kind in ("c_token", "string")]
    results: list[dict] = []

    n = len(c_tokens)
    idx = 0
    paren_depth = 0
    last_top_boundary = -1

    while idx < n:
        tok = c_tokens[idx]
        text = tok.text

        if text == "(":
            paren_depth += 1
            idx += 1
            continue
        if text == ")":
            paren_depth = max(0, paren_depth - 1)
            idx += 1
            continue
        if text == ";" and paren_depth == 0:
            last_top_boundary = idx
            idx += 1
            continue
        if text == "}" and paren_depth == 0:
            last_top_boundary = idx
            idx += 1
            continue

        if text == "{":
            # A brace inside parentheses, as in `MACRO(x, ({ ... }))`, is not a top-level body.
            if paren_depth == 0:
                header_slice = c_tokens[last_top_boundary + 1 : idx]
                if (
                    len(header_slice) >= 2
                    and header_slice[-2].text == "extern"
                    and header_slice[-1].text in ('"C"', '"C++"')
                ) or (len(header_slice) == 1 and header_slice[-1].text == "extern"):
                    last_top_boundary = idx
                    idx += 1
                    continue

                close_brace = _find_matching_forward(c_tokens, idx, "{", "}")
                if close_brace == -1:
                    break

                # Check if tokens between last_top_boundary and idx form a function header
                has_top_equals = False
                p_depth = 0
                for ht in header_slice:
                    if ht.text == "(":
                        p_depth += 1
                    elif ht.text == ")":
                        p_depth = max(0, p_depth - 1)
                    elif ht.text == "=" and p_depth == 0:
                        has_top_equals = True
                        break

                if not has_top_equals and header_slice:
                    before_brace = _strip_trailing_attributes(c_tokens, idx, last_top_boundary)
                    if before_brace > last_top_boundary and c_tokens[before_brace].text == ")":
                        open_params = _find_matching_backward(c_tokens, before_brace, "(", ")")
                        if open_params > last_top_boundary:
                            fn_name, param_tokens, decl_prefix = _resolve_declarator(
                                c_tokens, last_top_boundary, open_params, before_brace
                            )
                            if fn_name and _is_ident(fn_name):
                                body_tokens = c_tokens[idx + 1 : close_brace]
                                start_line = decl_prefix[0].line if decl_prefix else c_tokens[open_params].line
                                end_line = c_tokens[close_brace].line
                                results.append(
                                    {
                                        "name": fn_name,
                                        "line": start_line,
                                        "end_line": end_line,
                                        "loc": max(1, end_line - start_line + 1),
                                        "decl_tokens": decl_prefix,
                                        "param_tokens": param_tokens,
                                        "body_tokens": body_tokens,
                                    }
                                )
                                last_top_boundary = close_brace
                                idx = close_brace + 1
                                continue

                # Otherwise (e.g. struct/union/enum or global array initializer), skip past closing '}'
                last_top_boundary = close_brace
                idx = close_brace + 1
                continue

        idx += 1

    return results


def _resolve_declarator(
    c_tokens: list[Token],
    last_top_boundary: int,
    open_params: int,
    close_params: int,
) -> tuple[str | None, list[Token], list[Token]]:
    """
    Resolve function name and parameter tokens from a top-level declarator.
    Handles `ret fn(params)`, `ret *fn(params)`, `ret (*fn)(params)`,
    `ret (*fn(params))(fp_params)`, and extra-paren-wrapped forms such as
    `ret (*(fn)(params))` (produced by macros like `void (*(name)(args))`).
    Type keywords are never accepted as the function name.
    """
    name_idx = open_params - 1
    if name_idx <= last_top_boundary:
        return None, [], []

    # Skip pointer stars between the return type and the declarator.
    j = name_idx
    while j > last_top_boundary and c_tokens[j].text == "*":
        j -= 1

    if j > last_top_boundary:
        candidate = c_tokens[j]
        if _is_ident(candidate.text) and candidate.text not in TYPE_MODIFIERS_AND_PRIMITIVES:
            return (
                candidate.text,
                c_tokens[open_params + 1 : close_params],
                c_tokens[last_top_boundary + 1 : j],
            )
        if candidate.text == ")":
            # Parenthesized declarator before the params: `ret (*fn)(params)` or
            # `ret (*fn(params))(fp_params)`.
            inner_open = _find_matching_backward(c_tokens, j, "(", ")")
            if inner_open > last_top_boundary:
                # `(*fn(params))(fp)`: the name sits before an inner params group.
                last_inner_open = -1
                depth = 0
                for k in range(inner_open + 1, j):
                    if c_tokens[k].text == "(":
                        depth += 1
                        last_inner_open = k
                    elif c_tokens[k].text == ")":
                        depth -= 1
                if last_inner_open != -1 and depth == 0:
                    inner_close = _find_matching_forward(c_tokens, last_inner_open, "(", ")")
                    return _resolve_declarator(c_tokens, inner_open, last_inner_open, inner_close)
                # `(*fn)(params)`: the name is the last identifier inside the parens.
                for k in range(j - 1, inner_open, -1):
                    if _is_ident(c_tokens[k].text) and c_tokens[k].text not in TYPE_MODIFIERS_AND_PRIMITIVES:
                        return (
                            c_tokens[k].text,
                            c_tokens[open_params + 1 : close_params],
                            c_tokens[last_top_boundary + 1 : inner_open],
                        )
                return None, [], []
        if candidate.text in TYPE_MODIFIERS_AND_PRIMITIVES:
            # The params group is wrapped in an extra paren pair, e.g.
            # `void (*(fn)(params))`: recurse into the group with its last inner
            # paren group as the real parameter list.
            last_inner_open = -1
            depth = 0
            for k in range(open_params + 1, close_params):
                if c_tokens[k].text == "(":
                    depth += 1
                    last_inner_open = k
                elif c_tokens[k].text == ")":
                    depth -= 1
            if last_inner_open != -1 and depth == 0:
                inner_close = _find_matching_forward(c_tokens, last_inner_open, "(", ")")
                return _resolve_declarator(c_tokens, open_params, last_inner_open, inner_close)
    return None, [], []
