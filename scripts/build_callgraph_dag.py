#!/usr/bin/env python3
"""
Builds the Function Call-Graph DAG, Topological Verification Waves (Wave 0..K),
Generic Structural Module Risk-Tier Classification, Per-Function WP Provability
Analysis (Verified Core vs. Unverified Shell), and Candidate Security Properties
using deterministic C/ACSL tokenization.

When the Phase 0 model exists (workspace/reports/phase0_model.json, scripts/phase0_model.py), the
functions and the call edges are the model's: every function the build compiles outside its tests,
under its real name, with Frama-C's direct and indirect edges and the build's macro aliases. Modules,
tiers and the per-function analysis stay the lexer's (`model_view`). `--no-model` keeps the lexer's.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acsl_ast import AcslSyntaxError, Token, tokenize_c_acsl  # noqa: E402
from framac_common import is_pipeline_output_dir  # noqa: E402

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

BYTE_BUFFER_TYPES = {
    "char",
    "uint8_t",
    "int8_t",
    "u8",
    "s8",
    "void",
    "unsigned",
}

INTEGER_BOUND_TYPES = {
    "size_t",
    "ssize_t",
    "int",
    "unsigned",
    "long",
    "short",
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
    "ptrdiff_t",
}

DYNAMIC_ALLOC_CALLEES = {
    "malloc",
    "calloc",
    "realloc",
    "free",
    "aligned_alloc",
    "strdup",
    "strndup",
    "alloca",
    "__builtin_alloca",
}

HARNESS_ENTRYPOINT_NAMES = frozenset(
    {
        "LLVMFuzzerTestOneInput",
        "LLVMFuzzerInitialize",
        "eva_main",
    }
)

DISAMBIGUATE_COLLISION_NAMES = frozenset({"main"}) | HARNESS_ENTRYPOINT_NAMES


ZEROIZATION_CALLEES = {
    "explicit_bzero",
    "memset_s",
    "SecureZeroMemory",
    "OPENSSL_cleanse",
}

FORMAT_OR_WRITE_CALLEES = {
    "snprintf",
    "vsnprintf",
    "sprintf",
    "vsprintf",
    "memcpy",
    "memmove",
    "strncpy",
    "strlcpy",
    "strncat",
    "strlcat",
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


def _extract_declarator_ident(lhs_tokens: list[Token]) -> str | None:
    """
    Extract the declared variable/array/function-pointer identifier from the left-hand side
    of a top-level object declaration (after stripping any inline struct/union/enum `{ ... }` body).
    """
    if not lhs_tokens:
        return None
    end_idx = _strip_trailing_attributes(lhs_tokens, len(lhs_tokens), -1)
    trimmed = lhs_tokens[: end_idx + 1]
    if not trimmed:
        return None

    # 1. Array declarator: `const struct Entry Table[...]` -> identifier immediately before top-level `[`
    p_depth = 0
    for idx, tok in enumerate(trimmed):
        if tok.text == "(":
            p_depth += 1
        elif tok.text == ")":
            p_depth = max(0, p_depth - 1)
        elif tok.text == "[" and p_depth == 0:
            if idx > 0 and _is_ident(trimmed[idx - 1].text):
                cand = trimmed[idx - 1].text
                if cand not in TYPE_MODIFIERS_AND_PRIMITIVES:
                    return cand
            break

    # 2. Function-pointer variable declarator: `int (*handler)(int)`
    for idx, tok in enumerate(trimmed):
        if tok.text == "(" and idx + 2 < len(trimmed) and trimmed[idx + 1].text == "*":
            for inner in trimmed[idx + 2 :]:
                if inner.text == ")":
                    break
                if _is_ident(inner.text) and inner.text not in TYPE_MODIFIERS_AND_PRIMITIVES:
                    return inner.text

    # 3. Plain scalar/struct declarator: last non-keyword identifier at paren_depth == 0
    # Require at least one preceding type token so bare identifiers are ignored.
    p_depth = 0
    ident_positions: list[tuple[int, str]] = []
    for idx, tok in enumerate(trimmed):
        if tok.text == "(":
            p_depth += 1
        elif tok.text == ")":
            p_depth = max(0, p_depth - 1)
        elif p_depth == 0 and _is_ident(tok.text):
            ident_positions.append((idx, tok.text))
    if not ident_positions:
        return None
    last_idx, last_ident = ident_positions[-1]
    if last_ident in TYPE_MODIFIERS_AND_PRIMITIVES:
        return None
    if last_idx == 0:
        return None
    if trimmed[last_idx - 1].text in ("struct", "union", "enum"):
        return None
    return last_ident


def extract_file_scope_objects(
    raw_code: str,
    path: str = "<input>",
    macros: dict[str, dict] | None = None,
) -> list[dict]:
    """
    Extract file-scope object definitions (global/static tables, structs, variables) and the
    identifiers referenced in their initializers.
    """
    try:
        all_tokens = tokenize_c_acsl(raw_code, path=path)
    except AcslSyntaxError:
        cleaned = re.sub(r"/\*.*?\*/", " ", raw_code, flags=re.DOTALL)
        cleaned = re.sub(r"//[^\n]*", " ", cleaned)
        all_tokens = tokenize_c_acsl(cleaned, path=path)

    c_tokens = [t for t in all_tokens if t.kind in ("c_token", "string")]
    macro_map = macros or {}
    objects: list[dict] = []

    n = len(c_tokens)
    idx = 0
    brace_depth = 0
    paren_depth = 0
    stmt_start = 0

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
        if text == "}" and paren_depth == 0:
            brace_depth = max(0, brace_depth - 1)
            if brace_depth == 0:
                stmt_start = idx + 1
            idx += 1
            continue

        if text == "{" and brace_depth == 0 and paren_depth == 0:
            header_slice = c_tokens[stmt_start:idx]
            if (
                len(header_slice) >= 2
                and header_slice[-2].text == "extern"
                and header_slice[-1].text in ('"C"', '"C++"')
            ) or (len(header_slice) == 1 and header_slice[-1].text == "extern"):
                stmt_start = idx + 1
                idx += 1
                continue

            close_brace = _find_matching_forward(c_tokens, idx, "{", "}")
            if close_brace == -1:
                break

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
                before_brace = _strip_trailing_attributes(c_tokens, idx, stmt_start - 1)
                if before_brace >= stmt_start and c_tokens[before_brace].text == ")":
                    open_params = _find_matching_backward(c_tokens, before_brace, "(", ")")
                    if open_params > stmt_start:
                        fn_name, _, _ = _resolve_declarator(c_tokens, stmt_start - 1, open_params, before_brace)
                        if fn_name and _is_ident(fn_name):
                            # Function definition: skip body and advance statement start
                            stmt_start = close_brace + 1
                            idx = close_brace + 1
                            continue

            # Struct/union/enum body or brace-enclosed initializer: jump past `}` and wait for `;`
            idx = close_brace + 1
            continue

        if text == ";" and brace_depth == 0 and paren_depth == 0:
            stmt_tokens = c_tokens[stmt_start:idx]
            stmt_start = idx + 1
            idx += 1
            if not stmt_tokens:
                continue
            first_text = stmt_tokens[0].text
            if first_text in ("typedef", "_Static_assert", "static_assert"):
                continue

            # Split on first top-level `=` (outside `{ ... }` and `( ... )`)
            eq_idx = -1
            b_d = 0
            p_d = 0
            for s_idx, st in enumerate(stmt_tokens):
                if st.text == "{":
                    b_d += 1
                elif st.text == "}":
                    b_d = max(0, b_d - 1)
                elif st.text == "(":
                    p_d += 1
                elif st.text == ")":
                    p_d = max(0, p_d - 1)
                elif st.text == "=" and b_d == 0 and p_d == 0:
                    eq_idx = s_idx
                    break

            lhs_tokens = stmt_tokens[:eq_idx] if eq_idx != -1 else stmt_tokens
            rhs_tokens = stmt_tokens[eq_idx + 1 :] if eq_idx != -1 else []

            # Strip any inline `{ ... }` body from lhs_tokens
            lhs_outer: list[Token] = []
            b_d = 0
            for lt in lhs_tokens:
                if lt.text == "{":
                    b_d += 1
                elif lt.text == "}":
                    b_d = max(0, b_d - 1)
                elif b_d == 0:
                    lhs_outer.append(lt)

            lhs_texts = [lt.text for lt in lhs_outer]
            if eq_idx == -1:
                if "extern" in lhs_texts:
                    continue
                if lhs_tokens and lhs_tokens[-1].text == "}":
                    continue
                # Skip function prototypes (`ret fn(params);`)
                before_semi = _strip_trailing_attributes(lhs_outer, len(lhs_outer), -1)
                if before_semi >= 0 and lhs_outer[before_semi].text == ")":
                    open_p = _find_matching_backward(lhs_outer, before_semi, "(", ")")
                    if open_p > 0 and _is_ident(lhs_outer[open_p - 1].text):
                        continue

            obj_name = _extract_declarator_ident(lhs_outer)
            if not obj_name:
                continue

            init_refs: set[str] = set()
            for r_idx, rt in enumerate(rhs_tokens):
                r_txt = rt.text
                if not _is_ident(r_txt) or r_txt in TYPE_MODIFIERS_AND_PRIMITIVES or r_txt == obj_name:
                    continue
                # Ignore designated initializer member names (`.field` or `->field`)
                if r_idx >= 1 and rhs_tokens[r_idx - 1].text in (".", "->"):
                    continue
                if r_idx >= 2 and rhs_tokens[r_idx - 2].text == "-" and rhs_tokens[r_idx - 1].text == ">":
                    continue
                if r_txt in macro_map:
                    init_refs |= {
                        ref
                        for ref in (macro_map[r_txt].get("ident_refs") or ())
                        if ref not in TYPE_MODIFIERS_AND_PRIMITIVES and ref != obj_name
                    }
                else:
                    init_refs.add(r_txt)

            objects.append(
                {
                    "name": obj_name,
                    "is_static": "static" in lhs_texts,
                    "refs": sorted(init_refs),
                }
            )
            continue

        idx += 1

    return objects


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


def _resolve_macro_wrapped_definitions(items: list[dict], macros: dict[str, dict]) -> list[dict]:
    """
    Recover the real function name for definitions written through a single-argument
    function-like macro, e.g. `static LIBSSH2_ALLOC_FUNC(ssh2_default_alloc) { ... }`
    where the macro expands to `void (*(name)(size_t, void **))`. The raw-text pass
    otherwise records the macro name itself as the function name.
    """
    if not macros:
        return items
    out: list[dict] = []
    for item in items:
        name = item.get("name", "")
        macro = macros.get(name)
        params = (macro or {}).get("params") or []
        body_text = (macro or {}).get("body_text") or ""
        param_tokens = item.get("param_tokens") or []
        if macro and len(params) == 1 and len(param_tokens) == 1 and body_text:
            arg_text = param_tokens[0].text
            expanded = re.sub(rf"\b{re.escape(params[0])}\b", lambda _m, repl=arg_text: repl, body_text)
            try:
                sub = extract_functions_from_code(expanded + "\n{}\n", path=f"<macro {name}>")
            except Exception:
                sub = []
            if sub and sub[0].get("name") and sub[0]["name"] != name:
                item = {
                    **item,
                    "name": sub[0]["name"],
                    "decl_tokens": sub[0]["decl_tokens"],
                    "param_tokens": sub[0]["param_tokens"],
                }
        out.append(item)
    return out


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


def _split_param_tokens(param_tokens: list[Token]) -> list[list[str]]:
    """Split param_tokens on top-level commas, treating '(void)' as 0 parameters."""
    params_split: list[list[str]] = []
    cur: list[str] = []
    p_depth = 0
    for tok in param_tokens:
        if tok.text in ("(", "[", "{"):
            p_depth += 1
            cur.append(tok.text)
        elif tok.text in (")", "]", "}"):
            p_depth = max(0, p_depth - 1)
            cur.append(tok.text)
        elif tok.text == "," and p_depth == 0:
            if cur:
                params_split.append(cur)
                cur = []
        else:
            cur.append(tok.text)
    if cur:
        params_split.append(cur)
    if params_split == [["void"]]:
        return []
    return params_split


def extract_prototypes_from_code(raw_code: str, path: str = "<input>") -> list[dict]:
    """
    Extract C function prototypes from `raw_code` (top-level declarations ending in ';').
    Returns a list of dicts with 'name', 'line', 'decl_tokens', 'param_tokens'.
    """
    try:
        all_tokens = tokenize_c_acsl(raw_code, path=path)
    except AcslSyntaxError:
        cleaned = re.sub(r"/\*.*?\*/", " ", raw_code, flags=re.DOTALL)
        cleaned = re.sub(r"//[^\n]*", " ", cleaned)
        all_tokens = tokenize_c_acsl(cleaned, path=path)

    c_tokens = [t for t in all_tokens if t.kind in ("c_token", "string")]
    results: list[dict] = []

    n = len(c_tokens)
    idx = 0
    brace_depth = 0
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
        if text == "{" and paren_depth == 0:
            if brace_depth == 0:
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
                last_top_boundary = close_brace
                idx = close_brace + 1
                continue
            else:
                brace_depth += 1
                idx += 1
                continue
        if text == "}" and paren_depth == 0:
            brace_depth = max(0, brace_depth - 1)
            if brace_depth == 0:
                last_top_boundary = idx
            idx += 1
            continue

        if text == ";" and brace_depth == 0 and paren_depth == 0:
            header_slice = c_tokens[last_top_boundary + 1 : idx]
            if header_slice and not any(t.text == "typedef" for t in header_slice):
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
                if not has_top_equals:
                    before_semi = _strip_trailing_attributes(c_tokens, idx, last_top_boundary)
                    if before_semi > last_top_boundary and c_tokens[before_semi].text == ")":
                        open_params = _find_matching_backward(c_tokens, before_semi, "(", ")")
                        if open_params > last_top_boundary:
                            fn_name, param_tokens, decl_prefix = _resolve_declarator(
                                c_tokens, last_top_boundary, open_params, before_semi
                            )
                            if fn_name and _is_ident(fn_name) and not any(t.text == "typedef" for t in decl_prefix):
                                start_line = decl_prefix[0].line if decl_prefix else c_tokens[open_params].line
                                results.append(
                                    {
                                        "name": fn_name,
                                        "line": start_line,
                                        "decl_tokens": decl_prefix,
                                        "param_tokens": param_tokens,
                                    }
                                )
            last_top_boundary = idx
            idx += 1
            continue

        idx += 1

    return results


def analyze_signature(decl_tokens: list[Token], param_tokens: list[Token]) -> dict:
    """Analyze function return type, storage class, and parameter structure without keyword hints."""
    decl_texts = [t.text for t in decl_tokens]
    is_static = "static" in decl_texts
    returns_pointer = "*" in decl_texts

    # Split param_tokens on top-level commas
    params_split: list[list[str]] = []
    cur: list[str] = []
    p_depth = 0
    for tok in param_tokens:
        if tok.text == "(":
            p_depth += 1
            cur.append(tok.text)
        elif tok.text == ")":
            p_depth = max(0, p_depth - 1)
            cur.append(tok.text)
        elif tok.text == "," and p_depth == 0:
            if cur:
                params_split.append(cur)
                cur = []
        else:
            cur.append(tok.text)
    if cur:
        params_split.append(cur)

    if params_split == [["void"]]:
        params_split = []

    const_ptr_params = 0
    mutable_ptr_params = 0
    byte_buf_in_params = 0
    byte_buf_out_params = 0
    int_bound_params = 0
    fn_ptr_params: set[str] = set()
    param_names: set[str] = set()

    for p_toks in params_split:
        # Detect function pointer parameter: e.g. `int (*cb)(const uint8_t *, size_t)`
        is_fn_ptr = False
        for i, tok_str in enumerate(p_toks):
            if tok_str == "(" and i + 2 < len(p_toks) and p_toks[i + 1] == "*":
                if _is_ident(p_toks[i + 2]):
                    fn_ptr_params.add(p_toks[i + 2])
                    param_names.add(p_toks[i + 2])
                is_fn_ptr = True
                break
        if is_fn_ptr:
            continue

        # Extract parameter name (last identifier before any `[` or end)
        p_name = None
        for tok_str in reversed(p_toks):
            if _is_ident(tok_str) and tok_str not in TYPE_MODIFIERS_AND_PRIMITIVES:
                p_name = tok_str
                break
        if p_name:
            param_names.add(p_name)

        is_ptr = ("*" in p_toks) or ("[" in p_toks)
        if is_ptr:
            # Check if `const` qualifies the pointed-to type (appears before `*`)
            star_idx = p_toks.index("*") if "*" in p_toks else len(p_toks)
            is_const_target = "const" in p_toks[:star_idx]
            has_byte_type = any(bt in p_toks[:star_idx] for bt in BYTE_BUFFER_TYPES)
            if is_const_target:
                const_ptr_params += 1
                if has_byte_type:
                    byte_buf_in_params += 1
            else:
                mutable_ptr_params += 1
                if has_byte_type:
                    byte_buf_out_params += 1
        else:
            if any(it in p_toks for it in INTEGER_BOUND_TYPES):
                int_bound_params += 1

    params_str = " ".join(" ".join(p) for p in params_split) if params_split else ("void" if param_tokens else "")
    if params_split:
        params_str = ", ".join(" ".join(p) for p in params_split)

    non_ws_params = [t for t in param_tokens if getattr(t, "kind", "") != "whitespace" and t.text.strip()]
    is_variadic = any(t.text == "..." for t in non_ws_params) or any(
        non_ws_params[idx].text == "." and non_ws_params[idx + 1].text == "." and non_ws_params[idx + 2].text == "."
        for idx in range(len(non_ws_params) - 2)
    )

    return {
        "is_static": is_static,
        "is_variadic": is_variadic,
        "returns_pointer": returns_pointer,
        "params_str": params_str,
        "param_names": param_names,
        "fn_ptr_params": fn_ptr_params,
        "const_ptr_params": const_ptr_params,
        "mutable_ptr_params": mutable_ptr_params,
        "byte_buf_in_params": byte_buf_in_params,
        "byte_buf_out_params": byte_buf_out_params,
        "int_bound_params": int_bound_params,
        "takes_bounded_buffer": (const_ptr_params > 0 or byte_buf_in_params > 0) and int_bound_params > 0,
        "writes_bounded_buffer": byte_buf_out_params > 0 and int_bound_params > 0,
    }


def analyze_body(
    fn_name: str,
    body_tokens: list[Token],
    sig_info: dict,
    macros: dict[str, dict] | None = None,
) -> dict:
    """
    Analyze function body token stream for:
    - direct callees & self-recursion (including callees inside file-scope #define macros)
    - indirect (function-pointer) calls requiring `//@ calls`
    - loop counts (including loops inside file-scope #define macros) & unsigned wraparound loop idioms
    - WP blockers (backward/irreducible goto, dynamic memory allocation, pointer casts,
      container_of, volatile/inline asm)
    - structural security patterns (memory zeroization, formatting/serialization)
    """
    direct_callees: set[str] = set()
    symbol_refs: set[str] = set()
    indirect_calls: list[str] = []
    self_recursive = False
    macro_loops: list[str] = []
    seen_loop_macros: set[str] = set()
    macro_map = macros or {}

    loop_count = 0
    has_unsigned_wrap_idiom = False
    has_volatile_or_asm = False
    has_container_of = False
    has_pointer_cast = False
    has_zeroization = False
    uses_format_or_write = False

    defined_labels: dict[str, int] = {}
    goto_sites: list[tuple[str, int, int]] = []  # (label, token_idx, line)

    fn_ptr_params: set[str] = sig_info["fn_ptr_params"]
    param_names: set[str] = sig_info["param_names"]

    n = len(body_tokens)
    for i, tok in enumerate(body_tokens):
        t = tok.text

        if t in macro_map:
            m_info = macro_map[t]
            for m_callee in m_info.get("callees") or ():
                if m_callee == fn_name:
                    self_recursive = True
                elif m_callee not in param_names:
                    direct_callees.add(m_callee)
                    if m_callee in ZEROIZATION_CALLEES:
                        has_zeroization = True
                    if m_callee in FORMAT_OR_WRITE_CALLEES:
                        uses_format_or_write = True
            for m_ref in m_info.get("ident_refs") or ():
                if m_ref != fn_name and m_ref not in param_names and m_ref not in TYPE_MODIFIERS_AND_PRIMITIVES:
                    symbol_refs.add(m_ref)
            m_loops = int(m_info.get("loop_count") or 0)
            if m_loops > 0:
                loop_count += m_loops
                if t not in seen_loop_macros:
                    seen_loop_macros.add(t)
                    macro_loops.append(t)
        elif (
            _is_ident(t)
            and t not in TYPE_MODIFIERS_AND_PRIMITIVES
            and t != fn_name
            and t not in param_names
            and not (i >= 1 and body_tokens[i - 1].text in (".", "->", "goto", "struct", "union", "enum"))
            and not (i >= 2 and body_tokens[i - 2].text == "-" and body_tokens[i - 1].text == ">")
            and not (i + 1 < n and body_tokens[i + 1].text == ":")
        ):
            symbol_refs.add(t)

        if t == "for":
            loop_count += 1
        elif t == "while":
            is_trivial_false = False
            if i + 1 < n and body_tokens[i + 1].text == "(":
                close_w = _find_matching_forward(body_tokens, i + 1, "(", ")")
                if close_w != -1:
                    cond_toks = [bt.text.lower() for bt in body_tokens[i + 2 : close_w] if bt.text not in ("(", ")")]
                    if len(cond_toks) == 1 and cond_toks[0] in ("0", "0u", "0l", "0ul", "0ull", "false"):
                        is_trivial_false = True
            if not is_trivial_false:
                loop_count += 1
            # Check for `while (count--)` or `while (--count)` unsigned wraparound idiom
            # Note: tokenize_c_acsl emits each `-` as a separate single-char c_token
            if i + 5 < n and body_tokens[i + 1].text == "(":
                c1 = body_tokens[i + 2].text
                c2 = body_tokens[i + 3].text
                c3 = body_tokens[i + 4].text
                c4 = body_tokens[i + 5].text
                if (_is_ident(c1) and c2 == "-" and c3 == "-" and c4 == ")") or (
                    c1 == "-" and c2 == "-" and _is_ident(c3) and c4 == ")"
                ):
                    has_unsigned_wrap_idiom = True

        if t in ("volatile", "asm", "__asm", "__asm__"):
            has_volatile_or_asm = True

        if t == "container_of":
            has_container_of = True

        # Statement label definition: `IDENT :` at statement boundary (not ternary `? a : b`)
        if (
            _is_ident(t)
            and i + 1 < n
            and body_tokens[i + 1].text == ":"
            and (i == 0 or body_tokens[i - 1].text in (";", "{", "}", ":"))
        ):
            defined_labels.setdefault(t, i)

        # `goto IDENT;`
        if t == "goto" and i + 1 < n and _is_ident(body_tokens[i + 1].text):
            goto_sites.append((body_tokens[i + 1].text, i, tok.line))

        # Detect pointer cast: `( <type-tokens> * ) <expr>`
        if t == "(" and i + 3 < n:
            close_p = _find_matching_forward(body_tokens, i, "(", ")")
            if close_p != -1 and close_p - i <= 6 and body_tokens[close_p - 1].text == "*":
                inner_texts = [bt.text for bt in body_tokens[i + 1 : close_p - 1]]
                if inner_texts and all((it in TYPE_MODIFIERS_AND_PRIMITIVES or _is_ident(it)) for it in inner_texts):
                    prev_text = body_tokens[i - 1].text if i > 0 else ";"
                    if not _is_ident(prev_text) and prev_text not in ("sizeof", "_Alignof", "typeof"):
                        if "void" not in inner_texts:
                            has_pointer_cast = True

        # Detect Zeroization loop assignment: `buf[i] = 0;`
        if (
            t == "="
            and i >= 4
            and i + 2 < n
            and body_tokens[i - 1].text == "]"
            and body_tokens[i + 1].text in ("0", "0u", "0U", "'\\0'")
            and body_tokens[i + 2].text == ";"
        ):
            has_zeroization = True

        # Detect function calls at `(`
        if t == "(" and i > 0:
            prev = body_tokens[i - 1].text
            if _is_ident(prev):
                # Check if preceded by `->` (`-` then `>`) or `.` (struct member function pointer call)
                if i >= 3 and body_tokens[i - 3].text == "-" and body_tokens[i - 2].text == ">":
                    base_tok = body_tokens[i - 4].text if i >= 4 else "obj"
                    call_expr = f"{base_tok}->{prev}"
                    if call_expr not in indirect_calls:
                        indirect_calls.append(call_expr)
                elif i >= 2 and body_tokens[i - 2].text in ("->", "."):
                    base_tok = body_tokens[i - 3].text if i >= 3 else "obj"
                    call_expr = f"{base_tok}{body_tokens[i - 2].text}{prev}"
                    if call_expr not in indirect_calls:
                        indirect_calls.append(call_expr)
                elif prev in fn_ptr_params:
                    if prev not in indirect_calls:
                        indirect_calls.append(prev)
                elif prev == fn_name:
                    self_recursive = True
                elif prev not in param_names and prev not in macro_map:
                    direct_callees.add(prev)
                    if prev in ZEROIZATION_CALLEES:
                        has_zeroization = True
                    elif prev == "memset":
                        # Check if 2nd arg of memset(ptr, 0, len) is 0
                        close_call = _find_matching_forward(body_tokens, i, "(", ")")
                        if close_call != -1:
                            call_inner = [bt.text for bt in body_tokens[i + 1 : close_call]]
                            if "," in call_inner:
                                first_comma = call_inner.index(",")
                                if (
                                    first_comma + 2 < len(call_inner)
                                    and call_inner[first_comma + 1] in ("0", "0u", "0U")
                                    and call_inner[first_comma + 2] == ","
                                ):
                                    has_zeroization = True
                    if prev in FORMAT_OR_WRITE_CALLEES:
                        uses_format_or_write = True
            elif prev == ")":
                # Check for dereferenced function pointer call `(*fp)(...)`
                open_deref = _find_matching_backward(body_tokens, i - 1, "(", ")")
                if open_deref != -1 and open_deref + 2 < i - 1 and body_tokens[open_deref + 1].text == "*":
                    deref_expr = "".join(bt.text for bt in body_tokens[open_deref:i])
                    if deref_expr not in indirect_calls:
                        indirect_calls.append(deref_expr)

    has_backward_goto = any(lbl in defined_labels and defined_labels[lbl] < goto_idx for lbl, goto_idx, _ in goto_sites)
    has_dynamic_alloc = bool(direct_callees & DYNAMIC_ALLOC_CALLEES)

    wp_blockers: list[str] = []
    if fn_name in HARNESS_ENTRYPOINT_NAMES:
        wp_blockers.append("fuzz_or_eva_harness_entrypoint")
    if sig_info.get("is_variadic", False):
        wp_blockers.append("internal_variadic")
    if has_backward_goto:
        wp_blockers.append("irreducible_goto")
    if has_dynamic_alloc:
        wp_blockers.append("dynamic_allocation")
    if has_container_of:
        wp_blockers.append("container_of")
    if has_volatile_or_asm:
        wp_blockers.append("volatile_or_asm")

    wp_notes: list[str] = []
    if fn_name in HARNESS_ENTRYPOINT_NAMES:
        wp_notes.append("fuzz/Eva harness entrypoint: verified dynamically by E-ACSL + LibFuzzer and Eva, not WP")
    if sig_info.get("is_variadic", False):
        wp_notes.append("internal variadic function: Frama-C WP does not support variadic function specifications")
    if indirect_calls:
        wp_notes.append(f"indirect call(s) {indirect_calls} require '//@ calls <targets>;'")
    if self_recursive:
        wp_notes.append("recursive function requires 'decreases <measure>;'")
    if has_unsigned_wrap_idiom:
        wp_notes.append("unsigned decrement loop idiom may require --no-warn-unsigned")
    if has_pointer_cast:
        wp_notes.append("pointer cast may trigger incompatible pointer cast warning under Typed model")
    if macro_loops:
        wp_notes.append(
            f"invokes loop-bearing preprocessor macro(s) {macro_loops}: "
            "C preprocessor strips '/*@ loop ... */' comments inside #define bodies"
        )

    if wp_blockers:
        verifiability = "shell_unverifiable_wp"
    elif indirect_calls:
        verifiability = "needs_calls_annotation"
    else:
        verifiability = "core_provable"

    return {
        "has_loops": loop_count > 0,
        "loop_count": loop_count,
        "macro_loops": macro_loops,
        "direct_callees": direct_callees,
        "symbol_refs": symbol_refs,
        "indirect_calls": indirect_calls,
        "self_recursive": self_recursive,
        "has_backward_goto": has_backward_goto,
        "has_dynamic_alloc": has_dynamic_alloc,
        "has_container_of": has_container_of,
        "has_pointer_cast": has_pointer_cast,
        "has_volatile_or_asm": has_volatile_or_asm,
        "has_unsigned_wrap_idiom": has_unsigned_wrap_idiom,
        "has_zeroization": has_zeroization,
        "uses_format_or_write": uses_format_or_write,
        "wp_blockers": wp_blockers,
        "wp_notes": wp_notes,
        "verifiability": verifiability,
    }


def infer_security_properties(
    fn_name: str,
    sig_info: dict,
    body_info: dict,
    is_recursive: bool,
    threat_model_text: str,
) -> list[dict]:
    """
    Infer candidate Security Layers (Layers 2-6) from structural C properties
    and explicit THREAT_MODEL.md references (without hardcoded domain keyword lists).
    """
    props: list[dict] = []

    # Layer 2: Loop or recursion termination (Anti-DoS)
    if body_info["has_loops"]:
        props.append(
            {
                "layer": 2,
                "category": "Termination / Anti-DoS",
                "template": "loop variant",
                "reason": f"Function contains {body_info['loop_count']} loop(s) requiring strict decreasing loop variant proofs.",
            }
        )
    elif is_recursive:
        props.append(
            {
                "layer": 2,
                "category": "Termination / Anti-DoS",
                "template": "decreases",
                "reason": "Recursive function requires a strict decreasing measure.",
            }
        )

    # Layer 5: Structured Output Buffer Formatting / Serialization
    if sig_info["writes_bounded_buffer"] and body_info["uses_format_or_write"]:
        props.append(
            {
                "layer": 5,
                "category": "Output Grammar & Sanitization (Anti-Injection)",
                "template": "templates/acsl/layer5_output_sanitization.acsl",
                "reason": f"Function '{fn_name}' formats or serializes data into a bounded mutable output buffer.",
            }
        )

    # Layer 6: Memory / Secret Zeroization
    if body_info["has_zeroization"]:
        props.append(
            {
                "layer": 6,
                "category": "Secret Zeroization & Non-Interference (Taint)",
                "template": "templates/acsl/layer6_zeroization_and_taint.acsl",
                "reason": f"Function '{fn_name}' performs explicit memory zeroization.",
            }
        )

    # Explicit Threat Model citation
    if threat_model_text and re.search(rf"\b{re.escape(fn_name)}\b", threat_model_text):
        props.append(
            {
                "layer": 4,
                "category": "Threat-Model Cited Entry/Boundary Function",
                "template": "THREAT_MODEL.md",
                "reason": f"Function '{fn_name}' is explicitly referenced in THREAT_MODEL.md.",
            }
        )

    return props


def classify_module_tier(module_name: str, fn_records: list[dict]) -> dict:
    """
    Classify a module into Risk Tiers 1A, 1B, 2, or 3 using purely structural
    metrics across its functions (no project-specific keyword hints).
    """
    if not fn_records:
        return {
            "tier": "Tier 3 (Internal Scalar / Glue Module)",
            "recommended_strategy": "Targeted RTE + Eva on entry points; on-demand WP for helpers",
            "run_wp_full": False,
            "run_eva": True,
            "run_eacsl_fuzz": False,
        }

    total = len(fn_records)
    heap_or_rec = sum(
        1
        for f in fn_records
        if f.get("has_dynamic_alloc")
        or (f.get("is_recursive") and f.get("const_ptr_params", 0) + f.get("mutable_ptr_params", 0) > 0)
    )
    bounded_readers = sum(1 for f in fn_records if f.get("takes_bounded_buffer"))
    bounded_writers = sum(1 for f in fn_records if f.get("writes_bounded_buffer") and f.get("uses_format_or_write"))
    provable_count = sum(1 for f in fn_records if f.get("verifiability") != "shell_unverifiable_wp")
    has_any_ptr_or_loop = any(
        f.get("has_loops") or f.get("const_ptr_params", 0) > 0 or f.get("mutable_ptr_params", 0) > 0 for f in fn_records
    )

    # Tier 2: Dynamic heap allocation or recursive pointer-linked structures
    if heap_or_rec > 0 and (heap_or_rec * 2 >= total or provable_count == 0):
        return {
            "tier": "Tier 2 (Recursive Heap / Tree Parser)",
            "recommended_strategy": "RTE + E-ACSL + LibFuzzer + WP/Eva on post-parse validator functions",
            "run_wp_full": False,
            "run_eva": True,
            "run_eacsl_fuzz": True,
        }

    # Tier 1B: Predominantly bounded output buffer formatting / serialization
    if bounded_writers > 0 and bounded_writers > bounded_readers and provable_count > 0:
        return {
            "tier": "Tier 1B (Structured Packet / Log Emitter)",
            "recommended_strategy": "RTE + Module Eva -> Full Wavefront WP + Layer 5 Output Sanitization & Bounds Contracts",
            "run_wp_full": True,
            "run_eva": True,
            "run_eacsl_fuzz": True,
        }

    # Tier 1A: Bounded buffer input parsing or general provable pointer/loop processing
    if (bounded_readers > 0 or has_any_ptr_or_loop) and provable_count > 0:
        return {
            "tier": "Tier 1A (Untrusted Binary / Network Parser)",
            "recommended_strategy": "RTE + E-ACSL + LibFuzzer -> Module Eva -> Full Wavefront WP + Security Contracts",
            "run_wp_full": True,
            "run_eva": True,
            "run_eacsl_fuzz": True,
        }

    # Tier 3: Pure scalar glue or unprovable hardware/OS shell
    return {
        "tier": "Tier 3 (Internal State / Glue Module)",
        "recommended_strategy": "Targeted RTE + Eva on entry points; on-demand WP for high-risk helpers",
        "run_wp_full": False,
        "run_eva": True,
        "run_eacsl_fuzz": False,
    }


def compute_topological_waves(
    functions: dict[str, dict],
    call_edges: dict[str, set[str]],
) -> tuple[list[list[str]], list[list[str]]]:
    """
    Compute exact Strongly Connected Components (Tarjan's algorithm) and
    bottom-up Topological Waves:
      Wave 0: Leaf project functions (call 0 other project functions)
      Wave k: Functions whose internal callees are all in Waves 0..k-1
    """
    all_fns = sorted(functions.keys())
    all_fn_set = set(all_fns)
    internal_callees: dict[str, set[str]] = {
        fn: {c for c in call_edges.get(fn, set()) if c in all_fn_set and c != fn} for fn in all_fns
    }

    # 1. Tarjan's SCC algorithm to detect mutual and self recursion accurately
    index = 0
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    sccs: list[list[str]] = []

    def strongconnect(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlink[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for succ in sorted(internal_callees[node]):
            if succ not in indices:
                strongconnect(succ)
                lowlink[node] = min(lowlink[node], lowlink[succ])
            elif succ in on_stack:
                lowlink[node] = min(lowlink[node], indices[succ])

        if lowlink[node] == indices[node]:
            scc: list[str] = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                scc.append(w)
                if w == node:
                    break
            sccs.append(sorted(scc))

    for fn in all_fns:
        if fn not in indices:
            strongconnect(fn)

    cycles: list[list[str]] = []
    for scc in sccs:
        if len(scc) > 1:
            cycles.append(scc)
        elif len(scc) == 1 and functions[scc[0]].get("self_recursive"):
            cycles.append(scc)

    # 2. Bottom-up wave scheduling
    remaining = set(all_fns)
    waves: list[list[str]] = []

    while remaining:
        current_wave = sorted(fn for fn in remaining if len(internal_callees[fn] & remaining) == 0)
        if current_wave:
            waves.append(current_wave)
            remaining -= set(current_wave)
        else:
            # Break mutual recursion cycle using a leaf SCC among remaining nodes
            rem_sccs = [scc for scc in sccs if set(scc).issubset(remaining) and len(scc) > 1]
            if rem_sccs:
                # Pick SCC that has no edges to any other remaining SCC
                chosen_scc = None
                for scc in rem_sccs:
                    scc_set = set(scc)
                    outside_deps = set()
                    for m in scc:
                        outside_deps |= (internal_callees[m] & remaining) - scc_set
                    if not outside_deps:
                        chosen_scc = scc
                        break
                picked_group = chosen_scc or rem_sccs[0]
                waves.append(picked_group)
                remaining -= set(picked_group)
            else:
                picked = sorted(
                    remaining,
                    key=lambda f: (len(internal_callees[f] & remaining), f),
                )[0]
                waves.append([picked])
                remaining.remove(picked)

    return waves, cycles


_INCLUDE_DIRECTIVE_RE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.MULTILINE)
_SYSTEM_INCLUDE_PREFIXES = ("-I/usr/include", "-I/usr/local/include", "-I/lib/", "-isystem/usr/")


_SKIPPED_WALK_DIRS = frozenset({"build", "CMakeFiles", "__pycache__"})


def _keep_walk_dir(root: str, name: str) -> bool:
    """Walk filter: skip hidden and build directories, and pipeline output copied into the target."""
    return not name.startswith(".") and name not in _SKIPPED_WALK_DIRS and not is_pipeline_output_dir(Path(root) / name)


def find_pipeline_output_dirs(target_dir: Path) -> list[str]:
    """Target-relative directories the source walks skip because they hold pipeline output."""
    found: list[str] = []
    for root, dirs, _ in os.walk(target_dir):
        kept: list[str] = []
        for d in dirs:
            if is_pipeline_output_dir(Path(root) / d):
                found.append((Path(root) / d).relative_to(target_dir).as_posix())
            elif not d.startswith(".") and d not in _SKIPPED_WALK_DIRS:
                kept.append(d)
        dirs[:] = kept
    return sorted(found)


def _filter_host_system_flags(flags: list[str]) -> list[str]:
    """Strip host system include directories (-I/usr/include*) so Frama-C keeps __fc_libc."""
    out: list[str] = []
    for fl in flags:
        norm = fl.replace("\\", "/")
        if any(norm.startswith(p) for p in _SYSTEM_INCLUDE_PREFIXES):
            continue
        if norm not in out:
            out.append(fl)
    return out


def discover_in_tree_cppflags(target_dir: Path, c_files: list[Path]) -> dict[str, list[str]]:
    """
    Build-free include path and define discovery across `target_dir`:
    1. Indexes all in-tree `.h` files by basename and relative path suffix.
    2. Extracts `-D...` defines from in-tree Makefiles / CMakeLists.txt.
    3. Resolves `#include` directives in each `.c` file (and its included local `.h` files)
       to concrete `-I<dir>` flags without requiring a build or touching `/target`.
    """
    target_dir = target_dir.resolve()
    headers_by_name: dict[str, list[Path]] = defaultdict(list)
    all_headers: list[Path] = []
    makefile_defines: list[str] = []

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if _keep_walk_dir(root, d)]
        root_path = Path(root).resolve()
        for f in sorted(files):
            fp = root_path / f
            if f.endswith(".h"):
                all_headers.append(fp)
                headers_by_name[f].append(fp)
            elif f in ("Makefile", "GNUmakefile", "CMakeLists.txt") or f.endswith(".mk"):
                try:
                    mk_text = fp.read_text(encoding="utf-8", errors="replace")
                    for m_def in re.findall(r"(?<![A-Za-z0-9_])-D[A-Za-z_][A-Za-z0-9_]*(?:=[^\s\"'\\]+)?", mk_text):
                        if m_def not in makefile_defines:
                            makefile_defines.append(m_def)
                except OSError:
                    pass

    def _resolve_include(inc: str) -> list[tuple[Path, Path]]:
        """Return list of (include_root_dir, resolved_header_file) for `#include inc`."""
        inc_norm = inc.replace("\\", "/").strip("/")
        inc_parts = Path(inc_norm).parts
        leaf = inc_parts[-1] if inc_parts else inc_norm
        matches: list[tuple[Path, Path]] = []
        for h_file in headers_by_name.get(leaf, []):
            try:
                rel_h = h_file.relative_to(target_dir)
            except ValueError:
                continue
            if len(inc_parts) == 1:
                matches.append((h_file.parent, h_file))
            elif len(rel_h.parts) >= len(inc_parts) and rel_h.parts[-len(inc_parts) :] == inc_parts:
                inc_root = h_file
                for _ in range(len(inc_parts)):
                    inc_root = inc_root.parent
                matches.append((inc_root, h_file))
        return matches

    result: dict[str, list[str]] = {}
    for c_file in c_files:
        try:
            rel_key = c_file.resolve().relative_to(target_dir).as_posix()
        except ValueError:
            rel_key = c_file.name

        include_dirs: list[Path] = [c_file.resolve().parent]
        seen_headers: set[Path] = set()
        queue: list[Path] = [c_file.resolve()]

        while queue:
            curr = queue.pop(0)
            try:
                text = curr.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in _INCLUDE_DIRECTIVE_RE.finditer(text):
                for inc_dir, h_file in _resolve_include(m.group(1)):
                    if inc_dir not in include_dirs:
                        include_dirs.append(inc_dir)
                    if h_file not in seen_headers:
                        seen_headers.add(h_file)
                        queue.append(h_file)

        flags: list[str] = []
        for d in include_dirs:
            try:
                rel_d = d.relative_to(target_dir).as_posix()
                inc_posix = (target_dir / rel_d).as_posix() if rel_d != "." else target_dir.as_posix()
            except ValueError:
                inc_posix = d.as_posix()
            if inc_posix.startswith("/framac-run/"):
                inc_posix = inc_posix[len("/framac-run/") :]
            flag = f"-I{inc_posix}"
            if flag not in flags:
                flags.append(flag)
        for d_flag in makefile_defines:
            if d_flag not in flags:
                flags.append(d_flag)
        result[rel_key] = flags

    return result


def _map_foreign_path(fpath: Path, target_dir: Path) -> str:
    """
    Map a source path that lives outside `target_dir` (e.g. a compile_commands entry
    recorded against the read-only `/target` mount while the DAG is built over the
    `workspace/work` overlay) to its target-relative key by longest suffix match.
    Falls back to the bare file name when nothing matches.
    """
    parts = fpath.parts
    for i in range(len(parts)):
        suffix = Path(*parts[i:])
        if suffix.is_absolute():
            continue
        if (target_dir / suffix).is_file():
            return suffix.as_posix()
    return fpath.name


def synthesize_compile_commands(
    target_dir: Path,
    c_files: list[Path],
    flags_by_file: dict[str, list[str]],
    out_path: Path,
) -> Path:
    """Write a build-free `compile_commands.json` inside the run workspace (never inside `/target`)."""
    out_resolved = out_path.resolve()
    if str(out_resolved).replace("\\", "/").startswith("/target/"):
        raise ValueError(f"refusing to write compile_commands.json into read-only target: {out_resolved}")
    target_resolved = target_dir.resolve()
    entries = []
    for c_file in sorted(set(c_files)):
        c_res = c_file.resolve()
        try:
            rel_key = c_res.relative_to(target_resolved).as_posix()
        except ValueError:
            rel_key = _map_foreign_path(c_res, target_resolved)
        flags = flags_by_file.get(rel_key, [])
        flag_str = " ".join(flags)
        cmd = f"clang -c {flag_str} {c_res.as_posix()}".strip()
        entries.append(
            {
                "directory": target_resolved.as_posix(),
                "file": c_res.as_posix(),
                "command": re.sub(r"\s+", " ", cmd),
            }
        )
    out_resolved.parent.mkdir(parents=True, exist_ok=True)
    out_resolved.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    return out_resolved


def _discover_header_inline_and_macros(target_dir: Path) -> tuple[dict[str, dict], dict[str, dict]]:
    """
    Scan in-tree `.h` files to extract `#define` macros and `static inline` / header-defined
    helper functions so calls through header wrappers or macros resolve to their underlying
    in-repo `.c` callees and global tables.
    """
    header_macros: dict[str, dict] = {}
    header_fns_raw: dict[str, tuple[str, dict]] = {}
    h_files: list[Path] = []
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if _keep_walk_dir(root, d)]
        for fname in sorted(files):
            if fname.endswith(".h"):
                h_files.append((Path(root) / fname).resolve())

    for h_file in h_files:
        try:
            rel_h = h_file.relative_to(target_dir).as_posix()
        except ValueError:
            rel_h = h_file.name
        try:
            raw = h_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        h_macros = extract_macro_definitions(raw, path=rel_h)
        header_macros.update(h_macros)
        for item in extract_functions_from_code(raw, path=rel_h):
            header_fns_raw[item["name"]] = (rel_h, item)

    header_inline: dict[str, dict] = {}
    for fn_name, (_rel_h, item) in header_fns_raw.items():
        sig_info = analyze_signature(item["decl_tokens"], item["param_tokens"])
        body_info = analyze_body(fn_name, item["body_tokens"], sig_info, macros=header_macros)
        header_inline[fn_name] = {
            "callees": set(body_info["direct_callees"]),
            "symbol_refs": set(body_info["symbol_refs"]),
        }
    return header_macros, header_inline


def _lexer_record(
    item: dict, rel_path: str, module_name: str, macros: dict[str, dict], cppflags: list[str]
) -> tuple[dict, dict]:
    """The lexer's record of one extracted definition, and its body analysis (callees, symbol references)."""
    fn_name = item["name"]
    sig_info = analyze_signature(item["decl_tokens"], item["param_tokens"])
    body_info = analyze_body(fn_name, item["body_tokens"], sig_info, macros=macros)
    record = {
        "name": fn_name,
        "file": rel_path,
        "module": module_name,
        "line": item["line"],
        "end_line": item["end_line"],
        "loc": item["loc"],
        "is_static": sig_info["is_static"],
        "is_variadic": sig_info.get("is_variadic", False),
        "returns_pointer": sig_info["returns_pointer"],
        "params": sig_info["params_str"],
        "const_ptr_params": sig_info["const_ptr_params"],
        "mutable_ptr_params": sig_info["mutable_ptr_params"],
        "takes_bounded_buffer": sig_info["takes_bounded_buffer"],
        "writes_bounded_buffer": sig_info["writes_bounded_buffer"],
        "has_loops": body_info["has_loops"],
        "loop_count": body_info["loop_count"],
        "macro_loops": body_info.get("macro_loops", []),
        "self_recursive": body_info["self_recursive"],
        "indirect_calls": body_info["indirect_calls"],
        "has_dynamic_alloc": body_info["has_dynamic_alloc"],
        "has_backward_goto": body_info["has_backward_goto"],
        "has_pointer_cast": body_info["has_pointer_cast"],
        "has_unsigned_wrap_idiom": body_info["has_unsigned_wrap_idiom"],
        "has_zeroization": body_info["has_zeroization"],
        "uses_format_or_write": body_info["uses_format_or_write"],
        "wp_blockers": body_info["wp_blockers"],
        "wp_notes": body_info["wp_notes"],
        "verifiability": body_info["verifiability"],
        "raw_callees": sorted(body_info["direct_callees"]),
        "cppflags": list(cppflags),
    }
    return record, body_info


def build_dag(
    target_dir: Path,
    compile_commands_path: Path | None = None,
    emit_compile_commands: Path | None = None,
    model: dict | None = None,
    units: bool = True,
) -> dict:
    target_dir = target_dir.resolve()
    threat_model_path = target_dir / "THREAT_MODEL.md"
    threat_model_text = (
        threat_model_path.read_text(encoding="utf-8", errors="replace") if threat_model_path.exists() else ""
    )

    c_files: list[Path] = []
    compile_flags_by_file: dict[str, list[str]] = {}

    if compile_commands_path and compile_commands_path.exists():
        entries = json.loads(compile_commands_path.read_text(encoding="utf-8"))
        for entry in entries:
            fpath = Path(entry.get("file", ""))
            if not fpath.is_absolute():
                fpath = Path(entry.get("directory", str(target_dir))) / fpath
            fpath = fpath.resolve()
            if fpath.exists() and fpath.suffix.lower() == ".c":
                try:
                    rel_key = fpath.relative_to(target_dir).as_posix()
                except ValueError:
                    # compile_commands recorded against another root (e.g. /target while
                    # the DAG is built over the workspace/work overlay): map by suffix.
                    rel_key = _map_foreign_path(fpath, target_dir)
                rel_parts = Path(rel_key).parts
                if any(part.startswith(".") for part in rel_parts[:-1]):
                    continue
                overlay = target_dir / rel_key
                c_files.append(overlay if overlay.is_file() else fpath)
                cmd_str = entry.get("command", "") or " ".join(entry.get("arguments", []))
                flags = _filter_host_system_flags(re.findall(r"(?:-[IDU]\S+|-std=\S+)", cmd_str))
                compile_flags_by_file[rel_key] = flags

    all_source_files: list[Path] = []
    c_files_needed = not c_files
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if _keep_walk_dir(root, d)]
        for f in sorted(files):
            suffix = Path(f).suffix.lower()
            if suffix in (".c", ".h"):
                resolved = (Path(root) / f).resolve()
                all_source_files.append(resolved)
                if c_files_needed and suffix == ".c":
                    c_files.append(resolved)

    # Supplement missing per-file flags via build-free in-tree header/Makefile discovery
    discovered_flags = discover_in_tree_cppflags(target_dir, c_files)
    for rel_key, disc in discovered_flags.items():
        if not compile_flags_by_file.get(rel_key):
            compile_flags_by_file[rel_key] = disc

    if emit_compile_commands is not None:
        synthesize_compile_commands(target_dir, c_files, compile_flags_by_file, emit_compile_commands)

    header_macros, header_inline = _discover_header_inline_and_macros(target_dir)

    functions: dict[str, dict] = {}
    def_param_counts: dict[str, int] = {}
    name_collisions: list[dict] = []
    call_edges: dict[str, set[str]] = defaultdict(set)
    symbol_edges: dict[str, set[str]] = defaultdict(set)
    exported_objects: dict[str, dict] = {}
    local_objects: dict[tuple[str, str], dict] = {}
    modules: dict[str, dict] = defaultdict(lambda: {"files": [], "functions": []})

    for c_file in sorted(set(c_files)):
        try:
            rel_path = c_file.relative_to(target_dir).as_posix()
        except ValueError:
            rel_path = _map_foreign_path(c_file, target_dir)

        parts = Path(rel_path).parts
        if len(parts) >= 2 and parts[0] == "src":
            module_name = parts[1] if len(parts) > 2 else Path(rel_path).stem
        elif len(parts) >= 2:
            module_name = parts[0]
        else:
            module_name = Path(rel_path).stem

        modules[module_name]["files"].append(rel_path)

        raw_code = c_file.read_text(encoding="utf-8", errors="replace")
        file_macros = extract_macro_definitions(raw_code, path=rel_path)
        effective_macros = {**header_macros, **file_macros}
        for obj in extract_file_scope_objects(raw_code, path=rel_path, macros=effective_macros):
            obj_rec = {"file": rel_path, "refs": set(obj["refs"])}
            if obj["is_static"]:
                local_objects[(rel_path, obj["name"])] = obj_rec
            else:
                exported_objects[obj["name"]] = obj_rec

        extracted = _resolve_macro_wrapped_definitions(
            extract_functions_from_code(raw_code, path=rel_path), effective_macros
        )

        for item in extracted:
            fn_name = item["name"]
            record, body_info = _lexer_record(
                item, rel_path, module_name, effective_macros, compile_flags_by_file.get(rel_path, [])
            )
            sig_info = record

            if fn_name in DISAMBIGUATE_COLLISION_NAMES:
                if fn_name in functions and functions[fn_name]["file"] != rel_path:
                    existing_file = functions[fn_name]["file"]
                    name_collisions.append({"function": fn_name, "files": [existing_file, rel_path]})
                    existing_key = f"{existing_file}#{fn_name}"
                    existing_rec = functions.pop(fn_name)
                    functions[existing_key] = existing_rec
                    ex_mod = existing_rec["module"]
                    if fn_name in modules[ex_mod]["functions"]:
                        ex_idx = modules[ex_mod]["functions"].index(fn_name)
                        modules[ex_mod]["functions"][ex_idx] = existing_key
                    if fn_name in call_edges:
                        call_edges[existing_key] = call_edges.pop(fn_name)
                    if fn_name in symbol_edges:
                        symbol_edges[existing_key] = symbol_edges.pop(fn_name)
                    fn_key = f"{rel_path}#{fn_name}"
                elif any(
                    k == f"{rel_path}#{fn_name}" or (k.endswith(f"#{fn_name}") and functions[k].get("name") == fn_name)
                    for k in functions
                ):
                    existing_files = [functions[k]["file"] for k in functions if functions[k].get("name") == fn_name]
                    if rel_path not in existing_files:
                        name_collisions.append({"function": fn_name, "files": existing_files + [rel_path]})
                    fn_key = f"{rel_path}#{fn_name}"
                else:
                    fn_key = fn_name
            else:
                fn_key = fn_name
                if fn_name in functions and functions[fn_name]["file"] != rel_path:
                    existing_file = functions[fn_name]["file"]
                    name_collisions.append({"function": fn_name, "files": [existing_file, rel_path]})
                    # Prefer non-static (exported) definition over a file-local static helper
                    if sig_info["is_static"] and not functions[fn_name].get("is_static", False):
                        continue

            functions[fn_key] = record
            def_param_counts[fn_name] = len(_split_param_tokens(item["param_tokens"]))
            call_edges[fn_key] = set(body_info["direct_callees"])
            symbol_edges[fn_key] = set(body_info["symbol_refs"])
            if fn_key not in modules[module_name]["functions"]:
                modules[module_name]["functions"].append(fn_key)

    all_fns = set(functions.keys())
    fn_object_files: dict[str, set[str]] = defaultdict(set)

    def _resolve_symbol_closure(start_syms: set[str], start_file: str | None) -> tuple[set[str], set[str]]:
        """
        Expand `start_syms` transitively through in-tree header `static inline` functions,
        file-local (`static`) object initializers, and exported global object initializers.
        Returns `(reached_in_repo_functions, reached_object_files)`.
        """
        reached_fns: set[str] = set()
        reached_files: set[str] = set()
        visited_inline: set[str] = set()
        visited_local: set[tuple[str, str]] = set()
        visited_exported: set[str] = set()
        queue: list[tuple[str, str | None]] = [(s, start_file) for s in sorted(start_syms)]
        while queue:
            sym, cur_file = queue.pop(0)
            if sym in all_fns:
                reached_fns.add(sym)
            if sym in header_inline and sym not in visited_inline:
                visited_inline.add(sym)
                h_info = header_inline[sym]
                for nxt in sorted(h_info["callees"] | h_info["symbol_refs"]):
                    queue.append((nxt, cur_file))
            if cur_file and (cur_file, sym) in local_objects and (cur_file, sym) not in visited_local:
                visited_local.add((cur_file, sym))
                l_info = local_objects[(cur_file, sym)]
                for nxt in sorted(l_info["refs"]):
                    queue.append((nxt, cur_file))
            elif sym in exported_objects and sym not in visited_exported:
                visited_exported.add(sym)
                e_info = exported_objects[sym]
                obj_file = e_info["file"]
                reached_files.add(obj_file)
                for nxt in sorted(e_info["refs"]):
                    queue.append((nxt, obj_file))
        return reached_fns, reached_files

    header_inline_callees: dict[str, list[str]] = {}
    for h_name, h_info in sorted(header_inline.items()):
        r_fns, _ = _resolve_symbol_closure(h_info["callees"] | h_info["symbol_refs"], None)
        if r_fns:
            header_inline_callees[h_name] = sorted(r_fns)

    for fn_key in sorted(all_fns):
        fn_file = functions[fn_key]["file"]
        r_fns, r_files = _resolve_symbol_closure(call_edges[fn_key] | symbol_edges[fn_key], fn_file)
        # Replace calls to in-tree header inline wrappers with their resolved in-repo `.c` targets
        call_edges[fn_key] = (call_edges[fn_key] - set(header_inline.keys())) | (r_fns - {fn_key})
        fn_object_files[fn_key] |= r_files

    # Pre-flight warnings: walk both .h and .c files to extract prototypes
    warnings: list[str] = [
        f"skipped pipeline output directory inside the target: {rel} (move run results out of the target tree)"
        for rel in find_pipeline_output_dirs(target_dir)
    ]
    proto_files = sorted(set(all_source_files) | set(c_files))
    for src_file in proto_files:
        try:
            rel_path = src_file.relative_to(target_dir).as_posix()
        except ValueError:
            rel_path = src_file.name
        raw = src_file.read_text(encoding="utf-8", errors="replace")
        prototypes = extract_prototypes_from_code(raw, path=rel_path)
        for proto in prototypes:
            fn_name = proto["name"]
            params_split = _split_param_tokens(proto["param_tokens"])
            K = len(params_split)

            # Check for multidimensional VLA parameters (2+ bracket pairs `[` `]`)
            for p_toks in params_split:
                bracket_pairs = min(p_toks.count("["), p_toks.count("]"))
                if bracket_pairs >= 2:
                    warn = (
                        f"multidimensional array/VLA parameter in function prototype "
                        f"'{fn_name}' at {rel_path}:{proto['line']}"
                    )
                    if warn not in warnings:
                        warnings.append(warn)
                        print(f"pre-flight warning: {warn}", file=sys.stderr)

            # Check for prototype/definition parameter count mismatches
            if fn_name in def_param_counts:
                M = def_param_counts[fn_name]
                if K != M:
                    def_file = functions[fn_name]["file"]
                    def_line = functions[fn_name]["line"]
                    warn = (
                        f"parameter count mismatch for '{fn_name}': prototype has {K} "
                        f"parameter(s) at {rel_path}:{proto['line']}, definition has {M} "
                        f"parameter(s) at {def_file}:{def_line}"
                    )
                    if warn not in warnings:
                        warnings.append(warn)
                        print(f"pre-flight warning: {warn}", file=sys.stderr)

    waves, cycles = compute_topological_waves(functions, call_edges)
    recursive_fns = {fn for scc in cycles for fn in scc}

    for wave_idx, wave_fns in enumerate(waves):
        for fn in wave_fns:
            fn_rec = functions[fn]
            fn_rec["wave"] = wave_idx
            fn_rec["is_recursive"] = fn in recursive_fns
            if (
                fn_rec["is_recursive"]
                and "recursive function requires 'decreases <measure>;'" not in fn_rec["wp_notes"]
            ):
                fn_rec["wp_notes"].append("recursive function requires 'decreases <measure>;'")
            fn_rec["internal_callees"] = sorted(call_edges[fn] & all_fns)
            fn_rec["external_callees"] = sorted(call_edges[fn] - all_fns)
            fn_rec["security_properties"] = infer_security_properties(
                fn_name=fn,
                sig_info=fn_rec,
                body_info=fn_rec,
                is_recursive=fn_rec["is_recursive"],
                threat_model_text=threat_model_text,
            )

    for fn in all_fns:
        functions[fn]["internal_callers"] = sorted(caller for caller in all_fns if fn in call_edges[caller])

    files_with_main_or_harness = {
        f_rec["file"]
        for f_rec in functions.values()
        if f_rec.get("name") == "main" or f_rec.get("name") in HARNESS_ENTRYPOINT_NAMES
    }

    module_summaries: dict[str, dict] = {}
    for mod_name, mod_data in sorted(modules.items()):
        mod_fns = mod_data["functions"]
        mod_fn_records = [functions[f] for f in mod_fns if f in functions]
        tier_info = classify_module_tier(mod_name, mod_fn_records)
        mod_fn_set = set(mod_fns)
        # Candidate entry points: non-static functions with 0 internal callers in this module,
        # falling back to any function with 0 internal callers in this module.
        non_static_roots = [
            f
            for f in mod_fns
            if f in functions
            and not functions[f].get("is_static", False)
            and not (set(functions[f]["internal_callers"]) & mod_fn_set)
        ]
        all_roots = [f for f in mod_fns if f in functions and not (set(functions[f]["internal_callers"]) & mod_fn_set)]
        entry_points = non_static_roots or all_roots or mod_fns[:1]
        provable_fns = [
            f for f in mod_fns if f in functions and functions[f]["verifiability"] != "shell_unverifiable_wp"
        ]
        shell_fns = [f for f in mod_fns if f in functions and functions[f]["verifiability"] == "shell_unverifiable_wp"]

        # Compute transitive in-repo callee closure so slices link real sibling sources instead of fake stubs
        mod_files_set = set(mod_data["files"])
        mod_effective_files = {f for f in mod_files_set if f not in files_with_main_or_harness}
        if not mod_effective_files:
            mod_effective_files = set(mod_files_set)

        closure_fns: set[str] = set(mod_fns)
        worklist: list[str] = list(mod_fns)
        visited_obj_files: set[str] = set()
        while worklist:
            cur_fn = worklist.pop(0)
            for callee in functions.get(cur_fn, {}).get("internal_callees", []):
                if callee not in closure_fns and callee in functions:
                    closure_fns.add(callee)
                    worklist.append(callee)
            for obj_file in sorted(fn_object_files.get(cur_fn, set())):
                if obj_file in files_with_main_or_harness or obj_file in visited_obj_files:
                    continue
                visited_obj_files.add(obj_file)
                for fn_k, fn_rec in functions.items():
                    if fn_rec["file"] == obj_file and fn_k not in closure_fns:
                        closure_fns.add(fn_k)
                        worklist.append(fn_k)

        cross_module_callees = sorted(
            f
            for f in (closure_fns - mod_fn_set)
            if f in functions
            and functions[f]["file"] not in mod_files_set
            and functions[f]["file"] not in files_with_main_or_harness
            and functions[f].get("name") != "main"
            and functions[f].get("name") not in HARNESS_ENTRYPOINT_NAMES
        )
        object_dep_files = {
            obj_file
            for f in closure_fns
            for obj_file in fn_object_files.get(f, set())
            if obj_file not in files_with_main_or_harness
        }
        required_sources = sorted(
            mod_effective_files
            | {
                functions[f]["file"]
                for f in cross_module_callees
                if f in functions and functions[f]["file"] not in files_with_main_or_harness
            }
            | object_dep_files
        )
        unresolved_external_callees = sorted(
            {ext for f in mod_fns if f in functions for ext in functions[f].get("external_callees", [])}
        )
        module_cppflags: list[str] = []
        for src_rel in required_sources:
            for fl in compile_flags_by_file.get(src_rel, []):
                if fl not in module_cppflags:
                    module_cppflags.append(fl)

        module_summaries[mod_name] = {
            "module": mod_name,
            "files": sorted(mod_files_set),
            "required_sources": required_sources,
            "cross_module_callees": cross_module_callees,
            "external_callees": unresolved_external_callees,
            "cppflags": module_cppflags,
            "function_count": len(mod_fns),
            "functions": mod_fns,
            "provable_functions": provable_fns,
            "shell_unverifiable_functions": shell_fns,
            "candidate_entry_points": entry_points,
            **tier_info,
        }

    dag = {
        "target_dir": str(target_dir),
        "callgraph_source": "regex",
        "total_c_files": len(set(c_files)),
        "total_functions": len(functions),
        "total_waves": len(waves),
        "name_collisions": name_collisions,
        "header_inline_callees": header_inline_callees,
        "warnings": warnings,
        "modules": module_summaries,
        "waves": [{"wave": idx, "count": len(w), "functions": w} for idx, w in enumerate(waves)],
        "recursion_cycles": cycles,
        "functions": functions,
    }
    if model is None:
        return dag
    held = model_view(dag, model, target_dir, header_macros, compile_flags_by_file, threat_model_text)
    root = target_dir.as_posix()
    root = root[len("/framac-run/") :] if root.startswith("/framac-run/") else root
    return unit_view(held, model, root=root) if units else held


# ---------------------------------------------------------------------------------------------------
# The DAG from the Phase 0 model (docs/phase0-implementation-plan.md step I5a)
# ---------------------------------------------------------------------------------------------------

DEFAULT_MODEL = Path("workspace/reports/phase0_model.json")


def load_model(path: Path) -> tuple[dict | None, str | None]:
    """The Phase 0 model when it exists and succeeded, else (None, why not)."""
    if not path.is_file():
        return None, f"{path} not found (run the build capture and phase0_model.py run first)"
    try:
        model = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"{path} unreadable: {exc}"
    if not isinstance(model, dict) or model.get("status") != "ok":
        return None, f"{path} status {model.get('status') if isinstance(model, dict) else None!r}"
    return model, None


# phase0_model.py's fact sources -> the ledger's callgraph_source values.
MODEL_SOURCES = {"frama-c-kernel": "frama_c", "gcc-callgraph-info": "gcc_callgraph"}
_DEFAULT_TIER = "Tier 3 (Internal State / Glue Module)"


def _model_key_of(model_fns: dict[str, dict]) -> dict[str, str]:
    """DAG keys for model ids (`file#name`): the plain name when it is unique, else the id."""
    names: dict[str, int] = defaultdict(int)
    for rec in model_fns.values():
        names[rec["name"]] += 1
    return {fid: (rec["name"] if names[rec["name"]] == 1 else fid) for fid, rec in model_fns.items()}


def _lexer_match(
    model_fns: dict[str, dict], lexer_fns: dict[str, dict], aliases: dict[str, dict]
) -> tuple[dict[str, str], list[str]]:
    """
    model id -> lexer key for every function both inventories know: by file and name, else through a
    macro alias defined to it (a definition written `sv crypto_box(...)` under `#define crypto_box
    crypto_box_curve25519xsalsa20poly1305_tweet` is one function under two names). Also returns the
    lexer keys left unmatched: code the build does not compile, test code, macro names.
    """
    by_id = {f"{r.get('file')}#{r.get('name', k)}": k for k, r in lexer_fns.items() if isinstance(r, dict)}
    match: dict[str, str] = {fid: by_id[fid] for fid in model_fns if fid in by_id}
    taken = set(match.values())
    for k, r in lexer_fns.items():
        if k in taken or not isinstance(r, dict):
            continue
        alias = aliases.get(r.get("name", k)) or {}
        same_file = [i for i in alias.get("ids") or [] if i in model_fns and model_fns[i]["file"] == r.get("file")]
        if len(same_file) == 1 and same_file[0] not in match:
            match[same_file[0]] = k
            taken.add(k)
    return match, sorted(k for k in lexer_fns if k not in taken)


def _file_records(
    target_dir: Path, rel_path: str, header_macros: dict[str, dict], flags: list[str], memo: dict[str, dict]
) -> dict[str, dict]:
    """The lexer's records of every definition in one file (headers included), by name; memoized."""
    if rel_path in memo:
        return memo[rel_path]
    out: dict[str, dict] = {}
    path = target_dir / rel_path
    if path.is_file():
        raw = path.read_text(encoding="utf-8", errors="replace")
        macros = {**header_macros, **extract_macro_definitions(raw, path=rel_path)}
        try:
            items = _resolve_macro_wrapped_definitions(extract_functions_from_code(raw, path=rel_path), macros)
        except AcslSyntaxError:
            items = []
        for item in items:
            out.setdefault(item["name"], _lexer_record(item, rel_path, "", macros, flags)[0])
    memo[rel_path] = out
    return out


def _empty_record(name: str, file: str) -> dict:
    """A function the lexer cannot see (a GNU nested function, a macro-generated definition)."""
    return {
        "name": name,
        "file": file,
        "loc": 0,
        "is_variadic": False,
        "returns_pointer": False,
        "params": "",
        "const_ptr_params": 0,
        "mutable_ptr_params": 0,
        "takes_bounded_buffer": False,
        "writes_bounded_buffer": False,
        "macro_loops": [],
        "indirect_calls": [],
        "has_dynamic_alloc": False,
        "has_backward_goto": False,
        "has_pointer_cast": False,
        "has_unsigned_wrap_idiom": False,
        "has_zeroization": False,
        "uses_format_or_write": False,
        "wp_blockers": [],
        "wp_notes": [],
        "verifiability": "core_provable",
        "raw_callees": [],
        "cppflags": [],
    }


def model_view(
    lexer: dict,
    model: dict,
    target_dir: Path,
    header_macros: dict[str, dict],
    compile_flags_by_file: dict[str, list[str]],
    threat_model_text: str = "",
) -> dict:
    """
    The DAG with the inventory and the call edges of the Phase 0 model (scripts/phase0_model.py),
    modules held fixed (step I5a):

    - functions are the model's (every function a non-test link unit compiles, under its real name);
      their file, lines, storage and loops come from Frama-C, the rest of their record (parameters,
      WP blockers, security properties) from the lexer's analysis of the same definition;
    - `internal_callees` are the model's edges, direct and indirect (type-matched function pointers,
      thread starts, callbacks), so waves, the WP scheduler and the hypothesis audit see them; the
      indirect ones are also listed in `indirect_callees`;
    - a function keeps the lexer's module of its file; a header function the module owning most of
      its unit's sources; modules keep their tier, sources, flags and entry points (translated to
      the model's keys);
    - `macro_aliases` maps each alias the model found to the DAG keys of its functions;
    - header functions are marked `header`, and `reached` when an entry point of the build calls them;
    - functions of a unit on the GCC fallback carry `callgraph_fallback` (Frama-C's first error);
    - each function carries the model's `trust` (scripts/trust.py: untrusted or trusted, the deciding
      rule, `boundary`), and the DAG the model's `trust` block.
    """
    model_fns: dict[str, dict] = model.get("functions") or {}
    units: dict[str, dict] = model.get("units") or {}
    lexer_fns: dict[str, dict] = lexer.get("functions") or {}
    lexer_modules: dict[str, dict] = lexer.get("modules") or {}
    aliases: dict[str, dict] = model.get("macro_aliases") or {}
    key_of = _model_key_of(model_fns)
    match, dropped = _lexer_match(model_fns, lexer_fns, aliases)
    new_key_of_lexer = {lk: key_of[fid] for fid, lk in match.items()}

    file_module = {f: m for m, rec in sorted(lexer_modules.items()) for f in rec.get("files") or []}
    fallback_error = {
        n: (u.get("parse") or {}).get("error") or "Frama-C could not parse this unit"
        for n, u in units.items()
        if (u.get("parse") or {}).get("status") == "gcc_fallback"
    }

    def module_of(rec: dict) -> str:
        if rec["file"] in file_module:
            return file_module[rec["file"]]
        votes: dict[str, int] = defaultdict(int)
        for unit in rec.get("units") or []:
            for src in (units.get(unit) or {}).get("files") or []:
                if src in file_module:
                    votes[file_module[src]] += 1
        if votes:
            return sorted(votes.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        return Path(rec["file"]).parent.name or Path(rec["file"]).stem

    succ: dict[str, set[str]] = defaultdict(set)
    indirect: dict[str, set[str]] = defaultdict(set)
    for e in model.get("edges") or []:
        caller, callee = key_of.get(e.get("caller")), key_of.get(e.get("callee"))
        if caller and callee:
            succ[caller].add(callee)
            if e.get("kind") == "indirect":
                indirect[caller].add(callee)

    memo: dict[str, dict] = {}
    model_names = {r["name"] for r in model_fns.values()}
    functions: dict[str, dict] = {}
    for fid, m in sorted(model_fns.items()):
        key = key_of[fid]
        flags = compile_flags_by_file.get(m["file"], [])
        if fid in match:
            base = dict(lexer_fns[match[fid]])
        else:
            base = dict(
                _file_records(target_dir, m["file"], header_macros, flags, memo).get(m["name"])
                or _empty_record(m["name"], m["file"])
            )
        source = MODEL_SOURCES.get(m.get("source") or "", "frama_c")
        loops = int(m["loops"]) if source == "frama_c" and m.get("loops") is not None else base.get("loop_count", 0)
        rec = {
            **base,
            "name": m["name"],
            "file": m["file"],
            "module": module_of(m),
            "line": m.get("line") or base.get("line", 0),
            "end_line": m.get("end_line") or base.get("end_line", m.get("line") or 0),
            "loc": m.get("lines") or base.get("loc", 0),
            "is_static": bool(m.get("static")),
            "has_loops": loops > 0,
            "loop_count": loops,
            "wp_notes": [n for n in base.get("wp_notes") or [] if "requires 'decreases" not in n],
            "cppflags": base.get("cppflags") or flags,
            "internal_callees": sorted(succ[key] - {key}),
            "indirect_callees": sorted(indirect[key] - {key}),
            "self_recursive": key in succ[key],
            "external_callees": sorted({c for c in base.get("raw_callees") or [] if c not in model_names}),
            "callgraph_source": source,
            "units": list(m.get("units") or []),
            "header": bool(m.get("header")),
        }
        errors = sorted({fallback_error[u] for u in m.get("units") or [] if u in fallback_error})
        if errors:
            rec["callgraph_fallback"] = errors[0]
        if m.get("cyclomatic") is not None:
            rec["cyclomatic"] = m["cyclomatic"]
        if isinstance(m.get("trust"), dict):
            rec["trust"] = m["trust"]  # step I7 (scripts/trust.py)
        functions[key] = rec

    waves, cycles = compute_topological_waves(functions, succ)
    in_cycle = {f for c in cycles for f in c}
    for idx, wave in enumerate(waves):
        for key in wave:
            rec = functions[key]
            rec["wave"] = idx
            rec["is_recursive"] = key in in_cycle
            if rec["is_recursive"]:
                rec["wp_notes"].append("recursive function requires 'decreases <measure>;'")
            rec["security_properties"] = infer_security_properties(
                fn_name=rec["name"],
                sig_info=rec,
                body_info=rec,
                is_recursive=rec["is_recursive"],
                threat_model_text=threat_model_text,
            )
    callers: dict[str, set[str]] = defaultdict(set)
    for caller, callees in succ.items():
        for callee in callees - {caller}:
            callers[callee].add(caller)
    for key, rec in functions.items():
        rec["internal_callers"] = sorted(callers[key])

    # Header functions get a ledger unit only when an entry point of the build reaches them.
    reached: set[str] = set()
    work = [key_of[e] for e in model.get("entry_points") or [] if e in key_of]
    while work:
        cur = work.pop()
        if cur not in reached:
            reached.add(cur)
            work.extend(succ[cur] - reached)
    for key, rec in functions.items():
        if rec["header"]:
            rec["reached"] = key in reached

    def translate(keys: list[str]) -> list[str]:
        out: list[str] = []
        for k in keys or []:
            new = new_key_of_lexer.get(k, k if k in functions else None)
            if new and new not in out:
                out.append(new)
        return out

    members: dict[str, list[str]] = defaultdict(list)
    for key, rec in functions.items():
        members[rec["module"]].append(key)
    modules: dict[str, dict] = {}
    for name in sorted(set(lexer_modules) | set(members)):
        base_mod = lexer_modules.get(name) or {
            "module": name,
            "files": [],
            "required_sources": [],
            "cross_module_callees": [],
            "external_callees": [],
            "cppflags": [],
            "tier": _DEFAULT_TIER,
        }
        mod = dict(base_mod)
        fns = sorted(members.get(name, []))
        mod["functions"] = fns
        mod["function_count"] = len(fns)
        fn_set = set(fns)
        mod["files"] = sorted(
            set(mod.get("files") or []) | {functions[k]["file"] for k in fns if functions[k]["file"].endswith(".c")}
        )
        mod["provable_functions"] = [k for k in fns if functions[k]["verifiability"] != "shell_unverifiable_wp"]
        mod["shell_unverifiable_functions"] = [
            k for k in fns if functions[k]["verifiability"] == "shell_unverifiable_wp"
        ]
        mod["cross_module_callees"] = translate(mod.get("cross_module_callees") or [])
        # The lexer's entry points under their model keys (held fixed); a module the lexer did not have
        # gets the lexer's rule: non-static functions no other function of the module calls.
        entries = [k for k in translate(mod.get("candidate_entry_points") or []) if k in fn_set]
        roots = [k for k in fns if not set(functions[k]["internal_callers"]) & fn_set]
        mod["candidate_entry_points"] = (
            entries or [k for k in roots if not functions[k]["is_static"]] or roots or fns[:1]
        )
        modules[name] = mod

    alias_keys = {
        alias: sorted(key_of[i] for i in rec.get("ids") or [] if i in key_of) for alias, rec in sorted(aliases.items())
    }
    by_name: dict[str, list[str]] = defaultdict(list)
    for rec in model_fns.values():
        by_name[rec["name"]].append(rec["file"])
    warnings = list(lexer.get("warnings") or []) + [
        f"unit {u}: Frama-C could not parse it, its call graph comes from GCC (-fcallgraph-info): {err}"
        for u, err in sorted(fallback_error.items())
    ]
    return {
        **lexer,
        "callgraph_source": "frama_c",
        "total_c_files": len({r["file"] for r in functions.values() if r["file"].endswith(".c")}),
        "total_functions": len(functions),
        "total_waves": len(waves),
        "name_collisions": [{"function": n, "files": sorted(f)} for n, f in sorted(by_name.items()) if len(f) > 1],
        "macro_aliases": {a: k for a, k in alias_keys.items() if k},
        "warnings": warnings,
        "modules": modules,
        "waves": [{"wave": i, "count": len(w), "functions": w} for i, w in enumerate(waves)],
        "recursion_cycles": cycles,
        "functions": functions,
        "model": {
            "generated_at": model.get("generated_at"),
            "functions": len(model_fns),
            "lexer_only_functions": dropped,
            "gcc_fallback_units": sorted(fallback_error),
        },
        **({"trust": model["trust"]} if isinstance(model.get("trust"), dict) else {}),
    }


# ---------------------------------------------------------------------------------------------------
# Link units as modules (docs/phase0-implementation-plan.md step I5b)
# ---------------------------------------------------------------------------------------------------

_UNIT_KIND_ORDER = {"static_lib": 0, "shared_lib": 1}
# Most to least demanding; a unit takes the most demanding tier among its lexer modules, while each
# function keeps its own lexer module's tier (tiers change in step I8, not here).
_TIER_RANK = ("Tier 1A", "Tier 1B", "Tier 2", "Tier 3")
_RESERVED_MODULE_NAMES = frozenset({"tune", "tune-base"})


def unit_module_name(unit: str) -> str:
    """A link artifact as a module name usable in Make targets and file names: `lib/libkv.a` -> `libkv_a`."""
    name = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in Path(unit).name).strip("_") or "unit"
    return name if name not in _RESERVED_MODULE_NAMES else f"{name}_unit"


def _tier_rank(tier: str | None) -> int:
    for idx, prefix in enumerate(_TIER_RANK):
        if (tier or "").startswith(prefix):
            return idx
    return len(_TIER_RANK)


_DIR_FLAGS = ("-I", "-isystem", "-iquote", "-idirafter")
_FORCE_INCLUDE_FLAGS = ("-include", "-imacros")


def unit_cppflags(unit_flags: list[str], lexer_flags: list[str], root: str = "") -> tuple[list[str], list[str]]:
    """
    A unit's compile flags, one token each, and its force-included files (`-include f` / `-imacros f`,
    which take two tokens and so are kept apart). Flags are the build's own (`-I inc` joined to `-Iinc`;
    `-isystem`/`-iquote`/`-idirafter` directories as `-I`), plus the include directories the lexer found
    in the unit's lexer modules. The lexer's macro definitions are left out: they come from scanning
    Makefiles and can contradict the build (both `-DFAST` and `-DLEGACY` from two branches of a Makefile).
    The model's paths are relative to the project root; with `root` (the DAG's target directory as the
    lexer writes it, e.g. `workspace/work`) relative directories and files are made relative to the run
    directory, like the lexer's.
    """

    def rooted(path: str) -> str:
        if not root or path.startswith("/") or path.startswith(root.rstrip("/") + "/"):
            return path
        path = path[2:] if path.startswith("./") else path
        return root.rstrip("/") if path in ("", ".") else f"{root.rstrip('/')}/{path}"

    out: list[str] = []
    forced: list[str] = []
    tokens = [str(t) for t in unit_flags]
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if tok in _FORCE_INCLUDE_FLAGS and nxt is not None:
            forced.append(rooted(nxt))
            i += 2
            continue
        if tok in _DIR_FLAGS and nxt is not None:
            tok = "-I" + rooted(nxt)
            i += 1
        elif tok in ("-D", "-U") and nxt is not None:
            tok += nxt
            i += 1
        else:
            for opt in _DIR_FLAGS:
                if tok.startswith(opt) and len(tok) > len(opt):
                    tok = "-I" + rooted(tok[len(opt) :])
                    break
        if tok not in out:
            out.append(tok)
        i += 1
    out += [f for f in dict.fromkeys(lexer_flags) if f.startswith("-I") and f not in out]
    return out, list(dict.fromkeys(forced))


def unit_view(dag: dict, model: dict, root: str = "") -> dict:
    """
    The model-based DAG (`model_view`) with the build's link units as its modules (step I5b):

    - one module per non-test link unit, libraries first: its own sources plus those of the project
      libraries it links (`required_sources`), its compile flags, its API entry points (exported
      functions, `main` for an executable, and an executable's embedded API), `concurrent`;
    - a source file belongs to the first unit that compiles it, a header function to the first unit
      it is compiled into;
    - each function keeps the lexer module it had (`lexer_module`) and that module's `tier`; a unit's
      tier and run flags are the most demanding of its lexer modules' (tiers change in step I8);
    - the lexer modules are kept under `lexer_modules`, and `unit_of_lexer_module` maps each to the
      unit holding most of its functions. Harnesses stay per lexer module as sub-modules of a unit
      (their sidecar's `unit`; scripts/module_map.py).
    """
    units = {n: u for n, u in (model.get("units") or {}).items() if not u.get("test")}
    if not units:
        return dag
    order = sorted(units, key=lambda u: (_UNIT_KIND_ORDER.get(units[u].get("kind") or "", 2), u))
    names: dict[str, str] = {}
    for u in order:
        base = unit_module_name(u)
        name, n = base, 2
        while name in names.values():
            name, n = f"{base}_{n}", n + 1
        names[u] = name
    unit_of_file: dict[str, str] = {}
    for u in order:
        for f in units[u].get("files") or []:
            unit_of_file.setdefault(f, u)

    lexer_modules: dict[str, dict] = dag.get("modules") or {}
    functions: dict[str, dict] = dag.get("functions") or {}
    model_fns: dict[str, dict] = model.get("functions") or {}
    key_of = _model_key_of(model_fns)

    def home(rec: dict) -> str | None:
        if rec["file"] in unit_of_file:
            return unit_of_file[rec["file"]]
        compiled_in = [u for u in order if u in set(rec.get("units") or [])]
        return compiled_in[0] if compiled_in else None

    members: dict[str, list[str]] = defaultdict(list)
    lexer_votes: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for key, rec in functions.items():
        lexer_mod = str(rec.get("module") or "")
        rec["lexer_module"] = lexer_mod or None
        rec["tier"] = (lexer_modules.get(lexer_mod) or {}).get("tier") or _DEFAULT_TIER
        u = home(rec)
        if u is None:
            continue  # stays in its lexer module (kept below)
        rec["module"] = names[u]
        members[u].append(key)
        if lexer_mod:
            lexer_votes[lexer_mod][names[u]] += 1

    modules: dict[str, dict] = {}
    folded: list[str] = []
    for u in order:
        rec = units[u]
        name = names[u]
        sources, seen, stack = list(rec.get("files") or []), {u}, list(rec.get("links") or [])
        while stack:
            lk = stack.pop()
            if lk in seen or lk not in units:
                continue
            seen.add(lk)
            sources += [f for f in units[lk].get("files") or [] if f not in sources]
            stack += units[lk].get("links") or []
        fns = sorted(members.get(u, []))
        if not fns:
            # Every source belongs to an earlier unit (x509-parser's .so builds its .a's files).
            folded.append(f"unit {u}: compiles only sources of an earlier unit, analysed there")
            continue
        fn_set = set(fns)
        lexer_names = sorted({functions[k]["lexer_module"] for k in fns if functions[k].get("lexer_module")})
        tier_src = [lexer_modules[m] for m in lexer_names if m in lexer_modules]
        best = min(tier_src, key=lambda m: _tier_rank(m.get("tier")), default={})
        api = [*(rec.get("entry_points") or []), *(rec.get("embedded_api") or [])]
        entries = [k for k in dict.fromkeys(key_of[e] for e in api if e in key_of) if k in fn_set]
        flags, forced = unit_cppflags(
            list(rec.get("cppflags") or []),
            [f for m in tier_src for f in m.get("cppflags") or [] if isinstance(f, str)],
            root,
        )
        modules[name] = {
            "module": name,
            "unit": u,
            "kind": rec.get("kind"),
            "concurrent": bool(rec.get("concurrent")),
            "files": sorted(f for f in sources if unit_of_file.get(f) == u),
            "required_sources": sources,
            "cross_module_callees": sorted(
                {c for k in fns for c in functions[k].get("internal_callees") or [] if c not in fn_set}
            ),
            "external_callees": sorted({c for k in fns for c in functions[k].get("external_callees") or []}),
            "cppflags": flags,
            "force_includes": forced,
            "function_count": len(fns),
            "functions": fns,
            "provable_functions": [k for k in fns if functions[k].get("verifiability") != "shell_unverifiable_wp"],
            "shell_unverifiable_functions": [
                k for k in fns if functions[k].get("verifiability") == "shell_unverifiable_wp"
            ],
            "candidate_entry_points": entries or [k for k in fns if not functions[k].get("is_static")],
            "lexer_modules": lexer_names,
            "tier": best.get("tier") or _DEFAULT_TIER,
            "recommended_strategy": best.get("recommended_strategy"),
            "run_wp_full": any(m.get("run_wp_full") for m in tier_src),
            "run_eva": any(m.get("run_eva") for m in tier_src) or not tier_src,
            "run_eacsl_fuzz": any(m.get("run_eacsl_fuzz") for m in tier_src),
            # Step I7: the threat model's status for the unit, and each entry point's trust.
            "threat_model": (rec.get("trust") or {}).get("threat_model"),
            "entry_trust": {
                k: {t: functions[k]["trust"].get(t) for t in ("value", "source", "boundary")}
                for k in (entries or [])
                if isinstance(functions[k].get("trust"), dict)
            },
        }
    # Functions no unit compiles (none in a successful model) keep their lexer module.
    for key, rec in functions.items():
        if rec["module"] not in modules:
            base_mod = dict(lexer_modules.get(rec["module"]) or {"module": rec["module"], "tier": _DEFAULT_TIER})
            mod = modules.setdefault(rec["module"], {**base_mod, "functions": [], "lexer_modules": [rec["module"]]})
            mod["functions"] = sorted({*mod["functions"], key})
            mod["function_count"] = len(mod["functions"])

    return {
        **dag,
        "module_kind": "link_unit",
        "warnings": [*(dag.get("warnings") or []), *folded],
        "modules": modules,
        "lexer_modules": lexer_modules,
        "unit_of_lexer_module": {
            m: sorted(v.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] for m, v in sorted(lexer_votes.items())
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Call-Graph DAG and Topological Waves for Frama-C.")
    parser.add_argument("--target", type=Path, required=True, help="Target C repository or overlay work directory")
    parser.add_argument("--compile-commands", type=Path, default=None, help="Optional compile_commands.json path")
    parser.add_argument(
        "--emit-compile-commands",
        type=Path,
        default=None,
        help="Optional output path (in workspace/) to write synthesized compile_commands.json when no build is available",
    )
    parser.add_argument("--out", type=Path, required=True, help="Output JSON path for the DAG")
    parser.add_argument(
        "--model",
        type=Path,
        default=DEFAULT_MODEL,
        help=f"Phase 0 model (scripts/phase0_model.py) giving the functions and edges (default {DEFAULT_MODEL})",
    )
    parser.add_argument("--no-model", action="store_true", help="Lexer inventory and edges only (no model)")
    parser.add_argument(
        "--held-modules",
        action="store_true",
        help="With the model, keep the lexer's modules instead of the build's link units (step I5a's view)",
    )
    args = parser.parse_args()

    model, model_note = (None, "disabled (--no-model)") if args.no_model else load_model(args.model)
    cc_path = args.compile_commands or (args.target / "compile_commands.json")
    dag = build_dag(
        args.target, cc_path, emit_compile_commands=args.emit_compile_commands, model=model, units=not args.held_modules
    )
    if model_note:
        dag["warnings"] = [*dag.get("warnings", []), f"Phase 0 model not used: {model_note}"]
        print(f"warning: Phase 0 model not used: {model_note}", file=sys.stderr)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(dag, indent=2) + "\n", encoding="utf-8")

    summary = {
        "out": str(args.out),
        "callgraph_source": dag["callgraph_source"],
        "total_c_files": dag["total_c_files"],
        "total_functions": dag["total_functions"],
        "total_waves": dag["total_waves"],
        "modules": {k: v["tier"] for k, v in dag["modules"].items()},
    }
    if model is not None:
        summary["lexer_only_functions"] = len(dag["model"]["lexer_only_functions"])
        summary["gcc_fallback_units"] = dag["model"]["gcc_fallback_units"]
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
