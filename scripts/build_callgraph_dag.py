#!/usr/bin/env python3
"""
Builds the Function Call-Graph DAG, Topological Verification Waves (Wave 0..K),
Generic Structural Module Risk-Tier Classification, Per-Function WP Provability
Analysis (Verified Core vs. Unverified Shell), and Candidate Security Properties
using deterministic C/ACSL tokenization.
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
        if text == ";" and brace_depth == 0 and paren_depth == 0:
            last_top_boundary = idx
            idx += 1
            continue
        if text == "}" and paren_depth == 0:
            brace_depth = max(0, brace_depth - 1)
            if brace_depth == 0:
                last_top_boundary = idx
            idx += 1
            continue

        if text == "{":
            if brace_depth == 0 and paren_depth == 0:
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
            else:
                brace_depth += 1
                idx += 1
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
    Handles standard `ret fn(params)` and function-pointer returning `ret (*fn(params))(fp_params)`.
    """
    name_idx = open_params - 1
    if name_idx <= last_top_boundary:
        return None, [], []

    candidate = c_tokens[name_idx]
    if _is_ident(candidate.text):
        return (
            candidate.text,
            c_tokens[open_params + 1 : close_params],
            c_tokens[last_top_boundary + 1 : name_idx],
        )

    # Function-pointer returning declarator: `ret_type (*fn_name(params))(fp_params)`
    if candidate.text == ")":
        inner_open = _find_matching_backward(c_tokens, name_idx, "(", ")")
        if inner_open > last_top_boundary:
            # Look inside inner_open .. name_idx for `fn_name ( params )`
            inner_close_p = _strip_trailing_attributes(c_tokens, name_idx, inner_open)
            if inner_close_p > inner_open and c_tokens[inner_close_p].text == ")":
                inner_open_p = _find_matching_backward(c_tokens, inner_close_p, "(", ")")
                if inner_open_p > inner_open and _is_ident(c_tokens[inner_open_p - 1].text):
                    fn_tok = c_tokens[inner_open_p - 1]
                    return (
                        fn_tok.text,
                        c_tokens[inner_open_p + 1 : inner_close_p],
                        c_tokens[last_top_boundary + 1 : inner_open],
                    )
    return None, [], []


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

    return {
        "is_static": is_static,
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
) -> dict:
    """
    Analyze function body token stream for:
    - direct callees & self-recursion
    - indirect (function-pointer) calls requiring `//@ calls`
    - loop counts & unsigned wraparound loop idioms
    - WP blockers (backward/irreducible goto, dynamic memory allocation, pointer casts,
      container_of, volatile/inline asm)
    - structural security patterns (memory zeroization, formatting/serialization)
    """
    direct_callees: set[str] = set()
    indirect_calls: list[str] = []
    self_recursive = False

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

        if t in ("for", "while", "do"):
            loop_count += 1
            # Check for `while (count--)` or `while (--count)` unsigned wraparound idiom
            # Note: tokenize_c_acsl emits each `-` as a separate single-char c_token
            if t == "while" and i + 5 < n and body_tokens[i + 1].text == "(":
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
                elif prev not in param_names:
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
    if has_backward_goto:
        wp_blockers.append("irreducible_goto")
    if has_dynamic_alloc:
        wp_blockers.append("dynamic_allocation")
    if has_container_of:
        wp_blockers.append("container_of")
    if has_volatile_or_asm:
        wp_blockers.append("volatile_or_asm")

    wp_notes: list[str] = []
    if indirect_calls:
        wp_notes.append(f"indirect call(s) {indirect_calls} require '//@ calls <targets>;'")
    if self_recursive:
        wp_notes.append("recursive function requires 'decreases <measure>;'")
    if has_unsigned_wrap_idiom:
        wp_notes.append("unsigned decrement loop idiom may require --no-warn-unsigned")
    if has_pointer_cast:
        wp_notes.append("pointer cast may trigger incompatible pointer cast warning under Typed model")

    if wp_blockers:
        verifiability = "shell_unverifiable_wp"
    elif indirect_calls:
        verifiability = "needs_calls_annotation"
    else:
        verifiability = "core_provable"

    return {
        "has_loops": loop_count > 0,
        "loop_count": loop_count,
        "direct_callees": direct_callees,
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
        dirs[:] = [
            d for d in dirs if not d.startswith(".framac") and d not in {".git", "build", "CMakeFiles", "__pycache__"}
        ]
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
                flag = f"-I{(target_dir / rel_d).as_posix()}" if rel_d != "." else f"-I{target_dir.as_posix()}"
            except ValueError:
                flag = f"-I{d.as_posix()}"
            if flag not in flags:
                flags.append(flag)
        for d_flag in makefile_defines:
            if d_flag not in flags:
                flags.append(d_flag)
        result[rel_key] = flags

    return result


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
            rel_key = c_res.name
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


def build_dag(
    target_dir: Path,
    compile_commands_path: Path | None = None,
    emit_compile_commands: Path | None = None,
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
                c_files.append(fpath)
                cmd_str = entry.get("command", "") or " ".join(entry.get("arguments", []))
                flags = _filter_host_system_flags(re.findall(r"(?:-[IDU]\S+|-std=\S+)", cmd_str))
                try:
                    rel_key = fpath.relative_to(target_dir).as_posix()
                except ValueError:
                    rel_key = fpath.name
                compile_flags_by_file[rel_key] = flags

    if not c_files:
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [
                d
                for d in dirs
                if not d.startswith(".framac") and d not in {".git", "build", "CMakeFiles", "__pycache__"}
            ]
            for f in sorted(files):
                if f.endswith(".c"):
                    c_files.append((Path(root) / f).resolve())

    # Supplement missing per-file flags via build-free in-tree header/Makefile discovery
    discovered_flags = discover_in_tree_cppflags(target_dir, c_files)
    for rel_key, disc in discovered_flags.items():
        if not compile_flags_by_file.get(rel_key):
            compile_flags_by_file[rel_key] = disc

    if emit_compile_commands is not None:
        synthesize_compile_commands(target_dir, c_files, compile_flags_by_file, emit_compile_commands)

    functions: dict[str, dict] = {}
    name_collisions: list[dict] = []
    call_edges: dict[str, set[str]] = defaultdict(set)
    modules: dict[str, dict] = defaultdict(lambda: {"files": [], "functions": []})

    for c_file in sorted(set(c_files)):
        try:
            rel_path = c_file.relative_to(target_dir).as_posix()
        except ValueError:
            rel_path = c_file.name

        parts = Path(rel_path).parts
        if len(parts) >= 2 and parts[0] == "src":
            module_name = parts[1] if len(parts) > 2 else Path(rel_path).stem
        elif len(parts) >= 2:
            module_name = parts[0]
        else:
            module_name = Path(rel_path).stem

        modules[module_name]["files"].append(rel_path)

        raw_code = c_file.read_text(encoding="utf-8", errors="replace")
        extracted = extract_functions_from_code(raw_code, path=rel_path)

        for item in extracted:
            fn_name = item["name"]
            sig_info = analyze_signature(item["decl_tokens"], item["param_tokens"])
            body_info = analyze_body(fn_name, item["body_tokens"], sig_info)

            if fn_name in functions and functions[fn_name]["file"] != rel_path:
                existing_file = functions[fn_name]["file"]
                name_collisions.append({"function": fn_name, "files": [existing_file, rel_path]})
                # Prefer non-static (exported) definition over a file-local static helper
                if sig_info["is_static"] and not functions[fn_name].get("is_static", False):
                    continue

            functions[fn_name] = {
                "name": fn_name,
                "file": rel_path,
                "module": module_name,
                "line": item["line"],
                "end_line": item["end_line"],
                "loc": item["loc"],
                "is_static": sig_info["is_static"],
                "returns_pointer": sig_info["returns_pointer"],
                "params": sig_info["params_str"],
                "const_ptr_params": sig_info["const_ptr_params"],
                "mutable_ptr_params": sig_info["mutable_ptr_params"],
                "takes_bounded_buffer": sig_info["takes_bounded_buffer"],
                "writes_bounded_buffer": sig_info["writes_bounded_buffer"],
                "has_loops": body_info["has_loops"],
                "loop_count": body_info["loop_count"],
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
                "cppflags": compile_flags_by_file.get(rel_path, []),
            }
            call_edges[fn_name] = set(body_info["direct_callees"])
            if fn_name not in modules[module_name]["functions"]:
                modules[module_name]["functions"].append(fn_name)

    waves, cycles = compute_topological_waves(functions, call_edges)
    recursive_fns = {fn for scc in cycles for fn in scc}

    all_fns = set(functions.keys())
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
        closure_fns: set[str] = set(mod_fns)
        worklist: list[str] = list(mod_fns)
        while worklist:
            cur_fn = worklist.pop(0)
            for callee in functions.get(cur_fn, {}).get("internal_callees", []):
                if callee not in closure_fns and callee in functions:
                    closure_fns.add(callee)
                    worklist.append(callee)

        cross_module_callees = sorted(
            f for f in (closure_fns - mod_fn_set) if f in functions and functions[f]["file"] not in mod_files_set
        )
        required_sources = sorted(
            mod_files_set | {functions[f]["file"] for f in cross_module_callees if f in functions}
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

    return {
        "target_dir": str(target_dir),
        "callgraph_source": "regex",
        "total_c_files": len(set(c_files)),
        "total_functions": len(functions),
        "total_waves": len(waves),
        "name_collisions": name_collisions,
        "modules": module_summaries,
        "waves": [{"wave": idx, "count": len(w), "functions": w} for idx, w in enumerate(waves)],
        "recursion_cycles": cycles,
        "functions": functions,
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
    args = parser.parse_args()

    cc_path = args.compile_commands or (args.target / "compile_commands.json")
    dag = build_dag(args.target, cc_path, emit_compile_commands=args.emit_compile_commands)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(dag, indent=2) + "\n", encoding="utf-8")

    summary = {
        "out": str(args.out),
        "total_c_files": dag["total_c_files"],
        "total_functions": dag["total_functions"],
        "total_waves": dag["total_waves"],
        "modules": {k: v["tier"] for k, v in dag["modules"].items()},
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
