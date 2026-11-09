#!/usr/bin/env python3
"""
Generates a per-module dual-use C harness
(supporting both Frama-C Eva via eva_main() and Clang LibFuzzer via LLVMFuzzerTestOneInput()),
and a structured sidecar JSON (harness_<module>.json) tracking sources, preprocessor and
linker flags, entry reachability, contract notes, and harness repair attempts (capped at 2).
The sidecar is what `pipeline_make.py gen` builds the module's Make recipes from.

By default the generated harness is probed with `clang -fsyntax-only` and any
headers (from the -I directories) that define identifiers the module header
uses without including are auto-#included before it ("auto-prelude"); disable
with --no-auto-prelude.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import (  # noqa: E402
    atomic_write_json,
    load_json_optional,
    load_json_strict,
    normalize_flag_args,
    utc_now,
)

DEFAULT_TEMPLATE_DIR = Path("/opt/framac-pipeline/templates")
MAX_HARNESS_REPAIR_ATTEMPTS = 2
VALID_ENTRY_STYLES = (
    "buffer_len",
    "global_buffer",
    "struct_arg",
    "void_call",
    "c_string",
    "custom",
    "auto_prototype",
    "argv",
    "dispatch",
)
# Compile-time bit mask of dispatch cases a fuzz build skips (run_eacsl_fuzz.py campaign rounds):
# DISPATCH_SKIP_MACRO holds cases 0..63, DISPATCH_SKIP_MACRO_<k> cases 64k..64k+63. A harness whose
# guard carries DISPATCH_SKIP_ALL_MARKER reads every word; one generated before it reads cases 0..63 only.
DISPATCH_SKIP_MACRO = "FRAMAC_FUZZ_SKIP_CASES"
DISPATCH_SKIP_ALL_MARKER = "every dispatch case skippable"
_WORKSPACE_PREFIXES = (
    "/framac-run/workspace/work/",
    "/framac-run/workspace/baseline/",
    "workspace/work/",
    "workspace/baseline/",
    "/target/",
)


_C_IDENT_JUNK = re.compile(r"\W")  # a module name in a C identifier


def resolve_template_dir() -> Path:
    if DEFAULT_TEMPLATE_DIR.exists():
        return DEFAULT_TEMPLATE_DIR
    return Path(__file__).resolve().parent.parent / "templates"


def _normalize_run_rel_dir(dir_str: str) -> str:
    norm = (dir_str or "").replace("\\", "/").strip()
    if norm.startswith("/framac-run/"):
        norm = norm[len("/framac-run/") :]
    elif norm == "/framac-run":
        norm = "."
    elif norm.startswith("/target/"):
        norm = f"workspace/work/{norm[len('/target/') :]}"
    elif norm == "/target":
        norm = "workspace/work"
    while norm.startswith("./"):
        norm = norm[2:]
    return norm.rstrip("/") or "."


def _append_cppflag(cppflags: str, flag: str) -> str:
    existing = _split_cppflags(cppflags)
    if flag not in existing:
        return f"{cppflags} {shlex.quote(flag)}".strip()
    return cppflags.strip()


def _normalize_header_include(header_include: str | None, cppflags: str) -> tuple[str | None, str]:
    """
    If `header_include` is passed as a workspace/target file path (e.g.
    `workspace/work/src/LibPtfCom/PtfMsg.h`), add `-I<parent_dir>` to `cppflags`
    and emit `#include "PtfMsg.h"` so compilers running from any working directory
    resolve the header cleanly. Returns `(None, updated_flags)` when `header_include`
    is omitted or `"none"`.
    """
    norm = (header_include or "").replace("\\", "/").strip()
    updated_flags = (cppflags or "-I.").strip()
    if not norm or norm.lower() == "none":
        return None, updated_flags
    p = Path(norm)
    parent_posix = _normalize_run_rel_dir(p.parent.as_posix())
    has_ws_prefix = any(norm.startswith(pref) for pref in _WORKSPACE_PREFIXES)
    if (has_ws_prefix or p.is_file()) and parent_posix not in ("", "."):
        updated_flags = _append_cppflag(updated_flags, f"-I{parent_posix}")
        return p.name, updated_flags
    return norm, updated_flags


def _wrap_null_terminated(eva_inner: str, fuzz_inner: str) -> tuple[str, str]:
    eva_wrapped = f"input_buf[input_len < MAX_INPUT_SIZE ? input_len : (MAX_INPUT_SIZE - 1)] = 0;\n    {eva_inner}"
    fuzz_wrapped = (
        "uint8_t *cstr_buf = (uint8_t *)malloc(size + 1U);\n"
        "    if (cstr_buf != NULL) {\n"
        "        if (size > 0) { memcpy(cstr_buf, bounded_buf, size); }\n"
        "        cstr_buf[size] = 0;\n"
        "        fuzz_buf = cstr_buf;\n"
        f"        {fuzz_inner}\n"
        "        free(cstr_buf);\n"
        "    }"
    )
    return eva_wrapped, fuzz_wrapped


_PARAM_DECL_RE = re.compile(
    r"^(?P<type_part>.*?)(?P<stars>(?:\*\s*)+)?(?P<name>[A-Za-z_]\w*)\s*(?P<array>\[[^\]]*\])?$"
)
_FN_PTR_PARAM_RE = re.compile(r"^(?P<ret>.+?)\(\s*\*(?P<inner>[^)]*)\)\s*\((?P<args>.*)\)$")
_FN_TYPE_PARAM_RE = re.compile(r"^(?P<head>[^(]+)\((?P<args>.*)\)$")
_C_PP_DIRECTIVE_RE = re.compile(r"^[ \t]*#[^\n]*(?:\\\r?\n[^\n]*)*", re.MULTILINE)
_CPP_GUARD_RE = re.compile(
    r"#[ \t]*if(?:def)?[ \t]+(?:defined[ \t]*\([ \t]*)?__cplusplus\b.*?#[ \t]*endif\b",
    re.DOTALL,
)
_C_TYPE_KEYWORDS = frozenset(
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
        "bool",
        "_Bool",
        "const",
        "volatile",
        "restrict",
        "__restrict",
        "__restrict__",
        "struct",
        "union",
        "enum",
    }
)
_C_QUALIFIER_OR_TAG_ONLY = frozenset(
    {
        "const",
        "volatile",
        "restrict",
        "__restrict",
        "__restrict__",
        "struct",
        "union",
        "enum",
    }
)


def _find_matching_paren(text: str, open_pos: int) -> int:
    """Return index of ')' matching '(' at `open_pos`, or -1 if unmatched."""
    depth = 0
    in_str: str | None = None
    i = open_pos
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = ch
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _strip_gcc_attributes(text: str) -> str:
    """Remove `__attribute__((...))` and `__asm__(...)` / `asm(...)` clauses with balanced parens."""
    out: list[str] = []
    i = 0
    n = len(text)
    attr_re = re.compile(r"\b(?:__attribute__|__asm__|asm)\s*\(")
    while i < n:
        m = attr_re.search(text, i)
        if not m:
            out.append(text[i:])
            break
        out.append(text[i : m.start()])
        open_pos = m.end() - 1
        close_pos = _find_matching_paren(text, open_pos)
        if close_pos < 0:
            out.append(text[m.start() :])
            break
        i = close_pos + 1
    return "".join(out)


def _has_concrete_type_token(type_part: str) -> bool:
    tokens = re.findall(r"[A-Za-z_]\w*", type_part)
    return any(tok not in _C_QUALIFIER_OR_TAG_ONLY for tok in tokens)


def _parse_c_param(raw_param: str, index: int) -> dict[str, Any]:
    clean = " ".join(_strip_gcc_attributes(raw_param).replace("\n", " ").split()).strip()
    m_fp = _FN_PTR_PARAM_RE.match(clean)
    if m_fp:
        ret = m_fp.group("ret").strip()
        inner = m_fp.group("inner").strip()
        args = m_fp.group("args").strip()
        ident_matches = [
            tok
            for tok in re.findall(r"[A-Za-z_]\w*", inner)
            if tok not in ("const", "volatile", "restrict", "__restrict", "__restrict__")
        ]
        if ident_matches:
            name = ident_matches[-1]
            inner_quals = re.sub(rf"\b{re.escape(name)}\b", "", inner).strip()
        else:
            name = f"arg_{index}"
            inner_quals = inner
        star_part = f"* {inner_quals}".strip() if inner_quals else "*"
        full_type = f"{ret} ({star_part})({args})"
        return {
            "raw": clean,
            "type": full_type,
            "pointee_type": full_type,
            "name": name,
            "is_pointer": True,
            "is_fn_pointer": True,
            "is_const": False,
        }

    m_ft = _FN_TYPE_PARAM_RE.match(clean)
    if m_ft:
        head = m_ft.group("head").strip()
        args = m_ft.group("args").strip()
        m_head = re.match(r"^(?P<ret>.*?)\b(?P<name>[A-Za-z_]\w*)$", head)
        if m_head:
            cand_ret = m_head.group("ret").strip()
            cand_name = m_head.group("name").strip()
            if cand_name not in _C_TYPE_KEYWORDS and _has_concrete_type_token(cand_ret):
                ret = cand_ret
                name = cand_name
            else:
                ret = head
                name = f"arg_{index}"
        else:
            ret = head
            name = f"arg_{index}"
        full_type = f"{ret} (*)({args})"
        return {
            "raw": clean,
            "type": full_type,
            "pointee_type": full_type,
            "name": name,
            "is_pointer": True,
            "is_fn_pointer": True,
            "is_const": False,
        }

    m = _PARAM_DECL_RE.match(clean)
    if m:
        type_part = m.group("type_part").strip()
        stars = (m.group("stars") or "").strip()
        cand_name = m.group("name").strip()
        array = (m.group("array") or "").strip()
    else:
        type_part = ""
        stars = ""
        cand_name = ""
        array = ""

    if m and cand_name not in _C_TYPE_KEYWORDS and _has_concrete_type_token(type_part):
        name = cand_name
        full_type = f"{type_part} {stars}".strip()
        if array:
            full_type = f"{full_type} *"
    else:
        array_m = re.search(r"\[[^\]]*\]\s*$", clean)
        if array_m:
            base = clean[: array_m.start()].strip()
            full_type = f"{base} *".strip()
            array = array_m.group(0).strip()
        else:
            full_type = clean
            array = ""
        name = f"arg_{index}"
        stars = "*" if "*" in full_type else ""

    is_pointer = ("*" in full_type) or bool(array)
    is_const = bool(re.search(r"\bconst\b", full_type))
    pointee_type = re.sub(r"\b(?:const|volatile|restrict|__restrict|__restrict__)\b", " ", full_type)
    pointee_type = pointee_type.replace("*", " ")
    pointee_type = " ".join(pointee_type.split()).strip() or "int"
    if pointee_type == "void":
        pointee_type = "uint8_t"

    return {
        "raw": clean,
        "type": full_type,
        "pointee_type": pointee_type,
        "name": name,
        "is_pointer": is_pointer,
        "is_fn_pointer": False,
        "is_const": is_const,
    }


def _split_top_level_params(params_raw: str) -> list[str]:
    """
    Split a C parameter or argument list on commas at top-level depth 0, counting
    parentheses, brackets and braces (so a compound-literal argument such as
    `(UsefulBuf){buf, sizeof(buf)}` stays one argument).
    """
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in params_raw:
        if ch in ("(", "[", "{"):
            depth += 1
            cur.append(ch)
        elif ch in (")", "]", "}"):
            if depth > 0:
                depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            part = "".join(cur).strip()
            if part and part != "...":
                parts.append(part)
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail and tail != "...":
        parts.append(tail)
    return parts


def _strip_brace_bodies(text: str) -> str:
    """Replace top-level `{ ... }` blocks with `{}` so calls inside function bodies are ignored."""
    out: list[str] = []
    depth = 0
    in_str: str | None = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                if depth == 0:
                    out.append(text[i : i + 2])
                i += 2
                continue
            if ch == in_str:
                in_str = None
            if depth == 0:
                out.append(ch)
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = ch
            if depth == 0:
                out.append(ch)
            i += 1
            continue
        if ch == "{":
            if depth == 0:
                out.append("{")
            depth += 1
            i += 1
            continue
        if ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0:
                    out.append("}")
            else:
                out.append("}")
            i += 1
            continue
        if depth == 0:
            out.append(ch)
        i += 1
    return "".join(out)


def _prepare_prototype_search_text(raw_text: str) -> str:
    """Strip comments, C++ extern guards, preprocessor directives, GCC attributes, and brace bodies."""
    no_comments = _strip_c_comments(raw_text)
    no_cpp_guards = _CPP_GUARD_RE.sub(" ", no_comments)
    no_pp = _C_PP_DIRECTIVE_RE.sub(" ", no_cpp_guards)
    no_attrs = _strip_gcc_attributes(no_pp)
    return _strip_brace_bodies(no_attrs)


def _collect_prototype_search_paths(
    header_include: str | None = None,
    sources: list[str] | None = None,
    cppflags: str = "-I.",
) -> list[Path]:
    search_paths: list[Path] = []
    include_dirs = _include_dirs_from_cppflags(cppflags)
    if header_include and header_include.lower() != "none":
        hp = Path(header_include.replace("\\", "/").strip())
        if hp.is_file():
            search_paths.append(hp)
        for inc_dir in include_dirs:
            cand = inc_dir / hp.name
            if cand.is_file() and cand not in search_paths:
                search_paths.append(cand)
        ws_cand = Path("workspace/work") / hp
        if ws_cand.is_file() and ws_cand not in search_paths:
            search_paths.append(ws_cand)

    for src in sources or []:
        sp = Path(src.replace("\\", "/").strip())
        if sp.is_file() and sp not in search_paths:
            search_paths.append(sp)
        for inc_dir in include_dirs:
            cand = inc_dir / sp.name
            if cand.is_file() and cand not in search_paths:
                search_paths.append(cand)
        ws_sp = Path("workspace/work") / sp
        if ws_sp.is_file() and ws_sp not in search_paths:
            search_paths.append(ws_sp)
    return search_paths


def extract_function_declaration(
    entry_fn: str,
    header_include: str | None = None,
    sources: list[str] | None = None,
    cppflags: str = "-I.",
) -> str | None:
    """
    Extract a C forward declaration (`<ret> <entry_fn>(<params>);`) from `header_include` or `sources`,
    stripping any leading `static` storage class so a multi-TU harness can declare it when `--header` is omitted.
    """
    search_paths = _collect_prototype_search_paths(header_include, sources, cppflags)
    sig_head_re = re.compile(
        rf"(?P<head>(?:[\w]+(?:\s+|\s*\*+\s*))+\**\s*\b{re.escape(entry_fn)})\s*\(",
        re.DOTALL,
    )
    for path in search_paths:
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            text = _prepare_prototype_search_text(raw_text)
        except OSError:
            continue
        for m in sig_head_re.finditer(text):
            open_pos = m.end() - 1
            close_pos = _find_matching_paren(text, open_pos)
            if close_pos < 0:
                continue
            trailing = text[close_pos + 1 :].lstrip()
            if not trailing.startswith((";", "{")):
                continue
            head = " ".join(m.group("head").split())
            head = re.sub(r"\b(?:static|inline|__inline__|__inline)\b\s*", "", head).strip() or f"int {entry_fn}"
            params_raw = " ".join(text[open_pos + 1 : close_pos].split()).strip() or "void"
            return f"{head}({params_raw});"
    return None


_FUZZER_ENTRY_DEF_RE = re.compile(r"\bLLVMFuzzerTestOneInput\s*\([^;{)]*\)\s*\{")
_FUZZER_INIT_DEF_RE = re.compile(r"\bLLVMFuzzerInitialize\s*\([^;{)]*\)\s*\{")

# A target's own libFuzzer hooks, renamed by -D in the sidecar cppflags so the generated harness's
# LLVMFuzzerTestOneInput (and the E-ACSL runtime's LLVMFuzzerInitialize, templates/eacsl_runtime/
# fuzz_init.c, compiled without the cppflags) stay the only ones at link time. run_eacsl_fuzz.py treats
# every name with this prefix as harness code (no RTE selection, never a crash location).
TARGET_EMBEDDED_PREFIX = "__framac_target_embedded_"
TARGET_EMBEDDED_ENTRY = f"{TARGET_EMBEDDED_PREFIX}LLVMFuzzerTestOneInput"
TARGET_EMBEDDED_INIT = f"{TARGET_EMBEDDED_PREFIX}LLVMFuzzerInitialize"
DEFAULT_MAX_INPUT_SIZE = 1500
# A target fuzz module's input bound when neither --max-size nor fuzz_assets.json gives one.
TARGET_FUZZER_DEFAULT_MAX_INPUT_SIZE = 4096
_TARGET_FUZZER_ID_JUNK = re.compile(r"[^A-Za-z0-9_.+-]")


def _source_defines(src: str, pattern: re.Pattern[str], cppflags: str = "-I.") -> bool:
    for p in _collect_prototype_search_paths(None, [src], cppflags):
        try:
            text = _strip_c_comments(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if pattern.search(text):
            return True
    return False


def _source_defines_fuzzer_entry(src: str, cppflags: str = "-I.") -> bool:
    """Return True if `src` defines `LLVMFuzzerTestOneInput(...) { ... }`."""
    return _source_defines(src, _FUZZER_ENTRY_DEF_RE, cppflags)


def _source_defines_fuzzer_initialize(src: str, cppflags: str = "-I.") -> bool:
    """Return True if `src` defines `LLVMFuzzerInitialize(...) { ... }`."""
    return _source_defines(src, _FUZZER_INIT_DEF_RE, cppflags)


def _read_target_fuzzer_text(src: str) -> str | None:
    """The target fuzzer's text without comments: `src` itself, else under workspace/work/; None if missing."""
    sp = Path(src.replace("\\", "/").strip())
    for cand in (sp, Path("workspace/work") / sp):
        if cand.is_file():
            try:
                return _strip_c_comments(cand.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                return None
    return None


def resolve_target_fuzzer_id(src: str, explicit: str | None = None) -> str:
    """The target fuzz module's id: `explicit` (checked), else the source's stem with other chars as `_`."""
    if explicit is not None:
        if not explicit or _TARGET_FUZZER_ID_JUNK.search(explicit):
            raise ValueError(f"invalid --target-fuzzer-id {explicit!r}: use only [A-Za-z0-9_.+-]")
        return explicit
    stem = Path(src.replace("\\", "/").strip()).stem
    return _TARGET_FUZZER_ID_JUNK.sub("_", stem) or "fuzzer"


def target_fuzzer_max_input_size(out_dir: Path, src: str, fuzzer_id: str | None = None) -> int:
    """
    A target fuzz module's `max_input_size` without --max-size: the `suggested_max_input_size` of its
    row in workspace/reports/fuzz_assets.json (scripts/fuzz_assets.py; the row whose `work_path` is
    `src`, else whose `id` is `fuzzer_id`), else TARGET_FUZZER_DEFAULT_MAX_INPUT_SIZE.
    """
    norm_src = _normalize_run_rel_dir(src)
    for path in (out_dir.parent / "reports" / "fuzz_assets.json", Path("workspace/reports/fuzz_assets.json")):
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rows = data.get("fuzzers") if isinstance(data, dict) else None
        rows = [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
        match = next(
            (
                r
                for r in rows
                if isinstance(r.get("work_path"), str) and _normalize_run_rel_dir(r["work_path"]) == norm_src
            ),
            None,
        )
        if match is None and fuzzer_id:
            match = next((r for r in rows if r.get("id") == fuzzer_id), None)
        size = match.get("suggested_max_input_size") if match else None
        if isinstance(size, int) and not isinstance(size, bool) and size > 0:
            return size
        break
    return TARGET_FUZZER_DEFAULT_MAX_INPUT_SIZE


def _target_fuzzer_prelude(initialize: bool) -> str:
    """Declarations (and the run-once LLVMFuzzerInitialize call) a target fuzz harness needs."""
    lines = [
        "/* Target fuzz module: the target's own fuzz target, renamed by -D in the sidecar cppflags. */",
        f"int {TARGET_EMBEDDED_ENTRY}(const uint8_t *data, size_t size);",
    ]
    if initialize:
        lines += [
            f"int {TARGET_EMBEDDED_INIT}(int *argc, char ***argv);",
            "static int __framac_target_initialized = 0;",
            "static void __framac_target_initialize_once(void) {",
            '    static char framac_target_argv0[] = "framac_target_fuzzer";',
            "    static char *framac_target_argv[2] = {framac_target_argv0, NULL};",
            "    int framac_target_argc = 1;",
            "    char **framac_target_argvp = framac_target_argv;",
            "    if (__framac_target_initialized) {",
            "        return;",
            "    }",
            "    __framac_target_initialized = 1;",
            f"    (void){TARGET_EMBEDDED_INIT}(&framac_target_argc, &framac_target_argvp);",
            "}",
        ]
    return "\n".join(lines)


def _target_fuzzer_invocation(initialize: bool) -> str:
    """The call of the target's fuzz function on the harness's own copy of the input (both builds)."""
    call = f"(void){TARGET_EMBEDDED_ENTRY}(fuzz_buf, fuzz_len);"
    return f"__framac_target_initialize_once();\n    {call}" if initialize else call


def extract_function_prototype(
    entry_fn: str,
    header_include: str | None = None,
    sources: list[str] | None = None,
    cppflags: str = "-I.",
) -> list[dict[str, Any]]:
    """
    Locate the C declaration or definition of `entry_fn` in `header_include` or `sources`
    and return its parsed parameter list.
    """
    search_paths = _collect_prototype_search_paths(header_include, sources, cppflags)

    sig_head_re = re.compile(
        rf"(?:[\w]+(?:\s+|\s*\*+\s*))+\**\s*\b{re.escape(entry_fn)}\s*\(",
        re.DOTALL,
    )
    for path in search_paths:
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            text = _prepare_prototype_search_text(raw_text)
        except OSError:
            continue
        for m in sig_head_re.finditer(text):
            open_pos = m.end() - 1
            close_pos = _find_matching_paren(text, open_pos)
            if close_pos < 0:
                continue
            trailing = text[close_pos + 1 :].lstrip()
            if not trailing.startswith((";", "{")):
                continue
            params_raw = text[open_pos + 1 : close_pos].strip()
            if not params_raw or params_raw == "void":
                return []
            parts = _split_top_level_params(params_raw)
            return [_parse_c_param(p, idx) for idx, p in enumerate(parts)]

    raise ValueError(
        f"Could not locate C prototype for function {entry_fn!r} in header {header_include!r} or sources {sources!r}"
    )


def _find_declaring_header(entry_fn: str, cppflags: str, exclude: set[str], max_headers: int = 400) -> str | None:
    """
    Find a header in the -I directories that declares `entry_fn` (used when the requested
    --header does not declare the entry function, e.g. a public header while the entry
    lives in a module-internal header). Returns the header's include name, or None.
    """
    for inc_dir in _include_dirs_from_cppflags(cppflags):
        if not inc_dir.is_dir():
            continue
        for h in sorted(inc_dir.glob("*.h"))[:max_headers]:
            if h.name in exclude:
                continue
            try:
                if extract_function_declaration(entry_fn, str(h), None, cppflags) is not None:
                    return h.name
            except Exception:
                continue
    return None


def _validate_call_expr_arity(entry_fn: str, call_expr: str, sources: list[str], cppflags: str) -> None:
    """
    Validate a custom call expression's argument count against the entry function's
    definition parsed from `sources` (not the DAG's truncated params string, which has
    cost real runs wrong arities, e.g. crypt_init_chacha20_poly takes 9 parameters).
    """
    try:
        params = extract_function_prototype(entry_fn, None, sources, cppflags)
    except ValueError:
        return
    m = re.search(rf"\b{re.escape(entry_fn)}\s*\(", call_expr)
    if not m:
        return
    open_pos = m.end() - 1
    close_pos = _find_matching_paren(call_expr, open_pos)
    if close_pos < 0:
        return
    args_raw = call_expr[open_pos + 1 : close_pos].strip()
    argc = 0 if not args_raw or args_raw == "void" else len(_split_top_level_params(args_raw))
    if argc != len(params):
        raise ValueError(
            f"call_expr passes {argc} argument(s) to {entry_fn!r} but its definition in the sources "
            f"takes {len(params)}; check the arity against the definition, not the DAG params string"
        )


def _is_c_string_param(param: dict[str, Any], next_param: dict[str, Any] | None) -> bool:
    if not param["is_pointer"] or param.get("is_fn_pointer"):
        return False
    pt = param["pointee_type"]
    if pt != "char":
        return False
    if next_param and not next_param["is_pointer"]:
        next_name = next_param["name"].lower()
        if any(k in next_name for k in ("len", "size", "count", "cap")):
            return False
    return True


def _is_buf_len_pair(param: dict[str, Any], next_param: dict[str, Any] | None) -> bool:
    if not param["is_pointer"] or param.get("is_fn_pointer") or next_param is None or next_param["is_pointer"]:
        return False
    pt = param["pointee_type"].lower()
    next_pt = next_param["pointee_type"].lower()
    next_name = next_param["name"].lower()
    is_int_like = any(k in next_pt for k in ("int", "size_t", "ssize_t", "long", "short", "unsigned", "len", "word"))
    if not is_int_like:
        return False
    if any(k in pt for k in ("uint8_t", "unsigned char", "int8_t", "byte", "uchar")) or param["type"].replace(
        "const", ""
    ).strip().startswith("void"):
        return True
    if pt == "char" and any(k in next_name for k in ("len", "size", "count", "cap")):
        return True
    return False


def _build_auto_prototype_invocations(
    entry_fn: str,
    params: list[dict[str, Any]],
) -> tuple[str, str, bool]:
    """
    Synthesize dual Eva (`eva_main`) and LibFuzzer (`LLVMFuzzerTestOneInput`) argument
    unpacking and invocation statements from a parsed C parameter list.
    Returns `(eva_stmt, fuzz_stmt, needs_null_terminate)`.
    """
    if not params:
        return (
            f"(void)input_buf; (void)input_len; {entry_fn}();",
            f"(void)bounded_buf; {entry_fn}();",
            False,
        )

    eva_lines: list[str] = []
    fuzz_lines: list[str] = ["size_t fuzz_off = 0;"]
    eva_args: list[str] = []
    fuzz_args: list[str] = []
    needs_null_terminate = False
    used_primary_buf = False

    i = 0
    while i < len(params):
        p = params[i]
        next_p = params[i + 1] if (i + 1) < len(params) else None

        if _is_buf_len_pair(p, next_p):
            assert next_p is not None
            ptr_cast = f"({p['type']})"
            len_cast = f"({next_p['type']})"
            if not used_primary_buf:
                used_primary_buf = True
                eva_args.append(f"{ptr_cast}fuzz_buf")
                eva_args.append(f"{len_cast}fuzz_len")
                fuzz_args.append(f"{ptr_cast}(fuzz_buf + fuzz_off)")
                fuzz_args.append(f"{len_cast}(fuzz_len - fuzz_off)")
            else:
                vname = f"arg_{i}"
                eva_lines.append(f"uint8_t {vname}[MAX_INPUT_SIZE];")
                eva_lines.append(f"Frama_C_make_unknown((char *){vname}, sizeof({vname}));")
                eva_args.append(f"{ptr_cast}{vname}")
                eva_args.append(f"{len_cast}sizeof({vname})")
                fuzz_lines.append(f"uint8_t {vname}[MAX_INPUT_SIZE];")
                fuzz_lines.append(f"memset({vname}, 0, sizeof({vname}));")
                fuzz_args.append(f"{ptr_cast}{vname}")
                fuzz_args.append(f"{len_cast}sizeof({vname})")
            i += 2
            continue

        if _is_c_string_param(p, next_p):
            ptr_cast = f"({p['type']})"
            if not used_primary_buf:
                used_primary_buf = True
                needs_null_terminate = True
                eva_args.append(f"{ptr_cast}fuzz_buf")
                fuzz_args.append(f"{ptr_cast}(fuzz_buf + fuzz_off)")
            else:
                vname = f"arg_{i}"
                eva_lines.append(f"char {vname}[MAX_INPUT_SIZE + 1];")
                eva_lines.append(f"Frama_C_make_unknown({vname}, MAX_INPUT_SIZE);")
                eva_lines.append(f"{vname}[MAX_INPUT_SIZE] = '\\0';")
                eva_args.append(f"{ptr_cast}{vname}")
                fuzz_lines.append(f"char {vname}[MAX_INPUT_SIZE + 1];")
                fuzz_lines.append(f"memset({vname}, 0, sizeof({vname}));")
                fuzz_args.append(f"{ptr_cast}{vname}")
            i += 1
            continue

        if p.get("is_fn_pointer"):
            eva_args.append("NULL")
            fuzz_args.append("NULL")
            i += 1
            continue

        if p["is_pointer"]:
            pt = p["pointee_type"]
            vname = f"arg_{i}"
            eva_lines.append(f"{pt} {vname};")
            eva_lines.append(f"Frama_C_make_unknown((char *)&{vname}, sizeof({vname}));")
            eva_args.append(f"&{vname}")

            fuzz_lines.append(f"{pt} {vname};")
            fuzz_lines.append(f"memset(&{vname}, 0, sizeof({vname}));")
            fuzz_lines.append(
                f"if (fuzz_len >= fuzz_off + sizeof({vname})) {{ "
                f"memcpy(&{vname}, fuzz_buf + fuzz_off, sizeof({vname})); "
                f"fuzz_off += sizeof({vname}); }}"
            )
            fuzz_args.append(f"&{vname}")
            i += 1
            continue

        # Scalar integer / enum / struct-by-value parameter
        st = p["pointee_type"]
        vname = f"arg_{i}"
        eva_lines.append(f"{st} {vname};")
        eva_lines.append(f"Frama_C_make_unknown((char *)&{vname}, sizeof({vname}));")
        eva_args.append(vname)

        fuzz_lines.append(f"{st} {vname};")
        fuzz_lines.append(f"memset(&{vname}, 0, sizeof({vname}));")
        fuzz_lines.append(
            f"if (fuzz_len >= fuzz_off + sizeof({vname})) {{ "
            f"memcpy(&{vname}, fuzz_buf + fuzz_off, sizeof({vname})); "
            f"fuzz_off += sizeof({vname}); }}"
        )
        fuzz_args.append(vname)
        i += 1

    if not used_primary_buf:
        eva_lines.insert(0, "(void)fuzz_buf; (void)fuzz_len;")
        fuzz_lines.insert(0, "(void)fuzz_buf; (void)fuzz_len;")

    eva_lines.append(f"{entry_fn}({', '.join(eva_args)});")
    fuzz_lines.append(f"{entry_fn}({', '.join(fuzz_args)});")
    eva_stmt = "\n    ".join(eva_lines)
    fuzz_stmt = "\n    ".join(fuzz_lines)
    return eva_stmt, fuzz_stmt, needs_null_terminate


def _build_dispatch_invocation(cases: list[str]) -> str:
    """
    One harness that drives several API calls: the first input byte selects a case and the
    rest of the input is the case's `fuzz_buf`/`fuzz_len`. Eva sees an unknown selector, so one
    analysis covers every case. Cases must not `return` (the fuzz side frees its buffer after).

    A campaign that already crashed in some cases rebuilds with -DFRAMAC_FUZZ_SKIP_CASES=<bit mask>
    (bit i skips case i, cases 0..63) and -DFRAMAC_FUZZ_SKIP_CASES_<k>=<mask> for cases 64k..64k+63,
    so the known crash stops ending every run. A word not given skips nothing. Eva never sees it.
    """
    stmts = [c.strip() for c in cases if c and c.strip()]
    if not stmts:
        raise ValueError("entry_style 'dispatch' requires at least one --dispatch-case")
    n = len(stmts)
    case = f"(harness_selector % {n}U)"
    n_words = (n + 63) // 64
    # The mask word of the selected case: word k for cases 64k..64k+63 (no comma, so the -D values
    # never pass through a comma-separated option list).
    word = f"(unsigned long long)({DISPATCH_SKIP_MACRO}_{n_words - 1})" if n_words > 1 else ""
    for k in range(n_words - 2, -1, -1):
        name = DISPATCH_SKIP_MACRO if k == 0 else f"{DISPATCH_SKIP_MACRO}_{k}"
        word = f"({case} < {64 * (k + 1)}U ? (unsigned long long)({name}) : {word})"
    if n_words == 1:
        word = f"((unsigned long long)({DISPATCH_SKIP_MACRO}))"
    # Joined with a newline plus 4 spaces under the template's indent, so nested lines carry 4 more.
    lines = [
        "if (fuzz_len > 0) {",
        "    uint8_t harness_selector = fuzz_buf[0];",
        "    fuzz_buf += 1;",
        "    fuzz_len -= 1;",
        f"#ifdef {DISPATCH_SKIP_MACRO}",
        f"    /* {DISPATCH_SKIP_ALL_MARKER}: {DISPATCH_SKIP_MACRO}_<k> holds cases 64k..64k+63 */",
    ]
    for k in range(1, n_words):
        lines += [
            f"#ifndef {DISPATCH_SKIP_MACRO}_{k}",
            f"#define {DISPATCH_SKIP_MACRO}_{k} 0ULL",
            "#endif",
        ]
    lines += [
        f"    if ((({word} >> ({case} & 63U)) & 1ULL) == 0ULL)",
        "#endif",
        f"    switch (harness_selector % {n}U) {{",
    ]
    for i, stmt in enumerate(stmts):
        lines.append(f"    case {i}U: {{ {stmt} }} break;")
    lines += ["    default: break;", "    }", "}"]
    return "\n    ".join(lines)


def _build_invocations(
    entry_fn: str,
    entry_style: str,
    global_buf: str | None = None,
    global_len: str | None = None,
    struct_type: str | None = None,
    call_expr: str | None = None,
    eva_expr: str | None = None,
    fuzz_expr: str | None = None,
    null_terminate: bool = False,
    auto_params: list[dict[str, Any]] | None = None,
    dispatch_cases: list[str] | None = None,
) -> tuple[str, str]:
    if entry_style == "dispatch":
        stmt = _build_dispatch_invocation(dispatch_cases or [])
        if null_terminate:
            return _wrap_null_terminated(stmt, stmt)
        return stmt, stmt
    if entry_style == "auto_prototype":
        eva_stmt, fuzz_stmt, auto_nt = _build_auto_prototype_invocations(entry_fn, auto_params or [])
        if null_terminate or auto_nt:
            return _wrap_null_terminated(eva_stmt, fuzz_stmt)
        return eva_stmt, fuzz_stmt
    if entry_style == "buffer_len":
        eva_call, fuzz_call = f"{entry_fn}(input_buf, input_len);", f"{entry_fn}(bounded_buf, size);"
        if null_terminate:
            return _wrap_null_terminated(f"{entry_fn}(fuzz_buf, fuzz_len);", f"{entry_fn}(fuzz_buf, fuzz_len);")
        return eva_call, fuzz_call
    if entry_style == "c_string":
        call_stmt = f"{entry_fn}((const char *)fuzz_buf);"
        return _wrap_null_terminated(call_stmt, call_stmt)
    if entry_style == "custom":
        e_stmt = (eva_expr or call_expr or "").strip()
        f_stmt = (fuzz_expr or call_expr or "").strip()
        if not e_stmt or not f_stmt:
            raise ValueError("entry_style 'custom' requires --call-expr (or both --eva-expr and --fuzz-expr)")
        if null_terminate:
            return _wrap_null_terminated(e_stmt, f_stmt)
        return e_stmt, f_stmt
    if entry_style == "global_buffer":
        if not global_buf:
            raise ValueError("entry_style 'global_buffer' requires global_buf")
        len_eva = f" {global_len} = input_len;" if global_len else ""
        len_fuzz = f" {global_len} = size;" if global_len else ""
        eva_call = (
            f"if (input_len > 0) {{ memcpy((void *){global_buf}, input_buf, input_len); }}{len_eva} {entry_fn}();"
        )
        fuzz_call = f"if (size > 0) {{ memcpy((void *){global_buf}, bounded_buf, size); }}{len_fuzz} {entry_fn}();"
        if null_terminate:
            eva_nt = (
                f"if (input_len > 0) {{ memcpy((void *){global_buf}, input_buf, input_len); }}\n"
                f"    ((char *){global_buf})[input_len < MAX_INPUT_SIZE ? input_len : (MAX_INPUT_SIZE - 1)] = 0;"
                f"{len_eva} {entry_fn}();"
            )
            fuzz_nt = (
                f"if (size > 0) {{ memcpy((void *){global_buf}, bounded_buf, size); }}\n"
                f"    ((char *){global_buf})[size < MAX_INPUT_SIZE ? size : (MAX_INPUT_SIZE - 1)] = 0;"
                f"{len_fuzz} {entry_fn}();"
            )
            return eva_nt, fuzz_nt
        return eva_call, fuzz_call
    if entry_style == "struct_arg":
        if not struct_type:
            raise ValueError("entry_style 'struct_arg' requires struct_type")
        eva_call = (
            f"{struct_type} target_arg;\n"
            f"    Frama_C_make_unknown((char *)&target_arg, sizeof(target_arg));\n"
            f"    (void)input_buf; (void)input_len;\n"
            f"    {entry_fn}(&target_arg);"
        )
        fuzz_call = (
            f"{struct_type} target_arg;\n"
            f"    memset(&target_arg, 0, sizeof(target_arg));\n"
            f"    if (size > 0) {{ memcpy(&target_arg, bounded_buf, size < sizeof(target_arg) ? size : sizeof(target_arg)); }}\n"
            f"    {entry_fn}(&target_arg);"
        )
        return eva_call, fuzz_call
    if entry_style == "void_call":
        return f"(void)input_buf; (void)input_len; {entry_fn}();", f"(void)bounded_buf; {entry_fn}();"
    if entry_style == "argv":
        # CLI-style entry (main(argc, argv)), modeled on upstream share/libc/eva_stubs.c
        # (vendored as docs/upstream/sources/eva_stubs.c). Eva side: nondet argc in [0..5] and five
        # 256-byte argv buffers made unknown. Fuzz side: argv[1] is the input as a NUL-terminated
        # string. The target's main is renamed via -Dmain=__framac_target_main in the sidecar
        # cppflags (see generate_module_harness), so libFuzzer's main does not clash at link time;
        # the -D renames this call and the synthesized declaration consistently.
        eva_call = (
            "(void)input_buf; (void)input_len; (void)fuzz_buf; (void)fuzz_len;\n"
            "    int argc = Frama_C_interval(0, 5);\n"
            "    char argv0[256], argv1[256], argv2[256], argv3[256], argv4[256];\n"
            "    char *argv[6] = {argv0, argv1, argv2, argv3, argv4, 0};\n"
            "    //@ loop unroll 5;\n"
            "    for (int i = 0; i < 5; i++) {\n"
            "        Frama_C_make_unknown(argv[i], 255);\n"
            "        argv[i][255] = 0;\n"
            "    }\n"
            f"    {entry_fn}(argc, argv);"
        )
        fuzz_call = (
            "char argv1[MAX_INPUT_SIZE + 1];\n"
            "    if (size > 0) { memcpy(argv1, bounded_buf, size); }\n"
            "    argv1[size < MAX_INPUT_SIZE ? size : MAX_INPUT_SIZE] = 0;\n"
            '    char *argv[2] = {(char *)"prog", argv1};\n'
            f"    {entry_fn}(2, argv);"
        )
        return eva_call, fuzz_call
    raise ValueError(f"invalid entry_style: {entry_style!r}")


# ---------------------------------------------------------------------------
# Automatic prelude resolution
#
# Module headers in real targets are frequently not self-sufficient: they use
# typedefs, enum constants, or macros defined in a sibling "root" header that
# they never include themselves. resolve_prelude_headers() compiles the
# generated harness with `clang -fsyntax-only` (LibFuzzer branch, i.e. without
# -D__FRAMAC__), collects unresolved identifiers from the diagnostics, finds
# the header in the -I directories that defines them, and #includes it before
# the module header. This replaces the manual
# `--header <root>.h --extra-include <mod>.h` workaround.
# ---------------------------------------------------------------------------

DEFAULT_PRELUDE_MAX_ITERATIONS = 3
_PRELUDE_CLANG_TIMEOUT_S = 120
_DIAG_SYMBOL_RE = re.compile(
    r"^(?P<file>.*?):\d+:\d+:\s+(?:fatal\s+)?error:\s+"
    r"(?:unknown type name|use of undeclared identifier)\s+'(?P<sym>[A-Za-z_]\w*)'",
    re.MULTILINE,
)
_DIAG_FATAL_RE = re.compile(r"^(?P<line>.*?:\d+:\d+:\s+fatal error:.*)$", re.MULTILINE)
_DIAG_ERROR_RE = re.compile(r"^(?P<line>.*?:\d+:\d+:\s+(?:fatal\s+)?error:.*)$", re.MULTILINE)
_C_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_C_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_ENUM_BODY_RE = re.compile(r"\benum\b[^{;]*\{[^{}]*\}", re.DOTALL)


def _split_cppflags(cppflags: str) -> list[str]:
    flags = cppflags or ""
    if os.name == "nt":
        # shlex (POSIX mode) treats backslashes as escapes; Windows paths use them as separators.
        flags = flags.replace("\\", "/")
    return shlex.split(flags)


def _include_dirs_from_cppflags(cppflags: str) -> list[Path]:
    """Return the -I directories (both `-Idir` and `-I dir` forms) in command-line order, de-duplicated."""
    tokens = _split_cppflags(cppflags)
    dirs: list[Path] = []
    seen: set[str] = set()
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        value: str | None = None
        if tok == "-I":
            if i + 1 < len(tokens):
                value = tokens[i + 1]
                i += 1
        elif tok.startswith("-I") and len(tok) > 2:
            value = tok[2:]
        i += 1
        if value is None:
            continue
        key = os.path.normcase(os.path.normpath(value))
        if key in seen:
            continue
        seen.add(key)
        dirs.append(Path(value))
    return dirs


def _candidate_headers(include_dirs: list[Path]) -> list[Path]:
    """
    List *.h files directly inside each -I directory (non-recursive). A basename
    found in an earlier -I directory shadows later ones, mirroring how the
    compiler resolves `#include "<basename>"`.
    """
    seen_names: set[str] = set()
    headers: list[Path] = []
    for d in include_dirs:
        if not d.is_dir():
            continue
        try:
            entries = sorted(d.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for p in entries:
            if p.suffix.lower() != ".h" or not p.is_file():
                continue
            if p.name in seen_names:
                continue
            seen_names.add(p.name)
            headers.append(p)
    return headers


def _strip_c_comments(text: str) -> str:
    return _C_LINE_COMMENT_RE.sub("", _C_BLOCK_COMMENT_RE.sub(" ", text))


def _header_defines_symbol(text: str, symbol: str) -> bool:
    """Heuristic check whether comment-stripped header `text` defines `symbol`."""
    s = re.escape(symbol)
    patterns = (
        # typedef unsigned char Boolean_T;  /  typedef uint8_t Buf_T[4];
        rf"\btypedef\b[^;{{}}]*\b{s}\s*(?:\[[^\]]*\]\s*)*;",
        # typedef void (*Handler_T)(int);
        rf"\btypedef\b[^;{{}}]*\(\s*\*\s*{s}\s*\)",
        # } Mode_T;  /  } Mode_T, *PMode_T;  (closing a typedef struct/union/enum)
        rf"\}}[^;{{}}]*?\b{s}\s*[,;]",
        # #define CMD_NAME_MAX_LEN 32
        rf"^[ \t]*#[ \t]*define[ \t]+{s}\b",
    )
    for pat in patterns:
        if re.search(pat, text, re.MULTILINE):
            return True
    enum_const = re.compile(rf"[{{,]\s*{s}\s*(?:=|,|\}})")
    return any(enum_const.search(m.group(0)) for m in _ENUM_BODY_RE.finditer(text))


def _parse_symbol_diagnostics(output: str) -> dict[str, list[str]]:
    """Map unresolved symbol -> list of files the diagnostic was reported in (discovery order)."""
    found: dict[str, list[str]] = {}
    for m in _DIAG_SYMBOL_RE.finditer(output or ""):
        sym = m.group("sym")
        fpath = m.group("file").strip()
        files = found.setdefault(sym, [])
        if fpath not in files:
            files.append(fpath)
    return found


def _insert_prelude_includes(
    harness_file: Path,
    header_include: str,
    new_headers: list[tuple[str, str | None]],
    anchor: str | None = None,
) -> None:
    """
    Insert `#include "<hdr>"` lines into the harness. Each entry is (header,
    before) where `before` is an already-included prelude header that depends
    on `header` (it must therefore come first), or None to insert directly
    before the module header line (preserving discovery order). Without a module
    header line, the headers go before `anchor`, the first line of the harness's
    header slot (a declaration synthesized from the sources needs them too).
    """
    lines = harness_file.read_text(encoding="utf-8").splitlines(keepends=True)
    module_line = f'#include "{header_include}"'

    def _find(target: str) -> int | None:
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped == target or stripped.startswith(target + " "):
                return idx
        return None

    for hdr, before in new_headers:
        idx = _find(f'#include "{before}"') if before else None
        if idx is None:
            idx = _find(module_line)
        if idx is None and anchor and anchor.strip():
            idx = _find(anchor.strip())
        if idx is None:
            # Module header line not found: insert before the first quoted include, else at the top.
            idx = next((i for i, line in enumerate(lines) if line.lstrip().startswith('#include "')), 0)
        lines.insert(idx, f'#include "{hdr}" /* auto-prelude */\n')
    harness_file.write_text("".join(lines), encoding="utf-8")


def resolve_prelude_headers(
    harness_file: Path,
    cppflags: str,
    header_include: str,
    max_iterations: int = DEFAULT_PRELUDE_MAX_ITERATIONS,
    clang: str | None = None,
    runner: Callable[..., Any] = subprocess.run,
    anchor: str | None = None,
) -> dict[str, Any]:
    """
    Make the harness self-sufficient by auto-including the headers that define
    identifiers the module header uses but does not declare.

    Runs `clang -fsyntax-only -x c <cppflags> <harness_file>` (without
    -D__FRAMAC__ so the LibFuzzer branch is checked), parses `unknown type name`
    and `use of undeclared identifier` diagnostics, searches *.h files in the
    -I directories for a definition (typedef, closing `} X;`, `#define X`, enum
    constant) and rewrites the harness so the defining headers are included
    before `#include "<header_include>"` (without one, before the `anchor` line:
    the first line of the harness's header slot). Repeats up to `max_iterations`
    rewrite rounds, re-running clang after each one.

    Returns a dict with `status` ("clean" | "resolved" | "unresolved" |
    "skipped"), `prelude_headers` (basenames as included), `unresolved_symbols`,
    `iterations` (number of clang runs) and, when skipped, `reason`.

    clang also gets the run snapshot's `-idirafter` options (scripts/target_env.py), as every other
    compile of the target does: a header the build generated (libpng's `pnglibconf.h`) is only there.
    They are not searched for definitions and not recorded in the sidecar.
    """
    from target_env import with_include_flags

    harness_file = Path(harness_file)
    result: dict[str, Any] = {
        "status": "skipped",
        "prelude_headers": [],
        "unresolved_symbols": [],
        "iterations": 0,
    }
    clang_bin = clang or shutil.which("clang")
    if not clang_bin:
        result["reason"] = "clang not found"
        return result

    include_dirs = _include_dirs_from_cppflags(cppflags)
    module_line_include = (header_include or "").replace("\\", "/").strip()
    harness_resolved = harness_file.resolve()
    header_cache: dict[Path, str] = {}

    def _header_text(p: Path) -> str:
        if p not in header_cache:
            try:
                header_cache[p] = _strip_c_comments(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                header_cache[p] = ""
        return header_cache[p]

    cmd = [
        clang_bin,
        "-fsyntax-only",
        "-fno-color-diagnostics",
        "-ferror-limit=0",
        "-x",
        "c",
        *_split_cppflags(with_include_flags(cppflags)),
        str(harness_file),
    ]
    prelude: list[str] = []
    max_rounds = max(0, int(max_iterations))
    rounds = 0
    while True:
        try:
            proc = runner(cmd, capture_output=True, text=True, check=False, timeout=_PRELUDE_CLANG_TIMEOUT_S)
        except (OSError, subprocess.SubprocessError) as exc:
            result.update(status="skipped", reason=f"clang invocation failed: {exc}", prelude_headers=list(prelude))
            return result
        result["iterations"] += 1
        output = f"{getattr(proc, 'stderr', '') or ''}\n{getattr(proc, 'stdout', '') or ''}"
        symbols = _parse_symbol_diagnostics(output)
        result["prelude_headers"] = list(prelude)

        if not symbols:
            fatal = _DIAG_FATAL_RE.search(output)
            if fatal and not prelude:
                # e.g. module header not found: nothing this resolver can fix.
                result.update(status="skipped", reason=f"clang fatal error: {fatal.group('line').strip()}")
            elif getattr(proc, "returncode", 0) != 0:
                err_m = _DIAG_ERROR_RE.search(output)
                err_line = (
                    err_m.group("line").strip()
                    if err_m
                    else (
                        output.strip().splitlines()[0].strip()
                        if output.strip()
                        else f"clang exited with {proc.returncode}"
                    )
                )
                result.update(status="error", reason=f"clang compile error: {err_line}", unresolved_symbols=[])
            else:
                result.update(status="resolved" if prelude else "clean", unresolved_symbols=[])
            return result

        if rounds >= max_rounds:
            result.update(status="unresolved", unresolved_symbols=list(symbols))
            result["reason"] = f"prelude iteration cap ({max_rounds}) reached"
            return result

        # Collect candidate definitions for every unresolved symbol.
        candidates: dict[str, list[Path]] = {}
        for sym, failing_files in symbols.items():
            failing_names = {Path(f.replace("\\", "/")).name for f in failing_files}
            cands: list[Path] = []
            for hdr in _candidate_headers(include_dirs):
                if hdr.resolve() == harness_resolved or hdr.name in prelude:
                    continue
                # A header cannot be its own prelude: skip it when the symbol failed inside it.
                if hdr.name in failing_names:
                    continue
                if _header_defines_symbol(_header_text(hdr), sym):
                    cands.append(hdr)
            candidates[sym] = cands

        coverage: dict[Path, int] = {}
        for cands in candidates.values():
            for hdr in cands:
                coverage[hdr] = coverage.get(hdr, 0) + 1

        new_headers: list[tuple[str, str | None]] = []
        chosen_names: list[str] = []
        unresolved: list[str] = []
        for sym, cands in candidates.items():
            if not cands:
                unresolved.append(sym)
                continue
            best = sorted(cands, key=lambda p: (-coverage[p], len(str(p)), str(p)))[0]
            if best.name in chosen_names:
                continue
            # If the symbol failed inside an earlier prelude header, the new header must precede it.
            failing_names = {Path(f.replace("\\", "/")).name for f in symbols[sym]}
            before = next((h for h in prelude if h in failing_names), None)
            chosen_names.append(best.name)
            new_headers.append((best.name, before))

        if not new_headers:
            result.update(status="unresolved", unresolved_symbols=unresolved or list(symbols))
            result["reason"] = "no defining header found in -I directories"
            return result

        _insert_prelude_includes(harness_file, module_line_include, new_headers, anchor)
        for hdr_name, before in new_headers:
            if before and before in prelude:
                prelude.insert(prelude.index(before), hdr_name)
            else:
                prelude.append(hdr_name)
        result["prelude_headers"] = list(prelude)
        rounds += 1


def _normalize_dag_cppflag(tok: str) -> str:
    if tok.startswith("-I") and len(tok) > 2:
        norm_dir = _normalize_run_rel_dir(tok[2:])
        return f"-I{norm_dir}"
    return tok


def _normalize_cppflags_dirs(cppflags: str) -> str:
    """Normalize container-absolute `-I/framac-run/...` or `-I/target/...` flags and deduplicate."""
    tokens = _split_cppflags(cppflags)
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "-I" and i + 1 < len(tokens):
            norm_tok = f"-I{_normalize_run_rel_dir(tokens[i + 1])}"
            i += 2
        else:
            norm_tok = _normalize_dag_cppflag(tok)
            i += 1
        if norm_tok.startswith(("-I", "-D", "-U", "-std=")) and norm_tok in out:
            continue
        out.append(norm_tok)
    # Quoted so a value such as -DLOG_PATH="log.txt" keeps its quotes through later shlex splits.
    return " ".join(shlex.quote(t) for t in out) or "-I."


def _dag_module_info(dag: dict, module_name: str, unit: str | None = None) -> dict | None:
    """
    The DAG record whose build flags a harness takes: its module's when it is a DAG module, else its
    link unit's (step I5b: the build's own flags, which a path module's scan can contradict). The unit
    is `unit` (given, the sidecar's, or inferred), else the path module's or the cluster's unit.
    """
    modules = dag.get("modules") or {}
    if isinstance(modules.get(module_name), dict):
        return modules[module_name]
    split = (dag.get("submodules") or {}).get(module_name)
    for name in (unit, (dag.get("unit_of_lexer_module") or {}).get(module_name), (split or {}).get("unit")):
        if name and isinstance(modules.get(name), dict):
            return modules[name]
    lexer = (dag.get("lexer_modules") or {}).get(module_name)
    return lexer if isinstance(lexer, dict) else None


def _merge_dag_module_cppflags(module_name: str, out_dir: Path, cppflags: str, unit: str | None = None) -> str:
    """
    If `callgraph_dag.json` exists next to `out_dir` (e.g. `workspace/reports/callgraph_dag.json`),
    normalize and merge its discovered `-I`/`-D` flags and force-included files for `module_name` (its
    link unit's, `_dag_module_info`) into `cppflags`.
    """
    cppflags = _normalize_cppflags_dirs(cppflags)
    dag_candidates = [
        out_dir.parent / "reports" / "callgraph_dag.json",
        Path("workspace/reports/callgraph_dag.json"),
    ]
    for dag_path in dag_candidates:
        if not dag_path.is_file():
            continue
        try:
            dag = json.loads(dag_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        dag = dag if isinstance(dag, dict) else {}
        mod_info = _dag_module_info(dag, module_name, unit)
        if not isinstance(mod_info, dict):
            continue
        for raw_flag in mod_info.get("cppflags") or []:
            if not isinstance(raw_flag, str) or not raw_flag.strip():
                continue
            norm_flag = _normalize_dag_cppflag(raw_flag.strip())
            if not norm_flag.startswith(("-I", "-D", "-U", "-std=")):
                continue
            # Not carried into the harness: a macro value with quotes or spaces (later stages split
            # and re-join flag strings, and `-DLOG="log.txt"` reaches the compiler as `log.txt`), and,
            # with link units, the build's `-std=` (the harness code is ours, and needs C99 or later
            # where a build may say -std=c89). The harness spec supplies such flags itself.
            if norm_flag.startswith("-D") and any(c in norm_flag for c in "\"' \\"):
                continue
            if norm_flag.startswith("-std=") and dag.get("module_kind") == "link_unit":
                continue
            cppflags = _append_cppflag(cppflags, norm_flag)
        # The unit's force-included files (`-include config.h` in the build): without them the
        # harness compiles different code than the build does.
        tokens = _split_cppflags(cppflags)
        forced = {tokens[i + 1] for i, t in enumerate(tokens[:-1]) if t in ("-include", "-imacros")}
        for raw in mod_info.get("force_includes") or []:
            path = _normalize_run_rel_dir(str(raw))
            if isinstance(raw, str) and raw.strip() and path not in forced:
                cppflags = f"{cppflags} -include {path}".strip()
                forced.add(path)
        break
    return cppflags


def _merge_dag_module_ldflags(module_name: str, out_dir: Path, ldflags: str, unit: str | None = None) -> str:
    """
    `ldflags` followed by the libraries the module's link unit links from outside the project (the
    DAG's `ldflags`, `-lz -lm`), those not already given. The sidecar carries them to every build.
    """
    for dag_path in (out_dir.parent / "reports" / "callgraph_dag.json", Path("workspace/reports/callgraph_dag.json")):
        if not dag_path.is_file():
            continue
        try:
            dag = json.loads(dag_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        mod_info = _dag_module_info(dag if isinstance(dag, dict) else {}, module_name, unit)
        if not isinstance(mod_info, dict):
            continue
        try:
            given = shlex.split(ldflags)
        except ValueError:
            return ldflags
        extra = [o for o in mod_info.get("ldflags") or [] if isinstance(o, str) and o.strip() and o not in given]
        return shlex.join([*given, *extra]) if extra else ldflags
    return ldflags


_HARNESS_IDENT_RE = re.compile(r"\b([A-Za-z_]\w*)\b")


def _infer_harness_unit(
    out_dir: Path, module_name: str, *snippets: str | None, sources: list[str] | None = None
) -> str | None:
    """The link unit of a new harness module, from the run's DAG (module_map.infer_unit, by DAG key)."""
    from module_map import infer_unit

    for dag_path in (out_dir.parent / "reports" / "callgraph_dag.json", Path("workspace/reports/callgraph_dag.json")):
        if dag_path.is_file():
            try:
                dag = json.loads(dag_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            idents = sorted({i for s in snippets if s for i in _HARNESS_IDENT_RE.findall(s)})
            return infer_unit(dag if isinstance(dag, dict) else None, module_name, idents, sources)
    return None


def _resolve_overlay_source(work_dir: Path, cand: str) -> str:
    """
    Resolve a run-relative source path against the `workspace/work` overlay by suffix
    match, so DAG entries stored as bare names (`misc.c`) or with a stale directory still
    point at the real overlay file (`workspace/work/src/misc.c`).
    """
    p = Path(cand.replace("\\", "/").strip())
    if p.is_file() or p.is_absolute():
        return cand
    if work_dir.is_dir():
        rel = cand[len("workspace/work/") :] if cand.startswith("workspace/work/") else cand
        matches = sorted(work_dir.glob(f"**/{rel}"), key=lambda m: (len(m.parts), m.as_posix()))
        if matches:
            return f"workspace/work/{matches[0].relative_to(work_dir).as_posix()}"
    return cand


def _merge_dag_harness_sources(
    out_dir: Path,
    sources: list[str],
    include_source: bool,
    *invocation_snippets: str | None,
) -> list[str]:
    """
    If `callgraph_dag.json` exists next to `out_dir` and `include_source` is False,
    inspect identifiers referenced in the harness invocation snippets (`entry_fn`,
    `call_expr`, `eva_expr`, `fuzz_expr`), resolve any in-tree functions or header
    `static inline` wrappers via the DAG, and append their module `required_sources`
    (preserving `workspace/work/` prefix conventions from `sources` and respecting
    explicit sub-module slices).
    """
    norm_sources = [_normalize_run_rel_dir(s) for s in sources if isinstance(s, str) and s.strip()]
    if include_source or not norm_sources:
        return list(norm_sources)
    dag_candidates = [
        out_dir.parent / "reports" / "callgraph_dag.json",
        Path("workspace/reports/callgraph_dag.json"),
    ]
    dag: dict[str, Any] | None = None
    for dag_path in dag_candidates:
        if not dag_path.is_file():
            continue
        try:
            loaded = json.loads(dag_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                dag = loaded
                break
        except (OSError, ValueError):
            continue
    if not dag:
        return list(norm_sources)

    functions_map = dag.get("functions") or {}
    modules_map = dag.get("modules") or {}
    if not isinstance(functions_map, dict) or not isinstance(modules_map, dict):
        return list(norm_sources)

    referenced_idents: set[str] = set()
    for snippet in invocation_snippets:
        if snippet:
            referenced_idents.update(_HARNESS_IDENT_RE.findall(snippet))

    # A name defined in several files is keyed `file#name` in the DAG, never by the name alone.
    colliding: dict[str, list[str]] = {}
    for key, rec in functions_map.items():
        if "#" in str(key) and isinstance(rec, dict) and rec.get("name"):
            colliding.setdefault(str(rec["name"]), []).append(str(key))

    def _colliding_keys(ident: str) -> list[str]:
        """The definition the harness means: one in its sources, else the only external one."""
        keys = sorted(colliding.get(ident) or [])
        in_sources = [
            k
            for k in keys
            if any(
                s == functions_map[k].get("file") or s.endswith("/" + str(functions_map[k].get("file")))
                for s in norm_sources
            )
        ]
        if in_sources:
            return in_sources
        external = [k for k in keys if not functions_map[k].get("is_static")]
        return external if len(external) == 1 else []

    aliases = dag.get("macro_aliases") or {}
    target_fns: set[str] = set()
    for ident in referenced_idents:
        if ident in functions_map:
            target_fns.add(ident)
        else:
            target_fns.update(_colliding_keys(ident))
        # A macro alias the build defines (the Phase 0 model's): alias -> DAG keys it expands to.
        alias_keys = aliases.get(ident) if isinstance(aliases, dict) else None
        for key in [alias_keys] if isinstance(alias_keys, str) else alias_keys or []:
            if isinstance(key, str) and key in functions_map:
                target_fns.add(key)

    if not target_fns:
        return list(norm_sources)

    # Determine whether `sources` uses a prefix like `workspace/work/`
    prefix = ""
    first_norm = norm_sources[0]
    if first_norm.startswith("workspace/work/"):
        prefix = "workspace/work/"
    elif (out_dir.parent / "work").is_dir() and first_norm.startswith(
        (out_dir.parent / "work").as_posix().rstrip("/") + "/"
    ):
        prefix = (out_dir.parent / "work").as_posix().rstrip("/") + "/"

    def _rel_path(p: str) -> str:
        clean = _normalize_run_rel_dir(p)
        return clean[len(prefix) :] if (prefix and clean.startswith(prefix)) else clean

    caller_rel_set = {_rel_path(s) for s in norm_sources}
    merged = list(norm_sources)
    seen_rel = set(caller_rel_set)
    # The unit module owning each source (a link-unit DAG's `files` partition the sources).
    owner_of: dict[str, str] = {}
    for mod_key, info in modules_map.items():
        for f in (info.get("files") if isinstance(info, dict) else None) or []:
            if isinstance(f, str):
                owner_of.setdefault(f, str(mod_key))

    for fn_name in sorted(target_fns):
        fn_rec = functions_map.get(fn_name)
        if not isinstance(fn_rec, dict):
            continue
        mod_name = fn_rec.get("module")
        mod_info = modules_map.get(mod_name) if isinstance(mod_name, str) else None
        # With link units (step I5b) a callee's sources are its lexer module's closure, as before,
        # not its whole unit's: a unit can hold files only some builds compile (x509-parser.c's
        # Frama-C-only `main`), and a harness should pull in what its callees need. A lexer module is
        # a directory, though, and can span units (libpng's contrib/ holds eight programs, each with
        # its own `main`): a file another unit owns is dropped unless the function's unit links it.
        # The project libraries the unit links come in whole, as the build links them: the model
        # parses each unit apart, so no call edge leads from a program into its library.
        unit_list = (
            [s for s in mod_info["required_sources"] if isinstance(s, str)]
            if isinstance(mod_info, dict) and isinstance(mod_info.get("required_sources"), list)
            else []
        )
        unit_sources = set(unit_list)
        lexer_info = (dag.get("lexer_modules") or {}).get(fn_rec.get("lexer_module") or "")
        if isinstance(lexer_info, dict) and isinstance(lexer_info.get("required_sources"), list):
            closure = [s for s in lexer_info["required_sources"] if isinstance(s, str)]
            kept = [s for s in closure if owner_of.get(s) in (None, mod_name) or s in unit_sources]
            fn_file = fn_rec.get("file")
            kept = kept or ([fn_file] if isinstance(fn_file, str) else [])
            kept += [s for s in unit_list if owner_of.get(s) not in (None, mod_name) and s not in kept]
            mod_info = {"required_sources": kept}
        extra_rels: list[str] = []
        if isinstance(mod_info, dict) and isinstance(mod_info.get("required_sources"), list):
            extra_rels.extend(s for s in mod_info["required_sources"] if isinstance(s, str))
        elif isinstance(fn_rec.get("file"), str):
            extra_rels.append(fn_rec["file"])
        for rel in extra_rels:
            rel_clean = _rel_path(rel)
            if rel_clean in seen_rel:
                continue
            cand = f"{prefix}{rel_clean}" if (prefix and not rel_clean.startswith(prefix)) else rel_clean
            cand = _resolve_overlay_source(out_dir.parent / "work", cand)
            merged.append(cand)
            seen_rel.add(rel_clean)
    return merged


def _entry_file(functions: dict, entry_fn: str, sources: list[str]) -> str | None:
    """
    The file (as the DAG names it) of the entry function the harness calls: the one among the harness's
    sources defining a function of that name, when exactly one does. None otherwise.
    """
    srcs = [s for s in _norm_scope_files(sources) if s]
    name = entry_fn.split("#")[-1]
    files = set()
    for key, rec in functions.items():
        if not isinstance(rec, dict) or (rec.get("name") or str(key).split("#")[-1]) != name:
            continue
        f = str(rec.get("file") or "").replace("\\", "/")
        if f and any(s == f or s.endswith("/" + f) or f.endswith("/" + s) for s in srcs):
            files.add(f)
    return files.pop() if len(files) == 1 else None


def _trust_reachability(out_dir: Path, entry_fn: str, sources: list[str] | None = None) -> tuple[str, str] | None:
    """
    The entry function's reachability from its trust (scripts/trust.py, step I7), read from the run's
    DAG: (`untrusted_surface` at a trust boundary, else `internal_api`; `trust:<deciding rule>`). The
    entry function's own record decides when the harness's `sources` name its file, so a same-named
    function elsewhere keeps its own trust; otherwise same-named records merge (untrusted wins).
    None when the DAG or the function's trust is missing.
    """
    from trust import function_trust, reachability_of

    for dag_path in (out_dir.parent / "reports" / "callgraph_dag.json", Path("workspace/reports/callgraph_dag.json")):
        if not dag_path.is_file():
            continue
        try:
            dag = json.loads(dag_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        functions = dag.get("functions") if isinstance(dag, dict) else None
        if not isinstance(functions, dict):
            continue
        entry_file = _entry_file(functions, entry_fn, sources or [])
        trust = function_trust(functions, entry_fn, entry_file) if entry_file else None
        if trust is None:
            trust = function_trust(functions, entry_fn)
        if trust is None:
            for key in (dag.get("macro_aliases") or {}).get(entry_fn) or []:
                trust = trust or function_trust(functions, key)
        reach = reachability_of(trust)
        if reach and trust is not None:
            return reach, f"trust:{trust.get('source')}"
        return None
    return None


_FUZZ_FN_BLOCK_RE = re.compile(
    r"/\*\s*\n\s*\*\s*LibFuzzer Entry Point.*?^int LLVMFuzzerTestOneInput\(const uint8_t \*data, size_t size\)\s*\{.*?^\}",
    re.DOTALL | re.MULTILINE,
)


def generate_module_harness(
    module_name: str,
    sources: list[str],
    header_include: str | None,
    entry_fn: str,
    max_input_size: int,
    cppflags: str,
    out_dir: Path,
    reachability: str | None = None,
    contract_notes: list[str] | None = None,
    entry_style: str = "buffer_len",
    global_buf: str | None = None,
    global_len: str | None = None,
    struct_type: str | None = None,
    include_source: bool = False,
    stubbed_callees: list[str] | None = None,
    extra_includes: list[str] | None = None,
    static_analysis_includes: list[str] | None = None,
    compat_includes: list[str] | None = None,
    self_harnessed: bool = False,
    call_expr: str | None = None,
    eva_expr: str | None = None,
    fuzz_expr: str | None = None,
    null_terminate: bool = False,
    auto_args: bool = False,
    auto_prelude: bool = True,
    prelude_max_iterations: int = DEFAULT_PRELUDE_MAX_ITERATIONS,
    prelude_clang: str | None = None,
    prelude_runner: Callable[..., Any] | None = None,
    ldflags: str = "",
    dispatch_cases: list[str] | None = None,
    unit: str | None = None,
    scope_files: list[str] | None = None,
    target_fuzzer: str | None = None,
    target_fuzzer_id: str | None = None,
) -> dict[str, Any]:
    # A target fuzz module (--target-fuzzer): the harness calls the target's own fuzz function, renamed
    # by -D (see the rename path below), on its own copy of the input. It answers for its fuzzer file only.
    target_fuzzer_record: dict[str, Any] | None = None
    target_fuzzer_snippet: str | None = None
    if target_fuzzer is not None:
        if self_harnessed:
            raise ValueError("--target-fuzzer and --self-harnessed are mutually exclusive")
        if not unit:
            raise ValueError("--target-fuzzer requires --unit (the link unit the fuzzer exercises)")
        tf_src = _normalize_run_rel_dir(target_fuzzer)
        if Path(tf_src).suffix.lower() != ".c":
            raise ValueError(f"--target-fuzzer {target_fuzzer!r}: only C fuzz targets (.c) are supported")
        target_fuzzer_snippet = _read_target_fuzzer_text(tf_src)
        if target_fuzzer_snippet is None:
            raise ValueError(f"--target-fuzzer {target_fuzzer!r}: file not found")
        if not _FUZZER_ENTRY_DEF_RE.search(target_fuzzer_snippet):
            raise ValueError(f"--target-fuzzer {target_fuzzer!r} does not define LLVMFuzzerTestOneInput")
        target_fuzzer_record = {
            "id": resolve_target_fuzzer_id(tf_src, target_fuzzer_id),
            "source": tf_src,
            "initialize": bool(_FUZZER_INIT_DEF_RE.search(target_fuzzer_snippet)),
        }
        norm_given = [_normalize_run_rel_dir(s) for s in sources if isinstance(s, str) and s.strip()]
        sources = list(sources) if tf_src in norm_given else [*sources, tf_src]
        entry_fn = TARGET_EMBEDDED_ENTRY
        entry_style = "buffer_len"
        auto_args = False
        scope_files = [tf_src]
    if auto_args:
        entry_style = "auto_prototype"
    # Reachability: explicit, else from the entry function's trust (step I7), else from the entry style.
    # A target fuzz target takes untrusted input by definition.
    reachability_source = "explicit"
    if reachability is None and target_fuzzer_record is not None:
        reachability, reachability_source = "untrusted_surface", "target_fuzzer"
    if reachability is None:
        from_trust = _trust_reachability(out_dir, entry_fn, sources)
        if from_trust is not None:
            reachability, reachability_source = from_trust
        else:
            reachability = "internal_api" if entry_style == "auto_prototype" else "untrusted_surface"
            reachability_source = "entry_style"
    if reachability not in ("untrusted_surface", "internal_api"):
        raise ValueError(f"invalid reachability: {reachability!r}")
    if entry_style not in VALID_ENTRY_STYLES:
        raise ValueError(f"invalid entry_style: {entry_style!r}")

    effective_self_harnessed = bool(self_harnessed or entry_fn == "LLVMFuzzerTestOneInput")

    tpl_dir = resolve_template_dir()
    harness_tpl = (tpl_dir / "harness_dual.c.template").read_text(encoding="utf-8")

    out_dir.mkdir(parents=True, exist_ok=True)
    harness_file = out_dir / f"harness_{module_name}.c"
    harness_meta_file = out_dir / f"harness_{module_name}.json"
    norm_ldflags = (ldflags or "").strip()

    # A repair that regenerates the harness keeps what its previous sidecar recorded (see below).
    previous = load_json_optional(harness_meta_file, {})
    previous = previous if isinstance(previous, dict) else {}
    # The link unit this harness module belongs to (step I5b; scripts/module_map.py): given, kept from
    # the previous sidecar, else inferred from the DAG. Null without link units (path modules). The
    # harness takes its unit's build flags, so a cluster or a freely named harness gets them too.
    unit = (
        unit
        or previous.get("unit")
        or _infer_harness_unit(
            out_dir, module_name, entry_fn, call_expr, eva_expr, fuzz_expr, *(dispatch_cases or []), sources=sources
        )
    )
    # The files whose functions a sub-module answers for at the reach gate (module_map.scope_functions):
    # given, else kept from the previous sidecar; empty means the sidecar's `sources`.
    scope = previous_scope_files(previous) if scope_files is None else _norm_scope_files(scope_files)

    norm_header, norm_cppflags = _normalize_header_include(header_include, cppflags)
    norm_cppflags = _merge_dag_module_cppflags(module_name, out_dir, norm_cppflags, unit)
    norm_ldflags = _merge_dag_module_ldflags(module_name, out_dir, norm_ldflags, unit)
    norm_extra_includes: list[str] = []
    for ext_inc in extra_includes or []:
        nh, norm_cppflags = _normalize_header_include(ext_inc, norm_cppflags)
        if nh and nh not in norm_extra_includes and nh != norm_header:
            norm_extra_includes.append(nh)

    # Target-compat headers (e.g. completing opaque external handles for E-ACSL's
    # _Alignof checks) are included source-side, after the module header — never via
    # `-include` in cppflags: force-including them re-registers libc properties per
    # merged translation unit and crashes the Frama-C kernel ("trying to register
    # twice property 'assumes nonnull_p'").
    norm_compat_includes: list[str] = []
    for ci in compat_includes or []:
        nh, norm_cppflags = _normalize_header_include(ci, norm_cppflags)
        if nh and nh not in norm_compat_includes and nh != norm_header and nh not in norm_extra_includes:
            norm_compat_includes.append(nh)

    norm_static_includes: list[str] = []
    for sa_inc in static_analysis_includes or []:
        raw_sa = (sa_inc or "").replace("\\", "/").strip()
        if not raw_sa:
            continue
        norm_sa = _normalize_run_rel_dir(raw_sa)
        sa_parent = _normalize_run_rel_dir(Path(norm_sa).parent.as_posix())
        if sa_parent not in ("", "."):
            norm_cppflags = _append_cppflag(norm_cppflags, f"-I{sa_parent}")
        existing_tokens = _split_cppflags(norm_cppflags)
        if norm_sa not in existing_tokens:
            norm_cppflags = f"{norm_cppflags} -include {norm_sa}".strip()
        if norm_sa not in norm_static_includes:
            norm_static_includes.append(norm_sa)

    if include_source:
        for src in sources:
            src_path = Path(src.replace("\\", "/").strip())
            src_parent = _normalize_run_rel_dir(src_path.parent.as_posix())
            if src_parent not in ("", "."):
                norm_cppflags = _append_cppflag(norm_cppflags, f"-I{src_parent}")
            else:
                ws_cand = Path("workspace/work") / src_path.name
                out_ws_cand = out_dir.parent / "work" / src_path.name
                if ws_cand.is_file() or out_ws_cand.is_file() or (out_dir.parent / "work").is_dir():
                    norm_cppflags = _append_cppflag(norm_cppflags, "-Iworkspace/work")

    # The --header must actually declare the entry function. When it does not (e.g. the
    # public header while the entry lives in a module-internal header), find the header
    # in the -I directories that does declare it and include it alongside.
    # A target fuzz module skips it: no header declares the renamed fuzz function.
    if norm_header and not effective_self_harnessed and target_fuzzer_record is None:
        if extract_function_declaration(entry_fn, norm_header, None, norm_cppflags) is None:
            declaring = _find_declaring_header(
                entry_fn, norm_cppflags, exclude={norm_header, *norm_extra_includes, *norm_compat_includes}
            )
            if declaring:
                norm_extra_includes.append(declaring)

    auto_params: list[dict[str, Any]] | None = None
    auto_needs_nt = False
    if entry_style == "auto_prototype":
        auto_params = extract_function_prototype(entry_fn, header_include, sources, norm_cppflags)
        _, _, auto_needs_nt = _build_auto_prototype_invocations(entry_fn, auto_params)

    effective_null_terminate = bool(null_terminate or entry_style == "c_string" or auto_needs_nt)
    if entry_style == "argv":
        # Rename the target's main in every build of this module (Eva and fuzz alike): the harness
        # calls main(argc, argv), and the -D renames that call together with the target's
        # definition, so libFuzzer's own main is the only main at link time.
        norm_cppflags = _append_cppflag(norm_cppflags, "-Dmain=__framac_target_main")
    eva_call, fuzz_call = _build_invocations(
        entry_fn=entry_fn,
        entry_style=entry_style,
        global_buf=global_buf,
        global_len=global_len,
        struct_type=struct_type,
        call_expr=call_expr,
        eva_expr=eva_expr,
        fuzz_expr=fuzz_expr,
        null_terminate=effective_null_terminate,
        auto_params=auto_params,
        dispatch_cases=dispatch_cases,
    )
    if target_fuzzer_record is not None:
        # The copy in fuzz_buf (never libFuzzer's `data`) is what E-ACSL's initialization checks need.
        tf_call = _target_fuzzer_invocation(bool(target_fuzzer_record["initialize"]))
        if effective_null_terminate:
            eva_call, fuzz_call = _wrap_null_terminated(tf_call, tf_call)
        else:
            eva_call, fuzz_call = tf_call, tf_call
    norm_dispatch_cases = [c.strip() for c in dispatch_cases or [] if c and c.strip()]
    arity_expr = call_expr or eva_expr or fuzz_expr or " ".join(norm_dispatch_cases)
    if arity_expr:
        _validate_call_expr_arity(entry_fn, arity_expr, sources, norm_cppflags)
    sources = _merge_dag_harness_sources(
        out_dir,
        sources,
        include_source,
        entry_fn,
        call_expr,
        eva_expr,
        fuzz_expr,
        *norm_dispatch_cases,
        # The unit functions the target's fuzzer calls pull in their sources too.
        target_fuzzer_snippet,
    )

    inc_lines: list[str] = []
    if norm_header:
        inc_lines.append(f'#include "{norm_header}"')
    for ext_h in norm_extra_includes:
        inc_lines.append(f'#include "{ext_h}"')
    for ci in norm_compat_includes:
        inc_lines.append(f'#include "{ci}"')

    embedded_fuzzer_in_sources = any(_source_defines_fuzzer_entry(s, norm_cppflags) for s in sources)
    rename_embedded_fuzzer = bool(embedded_fuzzer_in_sources and not effective_self_harnessed)
    # A source's own LLVMFuzzerInitialize is renamed too: the E-ACSL init hook (fuzz_init.c) defines the
    # real one, and the harness never does (a target fuzz harness calls the renamed one itself).
    rename_embedded_init = bool(
        not effective_self_harnessed and any(_source_defines_fuzzer_initialize(s, norm_cppflags) for s in sources)
    )

    if include_source:
        for src in sources:
            src_path = Path(src.replace("\\", "/").strip())
            renames = []
            if rename_embedded_fuzzer and _source_defines_fuzzer_entry(src, norm_cppflags):
                renames.append(("LLVMFuzzerTestOneInput", TARGET_EMBEDDED_ENTRY))
            if rename_embedded_init and _source_defines_fuzzer_initialize(src, norm_cppflags):
                renames.append(("LLVMFuzzerInitialize", TARGET_EMBEDDED_INIT))
            inc_lines.extend(f"#define {name} {embedded}" for name, embedded in renames)
            inc_lines.append(f'#include "{src_path.name}"')
            inc_lines.extend(f"#undef {name}" for name, _ in renames)
    else:
        if rename_embedded_fuzzer:
            norm_cppflags = _append_cppflag(norm_cppflags, f"-DLLVMFuzzerTestOneInput={TARGET_EMBEDDED_ENTRY}")
        if rename_embedded_init:
            norm_cppflags = _append_cppflag(norm_cppflags, f"-DLLVMFuzzerInitialize={TARGET_EMBEDDED_INIT}")
        # A target fuzz module's declarations come below, with its run-once initialization.
        if not norm_header and target_fuzzer_record is None:
            if effective_self_harnessed:
                inc_lines.append("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);")
            else:
                synth_decl = extract_function_declaration(entry_fn, None, sources, norm_cppflags)
                if synth_decl:
                    inc_lines.append(synth_decl)
        elif effective_self_harnessed:
            inc_lines.append("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);")
    if target_fuzzer_record is not None:
        inc_lines.append(_target_fuzzer_prelude(bool(target_fuzzer_record["initialize"])))

    if not inc_lines:
        inc_lines.append("/* No external module header required */")

    rendered_tpl = harness_tpl
    if effective_self_harnessed:
        rendered_tpl = _FUZZ_FN_BLOCK_RE.sub(
            "/* Self-harnessed slice: LLVMFuzzerTestOneInput is defined by the target source. */",
            rendered_tpl,
        )
    elif rename_embedded_fuzzer and not include_source:
        rendered_tpl = rendered_tpl.replace(
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {",
            "#undef LLVMFuzzerTestOneInput\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {",
        )

    main_def_re = re.compile(r"\bmain\s*\([^;{}]*\)\s*\{")
    has_main_def = False
    for src in sources or []:
        sp = Path(src.replace("\\", "/").strip())
        cands = [sp, Path("workspace/work") / sp]
        for c in cands:
            if c.is_file():
                try:
                    content = c.read_text(encoding="utf-8", errors="replace")
                    cleaned = _strip_c_comments(content)
                    if main_def_re.search(cleaned):
                        has_main_def = True
                        break
                except OSError:
                    pass
        if has_main_def:
            break

    if has_main_def:
        main_flag = f"-Dmain=__framac_module_main_{_C_IDENT_JUNK.sub('_', module_name)}"
        if "-Dmain=" not in norm_cppflags:
            norm_cppflags = f"{norm_cppflags} {main_flag}".strip() if norm_cppflags else main_flag

    harness_content = (
        rendered_tpl.replace("{{MODULE_NAME}}", module_name)
        .replace('#include "{{MODULE_HEADER}}"', "\n".join(inc_lines))
        .replace("{{MAX_INPUT_SIZE}}", str(max_input_size))
        .replace("{{TARGET_INVOCATION_EVA}}", eva_call)
        .replace("{{TARGET_INVOCATION_FUZZ}}", fuzz_call)
    )

    harness_file.write_text(harness_content, encoding="utf-8")

    if auto_prelude:
        prelude = resolve_prelude_headers(
            harness_file,
            norm_cppflags,
            norm_header or "",
            max_iterations=prelude_max_iterations,
            clang=prelude_clang,
            runner=prelude_runner or subprocess.run,
            # The header slot's first line: without a --header, the declaration synthesized from
            # the sources sits there, and the headers defining its types must come before it.
            anchor=inc_lines[0],
        )
    else:
        prelude = {"status": "disabled", "prelude_headers": [], "unresolved_symbols": [], "iterations": 0}
    prelude_fields = {
        "prelude_headers": list(prelude.get("prelude_headers") or []),
        "prelude_status": prelude.get("status"),
        "prelude_unresolved": list(prelude.get("unresolved_symbols") or []),
    }
    if prelude.get("reason"):
        prelude_fields["prelude_reason"] = prelude["reason"]

    # A repair that regenerates the harness keeps the count `--record-repair` kept, or the
    # repair cap would reset on every repair and the loop would never end.
    try:
        repair_attempts = max(0, int(previous.get("repair_attempts") or 0))
    except (TypeError, ValueError):
        repair_attempts = 0
    repair_history = previous.get("repair_history")
    repair_history = list(repair_history) if isinstance(repair_history, list) else []
    # Gaps accepted at the reachability gate (harness_reach.py exempt) survive regeneration too.
    reach_exempt = previous.get("reach_exempt")
    reach_exempt = dict(reach_exempt) if isinstance(reach_exempt, dict) else {}

    sidecar = {
        "module": module_name,
        "unit": unit,
        "harness_file": str(harness_file).replace("\\", "/"),
        "sources": list(sources),
        "scope_files": scope,
        "header": norm_header,
        "extra_includes": norm_extra_includes,
        "static_analysis_includes": norm_static_includes,
        "compat_includes": norm_compat_includes,
        "cppflags": norm_cppflags,
        "ldflags": norm_ldflags,
        "entry_fn": entry_fn,
        "entry_style": entry_style,
        # The globals a `global_buffer` entry writes the input into: workspace_overlay's trust-boundary
        # check treats them as entry parameters. Null for every other entry style.
        "global_buf": global_buf if entry_style == "global_buffer" else None,
        "global_len": (global_len or None) if entry_style == "global_buffer" else None,
        "self_harnessed": effective_self_harnessed,
        "null_terminate": effective_null_terminate,
        "call_expr": call_expr,
        "eva_expr": eva_expr,
        "fuzz_expr": fuzz_expr,
        "dispatch_cases": norm_dispatch_cases if entry_style == "dispatch" else [],
        "include_source": include_source,
        "stubbed_callees": sorted(set(stubbed_callees or [])),
        "reachability": reachability,
        "reachability_source": reachability_source,
        "max_input_size": max_input_size,
        "contract_notes": list(contract_notes or []),
        "repair_attempts": repair_attempts,
        "max_repair_attempts": MAX_HARNESS_REPAIR_ATTEMPTS,
        "repair_history": repair_history,
        "reach_exempt": reach_exempt,
        **prelude_fields,
    }
    if target_fuzzer_record is not None:
        sidecar["target_fuzzer"] = dict(target_fuzzer_record)
    write_sidecar(harness_meta_file, sidecar)

    if (
        prelude.get("status") == "unresolved"
        and prelude_fields["prelude_unresolved"]
        and prelude.get("iterations", 0) > 0
    ):
        raise ValueError(
            "harness for module "
            f"{module_name!r} has unresolved identifiers after automatic prelude resolution: "
            f"{', '.join(prelude_fields['prelude_unresolved'])}. "
            "Pass the defining root header manually (--header <root>.h --extra-include <mod>.h), "
            "add its directory to --cppflags with -I, or disable resolution with --no-auto-prelude."
        )

    return {
        "module": module_name,
        "harness_file": str(harness_file),
        "harness_meta": str(harness_meta_file),
        "sources": sources,
        "header": norm_header,
        "extra_includes": norm_extra_includes,
        "static_analysis_includes": norm_static_includes,
        "compat_includes": norm_compat_includes,
        "cppflags": norm_cppflags,
        "ldflags": norm_ldflags,
        "entry_fn": entry_fn,
        "entry_style": entry_style,
        "self_harnessed": effective_self_harnessed,
        "null_terminate": effective_null_terminate,
        "include_source": include_source,
        "reachability": reachability,
        "reachability_source": reachability_source,
        "scope_files": scope,
        **({"target_fuzzer": dict(target_fuzzer_record)} if target_fuzzer_record is not None else {}),
        **prelude_fields,
    }


def _norm_scope_files(files: list[str]) -> list[str]:
    """Scope files as module_map compares them: run-relative, `/`-separated, without `workspace/work/`."""
    out: list[str] = []
    for f in files:
        p = str(f).strip().replace("\\", "/")
        while p.startswith("./"):
            p = p[2:]
        p = p[len("workspace/work/") :] if p.startswith("workspace/work/") else p
        if p and p not in out:
            out.append(p)
    return out


def previous_scope_files(previous: dict[str, Any]) -> list[str]:
    """The `scope_files` a previous sidecar recorded (empty when it has none)."""
    raw = previous.get("scope_files")
    return _norm_scope_files([f for f in raw if isinstance(f, str)]) if isinstance(raw, list) else []


SIDECAR_SCHEMA = "harness_sidecar"


def write_sidecar(path: Path, sidecar: dict[str, Any]) -> dict[str, Any]:
    """
    Write a harness sidecar after checking it against schemas/harness_sidecar.schema.json: schema
    problems go to its `warnings` (validate_artifacts.py run-dir fails on them), never stop the write.
    """
    from validate_artifacts import schema_warning

    sidecar.pop("warnings", None)
    warning = schema_warning(SIDECAR_SCHEMA, sidecar)
    if warning:
        sidecar["warnings"] = [warning]
    atomic_write_json(path, sidecar)
    return sidecar


def record_harness_repair(harness_meta_path: Path, reason: str) -> dict[str, Any]:
    """Increment repair_attempts in harness_<module>.json and report whether the cap (2) is reached."""
    meta = load_json_strict(harness_meta_path)
    attempts = int(meta.get("repair_attempts", 0)) + 1
    max_attempts = int(meta.get("max_repair_attempts", MAX_HARNESS_REPAIR_ATTEMPTS))
    meta["repair_attempts"] = attempts
    history = list(meta.get("repair_history") or [])
    history.append({"attempt": attempts, "reason": reason, "timestamp": utc_now()})
    meta["repair_history"] = history
    write_sidecar(harness_meta_path, meta)
    return {
        "module": meta.get("module"),
        "repair_attempts": attempts,
        "max_repair_attempts": max_attempts,
        "exhausted": attempts >= max_attempts,
    }


def _bind_flag_values(argv: list[str]) -> list[str]:
    """
    argparse reads a lone value such as `--ldflags -lbsd` as an unknown option; bind the value of
    --cppflags / --ldflags with `=` so single flags work as well as quoted flag lists.
    """
    return normalize_flag_args(argv, ("--cppflags", "--ldflags"))


def main(argv: list[str] | None = None) -> int:
    raw_argv = _bind_flag_values(list(argv) if argv is not None else sys.argv[1:])
    parser = argparse.ArgumentParser(description="Generate Dual-Use Eva + E-ACSL LibFuzzer Harness.")
    parser.add_argument("--module", help="Module slice identifier (e.g. snmpv3)")
    parser.add_argument(
        "--unit",
        default=None,
        help="Link unit (DAG module) this harness belongs to when it is a sub-module (default: inferred)",
    )
    parser.add_argument("--sources", nargs="+", help="List of C source files in the module slice")
    parser.add_argument("--header", default=None, help="Optional module header to include in harness (or 'none')")
    parser.add_argument("--entry-fn", help="Target entry function accepting (buf, len) or LLVMFuzzerTestOneInput")
    parser.add_argument(
        "--max-size",
        type=int,
        default=None,
        help=(
            f"Max symbolic/fuzzer buffer size in bytes (default: {DEFAULT_MAX_INPUT_SIZE}; with --target-fuzzer, "
            "the fuzzer's suggested_max_input_size in workspace/reports/fuzz_assets.json, else "
            f"{TARGET_FUZZER_DEFAULT_MAX_INPUT_SIZE})"
        ),
    )
    parser.add_argument("--cppflags", default="-I.", help="Extra preprocessor flags")
    parser.add_argument(
        "--ldflags",
        default="",
        help="Linker flags the module's fuzz builds need (e.g. '-lbsd -lm'); recorded in the sidecar for pipeline_make.py",
    )
    parser.add_argument("--out-dir", type=Path, default=Path("workspace/harnesses"))
    parser.add_argument(
        "--reachability",
        choices=["untrusted_surface", "internal_api"],
        default=None,
        help=(
            "Reachability classification of the entry function (default: from its trust in the DAG, "
            "untrusted_surface at a trust boundary; without trust, internal_api for auto_prototype, "
            "else untrusted_surface)"
        ),
    )
    parser.add_argument(
        "--entry-style",
        choices=list(VALID_ENTRY_STYLES),
        default="buffer_len",
        help="Entry invocation pattern: buffer_len (default), c_string, global_buffer, struct_arg, void_call, custom, auto_prototype, argv (CLI main(argc, argv); defaults automatically when --entry-fn is main), or dispatch (first input byte selects one of the --dispatch-case statements)",
    )
    parser.add_argument(
        "--auto-args",
        action="store_true",
        help="Synthesize argument bindings automatically from the C prototype of --entry-fn (sets --entry-style=auto_prototype and defaults --reachability=internal_api)",
    )
    parser.add_argument("--global-buf", default=None, help="Global buffer symbol when --entry-style=global_buffer")
    parser.add_argument(
        "--global-len", default=None, help="Optional global length symbol when --entry-style=global_buffer"
    )
    parser.add_argument(
        "--struct-type", default=None, help="C struct type (e.g. 'Anomaly_T') when --entry-style=struct_arg"
    )
    parser.add_argument(
        "--extra-include", action="append", default=[], help="Additional header to #include in the harness (repeatable)"
    )
    parser.add_argument(
        "--static-analysis-include",
        action="append",
        default=[],
        help="Header to force-include via -include in sidecar cppflags so Eva, WP, guardrail, and merge re-checks inherit it (repeatable)",
    )
    parser.add_argument(
        "--compat-include",
        action="append",
        default=[],
        help=(
            "Target-compat header (e.g. completing opaque external handles for E-ACSL _Alignof checks) "
            "to #include source-side in the harness after the module header — never via -include, which "
            "crashes the Frama-C kernel with duplicate libc property registration (repeatable)"
        ),
    )
    parser.add_argument(
        "--self-harnessed",
        action="store_true",
        help="Target already defines LLVMFuzzerTestOneInput; emit only eva_main in the generated harness",
    )
    parser.add_argument(
        "--target-fuzzer",
        default=None,
        help=(
            "A C fuzz target the analysed project ships (defines LLVMFuzzerTestOneInput, e.g. "
            "workspace/work/fuzz/fuzz_parse.c): generate a target fuzz module whose harness calls it, renamed "
            f"to {TARGET_EMBEDDED_ENTRY}, on a copy of the input; requires --unit; sets --entry-fn, "
            "--entry-style buffer_len and --scope-file; adds the file to --sources"
        ),
    )
    parser.add_argument(
        "--target-fuzzer-id",
        default=None,
        help="Id of the --target-fuzzer recorded in the sidecar (default: the file's stem, chars [A-Za-z0-9_.+-])",
    )
    parser.add_argument(
        "--call-expr",
        default=None,
        help="Custom C invocation statements using fuzz_buf and fuzz_len when --entry-style=custom",
    )
    parser.add_argument(
        "--eva-expr", default=None, help="Custom Eva invocation statements (overrides --call-expr for eva_main)"
    )
    parser.add_argument(
        "--fuzz-expr",
        default=None,
        help="Custom LibFuzzer invocation statements (overrides --call-expr for LLVMFuzzerTestOneInput)",
    )
    parser.add_argument(
        "--dispatch-case",
        action="append",
        default=[],
        help=(
            "One API-call case for --entry-style=dispatch (repeatable): C statements using fuzz_buf and "
            "fuzz_len (the input after the selector byte); must respect the callee's contract and never return"
        ),
    )
    parser.add_argument(
        "--null-terminate", action="store_true", help="Guarantee fuzz_buf is NUL-terminated in both Eva and LibFuzzer"
    )
    parser.add_argument(
        "--include-source",
        action="store_true",
        help="Include target .c source(s) directly in the harness translation unit for static-function visibility",
    )
    parser.add_argument(
        "--stubbed-callee", action="append", default=[], help="External/I/O callee stubbed by the harness (repeatable)"
    )
    parser.add_argument("--contract-note", action="append", default=[], help="Entry contract note (repeatable)")
    parser.add_argument(
        "--scope-file",
        action="append",
        default=None,
        help=(
            "Source file whose functions this harness module answers for at the reach gate, when it is a "
            "sub-module that is neither a lexer module nor a split cluster (repeatable; recorded as the "
            "sidecar's `scope_files`; default: the previous sidecar's, else the --sources)"
        ),
    )
    parser.add_argument(
        "--no-auto-prelude",
        dest="auto_prelude",
        action="store_false",
        help=(
            "Disable automatic prelude resolution (clang -fsyntax-only probe that #includes headers from the "
            "-I directories defining identifiers the module header uses but does not include)"
        ),
    )
    parser.add_argument(
        "--api",
        action="store_true",
        help=(
            "Generate a dispatch harness for the module's whole API from the Phase 0 model "
            "(scripts/api_harness.py): one case per API entry point, plus recorded call sequences; "
            "--sources and --entry-fn come from the DAG"
        ),
    )
    parser.add_argument(
        "--record-repair", type=Path, default=None, help="Path to harness_<mod>.json to record a repair"
    )
    parser.add_argument("--reason", default="", help="Reason for harness repair when using --record-repair")
    args = parser.parse_args(raw_argv)

    if args.record_repair is not None:
        if not args.reason.strip():
            print(json.dumps({"ok": False, "error": "--record-repair requires --reason"}, indent=2))
            return 1
        res = record_harness_repair(args.record_repair, args.reason.strip())
        print(json.dumps(res, indent=2))
        return 0

    if args.api:
        if not args.module:
            parser.error("--api requires --module")
        from api_harness import ApiHarnessError, generate

        try:
            result = generate(
                module=args.module,
                header=args.header,
                max_input_size=args.max_size if args.max_size is not None else DEFAULT_MAX_INPUT_SIZE,
                cppflags=args.cppflags,
                out_dir=args.out_dir,
                unit=args.unit,
                ldflags=args.ldflags,
                extra_includes=args.extra_include,
                reachability=args.reachability,
                auto_prelude=args.auto_prelude,
                scope_files=args.scope_file,
            )
        except (ApiHarnessError, ValueError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
            return 1
        print(json.dumps(result, indent=2))
        return 0

    if args.target_fuzzer is not None:
        if args.self_harnessed:
            parser.error("--target-fuzzer and --self-harnessed are mutually exclusive")
        if not args.unit:
            parser.error("--target-fuzzer requires --unit")
        if not args.module:
            parser.error("--target-fuzzer requires --module")
        try:
            tf_id = resolve_target_fuzzer_id(args.target_fuzzer, args.target_fuzzer_id)
        except ValueError as exc:
            parser.error(str(exc))
        # The fuzzer's own file is a source; the entry function is its renamed fuzz function.
        args.sources = list(args.sources or [])
        args.entry_fn = TARGET_EMBEDDED_ENTRY
        if args.max_size is None:
            args.max_size = target_fuzzer_max_input_size(args.out_dir, args.target_fuzzer, tf_id)
    elif args.target_fuzzer_id is not None:
        parser.error("--target-fuzzer-id requires --target-fuzzer")
    if args.max_size is None:
        args.max_size = DEFAULT_MAX_INPUT_SIZE

    if not (args.module and (args.sources or args.target_fuzzer) and args.entry_fn):
        parser.error("--module, --sources, and --entry-fn are required when generating a harness")

    effective_style = "auto_prototype" if args.auto_args else args.entry_style
    style_explicit = any(a == "--entry-style" or a.startswith("--entry-style=") for a in raw_argv)
    if not style_explicit and not args.auto_args and args.entry_fn == "main":
        # CLI-style target: drive main(argc, argv) instead of a (buf, len) entry.
        effective_style = "argv"
    # None: generate_module_harness takes it from the entry function's trust, else from the entry style.
    effective_reachability = args.reachability

    try:
        result = generate_module_harness(
            module_name=args.module,
            sources=args.sources,
            header_include=args.header,
            entry_fn=args.entry_fn,
            max_input_size=args.max_size,
            cppflags=args.cppflags,
            out_dir=args.out_dir,
            reachability=effective_reachability,
            contract_notes=args.contract_note,
            entry_style=effective_style,
            global_buf=args.global_buf,
            global_len=args.global_len,
            struct_type=args.struct_type,
            include_source=args.include_source,
            stubbed_callees=args.stubbed_callee,
            extra_includes=args.extra_include,
            static_analysis_includes=args.static_analysis_include,
            compat_includes=args.compat_include,
            self_harnessed=args.self_harnessed,
            call_expr=args.call_expr,
            eva_expr=args.eva_expr,
            fuzz_expr=args.fuzz_expr,
            null_terminate=args.null_terminate,
            auto_args=args.auto_args,
            auto_prelude=args.auto_prelude,
            ldflags=args.ldflags,
            dispatch_cases=args.dispatch_case,
            unit=args.unit,
            scope_files=args.scope_file,
            target_fuzzer=args.target_fuzzer,
            target_fuzzer_id=args.target_fuzzer_id,
        )
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
