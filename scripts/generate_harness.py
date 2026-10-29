#!/usr/bin/env python3
"""
Generates per-module Frama-C GNUmakefile, dual-use C harness
(supporting both Frama-C Eva via eva_main() and Clang LibFuzzer via LLVMFuzzerTestOneInput()),
and a structured sidecar JSON (harness_<module>.json) tracking entry reachability,
contract notes, and harness repair attempts (capped at 2).

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

from framac_common import atomic_write_json, load_json_strict, utc_now  # noqa: E402


DEFAULT_TEMPLATE_DIR = Path("/opt/framac-pipeline/templates")
MAX_HARNESS_REPAIR_ATTEMPTS = 2
VALID_ENTRY_STYLES = ("buffer_len", "global_buffer", "struct_arg", "void_call", "c_string", "custom")
_WORKSPACE_PREFIXES = (
    "/framac-run/workspace/work/",
    "/framac-run/workspace/baseline/",
    "workspace/work/",
    "workspace/baseline/",
    "/target/",
)


def resolve_template_dir() -> Path:
    if DEFAULT_TEMPLATE_DIR.exists():
        return DEFAULT_TEMPLATE_DIR
    return Path(__file__).resolve().parent.parent / "templates"


def _normalize_header_include(header_include: str, cppflags: str) -> tuple[str, str]:
    """
    If `header_include` is passed as a workspace/target file path (e.g.
    `workspace/work/src/LibPtfCom/PtfMsg.h`), add `-I<parent_dir>` to `cppflags`
    and emit `#include "PtfMsg.h"` so compilers running from any working directory
    resolve the header cleanly.
    """
    norm = (header_include or "").replace("\\", "/").strip()
    updated_flags = (cppflags or "-I.").strip()
    p = Path(norm)
    parent_posix = p.parent.as_posix()
    has_ws_prefix = any(norm.startswith(pref) for pref in _WORKSPACE_PREFIXES)
    if (has_ws_prefix or p.is_file()) and parent_posix not in ("", "."):
        inc_flag = f"-I{parent_posix}"
        if inc_flag not in updated_flags.split():
            updated_flags = f"{updated_flags} {inc_flag}".strip()
        return p.name, updated_flags
    return norm, updated_flags


def _wrap_null_terminated(eva_inner: str, fuzz_inner: str) -> tuple[str, str]:
    eva_wrapped = (
        "input_buf[input_len < MAX_INPUT_SIZE ? input_len : (MAX_INPUT_SIZE - 1)] = 0;\n"
        f"    {eva_inner}"
    )
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
) -> tuple[str, str]:
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
            f"if (input_len > 0) {{ memcpy((void *){global_buf}, input_buf, input_len); }}"
            f"{len_eva} {entry_fn}();"
        )
        fuzz_call = (
            f"if (size > 0) {{ memcpy((void *){global_buf}, bounded_buf, size); }}"
            f"{len_fuzz} {entry_fn}();"
        )
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
) -> None:
    """
    Insert `#include "<hdr>"` lines into the harness. Each entry is (header,
    before) where `before` is an already-included prelude header that depends
    on `header` (it must therefore come first), or None to insert directly
    before the module header line (preserving discovery order).
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
) -> dict[str, Any]:
    """
    Make the harness self-sufficient by auto-including the headers that define
    identifiers the module header uses but does not declare.

    Runs `clang -fsyntax-only -x c <cppflags> <harness_file>` (without
    -D__FRAMAC__ so the LibFuzzer branch is checked), parses `unknown type name`
    and `use of undeclared identifier` diagnostics, searches *.h files in the
    -I directories for a definition (typedef, closing `} X;`, `#define X`, enum
    constant) and rewrites the harness so the defining headers are included
    before `#include "<header_include>"`. Repeats up to `max_iterations`
    rewrite rounds, re-running clang after each one.

    Returns a dict with `status` ("clean" | "resolved" | "unresolved" |
    "skipped"), `prelude_headers` (basenames as included), `unresolved_symbols`,
    `iterations` (number of clang runs) and, when skipped, `reason`.
    """
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
        *_split_cppflags(cppflags),
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
            failing_names = [Path(f.replace("\\", "/")).name for f in symbols[sym]]
            before = next((h for h in prelude if h in failing_names), None)
            chosen_names.append(best.name)
            new_headers.append((best.name, before))

        if not new_headers:
            result.update(status="unresolved", unresolved_symbols=unresolved or list(symbols))
            result["reason"] = "no defining header found in -I directories"
            return result

        _insert_prelude_includes(harness_file, module_line_include, new_headers)
        for hdr, before in new_headers:
            if before and before in prelude:
                prelude.insert(prelude.index(before), hdr)
            else:
                prelude.append(hdr)
        result["prelude_headers"] = list(prelude)
        rounds += 1


def generate_module_harness(
    module_name: str,
    sources: list[str],
    header_include: str,
    entry_fn: str,
    max_input_size: int,
    cppflags: str,
    out_dir: Path,
    reachability: str = "untrusted_surface",
    contract_notes: list[str] | None = None,
    entry_style: str = "buffer_len",
    global_buf: str | None = None,
    global_len: str | None = None,
    struct_type: str | None = None,
    include_source: bool = False,
    stubbed_callees: list[str] | None = None,
    extra_includes: list[str] | None = None,
    call_expr: str | None = None,
    eva_expr: str | None = None,
    fuzz_expr: str | None = None,
    null_terminate: bool = False,
    auto_prelude: bool = True,
    prelude_max_iterations: int = DEFAULT_PRELUDE_MAX_ITERATIONS,
    prelude_clang: str | None = None,
    prelude_runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    if reachability not in ("untrusted_surface", "internal_api"):
        raise ValueError(f"invalid reachability: {reachability!r}")
    if entry_style not in VALID_ENTRY_STYLES:
        raise ValueError(f"invalid entry_style: {entry_style!r}")

    tpl_dir = resolve_template_dir()
    harness_tpl = (tpl_dir / "harness_dual.c.template").read_text(encoding="utf-8")
    mk_tpl = (tpl_dir / "GNUmakefile.template").read_text(encoding="utf-8")

    out_dir.mkdir(parents=True, exist_ok=True)
    harness_file = out_dir / f"harness_{module_name}.c"
    harness_meta_file = out_dir / f"harness_{module_name}.json"
    makefile_path = out_dir / f"{module_name}.mk"

    norm_header, norm_cppflags = _normalize_header_include(header_include, cppflags)
    norm_extra_includes: list[str] = []
    for ext_inc in extra_includes or []:
        nh, norm_cppflags = _normalize_header_include(ext_inc, norm_cppflags)
        if nh and nh not in norm_extra_includes and nh != norm_header:
            norm_extra_includes.append(nh)

    effective_null_terminate = bool(null_terminate or entry_style == "c_string")
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
    )

    inc_lines = [f'#include "{norm_header}"']
    for ext_h in norm_extra_includes:
        inc_lines.append(f'#include "{ext_h}"')
    if include_source:
        for src in sources:
            src_path = Path(src.replace("\\", "/").strip())
            src_parent = src_path.parent.as_posix()
            if src_parent not in ("", "."):
                inc_flag = f"-I{src_parent}"
                if inc_flag not in norm_cppflags.split():
                    norm_cppflags = f"{norm_cppflags} {inc_flag}".strip()
            inc_lines.append(f'#include "{src_path.name}"')
        all_sources = str(harness_file)
    else:
        all_sources = " ".join(sources + [str(harness_file)])

    harness_content = (
        harness_tpl.replace("{{MODULE_NAME}}", module_name)
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
            norm_header,
            max_iterations=prelude_max_iterations,
            clang=prelude_clang,
            runner=prelude_runner or subprocess.run,
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

    mk_content = (
        f"TARGET := {module_name}\n"
        f"MAIN_FN := eva_main\n"
        f"SOURCES := {all_sources}\n"
        f"CPPFLAGS := {norm_cppflags} -I. -I{tpl_dir / 'acsl'}\n\n"
        + mk_tpl
    )
    makefile_path.write_text(mk_content, encoding="utf-8")

    sidecar = {
        "module": module_name,
        "harness_file": str(harness_file).replace("\\", "/"),
        "makefile": str(makefile_path).replace("\\", "/"),
        "sources": list(sources),
        "header": norm_header,
        "extra_includes": norm_extra_includes,
        "cppflags": norm_cppflags,
        "entry_fn": entry_fn,
        "entry_style": entry_style,
        "null_terminate": effective_null_terminate,
        "call_expr": call_expr,
        "eva_expr": eva_expr,
        "fuzz_expr": fuzz_expr,
        "include_source": include_source,
        "stubbed_callees": sorted(set(stubbed_callees or [])),
        "reachability": reachability,
        "max_input_size": max_input_size,
        "contract_notes": list(contract_notes or []),
        "repair_attempts": 0,
        "max_repair_attempts": MAX_HARNESS_REPAIR_ATTEMPTS,
        "repair_history": [],
        **prelude_fields,
    }
    atomic_write_json(harness_meta_file, sidecar)

    if prelude.get("status") == "unresolved" and prelude_fields["prelude_unresolved"] and prelude.get("iterations", 0) > 0:
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
        "makefile": str(makefile_path),
        "sources": sources,
        "header": norm_header,
        "extra_includes": norm_extra_includes,
        "cppflags": norm_cppflags,
        "entry_fn": entry_fn,
        "entry_style": entry_style,
        "null_terminate": effective_null_terminate,
        "include_source": include_source,
        "reachability": reachability,
        **prelude_fields,
    }


def record_harness_repair(harness_meta_path: Path, reason: str) -> dict[str, Any]:
    """Increment repair_attempts in harness_<module>.json and report whether the cap (2) is reached."""
    meta = load_json_strict(harness_meta_path)
    attempts = int(meta.get("repair_attempts", 0)) + 1
    max_attempts = int(meta.get("max_repair_attempts", MAX_HARNESS_REPAIR_ATTEMPTS))
    meta["repair_attempts"] = attempts
    history = list(meta.get("repair_history") or [])
    history.append({"attempt": attempts, "reason": reason, "timestamp": utc_now()})
    meta["repair_history"] = history
    atomic_write_json(harness_meta_path, meta)
    return {
        "module": meta.get("module"),
        "repair_attempts": attempts,
        "max_repair_attempts": max_attempts,
        "exhausted": attempts >= max_attempts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Dual-Use Eva + E-ACSL LibFuzzer Harness.")
    parser.add_argument("--module", help="Module slice identifier (e.g. snmpv3)")
    parser.add_argument("--sources", nargs="+", help="List of C source files in the module slice")
    parser.add_argument("--header", help="Primary module header to include in harness")
    parser.add_argument("--entry-fn", help="Target entry function accepting (buf, len)")
    parser.add_argument("--max-size", type=int, default=1500, help="Max symbolic/fuzzer buffer size in bytes")
    parser.add_argument("--cppflags", default="-I.", help="Extra preprocessor flags")
    parser.add_argument("--out-dir", type=Path, default=Path("workspace/harnesses"))
    parser.add_argument(
        "--reachability",
        choices=["untrusted_surface", "internal_api"],
        default="untrusted_surface",
        help="Reachability classification of the entry function",
    )
    parser.add_argument(
        "--entry-style",
        choices=list(VALID_ENTRY_STYLES),
        default="buffer_len",
        help="Entry invocation pattern: buffer_len (default), c_string, global_buffer, struct_arg, void_call, or custom",
    )
    parser.add_argument("--global-buf", default=None, help="Global buffer symbol when --entry-style=global_buffer")
    parser.add_argument("--global-len", default=None, help="Optional global length symbol when --entry-style=global_buffer")
    parser.add_argument("--struct-type", default=None, help="C struct type (e.g. 'Anomaly_T') when --entry-style=struct_arg")
    parser.add_argument("--extra-include", action="append", default=[], help="Additional header to #include in the harness (repeatable)")
    parser.add_argument("--call-expr", default=None, help="Custom C invocation statements using fuzz_buf and fuzz_len when --entry-style=custom")
    parser.add_argument("--eva-expr", default=None, help="Custom Eva invocation statements (overrides --call-expr for eva_main)")
    parser.add_argument("--fuzz-expr", default=None, help="Custom LibFuzzer invocation statements (overrides --call-expr for LLVMFuzzerTestOneInput)")
    parser.add_argument("--null-terminate", action="store_true", help="Guarantee fuzz_buf is NUL-terminated in both Eva and LibFuzzer")
    parser.add_argument(
        "--include-source",
        action="store_true",
        help="Include target .c source(s) directly in the harness translation unit for static-function visibility",
    )
    parser.add_argument("--stubbed-callee", action="append", default=[], help="External/I/O callee stubbed by the harness (repeatable)")
    parser.add_argument("--contract-note", action="append", default=[], help="Entry contract note (repeatable)")
    parser.add_argument(
        "--no-auto-prelude",
        dest="auto_prelude",
        action="store_false",
        help=(
            "Disable automatic prelude resolution (clang -fsyntax-only probe that #includes headers from the "
            "-I directories defining identifiers the module header uses but does not include)"
        ),
    )
    parser.add_argument("--record-repair", type=Path, default=None, help="Path to harness_<mod>.json to record a repair")
    parser.add_argument("--reason", default="", help="Reason for harness repair when using --record-repair")
    args = parser.parse_args(argv)

    if args.record_repair is not None:
        if not args.reason.strip():
            print(json.dumps({"ok": False, "error": "--record-repair requires --reason"}, indent=2))
            return 1
        res = record_harness_repair(args.record_repair, args.reason.strip())
        print(json.dumps(res, indent=2))
        return 0

    if not (args.module and args.sources and args.header and args.entry_fn):
        parser.error("--module, --sources, --header, and --entry-fn are required when generating a harness")

    try:
        result = generate_module_harness(
            module_name=args.module,
            sources=args.sources,
            header_include=args.header,
            entry_fn=args.entry_fn,
            max_input_size=args.max_size,
            cppflags=args.cppflags,
            out_dir=args.out_dir,
            reachability=args.reachability,
            contract_notes=args.contract_note,
            entry_style=args.entry_style,
            global_buf=args.global_buf,
            global_len=args.global_len,
            struct_type=args.struct_type,
            include_source=args.include_source,
            stubbed_callees=args.stubbed_callee,
            extra_includes=args.extra_include,
            call_expr=args.call_expr,
            eva_expr=args.eva_expr,
            fuzz_expr=args.fuzz_expr,
            null_terminate=args.null_terminate,
            auto_prelude=args.auto_prelude,
        )
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
