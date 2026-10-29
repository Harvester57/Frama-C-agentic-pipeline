#!/usr/bin/env python3
"""
Generates per-module Frama-C GNUmakefile, dual-use C harness
(supporting both Frama-C Eva via eva_main() and Clang LibFuzzer via LLVMFuzzerTestOneInput()),
and a structured sidecar JSON (harness_<module>.json) tracking entry reachability,
contract notes, and harness repair attempts (capped at 2).
"""

from __future__ import annotations

import argparse
import json
import sys
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
    }
    atomic_write_json(harness_meta_file, sidecar)

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
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
