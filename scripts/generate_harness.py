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


def resolve_template_dir() -> Path:
    if DEFAULT_TEMPLATE_DIR.exists():
        return DEFAULT_TEMPLATE_DIR
    return Path(__file__).resolve().parent.parent / "templates"


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
) -> dict[str, Any]:
    if reachability not in ("untrusted_surface", "internal_api"):
        raise ValueError(f"invalid reachability: {reachability!r}")

    tpl_dir = resolve_template_dir()
    harness_tpl = (tpl_dir / "harness_dual.c.template").read_text(encoding="utf-8")
    mk_tpl = (tpl_dir / "GNUmakefile.template").read_text(encoding="utf-8")

    out_dir.mkdir(parents=True, exist_ok=True)
    harness_file = out_dir / f"harness_{module_name}.c"
    harness_meta_file = out_dir / f"harness_{module_name}.json"
    makefile_path = out_dir / f"{module_name}.mk"

    eva_call = f"{entry_fn}(input_buf, input_len);"
    fuzz_call = f"{entry_fn}(bounded_buf, size);"

    harness_content = (
        harness_tpl.replace("{{MODULE_NAME}}", module_name)
        .replace("{{MODULE_HEADER}}", header_include)
        .replace("{{MAX_INPUT_SIZE}}", str(max_input_size))
        .replace("{{TARGET_INVOCATION_EVA}}", eva_call)
        .replace("{{TARGET_INVOCATION_FUZZ}}", fuzz_call)
    )
    harness_file.write_text(harness_content, encoding="utf-8")

    all_sources = " ".join(sources + [str(harness_file)])
    mk_content = (
        f"TARGET := {module_name}\n"
        f"MAIN_FN := eva_main\n"
        f"SOURCES := {all_sources}\n"
        f"CPPFLAGS := {cppflags} -I. -I{tpl_dir / 'acsl'}\n\n"
        + mk_tpl
    )
    makefile_path.write_text(mk_content, encoding="utf-8")

    sidecar = {
        "module": module_name,
        "harness_file": str(harness_file).replace("\\", "/"),
        "makefile": str(makefile_path).replace("\\", "/"),
        "sources": list(sources),
        "header": header_include,
        "entry_fn": entry_fn,
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
        "entry_fn": entry_fn,
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
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
