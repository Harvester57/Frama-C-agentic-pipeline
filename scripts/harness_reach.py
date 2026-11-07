#!/usr/bin/env python3
"""
Phase 0 harness reachability gate (stdlib only).

A module harness that calls one entry point leaves the rest of the module's API
unexercised: Phase 1 never fuzzes it, Phase 2 marks it dead ("harness gap"), and
Phase 3 breakers cannot reach it. This gate measures, before any fuzzing, which of
each module's entry points (`candidate_entry_points` in the call-graph DAG) the
harness reaches statically:

  roots    = DAG functions the harness file names, directly or through a header
             macro (e.g. a `for_each` iterator) or a header `static inline` wrapper
  reached  = roots plus their transitive in-repo callees (`internal_callees`)

An entry point the harness does not reach fails the gate unless the sidecar
records why it cannot be harnessed (`reach_exempt`, written by the `exempt`
subcommand). Static reach over-approximates (a call behind an impossible branch
counts); Phase 1/2 measure the dynamic reach.

Subcommands:
  check   [--module M]... [--out FILE]   gate every harnessed module (exit 1 on a gap)
  exempt  --module M [--function F] --reason R
          record an accepted gap: one entry point (in the module's sidecar), or a whole
          module that needs no harness (in reach_exempt_modules.json)

Exit code 0 when the gate passes, 1 when a module has an unexempted gap, 2 on
usage/IO problems.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import phase0_gates  # noqa: E402
from framac_common import (  # noqa: E402
    ArtifactError,
    atomic_write_json,
    load_json_optional,
    load_json_strict,
    utc_now,
)
from generate_harness import _include_dirs_from_cppflags, _strip_c_comments  # noqa: E402

DEFAULT_DAG = Path("workspace/reports/callgraph_dag.json")
DEFAULT_HARNESS_DIR = Path("workspace/harnesses")
DEFAULT_OUT = Path("workspace/reports/harness_reach.json")
# Not named harness_*.json, so the sidecar glob never reads it as a module.
MODULE_EXEMPT_FILE = "reach_exempt_modules.json"
# Tiers Phase 0 must harness (framac-slice Step 4); a Tier 3 module without a harness is by design.
HARNESSED_TIER_PREFIXES = ("Tier 1A", "Tier 1B", "Tier 2")
_IDENT_RE = re.compile(r"\b([A-Za-z_]\w*)\b")
_DEFINE_RE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(.*)$")
_HEADER_SUFFIXES = (".h", ".hh", ".hpp", ".inc")


def _logical_lines(text: str) -> list[str]:
    """Join backslash-continued lines so a multi-line #define is one line."""
    return text.replace("\\\r\n", " ").replace("\\\n", " ").splitlines()


def header_macro_functions(include_dirs: list[Path], fn_names: set[str]) -> dict[str, set[str]]:
    """
    Map each function-naming macro defined in the headers of `include_dirs` (top level of
    each directory) to the DAG functions its body names, following macro-to-macro uses.
    """
    raw: dict[str, set[str]] = {}
    for inc_dir in include_dirs:
        if not inc_dir.is_dir():
            continue
        for hdr in sorted(inc_dir.iterdir()):
            if not hdr.is_file() or hdr.suffix not in _HEADER_SUFFIXES:
                continue
            try:
                text = _strip_c_comments(hdr.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            for line in _logical_lines(text):
                m = _DEFINE_RE.match(line)
                if m:
                    raw.setdefault(m.group(1), set()).update(_IDENT_RE.findall(m.group(2)))
    resolved: dict[str, set[str]] = {}

    def _resolve(name: str, stack: frozenset[str]) -> set[str]:
        if name in resolved:
            return resolved[name]
        out: set[str] = set()
        for ident in raw.get(name, set()):
            if ident in fn_names:
                out.add(ident)
            elif ident in raw and ident not in stack:
                out |= _resolve(ident, stack | {ident})
        resolved[name] = out
        return out

    return {name: fns for name in raw if (fns := _resolve(name, frozenset({name})))}


def _functions_by_name(dag: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Index DAG function records by plain name (colliding names are keyed `file#name`)."""
    by_name: dict[str, list[dict[str, Any]]] = {}
    for key, rec in (dag.get("functions") or {}).items():
        if isinstance(rec, dict):
            by_name.setdefault(str(rec.get("name") or key), []).append(rec)
    return by_name


def harness_roots(
    harness_text: str,
    fn_names: set[str],
    macros: dict[str, set[str]],
    inline_map: dict[str, list[str]],
) -> set[str]:
    """DAG functions the harness names directly, through a header macro, or through an inline wrapper."""
    roots: set[str] = set()
    for ident in set(_IDENT_RE.findall(_strip_c_comments(harness_text))):
        if ident in fn_names:
            roots.add(ident)
        roots |= macros.get(ident, set())
        roots |= {f for f in inline_map.get(ident) or [] if f in fn_names}
    return roots


def callee_closure(roots: set[str], by_name: dict[str, list[dict[str, Any]]], module: str) -> set[str]:
    """Transitive in-repo callees of `roots`; a colliding name resolves to its record in `module` first."""
    reached: set[str] = set()
    work = sorted(roots)
    while work:
        name = work.pop()
        if name in reached:
            continue
        reached.add(name)
        recs = by_name.get(name) or []
        same_mod = [r for r in recs if r.get("module") == module]
        for rec in same_mod or recs:
            work.extend(c for c in rec.get("internal_callees") or [] if c not in reached)
    return reached


def check_module(
    module: str,
    dag: dict[str, Any],
    sidecar: dict[str, Any],
    harness_text: str,
    include_dirs: list[Path],
) -> dict[str, Any]:
    by_name = _functions_by_name(dag)
    fn_names = set(by_name)
    mod_info = (dag.get("modules") or {}).get(module) or {}
    mod_fns = [f for f in mod_info.get("functions") or [] if isinstance(f, str)]
    entries = [f for f in mod_info.get("candidate_entry_points") or [] if isinstance(f, str)]
    if not entries:
        entries = [f for f in mod_fns if not any(r.get("is_static") for r in by_name.get(f) or [])]

    macros = header_macro_functions(include_dirs, fn_names)
    inline_map = dag.get("header_inline_callees") or {}
    roots = harness_roots(harness_text, fn_names, macros, inline_map if isinstance(inline_map, dict) else {})
    reached = callee_closure(roots, by_name, module)

    exempt_raw = sidecar.get("reach_exempt")
    exempt = {str(k): str(v) for k, v in exempt_raw.items()} if isinstance(exempt_raw, dict) else {}
    unreached = sorted(f for f in entries if f not in reached)
    gaps = [f for f in unreached if f not in exempt]
    return {
        "module": module,
        "tier": mod_info.get("tier"),
        "harness_file": sidecar.get("harness_file"),
        "entry_points": len(entries),
        "entry_points_reached": len(entries) - len(unreached),
        "functions": len(mod_fns),
        "functions_reached": sum(1 for f in mod_fns if f in reached),
        "roots": sorted(roots & set(mod_fns)) + sorted(roots - set(mod_fns)),
        "unreached_entry_points": unreached,
        "exempt": {f: exempt[f] for f in unreached if f in exempt},
        "gaps": gaps,
        "passed": not gaps,
    }


def _harness_path(sidecar: dict[str, Any], sidecar_path: Path) -> Path:
    declared = sidecar.get("harness_file")
    if isinstance(declared, str) and Path(declared).is_file():
        return Path(declared)
    return sidecar_path.with_suffix(".c")


def run_check(dag_path: Path, harness_dir: Path, modules: list[str] | None) -> dict[str, Any]:
    dag = load_json_strict(dag_path)
    if not isinstance(dag, dict):
        raise ValueError(f"{dag_path}: not a call-graph DAG object")
    dag_modules = dag.get("modules") or {}
    wanted = set(modules or [])
    module_exempt = load_json_optional(harness_dir / MODULE_EXEMPT_FILE, {})
    module_exempt = module_exempt if isinstance(module_exempt, dict) else {}
    results: list[dict[str, Any]] = []
    harnessed: set[str] = set()
    for sidecar_path in sorted(harness_dir.glob("harness_*.json")):
        sidecar = load_json_optional(sidecar_path, {})
        if not isinstance(sidecar, dict):
            continue
        module = str(sidecar.get("module") or sidecar_path.stem[len("harness_") :])
        harnessed.add(module)
        if wanted and module not in wanted:
            continue
        if module not in dag_modules:
            results.append({"module": module, "passed": True, "skipped": "module_not_in_dag"})
            continue
        harness_file = _harness_path(sidecar, sidecar_path)
        try:
            harness_text = harness_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            results.append({"module": module, "passed": False, "error": f"harness_unreadable: {exc}"})
            continue
        include_dirs = _include_dirs_from_cppflags(str(sidecar.get("cppflags") or ""))
        results.append(check_module(module, dag, sidecar, harness_text, include_dirs))
    for module, info in sorted(dag_modules.items()):
        if module in harnessed or (wanted and module not in wanted) or not isinstance(info, dict):
            continue
        if not str(info.get("tier") or "").startswith(HARNESSED_TIER_PREFIXES):
            continue
        if module in module_exempt:
            results.append(
                {"module": module, "tier": info.get("tier"), "passed": True, "exempt": str(module_exempt[module])}
            )
        else:
            results.append({"module": module, "tier": info.get("tier"), "passed": False, "error": "no_harness"})
    return {
        "generated_at": utc_now(),
        "dag": str(dag_path).replace("\\", "/"),
        "passed": all(r.get("passed") for r in results),
        "modules": results,
    }


def record_exempt(harness_dir: Path, module: str, function: str | None, reason: str) -> dict[str, Any]:
    if function is None:
        path = harness_dir / MODULE_EXEMPT_FILE
        exempt_modules = load_json_optional(path, {})
        exempt_modules = dict(exempt_modules) if isinstance(exempt_modules, dict) else {}
        exempt_modules[module] = reason
        harness_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, dict(sorted(exempt_modules.items())))
        return {"module": module, "function": None, "reason": reason}
    sidecar_path = harness_dir / f"harness_{module}.json"
    sidecar = load_json_strict(sidecar_path)
    if not isinstance(sidecar, dict):
        raise ValueError(f"{sidecar_path}: not a harness sidecar object")
    exempt = sidecar.get("reach_exempt")
    exempt = dict(exempt) if isinstance(exempt, dict) else {}
    exempt[function] = reason
    sidecar["reach_exempt"] = dict(sorted(exempt.items()))
    atomic_write_json(sidecar_path, sidecar)
    return {"module": module, "function": function, "reason": reason, "reach_exempt": sidecar["reach_exempt"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 0 harness reachability gate.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_check = sub.add_parser("check", help="Gate every harnessed module against its DAG entry points")
    p_check.add_argument("--dag", type=Path, default=DEFAULT_DAG)
    p_check.add_argument("--harness-dir", type=Path, default=DEFAULT_HARNESS_DIR)
    p_check.add_argument("--module", action="append", default=[], help="Limit to this module (repeatable)")
    p_check.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Report path ('-' for stdout only)")
    p_ex = sub.add_parser("exempt", help="Record why an entry point cannot be harnessed")
    p_ex.add_argument("--harness-dir", type=Path, default=DEFAULT_HARNESS_DIR)
    p_ex.add_argument("--module", required=True)
    p_ex.add_argument(
        "--function", default=None, help="Entry point to exempt; omit to exempt a module without a harness"
    )
    p_ex.add_argument("--reason", required=True)
    args = parser.parse_args(argv)

    try:
        if args.cmd == "exempt":
            if not args.reason.strip():
                raise ValueError("--reason must not be empty")
            print(
                json.dumps(record_exempt(args.harness_dir, args.module, args.function, args.reason.strip()), indent=2)
            )
            return 0
        report = run_check(args.dag, args.harness_dir, args.module)
    except (ArtifactError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 2
    if str(args.out) != "-":
        args.out.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(args.out, report)
        # The gate stamp the Make recipes check (phase0_gates.py); `--out -` is a dry look.
        phase0_gates.record_reach(Path("."), report, partial=bool(args.module))
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
