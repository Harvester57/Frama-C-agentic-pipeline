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

With link units as DAG modules (step I5b, scripts/module_map.py), a harness that is a
sub-module of a unit answers for the unit's entry points in its scope (its lexer
module's functions), with callees followed across the whole unit. The unit itself
gets a row only for its Tier 1/2 entry points that lie in no harness module's scope
(or all of them when it has no harness): each is a gap unless its lexer module (or
the unit) is exempt in reach_exempt_modules.json, or a sidecar of the unit exempts it.

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
from module_map import ModuleMap, load_sidecars  # noqa: E402

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


def _functions_by_name(dag: dict[str, Any]) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    """Index DAG function records, as (DAG key, record), by plain name and by DAG key.

    A colliding name is keyed `file#name` in the DAG, and the model's edges name it by that key.
    """
    by_name: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for key, rec in (dag.get("functions") or {}).items():
        if isinstance(rec, dict):
            name = str(rec.get("name") or key)
            by_name.setdefault(name, []).append((key, rec))
            if key != name:
                by_name.setdefault(key, []).append((key, rec))
    return by_name


def dag_macro_aliases(dag: dict[str, Any]) -> dict[str, set[str]]:
    """The model's macro aliases (alias -> DAG keys of the functions it expands to)."""
    raw = dag.get("macro_aliases") or {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, set[str]] = {}
    for alias, keys in raw.items():
        vals = [keys] if isinstance(keys, str) else keys if isinstance(keys, list) else []
        if found := {str(k) for k in vals if isinstance(k, str)}:
            out[str(alias)] = found
    return out


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


def callee_closure(roots: set[str], by_name: dict[str, list[tuple[str, dict[str, Any]]]], module: str) -> set[str]:
    """Transitive in-repo callees of `roots`, as names and DAG keys.

    A colliding plain name resolves to its record in `module` first; a `file#name` key to its record.
    """
    reached: set[str] = set()
    work = sorted(roots)
    while work:
        name = work.pop()
        if name in reached:
            continue
        reached.add(name)
        recs = by_name.get(name) or []
        same_mod = [kr for kr in recs if kr[1].get("module") == module]
        for key, rec in same_mod or recs:
            plain = str(rec.get("name") or key)
            # The plain name stands for this record only when no other record shares it.
            idents = (key, plain) if len(by_name.get(plain) or []) == 1 else (key,)
            work.extend(i for i in idents if i not in reached)
            work.extend(c for c in rec.get("internal_callees") or [] if c not in reached)
    return reached


def check_module(
    module: str,
    dag: dict[str, Any],
    sidecar: dict[str, Any],
    harness_text: str,
    include_dirs: list[Path],
    mm: ModuleMap | None = None,
) -> dict[str, Any]:
    by_name = _functions_by_name(dag)
    fn_names = set(by_name)
    unit = mm.unit_of(module) if mm is not None else module
    mod_info = (dag.get("modules") or {}).get(module) or {}
    tier = mod_info.get("tier")
    if mm is not None and unit != module:
        # A sub-module of a link unit: the unit's entry points in its scope, callees across the unit.
        mod_fns = mm.scope_functions(module)
        entries = mm.scope_entry_points(module)
        tier = mm.tier_of(module)
    else:
        mod_fns = [f for f in mod_info.get("functions") or [] if isinstance(f, str)]
        entries = [f for f in mod_info.get("candidate_entry_points") or [] if isinstance(f, str)]
        if not entries:
            entries = [f for f in mod_fns if not any(r.get("is_static") for _, r in by_name.get(f) or [])]

    macros = header_macro_functions(include_dirs, fn_names)
    for alias, keys in dag_macro_aliases(dag).items():
        macros[alias] = macros.get(alias, set()) | keys
    inline_map = dag.get("header_inline_callees") or {}
    roots = harness_roots(harness_text, fn_names, macros, inline_map if isinstance(inline_map, dict) else {})
    reached = callee_closure(roots, by_name, unit)

    exempt_raw = sidecar.get("reach_exempt")
    exempt = {str(k): str(v) for k, v in exempt_raw.items()} if isinstance(exempt_raw, dict) else {}
    unreached = sorted(f for f in entries if f not in reached)
    gaps = [f for f in unreached if f not in exempt]
    row: dict[str, Any] = {
        "module": module,
        "tier": tier,
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
    if unit != module:
        row["unit"] = unit
    return row


def _harness_path(sidecar: dict[str, Any], sidecar_path: Path) -> Path:
    declared = sidecar.get("harness_file")
    if isinstance(declared, str) and Path(declared).is_file():
        return Path(declared)
    return sidecar_path.with_suffix(".c")


def _is_harnessed_tier(tier: Any) -> bool:
    return str(tier or "").startswith(HARNESSED_TIER_PREFIXES)


def check_unit(
    unit: str,
    mm: ModuleMap,
    harness_modules: list[str],
    module_exempt: dict[str, Any],
) -> dict[str, Any] | None:
    """
    The gate row of a link unit for its Tier 1/2 entry points outside every harness module's scope
    (all of them without a harness), or None when it has nothing to answer for: a unit-named harness
    covers the whole unit, and Tier 3 code without a harness is deferred by design.
    """
    info = mm.modules.get(unit) or {}
    tier = info.get("tier")
    if not harness_modules and unit in module_exempt and _is_harnessed_tier(tier):
        return {"module": unit, "tier": tier, "passed": True, "exempt": str(module_exempt[unit])}
    if unit in harness_modules:
        return None
    covered: set[str] = set()
    for h in harness_modules:
        covered.update(mm.scope_functions(h))
    entries = [e for e in info.get("candidate_entry_points") or [] if isinstance(e, str)]
    lexer_of = {e: str((mm.functions.get(e) or {}).get("lexer_module") or "") for e in entries}

    def fn_tier(e: str) -> Any:
        rec = mm.functions.get(e) or {}
        return rec.get("tier") or (mm.lexer_modules.get(lexer_of[e]) or {}).get("tier") or tier

    unharnessed = [e for e in entries if e not in covered and _is_harnessed_tier(fn_tier(e))]
    if not entries and not harness_modules and _is_harnessed_tier(tier):
        # No API entry point to place: the whole unit needs a harness or an exemption, as a module did.
        lexers = [str(m) for m in info.get("lexer_modules") or []]
        if lexers and all(m in module_exempt for m in lexers):
            return {"module": unit, "tier": tier, "passed": True, "exempt": _exempt_note(lexers, module_exempt)}
        return {"module": unit, "tier": tier, "passed": False, "error": "no_harness"}
    if not unharnessed:
        return None
    # The unit's name exempts it unless it also names one of the DAG's lexer modules (tweetnacl's
    # executable `main` holds the lexer module `main`): that key then exempts that lexer module only.
    unit_key = unit in module_exempt and (not harness_modules or unit not in mm.lexer_modules)
    sidecar_exempt: dict[str, str] = {}
    for h in harness_modules:
        raw = (mm.sidecars.get(h) or {}).get("reach_exempt")
        if isinstance(raw, dict):
            for fn, why in raw.items():
                sidecar_exempt.setdefault(str(fn), str(why))
    exempt: dict[str, str] = {}
    for e in unharnessed:
        if lexer_of[e] in module_exempt:
            exempt[e] = f"module {lexer_of[e]}: {module_exempt[lexer_of[e]]}"
        elif unit_key:
            exempt[e] = f"unit {unit}: {module_exempt[unit]}"
        elif e in sidecar_exempt:
            exempt[e] = sidecar_exempt[e]
    gaps = [e for e in unharnessed if e not in exempt]
    if not harness_modules:
        if gaps:
            return {
                "module": unit,
                "tier": tier,
                "passed": False,
                "error": "no_harness",
                "unharnessed_entry_points": unharnessed,
                "gaps": gaps,
            }
        lexers = sorted({lexer_of[e] for e in unharnessed})
        return {"module": unit, "tier": tier, "passed": True, "exempt": _exempt_note(lexers, module_exempt, unit)}
    return {
        "module": unit,
        "tier": tier,
        "harness_modules": harness_modules,
        "entry_points": len(entries),
        "unharnessed_entry_points": unharnessed,
        "exempt": exempt,
        "gaps": gaps,
        "passed": not gaps,
    }


def _exempt_note(lexers: list[str], module_exempt: dict[str, Any], unit: str | None = None) -> str:
    """Why a unit without a harness passes: the exemptions of the lexer modules holding its entry points."""
    parts = [f"{m}: {module_exempt[m]}" for m in lexers if m in module_exempt]
    if unit is not None and len(parts) < len(lexers):
        parts.append(f"{unit}: {module_exempt.get(unit, 'sidecar exemptions')}")
    return "every entry point is in an exempt module (" + "; ".join(parts) + ")"


def run_check(dag_path: Path, harness_dir: Path, modules: list[str] | None) -> dict[str, Any]:
    dag = load_json_strict(dag_path)
    if not isinstance(dag, dict):
        raise ValueError(f"{dag_path}: not a call-graph DAG object")
    dag_modules = dag.get("modules") or {}
    wanted = set(modules or [])
    module_exempt = load_json_optional(harness_dir / MODULE_EXEMPT_FILE, {})
    module_exempt = module_exempt if isinstance(module_exempt, dict) else {}
    mm = ModuleMap(dag, load_sidecars(harness_dir))
    link_units = mm.units_are_link_units
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
        if (mm.unit_of(module) if link_units else module) not in dag_modules:
            results.append({"module": module, "passed": True, "skipped": "module_not_in_dag"})
            continue
        harness_file = _harness_path(sidecar, sidecar_path)
        try:
            harness_text = harness_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            results.append({"module": module, "passed": False, "error": f"harness_unreadable: {exc}"})
            continue
        include_dirs = _include_dirs_from_cppflags(str(sidecar.get("cppflags") or ""))
        results.append(check_module(module, dag, sidecar, harness_text, include_dirs, mm=mm if link_units else None))
    if link_units:
        for unit in sorted(dag_modules):
            if wanted and unit not in wanted:
                continue
            subs = sorted(h for h in harnessed if mm.unit_of(h) == unit)
            row = check_unit(unit, mm, subs, module_exempt)
            if row is not None:
                results.append(row)
        return _report(dag_path, results)
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
    return _report(dag_path, results)


def _report(dag_path: Path, results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "generated_at": utc_now(),
        "dag": str(dag_path).replace("\\", "/"),
        "passed": all(r.get("passed") for r in results),
        "modules": results,
    }


def record_exempt(
    harness_dir: Path, module: str, function: str | None, reason: str, dag_path: Path | None = None
) -> dict[str, Any]:
    """
    Record an exemption: a whole module (a lexer module or link unit name) without `function`, else
    one entry point in the module's sidecar. A link unit without a harness of its own records an entry
    point it leaves unharnessed in the sidecar of its first sub-module (read from `dag_path`).
    """
    if function is None:
        path = harness_dir / MODULE_EXEMPT_FILE
        exempt_modules = load_json_optional(path, {})
        exempt_modules = dict(exempt_modules) if isinstance(exempt_modules, dict) else {}
        exempt_modules[module] = reason
        harness_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, dict(sorted(exempt_modules.items())))
        return {"module": module, "function": None, "reason": reason}
    sidecar_path = harness_dir / f"harness_{module}.json"
    if not sidecar_path.is_file() and dag_path is not None and dag_path.is_file():
        stand_in = ModuleMap(load_json_strict(dag_path), load_sidecars(harness_dir)).harness_module_for(module)
        if stand_in:
            sidecar_path = harness_dir / f"harness_{stand_in}.json"
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
    p_ex.add_argument("--dag", type=Path, default=DEFAULT_DAG, help="To place a link unit's exemption")
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
                json.dumps(
                    record_exempt(args.harness_dir, args.module, args.function, args.reason.strip(), args.dag),
                    indent=2,
                )
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
