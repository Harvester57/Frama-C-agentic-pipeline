#!/usr/bin/env python3
"""
Phase 0 gate stamp (stdlib only): workspace/reports/phase0_gates.json.

The two Phase 0 gates write their results here, and the Make recipes that consume harnesses
(build, fuzz, coverage, Eva, wp-queue) check it first, so no step can run on a harness that failed
a gate (docs/phase0-implementation-plan.md, step I1):

  reach        harness_reach.py check: every DAG entry point of a module is reached by its harness,
               or exempted with a reason. Recorded with a digest of the module's harness files and
               of the call-graph DAG, so a harness regenerated or a DAG rebuilt after the check fails
               the gate until the check runs again.
  build_check  pipeline_make.py build-check: every fuzzed module builds with E-ACSL, or its
               sanitizer engine is a recorded choice (params set --fuzz-engine sanitizers). The check
               judges the module's current build report when there is one: Make rebuilds a module
               as a prerequisite of fuzz-<mod>, so that is the binary the campaign uses.

    phase0_gates.py check [--module M] [--need reach,build_check] [--modules "A B"] [--fuzzed "A"]

exits 0 when the gate passes and 1 with the reasons otherwise. Without --module, every module of
each needed section must pass, with its harness and the DAG unchanged since the reach check; --modules and
--fuzzed (wp-queue passes the plan's) also require a row for each module they name.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import ArtifactError, atomic_write_json, load_json_optional, run_lock, utc_now  # noqa: E402

GATES_JSON = "workspace/reports/phase0_gates.json"
HARNESS_DIR = "workspace/harnesses"
DAG_JSON = "workspace/reports/callgraph_dag.json"
SECTIONS = ("reach", "build_check")
HOW_TO_RUN = {
    "reach": "python3 $S/harness_reach.py check",
    "build_check": "python3 $S/pipeline_make.py build-check",
}


def harness_digest(run_dir: Path, module: str) -> str | None:
    """sha256 over the module's harness sidecar and source, or None when the harness is missing."""
    h = hashlib.sha256()
    found = False
    for suffix in (".json", ".c"):
        path = run_dir / HARNESS_DIR / f"harness_{module}{suffix}"
        if path.is_file():
            found = True
            h.update(suffix.encode())
            h.update(path.read_bytes())
    return h.hexdigest() if found else None


def dag_digest(run_dir: Path, dag_path: Path | None = None) -> str | None:
    """sha256 of the call-graph DAG (the run's own unless `dag_path`), or None when it is missing."""
    path = Path(dag_path) if dag_path is not None else Path(run_dir) / DAG_JSON
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def load_gates(run_dir: Path) -> dict[str, Any]:
    data = load_json_optional(run_dir / GATES_JSON, {})
    return data if isinstance(data, dict) else {}


def _store(run_dir: Path, section: str, entry: dict[str, Any]) -> dict[str, Any]:
    with run_lock("phase0_gates", run_dir):
        gates = load_gates(run_dir)
        gates[section] = entry
        atomic_write_json(run_dir / GATES_JSON, gates)
    return gates


def record_reach(
    run_dir: Path, report: dict[str, Any], partial: bool = False, dag_path: Path | None = None
) -> dict[str, Any]:
    """
    Store a harness_reach.py report. A `partial` report (check limited with --module) updates only
    its modules; the section passes only while every recorded module does. Each row records the
    digest of the DAG it was checked against (`dag_path`, default the run's), so a DAG rebuilt after
    the check fails the gate for that row until the check runs again.
    """
    run_dir = Path(run_dir)
    dag = dag_digest(run_dir, dag_path)
    rows: dict[str, Any] = {}
    for row in report.get("modules") or []:
        name = str(row.get("module"))
        rows[name] = {
            "passed": bool(row.get("passed")),
            "gaps": list(row.get("gaps") or []),
            "error": row.get("error"),
            "exempt": row.get("exempt"),
            "harness_digest": harness_digest(run_dir, name),
            "dag_digest": dag,
        }
    # Read the prior rows under the lock: Make runs one partial check per module in parallel
    # (reach-dynamic-<m>), and a read outside it loses the rows another one stores meanwhile.
    with run_lock("phase0_gates", run_dir):
        gates = load_gates(run_dir)
        modules: dict[str, Any] = {}
        if partial:
            prior = gates.get("reach")
            if isinstance(prior, dict) and isinstance(prior.get("modules"), dict):
                modules = dict(prior["modules"])
        modules.update(rows)
        gates["reach"] = {
            "passed": all(m["passed"] for m in modules.values()),
            "generated_at": utc_now(),
            "modules": dict(sorted(modules.items())),
        }
        atomic_write_json(run_dir / GATES_JSON, gates)
    return gates


def record_build_check(run_dir: Path, out: dict[str, Any]) -> dict[str, Any]:
    """Store a pipeline_make.py build-check result."""
    modules = {
        str(name): {
            "ok": bool(r.get("ok")),
            "status": r.get("status"),
            "fuzz_engine": r.get("fuzz_engine"),
            "first_error": r.get("first_error"),
            "reason": r.get("reason"),
        }
        for name, r in (out.get("modules") or {}).items()
        if isinstance(r, dict)
    }
    entry = {
        "ok": bool(out.get("ok")),
        "generated_at": utc_now(),
        "error": out.get("error"),
        "modules": dict(sorted(modules.items())),
    }
    return _store(Path(run_dir), "build_check", entry)


def _section_ok(section: str, entry: dict[str, Any]) -> bool:
    return bool(entry.get("passed") if section == "reach" else entry.get("ok"))


def current_build_status(run_dir: Path, module: str, row: dict[str, Any]) -> tuple[bool, str] | None:
    """
    The build-check verdict on the module's current build report (workspace/build/<mod>.build.json),
    or None when there is none. Make rebuilds a module as a prerequisite of fuzz-<mod> before the
    gate runs, so the report the campaign will use can be newer than build-check's stamp.
    """
    try:
        report = load_json_optional(run_dir / "workspace" / "build" / f"{module}.build.json", None)
    except ArtifactError:
        return None
    if not isinstance(report, dict):
        return None
    if (report.get("compile") or {}).get("returncode") != 0:
        return False, "build_failed"
    if report.get("engine_used") == "eacsl":
        return True, "eacsl"
    if row.get("fuzz_engine") == "sanitizers":
        return True, "sanitizers_chosen"
    return False, "eacsl_fallback"


def check(
    run_dir: Path,
    module: str | None = None,
    need: tuple[str, ...] = SECTIONS,
    modules_expected: list[str] | None = None,
    fuzzed_expected: list[str] | None = None,
) -> list[str]:
    """
    Reasons the gate fails for `module` (or for the whole run when None); empty when it passes.

    For the whole run, every recorded module must pass, and a harness or a DAG changed since the
    reach check fails it (for one module, its own row). `modules_expected` (every module of the plan) and `fuzzed_expected` (its fuzzed ones)
    name the modules each section must have checked: a harness added after the check, or a module
    build-check never built, fails the gate instead of passing unseen.
    """
    run_dir = Path(run_dir)
    gates = load_gates(run_dir)
    current_dag = dag_digest(run_dir)
    reasons: list[str] = []
    for section in need:
        entry = gates.get(section)
        if not isinstance(entry, dict):
            reasons.append(f"{section} has not run: run `{HOW_TO_RUN[section]}` first")
            continue
        raw_modules = entry.get("modules")
        modules: dict[str, Any] = raw_modules if isinstance(raw_modules, dict) else {}
        if module is None:
            if section == "build_check":
                failed = sorted(m for m, r in modules.items() if not _build_ok(run_dir, m, r)[0])
                if failed or (not modules and not entry.get("ok")):
                    reasons.append(f"{section} failed for {', '.join(failed) or 'the run'}")
                expected = fuzzed_expected
            else:
                if not _section_ok(section, entry):
                    failed = sorted(m for m, r in modules.items() if not r.get("passed"))
                    reasons.append(f"{section} failed for {', '.join(failed) or 'the run'}")
                stale = sorted(
                    m
                    for m, r in modules.items()
                    if r.get("passed") and r.get("harness_digest") != harness_digest(run_dir, m)
                )
                if stale:
                    reasons.append(f"the harness of {', '.join(stale)} changed after the reach gate ran; run it again")
                dag_stale = sorted(
                    m for m, r in modules.items() if r.get("passed") and r.get("dag_digest") != current_dag
                )
                if dag_stale:
                    reasons.append(_dag_changed(", ".join(dag_stale)))
                expected = modules_expected
            unchecked = sorted({m for m in expected or [] if m} - set(modules))
            if unchecked:
                reasons.append(f"{section}: {', '.join(unchecked)} not checked; run `{HOW_TO_RUN[section]}` again")
            continue
        row = modules.get(module)
        if section == "build_check" and row is None:
            continue  # build-check covers fuzzed modules only; this one is not fuzzed
        if row is None:
            reasons.append(f"{section}: module {module} was not checked; run `{HOW_TO_RUN[section]}` again")
            continue
        if section == "reach":
            if not row.get("passed"):
                detail = row.get("error") or f"entry points not reached: {', '.join(row.get('gaps') or [])}"
                reasons.append(f"reach gate failed for {module}: {detail}")
            elif row.get("harness_digest") != harness_digest(run_dir, module):
                reasons.append(f"the harness of {module} changed after the reach gate ran; run it again")
            elif row.get("dag_digest") != current_dag:
                reasons.append(_dag_changed(module))
        else:
            ok, status = _build_ok(run_dir, module, row)
            if not ok:
                detail = row.get("first_error") or row.get("reason")
                first = f" ({detail})" if detail and status == row.get("status") else ""
                reasons.append(f"build-check failed for {module}: {status}{first}")
    return reasons


def _dag_changed(modules: str) -> str:
    return f"the call-graph DAG changed after the reach gate ran for {modules}; run `{HOW_TO_RUN['reach']}` again"


def _build_ok(run_dir: Path, module: str, row: dict[str, Any]) -> tuple[bool, str]:
    """The current build report's verdict when there is one, else the one build-check recorded."""
    current = current_build_status(run_dir, module, row)
    return current if current is not None else (bool(row.get("ok")), str(row.get("status")))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Check the Phase 0 gate stamp")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--run-dir", type=Path, default=Path("."))
    c.add_argument("--module", default=None)
    c.add_argument("--need", default=",".join(SECTIONS), help="Comma-separated sections: reach, build_check")
    c.add_argument(
        "--modules", default=None, help="Whole run: the plan's modules (space-separated), each needing a reach row"
    )
    c.add_argument(
        "--fuzzed",
        default=None,
        help="Whole run: the plan's fuzzed modules (space-separated), each needing a build row",
    )
    a = p.parse_args(argv)
    need = tuple(s.strip() for s in a.need.split(",") if s.strip())
    unknown = [s for s in need if s not in SECTIONS]
    if unknown:
        p.error(f"unknown gate section(s): {', '.join(unknown)}")
    if a.module and (a.modules is not None or a.fuzzed is not None):
        p.error("--modules and --fuzzed apply to the whole run, not with --module")
    try:
        reasons = check(
            a.run_dir,
            a.module,
            need,
            None if a.modules is None else a.modules.split(),
            None if a.fuzzed is None else a.fuzzed.split(),
        )
    except (ArtifactError, OSError, ValueError) as exc:
        reasons = [f"cannot read {GATES_JSON}: {exc}"]
    print(json.dumps({"ok": not reasons, "module": a.module, "need": list(need), "reasons": reasons}))
    for reason in reasons:
        print(f"phase0 gate: {reason}", file=sys.stderr)
    return 1 if reasons else 0


if __name__ == "__main__":
    sys.exit(main())
