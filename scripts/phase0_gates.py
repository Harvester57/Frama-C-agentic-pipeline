#!/usr/bin/env python3
"""
Phase 0 gate stamp (stdlib only): workspace/reports/phase0_gates.json.

The two Phase 0 gates write their results here, and the Make recipes that consume harnesses
(build, fuzz, coverage, Eva, wp-queue) check it first, so no step can run on a harness that failed
a gate (docs/plans/archive/phase0-implementation-plan.md, step I1):

  reach        harness_reach.py check: every DAG entry point of a module is reached by its harness,
               or exempted with a reason. Recorded with a digest of the module's harness files and
               of the call-graph DAG, so a harness regenerated or a DAG rebuilt after the check fails
               the gate until the check runs again.
  build_check  pipeline_make.py build-check: every fuzzed module builds with E-ACSL, or its
               sanitizer engine is a recorded choice (params set --fuzz-engine sanitizers). The check
               judges the module's current build report when there is one: Make rebuilds a module
               as a prerequisite of fuzz-<mod>, so that is the binary the campaign uses.

Independently of the sections, a module that calls a function of a stub overlay header whose
stub-check failed (workspace/reports/stub_check.json, scripts/stub_check.py) fails the gate until a
stub-check of the fixed header passes.

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
from collections.abc import Iterable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import ArtifactError, atomic_write_json, load_json_optional, run_lock, utc_now  # noqa: E402

GATES_JSON = "workspace/reports/phase0_gates.json"
HARNESS_DIR = "workspace/harnesses"
DAG_JSON = "workspace/reports/callgraph_dag.json"
SECTIONS = ("reach", "build_check")
DYNAMIC_GAP_ERROR = "dynamic: entry points never executed by the corpus"
HOW_TO_RUN = {
    "reach": "python3 $S/harness_reach.py check",
    "build_check": "python3 $S/pipeline_make.py build-check",
}


WORK_DIR = "workspace/work"


def target_fuzzer_source(run_dir: Path, sidecar: Any) -> Path | None:
    """
    The fuzzer source file of a target fuzz module (sidecar `target_fuzzer.source`), resolved like the
    sidecar's sources (pipeline_make._plan_module: the run directory, then the work tree), or None when
    the sidecar has no `target_fuzzer` or the file is not found.
    """
    tf = sidecar.get("target_fuzzer") if isinstance(sidecar, dict) else None
    src = tf.get("source") if isinstance(tf, dict) else None
    if not isinstance(src, str) or not src.strip():
        return None
    candidates = [Path(src)] if src.startswith("/") else [Path(run_dir) / src]
    candidates.append(Path(run_dir) / WORK_DIR / src.lstrip("/"))
    return next((p for p in candidates if p.is_file()), None)


def harness_digest(run_dir: Path, module: str, ignore_exempt: bool = False) -> str | None:
    """
    sha256 over the module's harness sidecar and source, or None when the harness is missing. A target
    fuzz module (sidecar `target_fuzzer`) also covers its fuzzer source: editing the target's fuzzer
    changes what the harness runs, as a harness edit does.

    `ignore_exempt` leaves the sidecar's `reach_exempt` (and `warnings`) out: the dynamic reach rows use it to tell a
    repaired harness (which clears every measured gap) from a recorded exemption (which clears only the
    entry points it names).
    """
    h = hashlib.sha256()
    found = False
    sidecar: Any = None
    for suffix in (".json", ".c"):
        path = run_dir / HARNESS_DIR / f"harness_{module}{suffix}"
        if path.is_file():
            found = True
            data = path.read_bytes()
            if suffix == ".json":
                try:
                    sidecar = json.loads(data)
                except ValueError:
                    sidecar = None
                if ignore_exempt and isinstance(sidecar, dict):
                    # `warnings` is rewritten with every sidecar write (the schema check's result).
                    rest = {k: v for k, v in sidecar.items() if k not in ("reach_exempt", "warnings")}
                    data = json.dumps(rest, sort_keys=True, separators=(",", ":")).encode()
            h.update(suffix.encode())
            h.update(data)
    if isinstance(sidecar, dict) and isinstance(sidecar.get("target_fuzzer"), dict):
        src = target_fuzzer_source(run_dir, sidecar)
        h.update(b"target_fuzzer")
        try:
            h.update(src.read_bytes() if src is not None else b"\0missing")
        except OSError:
            h.update(b"\0unreadable")
    return h.hexdigest() if found else None


# `harness_digest` of a report built from runs that cannot be tied to the current harness. It equals no
# digest, so every comparison with the current harness fails (wp_scheduler.py refresh: stale evidence).
HARNESS_DIGEST_UNKNOWN = "unknown"


def derived_harness_digest(run_dir: Path, module: str, inputs: Iterable[Path]) -> str | None:
    """
    The `harness_digest` of a report built from `inputs` that record none (Eva trials or shards written
    before the field existed). It is the current harness's digest when every input is newer than the
    harness source, else HARNESS_DIGEST_UNKNOWN: a report rebuilt today from runs that predate a harness
    repair must not pass for one of the repaired harness because the rebuild is recent. None when the
    module has no harness.
    """
    current = harness_digest(run_dir, module, ignore_exempt=True)
    if current is None:
        return None
    paths = [Path(p) for p in inputs]
    try:
        # The source, as wp_scheduler's refresh reads it: the sidecar is rewritten for bookkeeping.
        source = next(
            p for s in (".c", ".json") if (p := Path(run_dir) / HARNESS_DIR / f"harness_{module}{s}").is_file()
        )
        changed = source.stat().st_mtime
        fresh = bool(paths) and all(p.stat().st_mtime > changed for p in paths)
    except (OSError, StopIteration):
        fresh = False
    return current if fresh else HARNESS_DIGEST_UNKNOWN


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
            # Why crash inputs did not count as execution of a gap (harness_reach.py `crash_notes`).
            "notes": [str(n) for n in (row.get("crash_notes") or [])],
            "exempt": row.get("exempt"),
            "origin": "dynamic" if row.get("error") == DYNAMIC_GAP_ERROR else "static",
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
            **{k: r[k] for k in ("reason_code", "next_step") if r.get(k)},
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


def row_origin(row: dict[str, Any]) -> str:
    """
    `dynamic` for a row that failed only on the dynamic corpus gap, `static` for every other failure. A row
    written before `origin` was recorded is dynamic when its error is the dynamic gap's.
    """
    origin = row.get("origin")
    if origin in ("dynamic", "static"):
        return str(origin)
    return "dynamic" if row.get("error") == DYNAMIC_GAP_ERROR else "static"


def _row_reach_ok(row: dict[str, Any]) -> bool:
    """
    A row passes when the check passed, or when it failed only on a dynamic gap (D2): that gap holds back
    the module's planned units from WP (`ledger.py gate-reach`), and no fuzz, coverage or Eva target.
    """
    return bool(row.get("passed")) or row_origin(row) == "dynamic"


def dynamic_gaps(run_dir: Path) -> dict[str, list[str]]:
    """Module -> the entry points its dynamic reach row never saw executed, for the rows that did not pass."""
    reach = load_gates(Path(run_dir)).get("reach")
    rows = reach.get("modules") if isinstance(reach, dict) else None
    if not isinstance(rows, dict):
        return {}
    return {
        str(module): [str(g) for g in row.get("gaps") or []]
        for module, row in sorted(rows.items())
        if isinstance(row, dict) and not row.get("passed") and row_origin(row) == "dynamic"
    }


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
    reach check fails it (for one module, its own row). A row that failed only on a dynamic gap passes
    (D2; `dynamic_gaps` lists them, and `ledger.py gate-reach` holds their units back). `modules_expected`
    (every module of the plan) and `fuzzed_expected` (its fuzzed ones) name the modules each section must
    have checked: a harness added after the check, or a module build-check never built, fails the gate
    instead of passing unseen.
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
                failed = sorted(m for m, r in modules.items() if not _row_reach_ok(r))
                if failed or (not modules and not _section_ok(section, entry)):
                    reasons.append(
                        f"{section} failed for {', '.join(failed) or 'the run'}; {_reach_next_step('<mod>')}"
                    )
                stale = sorted(
                    m
                    for m, r in modules.items()
                    if _row_reach_ok(r) and r.get("harness_digest") != harness_digest(run_dir, m)
                )
                if stale:
                    reasons.append(f"the harness of {', '.join(stale)} changed after the reach gate ran; run it again")
                dag_stale = sorted(
                    m for m, r in modules.items() if _row_reach_ok(r) and r.get("dag_digest") != current_dag
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
            if not _row_reach_ok(row):
                detail = row.get("error") or f"entry points not reached: {', '.join(row.get('gaps') or [])}"
                if row.get("notes"):
                    detail += f" ({'; '.join(row['notes'][:3])})"
                reasons.append(f"reach gate failed for {module}: {detail}; {_reach_next_step(module)}")
            elif row.get("harness_digest") != harness_digest(run_dir, module):
                reasons.append(f"the harness of {module} changed after the reach gate ran; run it again")
            elif row.get("dag_digest") != current_dag:
                reasons.append(_dag_changed(module))
        else:
            ok, status = _build_ok(run_dir, module, row)
            if not ok:
                same = status == row.get("status")
                detail = row.get("first_error") or row.get("reason")
                first = f" ({detail})" if detail and same else ""
                if same and row.get("next_step"):
                    first += (
                        f"; {row.get('reason_code')}: E-ACSL cannot instrument it, "
                        f"to fuzz it with the sanitizers run `{row['next_step']}`"
                    )
                reasons.append(f"build-check failed for {module}: {status}{first}")
    from stub_check import gate_reasons as stub_gate_reasons  # a failed stub contract blocks its callers (S3)

    reasons.extend(stub_gate_reasons(run_dir, module))
    return reasons


def _reach_next_step(module: str) -> str:
    """What to run after a failed reach row: the gate's message is the one text every caller reads."""
    return (
        f"repair the harness and run `{HOW_TO_RUN['reach']}` again, or record why with "
        f"`python3 $S/harness_reach.py exempt --module {module} --function <fn> --reason <why>` "
        "(which re-checks the gate)"
    )


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
