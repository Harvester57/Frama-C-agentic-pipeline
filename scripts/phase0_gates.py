#!/usr/bin/env python3
"""
Phase 0 gate stamp (stdlib only): workspace/reports/phase0_gates.json.

The two Phase 0 gates write their results here, and the Make recipes that consume harnesses
(build, fuzz, coverage, Eva, wp-queue) check it first, so no step can run on a harness that failed
a gate (docs/phase0-implementation-plan.md, step I1):

  reach        harness_reach.py check: every DAG entry point of a module is reached by its harness,
               or exempted with a reason. Recorded with a digest of the module's harness files, so
               a harness regenerated after the check fails the gate until the check runs again.
  build_check  pipeline_make.py build-check: every fuzzed module builds with E-ACSL, or its
               sanitizer engine is a recorded choice (params set --fuzz-engine sanitizers).

    phase0_gates.py check [--module M] [--need reach,build_check]

exits 0 when the gate passes and 1 with the reasons otherwise. Without --module, every module of
each needed section must pass.
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


def load_gates(run_dir: Path) -> dict[str, Any]:
    data = load_json_optional(run_dir / GATES_JSON, {})
    return data if isinstance(data, dict) else {}


def _store(run_dir: Path, section: str, entry: dict[str, Any]) -> dict[str, Any]:
    with run_lock("phase0_gates", run_dir):
        gates = load_gates(run_dir)
        gates[section] = entry
        atomic_write_json(run_dir / GATES_JSON, gates)
    return gates


def record_reach(run_dir: Path, report: dict[str, Any], partial: bool = False) -> dict[str, Any]:
    """
    Store a harness_reach.py report. A `partial` report (check limited with --module) updates only
    its modules; the section passes only while every recorded module does.
    """
    run_dir = Path(run_dir)
    modules: dict[str, Any] = {}
    if partial:
        prior = load_gates(run_dir).get("reach")
        if isinstance(prior, dict) and isinstance(prior.get("modules"), dict):
            modules = dict(prior["modules"])
    for row in report.get("modules") or []:
        name = str(row.get("module"))
        modules[name] = {
            "passed": bool(row.get("passed")),
            "gaps": list(row.get("gaps") or []),
            "error": row.get("error"),
            "exempt": row.get("exempt"),
            "harness_digest": harness_digest(run_dir, name),
        }
    entry = {
        "passed": all(m["passed"] for m in modules.values()),
        "generated_at": utc_now(),
        "modules": dict(sorted(modules.items())),
    }
    return _store(run_dir, "reach", entry)


def record_build_check(run_dir: Path, out: dict[str, Any]) -> dict[str, Any]:
    """Store a pipeline_make.py build-check result."""
    modules = {
        str(name): {"ok": bool(r.get("ok")), "status": r.get("status"), "first_error": r.get("first_error")}
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


def check(run_dir: Path, module: str | None = None, need: tuple[str, ...] = SECTIONS) -> list[str]:
    """Reasons the gate fails for `module` (or for every module when None); empty when it passes."""
    run_dir = Path(run_dir)
    gates = load_gates(run_dir)
    reasons: list[str] = []
    for section in need:
        entry = gates.get(section)
        if not isinstance(entry, dict):
            reasons.append(f"{section} has not run: run `{HOW_TO_RUN[section]}` first")
            continue
        raw_modules = entry.get("modules")
        modules: dict[str, Any] = raw_modules if isinstance(raw_modules, dict) else {}
        if module is None:
            if not _section_ok(section, entry):
                failed = sorted(m for m, r in modules.items() if not (r.get("passed") or r.get("ok")))
                reasons.append(f"{section} failed for {', '.join(failed) or 'the run'}")
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
        elif not row.get("ok"):
            first = f" ({row['first_error']})" if row.get("first_error") else ""
            reasons.append(f"build-check failed for {module}: {row.get('status')}{first}")
    return reasons


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Check the Phase 0 gate stamp")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--run-dir", type=Path, default=Path("."))
    c.add_argument("--module", default=None)
    c.add_argument("--need", default=",".join(SECTIONS), help="Comma-separated sections: reach, build_check")
    a = p.parse_args(argv)
    need = tuple(s.strip() for s in a.need.split(",") if s.strip())
    unknown = [s for s in need if s not in SECTIONS]
    if unknown:
        p.error(f"unknown gate section(s): {', '.join(unknown)}")
    try:
        reasons = check(a.run_dir, a.module, need)
    except (ArtifactError, OSError, ValueError) as exc:
        reasons = [f"cannot read {GATES_JSON}: {exc}"]
    print(json.dumps({"ok": not reasons, "module": a.module, "need": list(need), "reasons": reasons}))
    for reason in reasons:
        print(f"phase0 gate: {reason}", file=sys.stderr)
    return 1 if reasons else 0


if __name__ == "__main__":
    sys.exit(main())
