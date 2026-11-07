#!/usr/bin/env python3
"""
Phase 0 A/B on the benchmark targets: the benchmark's own Phases 0-2 run twice per target, once with
the current lexer DAG and once with the phase0b view (dag_view.py), harnesses held fixed by the
manifest. Host side; drives scripts/benchmark.py's run_target (read-only use) through the wrapper.

    python -I poc/phase0/ab.py run [--target ID ...] [--fuzz]   # results in poc/phase0/out/ab/

The only change to the benchmark is the command of its `phase0` stage in phase0b mode
(ab_inner.py instead of `benchmark.py inner-phase0`). Compared per target: ledger units by status
and class, units with Eva evidence, Eva-analysed functions with no ledger unit, the Phase 3 queue,
candidates, and the known bugs' outcome.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import benchmark  # noqa: E402

POC_FILES = ("ab_inner.py", "phase0b.py", "dag_view.py", "p0_dump.ml")
MODES = ("lexer", "phase0b")


def staged_runner(mode: str, build: str) -> Any:
    original = benchmark.run_stage

    def run_stage(name: str, command: str, target: Path, run_dir: Path, repo: str, **kwargs: Any) -> dict:
        if mode == "phase0b" and name == "phase0":
            poc = run_dir / benchmark.BENCH_SUBDIR / "poc"
            poc.mkdir(parents=True, exist_ok=True)
            for f in POC_FILES:
                shutil.copyfile(HERE / f, poc / f)
            (poc / "build.txt").write_text(build + "\n", encoding="utf-8")
            command = f"python3 -B {benchmark.BENCH_SUBDIR}/poc/ab_inner.py"
        return original(name, command, target, run_dir, repo, **kwargs)

    return run_stage, original


def eva_functions(run_dir: Path, modules: list[str]) -> set[str]:
    """`file#function` of every function an Eva report gives properties for."""
    out: set[str] = set()
    for m in modules:
        report = benchmark.read_json(run_dir / "workspace" / "reports" / "eva" / f"{m}.json") or {}
        by_file = report.get("functions_with_properties_by_file") or []
        items = (
            [{"file": f, "function": fn} for f, fns in by_file.items() for fn in fns or []]
            if isinstance(by_file, dict)
            else by_file
        )
        for item in items:
            if isinstance(item, dict) and item.get("function"):
                out.add(f"{benchmark.normalize_file(str(item.get('file', '')))}#{item['function']}")
    return out


def ledger_metrics(run_dir: Path, target: dict) -> dict:
    ledger = benchmark.read_json(run_dir / "coverage-ledger.json", []) or []
    rte = {f"{u['file']}#{u['function']}": u for u in ledger if u.get("obligation_class") == "rte"}
    work = run_dir / "workspace" / "work"
    # Only the target's own functions: Eva also reports Frama-C's libc and builtins.
    evafns = {
        f for f in eva_functions(run_dir, [m["name"] for m in target["modules"]]) if (work / f.split("#")[0]).is_file()
    }
    with_eva = [u for u in ledger if any(e.get("phase") == "eva" for e in u.get("evidence") or [])]
    return {
        "units": len(ledger),
        "functions": len({(u["file"], u["function"]) for u in ledger}),
        "by_status": dict(sorted(Counter(u.get("status") for u in ledger).items())),
        "by_class": dict(sorted(Counter(u.get("obligation_class") for u in ledger).items())),
        "units_with_eva_evidence": len(with_eva),
        "eva_functions": len(evafns),
        "eva_functions_without_unit": sorted(evafns - set(rte)),
        "rte_units_eva_never_saw_list": sorted(
            k for k, u in rte.items() if u.get("status") not in ("out_of_scope", "deferred") and k not in evafns
        ),
        "rte_units_eva_never_saw": len(
            [k for k, u in rte.items() if u.get("status") not in ("out_of_scope", "deferred") and k not in evafns]
        ),
    }


def run_one(target: dict, manifest: dict, work_dir: Path, run_id: str, mode: str, build: str, fuzz: bool) -> dict:
    patched, original = staged_runner(mode, build)
    benchmark.run_stage = patched
    try:
        entry = benchmark.run_target(
            target, manifest, work_dir, run_id, run_fuzz=fuzz, fuzz_budget=None, eva_timeout=None
        )
    finally:
        benchmark.run_stage = original
    run_dir = work_dir / "runs" / run_id / target["id"] / benchmark.RUN_DIR_NAME
    outcomes = benchmark.replay_outcomes(target["id"], entry.get("_replay") or {}, entry.get("_gate") or {})
    bugs = {
        b["id"]: benchmark.decide_bug(b, outcomes.get(b["id"], {}))["status"]
        for b in manifest.get("bugs", [])
        if any(r.get("target") == target["id"] for r in b.get("replays", []))
    }
    total = entry["units"]["total"]
    return {
        "status": entry["status"],
        "problems": entry["problems"],
        "wall_s": entry["wall_s"],
        "phase0_s": (entry["stages"].get("phase0") or {}).get("wall_s"),
        "dag_functions": entry["dag"]["functions"],
        "units_total": total,
        "functions_with_unknown_no_unit": entry["functions_with_unknown_no_unit"],
        "prover_tasks": entry["prover_tasks"],
        "candidates": entry["candidates"],
        "bugs": bugs,
        "ledger": ledger_metrics(run_dir, target),
        "run_dir": str(run_dir),
    }


def render(results: dict) -> str:
    rows = [
        ("Ledger functions", lambda r: r["ledger"]["functions"]),
        ("Ledger units", lambda r: r["ledger"]["units"]),
        ("Units with Eva evidence", lambda r: r["ledger"]["units_with_eva_evidence"]),
        ("Eva-analysed functions", lambda r: r["ledger"]["eva_functions"]),
        ("Eva functions with no unit", lambda r: len(r["ledger"]["eva_functions_without_unit"])),
        ("Unknown functions with no unit", lambda r: len(r["functions_with_unknown_no_unit"])),
        ("Planned RTE units Eva never saw", lambda r: r["ledger"]["rte_units_eva_never_saw"]),
        ("Phase 3 queue", lambda r: r["prover_tasks"]["count"]),
        ("Covered units", lambda r: r["ledger"]["by_status"].get("covered", 0)),
        ("Candidate units", lambda r: r["ledger"]["by_status"].get("candidate", 0)),
        ("Bugs retained", lambda r: sum(1 for s in r["bugs"].values() if s == "retained")),
        ("Phase 0 wall s", lambda r: r["phase0_s"]),
        ("Run wall s", lambda r: r["wall_s"]),
    ]
    lines = [
        "# Phase 0 A/B: benchmark Phases 0-2",
        "",
        "Each cell: lexer → phase0b view. Harnesses, tiers and modules held fixed.",
        "",
    ]
    tids = list(results)
    lines.append("| Metric | " + " | ".join(f"`{t}`" for t in tids) + " |")
    lines.append("| :--- |" + " ---: |" * len(tids))

    def cell(r: dict, f: Any) -> str:
        try:
            return str(f(r))
        except (KeyError, TypeError, AttributeError):
            return r.get("status", "?")

    for label, f in rows:
        lines.append(
            f"| {label} | "
            + " | ".join(f"{cell(results[t]['lexer'], f)} → {cell(results[t]['phase0b'], f)}" for t in tids)
            + " |"
        )
    lines += ["", "## Details", ""]
    for t, r in results.items():
        for mode in MODES:
            m = r[mode]
            lines.append(f"- `{t}` {mode}: status {m.get('status')}, problems {m.get('problems')}")
            miss = m.get("ledger", {}).get("eva_functions_without_unit") or []
            if miss:
                lines.append(f"  - Eva functions with no ledger unit: {miss[:12]}")
            unseen = m.get("ledger", {}).get("rte_units_eva_never_saw_list") or []
            if unseen:
                lines.append(f"  - planned RTE units Eva never saw: {unseen[:12]}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Phase 0 A/B on the benchmark targets")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--target", action="append", default=[])
    r.add_argument("--work-dir", type=Path, default=HERE / "out" / "checkouts")
    r.add_argument("--out", type=Path, default=HERE / "out" / "ab")
    r.add_argument("--fuzz", action="store_true", help="also run Phase 1 campaigns (off: Eva and replay only)")
    a = p.parse_args(argv)
    manifest = benchmark.load_manifest()
    builds = json.loads((HERE / "targets.json").read_text(encoding="utf-8"))
    ids = a.target or list(builds)
    targets = benchmark.select_targets(manifest, ["all"], ids)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    a.out.mkdir(parents=True, exist_ok=True)
    out_file = a.out / f"ab-{stamp}.json"
    results: dict = {}
    for t in targets:
        results[t["id"]] = {}
        for mode in MODES:
            print(f"== {t['id']} {mode}", flush=True)
            try:
                results[t["id"]][mode] = run_one(
                    t, manifest, a.work_dir.resolve(), f"ab-{stamp}-{mode}", mode, builds[t["id"]]["build"], a.fuzz
                )
            except Exception as exc:  # one target failing must not lose the others
                results[t["id"]][mode] = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
            out_file.write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    (a.out / f"ab-{stamp}.md").write_text(render(results), encoding="utf-8")
    print(f"results: {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
