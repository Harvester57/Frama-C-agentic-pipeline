#!/usr/bin/env python3
"""
Eva sharding: one module's Eva run split by dispatch case into k runs, and their reports merged into
the module's report (docs/eva-sharding.md).

Eva is single-threaded, so a module whose harness has many dispatch cases takes the sum of all of
them in one run (QCBOR run-5: 6,964 s for 179 cases). A shard is the same analysis of the same
harness with only some cases left in the source: generate_harness.py wraps each `case k:` in
`#if !defined(FRAMAC_EVA_SHARD) || defined(FRAMAC_EVA_SHARD_CASE_k)`, and a shard is built with
-DFRAMAC_EVA_SHARD plus -DFRAMAC_EVA_SHARD_CASE_k for each case it keeps. The other selector values
go to `default: break;` and call nothing. Every execution of eva_main takes exactly one selector
value, so it is an execution of exactly one shard.

Planning (pipeline_make.py, at `gen`): a module is sharded when its last single run was too slow for
the tuning ladder to finish (eva_options.tuning_skip_reason), or when params.json sets `eva_shards`.
Each case's cost comes from that run's flamegraph.txt; the cases are packed longest first into k
shards. The plan is recorded in workspace/reports/eva-shards/<mod>/plan.json and kept while the
module's settings and case count stay the same, so the shards never move between runs.

Merging (`eva_shards.py merge`, run by eva-<mod>): an obligation is Valid only if no shard that
reaches it leaves it Unknown or Invalid. A shard that never reached the obligation's function and
left it Never tried is "not here" and has no say. An obligation no shard reaches keeps Never tried,
as the single run reports it. Any shard that did not complete makes the module's report incomplete.
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import os
import re
import shutil
import sys
import tempfile
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from eva_flamegraph import fold_flamegraph  # noqa: E402
from framac_common import (  # noqa: E402
    STATUS_NEVER_TRIED,
    ArtifactError,
    atomic_write_json,
    load_json_strict,
)

SHARD_FORMAT = 1
SHARD_DIR = "workspace/reports/eva-shards"
EVA_SHARD_MACRO = "FRAMAC_EVA_SHARD"  # generate_harness.EVA_SHARD_MACRO
# How many shards a module may run as. Fixed: k decides what each run analyses, so it never follows
# the machine (a machine with fewer slots runs the same shards one after another).
MAX_SHARDS = 16
# k grows past the smallest that brings every shard under the tuning limit only while one more
# shard still cuts the predicted makespan by this share (each shard re-analyses shared callees).
SHARD_GAIN = 0.10
# Shard reports can carry tens of megabytes of flows.
_MAX_REPORT_BYTES = 1 << 31

_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_NOT_CALLS = frozenset({"if", "for", "while", "switch", "return", "sizeof", "defined", "_Alignof", "alignof"})


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


def harness_shardable(harness_text: str) -> bool:
    """Whether the harness has the per-case guards a shard needs (generated since sharding exists)."""
    return f"defined({EVA_SHARD_MACRO}_CASE_0)" in harness_text


def shard_cppflags(cases: Iterable[int]) -> list[str]:
    """The defines that leave only `cases` in the harness."""
    return [f"-D{EVA_SHARD_MACRO}", *(f"-D{EVA_SHARD_MACRO}_CASE_{k}" for k in sorted(cases))]


def case_callees(case_text: str) -> set[str]:
    """The functions a dispatch case calls directly (its statements as generate_harness wrote them)."""
    return {m.group(1) for m in _CALL_RE.finditer(case_text or "") if m.group(1) not in _NOT_CALLS}


def case_costs(cases: list[str], flamegraph_txt: Path | None, main_fn: str = "eva_main") -> tuple[list[float], str]:
    """
    Each dispatch case's share of a single run's time, from its `-eva-flamegraph` file: the inclusive
    time of every function eva_main calls directly, split evenly between the cases that call it. Time
    no case accounts for (eva_main's own, and callees outside the switch) is split evenly between all
    cases. Every case costs the same without a usable profile. Returns (costs, basis).
    """
    n = len(cases)
    uniform = [1.0] * n, "uniform"
    if n == 0 or flamegraph_txt is None:
        return uniform
    shared = 0.0
    inclusive: defaultdict[str, float] = defaultdict(float)
    try:
        with Path(flamegraph_txt).open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stack, _, raw = line.rstrip().rpartition(" ")
                try:
                    t = float(raw)
                except ValueError:
                    continue
                frames = [f for f in stack.split(";") if f]
                if not frames or t < 0 or frames[0] != main_fn:
                    continue
                if len(frames) == 1:
                    shared += t
                else:
                    inclusive[frames[1]] += t
    except OSError:
        return uniform
    callees = [case_callees(text) for text in cases]
    callers: defaultdict[str, list[int]] = defaultdict(list)
    for k, names in enumerate(callees):
        for name in names:
            callers[name].append(k)
    costs = [0.0] * n
    for name, t in inclusive.items():
        owners = callers.get(name)
        if not owners:
            shared += t
            continue
        for k in owners:
            costs[k] += t / len(owners)
    costs = [c + shared / n for c in costs]
    if sum(costs) <= 0:
        return uniform
    return costs, "flamegraph"


def pack(costs: list[float], k: int) -> list[list[int]]:
    """
    Longest processing time first into at most k shards: deterministic (ties on the case number and the
    shard index), every case in exactly one shard, no empty shard, each shard's cases in order.
    """
    k = max(1, min(k, len(costs)))
    bins: list[list[int]] = [[] for _ in range(k)]
    heap = [(0.0, i) for i in range(k)]
    for case in sorted(range(len(costs)), key=lambda c: (-costs[c], c)):
        load, i = heapq.heappop(heap)
        bins[i].append(case)
        heapq.heappush(heap, (load + costs[case], i))
    return [sorted(b) for b in bins if b]


def predicted_makespan(costs: list[float], shards: list[list[int]], total_s: float) -> float:
    """The slowest shard's predicted time, with the single run's time spread by cost."""
    whole = sum(costs) or 1.0
    return max((sum(costs[c] for c in shard) for shard in shards), default=0.0) * total_s / whole


def choose_shard_count(costs: list[float], total_s: float, limit_s: float) -> int:
    """
    The smallest k whose slowest shard is predicted under `limit_s`, then more only while one more
    shard still cuts the predicted makespan by SHARD_GAIN. At most MAX_SHARDS and one per case.
    """
    cap = max(1, min(MAX_SHARDS, len(costs)))
    k = 1
    while k < cap and predicted_makespan(costs, pack(costs, k), total_s) >= limit_s:
        k += 1
    while k < cap:
        now = predicted_makespan(costs, pack(costs, k), total_s)
        nxt = predicted_makespan(costs, pack(costs, k + 1), total_s)
        if nxt > (1.0 - SHARD_GAIN) * now:
            break
        k += 1
    return k


def make_plan(
    cases: list[str],
    flamegraph_txt: Path | None,
    total_s: float,
    limit_s: float,
    settings_digest: str,
    forced: int | None = None,
    basis_report: str | None = None,
) -> dict:
    """A module's shard plan: which cases each shard keeps, and what it was predicted from."""
    costs, basis = case_costs(cases, flamegraph_txt)
    k = forced if forced else choose_shard_count(costs, total_s, limit_s)
    shards = pack(costs, k)
    return {
        "format": SHARD_FORMAT,
        "settings_digest": settings_digest,
        "case_count": len(cases),
        "k": len(shards),
        "shards": shards,
        "forced": bool(forced),
        "basis": {
            "costs": basis,
            "report": basis_report,
            "flamegraph": str(flamegraph_txt) if flamegraph_txt and basis == "flamegraph" else None,
            "single_run_s": round(total_s, 1),
            "limit_s": round(limit_s, 1),
        },
        "predicted_makespan_s": round(predicted_makespan(costs, shards, total_s), 1),
    }


def plan_problem(record: Any, case_count: int, settings_digest: str, forced: int | None = None) -> str | None:
    """Why a recorded plan cannot be used for this module now, or None."""
    if not isinstance(record, dict) or record.get("format") != SHARD_FORMAT:
        return "no plan in the current format"
    if record.get("settings_digest") != settings_digest:
        return "the module's Eva settings changed since"
    if record.get("case_count") != case_count:
        return "the harness's case count changed since"
    shards = record.get("shards")
    if not isinstance(shards, list) or not shards or not all(isinstance(s, list) and s for s in shards):
        return "malformed shard list"
    flat = [c for s in shards for c in s]
    if sorted(flat) != list(range(case_count)) or any(not isinstance(c, int) or isinstance(c, bool) for c in flat):
        return "the shards do not cover every case exactly once"
    if forced and len(shards) != min(forced, case_count):
        return f"params.json asks for {forced} shards"
    if not forced and record.get("forced"):
        return "the shard count params.json forced was removed"
    return None


def plan_digest(record: dict) -> str:
    return hashlib.sha256(json.dumps(record.get("shards"), separators=(",", ":")).encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Merging
# ---------------------------------------------------------------------------

# Worst first: the merged status of an obligation is the worst any reaching shard gives it.
_RANK = {"invalid": 5, "other": 4, "unknown": 3, "assumed": 2, "valid": 1, "dead": 0}


@dataclass
class Shard:
    index: int
    cases: list[int]
    run: Any  # eva_tuning.EvaRun
    reached: set[str] = field(default_factory=set)
    by_key: dict[tuple[str, int], list[dict]] = field(default_factory=dict)
    problem: str | None = None


def load_shard(index: int, cases: list[int], report: dict | None, entry_fn: str | None) -> Shard:
    from eva_tuning import degeneration_reason, load_run, obligation_key, statements_by_function

    run = load_run(f"shard{index}", report, entry_fn)
    shard = Shard(index=index, cases=cases, run=run)
    if not run.completed:
        shard.problem = f"did not complete ({run.report.get('status')})"
        return shard
    degenerated = degeneration_reason(run.log_text)
    if degenerated:
        shard.problem = f"degenerated ({degenerated})"
        return shard
    shard.reached = set(statements_by_function(run.log_text))
    for row in run.rows:
        shard.by_key.setdefault(obligation_key(row), []).append(row)
    return shard


def _bucket(row: dict) -> str:
    from eva_tuning import _bucket as bucket

    return bucket(row)


def identity_problem(shards: list[Shard]) -> str | None:
    """Shards differ only in their cases: the same sources, entry, checks and assumptions."""
    from eva_options import assumption_options

    def identity(s: Shard) -> tuple:
        r = s.run.report
        return (
            r.get("main_fn"),
            tuple(sorted(r.get("sources") or [])),
            tuple(sorted(r.get("reduced_checks") or [])),
            tuple(sorted(assumption_options(r.get("eva_options") or {}).items())),
        )

    first = identity(shards[0])
    for s in shards[1:]:
        if identity(s) != first:
            return f"shard{s.index} is not the same analysis as shard{shards[0].index}"
    return None


def merge_rows(shards: list[Shard]) -> tuple[list[dict], dict]:
    """
    One row set for the module. Per obligation key: the rows of the shard that gives it the worst
    status among the shards that reach it; a shard that left it Never tried in a function it never
    reached has no say. A key no shard reaches keeps the first shard's rows (Never tried), as the single
    run would report it.
    """
    keys = sorted({key for s in shards for key in s.by_key})
    rows: list[dict] = []
    unreached = 0
    from_shard: defaultdict[int, int] = defaultdict(int)
    for key in keys:
        best: tuple[int, int] | None = None
        chosen: Shard | None = None
        fallback: Shard | None = None
        for s in shards:
            found = s.by_key.get(key)
            if not found:
                continue
            fallback = fallback or s
            function = found[0].get("function") or ""
            if function not in s.reached and all(r.get("status") == STATUS_NEVER_TRIED for r in found):
                continue  # not here: this shard's executions never reach the function
            rank = (max(_RANK.get(_bucket(r), _RANK["other"]) for r in found), -s.index)
            if best is None or rank > best:
                best, chosen = rank, s
        if chosen is None:
            unreached += 1
            chosen = fallback
        assert chosen is not None
        from_shard[chosen.index] += 1
        rows.extend(chosen.by_key[key])
    stats = {
        "keys": len(keys),
        "not_reached_anywhere": unreached,
        "from_shard": {f"shard{i}": n for i, n in sorted(from_shard.items())},
    }
    return rows, stats


_FLOW_INTERSECT = frozenset({"sure_outputs"})
_FLOW_ALL = frozenset({"non_terminating", "no_effects"})


def merge_flows(flows: list[dict]) -> dict:
    """
    Read and write sets per function, over the shards that analysed it: lists are unions (sure
    outputs an intersection), `non_terminating` and `no_effects` hold only if they hold in every
    shard. Hints for prover briefs, never verdicts.
    """
    usable = [f for f in flows if isinstance(f, dict)]
    if not usable:
        return {"status": "not_run", "reason": "no shard collected flows"}
    by_function: dict[str, dict] = {}
    for flow in usable:
        for fn, info in (flow.get("by_function") or {}).items():
            if not isinstance(info, dict):
                continue
            mine = by_function.get(fn)
            if mine is None:
                by_function[fn] = json.loads(json.dumps(info))
                continue
            for name, value in info.items():
                old = mine.get(name)
                if name in _FLOW_ALL:
                    mine[name] = bool(old) and bool(value)
                elif isinstance(value, list) and isinstance(old, list):
                    if name in _FLOW_INTERSECT:
                        mine[name] = [v for v in old if v in value]
                    else:
                        seen = {json.dumps(v, sort_keys=True) for v in old}
                        mine[name] = old + [v for v in value if json.dumps(v, sort_keys=True) not in seen]
                elif name not in mine:
                    mine[name] = value
    edges: dict[str, set[str]] = defaultdict(set)
    for flow in usable:
        for fn, callees in (flow.get("call_edges") or {}).items():
            edges[fn].update(c for c in callees or [] if isinstance(c, str))
    bad = [f for f in usable if f.get("status") != "ok"]
    out: dict[str, Any] = {
        "status": "ok" if not bad and len(usable) == len(flows) else "partial",
        "reason": None if not bad else "; ".join(str(f.get("reason") or f.get("status")) for f in bad),
        "by_function": dict(sorted(by_function.items())),
        "call_edges": {fn: sorted(cs) for fn, cs in sorted(edges.items())},
    }
    return out


def merge_reach(shards: list[Shard], entry_fn: str | None) -> dict:
    """Coverage and entry reachability of the union of the shards' executions."""
    from eva_tuning import DEFAULT_MIN_COVERAGE_PCT, statements_by_function

    reached: set[str] = set()
    stmts: dict[str, int] = {}
    denominator = None
    for s in shards:
        reached |= s.reached
        for fn, n in statements_by_function(s.run.log_text).items():
            stmts[fn] = max(stmts.get(fn, 0), n)
        cov = s.run.reach.get("eva_coverage") or {}
        if denominator is None and cov.get("coverage_estimate_pct") and cov.get("functions_analyzed"):
            # Every shard has the same syntactically reachable functions: Eva's estimate is analysed / that.
            denominator = 100.0 * cov["functions_analyzed"] / cov["coverage_estimate_pct"]
    first = shards[0].run.reach.get("eva_coverage") or {}
    coverage: dict[str, Any] = {}
    if reached:
        coverage["functions_analyzed"] = len(reached)
    if "functions_total" in first:
        coverage["functions_total"] = first["functions_total"]
    if stmts:
        coverage["statements_reached"] = sum(stmts.values())
    if "statements_total" in first:
        coverage["statements_total"] = first["statements_total"]
    if denominator:
        coverage["coverage_estimate_pct"] = round(min(100.0, 100.0 * len(reached) / denominator), 1)
    entries = [s.run.reach.get("entry_reached") for s in shards]
    entry_reached = True if True in entries else (False if entries and all(e is False for e in entries) else None)
    estimate = coverage.get("coverage_estimate_pct")
    if entry_reached is False:
        reachability = "entry_unreached"
    elif estimate is not None and estimate < DEFAULT_MIN_COVERAGE_PCT:
        reachability = "low_coverage"
    elif entry_reached:
        reachability = "ok"
    else:
        reachability = "unknown"
    # Non-terminating only where every shard that analysed the function says so.
    stuck: set[str] = set()
    for fn in {f for s in shards for f in s.run.reach.get("non_terminating_functions") or []}:
        if all(fn in (s.run.reach.get("non_terminating_functions") or []) for s in shards if fn in s.reached):
            stuck.add(fn)
    return {
        "entry_fn": entry_fn,
        "entry_reached": entry_reached,
        "reachability": reachability,
        "eva_coverage": coverage,
        "non_terminating_functions": sorted(stuck),
        "min_coverage_pct": DEFAULT_MIN_COVERAGE_PCT,
    }


def _union(lists: Iterable[Any]) -> list:
    out: list = []
    seen: set[str] = set()
    for items in lists:
        for item in items if isinstance(items, list) else []:
            mark = json.dumps(item, sort_keys=True)
            if mark not in seen:
                seen.add(mark)
                out.append(item)
    return out


def write_rows_csv(path: Path, rows: list[dict]) -> None:
    """The merged rows as a Frama-C -report-csv file (tab-separated), which read_report_csv reads back."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_alarms_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write("directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n")
            for r in rows:
                cells = [r.get("directory"), r.get("file"), r.get("line"), r.get("function"), r.get("kind")]
                cells += [r.get("status_raw"), r.get("property")]
                f.write("\t".join(str(c if c is not None else "").replace("\t", " ").replace("\n", " ") for c in cells))
                f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def concat_flamegraphs(sources: list[Path], dest: Path) -> bool:
    """All shards' folded stacks in one file: their sum is the module's whole Eva work."""
    present = [p for p in sources if p.is_file()]
    if not present:
        dest.unlink(missing_ok=True)
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(dest.parent), prefix=".tmp_flamegraph_")
    try:
        with os.fdopen(fd, "wb") as out:
            for p in present:
                with p.open("rb") as src:
                    shutil.copyfileobj(src, out)
        os.replace(tmp, dest)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    # Shards share stacks (eva_main and common callees): merge them as one run's profile is.
    fold_flamegraph(dest)
    return True


def _shard_row(s: Shard) -> dict:
    r = s.run.report
    return {
        "shard": s.index,
        "cases": s.cases,
        "status": r.get("status"),
        **({"problem": s.problem} if s.problem else {}),
        "elapsed_s": r.get("elapsed_s"),
        "unknown_count": r.get("unknown_count"),
        "invalid_count": r.get("invalid_count"),
        "cache_hit": (r.get("cache") or {}).get("hit"),
        **({"timeout_fallback": r["timeout_fallback"]} if r.get("timeout_fallback") else {}),
        "report": r.get("_path"),
    }


def merge(
    module: str,
    plan: dict,
    reports: list[dict | None],
    entry_fn: str | None,
    csv_out: Path,
    flamegraph_out: Path | None = None,
) -> dict:
    """The module's report from its shards' reports (one per plan shard, None when missing)."""
    from run_eva_slice import summarize_rows

    shards = [load_shard(i, cases, reports[i], entry_fn) for i, cases in enumerate(plan["shards"])]
    elapsed = [float(s.run.report.get("elapsed_s") or 0.0) for s in shards]
    sharding: dict[str, Any] = {
        "k": len(shards),
        "plan": plan_digest(plan),
        "predicted_makespan_s": plan.get("predicted_makespan_s"),
        "makespan_s": round(max(elapsed, default=0.0), 1),
        "total_s": round(sum(elapsed), 1),
        "runs": [_shard_row(s) for s in shards],
    }
    failed = [s for s in shards if s.problem]
    problem = identity_problem([s for s in shards if not s.problem]) if len(failed) < len(shards) else None
    if failed or problem:
        first = failed[0] if failed else None
        status = (first.run.report.get("status") if first else None) or "analysis_error"
        if status in ("ok", "no_report"):  # degenerated, a different analysis, or no report at all
            status = "analysis_error"
        reason = f"shard{first.index} of {len(shards)} (cases {first.cases}) {first.problem}" if first else str(problem)
        errors = list((first.run.report.get("error_summary") if first else None) or [])
        report = {
            "status": status,
            "reason": reason,
            "error_summary": [f"Eva shard {reason}", *errors][:20],
            "module": module,
            "main_fn": shards[0].run.report.get("main_fn") or "eva_main",
            "elapsed_s": sharding["makespan_s"],
            "eva_shards": sharding,
            "tuning": {"mode": "skipped", "reason": "the module runs as shards (no ladder per shard yet)"},
        }
        if flamegraph_out is not None:
            concat_flamegraphs([Path(p) for s in shards if (p := s.run.report.get("flamegraph_file"))], flamegraph_out)
        return report

    rows, stats = merge_rows(shards)
    write_rows_csv(csv_out, rows)
    reach = merge_reach(shards, entry_fn)
    base = shards[0].run.report
    report = {k: v for k, v in base.items() if not k.startswith("_")}
    report.update(summarize_rows(rows))
    report.update(reach)
    digests = [str(s.run.report.get("input_digest") or "") for s in shards]
    report.update(
        {
            "module": module,
            "status": "ok",
            "reason": None,
            "returncode": 0,
            "elapsed_s": sharding["makespan_s"],
            "csv_file": str(csv_out),
            "log_file": None,
            "sarif_file": None,
            "sav_file": None,
            "nonterm_log_file": None,
            "flamegraph_file": None,
            "input_digest": hashlib.sha256("\n".join(digests).encode()).hexdigest() if all(digests) else None,
            "cache": {"hit": all((s.run.report.get("cache") or {}).get("hit") for s in shards), "key": None},
            "flows": merge_flows([s.run.report.get("flows") for s in shards]),
            "nonterm": _union(s.run.report.get("nonterm") for s in shards),
            "repair_hints": _union(s.run.report.get("repair_hints") for s in shards),
            "undeclared_functions": sorted(
                {str(f) for s in shards for f in (s.run.report.get("undeclared_functions") or [])}
            ),
            "eva_shards": {
                **sharding,
                "merge": {
                    "method": "worst_status_over_reaching_shards",
                    "keys": stats["keys"],
                    "not_reached_anywhere": stats["not_reached_anywhere"],
                    "rows_from": stats["from_shard"],
                },
            },
            "tuning": {"mode": "skipped", "reason": "the module runs as shards (no ladder per shard yet)"},
        }
    )
    report.pop("cost_profile", None)
    report.pop("timeout_fallback", None)
    fallbacks = [s.index for s in shards if s.run.report.get("timeout_fallback")]
    if fallbacks:
        report["timeout_fallback_shards"] = fallbacks
    if flamegraph_out is not None and concat_flamegraphs(
        [Path(p) for s in shards if (p := s.run.report.get("flamegraph_file"))], flamegraph_out
    ):
        report["flamegraph_file"] = str(flamegraph_out)
    return report


def shard_report_path(shard_dir: Path, index: int) -> Path:
    return shard_dir / f"shard{index}.json"


def load_report(path: Path) -> dict | None:
    try:
        data = load_json_strict(path, max_bytes=_MAX_REPORT_BYTES)
    except ArtifactError:
        return None
    if not isinstance(data, dict):
        return None
    data["_path"] = str(path)
    return data


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Merge a sharded module's Eva runs into its report.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("merge", help="Merge the shard reports of a module (eva-<mod> for a sharded module)")
    p.add_argument("--module", required=True)
    p.add_argument("--shard-dir", type=Path, required=True, help="Holds plan.json and shard<i>.json")
    p.add_argument("--entry-fn", default=None)
    p.add_argument("--csv-out", type=Path, required=True, help="The merged alarms.csv")
    p.add_argument("--flamegraph-out", type=Path, default=None, help="All shards' flamegraph.txt, concatenated")
    p.add_argument("--out-json", type=Path, required=True)
    args = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])

    try:
        plan = load_json_strict(args.shard_dir / "plan.json")
    except ArtifactError as exc:
        report: dict = {"status": "analysis_error", "reason": f"no shard plan: {exc}", "error_summary": [str(exc)]}
    else:
        shards = plan.get("shards") if isinstance(plan, dict) else None
        if not isinstance(shards, list) or not shards:
            report = {"status": "analysis_error", "reason": "malformed shard plan", "error_summary": []}
        else:
            reports = [load_report(shard_report_path(args.shard_dir, i)) for i in range(len(shards))]
            report = merge(args.module, plan, reports, args.entry_fn, args.csv_out, args.flamegraph_out)
    report["module"] = args.module
    atomic_write_json(args.out_json, report)
    sharding = report.get("eva_shards") or {}
    print(
        json.dumps(
            {
                "status": report.get("status"),
                "module": args.module,
                "reason": report.get("reason"),
                "unknown_count": report.get("unknown_count"),
                "invalid_count": report.get("invalid_count"),
                "shards": sharding.get("k"),
                "makespan_s": sharding.get("makespan_s"),
                "total_s": sharding.get("total_s"),
            },
            indent=2,
        )
    )
    return 0 if report.get("status") == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
