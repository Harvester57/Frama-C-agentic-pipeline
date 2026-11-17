#!/usr/bin/env python3
"""
Census of the WP goals a finished run left unproved (proof-papers plan, Tier 2a).

Reads the promoted per-function WP reports of a run (`workspace/reports/wp/<function>.json`,
written by run_wp_function.py: the scheduler's baseline wave writes them, and a merge whose parent
re-check passed publishes over them) and counts the unproved goals by obligation class, diagnostic
bucket and verdict kind, per function and in total. The result sizes an interactive-prover fallback
or a `-wp-auto` second pass: which functions would be `all_proven` if their timed-out goals alone
were closed, and which have so few unproved goals that a per-goal fallback is worth a trial.

Read-only: nothing in the run is written or changed (no ledger, no status, no lock). The only file
written is the one named by `--out`.

Verdict kinds come from `unproven_goal_costs` (one entry per WP goal: timeout, stepout, unknown,
failed). A report written before that field existed has verdict kind `unrecorded`. The costs are
keyed by WP goal name while `unproven_goals` are rows of the WP CSV report, which has no goal name,
so a row is paired with the costs WP reports at the same source line (and file name) whose property
name has the row's kind: `signed_overflow` pairs with `<function>_assert_rte_signed_overflow_3`,
`postcondition` with `<function>_ensures...`. The row takes the verdict kind those costs agree on,
`mixed` when they disagree, and `unjoined` when there is none, when a cost has no line (it came
from the log, or the report predates the `file` and `line` fields), or when the line has more rows
than costs. `join` says how far that went for a function: `by_line_and_kind` (every row paired),
`partial`, or `per_function_only` (none; the verdict kinds are then only a distribution next to the
class and bucket distributions). The kind mapping was checked on Frama-C 34 for RTE assertions,
postconditions, loop invariants and user assertions; the other kinds (a callee's precondition, a
clause in a behavior) follow WP's naming scheme unchecked, and a mismatch there gives `unjoined`.

A verdict kind is WP's merged verdict over the provers of the run: with several provers a timeout
can hide another prover's unknown, so `would_be_all_proven_if_timeouts_closed` is an upper bound.
For the same reason `unproved_by_prover` (timed out, gave up, failed, per prover) counts only the
goals of reports whose run had exactly one prover; `unproved_without_prover_data` counts the rest.
It changes no prover and no timeout: it is there to decide later whether a prover costs time for nothing.

Fail closed: a report that cannot be read or has the wrong shape is counted and named under
`reports.unreadable`, never dropped. A missing WP report directory is an error.

Usage:
  python scripts/wp_residual_census.py --run-dir <run> [--out f.json] [--format json|table] [--near-miss N]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from framac_common import ArtifactError, atomic_write_json, load_json_optional, load_json_strict, to_run_relative

# Where promoted WP reports live, in the order wp_scheduler.py looks for them.
WP_REPORT_DIRS = ("workspace/reports/wp", "reports/wp")
LEDGER_REL = "coverage-ledger.json"
# Ledger units WP never proves, so a same-named function among them loses no report.
LEDGER_NOT_WP = frozenset({"out_of_scope", "excluded"})
UNPROVEN_STATUS = "unproven_goals_remain"
PROVEN_STATUS = "all_proven"
TIMEOUT_KINDS = frozenset({"timeout", "stepout"})
UNRECORDED = "unrecorded"
UNJOINED = "unjoined"
MIXED = "mixed"
JOIN_BY_LINE = "by_line_and_kind"
JOIN_PARTIAL = "partial"
JOIN_PER_FUNCTION = "per_function_only"
JOIN_KEY = (
    "unproven_goals[] (file name, line, kind) against unproven_goal_costs[] (file name, line, kind token of property)"
)
DEFAULT_NEAR_MISS = 3

# The CSV report's `property kind` -> the token WP's property name carries for it after the
# `<function>_` prefix. A kind that is one word and not listed is an RTE alarm kind, which WP names
# `assert_rte_<kind>`. A kind in neither group pairs on the line alone.
_CLAUSE_KIND_TOKENS = {
    "postcondition": "ensures",
    "precondition": "requires",
    "loop invariant": "loop_invariant",
    "loop variant": "loop_variant",
    "assigns clause": "assigns",  # `loop_assigns` too: the CSV has one kind for both
    "termination clause": "terminates",
    "user assertion": "assert",
}
_RTE_KIND_RE = re.compile(r"[a-z][a-z0-9_]*")


class CensusError(RuntimeError):
    """The run has no WP report directory to take a census of."""


def wp_reports_dir(run_dir: Path) -> Path:
    for rel in WP_REPORT_DIRS:
        candidate = run_dir / rel
        if candidate.is_dir():
            return candidate
    raise CensusError(f"no WP report directory under {run_dir} (looked for {', '.join(WP_REPORT_DIRS)})")


def _source_file(raw: object) -> str:
    """The report's `file`, relative to the work tree when it names one (container paths differ per run)."""
    text = str(raw or "").replace("\\", "/")
    marker = "workspace/work/"
    idx = text.rfind(marker)
    return text[idx + len(marker) :] if idx >= 0 else text


def _shape_problem(report: dict) -> str | None:
    goals = report.get("unproven_goals", [])
    if not isinstance(goals, list) or not all(isinstance(g, dict) for g in goals):
        return "unproven_goals is not a list of objects"
    costs = report.get("unproven_goal_costs")
    if costs is not None and (not isinstance(costs, list) or not all(isinstance(c, dict) for c in costs)):
        return "unproven_goal_costs is not a list of objects"
    return None


def _skip_reason(report: dict) -> str | None:
    """Mirrors ledger.cmd_ingest_wp: only per-function WP results count."""
    if report.get("mode") == "guardrail":
        return "guardrail report"
    if "function" not in report or "status" not in report:
        return "not a per-function WP report (no function or status)"
    return None


def _verdict_kind(cost: dict) -> str:
    return str(cost.get("verdict_kind") or "unspecified")


def _line_number(raw: object) -> int | None:
    """A positive source line from a report field (the CSV rows carry it as a number or as text)."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, str) and raw.strip().isdigit():
        raw = int(raw.strip())
    return raw if isinstance(raw, int) and raw > 0 else None


def _file_name(raw: object) -> str:
    """The last path component: a cost's file is a path of the analysis run, a row's is relative."""
    return str(raw or "").replace("\\", "/").rsplit("/", 1)[-1]


def _kind_matches(kind: str, prop: str, function: str) -> bool:
    """Whether WP's property name `prop` is of the CSV report kind `kind` (see _CLAUSE_KIND_TOKENS)."""
    kind = " ".join(kind.lower().split())
    rest = prop[len(function) + 1 :] if function and prop.startswith(function + "_") else prop
    token = _CLAUSE_KIND_TOKENS.get(kind)
    if token is None and _RTE_KIND_RE.fullmatch(kind):
        # Anchored on both sides: `signed_overflow` must not pair with `unsigned_overflow`.
        return re.search(rf"(?:^|_)assert_rte_{re.escape(kind)}(?:_|$)", rest) is not None
    if token is None:
        return True
    if re.search(rf"(?:^|_){token}(?:_|$)", rest) is None:
        return False
    return not (kind == "user assertion" and re.search(r"(?:^|_)assert_rte(?:_|$)", rest))


def join_by_line(goals: list[dict], costs: list[dict], function: str) -> tuple[list[str], int]:
    """
    Verdict kind per unproved goal, in goal order, and the number of costs paired with no goal.
    A goal's candidates are the costs at its line (and file name, when both give one) whose property
    is of its kind. Fails closed to `unjoined`: no candidate, or more goals than costs sharing the
    same candidates (one of those rows then has no cost of its own).
    """
    located = [
        (i, line, _file_name(c.get("file")), str(c.get("property") or ""))
        for i, c in enumerate(costs)
        if (line := _line_number(c.get("line"))) is not None
    ]
    candidates: list[frozenset[int]] = []
    for g in goals:
        g_line, g_file, g_kind = _line_number(g.get("line")), _file_name(g.get("file")), str(g.get("kind") or "")
        candidates.append(
            frozenset(
                i
                for i, line, file, prop in located
                if line == g_line
                and (not file or not g_file or file == g_file)
                and _kind_matches(g_kind, prop, function)
            )
        )
    sharing = Counter(candidates)
    kinds: list[str] = []
    for cand in candidates:
        if not cand or sharing[cand] > len(cand):
            kinds.append(UNJOINED)
            continue
        verdicts = {_verdict_kind(costs[i]) for i in cand}
        kinds.append(verdicts.pop() if len(verdicts) == 1 else MIXED)
    paired = set().union(*(c for c, k in zip(candidates, kinds, strict=True) if k != UNJOINED))
    return kinds, len(costs) - len(paired)


def prover_verdicts(report: dict) -> tuple[dict[str, dict[str, int]], int]:
    """
    ({prover: {timeout, gave_up, failed}}, goals without per-prover data) for the unproved WP goals of a
    report. WP merges the verdicts of several provers into one entry per goal (a Timeout outranks an
    Unknown), so a goal is attributed to a prover only when the run had exactly one (`wp_provers`);
    every other unproved goal, and every row of a report without `unproven_goal_costs`, has no
    per-prover data. `timeout` counts timeout and stepout, `gave_up` unknown, `failed` a prover error.
    """
    raw_costs = report.get("unproven_goal_costs")
    if not isinstance(raw_costs, list):
        return {}, len(report.get("unproven_goals") or [])
    provers = report.get("wp_provers")
    names = [p for p in provers if isinstance(p, str)] if isinstance(provers, list) else []
    if len(names) != 1:
        return {}, len(raw_costs)
    counts = {"timeout": 0, "gave_up": 0, "failed": 0}
    missing = 0
    for cost in raw_costs:
        kind = _verdict_kind(cost)
        if kind in TIMEOUT_KINDS:
            counts["timeout"] += 1
        elif kind == "unknown":
            counts["gave_up"] += 1
        elif kind == "failed":
            counts["failed"] += 1
        else:
            missing += 1
    return ({names[0]: counts} if any(counts.values()) else {}), missing


def function_record(report: dict, report_rel: str) -> tuple[dict, list[dict]]:
    """Per-function counts and the function's unproved goals (with their verdict kind)."""
    goals: list[dict] = list(report.get("unproven_goals") or [])
    raw_costs = report.get("unproven_goal_costs")
    recorded = isinstance(raw_costs, list)
    costs: list[dict] = list(raw_costs) if isinstance(raw_costs, list) else []
    file = _source_file(report.get("file"))
    function = str(report.get("function"))

    join: str | None = None
    unpaired_costs = 0
    if not goals:
        goal_kinds: list[str] = []
    elif not recorded:
        goal_kinds = [UNRECORDED] * len(goals)
        join = JOIN_PER_FUNCTION
    else:
        goal_kinds, unpaired_costs = join_by_line(goals, costs, function)
        joined = sum(k != UNJOINED for k in goal_kinds)
        join = JOIN_BY_LINE if joined == len(goals) else JOIN_PARTIAL if joined else JOIN_PER_FUNCTION

    if recorded:
        by_verdict = dict(sorted(Counter(_verdict_kind(c) for c in costs).items()))
    else:
        by_verdict = {UNRECORDED: len(goals)} if goals else {}

    by_prover, without_prover_data = prover_verdicts(report)
    proven = int(report.get("proven_count") or 0)
    under_hyp = int(report.get("proven_under_hyp_count") or 0)
    record: dict[str, Any] = {
        "file": file,
        "function": function,
        "report": report_rel,
        "status": str(report.get("status")),
        "total_goals": int(report.get("total_goals") or 0),
        "proved": proven + under_hyp,
        "proven_under_hyp": under_hyp,
        "unproved": len(goals),
        "unproven_count_reported": int(report.get("unproven_count") or 0),
        "by_class": dict(sorted(Counter(str(g.get("obligation_class") or "rte") for g in goals).items())),
        "by_bucket": dict(sorted(Counter(str(g.get("diagnostic_bucket") or "unbucketed") for g in goals).items())),
        "by_verdict": by_verdict,
        # The same verdicts counted per CSV row (what `unproved`, classes and buckets count).
        "rows_by_verdict": dict(sorted(Counter(goal_kinds).items())),
        "verdicts_recorded": recorded,
        "join": join,
        "unpaired_costs": unpaired_costs,
        "provers": [p for p in report.get("wp_provers") or [] if isinstance(p, str)]
        if isinstance(report.get("wp_provers"), list)
        else [],
        "by_prover": by_prover,
        "without_prover_data": without_prover_data,
    }
    unproved = [
        {
            "file": file,
            "function": function,
            "line": g.get("line"),
            "kind": g.get("kind"),
            "annotation": g.get("annotation"),
            "obligation_class": str(g.get("obligation_class") or "rte"),
            "diagnostic_bucket": str(g.get("diagnostic_bucket") or "unbucketed"),
            "verdict_kind": kind,
        }
        for g, kind in zip(goals, goal_kinds, strict=True)
    ]
    return record, unproved


def ambiguous_function_names(run_dir: Path, notes: list[str]) -> list[dict]:
    """
    Function names the ledger has in more than one file among units in WP's scope. `reports/wp/`
    holds one report per name, so at most one of those functions is in the census.
    """
    try:
        units = load_json_optional(run_dir / LEDGER_REL, None)
    except ArtifactError as exc:
        notes.append(f"{LEDGER_REL} unreadable ({exc}); same-named functions in different files not checked")
        return []
    if units is None:
        notes.append(f"no {LEDGER_REL}; same-named functions in different files not checked")
        return []
    if not isinstance(units, list):
        notes.append(f"{LEDGER_REL} is not a list; same-named functions in different files not checked")
        return []
    files: dict[str, set[str]] = {}
    for u in units:
        if isinstance(u, dict) and u.get("function") and u.get("status") not in LEDGER_NOT_WP:
            files.setdefault(str(u["function"]), set()).add(_source_file(u.get("file")))
    return [{"function": fn, "files": sorted(fs)} for fn, fs in sorted(files.items()) if len(fs) > 1]


def _sum_counts(records: list[dict], key: str) -> dict[str, int]:
    total: Counter = Counter()
    for r in records:
        total.update(r[key])
    return dict(sorted(total.items()))


def census(run_dir: Path, near_miss: int = DEFAULT_NEAR_MISS) -> dict:
    run_dir = Path(run_dir)
    reports_dir = wp_reports_dir(run_dir)
    notes: list[str] = []
    read = 0
    skipped: list[dict] = []
    unreadable: list[dict] = []
    records: list[dict] = []
    goals_by_fn: dict[tuple[str, str], list[dict]] = {}

    # Non-recursive: reports/wp/work/ holds per-function scratch output, not reports.
    for path in sorted(reports_dir.glob("*.json")):
        rel = to_run_relative(path, run_dir)
        try:
            report = load_json_strict(path)
        except (ArtifactError, OSError) as exc:
            unreadable.append({"report": rel, "error": str(exc)})
            continue
        if not isinstance(report, dict):
            unreadable.append({"report": rel, "error": "top level is not a JSON object"})
            continue
        reason = _skip_reason(report)
        if reason:
            skipped.append({"report": rel, "reason": reason})
            continue
        problem = _shape_problem(report)
        if problem:
            unreadable.append({"report": rel, "error": problem})
            continue
        try:
            record, unproved = function_record(report, rel)
        except (TypeError, ValueError) as exc:  # a goal count that is not a number
            unreadable.append({"report": rel, "error": f"malformed goal counts: {exc}"})
            continue
        read += 1
        records.append(record)
        goals_by_fn[(record["file"], record["function"])] = unproved

    records.sort(key=lambda r: (-r["unproved"], r["function"], r["file"]))
    with_unproved = [r for r in records if r["unproved"]]
    recorded = [r for r in with_unproved if r["verdicts_recorded"]]
    unrecorded = [r for r in with_unproved if not r["verdicts_recorded"]]

    would_be = [
        {"file": r["file"], "function": r["function"], "unproved": r["unproved"], "by_verdict": r["by_verdict"]}
        for r in recorded
        if r["status"] == UNPROVEN_STATUS and r["by_verdict"] and set(r["by_verdict"]) <= TIMEOUT_KINDS
    ]
    if with_unproved and not recorded:
        notes.append(
            "would_be_all_proven_if_timeouts_closed is empty: no report with unproved goals records verdict "
            "kinds (unproven_goal_costs absent; reports predate per-goal costs)"
        )
    elif unrecorded:
        notes.append(
            f"{len(unrecorded)} function(s) with unproved goals record no verdict kinds and were not considered "
            "for would_be_all_proven_if_timeouts_closed"
        )

    near = [r for r in records if r["status"] == UNPROVEN_STATUS and 1 <= r["unproved"] <= near_miss]
    frame = [g for r in near for g in goals_by_fn[(r["file"], r["function"])]]

    joins = Counter(str(r["join"]) for r in with_unproved)
    if with_unproved and joins.get(JOIN_BY_LINE) == len(with_unproved):
        join = JOIN_BY_LINE
    elif joins.get(JOIN_BY_LINE) or joins.get(JOIN_PARTIAL):
        join = JOIN_PARTIAL
    else:
        join = JOIN_PER_FUNCTION
    unpaired = sum(r["unpaired_costs"] for r in records)
    if unpaired:
        notes.append(
            f"{unpaired} WP goal(s) with a verdict kind were paired with no unproved report row "
            "(no line recorded, or no row of that kind at that line); they count in the verdict totals only"
        )
    if any(len(r["provers"]) != 1 for r in recorded):
        notes.append(
            "verdict kinds are WP's merged verdict over the provers of a run: with several provers a timeout "
            "can hide another prover's unknown, so would_be_all_proven_if_timeouts_closed is an upper bound"
        )
    undecided = [
        {"file": r["file"], "function": r["function"], "status": r["status"]}
        for r in records
        if r["status"] not in (PROVEN_STATUS, UNPROVEN_STATUS)
    ]
    if undecided:
        notes.append(
            f"{len(undecided)} function(s) have a status other than all_proven or unproven_goals_remain "
            "(no goal decided, or the proof was rejected); their 0 unproved goals do not mean proved"
        )
    mismatched = [r["function"] for r in records if r["unproved"] != r["unproven_count_reported"]]
    if mismatched:
        notes.append(f"unproven_goals length differs from unproven_count in: {', '.join(sorted(mismatched))}")
    verdict_total = sum(sum(r["by_verdict"].values()) for r in records)
    unproved_total = sum(r["unproved"] for r in records)
    if verdict_total != unproved_total:
        notes.append(
            f"verdict kinds count WP goals ({verdict_total}) while classes and buckets count CSV report rows "
            f"({unproved_total}); one row can be several WP goals"
        )
    by_prover: dict[str, Counter] = {}
    for r in records:
        for prover, counts in r["by_prover"].items():
            by_prover.setdefault(prover, Counter()).update(counts)
    without_prover_data = sum(r["without_prover_data"] for r in records)
    if without_prover_data:
        notes.append(
            f"{without_prover_data} unproved goal(s) have no per-prover data: WP records one merged verdict per "
            "goal, so a goal counts for a prover only in a report whose run had exactly one prover (wp_provers); "
            "goals of a report without unproven_goal_costs count as rows"
        )
    ambiguous = ambiguous_function_names(run_dir, notes)
    if ambiguous:
        notes.append(
            f"{len(ambiguous)} function name(s) are defined in more than one file; reports/wp/ holds one report "
            "per name, so the others are not in this census (see ambiguous_function_names)"
        )
    if unreadable:
        notes.append("derived lists and totals cover readable reports only; see reports.unreadable")
    notes.append(
        "the report of a function that never merged is the scheduler's baseline (or last parent re-check); "
        "a stalled prover's own report under agents/ is not read"
    )

    return {
        "run_dir": run_dir.as_posix(),
        "source": to_run_relative(reports_dir, run_dir),
        "near_miss_max": near_miss,
        "reports": {
            "read": read,
            "skipped": len(skipped),
            "unreadable": len(unreadable),
            "skipped_reports": skipped,
            "unreadable_reports": unreadable,
        },
        "join": join,
        "join_key": JOIN_KEY,
        "join_by_function": dict(sorted(joins.items())),
        "totals": {
            "functions": len(records),
            "functions_with_unproved_goals": len(with_unproved),
            "functions_by_status": dict(sorted(Counter(r["status"] for r in records).items())),
            "goals": sum(r["total_goals"] for r in records),
            "proved": sum(r["proved"] for r in records),
            "proven_under_hyp": sum(r["proven_under_hyp"] for r in records),
            "unproved": sum(r["unproved"] for r in records),
            "unproved_by_class": _sum_counts(records, "by_class"),
            "unproved_by_bucket": _sum_counts(records, "by_bucket"),
            "unproved_by_verdict": _sum_counts(records, "by_verdict"),
            "unproved_rows_by_verdict": _sum_counts(records, "rows_by_verdict"),
            "unproved_by_prover": {
                p: {k: c[k] for k in ("timeout", "gave_up", "failed")} for p, c in sorted(by_prover.items())
            },
            "unproved_without_prover_data": without_prover_data,
        },
        "functions": records,
        "functions_without_decided_goals": undecided,
        "would_be_all_proven_if_timeouts_closed": would_be,
        "near_miss_functions": [
            {"file": r["file"], "function": r["function"], "unproved": r["unproved"], "total_goals": r["total_goals"]}
            for r in near
        ],
        "near_miss_goals": frame,
        "ambiguous_function_names": ambiguous,
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# Markdown table
# ---------------------------------------------------------------------------


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.replace("\r", " ").replace("\n", " ").split())
    return text.replace("|", "\\|")


def _counts_text(counts: dict[str, int]) -> str:
    return ", ".join(f"{k}: {v}" for k, v in counts.items()) or "-"


def _table(header: list[str], rows: list[list[object]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join(" --- " for _ in header) + "|"]
    out += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return out + [""]


def render_table(data: dict) -> str:
    totals = data["totals"]
    rep = data["reports"]
    out = [f"## WP residual census: `{data['run_dir']}`", ""]
    out.append(
        f"- Reports (`{data['source']}`): read {rep['read']}, skipped {rep['skipped']}, unreadable {rep['unreadable']}"
    )
    out.append(f"- Functions: {totals['functions']} ({_counts_text(totals['functions_by_status'])})")
    out.append(
        f"- Goals: {totals['proved']} proved of {totals['goals']} "
        f"({totals['proven_under_hyp']} under hypotheses), {totals['unproved']} unproved"
    )
    out.append(f"- Verdict join: `{data['join']}` ({_counts_text(data['join_by_function'])}); key: {data['join_key']}")
    out.append("")
    for title, key in (
        ("obligation class", "unproved_by_class"),
        ("diagnostic bucket", "unproved_by_bucket"),
        ("verdict kind", "unproved_by_verdict"),
        ("verdict kind, per report row", "unproved_rows_by_verdict"),
    ):
        out += [f"### Unproved goals by {title}", ""]
        out += _table([title.capitalize(), "Goals"], [[k, v] for k, v in totals[key].items()] or [["-", 0]])

    out += ["### Unproved goals by prover (single-prover runs only)", ""]
    out += _table(
        ["Prover", "Timed out", "Gave up", "Failed"],
        [[p, c["timeout"], c["gave_up"], c["failed"]] for p, c in totals["unproved_by_prover"].items()]
        or [["-", 0, 0, 0]],
    )
    out += [f"Goals without per-prover data: {totals['unproved_without_prover_data']}", ""]

    out += ["### Per function", ""]
    out += _table(
        ["Function", "File", "Status", "Proved/Total", "Unproved", "Classes", "Buckets", "Verdicts", "Join"],
        [
            [
                r["function"],
                r["file"],
                r["status"],
                f"{r['proved']}/{r['total_goals']}",
                r["unproved"],
                _counts_text(r["by_class"]),
                _counts_text(r["by_bucket"]),
                _counts_text(r["by_verdict"]),
                r["join"] or "-",
            ]
            for r in data["functions"]
        ],
    )

    out += ["### Would be all proven if timeouts closed", ""]
    if data["would_be_all_proven_if_timeouts_closed"]:
        out += _table(
            ["Function", "File", "Unproved", "Verdicts"],
            [
                [w["function"], w["file"], w["unproved"], _counts_text(w["by_verdict"])]
                for w in data["would_be_all_proven_if_timeouts_closed"]
            ],
        )
    else:
        out += ["None.", ""]

    out += [f"### Near-miss functions (1 to {data['near_miss_max']} unproved goals)", ""]
    if data["near_miss_functions"]:
        out += _table(
            ["Function", "File", "Unproved", "Total goals"],
            [[n["function"], n["file"], n["unproved"], n["total_goals"]] for n in data["near_miss_functions"]],
        )
        out += ["### Unproved goals of near-miss functions (sampling frame)", ""]
        out += _table(
            ["File", "Function", "Line", "Kind", "Annotation", "Class", "Bucket", "Verdict"],
            [
                [
                    g["file"],
                    g["function"],
                    g["line"],
                    g["kind"],
                    g["annotation"],
                    g["obligation_class"],
                    g["diagnostic_bucket"],
                    g["verdict_kind"],
                ]
                for g in data["near_miss_goals"]
            ],
        )
    else:
        out += ["None.", ""]

    if data["functions_without_decided_goals"]:
        out += ["### Functions without decided goals", ""]
        out += _table(
            ["Function", "File", "Status"],
            [[u["function"], u["file"], u["status"]] for u in data["functions_without_decided_goals"]],
        )
    if rep["unreadable_reports"]:
        out += ["### Unreadable reports", ""]
        out += _table(["Report", "Error"], [[u["report"], u["error"]] for u in rep["unreadable_reports"]])
    if rep["skipped_reports"]:
        out += ["### Skipped reports", ""]
        out += _table(["Report", "Reason"], [[s["report"], s["reason"]] for s in rep["skipped_reports"]])
    if data["ambiguous_function_names"]:
        out += ["### Function names defined in more than one file", ""]
        out += _table(
            ["Function", "Files"], [[a["function"], ", ".join(a["files"])] for a in data["ambiguous_function_names"]]
        )
    if data["notes"]:
        out += ["### Notes", ""] + [f"- {_cell(n)}" for n in data["notes"]] + [""]
    return "\n".join(out)


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_", suffix=path.suffix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Census of the WP goals a finished run left unproved (read-only).")
    parser.add_argument("--run-dir", type=Path, required=True, help="run directory (holds workspace/reports/wp/)")
    parser.add_argument("--out", type=Path, default=None, help="output file (default: stdout)")
    parser.add_argument("--format", choices=("json", "table"), default="json", help="JSON or a Markdown table")
    parser.add_argument(
        "--near-miss",
        type=int,
        default=DEFAULT_NEAR_MISS,
        help=f"most unproved goals for a near-miss function (default {DEFAULT_NEAR_MISS})",
    )
    args = parser.parse_args(argv)
    if args.near_miss < 1:
        parser.error("--near-miss must be at least 1")
    try:
        data = census(args.run_dir, near_miss=args.near_miss)
    except CensusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if data["reports"]["unreadable"]:
        names = ", ".join(u["report"] for u in data["reports"]["unreadable_reports"])
        print(f"warning: {data['reports']['unreadable']} unreadable WP report(s): {names}", file=sys.stderr)

    if args.out is not None:
        if args.format == "json":
            atomic_write_json(args.out, data)
        else:
            _atomic_write_text(args.out, render_table(data) + "\n")
        return 0
    text = json.dumps(data, indent=2, ensure_ascii=False) if args.format == "json" else render_table(data)
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(encoding="utf-8")
    sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
