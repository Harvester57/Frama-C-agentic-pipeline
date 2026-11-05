#!/usr/bin/env python3
"""
Deterministic Eva tuning: a fixed ladder of configurations, one selection rule, and a per-obligation
combination, so that tuning is a cached Make step rather than a judgment call (stdlib only).

The Makefile runs the module's base configuration and, when it leaves Unknown obligations, each rung
of the ladder through run_eva_slice.py and its content cache. `finish`, here, then decides:

1. Guards. A rung is rejected when it did not complete, analysed different inputs, degenerated, grew
   the Dead obligations, gave an obligation an inconsistent status, or reached fewer functions than the
   base run. Alarm count alone is not a safe objective: a run that stops reaching code also stops
   reporting alarms there.
2. Selection among the base run and the admissible rungs: fewest functions with an Unknown, then
   fewest Unknowns, then ladder order. Elapsed time plays no part.
3. Per-loop differential analysis, only for loops in functions that still have Unknowns: unroll one
   loop nest on a scratch mirror and keep it only if Unknowns fall and no obligation turns Dead.
4. Per-obligation combination. An obligation is discharged when any admissible run proves it.
5. The decision goes into workspace/build/params.json and the report's `tuning` block, so another
   machine replays the recorded runs instead of searching again.

Why combining is sound. Eva's values hold "under the assumption that the alarms emitted during the
analysis have been verified" (Eva manual 5.7) and it reduces the state by each alarm it emits (8.1.2),
but those assumptions only cover the execution so far: a Valid status at a statement means no execution
can violate that property before violating one reported as an alarm earlier on the same path. So in
every sound run, the *first* obligation a real execution violates is reported as not Valid. If any run
proves an obligation it cannot be the first one violated; an alarm absent from a run that reached as many
statements is the same claim, since Eva emits one whenever it cannot prove the property. Therefore the obligations no run proves are
enough: if all of them hold, no execution violates anything, by induction on the length of the
execution. Two runs that each assume what the other proves are no circle, because the assumption only
reaches back in time. The kernel states the same contract: a tuning parameter "may improve a generated
element ... a valid status cannot become invalid" (emitter.mli), and Property_status.emit keeps the
strongest status across runs in one session. A red status wins any conflict, as it does there.

The argument needs the runs to differ only in tuning, so every rung holds the sources, harness and
checks fixed and input_digest and reduced_checks are compared. Dead is never counted as a proof: it is
a harness gap (see docs/resources-and-caching.md).

A machine that completes fewer rungs discharges a subset of the same obligations and finds a subset of
the same red statuses: both are unions over completed runs, so it can only leave more units `planned`.
The one case that can differ is a red status only an unfinished rung would have found, on an obligation
another run proves. Under the argument above that statement is unreachable unless an earlier alarm
fails, so verification of the candidate finds no witness and the final verdict is the same.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from eva_loops import LoopRef, find_loops, loop_nests, loop_ref_from_json, mirror_id  # noqa: E402
from eva_options import (  # noqa: E402
    DEFAULT_LOOP_UNROLL,
    LADDER_VERSION,
    TRIAL_TIMEOUT_CEILING_S,
    assumption_options,
    loop_trial_timeout,
    record_is_current,
)
from fingerprint import make_fingerprint  # noqa: E402
from framac_common import (  # noqa: E402
    STATUS_ASSUMED,
    STATUS_DEAD,
    STATUS_INVALID,
    STATUS_INVALID_UNDER_HYP,
    STATUS_NEVER_TRIED,
    STATUS_UNKNOWN,
    STATUS_VALID,
    STATUS_VALID_UNDER_HYP,
    ArtifactError,
    atomic_write_json,
    load_json_optional,
    normalize_flag_args,
)
from run_eva_slice import read_report_rows, run_eva_on_slice, summarize_rows  # noqa: E402

# Loop trials per module: each one is a whole Eva run, and one-by-one analysis is what Loupe measured
# as 137x slower than its model, so the search stops here whatever the machine.
MAX_LOOP_TRIALS = 8
DEFAULT_MIN_COVERAGE_PCT = 30.0
# Measured: at most 14 of 815 obligations go missing from a rung, all alarms Eva emits on its own. Far
# more means obligations no longer match between runs, and an absent alarm would then look like a proof.
MAX_MISSING_SHARE = 0.25
MAX_MISSING_ALWAYS_ALLOWED = 8

_BUCKETS = {
    STATUS_VALID: "valid",
    STATUS_VALID_UNDER_HYP: "valid",
    STATUS_UNKNOWN: "unknown",
    STATUS_NEVER_TRIED: "unknown",
    STATUS_INVALID: "invalid",
    STATUS_INVALID_UNDER_HYP: "invalid",
    STATUS_DEAD: "dead",
    STATUS_ASSUMED: "assumed",
}


# ---------------------------------------------------------------------------
# Reachability, compatible with the fields planned for run_eva_slice.py
# ---------------------------------------------------------------------------

_SUMMARY_MARK = "ANALYSIS SUMMARY"
_FUNCTIONS_RE = re.compile(r"^\s*(\d+) functions analyzed \(out of (\d+)\)", re.M)
_STATEMENTS_RE = re.compile(r"(\d+) statements reached \(out of (\d+)\)")
_COVERAGE_RE = re.compile(r"Coverage estimation = ([\d.]+)%")
_UNREACHED_RE = re.compile(r"Unreached functions \((\d+)\) =")
_FINAL_STATE_RE = re.compile(r"^\[eva:final-states\] Values at end of function (\w+):[ \t]*\n(.*)$", re.M)
_NON_TERMINATING_RE = re.compile(r"^\s*NON TERMINATING FUNCTION\s*$")
_UNREACHED_CALL_RE = re.compile(r"^\s*Function (\w+) calls (\w+) \(at ([^)]+)\)", re.M)
_REACHED_STMTS_MARK = "[metrics:eva:reached-stmts]"
_REACHED_STMTS_RE = re.compile(r"^\s*(\w+): (\d+) stmts out of \d+", re.M)
_DEGENERATION_MARKS = ("Stopping analysis at user request", "Degeneration occurred")


def parse_eva_reachability(
    log_text: str,
    entry_fn: str | None,
    main_fn: str,
    rows: Iterable[dict] = (),
    min_coverage_pct: float = DEFAULT_MIN_COVERAGE_PCT,
) -> dict:
    """Coverage and entry reachability from Eva's log and, for the entry, the report's rows."""
    text = log_text or ""
    coverage: dict[str, Any] = {}
    m = _FUNCTIONS_RE.search(text)
    if m:
        coverage.update(functions_analyzed=int(m.group(1)), functions_total=int(m.group(2)))
    m = _STATEMENTS_RE.search(text)
    if m:
        coverage.update(statements_reached=int(m.group(1)), statements_total=int(m.group(2)))
    m = _COVERAGE_RE.search(text)
    if m:
        coverage["coverage_estimate_pct"] = float(m.group(1))
    m = _UNREACHED_RE.search(text)
    if m:
        coverage["unreached_functions"] = int(m.group(1))

    final_states: set[str] = set()
    non_terminating: set[str] = set()
    for m in _FINAL_STATE_RE.finditer(text):
        final_states.add(m.group(1))
        if _NON_TERMINATING_RE.match(m.group(2)):
            non_terminating.add(m.group(1))

    entry_reached: bool | None = None
    if entry_fn:
        unreached_call = any(
            m.group(1) == main_fn and m.group(2) == entry_fn for m in _UNREACHED_CALL_RE.finditer(text)
        )
        if unreached_call:
            entry_reached = False
        elif entry_fn in final_states:
            entry_reached = True
        elif any(r.get("function") == entry_fn and _bucket(r) != "dead" for r in rows):
            entry_reached = True

    estimate = coverage.get("coverage_estimate_pct")
    if entry_reached is False:
        reachability = "entry_unreached"
    elif estimate is not None and estimate < min_coverage_pct:
        reachability = "low_coverage"
    elif entry_reached:
        reachability = "ok"
    else:
        reachability = "unknown"
    return {
        "entry_fn": entry_fn,
        "entry_reached": entry_reached,
        "reachability": reachability,
        "eva_coverage": coverage,
        "non_terminating_functions": sorted(non_terminating),
        "min_coverage_pct": min_coverage_pct,
    }


def statements_by_function(log_text: str) -> dict[str, int]:
    """Statements Eva reached per function, from the metrics section of its log."""
    text = log_text or ""
    start = text.find(_REACHED_STMTS_MARK)
    if start < 0:
        return {}
    return {m.group(1): int(m.group(2)) for m in _REACHED_STMTS_RE.finditer(text, start)}


def degeneration_reason(log_text: str) -> str | None:
    """
    Why a run with a report is incomplete, or None. In every stopped analysis tried on this image
    (SIGUSR1, -eva-stop-at-nth-alarm, an uncomputable initial state) Frama-C exits non-zero with no CSV,
    so the run fails as not completed first. This is the backstop: Eva prints its summary only after a
    complete analysis (Analysis.post_analysis), and a report without one must not be trusted.
    """
    text = log_text or ""
    for mark in _DEGENERATION_MARKS:
        if mark in text:
            return mark
    return None if _SUMMARY_MARK in text else "no analysis summary in the log"


# ---------------------------------------------------------------------------
# Runs and their obligations
# ---------------------------------------------------------------------------


def _bucket(row: dict) -> str:
    return _BUCKETS.get(row.get("status", ""), "other")


def row_path(row: dict) -> str:
    directory = (row.get("directory") or "").replace("\\", "/").rstrip("/")
    file = (row.get("file") or "").replace("\\", "/")
    return f"{directory}/{file}" if directory and directory != "." and not file.startswith("/") else file


def target_unknown_rows(rows: Iterable[dict]) -> list[dict]:
    """
    The Unknown rows that can become prover work. A libc function's own row summarizes its call sites,
    which have rows of their own in the callers, and no ledger unit ever exists for it.
    """
    return [r for r in rows if _bucket(r) == "unknown" and "FRAMAC_SHARE" not in row_path(r)]


def obligation_key(row: dict) -> tuple[str, int]:
    """
    The fingerprint names a property in a function; the line tells apart two statements checking the
    same predicate. The CSV hides the column and drops identical rows, so one key can stand for several
    statements on a line, and only the set of statuses under it can be compared between runs.
    """
    fingerprint = make_fingerprint(row_path(row), row.get("function", ""), row.get("kind", ""), row.get("property", ""))
    return fingerprint, int(row.get("line") or 0)


def key_function(key: tuple[str, int]) -> str:
    """The function an obligation key belongs to (fingerprint format: file#function::kind::hash)."""
    return key[0].split("#", 1)[-1].split("::", 1)[0]


@dataclass(eq=False)
class EvaRun:
    name: str
    report: dict
    rows: list[dict] = field(default_factory=list)
    log_text: str = ""
    entry_fn: str | None = None
    reach: dict = field(default_factory=dict)
    groups: dict[tuple[str, int], set[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.groups:
            for row in self.rows:
                self.groups.setdefault(obligation_key(row), set()).add(_bucket(row))
        if not self.reach:
            main_fn = self.report.get("main_fn") or "eva_main"
            self.reach = parse_eva_reachability(self.log_text, self.entry_fn, main_fn, self.rows)
            # What run_eva_slice.py reports itself takes precedence over this parse.
            for name in tuple(self.reach):
                if name in self.report:
                    self.reach[name] = self.report[name]

    @property
    def completed(self) -> bool:
        return self.report.get("status") == "ok"

    @property
    def unknown_rows(self) -> list[dict]:
        return target_unknown_rows(self.rows)

    @property
    def unknown_count(self) -> int:
        return len(self.unknown_rows)

    @property
    def unknown_functions(self) -> set[str]:
        return {r["function"] for r in self.unknown_rows if r.get("function")}

    def target_keys(self) -> set[tuple[str, int]]:
        return {obligation_key(r) for r in self.rows if "FRAMAC_SHARE" not in row_path(r)}

    def keys_with(self, bucket: str) -> set[tuple[str, int]]:
        return {key for key, buckets in self.groups.items() if bucket in buckets}

    def score(self) -> tuple[int, int]:
        return len(self.unknown_functions), self.unknown_count

    def reaches_as_much_as(self, other: EvaRun, function: str | None = None) -> bool:
        """
        Whether this run reached at least as many statements as `other` in `function`, which an absent
        alarm relies on. Without per-function figures for it, the whole run has to.
        """
        mine = statements_by_function(self.log_text).get(function or "")
        theirs = statements_by_function(other.log_text).get(function or "")
        if mine is None or theirs is None:
            mine = (self.reach.get("eva_coverage") or {}).get("statements_reached")
            theirs = (other.reach.get("eva_coverage") or {}).get("statements_reached")
        return mine is not None and theirs is not None and mine >= theirs

    def proves(self, key: tuple[str, int], base: EvaRun) -> bool:
        """
        Whether this run discharges an obligation: every row under it Valid, or no alarm at all. Eva
        emits an alarm whenever it cannot prove the property, unless it never reaches the statement,
        so absence only counts where the run reached as much of the function as the base run did.
        """
        buckets = self.groups.get(key)
        return buckets == {"valid"} if buckets is not None else self.reaches_as_much_as(base, key_function(key))

    def metrics(self) -> dict:
        cov = self.reach.get("eva_coverage") or {}
        return {
            "status": self.report.get("status"),
            "functions_with_unknown": len(self.unknown_functions),
            "unknown_count": self.unknown_count,
            "valid_count": self.report.get("valid_count"),
            "invalid_count": self.report.get("invalid_count"),
            "dead_count": self.report.get("dead_count"),
            "functions_analyzed": cov.get("functions_analyzed"),
            "statements_reached": cov.get("statements_reached"),
            "coverage_estimate_pct": cov.get("coverage_estimate_pct"),
            "entry_reached": self.reach.get("entry_reached"),
            "elapsed_s": self.report.get("elapsed_s"),
            "cache_hit": (self.report.get("cache") or {}).get("hit"),
        }


def load_run(name: str, report: dict | None, entry_fn: str | None = None) -> EvaRun:
    """A run from its report; its CSV and log are read when the report says it completed."""
    report = report if isinstance(report, dict) else {"status": "no_report"}
    rows: list[dict] = []
    log_text = ""
    if report.get("status") == "ok":
        csv_file = report.get("csv_file")
        if not csv_file or not Path(csv_file).is_file():
            report = {**report, "status": "no_report", "reason": "the report names no readable alarms.csv"}
        else:
            rows = read_report_rows(Path(csv_file), report.get("mirror_root"))
            log_file = report.get("log_file")
            if log_file and Path(log_file).is_file():
                log_text = Path(log_file).read_text(encoding="utf-8", errors="replace")
    return EvaRun(name=name, report=report, rows=rows, log_text=log_text, entry_fn=entry_fn)


def analysis_identity(run: EvaRun) -> tuple:
    """What two runs must share to be the same analysis apart from tuning."""
    report = run.report
    return (
        report.get("input_digest"),
        report.get("main_fn"),
        tuple(sorted(report.get("sources") or [])),
        tuple(sorted(report.get("reduced_checks") or [])),
        tuple(sorted(assumption_options(report.get("eva_options") or {}).items())),
    )


# ---------------------------------------------------------------------------
# Guards and selection
# ---------------------------------------------------------------------------


def guard_reasons(run: EvaRun, base: EvaRun) -> list[str]:
    """Why `run` must not be used in place of `base`; empty when it is admissible."""
    if not run.completed:
        return [f"not_completed:{run.report.get('status')}"]
    reasons: list[str] = []
    if not run.report.get("input_digest") or analysis_identity(run) != analysis_identity(base):
        reasons.append("different_analysis")
    degenerated = degeneration_reason(run.log_text)
    if degenerated:
        reasons.append(f"degenerated:{degenerated}")
    new_dead = run.keys_with("dead") - base.keys_with("dead")
    if new_dead:
        reasons.append(f"dead_grew:{len(new_dead)}")
    new_other = run.keys_with("other") - base.keys_with("other")
    if new_other:
        reasons.append(f"inconsistent_status:{len(new_other)}")
    target_keys = base.target_keys()
    missing = target_keys - set(run.groups)
    if len(missing) > max(MAX_MISSING_ALWAYS_ALLOWED, MAX_MISSING_SHARE * len(target_keys)):
        reasons.append(f"obligations_missing:{len(missing)}")
    if (run.report.get("cache") or {}).get("not_published"):
        reasons.append("inputs_changed_during_the_run")
    if base.reach.get("entry_reached") is True and run.reach.get("entry_reached") is not True:
        reasons.append("entry_reachability_dropped")
    new_stuck = set(run.reach.get("non_terminating_functions") or []) - set(
        base.reach.get("non_terminating_functions") or []
    )
    if new_stuck:
        reasons.append(f"non_termination_grew:{','.join(sorted(new_stuck))}")
    # Not statements: one that stops being reached shows up here only if it carries no obligation, and
    # a statement proved infeasible is what more precision is for. See EvaRun.proves for what it does affect.
    run_cov = run.reach.get("eva_coverage") or {}
    base_cov = base.reach.get("eva_coverage") or {}
    for name in ("functions_analyzed", "coverage_estimate_pct"):
        if name in base_cov and (name not in run_cov or run_cov[name] < base_cov[name]):
            reasons.append(f"coverage_dropped:{name}")
    return reasons


def select_run(base: EvaRun, candidates: Iterable[EvaRun]) -> EvaRun:
    """The admissible run with the fewest functions with an Unknown, then the fewest Unknowns. Ties go first."""
    best = base
    for run in candidates:
        if not guard_reasons(run, base) and run.score() < best.score():
            best = run
    return best


# ---------------------------------------------------------------------------
# Per-obligation combination
# ---------------------------------------------------------------------------


@dataclass
class Combination:
    rows: list[dict]
    upgraded: list[dict]
    conflicts: list[dict]


def combine_runs(
    selected: EvaRun, base: EvaRun, admissible: list[EvaRun], red_sources: Iterable[EvaRun] = ()
) -> Combination:
    """
    The selected run's rows, with every Unknown that an admissible run discharges turned Valid and every
    Invalid status of any complete run brought in. An obligation stays Unknown only if no admissible run
    discharges it, so what remains does not depend on which run happens to be selected.
    """
    runs = [selected, *(r for r in admissible if r is not selected)]
    reds: dict[tuple[str, int], tuple[EvaRun, list[dict]]] = {}
    for run in dict.fromkeys([*runs, *red_sources]):
        for row in run.rows:
            if _bucket(row) == "invalid":
                key = obligation_key(row)
                reds.setdefault(key, (run, []))
                if reds[key][0] is run:
                    reds[key][1].append(row)

    upgraded: dict[tuple[str, int], dict] = {}
    conflicts: list[dict] = []
    for key, buckets in selected.groups.items():
        provers = [r for r in runs if r.proves(key, base)]
        if key in reds:
            if provers:
                conflicts.append({"fingerprint": key[0], "line": key[1], "invalid_in": reds[key][0].name})
            continue
        if "unknown" in buckets and provers:
            upgraded[key] = {
                "fingerprint": key[0],
                "line": key[1],
                "function": key_function(key),
                "proved_by": provers[0].name,
                "how": "absent" if key not in provers[0].groups else "valid",
            }

    rows: list[dict] = []
    for row in selected.rows:
        key = obligation_key(row)
        if key in reds and reds[key][0] is not selected:
            continue
        if key in upgraded and _bucket(row) == "unknown":
            row = {**row, "status": STATUS_VALID, "status_raw": "Valid"}
        rows.append(row)
    # An alarm only other runs report still stands, unless some run's proof or silence discharges it.
    # The selected run's own silence is simply its result; another run's is one the report relies on.
    carried: dict[tuple[str, int], EvaRun] = {}
    for run in runs[1:]:
        for key in run.keys_with("unknown"):
            if key in selected.groups or key in reds or key in carried or key in upgraded:
                continue
            provers = [r for r in runs if r.proves(key, base)]
            if not provers:
                carried[key] = run
            elif provers[0] is not selected:
                upgraded[key] = {
                    "fingerprint": key[0],
                    "line": key[1],
                    "function": key_function(key),
                    "proved_by": provers[0].name,
                    "how": "absent" if key not in provers[0].groups else "valid",
                }
    for key in sorted(carried):
        run = carried[key]
        rows.extend(
            {**row, "tuning_run": run.name}
            for row in run.rows
            if obligation_key(row) == key and _bucket(row) == "unknown"
        )
    for key in sorted(reds):
        run, red_rows = reds[key]
        if run is not selected:
            rows.extend({**row, "tuning_run": run.name} for row in red_rows)
    return Combination(
        rows=rows,
        upgraded=[upgraded[key] for key in sorted(upgraded)],
        conflicts=sorted(conflicts, key=lambda c: (c["fingerprint"], c["line"])),
    )


# ---------------------------------------------------------------------------
# Per-loop differential analysis
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LoopCandidate:
    function: str
    file: str
    root_ordinal: int
    refs: tuple[LoopRef, ...]

    @property
    def name(self) -> str:
        return f"loop-{self.function}-{self.root_ordinal}"


def plan_loop_candidates(run: EvaRun, unroll: int, limit: int = MAX_LOOP_TRIALS) -> list[LoopCandidate]:
    """
    Loop nests of the functions that have Unknowns, those with the most Unknowns first. A nest is
    unrolled as a whole: unrolling only one level of a nest rarely separates states.
    """
    counts: Counter[tuple[str, str]] = Counter()
    for row in run.unknown_rows:
        path = row_path(row)
        if row.get("function") and not path.startswith("/") and "FRAMAC_SHARE" not in path:
            counts[(row["function"], path)] += 1
    candidates: list[LoopCandidate] = []
    for (function, path), _ in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        try:
            source = Path(path).read_text(encoding="utf-8", errors="surrogateescape")
        except OSError:
            continue
        for nest in loop_nests(find_loops(source, function, path)):
            refs = tuple(LoopRef(path, function, site.ordinal, unroll) for site in nest if not site.annotated)
            if refs:
                candidates.append(LoopCandidate(function, path, nest[0].ordinal, refs))
    return candidates[:limit]


def loop_trial_helps(trial: EvaRun, current: EvaRun, base: EvaRun) -> bool:
    """Keep an annotation only if it removes Unknowns without any obligation turning Dead."""
    return (
        not guard_reasons(trial, base)
        and trial.unknown_count < current.unknown_count
        and not trial.keys_with("dead") - current.keys_with("dead")
    )


# ---------------------------------------------------------------------------
# finish: what the Makefile runs for a module once its trials are done
# ---------------------------------------------------------------------------


@dataclass
class Tuner:
    """Reads a module's finished trials and runs further ones, through run_eva_on_slice and its cache."""

    args: argparse.Namespace

    @property
    def report_dir(self) -> Path:
        return Path(self.args.report_dir)

    @property
    def work_dir(self) -> Path:
        return Path(self.args.work_dir)

    def read_trial(self, name: str) -> EvaRun:
        try:
            report = load_json_optional(self.report_dir / f"{name}.json", None)
        except ArtifactError as exc:
            report = {"status": "no_report", "reason": str(exc)}
        return load_run(name, report, self.args.entry_fn)

    def run_trial(self, name: str, options: dict, refs: Iterable[LoopRef], timeout: int | None = None) -> EvaRun:
        a = self.args
        refs = sorted(set(refs))
        result = run_eva_on_slice(
            sources=a.sources,
            main_fn=a.main,
            out_dir=self.work_dir / name,
            cppflags=a.cppflags,
            slevel=a.slevel,
            mlevel=a.mlevel,
            timeout=timeout or a.timeout or TRIAL_TIMEOUT_CEILING_S,
            extra_domains=a.extra_domains,
            allow_incomplete_recursion_specs=a.allow_incomplete_recursion_specs,
            eva_options=options,
            loop_unroll=refs,
            # Fixed by the annotation set, so the same set is one cache entry under any trial's name.
            mirror_root=(self.work_dir / "mirrors" / mirror_id(refs)).as_posix() if refs else None,
        )
        result["module"] = a.module
        atomic_write_json(self.report_dir / f"{name}.json", result)
        return load_run(name, result, a.entry_fn)


def _run_row(run: EvaRun, base: EvaRun, verdict: str | None = None) -> dict:
    reasons = guard_reasons(run, base) if run is not base else []
    row = {
        "name": run.name,
        "options": run.report.get("eva_options") or {},
        "loop_unroll": run.report.get("loop_unroll") or [],
        **run.metrics(),
        "verdict": verdict or ("rejected" if reasons else "admissible"),
    }
    if reasons:
        row["reasons"] = reasons
    return row


def search_loops(tuner: Tuner, rung: EvaRun, base: EvaRun, unroll: int) -> tuple[EvaRun, list[EvaRun], list[dict]]:
    """
    One loop nest at a time on top of the selected rung, each kept only if it helps, so a later nest
    is judged with the earlier ones in place. Returns the best run, every completed trial, the table.
    """
    current = rung
    options = dict(rung.report.get("eva_options") or {})
    timeout = min(tuner.args.timeout or TRIAL_TIMEOUT_CEILING_S, loop_trial_timeout(rung.report.get("elapsed_s")))
    kept: list[LoopRef] = []
    trials: list[EvaRun] = []
    table: list[dict] = []
    for candidate in plan_loop_candidates(rung, unroll):
        if candidate.function not in current.unknown_functions:
            table.append({"name": candidate.name, "function": candidate.function, "verdict": "not_needed"})
            continue
        trial = tuner.run_trial(candidate.name, options, [*kept, *candidate.refs], timeout)
        trials.append(trial)
        helps = loop_trial_helps(trial, current, base)
        table.append({"function": candidate.function, **_run_row(trial, base, "kept" if helps else None)})
        if helps:
            kept.extend(candidate.refs)
            current = trial
    return current, trials, table


def replay_loops(tuner: Tuner, record: dict, rung: EvaRun, base: EvaRun) -> tuple[EvaRun, list[EvaRun], list[dict]]:
    """The recorded annotations and the recorded loop trials, without searching."""
    options = dict(record.get("options") or {})
    loops = [loop_ref_from_json(item) for item in record.get("loops") or []]
    selected = rung
    trials: list[EvaRun] = []
    if loops:
        selected = tuner.run_trial("loops", options, loops)
        trials.append(selected)
    for item in record.get("contributors") or []:
        refs = [loop_ref_from_json(ref) for ref in item.get("loops") or []]
        if refs and sorted(refs) != sorted(loops):
            trials.append(tuner.run_trial(str(item["name"]), dict(item.get("options") or {}), refs))
    return selected, trials, [_run_row(trial, base) for trial in trials]


def build_record(
    args: argparse.Namespace,
    base: EvaRun,
    rung: EvaRun,
    selected: EvaRun,
    contributors: list[dict],
    unfinished: list[EvaRun],
) -> dict:
    return {
        "ladder": LADDER_VERSION,
        "settings_digest": args.settings_digest,
        "input_digest": base.report.get("input_digest"),
        "selected": selected.name,
        "rung": rung.name,
        "options": dict(selected.report.get("eva_options") or {}),
        "loops": selected.report.get("loop_unroll") or [],
        "contributors": contributors,
        # For the record: a later search happens on other settings or sources, or on --eva-retune.
        "unfinished": [run.name for run in unfinished],
    }


def finish(args: argparse.Namespace) -> dict:
    """
    Decide for one module from its finished trials: write the module's report (the only one the ledger
    reads) and the evidence, and record the decision in params.json unless this was a replay of it.
    """
    from pipeline_make import load_params, record_eva_tuning

    tuner = Tuner(args)
    base = tuner.read_trial("base")

    def write(report: dict) -> dict:
        report["module"] = args.module
        atomic_write_json(Path(args.out_json), report)
        atomic_write_json(tuner.report_dir / "decision.json", report.get("tuning") or {})
        return report

    if not base.completed:
        failed = {"error_summary": [], **base.report}
        if failed.get("status") == "no_report":
            failed.update(status="analysis_error", reason="no_report")
        failed["tuning"] = {"mode": "skipped", "reason": "the base run did not complete"}
        return write(failed)
    if not base.unknown_rows:
        clean = {**base.report, **base.reach}
        clean["tuning"] = {"mode": "skipped", "reason": "the base run left no Unknown obligations"}
        return write(clean)

    record = load_params(args.run_dir)["modules"].get(args.module, {}).get("eva_tuned")
    replay = record_is_current(record, args.settings_digest, base.report.get("input_digest"))
    rungs = [tuner.read_trial(name) for name in args.rungs]
    by_name = {run.name: run for run in rungs}

    if replay:
        rung = by_name.get(record.get("rung", "base"), base)
        selected, loop_runs, loop_table = replay_loops(tuner, record, rung, base)
    else:
        rung = select_run(base, rungs)
        selected, loop_runs, loop_table = search_loops(tuner, rung, base, args.loop_unroll)

    # A replay on a slower machine may not finish what was recorded: fall back, leaving more `planned`.
    all_runs = [base, *rungs, *loop_runs]
    if selected is not base and guard_reasons(selected, base):
        selected = select_run(base, all_runs[1:])
    admissible = [run for run in all_runs if run is base or not guard_reasons(run, base)]
    # Red statuses count from any complete run of this analysis, even one rejected for losing coverage:
    # the alarm is often why it lost it.
    red_sources = [
        run
        for run in all_runs
        if run.completed and analysis_identity(run) == analysis_identity(base) and not degeneration_reason(run.log_text)
    ]
    combination = combine_runs(selected, base, admissible, red_sources)

    # Everything the report rests on has to run again on a replay: proofs and red statuses alike.
    relied_on = {item["proved_by"] for item in combination.upgraded}
    relied_on |= {row["tuning_run"] for row in combination.rows if row.get("tuning_run")}
    contributors = [
        {
            "name": run.name,
            "options": run.report.get("eva_options") or {},
            "loops": run.report.get("loop_unroll") or [],
        }
        for run in all_runs
        if run.name in relied_on and run is not base and run is not selected
    ]
    unfinished = [run for run in all_runs if not run.completed]
    decision = build_record(args, base, rung if rung in admissible else base, selected, contributors, unfinished)
    summary = summarize_rows(combination.rows)
    remaining = target_unknown_rows(combination.rows)
    report = {**selected.report, **summary, **selected.reach}
    report["tuning"] = {
        "mode": "replay" if replay else "ladder",
        "selected": selected.name,
        "selected_options": decision["options"],
        "selected_loops": decision["loops"],
        "before": base.metrics(),
        "selected_metrics": selected.metrics(),
        "after": {
            "functions_with_unknown": len({r["function"] for r in remaining if r.get("function")}),
            "unknown_count": len(remaining),
            "valid_count": summary["valid_count"],
            "invalid_count": summary["invalid_count"],
            "dead_count": summary["dead_count"],
        },
        "runs": [_run_row(run, base, "selected" if run is selected else None) for run in [base, *rungs]],
        "loops": loop_table,
        "combination": {
            "method": "per_obligation_union_of_admissible_runs",
            "runs": [run.name for run in admissible],
            "upgraded": combination.upgraded,
            "conflicts": combination.conflicts,
        },
        "decision": decision,
    }
    write(report)
    if not replay:
        record_eva_tuning(args.run_dir, args.module, decision)
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decide a module's Eva tuning from its finished trials.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_finish = sub.add_parser("finish", help="Select, try per-loop unrolling, combine, write the report and decision")
    p_finish.add_argument("--module", required=True)
    p_finish.add_argument("--sources", nargs="+", required=True)
    p_finish.add_argument("--main", required=True)
    p_finish.add_argument("--entry-fn", default=None)
    p_finish.add_argument("--cppflags", default="-I.")
    p_finish.add_argument("--slevel", type=int, default=100)
    p_finish.add_argument("--mlevel", type=int, default=0)
    p_finish.add_argument("--extra-domains", default="")
    p_finish.add_argument("--allow-incomplete-recursion-specs", action="store_true")
    p_finish.add_argument("--timeout", type=int, default=None, help="Seconds for each loop trial")
    p_finish.add_argument("--settings-digest", required=True, help="Digest of the module settings (pipeline_make.py)")
    p_finish.add_argument("--rungs", nargs="*", default=[], help="Names of the finished rung trials, in ladder order")
    p_finish.add_argument("--loop-unroll", type=int, default=DEFAULT_LOOP_UNROLL)
    p_finish.add_argument("--report-dir", required=True)
    p_finish.add_argument("--work-dir", required=True)
    p_finish.add_argument("--run-dir", type=Path, default=Path("."))
    p_finish.add_argument("--out-json", required=True)
    raw = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(normalize_flag_args(raw, ("--cppflags",)))
    report = finish(args)
    tuning = report.get("tuning") or {}
    print(
        json.dumps(
            {
                "status": report.get("status"),
                "module": report.get("module"),
                "unknown_count": report.get("unknown_count"),
                "surviving_unknown_functions": report.get("surviving_unknown_functions"),
                "tuning": {k: tuning[k] for k in ("mode", "selected", "reason", "before", "after") if k in tuning},
            },
            indent=2,
        )
    )
    return 0 if report.get("status") == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
