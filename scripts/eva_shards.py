#!/usr/bin/env python3
"""
Eva sharding: one module's Eva run split by dispatch case into k runs, and their reports merged into
the module's report (docs/guides/eva-sharding.md).

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
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import phase0_gates  # noqa: E402
from eva_flamegraph import fold_flamegraph  # noqa: E402
from eva_options import TUNING_SKIP_MARGIN  # noqa: E402
from framac_common import (  # noqa: E402
    STATUS_NEVER_TRIED,
    ArtifactError,
    atomic_write_json,
    bound_flow_location,
    load_json_strict,
    resolve_flows,
    spill_large_flows,
)

SHARD_FORMAT = 1
SHARD_DIR = "workspace/reports/eva-shards"
EVA_SHARD_MACRO = "FRAMAC_EVA_SHARD"  # generate_harness.EVA_SHARD_MACRO
# The reduced check run_eva_slice records when it retries a run that aborted on `assigns:missing` (a
# recursive call without an ACSL assigns clause). Must equal the string run_eva_slice._eva_command
# appends (a test checks it). It reacts to what a shard's cases reached, not to how the shard was
# configured: a shard that finished without it never raised `assigns:missing` (an error by default), so
# running it with the downgrade changes nothing. Shards may therefore differ in it alone, and the merged
# report carries it when any shard does.
RECURSION_REDUCED_CHECK = "-eva-warn-key assigns:missing=warning (recursive calls use kernel-inferred assigns)"
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


def case_callee_counts(case_text: str) -> dict[str, int]:
    """Direct call multiplicity per function in a dispatch case (`name -> count >= 1`)."""
    counts: Counter[str] = Counter(
        m.group(1) for m in _CALL_RE.finditer(case_text or "") if m.group(1) not in _NOT_CALLS
    )
    return dict(counts)


def case_callees(case_text: str) -> set[str]:
    """The functions a dispatch case calls directly (its statements as generate_harness wrote them)."""
    return set(case_callee_counts(case_text))


def case_costs(cases: list[str], flamegraph_txt: Path | None, main_fn: str = "eva_main") -> tuple[list[float], str]:
    """
    Each dispatch case's share of a single run's time, from its `-eva-flamegraph` file: the inclusive
    time of every function eva_main calls directly, split between the cases that call it in proportion
    to static call multiplicity (uniform `1 / len(owners)` when each caller calls it once). Time no
    case accounts for (eva_main's own, and callees outside the switch) is split evenly between all
    cases. Every case costs the same without a usable profile. Returns (costs, basis).
    """
    costs, basis, _ = _case_profile(cases, flamegraph_txt, main_fn)
    return costs, basis


def _case_profile(cases: list[str], flamegraph_txt: Path | None, main_fn: str) -> tuple[list[float], str, list[int]]:
    """
    `case_costs`, plus the cases the profile has no sample of (`unsampled_cases`). Empty without a
    usable profile.
    """
    n = len(cases)
    uniform: tuple[list[float], str, list[int]] = [1.0] * n, "uniform", []
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
    callee_counts = [case_callee_counts(text) for text in cases]
    callers: defaultdict[str, list[tuple[int, int]]] = defaultdict(list)
    for k, counts in enumerate(callee_counts):
        for name, mult in counts.items():
            if mult > 0:
                callers[name].append((k, mult))
    costs = [0.0] * n
    for name, t in inclusive.items():
        owners = callers.get(name)
        if not owners:
            shared += t
            continue
        total_mult = sum(mult for _, mult in owners)
        for k, mult in owners:
            costs[k] += t * mult / total_mult
    costs = [c + shared / n for c in costs]
    if sum(costs) <= 0:
        return uniform
    return costs, "flamegraph", unsampled_cases(callee_counts, inclusive)


def unsampled_cases(callee_counts: list[dict[str, int]], inclusive: dict[str, float]) -> list[int]:
    """
    The cases a profile shows no sign of: none of the case's own callees has a sample. A case's own
    callees are those of its direct callees that the fewest cases call (only it, usually: the API
    function it exercises), so time in a helper every case calls, or in a callee another case shares,
    is not taken as a sign of this case. A case that calls nothing has no sign either way and is not
    listed. In a run that timed out, these are the cases Eva had not reached yet: their cost is unknown,
    not zero.
    """
    callers: Counter[str] = Counter(name for counts in callee_counts for name, mult in counts.items() if mult > 0)
    out: list[int] = []
    for k, counts in enumerate(callee_counts):
        names = [name for name, mult in counts.items() if mult > 0]
        if not names:
            continue
        fewest = min(callers[name] for name in names)
        own = [name for name in names if callers[name] == fewest]
        if all(inclusive.get(name, 0.0) <= 0 for name in own):
            out.append(k)
    return out


def impute_unsampled(costs: list[float], unsampled: list[int]) -> tuple[list[float], float | None]:
    """
    The costs with each unsampled case raised to the mean cost of the sampled ones, and that prior
    (None, costs unchanged, when no case or every case is unsampled). The mean, not the median: in a
    timed-out run one case usually holds nearly all the samples (c-ares dnsrec: 99.98%) and the median
    is then ~0, which would pack every unreached case into one shard again. The mean says an unreached
    case may cost as much as an average reached one, the dominant case included.
    """
    missing = set(unsampled)
    sampled = [c for k, c in enumerate(costs) if k not in missing]
    if not missing or not sampled:
        return costs, None
    prior = sum(sampled) / len(sampled)
    return [max(c, prior) if k in missing else c for k, c in enumerate(costs)], prior


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


def predicted_shard_times(costs: list[float], shards: list[list[int]], total_s: float) -> list[float]:
    """Each shard's predicted time, with the single run's time spread by cost."""
    whole = sum(costs) or 1.0
    return [sum(costs[c] for c in shard) * total_s / whole for shard in shards]


def predicted_makespan(costs: list[float], shards: list[list[int]], total_s: float) -> float:
    """The slowest shard's predicted time, with the single run's time spread by cost."""
    return max(predicted_shard_times(costs, shards, total_s), default=0.0)


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
    censored: bool = False,
    profile_censored: bool | None = None,
) -> dict:
    """
    A module's shard plan: which cases each shard keeps, and what it was predicted from. `censored`: the
    run it is predicted from timed out, so its time and its flamegraph's per-case costs are truncated and
    every predicted time is a lower bound. `choose_shard_count` stops at MAX_SHARDS (or one shard per
    case) even when the slowest shard is still predicted over `limit_s`; `predicted_over_limit` records
    that, and `over_limit_note` says it at `gen`. The plan is still made then: the other shards finish,
    and a single run would hit the same limit.

    `profile_censored` (default: `censored`): the flamegraph is the timed-out run's (not a completed
    fallback tier's). Then a case it has no sample of was not reached before the timeout: its cost is
    unknown rather than ~0, so it gets the mean sampled case's (`impute_unsampled`) on top of `total_s`,
    which the sampled cases keep. The plan lists those cases in `basis.imputed_cases`.
    """
    costs, basis, unsampled = _case_profile(cases, flamegraph_txt, "eva_main")
    censored_profile = censored if profile_censored is None else profile_censored
    predict_s, imputed, prior_s = total_s, [], None
    if censored_profile and basis == "flamegraph":
        observed = sum(costs)
        costs_in, prior = impute_unsampled(costs, unsampled)
        if prior is not None:
            # Seconds per unit of cost stay those of the sampled cases: the imputed time is added.
            predict_s = total_s * sum(costs_in) / observed
            imputed, prior_s, costs = sorted(unsampled), prior * total_s / observed, costs_in
    k = forced if forced else choose_shard_count(costs, predict_s, limit_s)
    shards = pack(costs, k)
    times = predicted_shard_times(costs, shards, predict_s)
    makespan = max(times, default=0.0)
    imputation = (
        {"imputed_cases": imputed, **({"imputed_case_s": round(prior_s, 1)} if prior_s is not None else {})}
        if censored_profile
        else {}
    )
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
            "censored": bool(censored),
            "predicted_over_limit": makespan >= limit_s,
            **imputation,
        },
        "predicted_makespan_s": round(makespan, 1),
        "predicted_shard_s": [round(t, 1) for t in times],
    }


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def timed_out_profile(report: dict) -> bool:
    """Whether a report's flamegraph is that of a run that timed out (not of a completed fallback tier)."""
    profile = report.get("cost_profile")
    if isinstance(profile, dict) and profile.get("run") == "timed_out":
        return True
    return report.get("status") == "analysis_timeout"


def timed_out_run_s(report: dict) -> float | None:
    """
    How long a timed-out run is known to have taken, at least: the wall limit it ran under and the time
    it ran, as its report recorded them (run_eva_slice.py puts both in the timed-out run's
    `cost_profile`, which a completed fallback tier's report keeps), else a timed-out report's own
    `elapsed_s` (the timed-out run's, also when no fallback tier completed). None when the report does
    not say: a completed fallback tier's report from before the fields existed, or one whose timed-out
    run left no flamegraph samples (no `cost_profile` then); its `elapsed_s` is the tier's.
    """
    seen: list[float] = []
    profile = report.get("cost_profile")
    if isinstance(profile, dict) and profile.get("run") == "timed_out":
        seen += [v for v in (_number(profile.get("timeout_s")), _number(profile.get("elapsed_s"))) if v]
    if report.get("status") == "analysis_timeout":
        elapsed = _number(report.get("elapsed_s"))
        if elapsed:
            seen.append(elapsed)
    return max(seen) if seen else None


def over_limit_note(record: Any, module: str) -> str | None:
    """
    What to tell the user when a plan's slowest shard is predicted at or over its limit, or None. Plans
    recorded before `predicted_over_limit` existed are judged from their makespan and limit.
    """
    if not isinstance(record, dict):
        return None
    raw_basis = record.get("basis")
    basis: dict = raw_basis if isinstance(raw_basis, dict) else {}
    predicted, limit = _number(record.get("predicted_makespan_s")), _number(basis.get("limit_s"))
    over = basis.get("predicted_over_limit")
    if not isinstance(over, bool):
        over = predicted is not None and limit is not None and predicted >= limit
    if not over:
        return None
    raw_shards = record.get("shards")
    shards: list = raw_shards if isinstance(raw_shards, list) else []
    raw_times = record.get("predicted_shard_s")
    times = [_number(t) for t in raw_times] if isinstance(raw_times, list) else []
    which, single = "the slowest shard", False
    if times and len(times) == len(shards) and all(t is not None for t in times):
        i = max(range(len(times)), key=lambda j: (times[j] or 0.0, -j))
        cases = shards[i] if isinstance(shards[i], list) else []
        single = len(cases) == 1
        which = f"the slowest shard, shard {i} ({'case' if single else 'cases'} {cases}),"
    note = (
        f"the plan is over its planning limit: {which} is predicted {predicted} s, at or over the {limit} s "
        f"limit (the module's Eva timeout / {TUNING_SKIP_MARGIN})"
    )
    censored = basis.get("censored")
    if censored is True:
        note += (
            "; that is a lower bound, since the run it is predicted from timed out (its time and its "
            "flamegraph's per-case costs are truncated), so the shard is likely to time out again"
        )
    elif censored is None:  # recorded before plans said so
        note += (
            "; the plan does not record whether the run it is predicted from timed out: if it did, that is "
            "a lower bound and the shard is likely to time out again"
        )
    if single:
        note += "; it is one case alone, so more shards cannot help"
    note += "; a shard that fails makes the module's merged report fail, so the other shards' results are lost too"
    if censored is False:
        # A completed run's time does not depend on the limit: a higher one gives a new plan under it.
        return note + (
            f". To keep every shard under the limit, raise it (pipeline_make.py params set --module {module} "
            "--eva-timeout <s>: the plan is made again under it) or make that shard's cases cheaper"
        )
    # A timed-out run's time is floored to the limit it ran under (recorded in its report), not to the
    # module's limit now: a higher limit gives a new plan, but from the same lower bound.
    return note + (
        f". Before running eva-{module}, make that shard's cases cheaper, raise the limit (pipeline_make.py "
        f"params set --module {module} --eva-timeout <s>: the shards are planned again under it, still from "
        "the timed-out run, so their times stay lower bounds), or run the module unsharded with a longer "
        f"limit (pipeline_make.py params set --module {module} --eva-shards 1 --eva-timeout <s>)"
    )


def imputed_note(record: Any) -> str | None:
    """What to tell the user when a plan guessed the cost of cases its timed-out basis never reached."""
    basis = record.get("basis") if isinstance(record, dict) else None
    if not isinstance(basis, dict):
        return None
    cases = basis.get("imputed_cases")
    if not isinstance(cases, list) or not cases:
        return None
    each = _number(basis.get("imputed_case_s"))
    return (
        f"the timed-out run it is planned from has no sample of {'case' if len(cases) == 1 else 'cases'} "
        f"{cases} (not reached before the timeout), so their cost is unknown: each is counted at the mean "
        f"sampled case's{f' ({each} s)' if each is not None else ''}, a guess that spreads them over the shards"
    )


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
    """
    Shards differ only in their cases: the same sources, entry, checks and assumptions. The one reduced
    check a shard may add on its own is RECURSION_REDUCED_CHECK (see there); merge() unions it.
    """
    from eva_options import assumption_options

    def identity(s: Shard) -> tuple:
        r = s.run.report
        return (
            r.get("main_fn"),
            tuple(sorted(r.get("sources") or [])),
            tuple(sorted(c for c in (r.get("reduced_checks") or []) if c != RECURSION_REDUCED_CHECK)),
            tuple(sorted(assumption_options(r.get("eva_options") or {}).items())),
        )

    first = identity(shards[0])
    for s in shards[1:]:
        if identity(s) != first:
            return f"shard{s.index} is not the same analysis as shard{shards[0].index}"
    # The merged report stands for one harness (`harness_digest`): shards of different harnesses, or a
    # stamped shard beside an unstamped one, cannot be merged into it.
    harness = shards[0].run.report.get("harness_digest")
    for s in shards[1:]:
        if s.run.report.get("harness_digest") != harness:
            return (
                f"shard{s.index} was run on a different harness than shard{shards[0].index} "
                f"(harness_digest {s.run.report.get('harness_digest')!r} != {harness!r}): run the shards again"
            )
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


def _bound_flow_item(item: Any) -> Any:
    return bound_flow_location(item) if isinstance(item, str) else item


def _merge_writes(old: list[Any], new: list[Any]) -> list[Any]:
    """
    Merge per-function `writes` (`{"loc": str, "from": list[str], "and_self": bool}`) by `loc`
    rather than whole-dict equality so slight `from` variations across N shards do not multiply
    entries by N.
    """
    out: list[Any] = []
    by_loc: dict[str, dict[str, Any]] = {}
    seen_other: set[str] = set()
    for raw in [*old, *new]:
        if isinstance(raw, dict) and isinstance(raw.get("loc"), str):
            loc = bound_flow_location(raw["loc"])
            raw_from = raw.get("from") or []
            from_items = [
                bound_flow_location(x) if isinstance(x, str) else x
                for x in (raw_from if isinstance(raw_from, list) else [])
            ]
            and_self = bool(raw.get("and_self"))
            existing = by_loc.get(loc)
            if existing is None:
                dedup_from: list[Any] = []
                seen_f: set[str] = set()
                for item in from_items:
                    key = item if isinstance(item, str) else json.dumps(item, sort_keys=True)
                    if key not in seen_f:
                        seen_f.add(key)
                        dedup_from.append(item)
                rec: dict[str, Any] = {
                    **raw,
                    "loc": loc,
                    "and_self": and_self,
                    "from": dedup_from,
                }
                by_loc[loc] = rec
                out.append(rec)
            else:
                existing["and_self"] = bool(existing.get("and_self")) or and_self
                cur_from = existing.get("from")
                cur_list = list(cur_from) if isinstance(cur_from, list) else []
                seen_f = {x if isinstance(x, str) else json.dumps(x, sort_keys=True) for x in cur_list}
                for item in from_items:
                    key = item if isinstance(item, str) else json.dumps(item, sort_keys=True)
                    if key not in seen_f:
                        seen_f.add(key)
                        cur_list.append(item)
                existing["from"] = cur_list
        else:
            key = json.dumps(raw, sort_keys=True)
            if key not in seen_other:
                seen_other.add(key)
                out.append(json.loads(key))
    return out


def _dedup_flow_list(items: list[Any]) -> list[Any]:
    out: list[Any] = []
    seen: set[str] = set()
    for raw in items:
        val = _bound_flow_item(raw)
        key = val if isinstance(val, str) else json.dumps(val, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(val)
    return out


def _normalize_fn_flow(info: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in info.items():
        if name == "writes" and isinstance(value, list):
            out[name] = _merge_writes([], value)
        elif isinstance(value, list):
            out[name] = _dedup_flow_list(value)
        else:
            out[name] = json.loads(json.dumps(value))
    return out


def merge_flows(flows: list[dict]) -> dict:
    """
    Read and write sets per function, over the shards that analysed it: lists are unions (sure
    outputs an intersection), `writes` entries merge by `loc`, and `non_terminating` and
    `no_effects` hold only if they hold in every shard. Hints for prover briefs, never verdicts.
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
                by_function[fn] = _normalize_fn_flow(info)
                continue
            for name, value in info.items():
                old = mine.get(name)
                if name in _FLOW_ALL:
                    mine[name] = bool(old) and bool(value)
                elif name == "writes" and isinstance(value, list):
                    mine[name] = _merge_writes(old if isinstance(old, list) else [], value)
                elif isinstance(value, list) and isinstance(old, list):
                    norm_new = _dedup_flow_list(value)
                    if name in _FLOW_INTERSECT:
                        new_keys = {v if isinstance(v, str) else json.dumps(v, sort_keys=True) for v in norm_new}
                        mine[name] = [
                            v for v in old if (v if isinstance(v, str) else json.dumps(v, sort_keys=True)) in new_keys
                        ]
                    else:
                        seen = {v if isinstance(v, str) else json.dumps(v, sort_keys=True) for v in old}
                        mine[name] = old + [
                            v
                            for v in norm_new
                            if (v if isinstance(v, str) else json.dumps(v, sort_keys=True)) not in seen
                        ]
                elif old is None and isinstance(value, list):
                    # A shard without the list did not report it (-inout printed no such section there):
                    # sure outputs intersect over the shards that report them, so a later list is kept.
                    mine[name] = _dedup_flow_list(value)
                elif name not in mine:
                    mine[name] = json.loads(json.dumps(value))
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
            # Shards normally differ only in their case defines; when they share one input digest, it
            # is the module's (recomputable), else the combination of theirs.
            "input_digest": (
                digests[0]
                if all(digests) and len(set(digests)) == 1
                else hashlib.sha256("\n".join(digests).encode()).hexdigest()
                if all(digests)
                else None
            ),
            # Shards without the field (identity_problem: then none has it) stand for the current
            # harness only when every shard report is newer than the harness source.
            "harness_digest": base.get("harness_digest")
            or phase0_gates.derived_harness_digest(
                Path("."), module, [Path(p) for s in shards if (p := s.run.report.get("_path"))]
            ),
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
    # The shards agree on every reduced check but the recursion retry (identity_problem); the module's
    # result carries it when any shard needed it, so the ledger keeps the caveat.
    report["reduced_checks"] = _union(s.run.report.get("reduced_checks") for s in shards)
    report.pop("auto_recursion_fallback", None)
    retried = [s.index for s in shards if s.run.report.get("auto_recursion_fallback")]
    if retried:
        report["auto_recursion_fallback"] = True
        report["auto_recursion_fallback_shards"] = retried
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
    if isinstance(data.get("flows"), dict) and "flows_file" in data["flows"]:
        resolved = resolve_flows(data["flows"], report_path=path, max_bytes=_MAX_REPORT_BYTES)
        if isinstance(resolved, dict):
            data["flows"] = resolved
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
    flows_dir = args.csv_out.parent
    if flows_dir.resolve() == args.out_json.parent.resolve():
        flows_dir = args.shard_dir
    disk_report = spill_large_flows(report, flows_dir / "flows.json", report_path=args.out_json)
    atomic_write_json(args.out_json, disk_report)
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
