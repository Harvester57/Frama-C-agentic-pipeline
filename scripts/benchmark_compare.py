#!/usr/bin/env python3
"""
Compares two benchmark runs (the JSON files scripts/benchmark.py writes) and classifies every
difference. Stdlib only, no tool dependency: this is the part that decides whether a change to the
pipeline's filters, Eva configuration or briefs helped, so it is unit-tested on its own.

Severities, most serious first:
  regression    the change made something worse. Fails the comparison (exit code 1).
  warning       a human must look: the numbers moved in a way that may hide a loss.
  improvement   better, and nothing suggests the gain is an artifact.
  changed       different, and neither better nor worse by itself.
  info          context (toolchain, machine, unseeded fuzzing, timings within tolerance).
  not_compared  one side has no data. Never read as a pass or as a loss.

Rules that are easy to get wrong, and why they are here:
  - Recall is the primary signal. A bug that is not retained fails the run even if the baseline
    had already lost it, and a build failure or timeout on a recall bug counts as not retained.
  - A bug that was not selected is `not_compared`, never lost.
  - Fewer Unknowns is an improvement only if nothing else explains it: the same analysis must have
    checked at least as many properties and statements, with no extra Dead code, no extra
    "Considered valid" assumptions and no weaker checks. Otherwise it is a warning.
  - Eva and DAG counts are deterministic, so their tolerance is zero. Timings are not, so they
    only warn beyond a tolerance, and only inform when the machine differs.
  - Fuzz campaigns are not seeded: what they find is reported, never scored.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
SEVERITIES = ("regression", "warning", "improvement", "changed", "info", "not_compared")
FAILING_BY_LEVEL = {"regression": ("regression",), "warning": ("regression", "warning")}

# Fields of an Eva module block that only inform (their effect shows in the counts).
_EVA_COUNTS = ("valid", "unknown", "invalid", "dead", "assumed", "total")


class IncomparableError(ValueError):
    """The two files cannot be compared at all (not benchmark runs, or another schema version)."""


@dataclass
class Tolerances:
    time_ratio: float = 1.5
    time_min_delta_s: float = 60.0


@dataclass
class Diff:
    severity: str
    area: str
    subject: str
    message: str
    primary: bool = False


@dataclass
class Comparison:
    diffs: list[Diff] = field(default_factory=list)

    def add(self, severity: str, area: str, subject: str, message: str, primary: bool = False) -> None:
        if severity not in SEVERITIES:
            raise ValueError(f"unknown severity {severity!r}")
        self.diffs.append(Diff(severity, area, subject, message, primary))

    def count(self, severity: str) -> int:
        return sum(1 for d in self.diffs if d.severity == severity)

    def failed(self, fail_on: str = "regression") -> bool:
        return any(d.severity in FAILING_BY_LEVEL[fail_on] for d in self.diffs)

    def to_json(self) -> dict:
        return {
            "counts": {s: self.count(s) for s in SEVERITIES},
            "recall_regression": any(d.primary for d in self.diffs),
            "diffs": [asdict(d) for d in self.diffs],
        }


def rate_block(passed: int, failed: int, undecided: int) -> dict:
    """
    One success rate, two ways: `over_decided` ignores what no tool decided; `strict` counts every
    timeout or tool failure as a failure. None, not 0, when there is nothing to divide by.
    """
    decided = passed + failed
    total = decided + undecided
    return {
        "passed": passed,
        "failed": failed,
        "undecided": undecided,
        "over_decided": round(passed / decided, 4) if decided else None,
        "strict": round(passed / total, 4) if total else None,
    }


def _check_run(run: Any, label: str) -> None:
    if not isinstance(run, dict) or "schema_version" not in run or "targets" not in run:
        raise IncomparableError(f"{label} is not a benchmark run file")
    if run["schema_version"] != SCHEMA_VERSION:
        raise IncomparableError(f"{label} has schema version {run['schema_version']}, expected {SCHEMA_VERSION}")


def _fmt_delta(base: int | float, cur: int | float) -> str:
    delta = cur - base
    return f"{base} -> {cur} ({delta:+g})"


# ---------------------------------------------------------------------------
# Recall (the primary signal)
# ---------------------------------------------------------------------------


def _compare_recall(base: dict, cur: dict, out: Comparison, require_all: bool) -> None:
    base_bugs = (base.get("recall") or {}).get("bugs") or {}
    cur_bugs = (cur.get("recall") or {}).get("bugs") or {}
    for bug_id in sorted(set(base_bugs) | set(cur_bugs)):
        was = (base_bugs.get(bug_id) or {}).get("status", "not_run")
        entry = cur_bugs.get(bug_id) or {}
        now = entry.get("status", "not_run")
        reason = entry.get("reason")
        detail = f" ({reason})" if reason else ""
        if now == "not_run":
            if require_all:
                out.add("regression", "recall", bug_id, f"not run, but every bug is required (baseline: {was})", True)
            else:
                out.add("not_compared", "recall", bug_id, f"not run in this selection (baseline: {was})")
        elif now == "retained":
            if was == "retained":
                _compare_bug_identity(bug_id, base_bugs[bug_id], entry, out)
            elif was == "not_run":
                out.add("changed", "recall", bug_id, "retained; not in the baseline")
            else:
                out.add("improvement", "recall", bug_id, f"retained again (baseline: {was})")
        elif now == "undecided":
            out.add("regression", "recall", bug_id, f"no decision, counted as lost{detail} (baseline: {was})", True)
        elif was == "retained":
            out.add("regression", "recall", bug_id, f"LOST{detail}", True)
        else:
            out.add("regression", "recall", bug_id, f"still not retained{detail} (baseline: {was})", True)


def _replay_key(replay: dict) -> tuple:
    return (replay.get("target"), replay.get("module"), replay.get("engine"))


def _compare_bug_identity(bug_id: str, base_entry: dict, cur_entry: dict, out: Comparison) -> None:
    """Both retained: the fingerprint is what verdicts and the ledger are keyed by, so a change matters."""
    base_replays = {_replay_key(r): r for r in base_entry.get("replays") or []}
    for replay in cur_entry.get("replays") or []:
        key = _replay_key(replay)
        before = base_replays.get(key)
        if before is None:
            continue
        where = "/".join(str(k) for k in key)
        old_fp = (before.get("observed") or {}).get("fingerprint")
        new_fp = (replay.get("observed") or {}).get("fingerprint")
        if old_fp and new_fp and old_fp != new_fp:
            out.add("warning", "recall", bug_id, f"{where}: fingerprint changed: {old_fp} -> {new_fp}")
        old_site, new_site = before.get("eva_site"), replay.get("eva_site")
        if old_site in ("unknown", "invalid") and new_site not in ("unknown", "invalid", None):
            # A real bug is at this line: Eva must not call it clean, whatever the alarm counts did.
            out.add(
                "warning", "recall", bug_id, f"{where}: Eva no longer flags the bug's site ({old_site} -> {new_site})"
            )
        if replay.get("required"):
            continue
        # Engines that did not confirm the bug: their results are a signal, not a condition.
        if before.get("outcome") != replay.get("outcome"):
            out.add(
                "warning",
                "recall",
                bug_id,
                f"{where} (informational engine): {before.get('outcome')} -> {replay.get('outcome')}",
            )


# ---------------------------------------------------------------------------
# Eva, per module
# ---------------------------------------------------------------------------


def _coverage_fell(base: dict, cur: dict) -> list[str]:
    """Reasons a lower Unknown count may be an artifact rather than a gain (empty: none found)."""
    reasons = []
    if cur.get("total", 0) < base.get("total", 0):
        reasons.append(f"properties checked fell {_fmt_delta(base.get('total', 0), cur.get('total', 0))}")
    if cur.get("dead", 0) > base.get("dead", 0):
        reasons.append(f"Dead rose {_fmt_delta(base.get('dead', 0), cur.get('dead', 0))}")
    if cur.get("assumed", 0) > base.get("assumed", 0):
        reasons.append(f"Considered valid rose {_fmt_delta(base.get('assumed', 0), cur.get('assumed', 0))}")
    weaker = sorted(set(cur.get("reduced_checks") or []) - set(base.get("reduced_checks") or []))
    if weaker:
        reasons.append("checks weakened: " + ", ".join(weaker))
    base_cov, cur_cov = base.get("coverage") or {}, cur.get("coverage") or {}
    for key, label in (("functions_analyzed", "functions analyzed"), ("statements_reached", "statements reached")):
        if isinstance(base_cov.get(key), int) and isinstance(cur_cov.get(key), int) and cur_cov[key] < base_cov[key]:
            reasons.append(f"{label} fell {_fmt_delta(base_cov[key], cur_cov[key])}")
    return reasons


def _compare_eva_module(subject: str, base: dict, cur: dict, out: Comparison) -> None:
    was, now = base.get("status"), cur.get("status")
    if was != now:
        if now == "ok":
            out.add("improvement", "eva", subject, f"analysis now completes (was {was})")
        elif was == "ok":
            out.add(
                "regression",
                "eva",
                subject,
                f"analysis no longer completes: {now} ({cur.get('reason') or 'no reason'})",
            )
        else:
            out.add("changed", "eva", subject, f"analysis still does not complete: {was} -> {now}")
    if was != "ok" or now != "ok":
        if was == now:
            out.add("warning", "eva", subject, f"analysis did not complete in either run ({now})")
        return

    reasons = _coverage_fell(base, cur)
    du = cur.get("unknown", 0) - base.get("unknown", 0)
    if du < 0:
        message = f"Unknown {_fmt_delta(base.get('unknown', 0), cur.get('unknown', 0))}"
        if reasons:
            out.add("warning", "eva", subject, f"{message}, but not a clear gain: {'; '.join(reasons)}")
        else:
            out.add("improvement", "eva", subject, message)
    elif du > 0:
        message = f"Unknown {_fmt_delta(base.get('unknown', 0), cur.get('unknown', 0))}"
        grew = cur.get("total", 0) - base.get("total", 0)
        if grew >= du and not reasons:
            out.add("changed", "eva", subject, f"{message} with {grew:+d} properties checked (more code analyzed)")
        else:
            out.add("regression", "eva", subject, message)
    elif reasons:
        out.add("warning", "eva", subject, "; ".join(reasons))
    elif any(cur.get(k, 0) != base.get(k, 0) for k in _EVA_COUNTS):
        changes = [
            f"{k} {_fmt_delta(base.get(k, 0), cur.get(k, 0))}" for k in _EVA_COUNTS if cur.get(k, 0) != base.get(k, 0)
        ]
        out.add("changed", "eva", subject, ", ".join(changes))

    gone = sorted(set(base.get("invalid_ids") or []) - set(cur.get("invalid_ids") or []))
    new = sorted(set(cur.get("invalid_ids") or []) - set(base.get("invalid_ids") or []))
    if gone:
        out.add(
            "warning",
            "eva",
            subject,
            "Invalid alarm(s) no longer reported, check none was a real bug: " + ", ".join(gone),
        )
    if new:
        out.add("warning", "eva", subject, "new Invalid alarm(s), each one is a candidate to verify: " + ", ".join(new))
    new_undeclared = sorted(set(cur.get("undeclared_functions") or []) - set(base.get("undeclared_functions") or []))
    if new_undeclared:
        out.add("warning", "eva", subject, "functions without a prototype: " + ", ".join(new_undeclared))


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


def _compare_functions_with_unknown(tid: str, base: dict, cur: dict, out: Comparison, suspect: bool) -> None:
    """Each function with an Unknown costs a prover task, so this outranks the raw alarm count."""
    before, after = set(base.get("functions_with_unknown") or []), set(cur.get("functions_with_unknown") or [])
    added, removed = sorted(after - before), sorted(before - after)
    if not added and not removed:
        return
    counts = f"{len(before)} -> {len(after)}"
    detail = "; ".join(
        p
        for p in (f"added {', '.join(added)}" if added else "", f"removed {', '.join(removed)}" if removed else "")
        if p
    )
    if added and not removed:
        # More code reached legitimately raises this; the module rule above already judged the counts.
        severity = "changed" if _more_properties_checked(base, cur) else "regression"
    elif removed and not added:
        severity = "warning" if suspect else "improvement"
    else:
        severity = "changed"
    out.add(severity, "prover_tasks", tid, f"functions with an Unknown {counts}: {detail}")


def _compare_unit_gaps(tid: str, base: dict, cur: dict, out: Comparison) -> None:
    """A function with an Unknown and no ledger unit gets no prover: its Unknowns would silently stay open."""
    before = set(base.get("functions_with_unknown_no_unit") or [])
    after = set(cur.get("functions_with_unknown_no_unit") or [])
    if after - before:
        out.add(
            "warning",
            "prover_tasks",
            tid,
            "new functions with an Unknown but no ledger unit: " + ", ".join(sorted(after - before)),
        )
    if before - after:
        out.add(
            "improvement",
            "prover_tasks",
            tid,
            f"{len(before - after)} function(s) with an Unknown now have a ledger unit",
        )
    # A unit covered while an Eva run leaves an Unknown in its function claims more than Eva showed.
    before = set(base.get("covered_with_unknown") or [])
    after = set(cur.get("covered_with_unknown") or [])
    if after - before:
        out.add(
            "regression",
            "units",
            tid,
            "covered although an Eva run leaves an Unknown in them: " + ", ".join(sorted(after - before)),
        )
    if before - after:
        out.add("improvement", "units", tid, f"{len(before - after)} unit(s) no longer covered over an Unknown")


def _module_total(target: dict) -> int:
    return sum(
        int((mod.get("eva") or {}).get("total") or 0)
        for mod in (target.get("modules") or {}).values()
        if (mod.get("eva") or {}).get("status") == "ok"
    )


def _more_properties_checked(base: dict, cur: dict) -> bool:
    return _module_total(cur) > _module_total(base)


def _compare_units(tid: str, base: dict, cur: dict, out: Comparison, suspect: bool) -> None:
    base_units, cur_units = base.get("units") or {}, cur.get("units") or {}
    before, after = set(base_units.get("covered") or []), set(cur_units.get("covered") or [])
    candidates = set(cur_units.get("candidate") or [])
    lost = sorted(before - after)
    gained = sorted(after - before)
    proof_lost = [u for u in lost if u not in candidates]
    flagged = [u for u in lost if u in candidates]
    if proof_lost:
        out.add("regression", "units", tid, "covered units lost: " + ", ".join(proof_lost))
    if flagged:
        # A crash the unseeded campaign happened to find this time, not a weaker proof.
        out.add("warning", "units", tid, "covered in the baseline, now a candidate: " + ", ".join(flagged))
    if gained:
        severity = "warning" if suspect else "improvement"
        out.add(severity, "units", tid, "newly covered units: " + ", ".join(gained))

    base_waves, cur_waves = base_units.get("by_wave") or {}, cur_units.get("by_wave") or {}
    for wave in sorted(set(base_waves) | set(cur_waves), key=_wave_order):
        old, new = base_waves.get(wave), cur_waves.get(wave)
        if old is None or new is None:
            out.add(
                "changed",
                "units",
                f"{tid} wave {wave}",
                "wave only in the " + ("current run" if old is None else "baseline"),
            )
        elif old != new:
            out.add(
                "info",
                "units",
                f"{tid} wave {wave}",
                f"strict rate {_rate(old)} -> {_rate(new)} (proved {old.get('passed')} -> {new.get('passed')})",
            )


def _wave_order(wave: str) -> tuple[int, str]:
    return (int(wave), "") if str(wave).isdigit() else (1 << 30, str(wave))


def _rate(block: dict) -> str:
    value = block.get("strict")
    return "n/a" if value is None else f"{100 * value:.1f}%"


def _compare_tooling(tid: str, base: dict, cur: dict, out: Comparison, fuzz_comparable: bool = True) -> None:
    base_mods, cur_mods = base.get("modules") or {}, cur.get("modules") or {}
    for name in sorted(set(base_mods) | set(cur_mods)):
        subject = f"{tid}/{name}"
        old, new = base_mods.get(name), cur_mods.get(name)
        if old is None or new is None:
            out.add(
                "warning", "modules", subject, "module only in the " + ("current run" if old is None else "baseline")
            )
            continue
        old_build, new_build = old.get("build") or {}, new.get("build") or {}
        if old_build.get("status") == "built" and new_build.get("status") not in ("built", None):
            out.add("regression", "build", subject, f"fuzz binary no longer builds: {new_build.get('status')}")
        if old_build.get("engine") and new_build.get("engine") and old_build["engine"] != new_build["engine"]:
            out.add("warning", "build", subject, f"engine changed: {old_build['engine']} -> {new_build['engine']}")
        weaker = sorted(set(new_build.get("reduced_checks") or []) - set(old_build.get("reduced_checks") or []))
        if weaker:
            out.add("warning", "build", subject, "runtime checks weakened: " + ", ".join(weaker))
        old_fuzz, new_fuzz = (old.get("fuzz") or {}, new.get("fuzz") or {}) if fuzz_comparable else ({}, {})
        if _fuzz_ran(old_fuzz) and new_fuzz.get("status") == "fuzzer_error":
            # Campaigns are unseeded, so this may not repeat, but it may also be a crash nobody can replay.
            out.add("warning", "fuzz", subject, "campaign aborted without leaving a crash input")
        elif _fuzz_ran(old_fuzz) and new_fuzz and not _fuzz_ran(new_fuzz):
            out.add("regression", "fuzz", subject, f"campaign no longer runs: {new_fuzz.get('status')}")
        elif old_fuzz.get("status") != new_fuzz.get("status") and new_fuzz:
            out.add(
                "info", "fuzz", subject, f"{old_fuzz.get('status')} -> {new_fuzz.get('status')} (unseeded, not scored)"
            )
        if old.get("eva") and new.get("eva"):
            _compare_eva_module(subject, old["eva"], new["eva"], out)
        elif old.get("eva") or new.get("eva"):
            out.add("not_compared", "eva", subject, "Eva ran on one side only")


def _fuzz_ran(block: dict) -> bool:
    return block.get("status") in ("clean", "crash_found", "timeout_found", "oom_found")


def _target_suspect(base: dict, cur: dict) -> bool:
    """True when any module lost coverage, so gains at the target level need a human look."""
    base_mods, cur_mods = base.get("modules") or {}, cur.get("modules") or {}
    for name in set(base_mods) & set(cur_mods):
        old, new = base_mods[name].get("eva") or {}, cur_mods[name].get("eva") or {}
        if old.get("status") == "ok" and new.get("status") == "ok" and _coverage_fell(old, new):
            return True
    return False


def _compare_candidates(tid: str, base: dict, cur: dict, out: Comparison) -> None:
    base_fps = (base.get("candidates") or {}).get("fingerprints") or {}
    cur_fps = (cur.get("candidates") or {}).get("fingerprints") or {}
    for source in sorted(set(base_fps) | set(cur_fps)):
        before, after = set(base_fps.get(source) or []), set(cur_fps.get(source) or [])
        added, removed = sorted(after - before), sorted(before - after)
        if not added and not removed:
            continue
        message = f"{source} candidates {len(before)} -> {len(after)}"
        if added:
            message += "; new: " + ", ".join(added)
        if removed:
            message += "; gone: " + ", ".join(removed)
        # Only the static source is deterministic; campaigns are unseeded.
        out.add("warning" if source == "eva" else "info", "candidates", tid, message)
    old_open, new_open = (
        (base.get("candidates") or {}).get("unverified"),
        (cur.get("candidates") or {}).get("unverified"),
    )
    if isinstance(old_open, int) and isinstance(new_open, int) and old_open != new_open:
        out.add("info", "candidates", tid, f"candidates awaiting a verifier agent {_fmt_delta(old_open, new_open)}")


def _compare_api_reach(tid: str, base: dict, cur: dict, out: Comparison) -> None:
    """
    API entry points the harnesses reach (the reach gate's count, before exemptions). Fewer is a
    regression even when the gate passes: an exemption accepts a gap, it does not fuzz the function.
    """
    old, new = base.get("api_reach"), cur.get("api_reach")
    if not isinstance(new, dict):
        return
    if not isinstance(old, dict):
        out.add(
            "not_compared",
            "api_reach",
            tid,
            f"not in the baseline; now {new.get('reached')}/{new.get('entry_points')} entry points reached",
        )
        return
    was, now = old.get("reached"), new.get("reached")
    total = f"{old.get('entry_points')} -> {new.get('entry_points')}"
    if isinstance(was, int) and isinstance(now, int) and was != now:
        severity = "regression" if now < was else "improvement"
        out.add(severity, "api_reach", tid, f"API entry points reached {_fmt_delta(was, now)} (of {total})")
    if old.get("exempt") != new.get("exempt"):
        out.add("info", "api_reach", tid, f"entry points exempted {old.get('exempt')} -> {new.get('exempt')}")
    old_seeds, new_seeds = old.get("seeds"), new.get("seeds")
    if isinstance(old_seeds, int) and isinstance(new_seeds, int) and old_seeds != new_seeds:
        out.add("info", "api_reach", tid, f"seed inputs {_fmt_delta(old_seeds, new_seeds)}")


def _compare_time(tid: str, base: dict, cur: dict, out: Comparison, tol: Tolerances, same_machine: bool) -> None:
    for key, label in (("wall_s", "wall-clock"), ("cpu_s", "CPU")):
        old, new = base.get(key), cur.get(key)
        if not isinstance(old, (int, float)) or not isinstance(new, (int, float)) or old <= 0:
            continue
        ratio = new / old
        message = f"{label} {old:.1f}s -> {new:.1f}s (x{ratio:.2f})"
        slower = ratio > tol.time_ratio and new - old > tol.time_min_delta_s
        if slower and same_machine:
            out.add("warning", "time", tid, message)
        elif ratio != 1.0 and (slower or ratio < 1 / tol.time_ratio):
            out.add("info", "time", tid, message + ("" if same_machine else ", machines differ"))


def _compare_target(
    tid: str, base: dict, cur: dict, out: Comparison, tol: Tolerances, same_machine: bool, fuzz_comparable: bool = True
) -> None:
    if base.get("revision") != cur.get("revision"):
        out.add("not_compared", "target", tid, f"revision differs: {base.get('revision')} vs {cur.get('revision')}")
        return
    if base.get("harness_digest") != cur.get("harness_digest"):
        out.add("warning", "target", tid, "harness, scope or tuning changed: the counts below are not like for like")
    was, now = base.get("status"), cur.get("status")
    if was != now:
        severity = "regression" if was == "ok" else ("improvement" if now == "ok" else "changed")
        out.add(
            severity, "target", tid, f"status {was} -> {now}: {'; '.join(cur.get('problems') or []) or 'no detail'}"
        )
    base_dag, cur_dag = base.get("dag") or {}, cur.get("dag") or {}
    for key in ("functions", "waves", "name_collisions", "recursion_cycles"):
        if base_dag.get(key) != cur_dag.get(key):
            out.add("warning", "dag", tid, f"{key} {base_dag.get(key)} -> {cur_dag.get(key)}")
    _compare_tooling(tid, base, cur, out, fuzz_comparable)
    suspect = _target_suspect(base, cur)
    _compare_functions_with_unknown(tid, base, cur, out, suspect)
    _compare_unit_gaps(tid, base, cur, out)
    old_tasks, new_tasks = (base.get("prover_tasks") or {}).get("count"), (cur.get("prover_tasks") or {}).get("count")
    if isinstance(old_tasks, int) and isinstance(new_tasks, int) and old_tasks != new_tasks:
        out.add("info", "prover_tasks", tid, f"queued prover tasks {_fmt_delta(old_tasks, new_tasks)}")
    _compare_units(tid, base, cur, out, suspect)
    _compare_api_reach(tid, base, cur, out)
    _compare_candidates(tid, base, cur, out)
    if fuzz_comparable:
        _compare_time(tid, base, cur, out, tol, same_machine)
    else:
        out.add("not_compared", "time", tid, "one run skipped the fuzz campaigns")
    _compare_phase3(tid, base, cur, out)


def _compare_phase3(tid: str, base: dict, cur: dict, out: Comparison) -> None:
    old, new = base.get("phase3"), cur.get("phase3")
    if not old and not new:
        return
    if not old or not new:
        out.add("not_compared", "phase3", tid, "LLM phase measured on one side only")
        return
    old_rate, new_rate = old.get("function_rate") or {}, new.get("function_rate") or {}
    if old_rate != new_rate:
        out.add(
            "changed",
            "phase3",
            tid,
            f"functions proved, strict {_rate(old_rate)} -> {_rate(new_rate)}, over decided {old_rate.get('over_decided')} -> {new_rate.get('over_decided')}",
        )
    if old.get("stalls") != new.get("stalls"):
        out.add("info", "phase3", tid, f"stalls {old.get('stalls')} -> {new.get('stalls')}")
    old_tokens, new_tokens = old.get("tokens"), new.get("tokens")
    if old_tokens != new_tokens:
        out.add("info", "phase3", tid, f"tokens {old_tokens} -> {new_tokens}")


def _compare_header(base: dict, cur: dict, out: Comparison) -> None:
    base_tools, cur_tools = base.get("toolchain") or {}, cur.get("toolchain") or {}
    for tool in sorted(set(base_tools) | set(cur_tools)):
        if base_tools.get(tool) != cur_tools.get(tool):
            out.add("info", "toolchain", tool, f"{base_tools.get(tool)} -> {cur_tools.get(tool)}")
    base_limits, cur_limits = base.get("limits") or {}, cur.get("limits") or {}
    for limit in sorted(set(base_limits) | set(cur_limits)):
        if base_limits.get(limit) != cur_limits.get(limit):
            # These limits decide results: a change here invalidates like-for-like counts.
            out.add(
                "warning",
                "limits",
                limit,
                f"result-deciding limit changed: {base_limits.get(limit)} -> {cur_limits.get(limit)}",
            )
    if (base.get("pipeline") or {}).get("content_digest") == (cur.get("pipeline") or {}).get("content_digest"):
        out.add("info", "pipeline", "content", "same scripts, templates, schemas and skills as the baseline")
    if base.get("machine") != cur.get("machine"):
        out.add("info", "machine", "size", f"{base.get('machine')} -> {cur.get('machine')}")


def _compare_briefs(base: dict, cur: dict, out: Comparison) -> None:
    old, new = base.get("briefs"), cur.get("briefs")
    if not old and not new:
        return
    if not old or not new:
        out.add("not_compared", "briefs", "control", "control arm ran on one side only")
        return
    old_samples, new_samples = old.get("samples") or {}, new.get("samples") or {}
    for sid in sorted(set(old_samples) & set(new_samples)):
        was, now = old_samples[sid].get("outcome"), new_samples[sid].get("outcome")
        if was != now:
            severity = "regression" if was == "proved" else ("improvement" if now == "proved" else "changed")
            out.add(severity, "briefs", sid, f"control arm {was} -> {now}")
    missing = sorted(set(old_samples) - set(new_samples))
    if missing:
        out.add("not_compared", "briefs", "control", f"{len(missing)} sample(s) not run")


def compare_runs(base: dict, cur: dict, tol: Tolerances | None = None, require_all: bool = False) -> Comparison:
    """Classify every difference between a baseline run and a current run (see the module docstring)."""
    _check_run(base, "the baseline")
    _check_run(cur, "the current run")
    tol = tol or Tolerances()
    out = Comparison()
    _compare_recall(base, cur, out, require_all)
    _compare_header(base, cur, out)
    same_machine = base.get("machine") == cur.get("machine")
    # `run --no-fuzz` is a narrower selection: no campaign is not a campaign that stopped working.
    base_fuzz, cur_fuzz = (
        (base.get("selection") or {}).get("fuzz", True),
        (cur.get("selection") or {}).get("fuzz", True),
    )
    fuzz_comparable = base_fuzz == cur_fuzz
    base_targets, cur_targets = base.get("targets") or {}, cur.get("targets") or {}
    for tid in sorted(set(base_targets) | set(cur_targets)):
        if tid not in cur_targets:
            out.add("not_compared", "target", tid, "not run in this selection")
        elif tid not in base_targets:
            out.add("not_compared", "target", tid, "not in the baseline")
        else:
            _compare_target(tid, base_targets[tid], cur_targets[tid], out, tol, same_machine, fuzz_comparable)
    _compare_briefs(base, cur, out)
    return out


def render_text(result: Comparison, verbose: bool = False) -> str:
    """The differences for a terminal, worst first; recall regressions always come first."""
    lines: list[str] = []
    primary = [d for d in result.diffs if d.primary]
    if primary:
        lines.append("RECALL REGRESSION (primary failure signal):")
        lines.extend(f"  {d.subject}: {d.message}" for d in primary)
        lines.append("")
    for severity in SEVERITIES:
        if severity in ("info", "not_compared") and not verbose:
            continue
        rows = [d for d in result.diffs if d.severity == severity and not d.primary]
        if not rows:
            continue
        lines.append(f"{severity.upper()} ({len(rows)}):")
        lines.extend(f"  [{d.area}] {d.subject}: {d.message}" for d in rows)
        lines.append("")
    summary = ", ".join(f"{result.count(s)} {s}" for s in SEVERITIES)
    lines.append(f"Summary: {summary}")
    if not verbose and (result.count("info") or result.count("not_compared")):
        lines.append("(info and not_compared rows are hidden; pass --verbose to see them)")
    return "\n".join(lines)


def load_run(path: Path | str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two benchmark runs and print the differences.")
    parser.add_argument("baseline", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--require-all", action="store_true", help="A bug that was not run counts as lost")
    parser.add_argument("--fail-on", choices=sorted(FAILING_BY_LEVEL), default="regression")
    parser.add_argument("--json", type=Path, default=None, help="Also write the differences to this file")
    parser.add_argument("--verbose", action="store_true", help="Also print info and not_compared rows")
    args = parser.parse_args(argv)
    try:
        result = compare_runs(load_run(args.baseline), load_run(args.current), require_all=args.require_all)
    except (OSError, ValueError) as exc:  # IncomparableError and malformed JSON are ValueErrors
        print(f"cannot compare: {exc}", file=sys.stderr)
        return 2
    print(render_text(result, verbose=args.verbose))
    if args.json:
        args.json.write_text(json.dumps(result.to_json(), indent=2) + "\n", encoding="utf-8")
    return 1 if result.failed(args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
