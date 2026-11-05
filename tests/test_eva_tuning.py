"""Tests for Eva tuning: the option allowlist, the guards, selection, combination and per-loop analysis."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

import eva_loops
import eva_options as eo
import eva_tuning as et
import ledger as L
import pipeline_make as pm
import run_eva_slice
from conftest import unit, write_json
from eva_loops import LoopRef
from framac_common import STATUS_DEAD, STATUS_INVALID, STATUS_UNKNOWN, STATUS_VALID
from test_pipeline_make import _make_run

REPO = Path(__file__).resolve().parent.parent
ACSL = "/opt/framac-pipeline/templates"
COMPLETE_LOG = """\
[eva:final-states] Values at end of function parse:
  n IN {0}
[eva:final-states] Values at end of function eva_main:
  __retres IN {0}
[eva:summary] ====== ANALYSIS SUMMARY ======
  7 functions analyzed (out of 9): 77% coverage.
  In these functions, 200 statements reached (out of 220): 90% coverage.
[metrics:eva:coverage]
  Coverage estimation = 80.0%
"""


def log(functions: int = 7, statements: int = 200, coverage: float = 80.0, extra: str = "") -> str:
    return (
        COMPLETE_LOG.replace("7 functions", f"{functions} functions")
        .replace("200 statements", f"{statements} statements")
        .replace("80.0%", f"{coverage}%")
        + extra
    )


def row(line: int, status: str = STATUS_UNKNOWN, function: str = "parse", predicate: str = "p", file: str = "a.c"):
    return {
        "directory": "workspace/work",
        "file": file,
        "function": function,
        "line": line,
        "kind": "mem_access",
        "status": status,
        "status_raw": status,
        "property": predicate,
    }


def run_of(name: str, rows: list[dict], *, log_text: str | None = None, **report) -> et.EvaRun:
    full = {
        "status": "ok",
        "input_digest": "same",
        "main_fn": "eva_main",
        "sources": ["a.c"],
        "reduced_checks": [],
        "eva_options": {},
        "valid_count": sum(r["status"] == STATUS_VALID for r in rows),
        "dead_count": sum(r["status"] == STATUS_DEAD for r in rows),
        "invalid_count": sum(r["status"] == STATUS_INVALID for r in rows),
        **report,
    }
    return et.EvaRun(name, full, rows=rows, log_text=log() if log_text is None else log_text, entry_fn="parse")


# ---------------------------------------------------------------------------
# The option allowlist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("min-loop-unroll=8", ("min-loop-unroll", 8)),
        ("auto-loop-unroll=1024", ("auto-loop-unroll", 1024)),
        ("widening-delay=6", ("widening-delay", 6)),
        ("partition-history=1", ("partition-history", 1)),
        ("slevel=1000", ("slevel", 1000)),
        ("ilevel=64", ("ilevel", 64)),
        ("plevel=1000", ("plevel", 1000)),
        ("subdivide-non-linear=100", ("subdivide-non-linear", 100)),
        ("split-return=auto", ("split-return", "auto")),
        ("split-return=full", ("split-return", "full")),
        ("split-return=-1", ("split-return", -1)),
        ("remove-redundant-alarms=false", ("remove-redundant-alarms", False)),
        ("octagon-through-calls=true", ("octagon-through-calls", True)),
        ("equality-through-calls=formals", ("equality-through-calls", "formals")),
        ("context-depth=4", ("context-depth", 4)),
        ("precision=8", ("precision", 8)),
        ("domains=multidim", ("domains", ["multidim"])),
    ],
)
def test_every_allowlisted_option_parses(text, expected):
    assert eo.parse_option(text) == expected
    name, value = expected
    assert eo.parse_option(eo.format_option(name, value)) == expected


@pytest.mark.parametrize(
    "text",
    [
        # Nothing that turns a check off or changes what is analysed gets in, however it is spelled.
        "use-spec=f",
        "no-warn-invalid-pointer=true",
        "warn-key=*=inactive",
        "stop-at-nth-alarm=1",
        "no-results=true",
        "domains=taint",
        "domains=cvalue",
        "domains=multidim,multidim",
        # Values are typed, never raw tokens.
        "slevel=1 -load evil.so",
        "slevel=-1",
        "slevel=1000001",
        "precision=12",
        "ilevel=1",
        "widening-delay=0",
        "context-depth=1",
        "split-return=-eva-use-spec",
        "equality-through-calls=everything",
        "remove-redundant-alarms=maybe",
        "slevel",
    ],
)
def test_options_outside_the_table_are_refused(text):
    with pytest.raises(ValueError):
        eo.parse_option(text)


def test_context_depth_is_the_only_option_that_is_not_tuning():
    assert [name for name, spec in eo.EVA_OPTIONS.items() if spec.correctness] == ["context-depth"]
    for rung in eo.LADDER:
        assert not eo.assumption_options(rung.options), rung.name


def test_framac_args_are_stable_and_spell_booleans_as_their_flags():
    options = {"split-return": "auto", "remove-redundant-alarms": False, "octagon-through-calls": True, "ilevel": 64}
    assert eo.framac_args(options) == [
        "-eva-ilevel",
        "64",
        "-eva-octagon-through-calls",
        "-eva-no-remove-redundant-alarms",
        "-eva-split-return",
        "auto",
    ]
    assert eo.framac_args({"domains": ["multidim"]}) == []


def test_a_rung_refines_the_module_settings_and_never_lowers_them():
    merged = eo.merge_options({"slevel": 5000, "ilevel": 16, "domains": ["multidim"]}, {"slevel": 1000, "ilevel": 64})
    assert merged == {"slevel": 5000, "ilevel": 64, "domains": ["multidim"]}


def _extends(later: dict, earlier: dict) -> bool:
    """Whether `later` asks for at least everything `earlier` does: the two would simply be nested."""
    for name, value in earlier.items():
        if name not in later:
            return False
        if eo.EVA_OPTIONS[name].kind == "int" and later[name] < value:
            return False
        if eo.EVA_OPTIONS[name].kind != "int" and later[name] != value:
            return False
    return True


def test_the_ladder_is_not_nested():
    rungs = {rung.name: dict(rung.options) for rung in eo.LADDER}
    assert len(eo.RUNG_NAMES) == len(rungs)
    composite = eo.RUNG_NAMES[-1]
    for name, options in rungs.items():
        for other, other_options in rungs.items():
            if name != other and other != composite:
                assert not _extends(other_options, options), f"{other} simply extends {name}"
    # PARF: history hurts on some programs even with a high slevel, so it never rides along with the top one.
    with_history = [name for name, options in rungs.items() if "partition-history" in options]
    assert with_history == ["history"]
    assert rungs["slevel"]["slevel"] > rungs["history"]["slevel"]


def test_eva_command_carries_options_and_keeps_every_check():
    plain, _ = run_eva_slice._eva_command(
        ["a.c"], "eva_main", Path("out"), "gcc_x86_64", "-I.", 100, True, True, True, ""
    )
    tuned, reduced = run_eva_slice._eva_command(
        ["a.c"],
        "eva_main",
        Path("out"),
        "gcc_x86_64",
        "-I.",
        100,
        True,
        True,
        True,
        "",
        eva_options={"slevel": 1000, "auto-loop-unroll": 1024, "domains": ["multidim"], "partition-history": 1},
    )
    assert reduced == []
    assert tuned[tuned.index("-eva-slevel") + 1] == "1000" and tuned[tuned.index("-eva-auto-loop-unroll") + 1] == "1024"
    assert tuned[tuned.index("-eva-domains") + 1].endswith(",multidim")
    assert tuned[tuned.index("-eva-partition-history") + 1] == "1"
    # What is checked stays the same: only tuning differs between the two command lines.
    assert [t for t in plain if t.startswith("-warn") or t == "-rte"] == [
        t for t in tuned if t.startswith("-warn") or t == "-rte"
    ]
    assert plain[plain.index("-eva-auto-loop-unroll") + 1] == "32"


# ---------------------------------------------------------------------------
# Reachability, in the shape planned for run_eva_slice.py
# ---------------------------------------------------------------------------

ENTRY_UNREACHED_LOG = """\
[eva:final-states] Values at end of function update_sa:
  NON TERMINATING FUNCTION
[eva:final-states] Values at end of function Crypto_Init:
  status IN {-48; 402}
  __retres IN {-48; 402}
[eva:final-states] Values at end of function eva_main:
  Frama_C_entropy_source IN [--..--]
[eva:summary] ====== ANALYSIS SUMMARY ======
  ----------------------------------------------------------------------------
  22 functions analyzed (out of 234): 9% coverage.
  In these functions, 1134 statements reached (out of 1331): 85% coverage.
[metrics:eva:coverage]
  Eva coverage statistics
  =======================
  Coverage estimation = 17.8%

  Unreached functions (111) =
    <workspace/work/src/core/crypto_tc.c>: Crypto_TC_ProcessSecurity;
[metrics:eva:unreached]
  References to non-analyzed functions
  ------------------------------------
  Function eva_main calls Crypto_TC_ProcessSecurity (at workspace/harnesses/harness_core.c:63)
"""


def test_parse_reachability_uses_the_planned_field_names():
    out = et.parse_eva_reachability(ENTRY_UNREACHED_LOG, "Crypto_TC_ProcessSecurity", "eva_main")
    assert out["entry_reached"] is False and out["reachability"] == "entry_unreached"
    assert out["non_terminating_functions"] == ["update_sa"]
    assert out["eva_coverage"] == {
        "functions_analyzed": 22,
        "functions_total": 234,
        "statements_reached": 1134,
        "statements_total": 1331,
        "coverage_estimate_pct": 17.8,
        "unreached_functions": 111,
    }


@pytest.mark.parametrize(
    ("text", "entry", "expected"),
    [
        (log(coverage=80.0), "parse", "ok"),
        (log(coverage=10.0), "parse", "low_coverage"),
        ("", "parse", "unknown"),
        (log(), None, "unknown"),
    ],
)
def test_reachability_verdicts(text, entry, expected):
    assert et.parse_eva_reachability(text, entry, "eva_main")["reachability"] == expected


def test_report_fields_take_precedence_over_the_log_parse():
    # Once run_eva_slice.py reports these itself, its values are the ones used.
    run = run_of("a", [], entry_reached=False, reachability="entry_unreached", eva_coverage={"functions_analyzed": 1})
    assert run.reach["entry_reached"] is False and run.reach["eva_coverage"] == {"functions_analyzed": 1}


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------


def test_clean_run_passes_every_guard():
    base = run_of("base", [row(1), row(2, STATUS_DEAD)])
    assert et.guard_reasons(run_of("r", [row(1, STATUS_VALID), row(2, STATUS_DEAD)]), base) == []


def test_a_run_that_turns_an_obligation_dead_is_rejected_however_few_alarms_it_leaves():
    base = run_of("base", [row(1), row(2), row(3)])
    collapsed = run_of("r", [row(1, STATUS_DEAD), row(2, STATUS_DEAD), row(3, STATUS_DEAD)])
    assert collapsed.unknown_count == 0
    assert et.guard_reasons(collapsed, base) == ["dead_grew:3"]
    assert et.select_run(base, [collapsed]) is base


def test_dead_growth_is_per_obligation_not_just_a_total():
    # As many Dead as before, but on an obligation the base run could still see: it would leave the
    # prover queue as a harness gap without ever being proved.
    base = run_of("base", [row(1, STATUS_DEAD), row(2)])
    moved = run_of("r", [row(1, STATUS_VALID), row(2, STATUS_DEAD)])
    assert moved.report["dead_count"] == base.report["dead_count"]
    assert et.guard_reasons(moved, base) == ["dead_grew:1"]


def test_fewer_dead_obligations_are_fine():
    base = run_of("base", [row(1, STATUS_DEAD), row(2)])
    assert et.guard_reasons(run_of("r", [row(1, STATUS_VALID), row(2)]), base) == []


def test_miniz_ex1_coverage_collapse_is_rejected_though_alarm_count_looks_best():
    # PARF's miniz-ex1: 1,828 alarms to 1 because coverage collapsed. The obligations in the code it
    # stopped reaching may not even be listed as Dead when the functions are never analysed.
    base = run_of("base", [row(line) for line in range(1, 40)])
    collapsed = run_of("r", [row(1)], log_text=log(functions=2, statements=30, coverage=8.0))
    reasons = et.guard_reasons(collapsed, base)
    assert "coverage_dropped:functions_analyzed" in reasons and "coverage_dropped:coverage_estimate_pct" in reasons
    assert et.select_run(base, [collapsed]) is base


def test_entry_reachability_drop_is_rejected():
    base = run_of("base", [row(1)])
    cut = run_of(
        "r",
        [row(1, STATUS_VALID)],
        log_text=log().replace("Values at end of function parse", "Values at end of function other")
        + "[metrics:eva:unreached]\n  Function eva_main calls parse (at h.c:3)\n",
    )
    assert base.reach["entry_reached"] is True and cut.reach["entry_reached"] is False
    assert "entry_reachability_dropped" in et.guard_reasons(cut, base)


def test_a_newly_non_terminating_function_is_rejected():
    base = run_of("base", [row(1)])
    stuck = run_of(
        "r",
        [row(1, STATUS_VALID)],
        log_text=log().replace("  n IN {0}", "  NON TERMINATING FUNCTION"),
    )
    assert et.guard_reasons(stuck, base) == ["non_termination_grew:parse"]


@pytest.mark.parametrize(
    "text",
    [
        "[kernel] Parsing a.c\n[eva] Analyzing a complete application\n",  # aborted before post_analysis
        "",
        log(extra="[eva] Warning: Stopping analysis at user request\n"),
        log(extra="Degeneration occurred:\nresults are not correct\n"),
    ],
)
def test_a_degenerated_run_is_rejected_even_though_it_wrote_a_report(text):
    base = run_of("base", [row(1)])
    degenerate = run_of("r", [row(1, STATUS_VALID)], log_text=text)
    assert degenerate.completed
    assert any(reason.startswith("degenerated:") for reason in et.guard_reasons(degenerate, base))
    assert et.select_run(base, [degenerate]) is base


@pytest.mark.parametrize("status", ["analysis_timeout", "analysis_error", "no_report"])
def test_a_run_that_did_not_complete_is_rejected(status):
    base = run_of("base", [row(1)])
    assert et.guard_reasons(run_of("r", [], status=status), base) == [f"not_completed:{status}"]


@pytest.mark.parametrize(
    "change",
    [
        {"input_digest": "another"},
        {"input_digest": None},
        {"main_fn": "other_main"},
        {"sources": ["a.c", "b.c"]},
        {"reduced_checks": ["-no-warn-invalid-pointer"]},
        {"eva_options": {"context-depth": 4}},
    ],
)
def test_a_run_of_another_analysis_cannot_stand_in_for_this_one(change):
    base = run_of("base", [row(1)])
    assert "different_analysis" in et.guard_reasons(run_of("r", [row(1, STATUS_VALID)], **change), base)


def test_an_inconsistent_status_is_no_way_to_lose_an_unknown():
    # It leaves the Unknown count and the Valid count alike, so without this guard it would look like a win.
    base = run_of("base", [row(1), row(2)])
    inconsistent = run_of("r", [row(1, "inconsistent"), row(2)])
    assert inconsistent.unknown_count == 1
    assert et.guard_reasons(inconsistent, base) == ["inconsistent_status:1"]
    assert et.select_run(base, [inconsistent]) is base
    assert not inconsistent.proves(et.obligation_key(row(1)), base)


def test_a_run_whose_obligations_stopped_matching_is_rejected():
    # If paths or predicates drifted, every alarm would look absent from every other run, hence proved.
    base = run_of("base", [row(line) for line in range(1, 21)])
    drifted = run_of("r", [{**row(line), "directory": "elsewhere"} for line in range(1, 21)])
    assert et.guard_reasons(drifted, base) == ["obligations_missing:20"]
    # A few alarms Eva stops emitting is what more precision looks like (measured: 14 of 815).
    fewer = run_of("r", [row(line) for line in range(1, 19)])
    assert et.guard_reasons(fewer, base) == []


def test_a_run_whose_inputs_changed_while_it_ran_is_rejected():
    base = run_of("base", [row(1)])
    moved = run_of("r", [row(1, STATUS_VALID)], cache={"hit": False, "not_published": "inputs changed"})
    assert et.guard_reasons(moved, base) == ["inputs_changed_during_the_run"]


def test_tuning_options_do_not_make_it_another_analysis():
    base = run_of("base", [row(1)])
    tuned = run_of("r", [row(1, STATUS_VALID)], eva_options={"slevel": 1000, "domains": ["multidim"]})
    assert et.guard_reasons(tuned, base) == []


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


def _unknowns(*functions: str) -> list[dict]:
    return [row(i + 1, function=fn) for i, fn in enumerate(functions)]


def test_selection_minimizes_functions_with_an_unknown_before_the_unknown_count():
    base = run_of("base", _unknowns("a", "b", "c"))
    fewer_alarms = run_of("r1", _unknowns("a", "b"))
    fewer_functions = run_of("r2", _unknowns("a", "a", "a", "a", "a"))
    assert et.select_run(base, [fewer_alarms, fewer_functions]) is fewer_functions


def test_selection_breaks_function_ties_by_unknown_count():
    base = run_of("base", _unknowns("a", "a", "a"))
    worse = run_of("r1", _unknowns("a", "a"))
    better = run_of("r2", _unknowns("a"))
    assert et.select_run(base, [worse, better]) is better


def test_a_tie_keeps_the_earlier_run_whatever_the_elapsed_time():
    base = run_of("base", _unknowns("a"), elapsed_s=500.0)
    same = run_of("r1", _unknowns("a"), elapsed_s=1.0)
    assert et.select_run(base, [same]) is base
    first = run_of("r1", _unknowns("a"), elapsed_s=900.0)
    second = run_of("r2", _unknowns("a"), elapsed_s=1.0)
    assert et.select_run(run_of("base", _unknowns("a", "b")), [first, second]) is first


def test_selection_never_reads_elapsed_time():
    one = run_of("r1", _unknowns("a"))
    two = run_of("r2", _unknowns("a"))
    base = run_of("base", _unknowns("a", "b"))
    fast = {"r1": 1.0, "r2": 900.0}
    picks = []
    for times in (fast, {k: 901.0 - v for k, v in fast.items()}):
        one.report["elapsed_s"], two.report["elapsed_s"] = times["r1"], times["r2"]
        picks.append(et.select_run(base, [one, two]).name)
    assert picks == ["r1", "r1"]


def test_libc_rows_do_not_count_as_functions_to_prove():
    libc = {**row(9, function="memcmp"), "directory": "FRAMAC_SHARE/libc", "file": "string.h"}
    run = run_of("r", [row(1, function="parse"), libc])
    assert run.unknown_functions == {"parse"} and run.unknown_count == 1


def test_a_trial_timeout_scales_with_the_base_run_and_an_explicit_timeout_wins():
    assert eo.trial_timeout(10.0) == eo.TRIAL_TIMEOUT_FLOOR_S
    assert eo.trial_timeout(100.0) == 100 * eo.TRIAL_TIMEOUT_FACTOR
    assert eo.trial_timeout(10_000.0) == eo.TRIAL_TIMEOUT_CEILING_S
    assert eo.trial_timeout(None) == eo.TRIAL_TIMEOUT_FLOOR_S
    assert eo.trial_timeout(100.0, 42) == 42
    assert eo.loop_trial_timeout(100.0) == eo.TRIAL_TIMEOUT_FLOOR_S
    assert eo.loop_trial_timeout(1000.0) == 1000 * eo.LOOP_TRIAL_TIMEOUT_FACTOR
    assert eo.loop_trial_timeout(None) == eo.TRIAL_TIMEOUT_FLOOR_S


# ---------------------------------------------------------------------------
# Combination
# ---------------------------------------------------------------------------


def _statuses(combination: et.Combination) -> dict[int, str]:
    return {r["line"]: r["status"] for r in combination.rows}


def test_an_obligation_proved_by_any_admissible_run_is_discharged():
    base = run_of("base", [row(1), row(2), row(3)])
    a = run_of("a", [row(1, STATUS_VALID), row(2), row(3)])
    b = run_of("b", [row(1), row(2, STATUS_VALID), row(3)])
    out = et.combine_runs(a, base, [base, a, b])
    assert _statuses(out) == {1: STATUS_VALID, 2: STATUS_VALID, 3: STATUS_UNKNOWN}
    assert [(u["line"], u["proved_by"], u["how"]) for u in out.upgraded] == [(2, "b", "valid")]


def test_two_runs_assuming_what_the_other_proves_is_no_circle():
    # Run a proves 1 assuming 2 holds, run b proves 2 assuming 1 holds. Whichever an execution violates
    # first would have to be an alarm in both runs, so neither can be violated.
    base = run_of("base", [row(1), row(2)])
    a = run_of("a", [row(1, STATUS_VALID), row(2)])
    b = run_of("b", [row(1), row(2, STATUS_VALID)])
    assert et.combine_runs(a, base, [base, a, b]).upgraded[0]["line"] == 2
    assert _statuses(et.combine_runs(a, base, [base, a, b])) == {1: STATUS_VALID, 2: STATUS_VALID}


def test_an_alarm_the_selected_run_lost_is_listed_when_another_run_is_what_discharges_it():
    # The selected run missed a statement, so its silence proves nothing; another run's proof does.
    base = run_of("base", [row(1), row(2)])
    selected = run_of("a", [row(2, STATUS_VALID)], log_text=log(statements=199))
    other = run_of("b", [row(1, STATUS_VALID), row(2)])
    out = et.combine_runs(selected, base, [base, selected, other])
    assert [(u["line"], u["proved_by"], u["how"]) for u in out.upgraded] == [(1, "b", "valid")]
    assert _statuses(out) == {2: STATUS_VALID}


def test_only_a_group_that_is_all_valid_counts_as_proved():
    # The CSV hides columns: two statements on a line give one key, and which one a run proved is unknowable.
    base = run_of("base", [row(1), row(1, STATUS_VALID)])
    other = run_of("r", [row(1, STATUS_VALID), row(1)])
    out = et.combine_runs(base, base, [base, other])
    assert out.upgraded == [] and sorted(r["status"] for r in out.rows) == [STATUS_UNKNOWN, STATUS_VALID]
    # Identical rows collapse in the CSV, so one Valid row here means every statement under the key.
    proved = run_of("r", [row(1, STATUS_VALID)])
    out = et.combine_runs(base, base, [base, proved])
    assert [r["status"] for r in out.rows] == [STATUS_VALID, STATUS_VALID] and len(out.upgraded) == 1


def test_an_alarm_absent_from_a_run_is_a_proof_only_if_that_run_reached_as_much():
    # Eva only emits an alarm it cannot discharge, unless it never reaches the statement.
    base = run_of("base", [row(1, predicate="\\initialized(p)"), row(2)])
    silent = run_of("a", [row(2)])
    out = et.combine_runs(base, base, [base, silent])
    assert [(u["line"], u["how"], u["proved_by"]) for u in out.upgraded] == [(1, "absent", "a")]
    missed = run_of("b", [row(2)], log_text=log(statements=199))
    assert et.combine_runs(base, base, [base, missed]).upgraded == []


def test_absence_is_judged_per_function_when_the_log_says_how_much_of_it_was_reached():
    # Measured on minmea: a run lost one statement in minmea_scan, which says nothing about the alarm
    # it no longer reports in minmea_parse_rmc.
    stmts = "[metrics:eva:reached-stmts]\n  parse: {parse} stmts out of 40 (100.0%)\n  scan: {scan} stmts out of 30\n"
    base_log = log(statements=70, extra=stmts.format(parse=40, scan=30))
    silent_log = log(statements=69, extra=stmts.format(parse=40, scan=29))
    base = run_of("base", [row(1, function="parse"), row(2, function="scan")], log_text=base_log)
    silent = run_of("r", [], log_text=silent_log)
    assert silent.proves(et.obligation_key(row(1, function="parse")), base)
    assert not silent.proves(et.obligation_key(row(2, function="scan")), base)
    assert et.statements_by_function(silent_log) == {"parse": 40, "scan": 29}
    assert et.statements_by_function("no metrics") == {}


def test_an_alarm_only_another_run_reports_stands_when_the_selected_run_missed_its_statement():
    base = run_of("base", [row(1), row(2)])
    selected = run_of("a", [row(2, STATUS_VALID)], log_text=log(statements=199))
    out = et.combine_runs(selected, base, [base, selected])
    assert _statuses(out) == {2: STATUS_VALID, 1: STATUS_UNKNOWN}
    assert next(r for r in out.rows if r["line"] == 1)["tuning_run"] == "base"
    reached = run_of("a", [row(2, STATUS_VALID)])
    assert _statuses(et.combine_runs(reached, base, [base, reached])) == {2: STATUS_VALID}


def test_dead_is_never_a_proof():
    base = run_of("base", [row(1), row(2, STATUS_DEAD)])
    # No admissible run can make an Unknown of the base run Dead, but the selected run may keep one
    # Dead that another run sees as Unknown: it stays as the selected run reports it.
    revived = run_of("r", [row(1), row(2)])
    out = et.combine_runs(base, base, [base, revived])
    assert _statuses(out) == {1: STATUS_UNKNOWN, 2: STATUS_DEAD} and out.upgraded == []


def test_a_red_status_wins_any_conflict_and_is_recorded():
    base = run_of("base", [row(1), row(2)])
    proves = run_of("a", [row(1, STATUS_VALID), row(2, STATUS_VALID)])
    red = run_of("b", [row(1, STATUS_INVALID), row(2)])
    out = et.combine_runs(proves, base, [base, proves, red], [red])
    assert _statuses(out)[1] == STATUS_INVALID and _statuses(out)[2] == STATUS_VALID
    # A run that is both admissible and a source of red statuses counts them once.
    assert run_eva_slice.summarize_rows(out.rows)["invalid_count"] == 1
    assert run_eva_slice.summarize_rows(out.rows)["invalid_alarms"][0]["tuning_run"] == "b"
    assert [c["line"] for c in out.conflicts] == [1] and out.conflicts[0]["invalid_in"] == "b"


def test_a_replay_runs_what_the_red_status_came_from_again(tune_run, capsys):
    # Reviewed: a rung that was neither selected nor the first prover would never run again, and a
    # second `run eva-tune` would quietly lose its alarm. It is recorded and replayed like a proof.
    _write_trial(tune_run, "m", "base", [_csv_row(1), _csv_row(2)])
    _write_trial(tune_run, "m", "slevel", [_csv_row(1, "Valid"), _csv_row(2)], eva_options={"slevel": 1000})
    red = "Invalid or unreachable"
    _write_trial(tune_run, "m", "values", [_csv_row(1), _csv_row(2, red)], eva_options={"ilevel": 64})
    assert et.main(_finish_args(tune_run, ["slevel", "values"])) == 0
    capsys.readouterr()
    first = json.loads((tune_run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    assert first["invalid_count"] == 1 and first["invalid_alarms"][0]["tuning_run"] == "values"
    record = pm.load_params(tune_run)["modules"]["m"]["eva_tuned"]
    assert [c["name"] for c in record["contributors"]] == ["values"]
    assert eo.recorded_rungs(record) == ["slevel", "values"]

    assert et.main(_finish_args(tune_run, eo.recorded_rungs(record))) == 0
    capsys.readouterr()
    second = json.loads((tune_run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    assert second["tuning"]["mode"] == "replay" and second["invalid_count"] == 1


def test_a_rung_that_did_not_finish_is_on_the_record(tune_run, capsys):
    _write_trial(tune_run, "m", "base", [_csv_row(1)])
    write_json(tune_run / pm.TUNE_REPORT_DIR / "m/slevel.json", {"status": "analysis_timeout"})
    assert et.main(_finish_args(tune_run, ["slevel"])) == 0
    capsys.readouterr()
    assert pm.load_params(tune_run)["modules"]["m"]["eva_tuned"]["unfinished"] == ["slevel"]


def test_a_red_status_from_a_rejected_run_still_reaches_the_report():
    # The alarm is often the very reason the rung lost coverage: it cut every path behind it.
    base = run_of("base", [row(1), row(2)])
    rejected = run_of("r", [row(1, STATUS_INVALID), row(2, STATUS_DEAD)])
    assert et.guard_reasons(rejected, base) == ["dead_grew:1"]
    out = et.combine_runs(base, base, [base], [rejected])
    assert _statuses(out) == {1: STATUS_INVALID, 2: STATUS_UNKNOWN}
    assert next(r for r in out.rows if r["line"] == 1)["tuning_run"] == "r"
    assert run_eva_slice.summarize_rows(out.rows)["invalid_count"] == 1


def _status_sets(combination: et.Combination, base: et.EvaRun) -> tuple[set, set, set]:
    keys = {et.obligation_key(r): r["status"] for r in combination.rows}
    return (
        {k for k, s in keys.items() if s == STATUS_VALID},
        {k for k, s in keys.items() if s == STATUS_UNKNOWN},
        {k for k, s in keys.items() if s == STATUS_INVALID},
    )


def test_a_machine_that_completes_fewer_rungs_ends_with_more_planned_never_another_verdict():
    """Any subset of the rungs: more rungs only move obligations from Unknown to Valid or Invalid."""
    lines = range(1, 7)
    base = run_of("base", [row(line) for line in lines])
    rungs = [
        run_of("a", [row(1, STATUS_VALID), *(row(line) for line in range(2, 7))]),
        run_of("b", [row(1), row(2, STATUS_VALID), row(3, STATUS_VALID), *(row(line) for line in range(4, 7))]),
        run_of("c", [*(row(line) for line in range(1, 4)), row(4, STATUS_VALID), row(5, STATUS_INVALID), row(6)]),
    ]
    results = {}
    for mask in range(8):
        chosen = [rung for i, rung in enumerate(rungs) if mask >> i & 1]
        selected = et.select_run(base, chosen)
        results[mask] = _status_sets(et.combine_runs(selected, base, [base, *chosen], chosen), base)
    for small in results:
        for large in results:
            if small & large == small:
                valid_s, unknown_s, invalid_s = results[small]
                valid_l, unknown_l, invalid_l = results[large]
                assert valid_s <= valid_l and invalid_s <= invalid_l, (small, large)
                assert unknown_l <= unknown_s, (small, large)


def test_what_remains_does_not_depend_on_which_run_is_selected():
    base = run_of("base", [row(1), row(2), row(3)])
    a = run_of("a", [row(1, STATUS_VALID), row(2), row(3)])
    b = run_of("b", [row(1), row(2, STATUS_VALID), row(3)])
    remaining = {
        frozenset(
            k
            for k, s in ((et.obligation_key(r), r["status"]) for r in et.combine_runs(sel, base, [base, a, b]).rows)
            if s == STATUS_UNKNOWN
        )
        for sel in (base, a, b)
    }
    assert len(remaining) == 1


# ---------------------------------------------------------------------------
# Finding and annotating loops
# ---------------------------------------------------------------------------

LOOPS_C = """\
int table[3];
/*@ requires n >= 0; */
int f(int n) {
  /* a for in a comment, "for" in a string */
  const char *s = "while (1) for (;;)";
  int i = 0;
  for (i = 0; i < n; i++) {
    while (i > 2) {
      i--;
    }
  }
  do {
    i++;
  } while (i < 3);
  //@ loop unroll 4;
  for (int j = 0; j < 2; j++)
    table[j] = j;
  return i;
}

int g(void) { for (;;) break; return 0; }
"""


def test_find_loops_sees_code_only_and_tells_a_do_while_from_a_while():
    sites = eva_loops.find_loops(LOOPS_C, "f")
    assert [(s.keyword, s.line) for s in sites] == [("for", 7), ("while", 8), ("do", 12), ("for", 16)]
    assert [s.parent for s in sites] == [None, 0, None, None]
    assert [s.annotated for s in sites] == [False, False, False, True]
    assert eva_loops.find_loops(LOOPS_C, "missing") == []
    assert [s.keyword for s in eva_loops.find_loops(LOOPS_C, "g")] == ["for"]


def test_nests_group_a_loop_with_the_loops_inside_it():
    nests = eva_loops.loop_nests(eva_loops.find_loops(LOOPS_C, "f"))
    assert [[s.ordinal for s in nest] for nest in nests] == [[0, 1], [2], [3]]


def test_annotation_stays_on_the_loops_line_so_obligations_keep_their_identity():
    refs = [LoopRef("a.c", "f", 0, 64), LoopRef("a.c", "f", 1, 64), LoopRef("a.c", "f", 9, 64)]
    text, applied, dropped = eva_loops.annotate_source(LOOPS_C, refs)
    assert text.count("\n") == LOOPS_C.count("\n")
    assert "  /*@ loop unroll 64; */ for (i = 0; i < n; i++) {" in text
    assert "    /*@ loop unroll 64; */ while (i > 2) {" in text
    assert applied == refs[:2] and dropped == refs[2:]
    # A loop that already has an unroll annotation keeps it: it is someone's decision.
    assert eva_loops.annotate_source(LOOPS_C, [LoopRef("a.c", "f", 3, 64)])[1] == []


def test_annotation_joins_an_existing_loop_annotation_as_its_first_clause():
    # What the kernel accepts, tried on this image: a second comment on a loop is a syntax error, a
    # `loop unroll` after `loop variant` is rejected, and the first clause works in every form.
    source = (
        "void f(int n) {\n"
        "  /*@ loop invariant 0 <= i; loop variant n - i; */ for (int i = 0; i < n; i++) {}\n"
        "  //@ loop assigns j;\n"
        "  for (int j = 0; j < n; j++) {}\n"
        "  /*@ for b: loop invariant k >= 0; */\n"
        "  while (k) {}\n"
        "  /*@ assert n > 0; */ for (;;) {}\n"
        "  /* just a comment */ for (;;) {}\n"
        "}\n"
    )
    refs = [LoopRef("a.c", "f", ordinal, 8) for ordinal in range(5)]
    text, applied, dropped = eva_loops.annotate_source(source, refs)
    assert applied == refs and dropped == []
    assert text.count("\n") == source.count("\n")
    assert "/*@ loop unroll 8; loop invariant 0 <= i; loop variant n - i; */ for (int i" in text
    assert "//@ loop unroll 8; loop assigns j;\n" in text
    assert "/*@ loop unroll 8; for b: loop invariant k >= 0; */\n" in text
    assert "/*@ assert n > 0; */ /*@ loop unroll 8; */ for (;;) {}" in text, "an assertion is not a loop annotation"
    assert "/* just a comment */ /*@ loop unroll 8; */ for (;;) {}" in text


def test_loop_refs_round_trip_and_reject_anything_else():
    ref = LoopRef("workspace/work/a.c", "f", 2, 256)
    assert eva_loops.parse_loop_ref(ref.to_arg()) == ref
    assert eva_loops.loop_ref_from_json(ref.to_json()) == ref
    for bad in ("../x.c#f#0=1", "/etc/passwd#f#0=1", "a.c#f;rm#0=1", "a.c#f#x=1", "a.c#f#0=-1", "a.c#f#0", "-x#f#0=1"):
        with pytest.raises(ValueError):
            eva_loops.parse_loop_ref(bad)
    # What a record accepts must be what the command line accepts, or `eva` could not replay it.
    for path in ("a b.c", "a=b.c", "a#b.c", "-x.c"):
        assert eva_loops.loop_ref_problem(path, "f", 0, 1) is not None, path


def test_mirror_flags_redirect_only_paths_into_the_run_tree():
    flags = ["-I.", "-Iworkspace/work/inc", "-I", "/framac-run/workspace/work/x", "-DA=1", "-I/usr/include"]
    flags += ["-include", "workspace/work/p.h", "-isystem", "/opt/s", "-iquoteworkspace/harnesses"]
    assert eva_loops.mirror_flags(flags, "M") == [
        "-IM",
        "-IM/workspace/work/inc",
        "-I",
        "M/workspace/work/x",
        "-DA=1",
        "-I/usr/include",
        "-include",
        "M/workspace/work/p.h",
        "-isystem",
        "/opt/s",
        "-iquoteM/workspace/harnesses",
    ]


def test_strip_mirror_maps_a_report_directory_back():
    assert eva_loops.strip_mirror("M/x/workspace/work/src", "M/x") == "workspace/work/src"
    assert eva_loops.strip_mirror("M/x", "M/x") == "."
    assert eva_loops.strip_mirror("FRAMAC_SHARE/libc", "M/x") == "FRAMAC_SHARE/libc"
    assert eva_loops.strip_mirror("workspace/work", None) == "workspace/work"


def _gcc_m_runner(deps: str):
    def run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=f"x.o: {deps}\n", stderr="")

    return run


def test_prepare_mirror_annotates_a_copy_and_leaves_the_tree_alone(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "workspace/work/src/a.c"
    src.parent.mkdir(parents=True)
    src.write_text(LOOPS_C, encoding="utf-8")
    inc = tmp_path / "workspace/work/inc/a.h"
    inc.parent.mkdir(parents=True)
    inc.write_text("int f(int);\n", encoding="utf-8")
    harness = tmp_path / "workspace/harnesses/harness_a.c"
    harness.parent.mkdir(parents=True)
    harness.write_text('#include "a.h"\n', encoding="utf-8")

    deps = "workspace/work/src/a.c workspace/work/src/../inc/a.h workspace/harnesses/harness_a.c /usr/include/stdio.h"
    ref = LoopRef("workspace/work/src/a.c", "f", 0, 64)
    missing = LoopRef("workspace/work/src/gone.c", "f", 0, 64)
    mirror = eva_loops.prepare_mirror(
        "workspace/eva/m/mirror",
        ["workspace/work/src/a.c", "workspace/harnesses/harness_a.c"],
        "-Iworkspace/work/inc -DX",
        ["-Iworkspace/work/inc"],
        [ref, missing],
        runner=_gcc_m_runner(deps),
    )
    assert mirror is not None
    root = "workspace/eva/m/mirror"
    assert mirror.sources == [f"{root}/workspace/work/src/a.c", f"{root}/workspace/harnesses/harness_a.c"]
    assert mirror.cppflags == f"-I{root}/workspace/work/inc -DX"
    assert mirror.applied == [ref] and mirror.dropped == [missing]
    assert "/*@ loop unroll 64; */ for" in (tmp_path / root / "workspace/work/src/a.c").read_text(encoding="utf-8")
    assert (tmp_path / root / "workspace/work/inc/a.h").is_file()
    assert (tmp_path / root / "workspace/harnesses/harness_a.c").is_file()
    assert src.read_text(encoding="utf-8") == LOOPS_C, "workspace/work must never change"


def test_the_same_analysis_is_one_cache_entry_wherever_it_writes(tmp_path, monkeypatch):
    # An output directory that is a prefix of the mirror path must not change the key: `eva-<mod>`
    # writes to workspace/eva/<mod> and reads a mirror under workspace/eva/<mod>/tune.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_eva_slice, "_input_digest", lambda sources, flags: "d")
    materials = []

    def fake_memoize(ns, material, **kwargs):
        materials.append(material)
        return {"status": "ok"}

    monkeypatch.setattr(run_eva_slice.cache, "memoize", fake_memoize)
    mirror = Path("workspace/eva/m/tune/mirrors/abc")
    monkeypatch.setattr(
        run_eva_slice,
        "prepare_mirror",
        lambda root, sources, cppflags, flags, refs: eva_loops.Mirror(
            root, [f"{root}/workspace/work/a.c"], f"-I{root}/workspace/work", list(refs), []
        ),
    )
    ref = LoopRef("workspace/work/a.c", "f", 0, 8)
    for out_dir in ("workspace/eva/m", "workspace/eva/m/tune/loops"):
        run_eva_slice.run_eva_on_slice(
            ["workspace/work/a.c"], "eva_main", Path(out_dir), loop_unroll=[ref], mirror_root=mirror.as_posix()
        )
    assert materials[0] == materials[1]
    assert not any("loops" in token for token in materials[1]["command"])


def test_a_trial_with_nothing_to_annotate_is_the_plain_analysis(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    seen: dict[str, Any] = {}

    def fake_execute(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root=None):
        seen.update(sources=sources, path_root=path_root)
        return {"status": "ok", "sources": sources, "reduced_checks": reduced_checks}

    monkeypatch.setattr(run_eva_slice, "_execute_eva", fake_execute)
    monkeypatch.setattr(run_eva_slice, "_input_digest", lambda sources, flags: "d")
    monkeypatch.setattr(run_eva_slice, "prepare_mirror", lambda *a, **k: None)
    ref = LoopRef("workspace/work/a.c", "f", 0, 8)
    res = run_eva_slice.run_eva_on_slice(["a.c"], "eva_main", tmp_path / "out", loop_unroll=[ref], use_cache=False)
    assert seen == {"sources": ["a.c"], "path_root": None}
    assert res["loop_unroll"] == [] and res["loop_unroll_dropped"] == [ref.to_json()]


def test_mirror_id_is_fixed_by_the_annotation_set():
    a, b = LoopRef("a.c", "f", 0, 8), LoopRef("a.c", "f", 1, 8)
    assert eva_loops.mirror_id([a, b]) == eva_loops.mirror_id([b, a, a])
    assert eva_loops.mirror_id([a]) != eva_loops.mirror_id([b])


def test_plan_loop_candidates_takes_only_functions_with_unknowns_most_first(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "workspace/work/a.c"
    src.parent.mkdir(parents=True)
    src.write_text(LOOPS_C, encoding="utf-8")
    run = run_of(
        "r", [row(1, function="g"), row(2, function="f"), row(3, function="f"), row(4, STATUS_VALID, function="h")]
    )
    candidates = et.plan_loop_candidates(run, 64)
    assert [c.name for c in candidates] == ["loop-f-0", "loop-f-2", "loop-g-0"]
    assert [r.ordinal for r in candidates[0].refs] == [0, 1], "a nest is unrolled as a whole"
    assert et.plan_loop_candidates(run, 64, limit=1)[0].name == "loop-f-0"


def test_libc_functions_get_no_loop_trials():
    libc = {**row(9, function="memcmp"), "directory": "FRAMAC_SHARE/libc", "file": "string.h"}
    assert et.plan_loop_candidates(run_of("r", [libc]), 64) == []


def test_keep_an_annotation_only_if_unknowns_fall_and_nothing_turns_dead():
    base = run_of("base", [row(1), row(2), row(3)])
    assert et.loop_trial_helps(run_of("t", [row(1, STATUS_VALID), row(2), row(3)]), base, base)
    assert not et.loop_trial_helps(run_of("t", [row(1), row(2), row(3)]), base, base), "no gain"
    assert not et.loop_trial_helps(run_of("t", [row(1, STATUS_DEAD), row(2), row(3)]), base, base), "Dead grew"
    assert not et.loop_trial_helps(run_of("t", [], status="analysis_timeout"), base, base), "did not finish"


# ---------------------------------------------------------------------------
# params.json and the generated Makefile
# ---------------------------------------------------------------------------


def _base_report(run_dir: Path, module: str = "snmp", **fields) -> None:
    unknowns = {"parse": [{"directory": "workspace/work", "file": "a.c", "line": 1}]}
    write_json(
        run_dir / pm.TUNE_REPORT_DIR / module / "base.json",
        {
            "status": "ok",
            "unknown_obligations_by_function": unknowns,
            "elapsed_s": 100.0,
            "input_digest": "d1",
            **fields,
        },
    )


def _mk(run: Path) -> str:
    pm.generate(run, templates_dir=ACSL)
    return (run / pm.MODULES_MK).read_text(encoding="utf-8")


def test_params_eva_options_are_validated_merged_and_cleared(tmp_path):
    run = _make_run(tmp_path)
    assert pm.params_set(run, "snmp", eva_options={"min-loop-unroll": 8})["overrides"] == {
        "eva_options": {"min-loop-unroll": 8}
    }
    res = pm.params_set(run, "snmp", eva_options={"split-return": "auto"})
    assert res["overrides"]["eva_options"] == {"min-loop-unroll": 8, "split-return": "auto"}
    res = pm.params_set(run, "snmp", eva_options={"min-loop-unroll": None})
    assert res["overrides"]["eva_options"] == {"split-return": "auto"}
    assert "eva_options" not in pm.params_set(run, "snmp", eva_options={"split-return": None})["overrides"]
    with pytest.raises(ValueError):
        pm.params_set(run, "snmp", eva_options={"use-spec": "f"})
    with pytest.raises(ValueError):
        pm.params_set(run, "snmp", eva_options={"slevel": "1000; rm -rf /"})


def test_params_cli_parses_eva_options_and_clears_with_an_empty_value(tmp_path, capsys):
    run = _make_run(tmp_path)
    base = ["--run-dir", str(run), "params", "set", "--module", "snmp"]
    assert pm.main([*base, "--eva-option", "slevel=1000", "--eva-option", "domains=multidim"]) == 0
    assert json.loads(capsys.readouterr().out)["overrides"]["eva_options"] == {"slevel": 1000, "domains": ["multidim"]}
    assert pm.main([*base, "--eva-option", "slevel="]) == 0
    assert json.loads(capsys.readouterr().out)["overrides"]["eva_options"] == {"domains": ["multidim"]}
    assert pm.main([*base, "--eva-option", "no-warn-invalid-pointer=true"]) == 1
    capsys.readouterr()
    assert pm.main([*base, "--eva-option", "use-spec="]) == 1


def test_a_tampered_params_file_is_refused(tmp_path):
    for bad in (
        {"eva_options": {"use-spec": "f"}},
        {"eva_options": {"slevel": "1 -load x"}},
        {"eva_tuned": {"rung": "x; rm", "selected": "x"}},
        {"eva_tuned": {"rung": "a", "selected": "a", "options": {"use-spec": "f"}}},
        {
            "eva_tuned": {
                "rung": "a",
                "selected": "a",
                "loops": [{"file": "../x", "function": "f", "ordinal": 0, "unroll": 1}],
            }
        },
    ):
        run = _make_run(tmp_path / str(abs(hash(str(bad)))), params={"modules": {"snmp": bad}})
        assert pm.generate(run)["ok"] is False, bad


def test_only_modules_left_with_unknowns_get_rungs_and_all_of_them(tmp_path):
    run = _make_run(tmp_path)
    assert "EVA_TUNE_RUNGS_snmp :=\n" in _mk(run), "no base run yet"
    _base_report(run, unknown_obligations_by_function={})
    assert "EVA_TUNE_RUNGS_snmp :=\n" in _mk(run), "nothing left to tune"
    libc_only = {"abs": [{"directory": "FRAMAC_SHARE/libc", "file": "stdlib.h", "line": 1}]}
    _base_report(run, unknown_obligations_by_function=libc_only)
    assert "EVA_TUNE_RUNGS_snmp :=\n" in _mk(run), "a libc row is no prover work"
    _base_report(run, status="analysis_error")
    assert "EVA_TUNE_RUNGS_snmp :=\n" in _mk(run), "the base run failed"
    _base_report(run)
    text = _mk(run)
    assert f"EVA_TUNE_RUNGS_snmp := {' '.join(eo.RUNG_NAMES)}\n" in text
    assert "EVA_TUNE_RUNGS_cfg :=\n" in text
    assert f"EVA_TUNE_TIMEOUT_snmp := {100 * eo.TRIAL_TIMEOUT_FACTOR}\n" in text
    assert "EVA_RUNG_OPTIONS_snmp__slevel := --eva-option=slevel=1000\n" in text


def test_rungs_refine_the_module_settings_and_a_rung_that_changes_nothing_is_skipped(tmp_path):
    run = _make_run(tmp_path, params={"modules": {"snmp": {"eva_slevel": 5000, "eva_options": {"ilevel": 128}}}})
    _base_report(run)
    text = _mk(run)
    assert "EVA_BASE_OPTIONS_snmp := --eva-option=ilevel=128\n" in text
    rungs = next(line for line in text.splitlines() if line.startswith("EVA_TUNE_RUNGS_snmp"))
    assert " slevel" not in rungs, "slevel 1000 changes nothing on a module at 5000"
    values_line = next(line for line in text.splitlines() if line.startswith("EVA_RUNG_OPTIONS_snmp__values"))
    assert "--eva-option=ilevel=128" in values_line


def _record(run: Path, **fields) -> dict:
    return _record_for(run, "snmp", **fields)


def _record_for(run: Path, module: str, **fields) -> dict:
    plan = pm.build_plan(run, templates_dir=ACSL)
    return {
        "ladder": eo.LADDER_VERSION,
        "settings_digest": plan.modules[module].settings_digest,
        "input_digest": "d1",
        "selected": "loop-f-0",
        "rung": "returns",
        "options": {"slevel": 500, "split-return": "auto"},
        "loops": [{"file": "workspace/work/a.c", "function": "f", "ordinal": 0, "unroll": 64}],
        "contributors": [{"name": "unroll", "options": {"min-loop-unroll": 8}, "loops": []}],
        **fields,
    }


def test_a_recorded_decision_is_replayed_by_eva_and_narrows_eva_tune(tmp_path):
    run = _make_run(tmp_path)
    _base_report(run)
    record = _record(run)
    pm.record_eva_tuning(run, "snmp", record)
    assert pm.load_params(run)["modules"]["snmp"]["eva_tuned"] == record
    text = _mk(run)
    assert "EVA_OPTIONS_snmp := --eva-option=slevel=500 --eva-option=split-return=auto\n" in text
    assert "EVA_BASE_OPTIONS_snmp :=\n" in text, "the base run stays the reference for the guards"
    loops_line = next(line for line in text.splitlines() if line.startswith("EVA_LOOPS_snmp"))
    assert r"--loop-unroll=workspace/work/a.c\#f\#0=64" in loops_line, "make reads an unescaped # as a comment"
    assert "--mirror-root=workspace/eva/snmp/tune/mirrors/" in loops_line
    assert "EVA_TUNE_RUNGS_snmp := unroll returns\n" in text


def test_a_decision_made_under_other_settings_or_sources_is_not_replayed(tmp_path):
    run = _make_run(tmp_path)
    _base_report(run)
    pm.record_eva_tuning(run, "snmp", _record(run, input_digest="older"))
    text = _mk(run)
    assert f"EVA_TUNE_RUNGS_snmp := {' '.join(eo.RUNG_NAMES)}\n" in text, "the sources changed: search again"
    assert "EVA_OPTIONS_snmp := --eva-option=slevel=500" in text, "`eva` still has the decision to apply"

    pm.params_set(run, "snmp", eva_slevel=250)
    text = _mk(run)
    assert "EVA_OPTIONS_snmp :=\n" in text and "EVA_LOOPS_snmp :=\n" in text, "another base: the decision is stale"
    assert f"EVA_TUNE_RUNGS_snmp := {' '.join(eo.RUNG_NAMES)}\n" in text

    pm.params_set(run, "snmp", eva_slevel=100, eva_retune=True)
    assert "eva_tuned" not in pm.load_params(run)["modules"]["snmp"]


def test_reserved_module_names_stay_out_of_the_make_targets(tmp_path):
    run = _make_run(tmp_path)
    dag = json.loads((run / pm.DAG_JSON).read_text(encoding="utf-8"))
    dag["modules"]["tune"] = {**dag["modules"]["snmp"]}
    write_json(run / pm.DAG_JSON, dag)
    write_json(run / pm.HARNESS_DIR / "harness_tune.json", {"cppflags": "-I.", "sources": []})
    (run / pm.HARNESS_DIR / "harness_tune.c").write_text("", encoding="utf-8")
    assert "tune" in pm.build_plan(run).excluded


def test_a_plain_eva_module_block_has_no_tuning_tokens(tmp_path):
    text = _mk(_make_run(tmp_path))
    assert "EVA_OPTIONS_snmp :=\n" in text and "EVA_LOOPS_snmp :=\n" in text


def test_run_eva_tune_runs_the_base_stage_first_then_regenerates(tmp_path):
    run = _make_run(tmp_path)
    pm.generate(run, templates_dir="/opt/framac-pipeline/templates")
    seen: list[list[str]] = []

    def runner(cmd, cwd, sink):
        seen.append([t for t in cmd if t.startswith("eva") or t == "ingest"])
        if "eva-tune-base" in cmd:
            _base_report(run)
        return 0

    rc, summary = pm.run_targets(
        ["ingest", "eva-tune"], run, jobs=2, make_runner=runner, templates_dir="/opt/framac-pipeline/templates"
    )
    assert seen == [["eva-tune-base"], ["eva-tune"], ["ingest"]]
    assert "evabase-snmp" in summary["targets"]["eva-tune-base"]["nodes"]
    assert summary["targets"]["eva-tune"]["nodes"]["evatune-snmp"]["output"] == "workspace/reports/eva/snmp.json"
    # The second stage saw the base report: its modules.mk has the rungs.
    assert f"EVA_TUNE_RUNGS_snmp := {' '.join(eo.RUNG_NAMES)}\n" in (run / pm.MODULES_MK).read_text(encoding="utf-8")


def test_eva_tune_is_a_trusted_static_step():
    import resources as R

    cmd = "python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva-tune"
    assert R.cache_mount_mode(cmd, True) == "rw"
    assert R.is_known_static_command(cmd) is True
    assert R.infer_class("python3 $S/eva_tuning.py finish --module m") == "eva"


# ---------------------------------------------------------------------------
# finish, and what the ledger makes of its report
# ---------------------------------------------------------------------------


def _write_trial(run_dir: Path, module: str, name: str, rows: list[dict], text: str | None = None, **report) -> Path:
    out = run_dir / "workspace/eva" / module / "tune" / name
    out.mkdir(parents=True, exist_ok=True)
    header = "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
    lines = [
        "\t".join([r["directory"], r["file"], str(r["line"]), r["function"], r["kind"], r["status_raw"], r["property"]])
        for r in rows
    ]
    (out / "alarms.csv").write_text(header + "".join(line + "\n" for line in lines), encoding="utf-8")
    (out / "eva.log").write_text(log() if text is None else text, encoding="utf-8")
    full = {
        "status": "ok",
        "main_fn": "eva_main",
        "sources": ["a.c"],
        "input_digest": "d1",
        "reduced_checks": [],
        "eva_options": {},
        "csv_file": (out / "alarms.csv").as_posix(),
        "log_file": (out / "eva.log").as_posix(),
        **report,
    }
    write_json(run_dir / pm.TUNE_REPORT_DIR / module / f"{name}.json", full)
    return out


def _csv_row(line: int, status: str = "Unknown", function: str = "parse") -> dict:
    return {
        "directory": "workspace/work",
        "file": "a.c",
        "function": function,
        "line": line,
        "kind": "mem_access",
        "status_raw": status,
        "property": f"\\valid(p+{line})",
    }


def _finish_args(run_dir: Path, rungs: list[str], digest: str = "dd") -> list[str]:
    return [
        "finish",
        "--module",
        "m",
        "--sources",
        "a.c",
        "--main",
        "eva_main",
        "--entry-fn",
        "parse",
        "--settings-digest",
        digest,
        "--rungs",
        *rungs,
        "--report-dir",
        f"{pm.TUNE_REPORT_DIR}/m",
        "--work-dir",
        "workspace/eva/m/tune",
        "--out-json",
        "workspace/reports/eva/m.json",
    ]


@pytest.fixture
def tune_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "workspace/build").mkdir(parents=True)
    return tmp_path


def test_finish_writes_the_report_the_evidence_and_the_decision(tune_run, capsys):
    _write_trial(tune_run, "m", "base", [_csv_row(1), _csv_row(2), _csv_row(3, function="other")])
    _write_trial(
        tune_run,
        "m",
        "slevel",
        [_csv_row(1, "Valid"), _csv_row(2), _csv_row(3, "Valid", "other")],
        eva_options={"slevel": 1000},
    )
    _write_trial(
        tune_run,
        "m",
        "history",
        [_csv_row(1), _csv_row(2, "Valid"), _csv_row(3, function="other")],
        eva_options={"partition-history": 1},
    )
    assert et.main(_finish_args(tune_run, ["slevel", "history"])) == 0
    capsys.readouterr()

    report = json.loads((tune_run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    assert report["status"] == "ok" and report["module"] == "m"
    assert report["unknown_count"] == 0 and report["surviving_unknown_functions"] == []
    tuning = report["tuning"]
    assert tuning["mode"] == "ladder" and tuning["selected"] == "slevel"
    assert tuning["before"]["unknown_count"] == 3 and tuning["after"]["unknown_count"] == 0
    assert tuning["combination"]["upgraded"][0]["proved_by"] == "history"
    assert report["entry_fn"] == "parse" and report["entry_reached"] is True and report["reachability"] == "ok"
    assert report["eva_coverage"]["functions_analyzed"] == 7

    decision = pm.load_params(tune_run)["modules"]["m"]["eva_tuned"]
    assert decision["rung"] == "slevel" and decision["options"] == {"slevel": 1000}
    assert [c["name"] for c in decision["contributors"]] == ["history"]
    assert decision["settings_digest"] == "dd" and decision["input_digest"] == "d1"
    assert (
        json.loads((tune_run / pm.TUNE_REPORT_DIR / "m/decision.json").read_text(encoding="utf-8"))["selected"]
        == "slevel"
    )


def test_finish_keeps_the_base_run_when_every_rung_is_rejected(tune_run, capsys):
    _write_trial(tune_run, "m", "base", [_csv_row(1), _csv_row(2)])
    _write_trial(tune_run, "m", "slevel", [_csv_row(1, "Dead"), _csv_row(2, "Dead")], eva_options={"slevel": 1000})
    _write_trial(tune_run, "m", "values", [_csv_row(1, "Valid"), _csv_row(2, "Valid")], text="aborted\n")
    assert et.main(_finish_args(tune_run, ["slevel", "values"])) == 0
    capsys.readouterr()
    report = json.loads((tune_run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    assert report["unknown_count"] == 2 and report["dead_count"] == 0
    rows = {r["name"]: r for r in report["tuning"]["runs"]}
    assert rows["base"]["verdict"] == "selected"
    assert rows["slevel"]["verdict"] == "rejected" and rows["slevel"]["reasons"] == ["dead_grew:2"]
    assert rows["values"]["reasons"][0].startswith("degenerated:")
    assert report["tuning"]["combination"]["runs"] == ["base"]


def test_a_rung_that_timed_out_leaves_more_unknowns_never_a_failure(tune_run, capsys):
    _write_trial(tune_run, "m", "base", [_csv_row(1), _csv_row(2)])
    write_json(tune_run / pm.TUNE_REPORT_DIR / "m/slevel.json", {"status": "analysis_timeout"})
    assert et.main(_finish_args(tune_run, ["slevel", "missing"])) == 0
    capsys.readouterr()
    report = json.loads((tune_run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    assert report["status"] == "ok" and report["unknown_count"] == 2
    rows = {r["name"]: r for r in report["tuning"]["runs"]}
    assert rows["slevel"]["reasons"] == ["not_completed:analysis_timeout"]
    assert rows["missing"]["reasons"] == ["not_completed:no_report"]


def test_finish_without_unknowns_records_nothing(tune_run, capsys):
    _write_trial(tune_run, "m", "base", [_csv_row(1, "Valid")])
    assert et.main(_finish_args(tune_run, [])) == 0
    capsys.readouterr()
    report = json.loads((tune_run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    assert report["tuning"]["mode"] == "skipped" and report["entry_reached"] is True
    assert "m" not in pm.load_params(tune_run)["modules"]


def test_finish_reports_a_failed_base_run_as_a_failure_never_as_zero_alarms(tune_run, capsys):
    write_json(tune_run / pm.TUNE_REPORT_DIR / "m/base.json", {"status": "analysis_error", "reason": "crashed"})
    assert et.main(_finish_args(tune_run, [])) == 1
    report = json.loads((tune_run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    capsys.readouterr()
    assert report["status"] == "analysis_error" and report["reason"] == "crashed"
    assert et.main(_finish_args(tune_run, [])) == 1
    capsys.readouterr()


def test_a_replay_uses_the_recorded_rung_and_keeps_the_record(tune_run, capsys):
    rows_base = [_csv_row(1), _csv_row(2)]
    _write_trial(tune_run, "m", "base", rows_base)
    _write_trial(tune_run, "m", "slevel", [_csv_row(1, "Valid"), _csv_row(2)], eva_options={"slevel": 1000})
    assert et.main(_finish_args(tune_run, ["slevel"])) == 0
    capsys.readouterr()
    first = json.loads((tune_run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    recorded = pm.load_params(tune_run)["modules"]["m"]["eva_tuned"]

    assert et.main(_finish_args(tune_run, ["slevel"])) == 0
    capsys.readouterr()
    second = json.loads((tune_run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    assert second["tuning"]["mode"] == "replay" and second["tuning"]["selected"] == "slevel"
    assert second["unknown_count"] == first["unknown_count"]
    assert pm.load_params(tune_run)["modules"]["m"]["eva_tuned"] == recorded

    # A slower machine does not finish the recorded rung: the base run stands, and the record survives it.
    write_json(tune_run / pm.TUNE_REPORT_DIR / "m/slevel.json", {"status": "analysis_timeout"})
    assert et.main(_finish_args(tune_run, ["slevel"])) == 0
    capsys.readouterr()
    slow = json.loads((tune_run / "workspace/reports/eva/m.json").read_text(encoding="utf-8"))
    assert slow["tuning"]["mode"] == "replay" and slow["tuning"]["selected"] == "base" and slow["unknown_count"] == 2
    assert pm.load_params(tune_run)["modules"]["m"]["eva_tuned"] == recorded


def _ledger_report(**fields) -> dict:
    return {
        "status": "ok",
        "module": "m",
        "sources": ["src/a.c"],
        "unknown_obligations_by_function": {},
        "functions_with_properties": ["parse"],
        "functions_with_properties_by_file": [{"directory": "workspace/work/src", "file": "a.c", "function": "parse"}],
        **fields,
    }


def test_the_ledger_records_that_a_proof_relied_on_combination(run_dir):
    write_json(
        run_dir / "coverage-ledger.json",
        [unit("src/a.c", "parse", "rte", module="m"), unit("src/a.c", "other", "rte", module="m")],
    )
    write_json(run_dir / "candidates.json", [])
    report = _ledger_report(
        tuning={
            "combination": {"upgraded": [{"function": "parse", "fingerprint": "x", "line": 1, "proved_by": "history"}]}
        },
    )
    report["functions_with_properties"] = ["parse", "other"]
    report["functions_with_properties_by_file"].append(
        {"directory": "workspace/work/src", "file": "a.c", "function": "other"}
    )
    write_json(run_dir / "workspace/reports/eva/m.json", report)
    L.cmd_ingest_eva([run_dir / "workspace/reports/eva/m.json"])
    ledger = {u["function"]: u for u in json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))}
    assert ledger["parse"]["status"] == "covered"
    notes = [a["description"] for a in ledger["parse"]["assumptions"]]
    assert any("per-obligation combination" in note for note in notes)
    assert not any("per-obligation combination" in a["description"] for a in ledger["other"]["assumptions"])


def test_a_report_without_tuning_ingests_exactly_as_before(run_dir):
    write_json(run_dir / "coverage-ledger.json", [unit("src/a.c", "parse", "rte", module="m")])
    write_json(run_dir / "candidates.json", [])
    write_json(run_dir / "workspace/reports/eva/m.json", _ledger_report())
    L.cmd_ingest_eva([run_dir / "workspace/reports/eva/m.json"])
    ledger = json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
    assert ledger[0]["status"] == "covered"
    assert not any("combination" in a["description"] for a in ledger[0]["assumptions"])


# ---------------------------------------------------------------------------
# GNU make (integration: needs make, e.g. inside the framac-pipeline container)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("make") is None, reason="GNU make not available")
def test_make_dry_run_of_the_ladder(tmp_path):
    run = _make_run(tmp_path)
    scripts = f"S={(REPO / 'scripts').as_posix()}"

    def make(*args):
        proc = subprocess.run(
            ["make", "-f", pm.MAKEFILE, scripts, "-n", *args], cwd=run, capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return proc.stdout.replace("\\n", " ")

    pm.generate(run, templates_dir=ACSL)
    out = make("eva-tune-base")
    assert "--out-dir workspace/eva/snmp/tune/base" in out and "evarung" not in out
    assert "eva_tuning.py finish --module snmp" in make("evatune-snmp"), "no rungs yet: finish alone"

    _base_report(run)
    pm.record_eva_tuning(run, "cfg", _record_for(run, "cfg"))
    pm.generate(run, templates_dir=ACSL)
    out = make("evatune-snmp")
    for rung in eo.RUNG_NAMES:
        assert f"--out-dir workspace/eva/snmp/tune/{rung}" in out
        assert f"--out-json workspace/reports/eva-tuning/snmp/{rung}.json" in out
    assert "--eva-option=slevel=1000" in out and "--timeout 800" in out
    assert out.index("run_eva_slice.py") < out.index("eva_tuning.py finish")
    assert "--settings-digest" in out and "--entry-fn=snmp_parse_pdu" in out and "--loop-unroll 256" in out

    # A recorded decision reaches plain `eva`, with its `#`-separated loop names through make intact.
    out = make("eva-cfg")
    assert "--eva-option=slevel=500" in out
    assert "--loop-unroll=workspace/work/a.c#f#0=64" in out
    assert "--mirror-root=workspace/eva/cfg/tune/mirrors/" in out
