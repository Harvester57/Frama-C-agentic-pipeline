"""Tests for scripts/wp_residual_census.py (Tier 2a: census of residual WP goals)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import wp_residual_census as census_mod

pytestmark = pytest.mark.unit


def _goal(line: int, annotation: str, cls: str = "rte", bucket: str = "step_c_rte_obligation") -> dict:
    return {
        "file": "a.c",
        "function": "f",
        "line": line,
        "kind": "mem_access",
        "status": "Unknown",
        "annotation": annotation,
        "obligation_class": cls,
        "diagnostic_bucket": bucket,
    }


def _cost(prop: str | None, kind: str, line: int | None = None, file: str | None = "/w/a.c") -> dict:
    """A cost as run_wp_function.py writes it; `line=None` is a cost from the log (no location)."""
    return {
        "goal": f"typed_f_{prop}",
        "property": prop,
        "file": file if line is not None else None,
        "line": line,
        "verdict_kind": kind,
        "provers": ["alt-ergo"],
        "time_ms": 10,
    }


def _row(line: int, kind: str, annotation: str = "p") -> dict:
    return {
        "file": "probe.c",
        "function": "f",
        "line": line,
        "kind": kind,
        "status": "Unknown",
        "annotation": annotation,
    }


# The unproved rows and goals of one real run (Frama-C 34, `-wp-report-csv` beside `-wp-report-json`
# on the same function): the CSV row has the predicate text, the JSON goal has WP's property name.
# Lines, kinds and property names are the run's; two of its ten timeouts are set to `unknown` here.
_PROBE_ROWS = [
    _row(4, "postcondition", "bad: \\result == 42"),
    _row(5, "postcondition", "\\result >= 0"),
    _row(10, "loop invariant", "s == i"),
    _row(15, "signed_overflow", "s + *(a + i) <= 2147483647"),
    _row(16, "signed_overflow", "-2147483648 <= s + (int)(*(a + i) * x)"),
    _row(16, "signed_overflow", "s + (int)(*(a + i) * x) <= 2147483647"),
    _row(16, "signed_overflow", "*(a + i) * x <= 2147483647"),
    _row(16, "signed_overflow", "-2147483648 <= *(a + i) * x"),
    _row(18, "user assertion", "s != 7"),
    _row(19, "signed_overflow", "s + x <= 2147483647"),
]
_PROBE_COSTS = [
    _cost("f_ensures_bad", "timeout", 4, "/w/probe.c"),
    _cost("f_ensures", "timeout", 5, "/w/probe.c"),
    _cost("f_loop_invariant_wrong", "timeout", 10, "/w/probe.c"),
    _cost("f_assert_rte_signed_overflow_2", "timeout", 15, "/w/probe.c"),
    _cost("f_assert_rte_signed_overflow_3", "timeout", 16, "/w/probe.c"),
    _cost("f_assert_rte_signed_overflow_4", "unknown", 16, "/w/probe.c"),
    _cost("f_assert_rte_signed_overflow_5", "timeout", 16, "/w/probe.c"),
    _cost("f_assert_rte_signed_overflow_6", "timeout", 16, "/w/probe.c"),
    _cost("f_assert", "unknown", 18, "/w/probe.c"),
    _cost("f_assert_rte_signed_overflow_9", "timeout", 19, "/w/probe.c"),
]


def _report(fn: str, goals: list[dict], total: int, costs: list[dict] | None = None, **extra) -> dict:
    status = "unproven_goals_remain" if goals else "all_proven"
    report = {
        "status": status,
        "function": fn,
        "file": f"/framac-run/workspace/work/src/{fn}.c",
        "total_goals": total,
        "proven_count": total - len(goals),
        "proven_under_hyp_count": 0,
        "unproven_count": len(goals),
        "unproven_goals": [{**g, "function": fn} for g in goals],
    }
    if costs is not None:
        report["unproven_goal_costs"] = costs
    report.update(extra)
    return report


def _write(run: Path, name: str, payload: object) -> None:
    wp = run / "workspace" / "reports" / "wp"
    wp.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload)
    (wp / f"{name}.json").write_text(text, encoding="utf-8")


@pytest.fixture
def census_run(tmp_path: Path) -> Path:
    run = tmp_path / "run"
    # Fully proved.
    _write(run, "proved", _report("proved", [], 5))
    # Old report: no unproven_goal_costs.
    _write(run, "legacy", _report("legacy", [_goal(10, "p1"), _goal(11, "p2", cls="l2_termination")], 6))
    # Each row pairs with the cost at its line and of its kind; all timeouts.
    _write(
        run,
        "timeouts",
        _report(
            "timeouts",
            [_goal(20, "q1"), _goal(21, "q2", bucket="step_b_loop_invariant")],
            9,
            costs=[
                _cost("timeouts_assert_rte_mem_access_2", "stepout", 21),
                _cost("timeouts_assert_rte_mem_access", "timeout", 20),
            ],
        ),
    )
    # Costs from the log carry no line: no pairing, distribution only.
    _write(
        run,
        "split",
        _report("split", [_goal(30, "r"), _goal(31, "r")], 4, costs=[_cost(None, "timeout"), _cost(None, "unknown")]),
    )
    # Many unproved goals, all failed: not a near miss, not timeouts only.
    many = [_goal(40 + i, f"s{i}") for i in range(5)]
    many_costs = [_cost(f"many_assert_rte_mem_access_{i}", "failed", 40 + i) for i in range(5)]
    _write(run, "many", _report("many", many, 12, costs=many_costs))
    # Not a per-function report, a guardrail report, and an unreadable one.
    _write(run, "guard", {"mode": "guardrail", "function": "g", "status": "passed_dynamic_oracle"})
    _write(run, "notes", {"something": "else"})
    _write(run, "broken", "{not json")
    # Scratch output beside the reports must not be read.
    work = run / "workspace" / "reports" / "wp" / "work"
    work.mkdir()
    (work / "inner.json").write_text("{not json", encoding="utf-8")
    return run


def _by_fn(data: dict) -> dict[str, dict]:
    return {r["function"]: r for r in data["functions"]}


def test_report_counts_fail_closed(census_run: Path) -> None:
    data = census_mod.census(census_run)
    reports = data["reports"]
    assert reports["read"] == 5
    assert reports["skipped"] == 2
    assert reports["unreadable"] == 1
    assert reports["unreadable_reports"][0]["report"] == "workspace/reports/wp/broken.json"
    assert {s["report"] for s in reports["skipped_reports"]} == {
        "workspace/reports/wp/guard.json",
        "workspace/reports/wp/notes.json",
    }
    assert any("readable reports only" in n for n in data["notes"])


def test_fully_proved_function(census_run: Path) -> None:
    rec = _by_fn(census_mod.census(census_run))["proved"]
    assert rec["status"] == "all_proven"
    assert (rec["proved"], rec["total_goals"], rec["unproved"]) == (5, 5, 0)
    assert rec["join"] is None and rec["by_verdict"] == {}


def test_legacy_report_is_unrecorded(census_run: Path) -> None:
    data = census_mod.census(census_run)
    rec = _by_fn(data)["legacy"]
    assert rec["verdicts_recorded"] is False
    assert rec["by_verdict"] == {"unrecorded": 2}
    assert rec["by_class"] == {"l2_termination": 1, "rte": 1}
    assert rec["join"] == "per_function_only"
    assert rec["file"] == "src/legacy.c"
    legacy_goals = [g for g in data["near_miss_goals"] if g["function"] == "legacy"]
    assert [g["verdict_kind"] for g in legacy_goals] == ["unrecorded", "unrecorded"]


def test_join_by_line_and_kind(census_run: Path) -> None:
    data = census_mod.census(census_run)
    rec = _by_fn(data)["timeouts"]
    assert rec["join"] == "by_line_and_kind"
    assert rec["rows_by_verdict"] == {"stepout": 1, "timeout": 1}
    goals = {g["line"]: g["verdict_kind"] for g in data["near_miss_goals"] if g["function"] == "timeouts"}
    assert goals == {20: "timeout", 21: "stepout"}


def test_join_fallback_on_costs_without_a_line(census_run: Path) -> None:
    data = census_mod.census(census_run)
    rec = _by_fn(data)["split"]
    assert rec["join"] == "per_function_only"
    assert rec["by_verdict"] == {"timeout": 1, "unknown": 1}
    assert rec["unpaired_costs"] == 2
    assert {g["verdict_kind"] for g in data["near_miss_goals"] if g["function"] == "split"} == {"unjoined"}
    assert data["join"] == "partial"
    assert data["join_by_function"] == {"by_line_and_kind": 2, "per_function_only": 2}
    assert any("paired with no unproved report row" in n for n in data["notes"])


def test_join_on_a_real_report_pair() -> None:
    kinds, unpaired = census_mod.join_by_line(_PROBE_ROWS, _PROBE_COSTS, "f")
    # Line 16 has four rows and four goals of one kind that disagree: each row is `mixed`, since
    # nothing says which goal belongs to which row. Line 15 pairs although a proved goal of the
    # same kind sits on it (a proved goal has no cost).
    assert kinds == [
        "timeout",
        "timeout",
        "timeout",
        "timeout",
        "mixed",
        "mixed",
        "mixed",
        "mixed",
        "unknown",
        "timeout",
    ]
    assert unpaired == 0


@pytest.mark.parametrize(
    ("kind", "prop", "expected"),
    [
        ("signed_overflow", "f_assert_rte_signed_overflow_3", True),
        ("signed_overflow", "f_assert_rte_unsigned_overflow", False),
        ("unsigned_overflow", "f_assert_rte_unsigned_overflow", True),
        ("signed_downcast", "f_assert_rte_unsigned_downcast_2", False),
        ("mem_access", "f_assert_rte_signed_overflow", False),
        ("postcondition", "f_ensures_bad", True),
        ("postcondition", "f_assert_rte_mem_access", False),
        ("loop invariant", "f_loop_invariant_wrong", True),
        ("loop invariant", "f_loop_variant", False),
        ("assigns clause", "f_loop_assigns", True),
        ("user assertion", "f_assert", True),
        ("user assertion", "f_assert_rte_mem_access", False),
        # The function's own name is not read as a kind token.
        ("postcondition", "check_ensures_ensures", True),
        ("user assertion", "check_ensures_ensures", False),
        # A kind the mapping does not know pairs on the line alone.
        ("instance of something", "f_whatever", True),
    ],
)
def test_kind_matches(kind: str, prop: str, expected: bool) -> None:
    function = "check_ensures" if prop.startswith("check_ensures") else "f"
    assert census_mod._kind_matches(kind, prop, function) is expected


@pytest.mark.parametrize(
    ("goals", "costs", "expected"),
    [
        # Same line and kind: paired.
        ([_row(3, "mem_access")], [_cost("f_assert_rte_mem_access", "timeout", 3, "/w/probe.c")], (["timeout"], 0)),
        # Another line, another kind, another file name: no candidate.
        ([_row(3, "mem_access")], [_cost("f_assert_rte_mem_access", "timeout", 4, "/w/probe.c")], (["unjoined"], 1)),
        ([_row(3, "mem_access")], [_cost("f_ensures", "timeout", 3, "/w/probe.c")], (["unjoined"], 1)),
        ([_row(3, "mem_access")], [_cost("f_assert_rte_mem_access", "timeout", 3, "/w/other.h")], (["unjoined"], 1)),
        # A cost from the log has no line and is never a candidate.
        ([_row(3, "mem_access")], [_cost(None, "timeout")], (["unjoined"], 1)),
        # A row whose line is text still pairs, and so does a cost without a file name.
        (
            [{**_row(3, "mem_access"), "line": "3"}],
            [{**_cost("f_assert_rte_mem_access", "failed", 3), "file": None}],
            (["failed"], 0),
        ),
        # Two rows, one cost: one row has no cost of its own, and nothing says which.
        (
            [_row(3, "mem_access"), _row(3, "mem_access")],
            [_cost("f_assert_rte_mem_access", "timeout", 3, "/w/probe.c")],
            (["unjoined", "unjoined"], 1),
        ),
        # One row split into two goals that agree.
        (
            [_row(9, "loop invariant")],
            [_cost("f_loop_invariant", "timeout", 9, "probe.c"), _cost("f_loop_invariant", "timeout", 9, "probe.c")],
            (["timeout"], 0),
        ),
    ],
)
def test_join_by_line_rules(goals: list[dict], costs: list[dict], expected: tuple[list[str], int]) -> None:
    assert census_mod.join_by_line(goals, costs, "f") == expected


def test_timeouts_only_and_near_miss(census_run: Path) -> None:
    data = census_mod.census(census_run, near_miss=3)
    assert [w["function"] for w in data["would_be_all_proven_if_timeouts_closed"]] == ["timeouts"]
    assert {n["function"] for n in data["near_miss_functions"]} == {"legacy", "timeouts", "split"}
    assert "many" not in {g["function"] for g in data["near_miss_goals"]}
    assert any("record no verdict kinds" in n for n in data["notes"])
    totals = data["totals"]
    assert totals["unproved"] == 11
    assert totals["unproved_by_verdict"] == {"failed": 5, "stepout": 1, "timeout": 2, "unknown": 1, "unrecorded": 2}
    assert totals["unproved_rows_by_verdict"] == {
        "failed": 5,
        "stepout": 1,
        "timeout": 1,
        "unjoined": 2,
        "unrecorded": 2,
    }
    # No fixture report names its provers, so the merged-verdict caveat is stated.
    assert any("upper bound" in n for n in data["notes"])
    assert totals["functions_by_status"] == {"all_proven": 1, "unproven_goals_remain": 4}


def test_all_unrecorded_leaves_timeouts_list_empty_with_note(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write(run, "legacy", _report("legacy", [_goal(1, "x")], 2))
    data = census_mod.census(run)
    assert data["would_be_all_proven_if_timeouts_closed"] == []
    assert any("no report with unproved goals records verdict kinds" in n for n in data["notes"])


def test_undecided_status_is_named(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write(run, "dead", _report("dead", [], 0, status="analysis_error"))
    data = census_mod.census(run)
    assert data["functions_without_decided_goals"] == [
        {"file": "src/dead.c", "function": "dead", "status": "analysis_error"}
    ]
    assert data["near_miss_functions"] == []


def test_verdict_and_row_count_difference_is_noted(tmp_path: Path) -> None:
    run = tmp_path / "run"
    costs = [_cost("twice_assert_rte_mem_access", "timeout", 1), _cost("twice_assert_rte_mem_access", "timeout", 1)]
    _write(run, "twice", _report("twice", [_goal(1, "x")], 3, costs=costs, wp_provers=["alt-ergo"]))
    data = census_mod.census(run)
    assert data["totals"]["unproved_by_verdict"] == {"timeout": 2}
    assert data["totals"]["unproved_rows_by_verdict"] == {"timeout": 1}
    assert data["join"] == "by_line_and_kind"
    # One prover: the verdict is that prover's own, so no merged-verdict caveat.
    assert not any("upper bound" in n for n in data["notes"])
    assert any("verdict kinds count WP goals (2)" in n for n in data["notes"])
    assert [w["function"] for w in data["would_be_all_proven_if_timeouts_closed"]] == ["twice"]


def test_bad_shape_is_unreadable(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write(run, "odd", _report("odd", [], 1, unproven_goals="nope"))
    _write(run, "list", [1, 2])
    data = census_mod.census(run)
    assert data["reports"]["read"] == 0
    assert data["reports"]["unreadable"] == 2


def test_ambiguous_names_from_ledger(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write(run, "helper", _report("helper", [], 1))
    ledger = [
        {"file": "workspace/work/a.c", "function": "helper", "status": "covered"},
        {"file": "workspace/work/b.c", "function": "helper", "status": "blocked"},
        {"file": "x.c", "function": "main", "status": "out_of_scope"},
        {"file": "y.c", "function": "main", "status": "out_of_scope"},
    ]
    (run / "coverage-ledger.json").write_text(json.dumps(ledger), encoding="utf-8")
    data = census_mod.census(run)
    assert data["ambiguous_function_names"] == [{"function": "helper", "files": ["a.c", "b.c"]}]


def test_missing_report_dir_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert census_mod.main(["--run-dir", str(tmp_path)]) == 2
    assert "no WP report directory" in capsys.readouterr().err


def test_table_rendering_escapes_cells(census_run: Path) -> None:
    _write(census_run, "pipe", _report("pipe", [_goal(7, "a ||\n b")], 3))
    text = census_mod.render_table(census_mod.census(census_run))
    assert "## WP residual census" in text
    assert "### Would be all proven if timeouts closed" in text
    assert "| timeouts | src/timeouts.c |" in text
    assert "a \\|\\| b" in text
    assert "workspace/reports/wp/broken.json" in text
    for line in text.splitlines():
        if line.startswith("| src/pipe.c"):
            assert line.count(" | ") == 7


def test_cli_writes_only_out_file(census_run: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    before = sorted(p.relative_to(census_run).as_posix() for p in census_run.rglob("*"))
    out_json = tmp_path / "out" / "census.json"
    out_md = tmp_path / "out" / "census.md"
    assert census_mod.main(["--run-dir", str(census_run), "--out", str(out_json)]) == 0
    assert census_mod.main(["--run-dir", str(census_run), "--out", str(out_md), "--format", "table"]) == 0
    assert "unreadable WP report" in capsys.readouterr().err
    assert sorted(p.relative_to(census_run).as_posix() for p in census_run.rglob("*")) == before
    assert json.loads(out_json.read_text(encoding="utf-8"))["reports"]["read"] == 5
    assert out_md.read_bytes().count(b"\r\n") == 0
    assert out_md.read_text(encoding="utf-8").startswith("## WP residual census")


def test_cli_stdout_json(census_run: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert census_mod.main(["--run-dir", str(census_run), "--near-miss", "5"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["near_miss_max"] == 5
    assert "many" in {n["function"] for n in data["near_miss_functions"]}
