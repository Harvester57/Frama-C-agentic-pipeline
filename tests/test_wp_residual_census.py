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


def _cost(prop: str | None, kind: str) -> dict:
    return {"goal": f"typed_f_{prop}", "property": prop, "verdict_kind": kind, "provers": ["alt-ergo"], "time_ms": 10}


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
    # Costs pair one-to-one through property; all timeouts.
    _write(
        run,
        "timeouts",
        _report(
            "timeouts",
            [_goal(20, "q1"), _goal(21, "q2", bucket="step_b_loop_invariant")],
            9,
            costs=[_cost("q2", "stepout"), _cost("q1", "timeout")],
        ),
    )
    # A repeated property: no pairing, distribution only.
    _write(
        run,
        "split",
        _report(
            "split",
            [_goal(30, "r"), _goal(31, "r")],
            4,
            costs=[_cost("r", "timeout"), _cost("r", "unknown")],
        ),
    )
    # Many unproved goals, one failed: not a near miss, not timeouts only.
    many = [_goal(40 + i, f"s{i}") for i in range(5)]
    _write(run, "many", _report("many", many, 12, costs=[_cost(f"s{i}", "failed") for i in range(5)]))
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


def test_join_by_property(census_run: Path) -> None:
    data = census_mod.census(census_run)
    rec = _by_fn(data)["timeouts"]
    assert rec["join"] == "by_property"
    goals = {g["line"]: g["verdict_kind"] for g in data["near_miss_goals"] if g["function"] == "timeouts"}
    assert goals == {20: "timeout", 21: "stepout"}


def test_join_fallback_on_repeated_property(census_run: Path) -> None:
    data = census_mod.census(census_run)
    rec = _by_fn(data)["split"]
    assert rec["join"] == "per_function_only"
    assert rec["by_verdict"] == {"timeout": 1, "unknown": 1}
    assert {g["verdict_kind"] for g in data["near_miss_goals"] if g["function"] == "split"} == {"unjoined"}
    assert data["join"] == "per_function_only"
    assert data["join_by_function"] == {"by_property": 2, "per_function_only": 2}


@pytest.mark.parametrize(
    ("goals", "costs", "expected"),
    [
        ([{"annotation": "a"}], [{"property": "a", "verdict_kind": "timeout"}], ["timeout"]),
        ([{"annotation": "a"}], [{"property": None, "verdict_kind": "timeout"}], None),
        ([{"annotation": "a"}], [{"property": "b", "verdict_kind": "timeout"}], None),
        ([{"annotation": "a"}, {"annotation": "b"}], [{"property": "a", "verdict_kind": "timeout"}], None),
    ],
)
def test_join_by_property_rules(goals: list[dict], costs: list[dict], expected: list[str] | None) -> None:
    assert census_mod.join_by_property(goals, costs) == expected


def test_timeouts_only_and_near_miss(census_run: Path) -> None:
    data = census_mod.census(census_run, near_miss=3)
    assert [w["function"] for w in data["would_be_all_proven_if_timeouts_closed"]] == ["timeouts"]
    assert {n["function"] for n in data["near_miss_functions"]} == {"legacy", "timeouts", "split"}
    assert "many" not in {g["function"] for g in data["near_miss_goals"]}
    assert any("record no verdict kinds" in n for n in data["notes"])
    totals = data["totals"]
    assert totals["unproved"] == 11
    assert totals["unproved_by_verdict"] == {"failed": 5, "stepout": 1, "timeout": 2, "unknown": 1, "unrecorded": 2}
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
    costs = [_cost("x", "timeout"), _cost("x", "timeout")]
    _write(run, "twice", _report("twice", [_goal(1, "x")], 3, costs=costs))
    data = census_mod.census(run)
    assert data["totals"]["unproved_by_verdict"] == {"timeout": 2}
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
