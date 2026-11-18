r"""`ledger.py ingest-wp`: an `l3_frame` unit is credited only for a frame the WP report shows.

libmodbus run-1 (2026-11-18): the merged contract of `modbus_write_register` had no `assigns` clause, its WP
report was `all_proven`, and `by_obligation_class` counted one proven `l3_frame` goal. That goal was WP's
memory-model hypothesis of the callee, `precondition of write_single: \separated(ctx + (..), &__fc_errno)`,
classed as a frame goal because its text holds `\separated`. `ingest-wp` credits `l3_frame` from that count
(`wp_proven`), and from no count at all (`wp_qed_simplified`).

The WP logs and report CSVs are Frama-C's own output: tests/fixtures/wp_frame_clause/ (see
test_wp_frame_clause.py), and `run1_modbus_write_register.{log,csv}`, the parent re-check of that function in
libmodbus run-1 (`agents/prove-modbus_write_register/scratch/parent_wp/`), cut the same way. The reports are
built from them by run_wp_function.py; only `limits` (the consistency check, another Frama-C run) and the
run-relative `file` are set here.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import ledger as L
import run_wp_function as W
from conftest import evidence, metadata, unit, write_json
from framac_common import read_report_csv

pytestmark = pytest.mark.unit

FRAME_CREDIT_FIXTURES = Path(__file__).parent / "fixtures" / "wp_frame_clause"
FRAME_C = FRAME_CREDIT_FIXTURES / "src" / "frame.c"
RUN1_FN = "modbus_write_register"
RUN1_C = Path(__file__).parent / "fixtures" / "libmodbus_run1_contracts" / "modbus_write_register.c"
NO_ASSIGNS_WARNING = "No 'assigns' specification for function"


def _wp_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fn: str, name: str | None = None, log_filter=None):
    """run_wp_function.py's report for the recorded log and CSV `name` (default: the function's own)."""
    name = name or fn
    log = (FRAME_CREDIT_FIXTURES / f"{name}.log").read_text(encoding="utf-8")
    if log_filter is not None:
        log = log_filter(log)

    def fake(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-wp" in cmd and "-report-csv" in cmd:
            shutil.copyfile(FRAME_CREDIT_FIXTURES / f"{name}.csv", cmd[cmd.index("-report-csv") + 1])
            return subprocess.CompletedProcess(cmd, 0, stdout=log, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(W.subprocess, "run", fake)
    res = W.run_wp_on_function(
        RUN1_C if fn == RUN1_FN else FRAME_C,
        fn,
        tmp_path / "wp",
        cache_dir="off",
        retry_tail=False,
        retry_bitwise=False,
        retry_bytes=False,
        retry_cast_probe=False,
    )
    res["limits"] = {"vacuity": {"status": "consistent", "doomed": [], "dead_goals": 0}}
    res["file"] = "workspace/work/src/frame.c"
    return res


def _ingest(run_dir: Path, report: dict, *units: dict, sweep: bool = False) -> dict[str, dict]:
    fn = report["function"]
    write_json(run_dir / "run-metadata.json", metadata("in_progress"))
    write_json(
        run_dir / "coverage-ledger.json",
        list(units) or [unit("src/frame.c", fn, "rte"), unit("src/frame.c", fn, "l3_frame")],
    )
    path = run_dir / "workspace/reports/wp" / f"{fn}.json"
    write_json(path, report)
    L.cmd_ingest_wp([path], sweep=sweep)
    ledger = json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
    return {u["obligation_class"]: u for u in ledger}


# ------------------------------------------------------------------ the regression


def test_the_run1_report_credits_no_frame_for_a_contract_without_assigns(run_dir, tmp_path, monkeypatch):
    """The recorded parent re-check: `all_proven`, five goals, no `assigns` clause, one `\\separated` precondition."""
    report = _wp_report(tmp_path, monkeypatch, RUN1_FN, f"run1_{RUN1_FN}")
    assert report["status"] == "all_proven"
    assert report["frame_summary"]["assigns_clause"] == "absent"
    # The callee's memory-model precondition is a call-site goal, not a frame goal.
    assert "l3_frame" not in report["by_obligation_class"]
    assert report["by_obligation_class"]["rte"]["proven"] == 4
    units = _ingest(run_dir, report)
    assert units["rte"]["status"] == "covered"
    frame = units["l3_frame"]
    assert frame["status"] == "planned" and frame["assumptions"] == []
    last = frame["evidence"][-1]
    assert last["result"] == "wp_no_frame_clause" and last["discharging"] is False
    assert "has no `assigns` clause" in last["summary"] and RUN1_FN in last["summary"]


@pytest.mark.parametrize("fn", ["post_only", "bare", "on_header_post_only"])
def test_no_frame_goal_at_all_is_not_a_frame_qed_discharged(run_dir, tmp_path, monkeypatch, fn):
    """Zero goals of the class and `all_proven` used to read as `wp_qed_simplified`."""
    report = _wp_report(tmp_path, monkeypatch, fn)
    assert report["status"] == "all_proven" and "l3_frame" not in report["by_obligation_class"]
    units = _ingest(run_dir, report)
    assert units["rte"]["status"] == "covered"
    assert units["l3_frame"]["status"] == "planned"
    assert units["l3_frame"]["evidence"][-1]["result"] == "wp_no_frame_clause"


@pytest.mark.parametrize("fn", ["guarded_some", "guarded_gap"])
def test_proven_assigns_of_named_behaviors_that_do_not_cover_the_function_are_not_its_frame(
    run_dir, tmp_path, monkeypatch, fn
):
    """The report counts a proven `assigns clause` row: it is the clause of behavior `pos` only."""
    report = _wp_report(tmp_path, monkeypatch, fn)
    assert report["status"] == "all_proven" and report["by_obligation_class"]["l3_frame"]["proven"] >= 1
    assert report["frame_summary"]["assigns_clause"] == "behaviors_only"
    units = _ingest(run_dir, report)
    assert units["l3_frame"]["status"] == "planned"
    last = units["l3_frame"]["evidence"][-1]
    assert last["result"] == "wp_no_frame_clause" and "named behaviors only (pos)" in last["summary"]


def _without_warning(log: str) -> str:
    """The log as a run would print it had WP not said that the contract has no frame."""
    lines = log.splitlines()
    drop = {i + d for i, line in enumerate(lines) if NO_ASSIGNS_WARNING in line for d in (-1, 0, 1)}
    return "\n".join(line for i, line in enumerate(lines) if i not in drop) + "\n"


def test_unknown_is_never_a_frame_even_with_a_proven_assigns_row(run_dir, tmp_path, monkeypatch):
    """
    The report CSV does not say which behavior an `assigns clause` row belongs to. Without WP's warning the
    state of `guarded_some` reads `unknown`, its one row is proven, and the frame is still not the function's.
    """
    report = _wp_report(tmp_path, monkeypatch, "guarded_some", log_filter=_without_warning)
    assert report["status"] == "all_proven" and report["by_obligation_class"]["l3_frame"]["proven"] == 1
    # `Assigns for 'pos'` is listed, so the reader says `present`; force the state a filtered run reports.
    report["frame_summary"].update(assigns_clause="unknown", assigns_clause_basis=None)
    units = _ingest(run_dir, report)
    assert units["rte"]["status"] == "covered"
    assert units["l3_frame"]["status"] == "planned"
    last = units["l3_frame"]["evidence"][-1]
    assert last["result"] == "wp_frame_not_shown" and "assigns_clause: unknown" in last["summary"]


def test_a_report_written_before_the_field_shows_no_frame(run_dir, tmp_path, monkeypatch):
    report = _wp_report(tmp_path, monkeypatch, "pure_ok")
    for key in ("assigns_clause", "assigns_clause_basis", "assigns_behaviors"):
        del report["frame_summary"][key]
    units = _ingest(run_dir, report)
    assert units["rte"]["status"] == "covered" and units["l3_frame"]["status"] == "planned"
    assert "assigns_clause: not recorded" in units["l3_frame"]["evidence"][-1]["summary"]


def test_a_frame_the_report_calls_unproven_is_not_credited(run_dir, tmp_path, monkeypatch):
    report = _wp_report(tmp_path, monkeypatch, "pure_ok")
    report["frame_summary"]["assigns_vcs_proven"] = False
    units = _ingest(run_dir, report)
    assert units["l3_frame"]["status"] == "planned"
    assert units["l3_frame"]["evidence"][-1]["result"] == "wp_frame_not_shown"


def test_the_sweep_blocks_a_frame_unit_the_reproof_shows_no_frame_for(run_dir, tmp_path, monkeypatch):
    """A unit credited before the fix: the trusted end-of-run re-proof does not credit it again."""
    report = _wp_report(tmp_path, monkeypatch, RUN1_FN, f"run1_{RUN1_FN}")
    proven = {**evidence("wp", "wp_proven"), "producer": "run_wp_function.py", "details": {"limits": report["limits"]}}
    covered = unit("src/frame.c", RUN1_FN, "l3_frame", status="covered", evidence=[proven])
    units = _ingest(run_dir, report, unit("src/frame.c", RUN1_FN, "rte"), covered, sweep=True)
    assert units["rte"]["status"] == "covered"
    assert units["l3_frame"]["status"] == "blocked"
    assert [e["result"] for e in units["l3_frame"]["evidence"][-2:]] == ["wp_no_frame_clause", "wp_sweep_not_reproven"]


# ------------------------------------------------------------------ controls


@pytest.mark.parametrize("fn", ["pure_ok", "on_header", "guarded_all"])
def test_a_proven_assigns_clause_is_still_credited(run_dir, tmp_path, monkeypatch, fn):
    """`assigns \\nothing`, a clause on the header prototype, complete behaviors that each have a clause."""
    report = _wp_report(tmp_path, monkeypatch, fn)
    assert report["status"] == "all_proven" and report["frame_summary"]["assigns_clause"] == "present"
    units = _ingest(run_dir, report)
    assert units["rte"]["status"] == "covered"
    assert units["l3_frame"]["status"] == "covered"
    assert units["l3_frame"]["evidence"][-1]["result"] == "wp_proven"


def test_an_unproven_assigns_clause_still_blocks_the_frame_unit(run_dir, tmp_path, monkeypatch):
    report = _wp_report(tmp_path, monkeypatch, "pure_broken")
    units = _ingest(run_dir, report)
    assert units["l3_frame"]["status"] == "blocked"
    assert units["l3_frame"]["evidence"][-1]["result"] == "wp_unproven"


def test_other_classes_do_not_depend_on_the_frame(run_dir, tmp_path, monkeypatch):
    """`l2_termination` keeps its zero-goal credit on the report that shows no frame."""
    report = _wp_report(tmp_path, monkeypatch, "post_only")
    loops = unit("src/frame.c", "post_only", "l2_termination")
    units = _ingest(run_dir, report, unit("src/frame.c", "post_only", "rte"), loops)
    assert units["rte"]["status"] == "covered" and units["l2_termination"]["status"] == "covered"


# ------------------------------------------------------------------ the goal classes, on the real rows


def _rows(name: str) -> list[dict]:
    return read_report_csv(FRAME_CREDIT_FIXTURES / f"{name}.csv")


def test_a_separated_precondition_of_a_callee_is_not_a_frame_goal():
    rows = _rows(f"run1_{RUN1_FN}")
    hypothesis = next(r for r in rows if r["kind"] == "precondition of write_single")
    assert hypothesis["property"] == "\\separated(ctx + (..), &__fc_errno)"
    assert W.goal_obligation_class({"kind": hypothesis["kind"], "annotation": hypothesis["property"]}) == "rte"
    assert {W.goal_obligation_class({"kind": r["kind"], "annotation": r["property"]}) for r in rows} == {"rte"}


def test_the_frame_goals_of_the_fixtures_are_the_assigns_rows():
    """Every row of every recorded CSV: `l3_frame` exactly for the kind `assigns clause`."""
    seen = 0
    for path in sorted(FRAME_CREDIT_FIXTURES.glob("*.csv")):
        for row in read_report_csv(path):
            cls = W.goal_obligation_class({"kind": row["kind"], "annotation": row["property"]})
            assert (cls == "l3_frame") == (row["kind"] == "assigns clause"), (path.name, row)
            seen += row["kind"] == "assigns clause"
    assert seen >= 8


@pytest.mark.parametrize(
    ("kind", "annotation", "expected"),
    [
        # Report kinds: the predicate of a requires or an ensures states no frame.
        ("precondition", "separation: \\separated(dest + (0 .. n - 1), src + (0 .. n - 1))", "rte"),
        ("precondition of memcpy", "separation: \\separated(dest + (0 .. n - 1), src + (0 .. n - 1))", "rte"),
        ("postcondition", "\\separated(&__fc_errno, &ctx->set_rts)", "rte"),
        # Unchanged: the clauses that state a frame, and the items ledger.py builds for a prover's or a
        # fuzzer's predicate (their class is part of a candidate's fingerprint).
        ("assigns clause", "assigns \\nothing;", "l3_frame"),
        ("from clause", "assigns \\result \\from number;", "l3_frame"),
        ("loop assigns", "loop assigns i, dest[0 .. n - 1];", "l3_frame"),
        ("assertion", "\\separated(p, q)", "l3_frame"),
        ("user assertion", "\\separated(p + (0 .. 3), &g)", "l3_frame"),
        ("postcondition", "L6_no_leak_k: meta: \\separated(p, &k)", "l6_no_leak"),
    ],
)
def test_goal_classes_by_report_kind(kind, annotation, expected):
    assert W.goal_obligation_class({"kind": kind, "annotation": annotation}) == expected
