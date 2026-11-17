"""
R1 of docs/plans/header-entry-points-plan.md: the dynamic reach row reports the public header functions
(the Phase 0 model's `header_api`) the corpus never executed, and the run report prints them. They are
not entry points, so no gate decision changes. Fixtures are synthetic: the tests write the run directory.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import generate_report
import harness_reach
import phase0_gates
from test_harness_reach import _coverage, _dynamic_doc, _run_dir, _write_fuzz_report, _write_harness
from test_harness_reach_crash_credit import TWO_CASES, _crash, _crash_art, _dispatch, _sanitizer_failure
from validate_artifacts import validate_dynamic_reach

pytestmark = pytest.mark.unit


def _hr_header_fn(name: str) -> dict:
    return {
        "name": name,
        "file": "include/api.h",
        "module": "api",
        "is_static": True,
        "header": True,
        "internal_callees": [],
    }


def _hr_setup(run: Path, header_api: list[str] | None) -> None:
    """The `api` module is the link unit `libapi.a`; its model unit lists `header_api` unless None."""
    dag_path = run / "workspace" / "reports" / "callgraph_dag.json"
    dag = json.loads(dag_path.read_text(encoding="utf-8"))
    dag["modules"]["api"]["unit"] = "libapi.a"
    for name in ("api_get_a", "api_get_b", "api_get_c"):
        dag["functions"][name] = _hr_header_fn(name)
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    unit: dict = {"kind": "static_lib", "test": False}
    if header_api is not None:
        unit["header_api"] = header_api
    model = {"units": {"libapi.a": unit}}
    (run / "workspace" / "reports" / "phase0_model.json").write_text(json.dumps(model), encoding="utf-8")


def _hr_three() -> list[str]:
    return ["include/api.h#api_get_a", "include/api.h#api_get_b", "include/api.h#api_get_c"]


def _hr_passing_run(tmp_path: Path, monkeypatch, header_api: list[str] | None) -> Path:
    """Every entry point executed (rec_print exempted): the gate passes. api_get_a ran, api_get_b
    has 0 executions, api_get_c is not in the coverage report."""
    run = _run_dir(tmp_path, monkeypatch)
    _hr_setup(run, header_api)
    hdir = _write_harness(
        run, "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 1);", reach_exempt={"rec_print": "debug"}
    )
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0
    _coverage(run, {"rec_parse": 20, "rec_put": 4, "api_get_a": 7, "api_get_b": 0})
    assert harness_reach.main(["dynamic", "--module", "api"]) == 0
    return run


def _hr_gate_unchanged(run: Path) -> dict:
    doc = _dynamic_doc(run)
    row = doc["modules"]["api"]
    assert row["passed"] is True and row["gaps"] == []
    assert row["entry_points"] == 3 and row["entry_points_executed"] == 2
    assert "warnings" not in doc and not validate_dynamic_reach(doc)
    assert phase0_gates.check(run, "api", ("reach",)) == []
    assert phase0_gates.dynamic_gaps(run) == {}
    return row


def test_unexecuted_header_functions_are_reported_and_the_gate_still_passes(tmp_path, monkeypatch):
    run = _hr_passing_run(tmp_path, monkeypatch, _hr_three())
    row = _hr_gate_unchanged(run)
    assert row["header_api_functions"] == 3
    # One with 0 executions, one the report does not list (D21): both never ran. DAG keys, sorted.
    assert row["header_api_unexecuted"] == {"count": 2, "functions": ["api_get_b", "api_get_c"]}


def test_a_model_without_header_api_gives_a_row_as_before(tmp_path, monkeypatch):
    run = _hr_passing_run(tmp_path, monkeypatch, None)
    row = _hr_gate_unchanged(run)
    assert "header_api_functions" not in row and "header_api_unexecuted" not in row
    assert generate_report.header_api_lines(run) == []


def test_an_empty_header_api_is_reported_as_zero(tmp_path, monkeypatch):
    run = _hr_passing_run(tmp_path, monkeypatch, [])
    row = _hr_gate_unchanged(run)
    assert row["header_api_functions"] == 0
    assert row["header_api_unexecuted"] == {"count": 0, "functions": []}


def test_the_name_list_is_bounded_and_the_count_is_not(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    _hr_setup(run, [])
    dag = json.loads((run / "workspace/reports/callgraph_dag.json").read_text(encoding="utf-8"))
    mm = harness_reach.ModuleMap(dag, {})
    ids = [f"include/api.h#api_h{i:02d}" for i in range(25)]
    model = {"units": {"libapi.a": {"header_api": ids}}}
    fields = harness_reach._header_api_fields("api", dag, mm, model, {})
    assert fields["header_api_functions"] == 25
    never = fields["header_api_unexecuted"]
    # Not DAG functions: the model id is the name.
    assert never["count"] == 25 and never["functions"] == sorted(ids)[: harness_reach._HEADER_API_NAMES_MAX]


def test_a_sub_module_counts_the_header_functions_in_its_scope(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    _hr_setup(run, _hr_three())
    dag = json.loads((run / "workspace/reports/callgraph_dag.json").read_text(encoding="utf-8"))
    dag["module_kind"] = "link_unit"
    dag["modules"]["api"]["functions"] += ["api_get_a", "api_get_b"]  # api_get_c is homed elsewhere
    mm = harness_reach.ModuleMap(dag, {"api_sub": {"unit": "api", "scope_files": ["include/api.h"]}})
    model = {"units": {"libapi.a": {"header_api": _hr_three()}}}
    runs = {"api_get_a": [("include/api.h", 3)]}
    sub = harness_reach._header_api_fields("api_sub", dag, mm, model, runs)
    assert sub == {"header_api_functions": 2, "header_api_unexecuted": {"count": 1, "functions": ["api_get_b"]}}
    # The unit's own row counts every header function the unit compiles.
    unit = harness_reach._header_api_fields("api", dag, mm, model, runs)
    assert unit["header_api_functions"] == 3 and unit["header_api_unexecuted"]["count"] == 2


def test_a_module_measured_by_its_crashes_reports_only_the_count(tmp_path, monkeypatch):
    # No coverage report: nothing measured the header functions, so the row does not claim which ran.
    run = _run_dir(tmp_path, monkeypatch)
    _hr_setup(run, _hr_three())
    hdir = _dispatch(run, TWO_CASES)
    art_parse = _crash(run, "crash-parse", b"\x00\x00")
    art_put = _crash(run, "crash-put", b"\x01\x00")
    fdir = _write_fuzz_report(
        run,
        "api",
        [
            _crash_art(art_parse, "rec_parse", failure=_sanitizer_failure("rec_parse")),
            _crash_art(art_put, "rec_put", failure=_sanitizer_failure("rec_put")),
        ],
    )
    argv = ["dynamic", "--module", "api", "--harnesses", str(hdir), "--fuzz-dir", str(fdir)]
    assert harness_reach.main(argv) == 0
    doc = _dynamic_doc(run)
    row = doc["modules"]["api"]
    assert row["measured_by"] == "crashes" and row["passed"] is True
    assert row["header_api_functions"] == 3 and "header_api_unexecuted" not in row
    assert "warnings" not in doc and not validate_dynamic_reach(doc)
    assert generate_report.header_api_lines(run) == []


def test_the_schema_rejects_a_malformed_header_row(tmp_path, monkeypatch):
    run = _hr_passing_run(tmp_path, monkeypatch, _hr_three())
    doc = _dynamic_doc(run)
    doc["modules"]["api"]["header_api_unexecuted"] = {"count": 2}
    assert validate_dynamic_reach(doc)


def test_the_report_prints_one_line_per_module_with_unexecuted_header_functions(tmp_path, monkeypatch):
    run = _hr_passing_run(tmp_path, monkeypatch, _hr_three())
    text = "\n".join(generate_report.header_api_lines(run))
    assert "### Public header functions the corpus never executed" in text
    assert "- `api`: 2 of 3 public header functions never executed: api_get_b, api_get_c" in text
    # Once all ran, nothing is printed.
    _coverage(run, {"rec_parse": 20, "rec_put": 4, "api_get_a": 7, "api_get_b": 1, "api_get_c": 1})
    assert harness_reach.main(["dynamic", "--module", "api"]) == 0
    assert generate_report.header_api_lines(run) == []
