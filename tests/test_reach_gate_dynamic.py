"""
The dynamic reach gate per module (S5, D2, D18): a dynamic gap holds back only its module, and only from
WP; a module without a usable coverage report is measured by its reproducible crashes when they prove
every entry point. Fixtures are synthetic: the run directory and the reports are written by the tests.
"""

from __future__ import annotations

import pytest

import harness_reach
import phase0_gates
from test_harness_reach import (
    _coverage,
    _dynamic_doc,
    _run_dir,
    _write_fuzz_report,
    _write_harness,
)
from test_harness_reach_crash_credit import (
    TWO_CASES,
    _crash,
    _crash_art,
    _dispatch,
    _sanitizer_failure,
)

pytestmark = pytest.mark.unit


def _dynamic(run, hdir, fdir) -> int:
    return harness_reach.main(["dynamic", "--module", "api", "--harnesses", str(hdir), "--fuzz-dir", str(fdir)])


def test_a_module_whose_every_input_crashes_is_measured_by_its_crashes(tmp_path, monkeypatch):
    # oscs-qlz: every input crashes the fuzz binary, so no coverage report exists. The reproducible
    # crashes still prove that each entry point ran, so the module is measured and its gate can pass.
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _dispatch(run, TWO_CASES)
    art_parse = _crash(run, "crash-parse", b"\x00\x00")
    art_put = _crash(run, "crash-put", b"\x01\x00")
    assert not (run / "workspace" / "reports" / "coverage" / "api.json").exists()
    fdir = _write_fuzz_report(
        run,
        "api",
        [
            _crash_art(art_parse, "rec_parse", failure=_sanitizer_failure("rec_parse")),
            _crash_art(art_put, "rec_put", failure=_sanitizer_failure("rec_put")),
        ],
    )
    assert _dynamic(run, hdir, fdir) == 0
    doc = _dynamic_doc(run)
    row = doc["modules"]["api"]
    assert row["passed"] is True and row["gaps"] == []
    assert row["measured_by"] == "crashes"
    assert set(row["crashed_entry_points"]) == {"rec_parse", "rec_put"}
    assert "api" not in doc.get("unmeasured", {})


def _dynamic_gap_run(tmp_path, monkeypatch):
    """A run whose reach gate holds rec_put back dynamically: the static check passed, the corpus never ran it."""
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(
        run,
        "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 1);",
        reach_exempt={"rec_print": "debug output"},
    )
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 0
    _coverage(run, {"rec_parse": 20, "rec_put": 0})
    assert harness_reach.main(["dynamic", "--module", "api"]) == 1
    return run


def test_record_reach_stores_the_origin(tmp_path):
    dynamic = {"module": "api", "passed": False, "gaps": ["rec_put"], "error": phase0_gates.DYNAMIC_GAP_ERROR}
    static = {"module": "tools", "passed": False, "gaps": ["rec_x"], "error": None}
    phase0_gates.record_reach(tmp_path, {"modules": [dynamic, static]})
    rows = phase0_gates.load_gates(tmp_path)["reach"]["modules"]
    assert rows["api"]["origin"] == "dynamic"
    assert rows["tools"]["origin"] == "static"
    # A row written before the field existed is dynamic by its error alone.
    assert phase0_gates.row_origin({"passed": False, "error": phase0_gates.DYNAMIC_GAP_ERROR}) == "dynamic"
    assert phase0_gates.row_origin({"passed": False, "error": None}) == "static"


def test_a_dynamic_gap_passes_the_module_check_and_the_whole_run_check(tmp_path, monkeypatch):
    run = _dynamic_gap_run(tmp_path, monkeypatch)
    assert phase0_gates.check(run, "api", ("reach",)) == []
    assert phase0_gates.check(run, None, ("reach",)) == []
    assert phase0_gates.dynamic_gaps(run) == {"api": ["rec_put"]}


def test_a_static_gap_still_fails_both(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len);", reach_exempt={"rec_print": "debug output"})
    harness_reach.record_exempt(hdir, "tools", None, "examples")
    assert harness_reach.main(["check", "--harness-dir", str(hdir)]) == 1
    [module_reason] = phase0_gates.check(run, "api", ("reach",))
    assert "reach gate failed for api" in module_reason
    [run_reason] = phase0_gates.check(run, None, ("reach",))
    assert "reach failed for api" in run_reason
    assert phase0_gates.dynamic_gaps(run) == {}


def test_a_dynamic_gap_with_a_changed_harness_is_stale(tmp_path, monkeypatch):
    run = _dynamic_gap_run(tmp_path, monkeypatch)
    harness_c = run / "workspace" / "harnesses" / "harness_api.c"
    harness_c.write_text(harness_c.read_text(encoding="utf-8") + "/* edited */\n", encoding="utf-8")
    [module_reason] = phase0_gates.check(run, "api", ("reach",))
    assert "the harness of api changed" in module_reason
    [run_reason] = phase0_gates.check(run, None, ("reach",))
    assert "the harness of api changed" in run_reason


def test_campaign_and_eva_gates_let_a_dynamically_gated_module_run(tmp_path, monkeypatch):
    import run_eacsl_fuzz
    import run_eva_slice

    run = _dynamic_gap_run(tmp_path, monkeypatch)
    phase0_gates.record_build_check(run, {"ok": True, "modules": {"api": {"ok": True, "status": "eacsl"}}})
    assert run_eacsl_fuzz.campaign_gate_reasons(run, "api") == []
    assert run_eva_slice.phase0_gate_reasons("api", run) == []


@pytest.mark.parametrize("status", [None, "compile_error"])
def test_a_module_without_coverage_and_without_crash_proof_stays_unmeasured(tmp_path, monkeypatch, status):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _dispatch(run, TWO_CASES)
    if status is not None:
        _coverage(run, {}, status=status)
    art = _crash(run, "crash-parse", b"\x00\x00")
    # rec_put is not proven: its gap cannot be decided, so the module stays unmeasured.
    fdir = _write_fuzz_report(run, "api", [_crash_art(art, "rec_parse", failure=_sanitizer_failure("rec_parse"))])
    assert _dynamic(run, hdir, fdir) == 2
    doc = _dynamic_doc(run)
    assert "api" not in doc["modules"]
    assert doc["unmeasured"]["api"] == f"no coverage ({status or 'missing'})"
