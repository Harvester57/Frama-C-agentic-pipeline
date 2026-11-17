"""
The dynamic reach gate per module (S5, D2, D18): a dynamic gap holds back only its module, and only from
WP; a module without a usable coverage report is measured by its reproducible crashes when they prove
every entry point. Fixtures are synthetic: the run directory and the reports are written by the tests.
"""

from __future__ import annotations

import pytest

import harness_reach
from test_harness_reach import (
    _coverage,
    _dynamic_doc,
    _run_dir,
    _write_fuzz_report,
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
