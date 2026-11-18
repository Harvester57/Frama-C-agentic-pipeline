r"""run_wp_function: the report says whether the function's contract has an `assigns` clause.

libmodbus run-1 (2026-11-18): `prove-modbus_write_register` deleted `assigns *ctx \from reg_addr, value;` from the
contract, WP proved what was left, and the report read `assigns_vcs_proven: true` and
`missing_assigns_warning: false`: no assigns goal failed because there was none. WP had said so itself:
`[wp:pedantic-assigns] ...: Warning: No 'assigns' specification for function 'modbus_write_register'.`

The logs and CSVs under tests/fixtures/wp_frame_clause/ are Frama-C's own output (34.0~beta, in
framac-analysis:latest) for the command line of run_wp_function.py with `--timeout 5 --cache-dir off
--security-props none`, one run per function of tests/fixtures/wp_frame_clause/src/frame.c. Each is cut to the
function under proof: the log keeps everything up to `[report] Computing properties status...`, the function's own
section of the `-report` output and the `Status Report Summary`; the CSV keeps the header and the function's rows.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import run_wp_function as W
import workspace_overlay

FRAME_FIXTURES = Path(__file__).parent / "fixtures" / "wp_frame_clause"
FRAME_SOURCE = FRAME_FIXTURES / "src" / "frame.c"


def _recorded(name: str):
    """A fake Frama-C answering the WP run with the recorded log and report CSV of `name`."""

    def fake(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-wp" in cmd and "-report-csv" in cmd:
            shutil.copyfile(FRAME_FIXTURES / f"{name}.csv", cmd[cmd.index("-report-csv") + 1])
            log = (FRAME_FIXTURES / f"{name}.log").read_text(encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout=log, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    return fake


def _report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fn: str) -> dict:
    monkeypatch.setattr(W.subprocess, "run", _recorded(fn))
    return W.run_wp_on_function(
        FRAME_SOURCE,
        fn,
        tmp_path / "wp",
        cache_dir="off",
        retry_tail=False,
        retry_bitwise=False,
        retry_bytes=False,
        retry_cast_probe=False,
    )


# ---------------------------------------------------------------------------
# A contract without a frame is never a proven frame
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_contract_without_assigns_is_proved_but_its_frame_is_not(tmp_path, monkeypatch) -> None:
    """The libmodbus shape: `requires` and `ensures` only, every goal proved."""
    res = _report(tmp_path, monkeypatch, "post_only")
    assert res["status"] == "all_proven" and res["unproven_count"] == 0
    assert res["unproven_by_bucket"]["step_a_assigns"] == []
    frame = res["frame_summary"]
    assert frame["assigns_clause"] == "absent"
    assert frame["assigns_clause_basis"] == "wp_no_assigns_warning"
    assert frame["missing_assigns_warning"] is True
    assert res["assigns_vcs_proven"] is False and frame["assigns_vcs_proven"] is False
    assert any("no 'assigns' clause" in hint for hint in res["diagnostic_hints"])


@pytest.mark.unit
@pytest.mark.parametrize("fn", ["bare", "on_header_post_only"])
def test_no_contract_and_a_header_contract_without_assigns_are_absent(tmp_path, monkeypatch, fn) -> None:
    res = _report(tmp_path, monkeypatch, fn)
    assert res["status"] == "all_proven"
    assert res["frame_summary"]["assigns_clause"] == "absent"
    assert res["assigns_vcs_proven"] is False


@pytest.mark.unit
def test_the_partial_merge_check_refuses_a_contract_without_assigns(tmp_path, monkeypatch) -> None:
    """The reader in workspace_overlay.py is unchanged: it follows the report."""
    res = _report(tmp_path, monkeypatch, "post_only")
    assert workspace_overlay.assigns_verified_for_partial_merge(res) is False
    assert workspace_overlay.assigns_verified_for_partial_merge(_report(tmp_path, monkeypatch, "pure_ok")) is True


# ---------------------------------------------------------------------------
# Controls: a frame that is there still reads as before
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("fn", ["pure_ok", "on_header"])
def test_a_proven_assigns_clause_is_still_a_proven_frame(tmp_path, monkeypatch, fn) -> None:
    """`assigns \\nothing` on the definition, and a contract on the header prototype only."""
    res = _report(tmp_path, monkeypatch, fn)
    assert res["status"] == "all_proven"
    frame = res["frame_summary"]
    assert frame["assigns_clause"] == "present" and frame["assigns_clause_basis"] == "property_report"
    assert frame["missing_assigns_warning"] is False and frame["assigns_behaviors"] == []
    assert res["assigns_vcs_proven"] is True and frame["assigns_vcs_proven"] is True
    assert res["diagnostic_hints"] == []


@pytest.mark.unit
def test_the_warning_for_a_callee_says_nothing_about_the_caller(tmp_path, monkeypatch) -> None:
    """WP prints the warning for each defined callee without a frame too: it is matched by function name.

    `calls_post_only` has `assigns *p;` and calls `post_only`, which has none. Its own clause is there; it stays
    unproven, as before, because WP lets the callee write anything.
    """
    log = (FRAME_FIXTURES / "calls_post_only.log").read_text(encoding="utf-8")
    assert "No 'assigns' specification for function 'post_only'" in log
    assert "No 'assigns' specification for function 'calls_post_only'" not in log
    res = _report(tmp_path, monkeypatch, "calls_post_only")
    frame = res["frame_summary"]
    assert frame["assigns_clause"] == "present" and frame["missing_assigns_warning"] is False
    assert res["status"] == "unproven_goals_remain" and res["assigns_vcs_proven"] is False
    assert [g["kind"] for g in res["unproven_by_bucket"]["step_a_assigns"]] == ["assigns clause"]


@pytest.mark.unit
def test_an_unproven_assigns_clause_is_present_and_not_proven(tmp_path, monkeypatch) -> None:
    res = _report(tmp_path, monkeypatch, "pure_broken")
    assert res["status"] == "unproven_goals_remain"
    assert res["frame_summary"]["assigns_clause"] == "present"
    assert res["assigns_vcs_proven"] is False and len(res["unproven_by_bucket"]["step_a_assigns"]) == 1


# ---------------------------------------------------------------------------
# Assigns clauses inside named behaviors: WP's own reading
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_complete_behaviors_that_all_assign_are_a_frame(tmp_path, monkeypatch) -> None:
    res = _report(tmp_path, monkeypatch, "guarded_all")
    frame = res["frame_summary"]
    assert res["status"] == "all_proven" and frame["assigns_clause"] == "present"
    assert frame["assigns_behaviors"] == ["neg", "pos"]
    assert res["assigns_vcs_proven"] is True


@pytest.mark.unit
@pytest.mark.parametrize("fn", ["guarded_some", "guarded_gap"])
def test_behaviors_that_do_not_cover_the_function_are_not_a_frame(tmp_path, monkeypatch, fn) -> None:
    """One behavior without `complete behaviors`, and complete behaviors of which one has no assigns."""
    res = _report(tmp_path, monkeypatch, fn)
    frame = res["frame_summary"]
    assert res["status"] == "all_proven" and res["unproven_by_bucket"]["step_a_assigns"] == []
    assert frame["assigns_clause"] == "behaviors_only" and frame["assigns_behaviors"] == ["pos"]
    assert frame["assigns_clause_basis"] == "wp_no_assigns_warning"
    assert res["assigns_vcs_proven"] is False
    assert any("named behaviors" in hint for hint in res["diagnostic_hints"])


# ---------------------------------------------------------------------------
# Frama-C said nothing either way: the answer is `unknown`, and nothing else changes
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_log_without_the_warning_and_without_the_report_is_unknown() -> None:
    state = W.frame_clause_state("[wp] 2 goals scheduled\n[wp] Proved goals:    2 / 2\n", "f")
    assert state == {"assigns_clause": "unknown", "assigns_clause_basis": None, "assigns_behaviors": []}


@pytest.mark.unit
def test_a_run_limited_to_some_properties_is_unknown() -> None:
    """Under `-wp-prop` WP prints no such warning and `-report` leaves out the properties it did not try."""
    log = (FRAME_FIXTURES / "pure_ok.log").read_text(encoding="utf-8")
    untried = "\n".join(line for line in log.splitlines() if "Assigns nothing" not in line) + "\n"
    assert W.frame_clause_state(log, "pure_ok")["assigns_clause"] == "present"
    assert W.frame_clause_state(untried, "pure_ok")["assigns_clause"] == "unknown"


@pytest.mark.unit
def test_loop_assigns_are_not_the_frame_of_the_function() -> None:
    log = (
        "--------------------------------------------------------------------------------\n"
        "--- Properties of Function 'f'\n"
        "--------------------------------------------------------------------------------\n\n"
        '[  Valid  ] Loop assigns ("f.c", line 8)\n            by Wp.typed (v1).\n\n'
        "--------------------------------------------------------------------------------\n"
        "--- Status Report Summary\n"
    )
    assert W.frame_clause_state(log, "f")["assigns_clause"] == "unknown"


@pytest.mark.unit
def test_an_exhausted_budget_keeps_what_the_last_report_said_about_the_frame(tmp_path, monkeypatch) -> None:
    scratch = tmp_path / "agents" / "prove-post_only" / "scratch"
    (scratch / "work").mkdir(parents=True)
    c_file = scratch / "work" / "frame.c"
    shutil.copyfile(FRAME_SOURCE, c_file)
    shutil.copyfile(FRAME_SOURCE.with_suffix(".h"), scratch / "work" / "frame.h")
    monkeypatch.setattr(W.subprocess, "run", _recorded("post_only"))
    options: dict = {"cache_dir": "off", "retry_tail": False, "retry_bitwise": False, "retry_bytes": False}
    first = W.run_wp_on_function(c_file, "post_only", scratch / "wp", **options)
    assert first["assigns_vcs_proven"] is False
    (scratch / "wp_post_only.json").write_text(json.dumps(first), encoding="utf-8")
    (scratch / ".prover_budget.json").write_text('{"max_wp_invocations": 1, "wp_invocations": 1}', encoding="utf-8")
    capped = W.run_wp_on_function(c_file, "post_only", scratch / "wp", **options)
    assert capped["budget_exhausted"] is True
    assert capped["assigns_vcs_proven"] is False
    assert capped["frame_summary"]["assigns_clause"] == "absent"
    assert workspace_overlay.assigns_verified_for_partial_merge(capped) is False
