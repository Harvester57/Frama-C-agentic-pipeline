"""The parent re-check replays a prover's signed-downcast waiver (`run_wp_function.py --waive-signed-downcast`).

QCBOR run-6, `IEEE754_SingleToDouble`: an implementation-defined narrowing on a declared wrap line left two
`signed_downcast` goals no flag could close. The runner records the waiver in `soundness.reduced_checks`; the
parent must re-check with the same flag, which is valid only with `--no-warn-unsigned` and declared lines.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import workspace_overlay as WO

UNSIGNED_OFF = "-warn-unsigned-overflow / -warn-unsigned-downcast OFF"
SIGNED_WAIVER = "-warn-signed-downcast OFF on declared wrap lines"


def _flags(run_dir: Path, reduced: list[str], lines: list[int] | None) -> list[str]:
    scratch = run_dir / "agents" / "prove-f" / "scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    report: dict = {"function": "f", "soundness": {"reduced_checks": reduced}}
    if lines is not None:
        report["unsigned_wraps"] = {"declared_code_lines": lines}
    (scratch / "wp_f.json").write_text(json.dumps(report), encoding="utf-8")
    return WO.infer_prover_wp_flags(run_dir, agent_id="prove-f", c_file="m.c", function="f")


def test_the_waiver_is_replayed_with_its_declared_lines(tmp_path: Path) -> None:
    flags = _flags(tmp_path, [UNSIGNED_OFF, SIGNED_WAIVER], [282])
    assert flags == ["--no-warn-unsigned", "--wrap-code-lines=282", "--waive-signed-downcast"]


def test_the_waiver_is_replayed_from_the_ledger_assumption(tmp_path: Path) -> None:
    """Without a prover report, the unit's recorded assumption says which checks the proof ran without."""
    report = tmp_path / "workspace" / "reports" / "wp" / "f.json"
    report.parent.mkdir(parents=True)
    report.write_text(json.dumps({"function": "f", "unsigned_wraps": {"declared_code_lines": [282]}}), encoding="utf-8")
    unit = {
        "function": "f",
        "file": "m.c",
        "assumptions": [{"description": f"WP run with reduced RTE check flags: {UNSIGNED_OFF}, {SIGNED_WAIVER}."}],
        "evidence": [{"phase": "wp", "tool_output": "workspace/reports/wp/f.json"}],
    }
    (tmp_path / "coverage-ledger.json").write_text(json.dumps([unit]), encoding="utf-8")
    flags = WO.infer_prover_wp_flags(tmp_path, c_file="m.c", function="f")
    assert flags == ["--no-warn-unsigned", "--wrap-code-lines=282", "--waive-signed-downcast"]


@pytest.mark.parametrize(
    "reduced,lines",
    [([UNSIGNED_OFF], [282]), ([UNSIGNED_OFF, SIGNED_WAIVER], None), ([SIGNED_WAIVER], [282])],
    ids=["no-waiver", "no-declared-lines", "unsigned-checks-on"],
)
def test_the_waiver_flag_is_only_added_where_the_runner_accepts_it(
    tmp_path: Path, reduced: list[str], lines: list[int] | None
) -> None:
    assert "--waive-signed-downcast" not in _flags(tmp_path, reduced, lines)
