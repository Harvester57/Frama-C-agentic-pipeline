"""The parent re-check replays only an accepted WP memory model, and refuses a prover that used another.

QCBOR run-6 post-run review: `infer_prover_wp_flags` replayed any reported model matching
`[A-Za-z0-9_+,-]+` that was not `cast` (so `Hoare`, `Region`, `+nat`), and a proof under it merged.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import workspace_overlay as WO
from framac_common import wp_model_problem


def _agent_report(run_dir: Path, report: dict, where: str = "scratch") -> None:
    d = run_dir / "agents" / "prove-f" / where
    d.mkdir(parents=True, exist_ok=True)
    (d / "wp_f.json").write_text(json.dumps({"function": "f", **report}), encoding="utf-8")


@pytest.mark.parametrize("model", ["Bytes", "Typed+ref+int", "Typed+nocast"])
def test_an_accepted_model_is_replayed(tmp_path: Path, model: str) -> None:
    _agent_report(tmp_path, {"wp_model": model})
    flags = WO.infer_prover_wp_flags(tmp_path, agent_id="prove-f", c_file="m.c", function="f")
    assert flags[-2:] == ["--wp-model", model]
    assert WO.prover_wp_model_problem(tmp_path, agent_id="prove-f", c_file="m.c", function="f") is None


@pytest.mark.parametrize("model", ["Hoare", "Region", "Typed+nat", "Typed+cast", "Typed+real", "Bytes+Typed"])
def test_a_model_with_a_problem_is_never_replayed(tmp_path: Path, model: str) -> None:
    _agent_report(tmp_path, {"wp_model": model})
    flags = WO.infer_prover_wp_flags(tmp_path, agent_id="prove-f", c_file="m.c", function="f")
    assert "--wp-model" not in flags
    assert WO.prover_wp_model_problem(tmp_path, agent_id="prove-f", c_file="m.c", function="f") == wp_model_problem(
        model
    )


def test_a_bad_model_only_in_the_canonical_report_is_not_the_provers(tmp_path: Path) -> None:
    canonical = tmp_path / "workspace" / "reports" / "wp"
    canonical.mkdir(parents=True)
    (canonical / "f.json").write_text(json.dumps({"function": "f", "wp_model": "Hoare"}), encoding="utf-8")
    assert "--wp-model" not in WO.infer_prover_wp_flags(tmp_path, agent_id="prove-f", c_file="m.c", function="f")
    assert WO.prover_wp_model_problem(tmp_path, agent_id="prove-f", c_file="m.c", function="f") is None


@pytest.mark.parametrize("allow_partial", [False, True], ids=["full", "partial"])
def test_the_merge_of_a_prover_that_used_a_rejected_model_is_refused(
    tmp_path: Path, monkeypatch, allow_partial: bool
) -> None:
    run_dir = tmp_path.resolve()
    overlay = run_dir / "workspace"
    (overlay / "work").mkdir(parents=True)
    (overlay / "work" / "m.c").write_text("int f(void) { return 0; }\n", encoding="utf-8")
    _agent_report(run_dir, {"wp_model": "Hoare", "status": "all_proven"})
    ran: list[list[str]] = []

    def fake_run(cmd, **_kw):
        ran.append(cmd)
        out = Path(cmd[cmd.index("--out-json") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"status": "all_proven", "function": "f", "soundness": {"ok": True}}), "utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(WO.subprocess, "run", fake_run)
    ok, reason = WO._run_parent_reverify(
        run_dir, "prove-f", "prover", overlay, "m.c", "f", None, None, "-I.", allow_partial_wp=allow_partial
    )
    assert not ok
    assert wp_model_problem("Hoare") in reason  # type: ignore[operator]
    assert ran == []
