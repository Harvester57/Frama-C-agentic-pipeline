"""`workspace_overlay.py merge-agent` (the single-agent path) builds and checks like the batch path.

QCBOR run-6 (2026-11-15, open bug #11): a hand-run `merge-agent --module libqcbor_a` preprocessed the parent
WP check with `-I.` only (the module's include paths were never used), would have skipped the E-ACSL
guardrail because no `--sources` were given, and its refusal printed only `status=...`.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import workspace_overlay

SIDECAR = {
    "module": "m",
    "sources": ["src/m.c"],
    "cppflags": "-Iinc -DM=1",
    "ldflags": "-lm",
}


def _overlay(tmp_path: Path, sidecar: dict | None) -> Path:
    run_dir = (tmp_path / "run").resolve()
    hdir = run_dir / "workspace" / "harnesses"
    hdir.mkdir(parents=True)
    if sidecar is not None:
        (hdir / "harness_m.json").write_text(json.dumps(sidecar), encoding="utf-8")
    return run_dir


def _capture(monkeypatch) -> list[dict]:
    calls: list[dict] = []

    def fake_merge(**kwargs):
        calls.append(kwargs)
        return {"ok": True}

    monkeypatch.setattr(workspace_overlay, "merge_agent_overlay", fake_merge)
    return calls


def _argv(run_dir: Path, *extra: str) -> list[str]:
    return [
        "merge-agent",
        "--run-dir",
        str(run_dir),
        "--agent-id",
        "prove-f",
        "--role",
        "prover",
        "--file",
        "src/m.c",
        "--function",
        "f",
        *extra,
    ]


def test_module_supplies_sources_and_flags_when_the_caller_passes_none(tmp_path: Path, monkeypatch) -> None:
    run_dir = _overlay(tmp_path, SIDECAR)
    calls = _capture(monkeypatch)
    assert workspace_overlay.main(_argv(run_dir, "--module", "m")) == 0
    (call,) = calls
    assert call["sources"] == ["src/m.c"]
    assert call["cppflags"] == "-Iinc -DM=1"
    assert call["ldflags"] == "-lm"


def test_explicit_flags_win_over_the_module(tmp_path: Path, monkeypatch) -> None:
    run_dir = _overlay(tmp_path, SIDECAR)
    calls = _capture(monkeypatch)
    argv = _argv(run_dir, "--module", "m", "--sources", "x.c", "--cppflags=-Iother", "--ldflags=-lz")
    assert workspace_overlay.main(argv) == 0
    (call,) = calls
    assert (call["sources"], call["cppflags"], call["ldflags"]) == (["x.c"], "-Iother", "-lz")


def test_without_a_module_the_defaults_are_unchanged(tmp_path: Path, monkeypatch) -> None:
    run_dir = _overlay(tmp_path, SIDECAR)
    calls = _capture(monkeypatch)
    assert workspace_overlay.main(_argv(run_dir)) == 0
    (call,) = calls
    assert (call["sources"], call["cppflags"], call["ldflags"]) == (None, "-I.", "")


def test_a_module_without_sources_fails_instead_of_skipping_the_guardrail(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    run_dir = _overlay(tmp_path, {"module": "m", "cppflags": "-Iinc"})
    calls = _capture(monkeypatch)
    assert workspace_overlay.main(_argv(run_dir, "--module", "m")) == 1
    assert calls == []
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and "guardrail" in out["error"] and "--sources" in out["error"]


def test_skip_reverify_needs_no_sources(tmp_path: Path, monkeypatch) -> None:
    run_dir = _overlay(tmp_path, {"module": "m", "cppflags": "-Iinc"})
    calls = _capture(monkeypatch)
    assert workspace_overlay.main(_argv(run_dir, "--module", "m", "--skip-reverify")) == 0
    assert calls[0]["cppflags"] == "-Iinc"


# ---------------------------------------------------------------------------
# The refusal names the WP report's reason
# ---------------------------------------------------------------------------

PREPROCESS_REPORT = {
    "status": "analysis_error",
    "function": "f",
    "reason": "preprocessing_failed: src/m.c:1:10: fatal error: m.h: No such file or directory",
    "preprocess_errors": ["src/m.c:1:10: fatal error: m.h: No such file or directory", "compilation terminated."],
    "soundness": {"ok": False},
}


@pytest.mark.parametrize("allow_partial", [False, True], ids=["full", "partial"])
def test_parent_wp_refusal_names_the_reports_reason(tmp_path: Path, monkeypatch, allow_partial: bool) -> None:
    run_dir = (tmp_path / "run").resolve()
    overlay = run_dir / "workspace"
    (overlay / "work" / "src").mkdir(parents=True)
    (overlay / "work" / "src" / "m.c").write_text("int f(void) { return 0; }\n", encoding="utf-8")

    def fake_run(cmd, **_kw):
        out = Path(cmd[cmd.index("--out-json") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(PREPROCESS_REPORT), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(workspace_overlay.subprocess, "run", fake_run)
    ok, reason = workspace_overlay._run_parent_reverify(
        run_dir, "prove-f", "prover", overlay, "src/m.c", "f", None, None, "-I.", allow_partial_wp=allow_partial
    )
    assert not ok
    assert "status='analysis_error'" in reason
    assert "preprocessing_failed: src/m.c:1:10: fatal error: m.h" in reason
