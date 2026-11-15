"""
Every run of a fuzz binary names an -artifact_prefix in a scratch it may write: without one, libFuzzer
writes `crash-<sha1>` into the current directory, the run-dir root (QCBOR run-6, issue #15).
"""

from __future__ import annotations

from pathlib import Path

import pytest

import run_eacsl_fuzz as R
from sandbox_exec import SandboxResult

pytestmark = pytest.mark.unit


def _recorder(calls: list, returncode: int = 1):
    def fake(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        calls.append((list(cmd), [Path(w).resolve() for w in writable]))
        return SandboxResult(returncode, "", "==1==ERROR: libFuzzer: deadly signal\n", False, "rlimits", list(cmd))

    return fake


def _prefix(cmd: list[str]) -> Path:
    prefixes = [a.split("=", 1)[1] for a in cmd if a.startswith("-artifact_prefix=")]
    assert len(prefixes) == 1, cmd
    assert prefixes[0].endswith("/"), prefixes[0]  # a directory, not a file-name prefix
    return Path(prefixes[0]).resolve()


def _assert_scratch_prefix(cmd: list[str], writable: list[Path], scratch: Path) -> None:
    prefix = _prefix(cmd)
    assert prefix.is_dir() and prefix.is_relative_to(scratch.resolve()), (prefix, scratch)
    assert any(prefix.is_relative_to(w) for w in writable), (prefix, writable)
    assert prefix != Path.cwd().resolve()


def test_replay_of_one_input_writes_its_artifacts_under_its_scratch(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    calls: list = []
    monkeypatch.setattr(R, "run_sandboxed", _recorder(calls))
    binary = tmp_path / "fuzz_mod"
    binary.write_bytes(b"BIN")
    crash = tmp_path / "crash-1"
    crash.write_bytes(b"\x01")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    rep = R.replay_artifact(binary, crash, scratch, module="mod")
    assert rep["reproduced"] is True
    (cmd, writable), = calls
    assert cmd[0] == str(binary.resolve()) and cmd[-1] == str(crash.resolve())
    _assert_scratch_prefix(cmd, writable, scratch)


def test_coverage_replay_writes_its_artifacts_under_its_scratch(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    calls: list = []
    monkeypatch.setattr(R, "run_sandboxed", _recorder(calls))
    binary = tmp_path / "cov_mod"
    binary.write_bytes(b"BIN")
    inputs = []
    for i in range(2):
        p = tmp_path / "corpus" / f"in{i}"
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(bytes([i]))
        inputs.append(p)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    R.replay_for_coverage(binary, inputs, tmp_path / "profiles", scratch, module="mod")
    assert calls
    for cmd, writable in calls:
        assert cmd[0] == str(binary.resolve())
        _assert_scratch_prefix(cmd, writable, scratch)


def test_campaign_runs_and_its_replays_never_write_artifacts_in_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    calls: list = []

    def fake(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        calls.append((list(cmd), [Path(w).resolve() for w in writable]))
        if "-runs=1" not in cmd:
            prefix = next(a for a in cmd if a.startswith("-artifact_prefix=")).split("=", 1)[1]
            Path(f"{prefix}crash-x").write_bytes(b"\x00")
        return SandboxResult(1, "", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(R, "run_sandboxed", fake)
    binary = tmp_path / "fuzz_mod"
    binary.write_bytes(b"BIN")
    artifacts_dir = tmp_path / "crashes"
    R.run_fuzz_campaign(binary, tmp_path / "corpus", artifacts_dir, 30)
    campaign, replay = calls
    assert _prefix(campaign[0]) == artifacts_dir.resolve()
    replay_prefix = _prefix(replay[0])
    assert any(replay_prefix.is_relative_to(w) for w in replay[1]) and replay_prefix != tmp_path.resolve()
    assert not list(tmp_path.glob("crash-*"))
