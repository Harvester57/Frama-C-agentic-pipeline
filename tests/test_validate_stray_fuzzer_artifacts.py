"""`validate_artifacts.py run-dir` refuses libFuzzer artifacts written into the run-dir root (run-6 #15)."""

from __future__ import annotations

import json

import pytest

import validate_artifacts as V
from conftest import metadata, write_json

pytestmark = pytest.mark.unit


def _run(tmp_path):
    run = tmp_path / "run-x"
    write_json(run / "run-metadata.json", metadata("complete"))
    write_json(run / "coverage-ledger.json", [])
    return run


def _cli(run, capsys) -> tuple[int, dict]:
    rc = V.main(["run-dir", str(run)])
    return rc, json.loads(capsys.readouterr().out)


@pytest.mark.parametrize(
    "name",
    ["crash-fa138ae356d35c8d77083c406a5be73745643aae", "leak-01", "timeout-ab", "oom-ff", "slow-unit-12"],
)
def test_a_fuzzer_artifact_in_the_run_dir_root_fails_the_run_dir_check(tmp_path, capsys, name):
    run = _run(tmp_path)
    assert _cli(run, capsys)[0] == 0
    (run / name).write_bytes(b"\x00")
    rc, out = _cli(run, capsys)
    assert rc == 1
    (err,) = out["errors"]
    assert err.startswith(f"{name}: ") and "run_eacsl_fuzz.py replay" in err
    # The run's state stays readable: generate_report and the ledger use validate_run_dir.
    assert V.validate_run_dir(run) == []


def test_fuzzer_artifacts_elsewhere_are_not_flagged(tmp_path, capsys):
    run = _run(tmp_path)
    (run / "workspace/crashes/m").mkdir(parents=True)
    (run / "workspace/crashes/m/crash-abc").write_bytes(b"\x00")
    (run / "crash-dir").mkdir()
    (run / "crashes.txt").write_text("x", encoding="utf-8")
    assert _cli(run, capsys) == (0, {"ok": True, "error_count": 0, "errors": []})
