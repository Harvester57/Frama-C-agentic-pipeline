"""`validate_artifacts.py agent-result`, run on a result in its run dir, refuses the evidence files ingest would.

mpack run-4 (S17): a verifier cited docs/references/rte/frama-c-rte-manual.md (a pipeline-repo doc) as
evidence[].tool_output. Its own agent-result check passed, then `wp_scheduler.py step --complete` answered
`requeued_ingest_error` ("referenced file does not exist under run dir") and the verdict was lost. The same
happens to a scratch evidence file above the 1 MiB promotion limit.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import validate_artifacts
from conftest import FP_REJ, rejected_record, write_json
from promote_artifact import MAX_ARTIFACT_BYTES

_AID = "verify-1"


def _check(tmp_path: Path, capsys, tool_outputs: list[str], files: dict[str, int]) -> dict:
    run = tmp_path / "run-4"
    for rel, size in files.items():
        f = run / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"x" * size)
    rec = rejected_record()
    rec["evidence"] = [{"phase": "verifier", "tool_output": t, "description": "evidence"} for t in tool_outputs]
    rec["verifier"]["agent_id"] = _AID
    result = {
        "role": "crash_verifier",
        "agent_id": _AID,
        "candidate_fingerprint": FP_REJ,
        "decision": "rejected",
        "refingerprint_reason": None,
        "record": rec,
    }
    path = run / "agents" / _AID / "scratch" / "result.json"
    write_json(path, result)
    rc = validate_artifacts.main(["agent-result", str(path)])
    out = json.loads(capsys.readouterr().out)
    assert (rc == 0) == out["ok"]
    return out


def test_repository_doc_cited_as_evidence_is_refused(tmp_path, capsys):
    out = _check(tmp_path, capsys, ["docs/references/rte/frama-c-rte-manual.md"], {})
    assert not out["ok"]
    assert any("does not exist under run dir: docs/references/rte/frama-c-rte-manual.md" in e for e in out["errors"])


def test_missing_scratch_evidence_is_refused(tmp_path, capsys):
    out = _check(tmp_path, capsys, [f"agents/{_AID}/scratch/replay.log"], {})
    assert not out["ok"]
    assert any(f"agents/{_AID}/scratch/replay.log" in e for e in out["errors"])


def test_scratch_evidence_above_the_promotion_limit_is_refused(tmp_path, capsys):
    big = f"agents/{_AID}/scratch/harness.instrumented.c"
    out = _check(tmp_path, capsys, [big], {big: MAX_ARTIFACT_BYTES + 1})
    assert not out["ok"]
    assert any("exceeds limit" in e and big in e for e in out["errors"])


@pytest.mark.parametrize("workspace_file", ["workspace/reports/fuzz/m.json"])
def test_scratch_and_run_dir_evidence_pass(tmp_path, capsys, workspace_file):
    small = f"agents/{_AID}/scratch/replay.log"
    out = _check(tmp_path, capsys, [small, workspace_file], {small: 100, workspace_file: 10})
    assert out["ok"], out
