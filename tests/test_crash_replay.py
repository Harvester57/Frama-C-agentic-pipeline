"""crash_replay (D3 step 2): the replay and minimize names have one home, and run_eacsl_fuzz re-exports them."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import crash_replay
import run_eacsl_fuzz as R

pytestmark = pytest.mark.unit

CRASH_REPLAY_MOVED_NAMES = (
    "replay_artifact",
    "replay_inputs",
    "_slim_compile",
    "prepare_replay_binary",
    "replay_report",
    "acsl_include_dir",
    "_unit_harness_module",
    "_sidecar_build_spec",
    "replay_build_spec",
    "_candidate_slug",
    "_candidate_engine",
    "_reproducer_paths",
    "replay_candidates",
    "find_creduce",
    "minimize_interest",
    "minimize_input",
    "minimize_candidates",
)
CRASH_REPLAY_SOURCE = Path(__file__).resolve().parent.parent / "scripts" / "crash_replay.py"


def test_run_eacsl_fuzz_reexports_every_moved_name():
    for name in CRASH_REPLAY_MOVED_NAMES:
        assert getattr(R, name) is getattr(crash_replay, name), name


def test_crash_replay_does_not_import_run_eacsl_fuzz():
    text = CRASH_REPLAY_SOURCE.read_text(encoding="utf-8")
    assert "import run_eacsl_fuzz" not in text
    assert "from run_eacsl_fuzz" not in text


XB_FP_SAN = "src/snmp/ber.c#ber_decode_len::mem_access::1111111111"
XB_FP_EAC = "src/snmp/ber.c#ber_decode_len::initialization::2222222222"
XB_SPEC = {"harness_module": "snmp", "sources": ["src/snmp/ber.c"], "cppflags": "", "ldflags": ""}


def _xb_run(tmp_path, monkeypatch, *, other_build_ok: bool):
    """replay_candidates with cross_engine on a sanitizer candidate; the other engine's build and replay are fakes."""
    from conftest import write_json

    repro = tmp_path / "crash-1"
    repro.write_bytes(b"\x30")
    write_json(
        tmp_path / "candidates.json",
        [
            {
                "fingerprint": XB_FP_SAN,
                "status": "unverified",
                "module": "snmp",
                "location": {"file": "src/snmp/ber.c", "line": 42, "function": "ber_decode_len"},
                "reproducers": [str(repro)],
                "tool_outputs": [],
            }
        ],
    )
    builds: list[tuple[str, str]] = []

    def fake_prepare(module, sources, out_bin, **kwargs):
        builds.append((kwargs["engine"], Path(out_bin).name))
        if kwargs["engine"] == "eacsl" and not other_build_ok:
            return {"binary": None, "reason": "no E-ACSL build"}
        return {"binary": str(out_bin)}

    def fake_replay(module, inputs, scratch, *, prepared, per_input_timeout):
        if prepared["binary"].endswith("cross_eacsl_snmp"):
            artifact = {
                "fingerprint": XB_FP_EAC,
                "failure": {
                    "file": "/framac-run/workspace/work/src/snmp/ber.c",
                    "line": 47,
                    "function": "ber_decode_len",
                    "kind": "Assertion",
                    "alarm_kind": "initialization",
                },
            }
            return {"status": "crash_found", "artifacts": [artifact, dict(artifact)]}
        return {"status": "crash_found", "artifacts": [{"fingerprint": XB_FP_SAN, "failure": {}}]}

    monkeypatch.setattr(crash_replay, "replay_build_spec", lambda *a, **k: dict(XB_SPEC))
    monkeypatch.setattr(crash_replay, "prepare_replay_binary", fake_prepare)
    monkeypatch.setattr(crash_replay, "replay_report", fake_replay)
    crash_replay.replay_candidates(
        tmp_path / "candidates.json",
        tmp_path / "harnesses",
        tmp_path / "replay",
        bin_dir=tmp_path / "bin",
        engine="sanitizers",
        cross_engine=True,
    )
    index = json.loads((tmp_path / "replay" / "index.json").read_text(encoding="utf-8"))
    return index["by_fingerprint"][XB_FP_SAN]["cross_engine"], builds


def test_cross_engine_replay_records_the_other_engines_failures(tmp_path, monkeypatch):
    cross, builds = _xb_run(tmp_path, monkeypatch, other_build_ok=True)
    assert ("eacsl", "cross_eacsl_snmp") in builds
    assert cross["engine"] == "eacsl" and cross["status"] == "crash_found"
    # Each distinct failure once, by its fingerprint.
    assert cross["failures"] == [
        {
            "fingerprint": XB_FP_EAC,
            "file": "/framac-run/workspace/work/src/snmp/ber.c",
            "line": 47,
            "function": "ber_decode_len",
            "kind": "initialization",
        }
    ]


def test_a_failed_cross_build_is_recorded_and_skipped(tmp_path, monkeypatch):
    cross, _ = _xb_run(tmp_path, monkeypatch, other_build_ok=False)
    assert cross["engine"] == "eacsl" and cross["status"] == "build_failed"
    assert cross["failures"] == []
