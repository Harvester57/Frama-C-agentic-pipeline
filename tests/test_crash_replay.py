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


def _obs_candidate(tmp_path):
    """A candidate whose key is a sanitizer failure, with an E-ACSL observation on its second reproducer."""
    rep_san, rep_eac = tmp_path / "crash-san", tmp_path / "crash-eac"
    rep_san.write_bytes(b"\x30")
    rep_eac.write_bytes(b"\x31")
    return {
        "fingerprint": XB_FP_SAN,
        "status": "unverified",
        "module": "snmp",
        "location": {"file": "src/snmp/ber.c", "line": 42, "function": "ber_decode_len"},
        "reproducers": [str(rep_san), str(rep_eac)],
        "tool_outputs": [],
        "observations": [
            {
                "fingerprint": XB_FP_EAC,
                "origin": "fuzz",
                "engine": "eacsl",
                "kind": "initialization",
                "message": "",
                "tool_output": "",
                "reproducer": str(rep_eac),
            }
        ],
    }


def test_replay_runs_an_observation_reproducer_on_its_engine(tmp_path, monkeypatch):
    from conftest import write_json

    cand = _obs_candidate(tmp_path)
    write_json(tmp_path / "candidates.json", [cand])
    calls: list[tuple[str, list[str]]] = []

    def fake_prepare(module, sources, out_bin, **kwargs):
        return {"binary": str(out_bin)}

    def fake_replay(module, inputs, scratch, *, prepared, per_input_timeout):
        calls.append((Path(prepared["binary"]).name, [Path(p).name for p in inputs]))
        # Only the E-ACSL build reproduces anything: the candidate's key itself never fails here.
        if prepared["binary"].endswith("cross_eacsl_snmp"):
            return {"status": "crash_found", "artifacts": [{"fingerprint": XB_FP_EAC, "failure": {}}]}
        return {"status": "clean", "artifacts": []}

    monkeypatch.setattr(crash_replay, "replay_build_spec", lambda *a, **k: dict(XB_SPEC))
    monkeypatch.setattr(crash_replay, "prepare_replay_binary", fake_prepare)
    monkeypatch.setattr(crash_replay, "replay_report", fake_replay)
    crash_replay.replay_candidates(
        tmp_path / "candidates.json", tmp_path / "harnesses", tmp_path / "replay", bin_dir=tmp_path / "bin"
    )
    # The E-ACSL reproducer replays on the E-ACSL build alone; the sanitizer one on the candidate's own build.
    assert sorted(calls) == sorted([("fuzz_snmp", ["crash-san"]), ("cross_eacsl_snmp", ["crash-eac"])])
    report = json.loads(
        (tmp_path / "replay" / f"{crash_replay._candidate_slug(XB_FP_SAN)}.json").read_text(encoding="utf-8")
    )
    assert {a["fingerprint"] for a in report["artifacts"]} == {XB_FP_EAC}
    # An observation's fingerprint is this candidate's failure too.
    assert report["fingerprint_matches"] is True


def test_minimize_interest_accepts_any_of_the_given_fingerprints(tmp_path, monkeypatch):
    monkeypatch.setattr(crash_replay, "replay_artifact", lambda *a, **k: {"reproduced": True, "failure": {"kind": "x"}})
    monkeypatch.setattr(crash_replay, "_failure_fingerprint", lambda failure: XB_FP_EAC)
    binary, variant = tmp_path / "bin", tmp_path / "v"
    scratch = tmp_path / "s"
    assert crash_replay.minimize_interest(binary, variant, scratch, f"{XB_FP_SAN},{XB_FP_EAC}") is True
    assert crash_replay.minimize_interest(binary, variant, scratch, XB_FP_SAN) is False


def test_minimize_candidates_passes_every_fingerprint_and_the_observation_engine(tmp_path, monkeypatch):
    from conftest import write_json

    cand = _obs_candidate(tmp_path)
    write_json(tmp_path / "candidates.json", [cand])
    seen: list[tuple[str, str, str | None]] = []

    def fake_minimize(binary, input_path, scratch, *, module, fingerprint, **kwargs):
        seen.append((Path(binary).name, Path(input_path).name, fingerprint))
        return {"status": "ok"}

    monkeypatch.setattr(crash_replay, "replay_build_spec", lambda *a, **k: dict(XB_SPEC))
    monkeypatch.setattr(
        crash_replay, "prepare_replay_binary", lambda module, sources, out_bin, **kw: {"binary": str(out_bin)}
    )
    monkeypatch.setattr(crash_replay, "minimize_input", fake_minimize)
    crash_replay.minimize_candidates(
        tmp_path / "candidates.json", tmp_path / "h", tmp_path / "min", bin_dir=tmp_path / "bin"
    )
    joined = f"{XB_FP_SAN},{XB_FP_EAC}"
    assert sorted(seen) == sorted([("fuzz_snmp", "crash-san", joined), ("cross_eacsl_snmp", "crash-eac", joined)])
