"""The fuzz campaign report records the harness it fuzzed: `harness_digest` and `dispatch_case_count`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import phase0_gates
import run_eacsl_fuzz as R
from generate_harness import generate_module_harness
from sandbox_exec import SandboxResult

pytestmark = pytest.mark.unit


def _run_dir(tmp_path: Path, monkeypatch, entry_style: str = "dispatch") -> list[str]:
    """A run dir with workspace/harnesses/harness_mod.{c,json}; returns the campaign's --sources."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    src = tmp_path / "src.c"
    src.write_text("int f(int x) { return x; }\n", encoding="utf-8")
    extra = {"dispatch_cases": ["(void)f(0);", "(void)f(1);", "(void)f(2);"]} if entry_style == "dispatch" else {}
    generate_module_harness(
        module_name="mod",
        sources=[str(src)],
        header_include="none",
        entry_fn="f",
        max_input_size=64,
        cppflags="-I.",
        out_dir=Path("workspace/harnesses"),
        entry_style=entry_style,
        auto_prelude=False,
        **extra,
    )
    return ["src.c", "workspace/harnesses/harness_mod.c"]


def _fake_build(sources, target_bin, **opts):
    target = Path(target_bin)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"BIN")
    return {
        "compile": {"returncode": 0, "binary": str(target), "environ_keep": {"status": "built"}},
        "engine_used": "eacsl",
        "engine_fallback_reason": None,
        "eacsl_compile_attempt": None,
    }


def _campaign(sources: list[str], out_json: Path, *extra: str) -> dict:
    argv = ["campaign", "--module", "mod", "--sources", *sources, "--out-bin", "workspace/harnesses/fuzz_mod"]
    argv += ["--corpus-dir", "workspace/corpus/mod", "--artifacts-dir", "workspace/crashes/mod", "--workers", "1"]
    argv += ["--max-time", "60", "--no-cache", "--no-attribution-replay", "--no-auto-dict", "--engine", "eacsl"]
    argv += ["--stop-on-first-crash", "--out-json", str(out_json), *extra]
    assert R.main(argv) == 0
    return json.loads(out_json.read_text(encoding="utf-8"))


def _sandbox(new_crash: bytes | None):
    """A fuzz run that writes `new_crash` under its -artifact_prefix (or exits 1 with nothing new)."""

    def fake(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        if "-runs=1" in cmd:
            return SandboxResult(1, "", "==1==ERROR: libFuzzer: deadly signal\n", False, "rlimits", list(cmd))
        prefix = next(a for a in cmd if a.startswith("-artifact_prefix=")).split("=", 1)[1]
        if new_crash is not None:
            Path(f"{prefix}crash-{new_crash.hex()}").write_bytes(new_crash)
        return SandboxResult(1, "", "", False, "rlimits", list(cmd))

    return fake


def test_campaign_report_and_each_found_artifact_carry_the_harness_identity(tmp_path, monkeypatch):
    sources = _run_dir(tmp_path, monkeypatch)
    monkeypatch.setattr(R, "build_module_binary", _fake_build)
    monkeypatch.setattr(R, "run_sandboxed", _sandbox(b"\x02\x41"))
    report = _campaign(sources, tmp_path / "workspace/reports/fuzz/mod.json")

    digest = phase0_gates.harness_digest(tmp_path, "mod", ignore_exempt=True)
    assert digest and report["harness_digest"] == digest
    assert report["dispatch_case_count"] == 3
    assert len(report["artifacts"]) == 1
    art = report["artifacts"][0]
    assert (art["harness_digest"], art["dispatch_case_count"]) == (digest, 3)
    # An exemption recorded later does not change the digest the report was stamped with.
    sidecar = tmp_path / "workspace/harnesses/harness_mod.json"
    data = json.loads(sidecar.read_text(encoding="utf-8"))
    data["reach_exempt"] = {"f": "debug"}
    sidecar.write_text(json.dumps(data), encoding="utf-8")
    assert phase0_gates.harness_digest(tmp_path, "mod", ignore_exempt=True) == digest


def test_an_artifact_carried_over_keeps_the_identity_it_was_found_under(tmp_path, monkeypatch):
    sources = _run_dir(tmp_path, monkeypatch)
    monkeypatch.setattr(R, "build_module_binary", _fake_build)
    out_json = tmp_path / "workspace/reports/fuzz/mod.json"
    crashes = tmp_path / "workspace/crashes/mod"
    crashes.mkdir(parents=True)
    old = crashes / "crash-old"
    old.write_bytes(b"\x05\x00")
    unknown = crashes / "crash-unknown"
    unknown.write_bytes(b"\x06\x00")
    # The report the campaign replaces found crash-old under a 2-case harness.
    prior = {
        "artifacts": [
            {"artifact": str(old), "sha256": R.sha256_file(old), "harness_digest": "a" * 64, "dispatch_case_count": 2}
        ]
    }
    out_json.parent.mkdir(parents=True)
    out_json.write_text(json.dumps(prior), encoding="utf-8")
    monkeypatch.setattr(R, "run_sandboxed", _sandbox(None))  # exits 1, nothing new: both re-reported
    report = _campaign(sources, out_json)

    by_name = {Path(a["artifact"]).name: a for a in report["artifacts"]}
    assert by_name["crash-old"]["pre_existing"] is True
    assert (by_name["crash-old"]["harness_digest"], by_name["crash-old"]["dispatch_case_count"]) == ("a" * 64, 2)
    assert "harness_digest" not in by_name["crash-unknown"]
    assert "dispatch_case_count" not in by_name["crash-unknown"]
    assert report["dispatch_case_count"] == 3


ASAN_REPLAY = """==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011 at pc 0x55 bp 0x7f sp 0x7f
READ of size 1 at 0x602000000011 thread T0
    #0 0x55a1 in __asan_memcpy (/framac-run/workspace/harnesses/fuzz_mod+0x1)
    #1 0x55a2 in rec_check /framac-run/workspace/work/src/api.c:4:40
    #2 0x55a3 in rec_parse /framac-run/workspace/work/src/api.c:8:38
    #3 0x55a4 in __gen_e_acsl_rec_put /framac-run/workspace/harnesses/fuzz_mod.instrumented.c:90:3
    #4 0x55a5 in LLVMFuzzerTestOneInput /framac-run/workspace/harnesses/harness_mod.c:3:1
    #5 0x55a6 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/framac-run/fuzz_mod+0x7b53a)
    #6 0x55a7 in main (/framac-run/fuzz_mod+0x95a26)
0x602000000011 is located 0 bytes after 1-byte region
allocated by thread T0 here:
    #0 0x55b1 in malloc (/framac-run/fuzz_mod+0x2)
    #1 0x55a2 in rec_parse /framac-run/workspace/work/src/api.c:8:38
    #2 0x55b3 in rec_alloc /framac-run/workspace/work/src/api.c:2:10
SUMMARY: AddressSanitizer: heap-buffer-overflow /framac-run/workspace/work/src/api.c:4:40 in rec_check
"""


def test_campaign_records_the_replay_stack_frames_of_each_crash(tmp_path, monkeypatch):
    assert R.stack_frames(ASAN_REPLAY) == [
        {"function": "rec_check", "file": "/framac-run/workspace/work/src/api.c", "line": 4},
        {"function": "rec_parse", "file": "/framac-run/workspace/work/src/api.c", "line": 8},
        {"function": "__gen_e_acsl_rec_put", "file": "/framac-run/workspace/harnesses/fuzz_mod.instrumented.c", "line": 90},
        {"function": "malloc", "file": "", "line": 0},
        {"function": "rec_alloc", "file": "/framac-run/workspace/work/src/api.c", "line": 2},
    ]
    sources = _run_dir(tmp_path, monkeypatch)
    monkeypatch.setattr(R, "build_module_binary", _fake_build)

    def fake(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        if "-runs=1" in cmd:
            return SandboxResult(1, "", ASAN_REPLAY, False, "rlimits", list(cmd))
        prefix = next(a for a in cmd if a.startswith("-artifact_prefix=")).split("=", 1)[1]
        Path(f"{prefix}crash-1").write_bytes(b"\x01")
        return SandboxResult(1, "", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(R, "run_sandboxed", fake)
    report = _campaign(sources, tmp_path / "workspace/reports/fuzz/mod.json")
    assert [f["function"] for f in report["artifacts"][0]["frames"]][:2] == ["rec_check", "rec_parse"]


def test_identity_of_a_non_dispatch_harness_and_of_a_campaign_that_did_not_run(tmp_path, monkeypatch):
    sources = _run_dir(tmp_path, monkeypatch, entry_style="void_call")
    assert R.campaign_harness_identity("mod", sources)["dispatch_case_count"] is None
    assert R.campaign_harness_identity("mod", sources)["harness_digest"] == phase0_gates.harness_digest(
        tmp_path, "mod", ignore_exempt=True
    )
    # A campaign fuzzing another copy of the harness (a breaker's scratch) does not claim the run's digest.
    copy = tmp_path / "scratch" / "harness_mod.c"
    copy.parent.mkdir()
    copy.write_text((tmp_path / sources[1]).read_text(encoding="utf-8"), encoding="utf-8")
    assert R.campaign_harness_identity("mod", ["src.c", str(copy)])["harness_digest"] is None
    # Every exit path is stamped: here the job has too little memory to fuzz at all.
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: 1)
    report = _campaign(sources, tmp_path / "workspace/reports/fuzz/mod.json")
    assert report["status"] == "insufficient_memory"
    assert report["harness_digest"] == phase0_gates.harness_digest(tmp_path, "mod", ignore_exempt=True)
    assert report["dispatch_case_count"] is None
