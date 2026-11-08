"""Fuzz campaigns keep going after a crash: dispatch-case rounds, fork mode, duplicate collapsing."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import run_eacsl_fuzz as R
from generate_harness import DISPATCH_SKIP_MACRO, _build_invocations
from sandbox_exec import SandboxResult

pytestmark = pytest.mark.unit

CASES = ["(void)fuzz_buf;", "(void)fuzz_len;", "(void)0;"]


def _harness(tmp_path: Path) -> Path:
    _, fuzz = _build_invocations("f", "dispatch", dispatch_cases=CASES)
    path = tmp_path / "harness_mod.c"
    path.write_text(
        "#include <stddef.h>\n#include <stdint.h>\n"
        f"int run(uint8_t *fuzz_buf, size_t fuzz_len) {{\n    {fuzz}\n    return 0;\n}}\n",
        encoding="utf-8",
    )
    return path


def _art(path: Path, data: bytes, fp: str, kind: str = "crash") -> dict:
    path.write_bytes(data)
    return {"artifact": str(path), "kind": kind, "sha256": data.hex(), "fingerprint": fp}


# --- harness and case detection ---------------------------------------------------------------


def test_dispatch_harness_can_skip_cases_at_compile_time(tmp_path):
    harness = _harness(tmp_path)
    text = harness.read_text(encoding="utf-8")
    assert f"#ifdef {DISPATCH_SKIP_MACRO}" in text
    assert R.dispatch_case_count([str(tmp_path / "src.c"), str(harness)]) == 3
    # A harness generated before the macro existed cannot skip cases: fork mode instead.
    old = tmp_path / "old.c"
    old.write_text("switch (harness_selector % 3U) {}\n", encoding="utf-8")
    assert R.dispatch_case_count([str(old)]) is None

    clang = shutil.which("clang")
    if clang:
        for flags in ([], [f"-D{DISPATCH_SKIP_MACRO}=0x5ULL"]):
            proc = subprocess.run(
                [clang, "-fsyntax-only", "-Wall", "-Werror", *flags, str(harness)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert proc.returncode == 0, proc.stderr


def test_artifact_case_is_first_byte_modulo_cases(tmp_path):
    a = _art(tmp_path / "crash-a", b"\x07rest", "fp")
    assert R.artifact_dispatch_case(a, 3) == 1
    empty = _art(tmp_path / "crash-b", b"", "fp")
    assert R.artifact_dispatch_case(empty, 3) is None


def test_duplicates_of_one_fingerprint_are_listed_at_most_three_times():
    arts = [{"fingerprint": "a"}] * 5 + [{"fingerprint": None}] * 2 + [{"fingerprint": "b"}]
    kept, dropped = R._collapse_duplicate_artifacts(arts)
    assert dropped == 2
    assert [a["fingerprint"] for a in kept] == ["a", "a", "a", None, None, "b"]


# --- rounds -----------------------------------------------------------------------------------


def test_rounds_skip_crashed_cases_until_a_clean_round(tmp_path):
    calls: list[tuple[str, int, bool]] = []
    masks: list[int] = []
    plan = [
        # round 1: case 2 crashes (input byte 5 % 3), twice with one fingerprint
        [_art(tmp_path / "crash-1", b"\x05a", "batch"), _art(tmp_path / "crash-2", b"\x02b", "batch")],
        # round 2: case 1 crashes
        [_art(tmp_path / "crash-3", b"\x01c", "fprintf")],
        # round 3: clean
        [],
    ]

    def campaign(binary, seconds, fork):
        calls.append((str(binary), seconds, fork))
        arts = plan[len(calls) - 1]
        return {"status": "crash_found" if arts else "clean", "returncode": 1 if arts else 0, "artifacts": arts}

    def rebuild(mask):
        masks.append(mask)
        return Path(f"bin{len(masks)}"), {"compile": {"returncode": 0}}

    res = R.run_campaign_rounds(Path("bin0"), 600, campaign=campaign, rebuild=rebuild, n_cases=3)
    assert [c[0] for c in calls] == ["bin0", "bin1", "bin2"]
    assert not any(c[2] for c in calls)
    assert masks == [0b100, 0b110]
    assert res["status"] == "crash_found"
    assert sorted(a["fingerprint"] for a in res["artifacts"]) == ["batch", "batch", "fprintf"]
    kg = res["keep_going"]
    assert kg["mode"] == "dispatch_rounds" and kg["skipped_cases"] == [1, 2]
    assert [r["crashed_cases"] for r in kg["rounds"]] == [[2], [1], []]
    assert [r["skipped_cases"] for r in kg["rounds"]] == [[], [2], [1, 2]]


def test_rounds_stop_when_every_case_is_skipped_or_a_rebuild_fails(tmp_path):
    def campaign_crashing(*cases):
        def campaign(binary, seconds, fork):
            arts = [_art(tmp_path / f"crash-{c}", bytes([c]), f"fp{c}") for c in cases]
            return {"status": "crash_found", "returncode": 1, "artifacts": arts}

        return campaign

    res = R.run_campaign_rounds(
        Path("b"), 600, campaign=campaign_crashing(0, 1), rebuild=lambda m: pytest.fail("no rebuild"), n_cases=2
    )
    assert res["keep_going"]["rounds"][-1]["stopped"] == "every_case_skipped"

    res = R.run_campaign_rounds(
        Path("b"),
        600,
        campaign=campaign_crashing(0),
        rebuild=lambda m: (None, {"compile": {"returncode": 1, "log_tail": "error: boom"}}),
        n_cases=2,
    )
    last = res["keep_going"]["rounds"][-1]
    assert last["stopped"] == "rebuild_failed" and "boom" in last["rebuild_log_tail"]
    assert res["status"] == "crash_found"


def test_rounds_share_one_time_budget(tmp_path, monkeypatch):
    clock = iter([0.0, 597.0])
    monkeypatch.setattr(R.time, "monotonic", lambda: next(clock))

    def campaign(binary, seconds, fork):
        return {"status": "crash_found", "returncode": 1, "artifacts": [_art(tmp_path / "crash-x", b"\x00", "fp")]}

    res = R.run_campaign_rounds(
        Path("b"), 600, campaign=campaign, rebuild=lambda m: pytest.fail("no time left"), n_cases=3
    )
    assert res["keep_going"]["rounds"][-1]["stopped"] == "time_budget_spent"


def test_a_minimum_size_campaign_that_crashes_at_once_still_gets_a_second_round(tmp_path, monkeypatch):
    # oscs-tweetnacl (r2v): a 30 s campaign crashed after 0.2 s and stopped, so its corpus stayed empty.
    clock = iter([0.0, 0.2, 0.2, 29.0])
    monkeypatch.setattr(R.time, "monotonic", lambda: next(clock))
    budgets: list[int] = []
    plan = [[_art(tmp_path / "crash-0", b"\x00", "fp")], []]

    def campaign(binary, seconds, fork):
        budgets.append(seconds)
        arts = plan[len(budgets) - 1]
        return {"status": "crash_found" if arts else "clean", "returncode": 1 if arts else 0, "artifacts": arts}

    res = R.run_campaign_rounds(
        Path("b"),
        R.MIN_FUZZ_WALL_S,
        campaign=campaign,
        rebuild=lambda m: (Path("b1"), {"compile": {"returncode": 0}}),
        n_cases=3,
    )
    assert budgets == [R.MIN_FUZZ_WALL_S, R.MIN_FUZZ_WALL_S - 1]  # int(30 - 0.2) = 29
    assert [r["crashed_cases"] for r in res["keep_going"]["rounds"]] == [[0], []]


def test_non_dispatch_harness_uses_fork_mode_and_stop_on_first_crash_runs_once():
    calls: list[bool] = []

    def campaign(binary, seconds, fork):
        calls.append(fork)
        return {"status": "clean", "returncode": 0, "artifacts": []}

    res = R.run_campaign_rounds(Path("b"), 60, campaign=campaign, rebuild=None, n_cases=None)
    assert calls == [True] and res["keep_going"] == {"mode": "fork"}
    res = R.run_campaign_rounds(Path("b"), 60, campaign=campaign, rebuild=None, n_cases=3, keep_going=False)
    assert calls == [True, False] and "keep_going" not in res


# --- libFuzzer command line ------------------------------------------------------------------


def test_fork_mode_command_and_replay_cap(tmp_path, monkeypatch):
    calls: list[tuple[list[str], dict]] = []
    n_crashes = R.MAX_REPLAYED_CRASHES + 5

    def fake(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        calls.append((list(cmd), dict(extra_env or {})))
        if "-runs=1" not in cmd:
            prefix = next(a for a in cmd if a.startswith("-artifact_prefix=")).split("=", 1)[1]
            for i in range(n_crashes):
                Path(f"{prefix}crash-{i:03d}").write_bytes(bytes([i]))
        return SandboxResult(1, "", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(R, "run_sandboxed", fake)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    binary = tmp_path / "fuzz_mod"
    binary.write_bytes(b"\x7fELF")
    res = R.run_fuzz_campaign(binary, tmp_path / "corpus", tmp_path / "arts", 30, workers=2, fork=True)
    cmd, env = calls[0]
    assert "-fork=2" in cmd and "-ignore_crashes=1" in cmd
    assert not any(a.startswith(("-jobs=", "-workers=")) for a in cmd)
    assert env["TMPDIR"] != "/tmp"
    replays = [c for c, _ in calls if "-runs=1" in c]
    assert len(replays) == R.MAX_REPLAYED_CRASHES
    assert res["fork"] == 2
    assert res["artifacts_omitted"]["not_replayed"] == 5
    assert len(res["artifacts"]) == R.MAX_REPLAYED_CRASHES


# --- both engines -----------------------------------------------------------------------------


def test_merge_engine_campaigns_keeps_every_artifact_and_the_worst_status():
    runs = {
        "sanitizers": {
            "status": "crash_found",
            "returncode": 1,
            "artifacts": [{"kind": "crash", "engine": "sanitizers"}],
        },
        "eacsl": {"status": "clean", "returncode": 0, "artifacts": [], "keep_going": {"mode": "fork"}},
    }
    out = R.merge_engine_campaigns(runs)
    assert out["status"] == "crash_found"
    assert out["engines"]["sanitizers"]["artifacts"] == 1 and out["engines"]["eacsl"]["keep_going"] == {"mode": "fork"}
    # An engine that did not finish is never hidden behind the other engine's clean run.
    runs["sanitizers"] = {"status": "fuzzer_error", "returncode": 2, "artifacts": []}
    assert R.merge_engine_campaigns(runs)["status"] == "fuzzer_error"
    runs["sanitizers"] = {"status": "clean", "returncode": 0, "artifacts": []}
    assert R.merge_engine_campaigns(runs)["status"] == "clean"


def _dual_campaign(tmp_path, monkeypatch, engine: str, san_rc: int = 0) -> tuple[dict, list]:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src.c").write_text("int f(void) { return 0; }\n", encoding="utf-8")
    (tmp_path / "harness_mod.c").write_text("int h;\n", encoding="utf-8")
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)

    def fake_build(sources, out_bin, **opts):
        eng = "eacsl" if opts.get("engine") in ("auto", "eacsl") else "sanitizers"
        rc = san_rc if eng == "sanitizers" else 0
        return {
            "compile": {"returncode": rc, "binary": f"bin.{eng}"},
            "engine_used": eng,
            "engine_fallback_reason": None,
            "eacsl_compile_attempt": None,
        }

    calls: list = []

    def fake_campaign(binary, corpus, artifacts, max_time, *a, **k):
        calls.append((str(binary), max_time))
        return {"status": "clean", "returncode": 0, "artifacts": []}

    monkeypatch.setattr(R, "build_module_binary", fake_build)
    monkeypatch.setattr(R, "run_fuzz_campaign", fake_campaign)
    out_json = tmp_path / "out.json"
    argv = ["campaign", "--module", "mod", "--sources", "src.c", "harness_mod.c", "--out-bin", "fuzz_mod"]
    argv += ["--corpus-dir", "corpus", "--artifacts-dir", "crashes", "--workers", "1", "--max-time", "100"]
    argv += ["--no-cache", "--no-attribution-replay", "--no-auto-dict", "--engine", engine, "--out-json", str(out_json)]
    R.main(argv)
    import json

    return json.loads(out_json.read_text(encoding="utf-8")), calls


def test_auto_fuzzes_with_sanitizers_then_eacsl_half_the_time_each(tmp_path, monkeypatch):
    report, calls = _dual_campaign(tmp_path, monkeypatch, "auto")
    assert calls == [("bin.sanitizers", 50), ("bin.eacsl", 50)]
    assert report["engine_used"] == R.DUAL_ENGINE and set(report["engines"]) == {"sanitizers", "eacsl"}
    assert report["status"] == "clean"


def test_explicit_engine_or_failed_sanitizer_build_fuzzes_with_one_engine(tmp_path, monkeypatch):
    report, calls = _dual_campaign(tmp_path, monkeypatch, "eacsl")
    assert calls == [("bin.eacsl", 100)] and report["engine_used"] == "eacsl"
    report, calls = _dual_campaign(tmp_path, monkeypatch, "auto", san_rc=1)
    assert calls == [("bin.eacsl", 100)] and report["dual_engine_skipped"] == "sanitizer build failed"


def test_candidate_engine_of_a_dual_report_is_the_artifact_engine(tmp_path):
    report = tmp_path / "mod.json"
    report.write_text(
        '{"engine_used": "eacsl+sanitizers", "artifacts": ['
        '{"fingerprint": "a", "engine": "sanitizers"}, {"fingerprint": "b", "engine": "eacsl"}]}',
        encoding="utf-8",
    )
    assert R._candidate_engine({"fingerprint": "a", "tool_outputs": [str(report)]}) == "sanitizers"
    assert R._candidate_engine({"fingerprint": "b", "tool_outputs": [str(report)]}) == "eacsl"
    assert R._candidate_engine({"fingerprint": "c", "tool_outputs": [str(report)]}) == "auto"
