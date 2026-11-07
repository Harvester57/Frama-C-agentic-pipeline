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
    clock = iter([0.0, 590.0])
    monkeypatch.setattr(R.time, "monotonic", lambda: next(clock))

    def campaign(binary, seconds, fork):
        return {"status": "crash_found", "returncode": 1, "artifacts": [_art(tmp_path / "crash-x", b"\x00", "fp")]}

    res = R.run_campaign_rounds(
        Path("b"), 600, campaign=campaign, rebuild=lambda m: pytest.fail("no time left"), n_cases=3
    )
    assert res["keep_going"]["rounds"][-1]["stopped"] == "time_budget_spent"


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
