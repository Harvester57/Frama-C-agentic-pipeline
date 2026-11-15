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
        "#ifndef FRAMAC_FUZZ_REJECT\n#define FRAMAC_FUZZ_REJECT() ((void)0)\n#endif\n"
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


def _harness_n(tmp_path: Path, n: int) -> Path:
    cases = [f"sink = {i};" for i in range(n)]
    _, fuzz = _build_invocations("f", "dispatch", dispatch_cases=cases)
    path = tmp_path / f"harness_{n}.c"
    path.write_text(
        "#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n"
        "#ifndef FRAMAC_FUZZ_REJECT\n#define FRAMAC_FUZZ_REJECT() ((void)0)\n#endif\n"
        "static int sink = -1;\n"
        f"static int run(uint8_t *fuzz_buf, size_t fuzz_len) {{\n    sink = -1;\n    {fuzz}\n    return sink;\n}}\n"
        "int main(void) {\n    for (int b = 0; b < 256; b++) {\n"
        '        uint8_t in[2] = {(uint8_t)b, 0};\n        printf("%d %d\\n", b, run(in, 2));\n    }\n'
        "    return 0;\n}\n",
        encoding="utf-8",
    )
    return path


def test_every_case_of_a_large_dispatch_harness_is_skippable(tmp_path):
    # QCBOR run-4: 115 of 179 cases could never be skipped, so the rounds ended with time left.
    harness = _harness_n(tmp_path, 179)
    text = harness.read_text(encoding="utf-8")
    assert R.dispatch_case_count([str(harness)]) == 179
    assert R.dispatch_skippable_cases([str(harness)], 179) == 179
    assert f"#define {DISPATCH_SKIP_MACRO}_2 0ULL" in text and f"{DISPATCH_SKIP_MACRO}_3" not in text
    skip = {3, 70, 113, 178}
    flags = R.dispatch_skip_cppflags(sum(1 << c for c in skip)).split()
    assert flags == [
        f"-D{DISPATCH_SKIP_MACRO}=0x8ULL",
        f"-D{DISPATCH_SKIP_MACRO}_1={(1 << (70 - 64)) | (1 << (113 - 64)):#x}ULL",
        f"-D{DISPATCH_SKIP_MACRO}_2={1 << (178 - 128):#x}ULL",
    ]
    # Word 0 is always given, so a build skipping only cases >= 64 still defines the macro.
    assert R.dispatch_skip_cppflags(1 << 100).split()[0] == f"-D{DISPATCH_SKIP_MACRO}=0x0ULL"

    clang = shutil.which("clang")
    if not clang:
        return
    exe = tmp_path / "h.exe"
    proc = subprocess.run(
        [clang, "-Wall", "-Werror", *flags, str(harness), "-o", str(exe)], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, proc.stderr
    out = subprocess.run([str(exe)], capture_output=True, text=True, check=True).stdout.split("\n")
    ran = {int(b): int(r) for b, r in (line.split() for line in out if line)}
    for b, r in ran.items():
        assert r == (-1 if b % 179 in skip else b % 179), b


def test_a_harness_generated_before_every_case_was_skippable_skips_cases_below_64_only(tmp_path):
    old = tmp_path / "old.c"
    old.write_text(
        f"#ifdef {DISPATCH_SKIP_MACRO}\n    if ((harness_selector % 179U) >= 64U || 1)\n#endif\n"
        "    switch (harness_selector % 179U) {}\n",
        encoding="utf-8",
    )
    assert R.dispatch_case_count([str(old)]) == 179
    assert R.dispatch_skippable_cases([str(old)], 179) == 64
    assert R.dispatch_skippable_cases([str(_harness(tmp_path))], 3) == 3


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
    # The time left after a failed rebuild runs in fork mode on the last binary built.
    assert res["keep_going"]["fork_fallback"]["reason"] == "rebuild_failed"


def test_unskippable_cases_end_the_rounds_with_a_reason_and_the_rest_runs_in_fork_mode(tmp_path):
    calls: list[tuple[str, int, bool]] = []
    masks: list[int] = []
    plan = [
        [_art(tmp_path / "crash-1", bytes([5]), "a"), _art(tmp_path / "crash-2", bytes([70]), "b")],
        [_art(tmp_path / "crash-3", bytes([70]), "b"), _art(tmp_path / "crash-4", bytes([113]), "c")],
        [_art(tmp_path / "crash-5", bytes([150]), "d")],
    ]

    def campaign(binary, seconds, fork):
        calls.append((str(binary), seconds, fork))
        arts = plan[len(calls) - 1]
        return {"status": "crash_found", "returncode": 1, "artifacts": arts}

    def rebuild(mask):
        masks.append(mask)
        return Path(f"bin{len(masks)}"), {"compile": {"returncode": 0}}

    # An old harness: only cases 0..63 of 179 can be skipped.
    res = R.run_campaign_rounds(Path("bin0"), 600, campaign=campaign, rebuild=rebuild, n_cases=179, skippable=64)
    kg = res["keep_going"]
    assert masks == [1 << 5]
    assert kg["skippable_cases"] == 64
    assert kg["rounds"][-1]["stopped"] == "unskippable_case"
    assert kg["rounds"][-1]["unskippable_cases"] == [70, 113]
    assert calls[-1][0] == "bin1" and calls[-1][2] is True
    assert kg["fork_fallback"]["reason"] == "unskippable_case" and kg["fork_fallback"]["artifacts"] == 1
    assert {a["fingerprint"] for a in res["artifacts"]} == {"a", "b", "c", "d"}

    # A current harness skips cases >= 64 like any other.
    calls.clear()
    masks.clear()
    plan[1] = plan[1][1:]  # case 70 is skipped in round 2: only case 113 crashes
    plan[2] = []
    res = R.run_campaign_rounds(Path("bin0"), 600, campaign=campaign, rebuild=rebuild, n_cases=179)
    assert masks == [(1 << 5) | (1 << 70), (1 << 5) | (1 << 70) | (1 << 113)]
    assert not any(c[2] for c in calls) and "fork_fallback" not in res["keep_going"]


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


# --- zero-rebuild runtime dispatch-case skipping ---------------------------------------------


def _runtime_skip_harness(tmp_path: Path) -> Path:
    """A 200-case dispatch harness of `hit_case(<case>)`, including "mod.h" by a relative name."""
    from generate_harness import generate_module_harness

    src = tmp_path / "mod.c"
    src.write_text("int hit_case(unsigned int c) { return (int)c; }\n", encoding="utf-8")
    (tmp_path / "mod.h").write_text("int hit_case(unsigned int c);\n", encoding="utf-8")
    res = generate_module_harness(
        module_name="mod",
        sources=[str(src)],
        header_include="mod.h",
        entry_fn="hit_case",
        max_input_size=64,
        cppflags=f"-I{tmp_path.as_posix()}",
        out_dir=tmp_path / "harnesses",
        entry_style="dispatch",
        dispatch_cases=[f"(void)hit_case({i}U);" for i in range(200)],
        auto_prelude=False,
    )
    return Path(res["harness_file"])


def test_runtime_skip_cases_marker(tmp_path):
    from generate_harness import generate_module_harness

    assert R.format_skip_cases_env([129, 0, 65, 300, 0]) == "0,65,129,300"
    assert R.format_skip_cases_env(set()) == ""
    assert R.harness_supports_runtime_skip_cases(None) is False

    src = tmp_path / "mod.c"
    harness_c = _runtime_skip_harness(tmp_path)
    text = harness_c.read_text(encoding="utf-8")
    assert "#define FRAMAC_FUZZ_RUNTIME_SKIP_CASES 1" in text
    assert "framac_fuzz_skip_case(" in text
    assert R.harness_supports_runtime_skip_cases(harness_c) is True
    assert R.harness_supports_runtime_skip_cases([str(src), str(harness_c)]) is True

    # Non-dispatch harnesses and legacy dispatch harnesses without the runtime helper return False.
    plain_dir = tmp_path / "plain"
    plain = generate_module_harness(
        module_name="plain",
        sources=[str(src)],
        header_include="none",
        entry_fn="hit_case",
        max_input_size=64,
        cppflags="-I.",
        out_dir=plain_dir,
        entry_style="void_call",
        auto_prelude=False,
    )
    assert R.harness_supports_runtime_skip_cases(Path(plain["harness_file"])) is False
    assert R.harness_supports_runtime_skip_cases(_harness(tmp_path)) is False


SKIP_ENV = "0, 65, 129, 300"


def test_runtime_skip_cases_c_execution(tmp_path):
    """
    The generated harness skips exactly the cases FRAMAC_FUZZ_SKIP_CASES lists, compiled and run: with the
    host's clang or gcc, else in the analysis image under FRAMAC_DOCKER_TESTS=1, else skipped (never a
    silent pass).
    """
    import os

    _runtime_skip_harness(tmp_path)
    driver = tmp_path / "driver.c"
    driver.write_text(
        '#include "harnesses/harness_mod.c"\n'
        "#include <stdio.h>\n"
        "static int last_hit = -1;\n"
        "int hit_case(unsigned int c) { last_hit = (int)c; return (int)c; }\n"
        "int main(void) {\n"
        '    printf("direct:%d,%d,%d,%d,%d,%d\\n",\n'
        "           framac_fuzz_skip_case(0U),\n"
        "           framac_fuzz_skip_case(65U),\n"
        "           framac_fuzz_skip_case(129U),\n"
        "           framac_fuzz_skip_case(300U),\n"
        "           framac_fuzz_skip_case(7U),\n"
        "           framac_fuzz_skip_case(5000U));\n"
        "    for (unsigned int c = 0; c < 200U; c++) {\n"
        "        uint8_t in[2] = {(uint8_t)c, 0x42U};\n"
        "        last_hit = -1;\n"
        "        int rc = LLVMFuzzerTestOneInput(in, 2U);\n"
        '        printf("case:%u:%d:%d\\n", c, rc, last_hit);\n'
        "    }\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    cc = shutil.which("clang") or shutil.which("gcc")
    if cc:
        exe = tmp_path / "rt_skip_driver.exe"
        proc = subprocess.run(
            [cc, "-Wall", "-Werror", f"-I{tmp_path.as_posix()}", str(driver), "-o", str(exe)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        env = dict(os.environ)
        env["FRAMAC_FUZZ_SKIP_CASES"] = SKIP_ENV
        stdout = subprocess.run([str(exe)], env=env, capture_output=True, text=True, check=True).stdout
    else:
        from conftest import ANALYSIS_IMAGE, require_docker_images

        require_docker_images(ANALYSIS_IMAGE)  # skips without FRAMAC_DOCKER_TESTS=1
        script = (
            "cd /tmp && clang -Wall -Werror -I/fixture /fixture/driver.c -o drv"
            f" && FRAMAC_FUZZ_SKIP_CASES='{SKIP_ENV}' timeout 60 ./drv"
        )
        argv = ["docker", "run", "--rm", "--network", "none", "-v", f"{tmp_path}:/fixture:ro", ANALYSIS_IMAGE, script]
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
        assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
        stdout = proc.stdout
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip().startswith(("direct:", "case:"))]
    assert len(lines) == 201, stdout[-2000:]
    assert lines[0] == "direct:1,1,1,1,0,0"
    for ln in lines[1:]:
        _, c_s, rc_s, hit_s = ln.split(":")
        c_i, rc_i, hit_i = int(c_s), int(rc_s), int(hit_s)
        if c_i in {0, 65, 129}:
            assert rc_i == -1 and hit_i == -1
        else:
            assert rc_i == 0 and hit_i == c_i


def test_runtime_skip_rounds_pass_env_with_zero_rebuilds(tmp_path):
    calls: list[tuple[str, int, bool, dict | None]] = []
    plan = [
        [_art(tmp_path / "crash-1", bytes([129]), "fp129")],
        [_art(tmp_path / "crash-2", bytes([5]), "fp5")],
        [],
    ]

    def campaign(binary, seconds, fork, *, extra_env=None):
        calls.append((str(binary), seconds, fork, extra_env))
        arts = plan[len(calls) - 1]
        return {"status": "crash_found" if arts else "clean", "returncode": 1 if arts else 0, "artifacts": arts}

    res = R.run_campaign_rounds(
        Path("bin0"),
        600,
        campaign=campaign,
        rebuild=lambda mask: pytest.fail(f"unexpected rebuild({mask:#x}) when runtime_skip=True"),
        n_cases=181,
        runtime_skip=True,
    )
    assert [c[0] for c in calls] == ["bin0", "bin0", "bin0"]
    assert [c[3] for c in calls] == [
        None,
        {"FRAMAC_FUZZ_SKIP_CASES": "129"},
        {"FRAMAC_FUZZ_SKIP_CASES": "5,129"},
    ]
    kg = res["keep_going"]
    assert kg["mode"] == "dispatch_rounds"
    assert kg["runtime_skip"] is True
    assert kg["skipped_cases"] == [5, 129]
    assert [r["skipped_cases"] for r in kg["rounds"]] == [[], [129], [5, 129]]


@pytest.mark.parametrize("runtime_skip", [True, False])
def test_a_crash_in_a_skipped_case_stops_the_rounds_with_an_error(tmp_path, runtime_skip):
    # Round 2 runs with case 0 skipped and crashes in case 0 again: the skip did not take (QCBOR
    # post-run review: the runtime skip without the environ shim stopped quietly after 0.4 s of 60).
    calls: list = []

    def campaign(binary, seconds, fork, *, extra_env=None):
        calls.append(extra_env)
        art = _art(tmp_path / f"crash-{len(calls)}", b"\x03\x00", f"fp{len(calls)}")  # 3 % 3 == case 0
        return {"status": "crash_found", "returncode": 1, "artifacts": [art]}

    res = R.run_campaign_rounds(
        Path("bin0"),
        600,
        campaign=campaign,
        rebuild=lambda mask: (Path("bin1"), {"compile": {"returncode": 0}}),
        n_cases=3,
        runtime_skip=runtime_skip,
    )
    assert len(calls) == 2
    kg = res["keep_going"]
    last = kg["rounds"][-1]
    assert last["stopped"] == "crash_in_skipped_case" and last["skipped_crashed_cases"] == [0]
    assert kg["status"] == "error" and "case 0" in kg["error"]
    assert "fork_fallback" not in kg
    assert res["status"] == "crash_found"  # the crashes found stay in the report for ingest


def _fake_build_recording(builds: list, environ_keep: str | None):
    def fake_build(sources, target_bin, **opts):
        target_path = Path(target_bin)
        cpp = str(opts.get("cppflags") or "")
        builds.append((target_path, cpp, opts.get("engine")))
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(b"UNMASKED" if "SKIP_CASES=" not in cpp else f"MASKED:{cpp}".encode())
        eng = "sanitizers" if opts.get("engine") == "sanitizers" else "eacsl"
        comp: dict = {"returncode": 0, "binary": str(target_path)}
        if eng == "eacsl" and environ_keep is not None:
            comp["environ_keep"] = {"status": environ_keep}
        return {"compile": comp, "engine_used": eng, "engine_fallback_reason": None, "eacsl_compile_attempt": None}

    return fake_build


def _two_crash_rounds(sandbox_envs: list):
    rounds = {"n": 0}

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        if "-runs=1" in cmd:
            return SandboxResult(1, "", "Assertion failed", False, "rlimits", list(cmd))
        sandbox_envs.append((cmd[0], dict(extra_env or {})))
        rounds["n"] += 1
        prefix = next(a for a in cmd if a.startswith("-artifact_prefix=")).split("=", 1)[1]
        n = rounds["n"] % 3
        if n in (1, 2):
            Path(f"{prefix}crash-r{rounds['n']}").write_bytes(bytes([2 * (n - 1), 0x11 * rounds["n"]]))
            return SandboxResult(1, "", "", False, "rlimits", list(cmd))
        return SandboxResult(0, "", "", False, "rlimits", list(cmd))

    return fake_sandbox


@pytest.mark.parametrize("engine,environ_keep", [("eacsl", "failed"), ("eacsl", None), ("auto", "failed")])
def test_runtime_skip_without_the_environ_shim_falls_back_to_skip_rebuilds(tmp_path, monkeypatch, engine, environ_keep):
    # The E-ACSL runtime leaves `environ` empty unless the shim restores it, so getenv() cannot see
    # FRAMAC_FUZZ_SKIP_CASES: without the shim the E-ACSL rounds rebuild with -DFRAMAC_FUZZ_SKIP_CASES.
    # A sanitizer build reads its environment normally and keeps the runtime skip.
    from generate_harness import generate_module_harness

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    src = tmp_path / "src.c"
    src.write_text("int f(int x) { return x; }\n", encoding="utf-8")
    gen = generate_module_harness(
        module_name="mod",
        sources=[str(src)],
        header_include="none",
        entry_fn="f",
        max_input_size=64,
        cppflags="-I.",
        out_dir=tmp_path / "gen",
        entry_style="dispatch",
        dispatch_cases=["(void)f(0);", "(void)f(1);", "(void)f(2);"],
        auto_prelude=False,
    )
    builds: list = []
    envs: list = []
    monkeypatch.setattr(R, "build_module_binary", _fake_build_recording(builds, environ_keep))
    monkeypatch.setattr(R, "run_sandboxed", _two_crash_rounds(envs))
    out_json = tmp_path / "reports" / "fuzz.json"
    argv = ["campaign", "--module", "mod", "--sources", str(src), gen["harness_file"], "--out-bin", "fuzz_mod"]
    argv += ["--corpus-dir", "corpus", "--artifacts-dir", "crashes", "--workers", "1", "--max-time", "240"]
    argv += ["--no-cache", "--no-attribution-replay", "--no-auto-dict", "--engine", engine, "--out-json", str(out_json)]
    assert R.main(argv) == 0
    import json

    report = json.loads(out_json.read_text(encoding="utf-8"))
    kg_eacsl = report["engines"]["eacsl"]["keep_going"] if engine == "auto" else report["keep_going"]
    assert "runtime_skip" not in kg_eacsl
    assert kg_eacsl["skipped_cases"] == [0, 2]
    assert "environ" in kg_eacsl["runtime_skip_unavailable"]
    eacsl_rebuilds = [b[1].split()[-1] for b in builds if b[2] == "eacsl" and "-DFRAMAC_FUZZ_SKIP_CASES=" in b[1]]
    assert eacsl_rebuilds == ["-DFRAMAC_FUZZ_SKIP_CASES=0x1ULL", "-DFRAMAC_FUZZ_SKIP_CASES=0x5ULL"]
    skip_envs = [e.get("FRAMAC_FUZZ_SKIP_CASES") for _, e in envs]
    if engine == "auto":
        # Sanitizers first, with the runtime skip; then E-ACSL on rebuilt binaries.
        kg_san = report["engines"]["sanitizers"]["keep_going"]
        assert kg_san["runtime_skip"] is True and kg_san["skipped_cases"] == [0, 2]
        assert not any(b[2] == "sanitizers" and "SKIP_CASES=" in b[1] for b in builds)
        assert skip_envs == [None, "0", "0,2", None, None, None]
    else:
        assert skip_envs == [None, None, None]


def test_campaign_mode_runtime_skip_never_rebuilds_and_legacy_rebuild_preserves_out_bin(tmp_path, monkeypatch):
    import json

    from generate_harness import generate_module_harness

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    src = tmp_path / "src.c"
    src.write_text("int f(int x) { return x; }\n", encoding="utf-8")

    # 1. Modern generated dispatch harness: 0 rebuilds, FRAMAC_FUZZ_SKIP_CASES passed via sandbox extra_env.
    gen_dir = tmp_path / "gen"
    gen = generate_module_harness(
        module_name="mod",
        sources=[str(src)],
        header_include="none",
        entry_fn="f",
        max_input_size=64,
        cppflags="-I.",
        out_dir=gen_dir,
        entry_style="dispatch",
        dispatch_cases=["(void)f(0);", "(void)f(1);", "(void)f(2);"],
        auto_prelude=False,
    )
    harness_new = Path(gen["harness_file"])
    out_bin = tmp_path / "fuzz_mod"
    builds: list[tuple[Path, str]] = []
    sandbox_envs: list[dict[str, str]] = []

    def fake_build(sources, target_bin, **opts):
        target_path = Path(target_bin)
        cpp = str(opts.get("cppflags") or "")
        builds.append((target_path, cpp))
        target_path.parent.mkdir(parents=True, exist_ok=True)
        payload = b"UNMASKED" if "SKIP_CASES=" not in cpp else f"MASKED:{cpp}".encode()
        target_path.write_bytes(payload)
        return {
            # The environ shim is linked: the E-ACSL build's getenv() sees the skip set.
            "compile": {"returncode": 0, "binary": str(target_path), "environ_keep": {"status": "built"}},
            "engine_used": "eacsl",
            "engine_fallback_reason": None,
            "eacsl_compile_attempt": None,
        }

    round_idx = 0

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        nonlocal round_idx
        if "-runs=1" in cmd:
            return SandboxResult(1, "", "Assertion failed", False, "rlimits", list(cmd))
        sandbox_envs.append(dict(extra_env or {}))
        round_idx += 1
        prefix = next(a for a in cmd if a.startswith("-artifact_prefix=")).split("=", 1)[1]
        if round_idx == 1:
            Path(f"{prefix}crash-r1").write_bytes(bytes([0, 0x11]))
            return SandboxResult(1, "", "", False, "rlimits", list(cmd))
        if round_idx == 2:
            Path(f"{prefix}crash-r2").write_bytes(bytes([2, 0x22]))
            return SandboxResult(1, "", "", False, "rlimits", list(cmd))
        return SandboxResult(0, "", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(R, "build_module_binary", fake_build)
    monkeypatch.setattr(R, "run_sandboxed", fake_sandbox)

    out_json = tmp_path / "reports" / "fuzz_new.json"
    rc = R.main(
        [
            "campaign",
            "--module",
            "mod",
            "--sources",
            str(src),
            str(harness_new),
            "--out-bin",
            str(out_bin),
            "--corpus-dir",
            str(tmp_path / "corpus_new"),
            "--artifacts-dir",
            str(tmp_path / "crashes_new"),
            "--workers",
            "1",
            "--max-time",
            "120",
            "--no-cache",
            "--no-attribution-replay",
            "--no-auto-dict",
            "--engine",
            "eacsl",
            "--out-json",
            str(out_json),
        ]
    )
    assert rc == 0
    assert len(builds) == 1, f"expected exactly 1 initial build and 0 rebuilds, got {builds}"
    assert out_bin.read_bytes() == b"UNMASKED"
    assert [e.get("FRAMAC_FUZZ_SKIP_CASES") for e in sandbox_envs] == [None, "0", "0,2"]
    report_new = json.loads(out_json.read_text(encoding="utf-8"))
    assert report_new["keep_going"]["skipped_cases"] == [0, 2]
    assert report_new["keep_going"]["runtime_skip"] is True

    # 2. Legacy dispatch harness without runtime marker: falls back to rebuild WITHOUT clobbering out_bin.
    builds.clear()
    sandbox_envs.clear()
    round_idx = 0
    legacy_harness = _harness(tmp_path)
    out_bin_legacy = tmp_path / "fuzz_legacy"
    out_json_legacy = tmp_path / "reports" / "fuzz_legacy.json"
    rc_leg = R.main(
        [
            "campaign",
            "--module",
            "legacy",
            "--sources",
            str(src),
            str(legacy_harness),
            "--out-bin",
            str(out_bin_legacy),
            "--corpus-dir",
            str(tmp_path / "corpus_leg"),
            "--artifacts-dir",
            str(tmp_path / "crashes_leg"),
            "--workers",
            "1",
            "--max-time",
            "120",
            "--no-cache",
            "--no-attribution-replay",
            "--no-auto-dict",
            "--engine",
            "eacsl",
            "--out-json",
            str(out_json_legacy),
        ]
    )
    assert rc_leg == 0
    assert len(builds) == 3  # initial build + 2 skip rebuilds
    assert builds[0][0] == out_bin_legacy
    assert all(b[0] != out_bin_legacy for b in builds[1:])
    assert out_bin_legacy.read_bytes() == b"UNMASKED"
    assert all("FRAMAC_FUZZ_SKIP_CASES" not in e for e in sandbox_envs)


def test_eacsl_stage2_links_environ_keep_shim_when_getenv_present(tmp_path, monkeypatch):
    from subprocess import CompletedProcess

    monkeypatch.setattr(R, "_resolve_eacsl_gcc", lambda: ("/usr/bin/e-acsl-gcc", True))
    src = tmp_path / "src.c"
    src.write_text("int target(int x) { return x; }\n", encoding="utf-8")

    stage2_links: list[str] = []

    def fake_runner(cmd, **kwargs):
        if cmd[0] == "clang" and "-E" in cmd:
            return CompletedProcess(cmd, 0, f'# 1 "{src.as_posix()}"\nint target(int x) {{ return x; }}\n', "")
        if cmd[0] == "clang" and "-c" in cmd:
            Path(cmd[cmd.index("-o") + 1]).write_bytes(b"OBJ")
            return CompletedProcess(cmd, 0, "", "")
        if cmd[0] == "/usr/bin/e-acsl-gcc" and "-n" in cmd:
            inst = Path(cmd[cmd.index("-o") + 1])
            inst.write_text(
                "extern char *getenv(const char *);\n"
                'static inline int framac_fuzz_skip_case(unsigned int c) { return getenv("FRAMAC_FUZZ_SKIP_CASES") != 0; }\n'
                "int target(int x) { return x; }\n"
                "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long s) { return framac_fuzz_skip_case(0U); }\n",
                encoding="utf-8",
            )
            return CompletedProcess(cmd, 0, "", "")
        if cmd[0] == "/usr/bin/e-acsl-gcc" and "-C" in cmd:
            stage2_links.append(cmd[cmd.index("-l") + 1])
            out = Path(cmd[cmd.index("-O") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.with_name(out.name + ".e-acsl").write_bytes(b"\x7fELF\x00__e_acsl_memory_init\x00")
            return CompletedProcess(cmd, 0, "", "")
        raise AssertionError(f"unexpected command: {cmd}")

    res = R.compile_eacsl_binary(
        [str(src)],
        tmp_path / "fuzz_mod",
        cppflags="-I.",
        fuzzer_flag=True,
        runner=fake_runner,
        use_cache=False,
    )
    assert res["returncode"] == 0
    assert res["environ_keep"]["status"] == "built"
    assert len(stage2_links) == 1
    assert "-Wl,--wrap=__e_acsl_memory_init" in stage2_links[0]
    assert "eacsl_env_keep.o" in stage2_links[0]
