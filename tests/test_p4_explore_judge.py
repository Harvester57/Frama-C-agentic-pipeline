"""Unit tests for P4 Explore / Judge engine, P1a/P1b per-case blinding, P1c pure timing,
P5a/P5d telemetry, P6a floor pass, P2e eacsl-fuzz, smoke integration, and JSON schemas.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import crash_replay
import fuzz_build
import minischema
import run_eacsl_fuzz as R
import sandbox_exec
from generate_harness import DISPATCH_SKIP_MACRO, _build_invocations
from sandbox_exec import SandboxResult

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent
FUZZ_REPORT_SCHEMA = REPO_ROOT / "schemas" / "fuzz_report.schema.json"
JUDGE_REPORT_SCHEMA = REPO_ROOT / "schemas" / "judge_report.schema.json"


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


def _write_dispatch_harness(tmp_path: Path, n_cases: int, *, with_only_case: bool = True) -> Path:
    cases = [f"/* case {i} */ (void)fuzz_buf;" for i in range(n_cases)]
    _, fuzz = _build_invocations("f", "dispatch", dispatch_cases=cases)
    only_block = 'const char *only_env = getenv("FRAMAC_FUZZ_ONLY_CASE"); (void)only_env;\n' if with_only_case else ""
    path = tmp_path / "harness_mod.c"
    path.write_text(
        "#include <stddef.h>\n#include <stdint.h>\n#include <stdlib.h>\n"
        "/* runtime dispatch case skip */\n"
        "static inline int framac_fuzz_skip_case(unsigned int c) {\n"
        f"    {only_block}"
        "    return (int)(c == 9999U);\n"
        "}\n"
        "#ifndef FRAMAC_FUZZ_REJECT\n#define FRAMAC_FUZZ_REJECT() ((void)0)\n#endif\n"
        f"int run(uint8_t *fuzz_buf, size_t fuzz_len) {{\n    {fuzz}\n    return 0;\n}}\n",
        encoding="utf-8",
    )
    return path


def _make_build_json(
    tmp_path: Path,
    *,
    module: str = "mod",
    sources: list[str] | None = None,
    with_san: bool = True,
    with_eacsl: bool = True,
) -> tuple[Path, Path | None, Path | None]:
    san_bin: Path | None = None
    eacsl_bin: Path | None = None
    if with_san:
        san_bin = tmp_path / f"fuzz_{module}.san"
        san_bin.write_bytes(b"#!/bin/sh\nexit 0\n")
    if with_eacsl:
        eacsl_bin = tmp_path / f"fuzz_{module}.e-acsl"
        eacsl_bin.write_bytes(b"#!/bin/sh\nexit 0\n")
    doc: dict[str, Any] = {
        "mode": "build",
        "module": module,
        "status": "built",
        "engine_used": "eacsl" if with_eacsl else "sanitizers",
        "binary": str(eacsl_bin or san_bin),
        "sources": list(sources or []),
        "binaries": {
            "sanitizers": str(san_bin) if san_bin else None,
            "eacsl": str(eacsl_bin) if eacsl_bin else None,
        },
        "compile": {"returncode": 0, "binary": str(eacsl_bin or san_bin), "engine": "eacsl" if with_eacsl else "sanitizers"},
    }
    if with_san:
        doc["sanitizer_compile"] = {"returncode": 0, "binary": str(san_bin), "engine": "sanitizers"}
    bpath = tmp_path / f"{module}.build.json"
    bpath.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return bpath, san_bin, eacsl_bin


def _eacsl_failure_log(file_: str = "src/a.c", line: int = 42, fn: str = "parse", pred: str = "\\valid_read(p)") -> str:
    return (
        f"{file_}: In function '{fn}'\n"
        f"{file_}:{line}: Error: Assertion failed:\n"
        f"        The failing predicate is:\n"
        f"        rte/mem_access:\n"
        f"            {pred}.\n"
        "SUMMARY: libFuzzer: deadly signal\n"
    )


def _asan_failure_log(file_: str = "src/a.c", line: int = 43, fn: str = "parse") -> str:
    return (
        "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010\n"
        "READ of size 4 at 0x602000000010 thread T0\n"
        f"    #0 0x401234 in {fn} {file_}:{line}:5\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow\n"
    )


# --- 1. P1c pure execution timing ------------------------------------------------------------


def test_p1c_pure_execution_timing_excludes_replay_and_attribution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Replay + attribution taking 180 s must NOT burn a 60 s fuzz budget (c-ares parsers regression)."""
    clock = FakeClock()
    monkeypatch.setattr(R.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    monkeypatch.setattr(R, "defined_process_launchers", lambda _b: [])

    binary = tmp_path / "fuzz_mod"
    binary.write_bytes(b"bin")
    san_binary = tmp_path / "fuzz_mod.san"
    san_binary.write_bytes(b"san")
    corpus = tmp_path / "corpus"
    artifacts = tmp_path / "artifacts"

    round_idx = 0

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        nonlocal round_idx
        round_idx += 1
        # LibFuzzer itself runs for only 2.0 s in round 1 (crash on case 0) and 5.0 s in round 2 (clean).
        if round_idx == 1:
            clock.now += 2.0
            prefix = next(a for a in cmd if a.startswith("-artifact_prefix=")).split("=", 1)[1]
            crash_path = Path(prefix) / "crash-case0"
            crash_path.write_bytes(b"\x00payload")
            return SandboxResult(
                returncode=77,
                stdout="",
                stderr=(
                    "#22\tNEW cov: 15 ft: 30 corp: 3/128b exec/s: 11 rss: 48Mb\n"
                    f"Test unit written to {crash_path}\n"
                    "stat::number_of_executed_units: 22\n"
                    "stat::peak_rss_mb: 48\n"
                ),
                timed_out=False,
                sandbox="fake",
            )
        clock.now += 5.0
        return SandboxResult(
            returncode=0,
            stdout="",
            stderr=(
                "#500\tDONE cov: 40 ft: 90 corp: 12/512b exec/s: 100 rss: 52Mb\n"
                "stat::number_of_executed_units: 500\n"
                "stat::peak_rss_mb: 52\n"
            ),
            timed_out=False,
            sandbox="fake",
        )

    def slow_replay(bin_path, art_path, scratch, **kw):
        # Post-exit replay takes 120 s on the fake clock!
        clock.now += 120.0
        return {
            "reproduced": True,
            "returncode": 1,
            "timed_out": False,
            "failure": None,
            "link_stub_abort": None,
            "resource_abort": None,
            "out_of_memory": False,
            "log_tail": "crash",
            "frames": [],
        }

    def slow_attribution_builder():
        # Lazy attribution build takes 60 s on the fake clock!
        clock.now += 60.0
        return san_binary

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_sandbox)
    monkeypatch.setattr(crash_replay, "replay_artifact", slow_replay)

    def _camp(b: Path, secs: int, fork: bool, *, extra_env: dict[str, str] | None = None) -> dict[str, Any]:
        return R.run_fuzz_campaign(
            b,
            corpus,
            artifacts,
            secs,
            attribution_builder=slow_attribution_builder,
            workers=1,
            fork=fork,
            extra_env=extra_env,
        )

    res = R.run_campaign_rounds(
        binary,
        60,
        campaign=_camp,
        rebuild=lambda _m: pytest.fail("runtime_skip must not rebuild"),
        n_cases=3,
        runtime_skip=True,
        selector="identity",
        workers=1,
        build_s=1.25,
    )

    # Round 2 MUST have executed even though replay + attribution consumed 300 s (120 + 60 + 120)!
    assert len(res["keep_going"]["rounds"]) == 2
    assert res["keep_going"]["rounds"][0]["crashed_cases"] == [0]
    assert res["keep_going"]["rounds"][1]["skipped_cases"] == [0]
    assert res["keep_going"]["rounds"][1]["stopped"] == "no_new_case"
    assert res["keep_going"]["fuzz_seconds"] == 7.0
    tel = res["telemetry"]
    assert tel["build_s"] == 1.25
    assert tel["fuzz_s"] == 7.0
    assert tel["replay_s"] == 300.0
    assert tel["total_executions"] == 522


# --- 2. P5a / P5d telemetry parsing ----------------------------------------------------------


def test_p5a_p5d_multi_job_and_fork_telemetry_parsing() -> None:
    job0 = (
        "#2\tINITED cov: 10 ft: 15 corp: 2/16b exec/s: 0 rss: 40Mb\n"
        "#100\tNEW    cov: 55 ft: 120 corp: 14/512b lim: 4096 exec/s: 1200 rss: 58Mb\n"
        "#500\tDONE   cov: 80 ft: 200 corp: 20/1024b lim: 4096 exec/s: 1500 rss: 64Mb\n"
        "stat::number_of_executed_units: 500\n"
        "stat::average_exec_per_sec: 1500\n"
        "stat::peak_rss_mb: 64\n"
    )
    job1 = (
        "#150\tNEW    cov: 62 ft: 145 corp: 18/640b lim: 4096 exec/s: 1400 rss: 61Mb\n"
        "#700\tDONE   cov: 92 ft: 230 corp: 24/2048b lim: 4096 exec/s: 1700 rss: 71Mb\n"
        "stat::number_of_executed_units: 700\n"
        "stat::average_exec_per_sec: 1700\n"
        "stat::peak_rss_mb: 71\n"
    )
    tel = R.parse_libfuzzer_telemetry(["INFO: -jobs=2 -workers=2\n", job0, job1], build_s=3.5, fuzz_s=10.0, replay_s=0.5)
    assert tel["build_s"] == 3.5
    assert tel["fuzz_s"] == 10.0
    assert tel["replay_s"] == 0.5
    assert tel["total_executions"] == 1200
    assert tel["jobs_observed"] == 2
    assert tel["max_cov"] == 92
    assert tel["max_ft"] == 230
    assert tel["max_corp"] == 24
    assert tel["peak_rss_mb"] == 71
    assert tel["exec_s"] == 3200.0
    assert len(tel["series"]) == 5
    assert tel["series"][-1]["cov"] == 92 and tel["series"][-1]["rss_mb"] == 71

    fork_log = (
        "#0: cov: 0 ft: 0 corp: 0 exec/s: 0 oom/timeout/crash: 0/0/10 time: 1s job: 10 dft_time: 0\n"
        "#0: cov: 0 ft: 0 corp: 0 exec/s: 0 oom/timeout/crash: 0/0/64 time: 2s job: 64 dft_time: 0\n"
    )
    ftel = R.parse_libfuzzer_telemetry(fork_log, fuzz_s=2.0)
    assert ftel["fork_summary"]["crashes"] == 64
    assert ftel["fork_summary"]["max_corp"] == 0
    assert ftel["fork_summary"]["passing_execs"] == 0

    # Downsampling preserves endpoints and caps at MAX_TELEMETRY_SERIES_POINTS.
    big = [{"cov": i, "ft": i, "corp": i, "exec_s": 100, "rss_mb": 50} for i in range(400)]
    ds = R._downsample_series(big)
    assert len(ds) <= R.MAX_TELEMETRY_SERIES_POINTS
    assert ds[0]["cov"] == 0 and ds[-1]["cov"] == 399


# --- 3. P1a / P1b per-case blinding, non-dispatch fork blinding, smoke integration, P6a floor ---


def test_p1a_dispatch_per_case_blinding_partial_and_all_blinded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")

    def _make_raw(case_idx: int, fp: str, count: int) -> list[dict[str, Any]]:
        out = []
        for i in range(count):
            p = tmp_path / f"crash_c{case_idx}_{i}"
            p.write_bytes(bytes([case_idx, i & 0xFF]))
            out.append(
                {
                    "artifact": str(p),
                    "kind": "crash",
                    "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                    "fingerprint": fp,
                }
            )
        return out

    # Partial blinding: case 0 hits K_case=16 consecutive crashes on one fp, cases 1 & 2 stay healthy.
    calls: list[dict[str, str] | None] = []
    c0_crashes = _make_raw(0, "fp_blind_0", R.BLINDING_CASE_THRESHOLD)

    def camp_partial(binary, seconds, fork, *, extra_env=None):
        calls.append(extra_env)
        if len(calls) == 1:
            return {
                "status": "crash_found",
                "returncode": 77,
                "artifacts": c0_crashes[:3],
                "_raw_crashes": c0_crashes,
                "fuzz_s": 1.0,
                "replay_s": 0.2,
            }
        return {"status": "clean", "returncode": 0, "artifacts": [], "fuzz_s": 10.0, "replay_s": 0.0}

    res = R.run_campaign_rounds(
        tmp_path / "bin",
        60,
        campaign=camp_partial,
        rebuild=lambda _m: pytest.fail("runtime_skip"),
        n_cases=3,
        runtime_skip=True,
        selector="identity",
    )
    assert res["status"] == "partial_blinded"
    assert res["partial_blinded"] is True
    assert [b["case"] for b in res["blinded_cases"]] == [0]
    assert res["blinded_cases"][0]["fingerprint"] == "fp_blind_0"
    assert calls[1] == {DISPATCH_SKIP_MACRO: "0"}

    # All-blinded: both cases 0 and 1 hit K_case=16 -> status == "blinded", partial_blinded == False.
    c1_crashes = _make_raw(1, "fp_blind_1", R.BLINDING_CASE_THRESHOLD)
    round_no = 0

    def camp_all_blind(binary, seconds, fork, *, extra_env=None):
        nonlocal round_no
        round_no += 1
        batch = c0_crashes if round_no == 1 else c1_crashes
        return {
            "status": "crash_found",
            "returncode": 77,
            "artifacts": batch[:3],
            "_raw_crashes": batch,
            "fuzz_s": 1.0,
            "replay_s": 0.1,
        }

    res_all = R.run_campaign_rounds(
        tmp_path / "bin",
        60,
        campaign=camp_all_blind,
        rebuild=lambda _m: pytest.fail("runtime_skip"),
        n_cases=2,
        runtime_skip=True,
        selector="identity",
    )
    assert res_all["status"] == "blinded"
    assert res_all["partial_blinded"] is False
    assert [b["case"] for b in res_all["blinded_cases"]] == [0, 1]


def test_p1a_non_dispatch_fork_blinding_stops_early(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    fork_calls: list[int] = []

    def camp_fork_blind(binary, seconds, fork, *, extra_env=None):
        assert fork is True
        fork_calls.append(seconds)
        tel = R.parse_libfuzzer_telemetry(
            "#0: cov: 0 ft: 0 corp: 0 exec/s: 0 oom/timeout/crash: 0/0/64 time: 2s job: 64 dft_time: 0\n",
            fuzz_s=2.0,
        )
        return {
            "status": "crash_found",
            "returncode": 77,
            "artifacts": [{"artifact": "crash-1", "kind": "crash", "sha256": "a" * 64, "fingerprint": "fp_fork_fp"}],
            "fuzz_s": 2.0,
            "replay_s": 0.1,
            "telemetry": tel,
        }

    res = R.run_campaign_rounds(
        tmp_path / "bin",
        120,
        campaign=camp_fork_blind,
        rebuild=None,
        n_cases=None,
        workers=4,
    )
    assert len(fork_calls) == 1
    assert fork_calls[0] == R.FORK_BLIND_PROBE_S
    assert res["status"] == "blinded"
    assert res["blinded_fingerprint"] == "fp_fork_fp"
    assert res["keep_going"]["stopped"] == "blinded"
    assert res["unspent_budget_s"] == pytest.approx((120.0 - 2.0) * 4)


def test_smoke_report_pre_skips_quarantined_cases(tmp_path: Path) -> None:
    smoke_path = tmp_path / "smoke_mod.json"
    smoke_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "module": "mod",
                "status": "degraded",
                "quarantined_cases": [1, 3],
                "skip_cases_env": "1,3",
            }
        ),
        encoding="utf-8",
    )
    assert R.load_smoke_skipped_cases(smoke_path) == [1, 3]

    seen_envs: list[dict[str, str] | None] = []

    def camp(binary, seconds, fork, *, extra_env=None):
        seen_envs.append(extra_env)
        return {"status": "clean", "returncode": 0, "artifacts": [], "fuzz_s": 1.0, "replay_s": 0.0}

    res = R.run_campaign_rounds(
        tmp_path / "bin",
        30,
        campaign=camp,
        rebuild=lambda _m: pytest.fail("runtime_skip"),
        n_cases=5,
        runtime_skip=True,
        selector="identity",
        smoke_skipped_cases=R.load_smoke_skipped_cases(smoke_path),
    )
    assert seen_envs == [{DISPATCH_SKIP_MACRO: "1,3"}]
    assert res["smoke_skipped_cases"] == [1, 3]
    assert res["keep_going"]["skipped_cases"] == [1, 3]


def test_p6a_floor_pass_uses_only_case_normalizes_corpus_and_blinds(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    artifacts_dir = tmp_path / "artifacts"
    binary = tmp_path / "fuzz_mod.san"
    binary.write_bytes(b"bin")
    seen_envs: list[dict[str, str]] = []
    case1_attempts = 0

    def fake_runner(
        bin_path,
        cdir,
        adir,
        max_time,
        *,
        extra_env=None,
        runs=None,
        seed=None,
        **kw,
    ):
        nonlocal case1_attempts
        env = dict(extra_env or {})
        seen_envs.append(env)
        case_idx = int(env[R.DISPATCH_ONLY_CASE_ENV])
        if case_idx == 0:
            # Healthy case writes a corpus unit with arbitrary byte 0 (0xFF); merge must normalize byte 0 to 0x00.
            (Path(cdir) / "u0").write_bytes(b"\xffhello")
            return {
                "status": "clean",
                "returncode": 0,
                "artifacts": [],
                "fuzz_s": 0.5,
                "replay_s": 0.0,
                "telemetry": R.parse_libfuzzer_telemetry(
                    "#500\tDONE cov: 25 ft: 40 corp: 1/6b exec/s: 1000 rss: 88Mb\nstat::number_of_executed_units: 500\nstat::peak_rss_mb: 88\n",
                    fuzz_s=0.5,
                ),
            }
        # Case 1 crashes with 0 passes on every attempt until K_case=16 triggers blinding.
        case1_attempts += 1
        cp = Path(adir) / f"crash-c1-{case1_attempts}"
        cp.parent.mkdir(parents=True, exist_ok=True)
        cp.write_bytes(b"\x01bad")
        art = {"artifact": str(cp), "kind": "crash", "sha256": hashlib.sha256(b"\x01bad").hexdigest(), "fingerprint": "fp_c1_blind"}
        return {
            "status": "crash_found",
            "returncode": 77,
            "artifacts": [art],
            "_raw_crashes": [art],
            "fuzz_s": 0.1,
            "replay_s": 0.05,
            "telemetry": R.parse_libfuzzer_telemetry("stat::number_of_executed_units: 1\nstat::peak_rss_mb: 72\n", fuzz_s=0.1),
        }

    out = R.run_floor_pass(
        binary,
        corpus_dir,
        artifacts_dir,
        n_cases=3,
        selector="identity",
        supports_only_case=True,
        profile="quick",
        smoke_skipped=[2],
        campaign_runner=fake_runner,
    )
    by_case = {c["case"]: c for c in out["cases"]}
    assert by_case[0]["status"] == "ok"
    assert by_case[1]["status"] == "blinded"
    assert by_case[2]["status"] == "smoke_skipped"
    assert case1_attempts == R.BLINDING_CASE_THRESHOLD
    assert out["skip_for_shared"] == [1, 2]
    assert out["peak_per_worker_mb"] == 88
    assert any(f.read_bytes() == b"\x00hello" for f in corpus_dir.iterdir())


# --- 4. P2a Explore mode (flag on vs legacy flag off) ----------------------------------------


def test_p2a_explore_mode_gated_by_flag_and_uses_prebuilt_san(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    harness = _write_dispatch_harness(tmp_path, 2)
    bjson, san_bin, eacsl_bin = _make_build_json(tmp_path, module="mod", sources=[str(harness)])
    assert san_bin is not None and eacsl_bin is not None
    corpus = tmp_path / "corpus"
    artifacts = tmp_path / "artifacts"
    out_json = tmp_path / "explore.json"

    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    monkeypatch.setattr(R, "defined_process_launchers", lambda _b: [])
    monkeypatch.setattr(R, "resolve_workers", lambda _v: 2)
    monkeypatch.setattr(R, "campaign_gate_reasons", lambda _r, _m: [])
    monkeypatch.setattr(R.cache, "warm_start_corpus", lambda _m, _c: 0)
    monkeypatch.setattr(R.cache, "publish_corpus", lambda _m, _c: 0)

    # 1. With FRAMAC_FUZZ_EXPLORE_JUDGE=on + --engine auto + --build-json:
    #    MUST resolve .san binary without calling build_module_binary, and set discovering_step="explore".
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    monkeypatch.setattr(fuzz_build, "build_module_binary", lambda *a, **kw: pytest.fail("P7f: must not compile in explore"))

    executed_bins: list[Path] = []
    executed_times: list[int] = []

    def fake_run_fuzz(binary, cdir, adir, max_time, *a, **kw):
        executed_bins.append(Path(binary))
        executed_times.append(int(max_time))
        return {
            "status": "clean",
            "returncode": 0,
            "timed_out": False,
            "artifacts": [],
            "fuzz_s": 1.0,
            "replay_s": 0.0,
            "telemetry": R.parse_libfuzzer_telemetry("stat::number_of_executed_units: 100\nstat::peak_rss_mb: 60\n", fuzz_s=1.0),
        }

    monkeypatch.setattr(R, "run_fuzz_campaign", fake_run_fuzz)

    rc = R.main(
        [
            "campaign",
            "--module",
            "mod",
            "--engine",
            "auto",
            "--build-json",
            str(bjson),
            "--profile",
            "deep",
            "--fuzz-budget",
            "1000",
            "--workers",
            "2",
            "--no-floor-pass",
            "--corpus-dir",
            str(corpus),
            "--artifacts-dir",
            str(artifacts),
            "--out-json",
            str(out_json),
        ]
    )
    assert rc == 0
    rep = json.loads(out_json.read_text(encoding="utf-8"))
    assert rep["engine_used"] == "sanitizers"
    assert rep["discovering_step"] == "explore"
    assert executed_bins == [san_bin]
    # Deep profile gives 4/5 of 1000 CPU-s = 800 CPU-s -> 400 s wall on 2 workers.
    assert rep["sizing"]["fuzz_budget_cpu_s"] == 800
    assert executed_times == [400]
    assert rep["telemetry"]["build_s"] == 0.0

    # Validate against schemas/fuzz_report.schema.json
    schema = minischema.load_schema(FUZZ_REPORT_SCHEMA)
    assert minischema.validate(rep, schema) == []

    # 2. With FRAMAC_FUZZ_EXPLORE_JUDGE=off (legacy default): --engine auto runs dual-engine 50/50 split!
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "off")
    executed_bins.clear()
    executed_times.clear()

    def fake_build(srcs, out_b, **opts):
        eng = opts.get("engine", "auto")
        if eng == "sanitizers":
            return {
                "compile": {"returncode": 0, "binary": str(san_bin), "engine": "sanitizers"},
                "engine_used": "sanitizers",
                "engine_fallback_reason": None,
                "eacsl_compile_attempt": None,
                "sources": list(srcs),
            }
        return {
            "compile": {"returncode": 0, "binary": str(eacsl_bin), "engine": "eacsl"},
            "engine_used": "eacsl",
            "engine_fallback_reason": None,
            "eacsl_compile_attempt": None,
            "sources": list(srcs),
        }

    monkeypatch.setattr(fuzz_build, "build_module_binary", fake_build)
    legacy_json = tmp_path / "legacy.json"
    rc_leg = R.main(
        [
            "campaign",
            "--module",
            "mod",
            "--sources",
            str(harness),
            "--out-bin",
            str(tmp_path / "fuzz_mod"),
            "--engine",
            "auto",
            "--max-time",
            "80",
            "--workers",
            "2",
            "--corpus-dir",
            str(corpus),
            "--artifacts-dir",
            str(artifacts),
            "--out-json",
            str(legacy_json),
        ]
    )
    assert rc_leg == 0
    leg_rep = json.loads(legacy_json.read_text(encoding="utf-8"))
    assert leg_rep["engine_used"] == R.DUAL_ENGINE
    assert "discovering_step" not in leg_rep
    assert executed_bins == [san_bin, eacsl_bin]
    assert executed_times == [40, 40]
    assert minischema.validate(leg_rep, schema) == []


# --- 5. P2d standalone `judge` subcommand ----------------------------------------------------


def test_p2d_judge_case_stratified_sha256_selection_and_mandatory_inputs(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    crashes = tmp_path / "crashes"
    crashes.mkdir()

    # Case 0 dominates grown corpus (40 files), cases 1 & 2 have 3 files each.
    for i in range(40):
        (corpus / f"grown_c0_{i:02d}").write_bytes(bytes([0, i]))
    for i in range(3):
        (corpus / f"grown_c1_{i:02d}").write_bytes(bytes([1, i]))
        (corpus / f"grown_c2_{i:02d}").write_bytes(bytes([2, i]))
    # Targeted seed in corpus + external seed + explorer crash artifact -> ALL mandatory!
    (corpus / "seed-target").write_bytes(bytes([0, 99]))
    (seeds / "imp_0").write_bytes(bytes([1, 99]))
    exp_crash = crashes / "crash-exp"
    exp_crash.write_bytes(bytes([2, 99]))

    explore_report = {"artifacts": [{"artifact": str(exp_crash), "sha256": hashlib.sha256(exp_crash.read_bytes()).hexdigest()}]}

    sel1 = R.select_judge_inputs(corpus, [seeds], explore_report, cap=9, n_cases=3, selector="identity")
    sel2 = R.select_judge_inputs(corpus, [seeds], explore_report, cap=9, n_cases=3, selector="identity")
    assert sel1["selected"] == sel2["selected"]  # deterministic across runs
    assert sel1["mandatory"] == 3
    assert sel1["grown_selected"] == 9
    assert sel1["not_judged_cap"] == 46 - 9

    selected_names = {p.name for p in sel1["selected"]}
    assert {"seed-target", "imp_0", "crash-exp"}.issubset(selected_names)
    # Stratified cap=9 across 3 cases picks all 3 of case 1, all 3 of case 2, and 3 of case 0 (no starvation!).
    c1_picked = [p for p in sel1["selected"] if p.name.startswith("grown_c1_")]
    c2_picked = [p for p in sel1["selected"] if p.name.startswith("grown_c2_")]
    c0_picked = [p for p in sel1["selected"] if p.name.startswith("grown_c0_")]
    assert len(c1_picked) == 3 and len(c2_picked) == 3 and len(c0_picked) == 3


def test_p2d_judge_on_batch_continuation_culprit_last_and_batch_state_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _write_dispatch_harness(tmp_path, 3)
    bjson, _san, eacsl_bin = _make_build_json(tmp_path, module="mod", sources=[str(harness)])
    assert eacsl_bin is not None
    corpus = tmp_path / "corpus"
    corpus.mkdir()

    # Create 4 inputs:
    # - a_ok: passes
    # - b_batch_only: crashes in batch, does NOT reproduce standalone -> batch_state_only
    # - c_ok: passes
    # - d_last_real: last element in batch crashes AND reproduces standalone -> culprit == last edge case!
    f0 = corpus / "u0"
    f1 = corpus / "u1"
    f2 = corpus / "u2"
    f3 = corpus / "u3"
    f0.write_bytes(b"\x00ok0")
    f1.write_bytes(b"\x01stateonly")
    f2.write_bytes(b"\x02ok2")
    f3.write_bytes(b"\x00realcrash")

    # Explorer found an adjacent-line ASan crash at src/a.c:43 in `parse`, and exact same artifact sha256!
    explore_report = tmp_path / "explore.json"
    explore_report.write_text(
        json.dumps(
            {
                "mode": "campaign",
                "module": "mod",
                "engine_used": "sanitizers",
                "status": "crash_found",
                "artifacts": [
                    {
                        "artifact": str(f3),
                        "sha256": hashlib.sha256(f3.read_bytes()).hexdigest(),
                        "engine": "sanitizers",
                        "fingerprint": "fp_explore_asan",
                        "failure": {"file": "src/a.c", "line": 43, "function": "parse", "alarm_kind": "mem_access"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    batches_seen: list[list[str]] = []
    executed_order: list[str] = []

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        inputs_in_cmd = [Path(a) for a in cmd[1:] if not a.startswith("-")]
        batches_seen.append([p.name for p in inputs_in_cmd])
        lines: list[str] = []
        for p in inputs_in_cmd:
            executed_order.append(p.name)
            lines.append(f"Running: {p.resolve()}")
            if p.name == "u1":
                lines.append(_eacsl_failure_log("src/a.c", 10, "leaky_fn", "\\valid(q)"))
                return SandboxResult(returncode=134, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")
            if p.name == "u3":
                lines.append(_eacsl_failure_log("src/a.c", 42, "parse", "\\valid_read(p)"))
                return SandboxResult(returncode=134, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")
            lines.append(f"Executed {p.resolve()} in 1 ms")
        return SandboxResult(returncode=0, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")

    standalone_calls: list[str] = []

    def fake_replay_artifact(bin_path, art_path, scratch, **kw):
        p = Path(art_path)
        standalone_calls.append(p.name)
        if p.name == "u1":
            # Does NOT reproduce alone in a fresh process -> batch_state_only!
            return {
                "reproduced": False,
                "returncode": 0,
                "timed_out": False,
                "failure": None,
                "link_stub_abort": None,
                "resource_abort": None,
                "out_of_memory": False,
                "log_tail": "clean alone",
                "frames": [],
            }
        return {
            "reproduced": True,
            "returncode": 134,
            "timed_out": False,
            "failure": {
                "file": "src/a.c",
                "line": 42,
                "function": "parse",
                "kind": "assertion",
                "alarm_kind": "mem_access",
                "predicate": "\\valid_read(p)",
                "is_rte": True,
            },
            "link_stub_abort": None,
            "resource_abort": None,
            "out_of_memory": False,
            "log_tail": "confirmed standalone",
            "frames": [],
        }

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_sandbox)
    monkeypatch.setattr(crash_replay, "replay_artifact", fake_replay_artifact)

    out_json = tmp_path / "judge.json"
    rc = R.main(
        [
            "judge",
            "--module",
            "mod",
            "--build-json",
            str(bjson),
            "--corpus-dir",
            str(corpus),
            "--explore-report",
            str(explore_report),
            "--profile",
            "quick",
            "--batch-size",
            "4",
            "--out-json",
            str(out_json),
        ]
    )
    assert rc == 0
    rep = json.loads(out_json.read_text(encoding="utf-8"))

    # O(N) strict forward progress: every input is executed at most ONCE across all batches!
    assert len(batches_seen) <= 3
    assert sorted(executed_order) == ["u0", "u1", "u2", "u3"]
    assert len(executed_order) == 4

    assert rep["status"] == "crash_found"
    assert rep["discovering_step"] == "judge"
    assert rep["corpus_cap"] == 512
    assert rep["inputs"]["judged"] == 4
    assert rep["inputs"]["passed"] == 2
    assert rep["inputs"]["failed"] == 2
    assert rep["not_judged"] == 0
    assert rep["inputs"]["judged"] + rep["not_judged"] == rep["inputs"]["total"]

    # Fresh-process confirmation separated u1 into batch_state_only and promoted u3 into artifacts.
    assert set(standalone_calls) == {"u1", "u3"}
    assert len(rep["batch_state_only"]) == 1
    assert Path(rep["batch_state_only"][0]["input"]).name == "u1"
    assert len(rep["artifacts"]) == 1
    assert Path(rep["artifacts"][0]["artifact"]).name == "u3"
    assert rep["artifacts"][0]["standalone_confirmed"] is True

    # Cross-engine linking (D1b) linked u3 to fp_explore_asan!
    assert len(rep["cross_engine_links"]) == 1
    assert rep["cross_engine_links"][0]["explore_fingerprint"] == "fp_explore_asan"
    assert rep["cross_engine_links"][0]["match"] == "same_artifact"

    # Validate against schemas/judge_report.schema.json!
    judge_schema = minischema.load_schema(JUDGE_REPORT_SCHEMA)
    assert minischema.validate(rep, judge_schema) == []


def test_p2d_judge_per_case_blinding_and_not_judged_accounting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _write_dispatch_harness(tmp_path, 2)
    bjson, _san, _eacsl = _make_build_json(tmp_path, module="mod", sources=[str(harness)])
    corpus = tmp_path / "corpus"
    corpus.mkdir()

    # 20 inputs for case 0 (will blind at K_case=16, leaving 4 as not_judged_blinded) + 4 healthy inputs for case 1.
    for i in range(20):
        (corpus / f"c0_{i:02d}").write_bytes(bytes([0, i]))
    for i in range(4):
        (corpus / f"c1_{i:02d}").write_bytes(bytes([1, i]))

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        inputs_in_cmd = [Path(a) for a in cmd[1:] if not a.startswith("-")]
        lines: list[str] = []
        for p in inputs_in_cmd:
            lines.append(f"Running: {p.resolve()}")
            if p.name.startswith("c0_"):
                lines.append(_eacsl_failure_log("src/bad.c", 12, "bad_fn", "\\valid(p)"))
                return SandboxResult(returncode=134, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")
            lines.append(f"Executed {p.resolve()} in 1 ms")
        return SandboxResult(returncode=0, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")

    def fake_replay_artifact(bin_path, art_path, scratch, **kw):
        return {
            "reproduced": True,
            "returncode": 134,
            "timed_out": False,
            "failure": {
                "file": "src/bad.c",
                "line": 12,
                "function": "bad_fn",
                "kind": "assertion",
                "alarm_kind": "mem_access",
                "predicate": "\\valid(p)",
                "is_rte": True,
            },
            "link_stub_abort": None,
            "resource_abort": None,
            "out_of_memory": False,
            "log_tail": "confirmed",
            "frames": [],
        }

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_sandbox)
    monkeypatch.setattr(crash_replay, "replay_artifact", fake_replay_artifact)

    rep = R.run_judge(
        "mod",
        bjson,
        corpus,
        profile="standard",
        batch_size=1,
    )
    assert rep["status"] == "partial_blinded"
    assert rep["partial_blinded"] is True
    assert [b["case"] for b in rep["blinded_cases"]] == [0]
    assert rep["inputs"]["passed"] == 4
    assert rep["inputs"]["failed"] == R.BLINDING_CASE_THRESHOLD
    assert rep["inputs"]["not_judged_breakdown"]["blinded"] == 20 - R.BLINDING_CASE_THRESHOLD
    assert rep["inputs"]["judged"] + rep["not_judged"] == rep["inputs"]["total"] == 24
    # Fresh-process replay ran ONCE for the fingerprint, not 16 times!
    assert rep["telemetry"]["fresh_confirmations"] == 1
    judge_schema = minischema.load_schema(JUDGE_REPORT_SCHEMA)
    assert minischema.validate(rep, judge_schema) == []


def test_p2d_judge_skips_cleanly_when_no_eacsl_binary(tmp_path: Path) -> None:
    bjson, _san, _eacsl = _make_build_json(tmp_path, module="mod", with_san=True, with_eacsl=False)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "u0").write_bytes(b"abc")
    rep = R.run_judge("mod", bjson, corpus, profile="quick")
    assert rep["status"] == "skipped"
    assert rep["binary"] is None
    assert rep["not_judged"] == 1
    judge_schema = minischema.load_schema(JUDGE_REPORT_SCHEMA)
    assert minischema.validate(rep, judge_schema) == []


# --- 6. P2e `eacsl-fuzz` subcommand ----------------------------------------------------------


def test_p2e_eacsl_fuzz_deep_share_skips_judge_and_smoke_cases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _write_dispatch_harness(tmp_path, 4)
    bjson, _san, eacsl_bin = _make_build_json(tmp_path, module="mod", sources=[str(harness)])
    assert eacsl_bin is not None
    smoke_path = tmp_path / "smoke.json"
    smoke_path.write_text(json.dumps({"quarantined_cases": [0]}), encoding="utf-8")
    judge_path = tmp_path / "judge.json"
    judge_path.write_text(
        json.dumps(
            {
                "status": "partial_blinded",
                "blinded_cases": [{"case": 1, "fingerprint": "fp1", "crashes": 16}],
                "artifacts": [{"artifact": "x", "case": 2, "fingerprint": "fp2"}],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    monkeypatch.setattr(R, "resolve_workers", lambda _v: 2)

    seen_calls: list[tuple[Path, int, dict[str, str] | None]] = []

    def fake_run_fuzz(binary, cdir, adir, max_time, *a, extra_env=None, **kw):
        seen_calls.append((Path(binary), int(max_time), extra_env))
        return {
            "status": "clean",
            "returncode": 0,
            "timed_out": False,
            "artifacts": [],
            "fuzz_s": 1.0,
            "replay_s": 0.0,
            "telemetry": R.parse_libfuzzer_telemetry("stat::number_of_executed_units: 50\n", fuzz_s=1.0),
        }

    monkeypatch.setattr(R, "run_fuzz_campaign", fake_run_fuzz)

    out_json = tmp_path / "eacsl_fuzz.json"
    rc = R.main(
        [
            "eacsl-fuzz",
            "--module",
            "mod",
            "--build-json",
            str(bjson),
            "--corpus-dir",
            str(tmp_path / "corpus"),
            "--artifacts-dir",
            str(tmp_path / "artifacts"),
            "--judge-report",
            str(judge_path),
            "--smoke-report",
            str(smoke_path),
            "--profile",
            "deep",
            "--fuzz-budget",
            "1000",
            "--workers",
            "2",
            "--out-json",
            str(out_json),
        ]
    )
    assert rc == 0
    rep = json.loads(out_json.read_text(encoding="utf-8"))
    assert rep["discovering_step"] == "eacsl_fuzz"
    assert rep["engine_used"] == "eacsl"
    assert rep["smoke_skipped_cases"] == [0]
    assert rep["judge_skipped_cases"] == [1, 2]
    assert rep["sizing"]["fuzz_budget_cpu_s"] == 200  # 1/5 of 1000
    assert seen_calls == [(eacsl_bin, 100, {DISPATCH_SKIP_MACRO: "0,1,2"})]
    fuzz_schema = minischema.load_schema(FUZZ_REPORT_SCHEMA)
    assert minischema.validate(rep, fuzz_schema) == []

    # Under standard profile, eacsl-fuzz skips cleanly without invoking libFuzzer.
    seen_calls.clear()
    out_std = tmp_path / "eacsl_fuzz_std.json"
    rc_std = R.main(
        [
            "eacsl-fuzz",
            "--module",
            "mod",
            "--build-json",
            str(bjson),
            "--corpus-dir",
            str(tmp_path / "corpus"),
            "--artifacts-dir",
            str(tmp_path / "artifacts"),
            "--profile",
            "standard",
            "--fuzz-budget",
            "1000",
            "--out-json",
            str(out_std),
        ]
    )
    assert rc_std == 0
    rep_std = json.loads(out_std.read_text(encoding="utf-8"))
    assert rep_std["status"] == "skipped" and seen_calls == []
    assert minischema.validate(rep_std, fuzz_schema) == []

    # When judge was fully blinded, eacsl-fuzz reports unspent_blinded without running libFuzzer.
    blind_judge = tmp_path / "judge_blind.json"
    blind_judge.write_text(json.dumps({"status": "blinded", "blinded_cases": []}), encoding="utf-8")
    out_blind = tmp_path / "eacsl_fuzz_blind.json"
    rc_blind = R.main(
        [
            "eacsl-fuzz",
            "--module",
            "mod",
            "--build-json",
            str(bjson),
            "--corpus-dir",
            str(tmp_path / "corpus"),
            "--artifacts-dir",
            str(tmp_path / "artifacts"),
            "--judge-report",
            str(blind_judge),
            "--profile",
            "deep",
            "--fuzz-budget",
            "1000",
            "--out-json",
            str(out_blind),
        ]
    )
    assert rc_blind == 0
    rep_blind = json.loads(out_blind.read_text(encoding="utf-8"))
    assert rep_blind["status"] == "unspent_blinded"
    assert rep_blind["unspent_budget_s"] == 200.0
    assert seen_calls == []
    assert minischema.validate(rep_blind, fuzz_schema) == []


# --- 7. Schema negative validation checks ----------------------------------------------------


def test_schemas_load_and_reject_invalid_payloads() -> None:
    fuzz_schema = minischema.load_schema(FUZZ_REPORT_SCHEMA)
    judge_schema = minischema.load_schema(JUDGE_REPORT_SCHEMA)

    # Fuzz schema rejects unknown status and invalid discovering_step.
    assert minischema.validate({"mode": "campaign", "status": "bogus_status"}, fuzz_schema)
    assert minischema.validate({"mode": "campaign", "status": "clean", "discovering_step": "unknown_step"}, fuzz_schema)

    # Judge schema rejects missing required keys and unexpected top-level keys.
    assert minischema.validate({"mode": "judge", "status": "clean"}, judge_schema)


def test_p2d_judge_culprit_is_last_no_infinite_loop_and_adjacent_line_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bjson, _san, _eacsl = _make_build_json(tmp_path, module="mod")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for name in ("a0", "a1", "a2"):
        (corpus / name).write_bytes(name.encode("utf-8"))

    # Different artifact sha256, same file + function, line 44 vs 42 (delta=2 <= 5 -> adjacent_line link!)
    explore_doc = {
        "engine_used": "sanitizers",
        "artifacts": [
            {
                "artifact": "other_crash",
                "sha256": "0" * 64,
                "engine": "sanitizers",
                "fingerprint": "fp_adj_asan",
                "failure": {"file": "src/a.c", "line": 44, "function": "parse"},
            }
        ],
    }

    batch_calls = 0

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        nonlocal batch_calls
        batch_calls += 1
        assert batch_calls <= 2, "infinite loop detected when culprit == last!"
        inputs_in_cmd = [Path(a) for a in cmd[1:] if not a.startswith("-")]
        lines = []
        for idx, p in enumerate(inputs_in_cmd):
            lines.append(f"Running: {p.resolve()}")
            if idx == len(inputs_in_cmd) - 1:
                lines.append(_eacsl_failure_log("src/a.c", 42, "parse", "\\valid_read(p)"))
                return SandboxResult(returncode=134, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")
            lines.append(f"Executed {p.resolve()} in 1 ms")
        return SandboxResult(returncode=0, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_sandbox)
    monkeypatch.setattr(
        crash_replay,
        "replay_artifact",
        lambda *_a, **_kw: {
            "reproduced": True,
            "returncode": 134,
            "timed_out": False,
            "failure": {
                "file": "src/a.c",
                "line": 42,
                "function": "parse",
                "kind": "assertion",
                "alarm_kind": "mem_access",
                "predicate": "\\valid_read(p)",
                "is_rte": True,
            },
            "link_stub_abort": None,
            "resource_abort": None,
            "out_of_memory": False,
            "log_tail": "confirmed",
            "frames": [],
        },
    )

    rep = R.run_judge("mod", bjson, corpus, explore_report=explore_doc, batch_size=3)
    assert batch_calls == 1
    assert rep["inputs"]["passed"] == 2
    assert rep["inputs"]["failed"] == 1
    assert rep["not_judged"] == 0
    assert rep["cross_engine_links"][0]["match"] == "adjacent_line"
    assert rep["cross_engine_links"][0]["line_delta"] == 2
    assert minischema.validate(rep, minischema.load_schema(JUDGE_REPORT_SCHEMA)) == []


def test_p2d_judge_non_dispatch_blinding_and_p8a_clean_mid_batch_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bjson, _san, _eacsl = _make_build_json(tmp_path, module="cli_mod")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for i in range(4):
        (corpus / f"x{i}").write_bytes(f"arg{i}".encode())

    # P8a: input at index 1 in the first batch calls _Exit(0) mid-batch; batch[2:] continues cleanly and all 4 inputs pass!
    calls: list[list[str]] = []

    def fake_p8a_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        inputs_in_cmd = [Path(a) for a in cmd[1:] if not a.startswith("-")]
        calls.append([p.name for p in inputs_in_cmd])
        lines = []
        for idx, p in enumerate(inputs_in_cmd):
            lines.append(f"Running: {p.resolve()}")
            if len(calls) == 1 and idx == 1:
                # Clean _Exit(0) without Executed line
                return SandboxResult(returncode=0, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")
            lines.append(f"Executed {p.resolve()} in 1 ms")
        return SandboxResult(returncode=0, stdout="", stderr="\n".join(lines), timed_out=False, sandbox="fake")

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_p8a_sandbox)
    rep_p8 = R.run_judge("cli_mod", bjson, corpus, batch_size=4)
    assert rep_p8["status"] == "clean"
    assert rep_p8["inputs"]["passed"] == 4 and rep_p8["not_judged"] == 0
    assert len(calls) == 2

    # Non-dispatch blinding: 20 identical failures stop at K=16, leaving 4 as not_judged_blinded.
    corpus2 = tmp_path / "corpus2"
    corpus2.mkdir()
    for i in range(20):
        (corpus2 / f"b{i:02d}").write_bytes(f"bad{i}".encode())

    def fake_blind_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        inputs_in_cmd = [Path(a) for a in cmd[1:] if not a.startswith("-")]
        p0 = inputs_in_cmd[0]
        return SandboxResult(
            returncode=134,
            stdout="",
            stderr=f"Running: {p0.resolve()}\n" + _eacsl_failure_log("src/c.c", 7, "main", "\\valid(argv)"),
            timed_out=False,
            sandbox="fake",
        )

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_blind_sandbox)
    monkeypatch.setattr(
        crash_replay,
        "replay_artifact",
        lambda *_a, **_kw: {
            "reproduced": True,
            "returncode": 134,
            "timed_out": False,
            "failure": {
                "file": "src/c.c",
                "line": 7,
                "function": "main",
                "kind": "assertion",
                "alarm_kind": "mem_access",
                "predicate": "\\valid(argv)",
                "is_rte": True,
            },
            "link_stub_abort": None,
            "resource_abort": None,
            "out_of_memory": False,
            "log_tail": "confirmed",
            "frames": [],
        },
    )
    rep_blind = R.run_judge("cli_mod", bjson, corpus2, batch_size=2)
    assert rep_blind["status"] == "blinded"
    assert rep_blind["inputs"]["failed"] == R.BLINDING_CASE_THRESHOLD
    assert rep_blind["inputs"]["not_judged_breakdown"]["blinded"] == 20 - R.BLINDING_CASE_THRESHOLD
    assert minischema.validate(rep_blind, minischema.load_schema(JUDGE_REPORT_SCHEMA)) == []

