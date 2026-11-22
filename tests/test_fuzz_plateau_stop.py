"""Unit and replay tests for W1-D execution-count plateau stop (`FRAMAC_FUZZ_PLATEAU_STOP`),
worker-log polling + graceful `SIGTERM`, `stopped_reason`/`cpu_saved_s` reporting, and
`schemas/fuzz_report.schema.json` validation.

Includes the verbatim shared-pass `telemetry.series` from QCBOR run-1
(`workspace/reports/fuzz/libqcbor_a.json`) inlined as a self-contained fixture so CI has zero
external path dependency.
"""

from __future__ import annotations

import io
import signal
import subprocess
from pathlib import Path
from typing import Any

import pytest

import minischema
import run_eacsl_fuzz as R
import sandbox_exec
from sandbox_exec import SandboxResult

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent
FUZZ_REPORT_SCHEMA = REPO_ROOT / "schemas" / "fuzz_report.schema.json"

# Verbatim shared-pass `telemetry.series` recorded in QCBOR/run-1/workspace/reports/fuzz/libqcbor_a.json
# (64 points across the multi-worker shared pass where `cov > 1000`, `standard` profile, 7 workers).
QCBOR_RUN1_SHARED_SERIES: list[dict[str, int]] = [
    {"unit": 147734, "cov": 2745, "ft": 4249, "corp": 2048, "exec_s": 3887, "rss_mb": 337},
    {"unit": 7403772, "cov": 2869, "ft": 5083, "corp": 2523, "exec_s": 5504, "rss_mb": 453},
    {"unit": 11012047, "cov": 2875, "ft": 5155, "corp": 2561, "exec_s": 4944, "rss_mb": 453},
    {"unit": 118207, "cov": 2679, "ft": 4138, "corp": 1958, "exec_s": 4728, "rss_mb": 278},
    {"unit": 597534, "cov": 2802, "ft": 4459, "corp": 2174, "exec_s": 6356, "rss_mb": 475},
    {"unit": 1584298, "cov": 2819, "ft": 4627, "corp": 2255, "exec_s": 7368, "rss_mb": 475},
    {"unit": 3209058, "cov": 2832, "ft": 4876, "corp": 2405, "exec_s": 6482, "rss_mb": 475},
    {"unit": 5489468, "cov": 2833, "ft": 4957, "corp": 2466, "exec_s": 5877, "rss_mb": 475},
    {"unit": 8087163, "cov": 2869, "ft": 5106, "corp": 2536, "exec_s": 5306, "rss_mb": 475},
    {"unit": 11990900, "cov": 2876, "ft": 5167, "corp": 2574, "exec_s": 4603, "rss_mb": 475},
    {"unit": 219041, "cov": 2752, "ft": 4278, "corp": 2069, "exec_s": 5342, "rss_mb": 417},
    {"unit": 819925, "cov": 2806, "ft": 4517, "corp": 2210, "exec_s": 6720, "rss_mb": 459},
    {"unit": 2059582, "cov": 2822, "ft": 4690, "corp": 2293, "exec_s": 7252, "rss_mb": 459},
    {"unit": 3646073, "cov": 2832, "ft": 4891, "corp": 2420, "exec_s": 6581, "rss_mb": 459},
    {"unit": 6121672, "cov": 2857, "ft": 5006, "corp": 2479, "exec_s": 5903, "rss_mb": 459},
    {"unit": 9196532, "cov": 2870, "ft": 5134, "corp": 2553, "exec_s": 5234, "rss_mb": 459},
    {"unit": 13950208, "cov": 2876, "ft": 5214, "corp": 2589, "exec_s": 4527, "rss_mb": 459},
    {"unit": 354374, "cov": 2799, "ft": 4377, "corp": 2132, "exec_s": 6328, "rss_mb": 475},
    {"unit": 1086888, "cov": 2813, "ft": 4556, "corp": 2221, "exec_s": 7103, "rss_mb": 475},
    {"unit": 2492291, "cov": 2823, "ft": 4754, "corp": 2338, "exec_s": 6961, "rss_mb": 475},
    {"unit": 4375259, "cov": 2832, "ft": 4929, "corp": 2444, "exec_s": 6368, "rss_mb": 475},
    {"unit": 6851651, "cov": 2868, "ft": 5072, "corp": 2518, "exec_s": 5556, "rss_mb": 475},
    {"unit": 10164739, "cov": 2870, "ft": 5148, "corp": 2560, "exec_s": 4929, "rss_mb": 475},
    {"unit": 68259, "cov": 2666, "ft": 4113, "corp": 1947, "exec_s": 2528, "rss_mb": 228},
    {"unit": 497626, "cov": 2802, "ft": 4445, "corp": 2170, "exec_s": 5468, "rss_mb": 453},
    {"unit": 1381652, "cov": 2819, "ft": 4619, "corp": 2248, "exec_s": 6486, "rss_mb": 453},
    {"unit": 2880522, "cov": 2831, "ft": 4830, "corp": 2379, "exec_s": 6546, "rss_mb": 453},
    {"unit": 4929361, "cov": 2833, "ft": 4941, "corp": 2455, "exec_s": 6018, "rss_mb": 453},
    {"unit": 7717232, "cov": 2869, "ft": 5098, "corp": 2529, "exec_s": 5430, "rss_mb": 453},
    {"unit": 11366993, "cov": 2876, "ft": 5167, "corp": 2572, "exec_s": 4882, "rss_mb": 453},
    {"unit": 161115, "cov": 2753, "ft": 4257, "corp": 2065, "exec_s": 4131, "rss_mb": 356},
    {"unit": 711440, "cov": 2811, "ft": 4515, "corp": 2207, "exec_s": 5978, "rss_mb": 456},
    {"unit": 1814366, "cov": 2821, "ft": 4677, "corp": 2285, "exec_s": 6795, "rss_mb": 456},
    {"unit": 3432120, "cov": 2832, "ft": 4889, "corp": 2419, "exec_s": 6085, "rss_mb": 456},
    {"unit": 5786735, "cov": 2866, "ft": 5036, "corp": 2493, "exec_s": 5423, "rss_mb": 456},
    {"unit": 8838379, "cov": 2870, "ft": 5136, "corp": 2553, "exec_s": 4954, "rss_mb": 456},
    {"unit": 9663, "cov": 2568, "ft": 3961, "corp": 1822, "exec_s": 508, "rss_mb": 153},
    {"unit": 375801, "cov": 2799, "ft": 4395, "corp": 2146, "exec_s": 5693, "rss_mb": 459},
    {"unit": 1190835, "cov": 2813, "ft": 4584, "corp": 2234, "exec_s": 7088, "rss_mb": 459},
    {"unit": 2638962, "cov": 2823, "ft": 4752, "corp": 2341, "exec_s": 7627, "rss_mb": 459},
    {"unit": 4383792, "cov": 2832, "ft": 4925, "corp": 2445, "exec_s": 6592, "rss_mb": 459},
    {"unit": 6992521, "cov": 2868, "ft": 5075, "corp": 2523, "exec_s": 5648, "rss_mb": 459},
    {"unit": 10665769, "cov": 2870, "ft": 5149, "corp": 2564, "exec_s": 4979, "rss_mb": 459},
    {"unit": 100212, "cov": 2710, "ft": 4184, "corp": 1999, "exec_s": 3340, "rss_mb": 267},
    {"unit": 588281, "cov": 2805, "ft": 4471, "corp": 2178, "exec_s": 6127, "rss_mb": 460},
    {"unit": 1599761, "cov": 2820, "ft": 4630, "corp": 2256, "exec_s": 7271, "rss_mb": 460},
    {"unit": 3203692, "cov": 2831, "ft": 4863, "corp": 2395, "exec_s": 6787, "rss_mb": 460},
    {"unit": 5495774, "cov": 2833, "ft": 4949, "corp": 2460, "exec_s": 6133, "rss_mb": 460},
    {"unit": 8267542, "cov": 2869, "ft": 5100, "corp": 2530, "exec_s": 5608, "rss_mb": 460},
    {"unit": 12584801, "cov": 2876, "ft": 5167, "corp": 2569, "exec_s": 4821, "rss_mb": 460},
    {"unit": 233233, "cov": 2775, "ft": 4311, "corp": 2098, "exec_s": 5182, "rss_mb": 427},
    {"unit": 889240, "cov": 2813, "ft": 4545, "corp": 2218, "exec_s": 6490, "rss_mb": 475},
    {"unit": 2087439, "cov": 2822, "ft": 4689, "corp": 2291, "exec_s": 7248, "rss_mb": 475},
    {"unit": 3601730, "cov": 2832, "ft": 4892, "corp": 2418, "exec_s": 6408, "rss_mb": 475},
    {"unit": 5985487, "cov": 2866, "ft": 5035, "corp": 2490, "exec_s": 5609, "rss_mb": 475},
    {"unit": 8921126, "cov": 2870, "ft": 5133, "corp": 2547, "exec_s": 5141, "rss_mb": 475},
    {"unit": 13461110, "cov": 2876, "ft": 5207, "corp": 2578, "exec_s": 4609, "rss_mb": 475},
    {"unit": 292570, "cov": 2799, "ft": 4392, "corp": 2137, "exec_s": 4643, "rss_mb": 466},
    {"unit": 988822, "cov": 2813, "ft": 4546, "corp": 2212, "exec_s": 6636, "rss_mb": 466},
    {"unit": 2264285, "cov": 2823, "ft": 4720, "corp": 2307, "exec_s": 7399, "rss_mb": 466},
    {"unit": 3975867, "cov": 2832, "ft": 4902, "corp": 2419, "exec_s": 6659, "rss_mb": 466},
    {"unit": 6475444, "cov": 2867, "ft": 5052, "corp": 2496, "exec_s": 5675, "rss_mb": 466},
    {"unit": 9654788, "cov": 2870, "ft": 5138, "corp": 2549, "exec_s": 5316, "rss_mb": 466},
    {"unit": 13930953, "cov": 2876, "ft": 5214, "corp": 2581, "exec_s": 4512, "rss_mb": 466},
]


def _split_worker_tracks(series: list[dict[str, int]]) -> list[list[dict[str, int]]]:
    """Split a combined `telemetry.series` into per-worker monotonic `unit` tracks."""
    tracks: list[list[dict[str, int]]] = []
    cur: list[dict[str, int]] = []
    for pt in series:
        if cur and pt["unit"] < cur[-1]["unit"]:
            tracks.append(cur)
            cur = []
        cur.append(pt)
    if cur:
        tracks.append(cur)
    return tracks


def test_qcbor_run1_replay_preserves_4m_8m_breakthrough_and_fires_in_flat_tail() -> None:
    """Replaying QCBOR run-1's recorded `telemetry.series` through `ExecutionPlateauDetector`:
    (a) must NOT fire at 1.5M execs/worker or during the 3M-5.5M lull (preserving the 4M-8M
        +37-edge breakthrough `2832 -> 2869`, `ft 4902 -> 5106`);
    (b) DOES fire cleanly once every active worker traverses the flat tail (`0` new `cov` edges
        and `< 0.5%` relative `ft` growth over `W = 4_000_000` executions) after ~8M-10M execs/worker.
    """
    tracks = _split_worker_tracks(QCBOR_RUN1_SHARED_SERIES)
    # Use the 7 full-resolution worker tracks (len >= 6) from the 7-worker shared pass.
    worker_tracks = [t for t in tracks if len(t) >= 6][:7]
    assert len(worker_tracks) == 7

    detector = R.ExecutionPlateauDetector.from_profile("standard", expected_workers=7)

    # Interleave observations in chronological execution order across all 7 workers.
    events = sorted(
        [(pt["unit"], f"fuzz-{idx}.log", pt["cov"], pt["ft"]) for idx, t in enumerate(worker_tracks) for pt in t],
        key=lambda e: e[0],
    )

    max_cov_seen_before_8m = 0
    for unit, wid, cov, ft in events:
        detector.observe(wid, unit, cov, ft)
        if unit <= 1_500_000:
            assert not detector.is_plateaued(), f"fired prematurely at {unit} execs (<= 1.5M)"
        if unit <= 8_500_000:
            max_cov_seen_before_8m = max(max_cov_seen_before_8m, cov)
            # Must NOT stop before the 4M-8M +37-edge breakthrough (2832 -> 2869).
            assert not detector.is_plateaued(), f"fired during breakthrough phase at {unit} execs"

    assert max_cov_seen_before_8m >= 2869

    # Now replay the flat tail after ~8M-10M execs/worker:
    # Take the exact recorded QCBOR prefix up through ~8M-10M (`cov=2869..2870`, `ft=5100..5149`),
    # then append flat pulse samples advancing by +1M execs/worker with 0 new `cov` and <0.5% `ft`.
    det_tail = R.ExecutionPlateauDetector.from_profile("standard", expected_workers=7)
    anchor_by_worker: dict[str, tuple[int, int, int]] = {}
    for idx, t in enumerate(worker_tracks):
        wid = f"fuzz-{idx}.log"
        for pt in t:
            if pt["unit"] <= 10_700_000:
                det_tail.observe(wid, pt["unit"], pt["cov"], pt["ft"])
                anchor_by_worker[wid] = (pt["unit"], pt["cov"], pt["ft"])

    assert not det_tail.is_plateaued()

    # Step forward 1M execs at a time in the flat tail (0 new cov, +0.2% ft total over 4M execs).
    fired_at_step: int | None = None
    for step in range(1, 7):
        for wid, (u0, c0, f0) in anchor_by_worker.items():
            # Tiny feature creep (+2 features per step -> +8 / ~5130 = 0.16% < 0.5%).
            det_tail.observe(wid, u0 + step * 1_000_000, c0, f0 + 2 * step)
        if det_tail.is_plateaued():
            fired_at_step = step
            break

    assert fired_at_step == 4, f"expected plateau stop right after W=4M flat execs, got step={fired_at_step}"


def test_plateau_detector_thresholds_cov_ft_and_all_workers() -> None:
    """Verify strict `0` cov delta, `< 0.5%` relative `ft` growth, `min_execs_per_worker`,
    all-workers requirement, and profile thresholds (`quick` / `standard` / `deep`).
    """
    assert R.plateau_config_for_profile("quick") == (1_000_000, 1_500_000)
    assert R.plateau_config_for_profile("standard") == (3_000_000, 4_000_000)
    assert R.plateau_config_for_profile("deep") == (10_000_000, 8_000_000)

    # 1. 0 new cov edges, but >= 0.5% relative ft growth -> must NOT fire.
    d_ft = R.ExecutionPlateauDetector(min_execs_per_worker=3_000_000, window_execs=4_000_000, expected_workers=2)
    for wid in ("fuzz-0.log", "fuzz-1.log"):
        d_ft.observe(wid, 1_000_000, 500, 1000)
        d_ft.observe(wid, 5_000_000, 500, 1005)  # +5 / 1000 == 0.50% (not strictly < 0.5%)
    assert not d_ft.is_plateaued()

    # 2. +1 new cov edge with 0% ft growth -> must NOT fire.
    d_cov = R.ExecutionPlateauDetector(min_execs_per_worker=3_000_000, window_execs=4_000_000, expected_workers=2)
    for wid in ("fuzz-0.log", "fuzz-1.log"):
        d_cov.observe(wid, 1_000_000, 500, 1000)
        d_cov.observe(wid, 5_000_000, 501, 1000)
    assert not d_cov.is_plateaued()

    # 3. 1 of 2 workers plateaued, 2nd still growing -> must NOT fire until BOTH plateau.
    d_all = R.ExecutionPlateauDetector(min_execs_per_worker=3_000_000, window_execs=4_000_000, expected_workers=2)
    d_all.observe("fuzz-0.log", 1_000_000, 500, 1000)
    d_all.observe("fuzz-0.log", 5_000_000, 500, 1004)  # +0.4% < 0.5% -> worker 0 plateaued
    d_all.observe("fuzz-1.log", 1_000_000, 500, 1000)
    d_all.observe("fuzz-1.log", 5_000_000, 502, 1010)  # worker 1 still gaining edges
    assert d_all.is_worker_plateaued("fuzz-0.log") is True
    assert d_all.is_worker_plateaued("fuzz-1.log") is False
    assert d_all.is_plateaued() is False

    d_all.observe("fuzz-1.log", 9_000_000, 502, 1014)  # +4 / 1010 = 0.396% < 0.5%
    assert d_all.is_worker_plateaued("fuzz-1.log") is True
    assert d_all.is_plateaued() is True

    # 4. Below min_execs_per_worker (even if window_execs is smaller) -> must NOT fire.
    d_floor = R.ExecutionPlateauDetector(min_execs_per_worker=10_000_000, window_execs=2_000_000, expected_workers=1)
    d_floor.observe("fuzz-0.log", 1_000_000, 500, 1000)
    d_floor.observe("fuzz-0.log", 9_999_999, 500, 1000)
    assert not d_floor.is_plateaued()
    d_floor.observe("fuzz-0.log", 10_000_000, 500, 1000)
    assert d_floor.is_plateaued()


def test_plateau_monitor_polls_worker_logs_sends_sigterm_and_records_cpu_saved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_run_sandboxed_with_plateau_monitor` incrementally polls `fuzz-*.log` (including lines
    split across reads), sends graceful `SIGTERM` once all workers plateau, and `_run_fuzz_campaign_once`
    + `run_campaign_rounds` record `status='clean'`, `stopped_reason='plateau'`, and `cpu_saved_s > 0`.
    """
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    detector = R.ExecutionPlateauDetector.from_profile("quick", expected_workers=2)

    signals_sent: list[int] = []

    class FakePopen:
        def __init__(self, argv: list[str], **_kw: Any) -> None:
            self.pid = 424242
            self.argv = argv
            self.stdout = io.BytesIO(b"INFO: -jobs=2 -workers=2\n")
            self.stderr = io.BytesIO(b"")
            self.returncode: int | None = None
            self._tick = 0

        def wait(self, timeout: float | None = None) -> int:
            if self.returncode is not None:
                return self.returncode
            self._tick += 1
            log0 = scratch / "fuzz-0.log"
            log1 = scratch / "fuzz-1.log"
            if self._tick == 1:
                # Partial line split across reads on log0, full line on log1.
                log0.write_text("#100000\tNEW cov: 120 ft: 400 corp: 20/1Kb ", encoding="utf-8")
                log1.write_text(
                    "#100000\tNEW cov: 120 ft: 400 corp: 20/1Kb exec/s: 5000 rss: 60Mb\n",
                    encoding="utf-8",
                )
                raise subprocess.TimeoutExpired(self.argv, timeout or 0.1)
            if self._tick == 2:
                with log0.open("a", encoding="utf-8") as f:
                    f.write("exec/s: 5000 rss: 60Mb\n")
                    f.write("#1600000\tpulse cov: 120 ft: 401 corp: 20/1Kb exec/s: 5000 rss: 60Mb\n")
                # Worker 1 still gaining cov -> must NOT stop yet.
                with log1.open("a", encoding="utf-8") as f:
                    f.write("#1600000\tNEW cov: 125 ft: 410 corp: 22/1Kb exec/s: 5000 rss: 60Mb\n")
                raise subprocess.TimeoutExpired(self.argv, timeout or 0.1)
            if self._tick == 3:
                with log0.open("a", encoding="utf-8") as f:
                    f.write("#3200000\tpulse cov: 120 ft: 401 corp: 20/1Kb exec/s: 5000 rss: 60Mb\n")
                with log1.open("a", encoding="utf-8") as f:
                    f.write("#3200000\tpulse cov: 125 ft: 411 corp: 22/1Kb exec/s: 5000 rss: 60Mb\n")
                raise subprocess.TimeoutExpired(self.argv, timeout or 0.1)
            # After SIGTERM, libFuzzer flushes final stats and exits cleanly.
            self.returncode = 0
            return 0

        def terminate(self) -> None:
            signals_sent.append(signal.SIGTERM)
            self.returncode = 0

        def kill(self) -> None:
            signals_sent.append(getattr(signal, "SIGKILL", signal.SIGTERM))
            self.returncode = -9

    def _fake_signal(proc: Any, sig: int) -> None:
        signals_sent.append(sig)
        proc.returncode = -15

    monkeypatch.setattr(sandbox_exec, "sandbox_mode", lambda: "rlimits")
    monkeypatch.setattr(R.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(R, "_signal_process_group", _fake_signal)

    res, plateau_stopped = R._run_sandboxed_with_plateau_monitor(
        ["fuzz_mod.san", "-jobs=2", "-workers=2"],
        writable=[scratch],
        timeout_s=600,
        scratch=scratch,
        detector=detector,
        poll_interval_s=0.05,
        sigterm_grace_s=1.0,
    )
    assert plateau_stopped is True
    assert signals_sent == [signal.SIGTERM]
    assert res.timed_out is False
    assert detector.is_plateaued() is True

    # Now verify `_run_fuzz_campaign_once` + `run_campaign_rounds` surface `stopped_reason='plateau'`,
    # `status='clean'` even when SIGTERM produced rc=-15, and positive `cpu_saved_s`.
    monkeypatch.delenv(R.FUZZ_PLATEAU_STOP_ENV, raising=False)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    monkeypatch.setattr(R, "defined_process_launchers", lambda _b: [])
    # Ensure sandbox_exec.run_sandboxed is untouched so plateau monitor path runs.
    monkeypatch.setattr(sandbox_exec, "run_sandboxed", R._ORIG_RUN_SANDBOXED)

    clock_t = [100.0]
    monkeypatch.setattr(R.time, "monotonic", lambda: clock_t[0])

    def fake_monitored(argv, writable, timeout_s, *, scratch, detector, **_kw):
        clock_t[0] += 100.0  # Used 100 s out of 1000 s wall budget across 4 workers -> saved 3600 CPU-s!
        return (
            SandboxResult(
                returncode=-15,
                stdout="",
                stderr=(
                    "#1000000\tDONE cov: 200 ft: 500 corp: 40/2Kb exec/s: 10000 rss: 64Mb\n"
                    "stat::number_of_executed_units: 1000000\n"
                    "stat::peak_rss_mb: 64\n"
                ),
                timed_out=False,
                sandbox="rlimits",
            ),
            True,
        )

    monkeypatch.setattr(R, "_run_sandboxed_with_plateau_monitor", fake_monitored)

    binary = tmp_path / "fuzz_mod.san"
    binary.write_bytes(b"bin")
    corpus = tmp_path / "corpus"
    artifacts = tmp_path / "artifacts"

    single_res = R.run_fuzz_campaign(binary, corpus, artifacts, max_time=1000, workers=4, profile="standard")
    assert single_res["status"] == "clean"
    assert single_res["stopped_reason"] == "plateau"
    assert single_res["cpu_saved_s"] == pytest.approx(3600.0, abs=1.0)

    rounds_res = R.run_campaign_rounds(
        binary,
        1000,
        campaign=lambda b, secs, fork, *, extra_env=None: R.run_fuzz_campaign(
            b, corpus, artifacts, secs, workers=4, fork=fork, extra_env=extra_env, profile="standard"
        ),
        rebuild=lambda _m: (None, {}),
        n_cases=3,
        runtime_skip=True,
        selector="identity",
        workers=4,
    )
    assert rounds_res["status"] == "clean"
    assert rounds_res["stopped_reason"] == "plateau"
    assert rounds_res["cpu_saved_s"] == pytest.approx(3600.0, abs=1.0)
    assert rounds_res["keep_going"]["stopped"] == "plateau"

    report_doc = {"mode": "campaign", "module": "mod", **rounds_res}
    assert minischema.validate(report_doc, minischema.load_schema(FUZZ_REPORT_SCHEMA)) == []


def test_plateau_stop_env_rollback_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`FRAMAC_FUZZ_PLATEAU_STOP=off` disables the plateau monitor and reports `stopped_reason='budget'`."""
    assert R.fuzz_plateau_stop_enabled({}) is True
    assert R.fuzz_plateau_stop_enabled({R.FUZZ_PLATEAU_STOP_ENV: "on"}) is True
    for off_val in ("off", "OFF", "0", "false", "no"):
        assert R.fuzz_plateau_stop_enabled({R.FUZZ_PLATEAU_STOP_ENV: off_val}) is False

    monkeypatch.setenv(R.FUZZ_PLATEAU_STOP_ENV, "off")
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    monkeypatch.setattr(R, "defined_process_launchers", lambda _b: [])

    monitor_called = False

    def fail_if_monitor(*_a, **_kw):
        nonlocal monitor_called
        monitor_called = True
        raise AssertionError("plateau monitor must not run when FRAMAC_FUZZ_PLATEAU_STOP=off")

    monkeypatch.setattr(R, "_run_sandboxed_with_plateau_monitor", fail_if_monitor)
    monkeypatch.setattr(
        sandbox_exec,
        "run_sandboxed",
        lambda *_a, **_kw: SandboxResult(
            returncode=0,
            stdout="",
            stderr="#100\tDONE cov: 10 ft: 20 corp: 2/8b exec/s: 100 rss: 32Mb\nstat::number_of_executed_units: 100\n",
            timed_out=False,
            sandbox="fake",
        ),
    )

    binary = tmp_path / "fuzz_mod.san"
    binary.write_bytes(b"bin")
    res = R.run_fuzz_campaign(
        binary, tmp_path / "corpus", tmp_path / "arts", max_time=60, workers=4, profile="standard"
    )
    assert monitor_called is False
    assert res["status"] == "clean"
    assert res["stopped_reason"] == "budget"
    assert res["cpu_saved_s"] == 0.0


def test_fuzz_report_schema_validates_stopped_reason_and_cpu_saved() -> None:
    """`schemas/fuzz_report.schema.json` accepts `stopped_reason` (`budget` | `plateau` | `crash`)
    and `cpu_saved_s`, remains backward-compatible when omitted, and rejects invalid values.
    """
    schema = minischema.load_schema(FUZZ_REPORT_SCHEMA)

    # Backward-compatible report omitting new optional fields.
    assert minischema.validate({"mode": "campaign", "status": "clean"}, schema) == []

    # Valid new fields.
    for reason in ("budget", "plateau", "crash"):
        doc = {
            "mode": "campaign",
            "status": "clean" if reason != "crash" else "crash_found",
            "stopped_reason": reason,
            "cpu_saved_s": 1234.5 if reason == "plateau" else 0.0,
        }
        assert minischema.validate(doc, schema) == []

    # Invalid stopped_reason or negative cpu_saved_s rejected.
    assert minischema.validate({"mode": "campaign", "status": "clean", "stopped_reason": "wall_time"}, schema)
    assert minischema.validate({"mode": "campaign", "status": "clean", "cpu_saved_s": -1.0}, schema)
