"""Tests for multi-worker `-jobs=N -workers=N` crash-stop monitoring, dead-worker plateau handling,
and effective worker-time budget accounting (`scripts/run_eacsl_fuzz.py`).
"""

from __future__ import annotations

import io
import json
import os
import signal
import subprocess
from pathlib import Path
from typing import Any

import pytest

import crash_replay
import minischema
import run_eacsl_fuzz as R
import sandbox_exec
from sandbox_exec import SandboxResult

REPO_ROOT = Path(__file__).resolve().parent.parent
FUZZ_REPORT_SCHEMA = REPO_ROOT / "schemas" / "fuzz_report.schema.json"


@pytest.mark.unit
def test_fuzz_crash_stop_env_toggle() -> None:
    assert R.fuzz_crash_stop_enabled({}) is True
    assert R.fuzz_crash_stop_enabled({R.FUZZ_CRASH_STOP_ENV: "on"}) is True
    for off_val in ("0", "false", "no", "off", "OFF"):
        assert R.fuzz_crash_stop_enabled({R.FUZZ_CRASH_STOP_ENV: off_val}) is False


@pytest.mark.unit
def test_job_exit_stream_parses_chunked_and_eof_lines() -> None:
    chunks = [
        b"INFO: running 4 workers\n================== Job 3 exited ",
        b"with exit code 77 ============\n",
        b"================== Job 0 exited with exit code 0 ============",
    ]
    it = iter(chunks)

    class _ChunkStream:
        def read(self, _size: int = -1) -> bytes:
            return next(it, b"")

    watcher = R._JobExitStream(_ChunkStream(), start_time=0.0)
    drainer = sandbox_exec.BoundedStreamDrainer(watcher)  # type: ignore[arg-type]
    drainer.run()
    assert drainer.get_bytes() == b"".join(chunks)
    snap = watcher.snapshot()
    assert set(snap) == {0, 3}
    assert snap[3][0] == 77
    assert snap[0][0] == 0


@pytest.mark.unit
def test_job_exit_stream_observes_short_line_on_buffered_pipe_before_eof() -> None:
    """Regression guard: `subprocess.Popen(..., stderr=PIPE)` wraps the pipe in `io.BufferedReader`.
    `BufferedReader.read(65536)` blocks until 64 KiB or EOF, which hid early `Job N exited` lines
    until the whole campaign ended. `_JobExitStream` must use `read1` so a 60-byte line is visible
    while the pipe is still open.
    """
    import threading

    r_fd, w_fd = os.pipe()
    reader = os.fdopen(r_fd, "rb")  # default buffering -> io.BufferedReader
    writer = os.fdopen(w_fd, "wb", buffering=0)
    watcher = R._JobExitStream(reader, start_time=0.0)
    drainer = sandbox_exec.BoundedStreamDrainer(watcher)  # type: ignore[arg-type]
    t = threading.Thread(target=drainer.run, daemon=True)
    t.start()
    try:
        writer.write(b"================== Job 6 exited with exit code 77 ============\n")
        writer.flush()
        # Pipe is STILL OPEN (no EOF), yet `watcher` must see job 6 promptly.
        import time

        deadline = time.monotonic() + 2.0
        while 6 not in watcher.snapshot() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert 6 in watcher.snapshot() and watcher.snapshot()[6][0] == 77
    finally:
        writer.close()
        t.join(timeout=2.0)
        reader.close()


@pytest.mark.unit
def test_effective_worker_fuzz_s_accounts_for_early_abnormal_exits() -> None:
    # All workers exited cleanly -> keep full wall time.
    clean_exits = {str(i): {"rc": 0, "elapsed_s": 3085.0} for i in range(7)}
    assert R.effective_worker_fuzz_s(3086.0, 7, clean_exits) == pytest.approx(3086.0)

    # QCBOR run-2 scenario: 7 workers, 3086 s wall budget; worker 6 crashed at 840 s, worker 5 at 1860 s.
    exits = {
        "6": {"rc": 77, "elapsed_s": 840.0},
        "5": {"rc": 77, "elapsed_s": 1860.0},
        "0": {"rc": 0, "elapsed_s": 3086.0},
    }
    expected = (840.0 + 1860.0 + 5 * 3086.0) / 7.0
    assert R.effective_worker_fuzz_s(3086.0, 7, exits) == pytest.approx(expected)

    # Single worker or empty exits -> unchanged wall time.
    assert R.effective_worker_fuzz_s(100.0, 1, {"0": {"rc": 77, "elapsed_s": 10.0}}) == 100.0
    assert R.effective_worker_fuzz_s(100.0, 4, {}) == 100.0


@pytest.mark.unit
def test_worker_crash_triggers_stop_filters_dispatch_slow_unit_and_empty_oom(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    arts = tmp_path / "arts"
    scratch.mkdir()
    arts.mkdir()

    # 1. Valid dispatch crash (case 72 = 0x48 under identity selector of 244 cases).
    crash72 = arts / "crash-case72"
    crash72.write_bytes(bytes([72, 0x3B, 0x7F]))
    (scratch / "fuzz-6.log").write_text(
        f"artifact_prefix='{arts}/'; Test unit written to {crash72}\n", encoding="utf-8"
    )
    assert (
        R._worker_crash_triggers_stop(
            job_id=6,
            scratch=scratch,
            artifacts_dir=arts,
            before_meta={},
            dispatch_cases=244,
            dispatch_selector="identity",
        )
        is True
    )

    # 2. Content-addressed rewrite already in before_meta still triggers via fuzz-N.log.
    before_meta = {crash72.name: (crash72.stat().st_mtime_ns, "old")}
    assert (
        R._worker_crash_triggers_stop(
            job_id=6,
            scratch=scratch,
            artifacts_dir=arts,
            before_meta=before_meta,
            dispatch_cases=244,
            dispatch_selector="identity",
        )
        is True
    )

    # 3. slow-unit- is not a fatal artifact.
    slow = arts / "slow-unit-123"
    slow.write_bytes(bytes([72, 1]))
    (scratch / "fuzz-1.log").write_text(f"Test unit written to {slow}\n", encoding="utf-8")
    assert (
        R._worker_crash_triggers_stop(
            job_id=1,
            scratch=scratch,
            artifacts_dir=arts,
            before_meta={crash72.name: (crash72.stat().st_mtime_ns, "old")},
            dispatch_cases=244,
            dispatch_selector="identity",
        )
        is False
    )

    # 4. 0-byte oom- selects no dispatch case -> keep surviving workers running.
    oom_empty = arts / "oom-da39a3ee"
    oom_empty.write_bytes(b"")
    (scratch / "fuzz-2.log").write_text(f"Test unit written to {oom_empty}\n", encoding="utf-8")
    assert (
        R._worker_crash_triggers_stop(
            job_id=2,
            scratch=scratch,
            artifacts_dir=arts,
            before_meta={
                crash72.name: (crash72.stat().st_mtime_ns, "old"),
                slow.name: (slow.stat().st_mtime_ns, "old"),
            },
            dispatch_cases=244,
            dispatch_selector="identity",
        )
        is False
    )
    # Non-dispatch campaign (dispatch_cases=None) DOES stop on any fatal artifact.
    assert (
        R._worker_crash_triggers_stop(
            job_id=2,
            scratch=scratch,
            artifacts_dir=arts,
            before_meta={
                crash72.name: (crash72.stat().st_mtime_ns, "old"),
                slow.name: (slow.stat().st_mtime_ns, "old"),
            },
            dispatch_cases=None,
            dispatch_selector=None,
        )
        is True
    )

    # 5. Worker exited non-zero without writing any artifact (e.g. seccomp/system()=-1 or exit(1)) -> False.
    (scratch / "fuzz-3.log").write_text("worker died before writing artifact\n", encoding="utf-8")
    assert (
        R._worker_crash_triggers_stop(
            job_id=3,
            scratch=scratch,
            artifacts_dir=arts,
            before_meta={
                crash72.name: (crash72.stat().st_mtime_ns, "old"),
                slow.name: (slow.stat().st_mtime_ns, "old"),
                oom_empty.name: (oom_empty.stat().st_mtime_ns, "old"),
            },
            dispatch_cases=244,
            dispatch_selector="identity",
        )
        is False
    )


@pytest.mark.unit
def test_monitor_stops_surviving_workers_on_dispatch_crash_and_skips_in_round2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When one `-jobs=N -workers=N` worker crashes on a dispatch case, `_run_sandboxed_with_plateau_monitor`
    sends `SIGTERM` immediately so `run_campaign_rounds` skips the crashed case and launches round 2
    with all workers alive and the remaining budget intact.
    """
    scratch = tmp_path / "scratch"
    arts = tmp_path / "arts"
    scratch.mkdir()
    arts.mkdir()

    r_fd, w_fd = os.pipe()
    stderr_reader = os.fdopen(r_fd, "rb", buffering=0)
    stderr_writer = os.fdopen(w_fd, "wb", buffering=0)
    signals_sent: list[int] = []

    class FakeCrashPopen:
        def __init__(self, argv: list[str], **_kw: Any) -> None:
            self.pid = 434343
            self.argv = argv
            self.stdout = io.BytesIO(b"")
            self.stderr = stderr_reader
            self.returncode: int | None = None
            self._tick = 0

        def wait(self, timeout: float | None = None) -> int:
            if self.returncode is not None:
                return self.returncode
            self._tick += 1
            if self._tick == 1:
                raise subprocess.TimeoutExpired(self.argv, timeout or 0.05)
            if self._tick == 2:
                crash_path = arts / "crash-case72"
                crash_path.write_bytes(bytes([72, 0x3B, 0x7F]))
                (scratch / "fuzz-6.log").write_text(
                    f"==99== ERROR: libFuzzer: deadly signal\nTest unit written to {crash_path}\n",
                    encoding="utf-8",
                )
                stderr_writer.write(b"================== Job 6 exited with exit code 77 ============\n")
                stderr_writer.flush()
                raise subprocess.TimeoutExpired(self.argv, timeout or 0.05)
            # Without crash-stop, the process would sit until max_total_time; test should stop before tick 5.
            if self._tick >= 5:
                stderr_writer.close()
                self.returncode = 77
                return 77
            raise subprocess.TimeoutExpired(self.argv, timeout or 0.05)

    def _fake_signal(proc: Any, sig: int) -> None:
        signals_sent.append(sig)
        try:
            stderr_writer.close()
        except OSError:
            pass
        proc.returncode = -15

    monkeypatch.setattr(sandbox_exec, "sandbox_mode", lambda: "rlimits")
    monkeypatch.setattr(R.subprocess, "Popen", FakeCrashPopen)
    monkeypatch.setattr(R, "_signal_process_group", _fake_signal)
    monkeypatch.setattr(R, "_live_pgid_pids", lambda _pgid: [])

    stats: dict[str, Any] = {}
    detector = R.ExecutionPlateauDetector.from_profile("standard", expected_workers=7)
    res, plateau_stopped = R._run_sandboxed_with_plateau_monitor(
        ["fuzz_mod.san", "-jobs=7", "-workers=7"],
        writable=[scratch, arts],
        timeout_s=3200,
        scratch=scratch,
        detector=detector,
        poll_interval_s=0.05,
        crash_poll_interval_s=0.05,
        sigterm_grace_s=1.0,
        stop_on_crash=True,
        artifacts_dir=arts,
        before_meta={},
        dispatch_cases=244,
        dispatch_selector="identity",
        monitor_stats=stats,
    )
    assert plateau_stopped is False
    assert stats["crash_stopped"] is True
    assert "6" in stats["job_exits"] and stats["job_exits"]["6"]["rc"] == 77
    assert signals_sent == [signal.SIGTERM]
    assert res.timed_out is False

    # End-to-end through run_fuzz_campaign + run_campaign_rounds (7 workers, 3086 s budget).
    monkeypatch.delenv(R.FUZZ_CRASH_STOP_ENV, raising=False)
    monkeypatch.delenv(R.FUZZ_PLATEAU_STOP_ENV, raising=False)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    monkeypatch.setattr(R, "defined_process_launchers", lambda _b: [])
    monkeypatch.setattr(sandbox_exec, "run_sandboxed", R._ORIG_RUN_SANDBOXED)

    clock_t = [0.0]
    monkeypatch.setattr(R.time, "monotonic", lambda: clock_t[0])
    round_envs: list[dict[str, str] | None] = []
    round_budgets: list[int] = []
    corpus = tmp_path / "corpus"
    round_arts = tmp_path / "round_arts"
    binary = tmp_path / "fuzz_mod.san"
    binary.write_bytes(b"bin")

    def fake_monitored(argv, writable, timeout_s, *, scratch, detector, extra_env=None, monitor_stats=None, **_kw):
        max_t = int(next(a.split("=", 1)[1] for a in argv if a.startswith("-max_total_time=")))
        round_budgets.append(max_t)
        round_envs.append(dict(extra_env) if extra_env else None)
        if len(round_budgets) == 1:
            clock_t[0] += 840.0
            cpath = round_arts / "crash-72"
            cpath.write_bytes(bytes([72, 0x3B, 0x7F]))
            (scratch / "fuzz-6.log").write_text(
                f"==99== ERROR: libFuzzer: deadly signal\nTest unit written to {cpath}\n"
                "stat::number_of_executed_units: 2300000\n",
                encoding="utf-8",
            )
            if monitor_stats is not None:
                monitor_stats["crash_stopped"] = True
                monitor_stats["job_exits"] = {"6": {"rc": 77, "elapsed_s": 840.0}}
            return SandboxResult(-15, "", "", False, "rlimits", list(argv)), False
        clock_t[0] += float(max_t)
        (scratch / "fuzz-0.log").write_text("stat::number_of_executed_units: 9000000\n", encoding="utf-8")
        if monitor_stats is not None:
            monitor_stats["crash_stopped"] = False
            monitor_stats["job_exits"] = {str(i): {"rc": 0, "elapsed_s": float(max_t)} for i in range(7)}
        return SandboxResult(0, "", "", False, "rlimits", list(argv)), False

    def fake_replay(_bin, _art, _scratch, **_kw):
        return {
            "reproduced": True,
            "returncode": 77,
            "timed_out": False,
            "failure": {
                "file": "qcbor_number_decode.c",
                "line": 1964,
                "function": "QCBORDecode_ProcessBigNumber",
                "kind": "ubsan",
                "alarm_kind": "signed_overflow",
                "predicate": "negation of int64_t min",
            },
            "link_stub_abort": None,
            "resource_abort": None,
            "out_of_memory": False,
            "log_tail": "ubsan",
            "frames": [],
        }

    monkeypatch.setattr(R, "_run_sandboxed_with_plateau_monitor", fake_monitored)
    monkeypatch.setattr(crash_replay, "replay_artifact", fake_replay)

    out = R.run_campaign_rounds(
        binary,
        3086,
        campaign=lambda b, secs, fork, *, extra_env=None: R.run_fuzz_campaign(
            b,
            corpus,
            round_arts,
            secs,
            workers=7,
            fork=fork,
            extra_env=extra_env,
            dispatch_cases=244,
            dispatch_selector="identity",
        ),
        rebuild=lambda _m: pytest.fail("runtime_skip must not rebuild"),
        n_cases=244,
        runtime_skip=True,
        selector="identity",
        workers=7,
    )
    assert round_budgets == [3086, 2246]
    assert round_envs[1] is not None and round_envs[1].get("FRAMAC_FUZZ_SKIP_CASES") == "72"
    kg = out["keep_going"]
    assert kg["skipped_cases"] == [72]
    assert len(kg["rounds"]) == 2
    assert kg["rounds"][0]["crash_stopped"] is True
    assert kg["rounds"][0]["crashed_cases"] == [72]
    assert kg["rounds"][1]["skipped_cases"] == [72]
    assert kg["rounds"][1]["stopped"] == "no_new_case"
    assert kg["cpu_seconds_spent"] == pytest.approx(3086.0 * 7, abs=10.0)
    report_doc = {"mode": "campaign", "module": "libqcbor_a", **out}
    assert minischema.validate(report_doc, minischema.load_schema(FUZZ_REPORT_SCHEMA)) == []


@pytest.mark.unit
def test_monitor_keeps_surviving_workers_alive_on_zero_byte_oom_and_recovers_plateau(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a worker exits with a 0-byte `oom-` (no dispatch case), crash-stop does NOT terminate
    surviving workers, and `ExecutionPlateauDetector` marks the dead worker exited so surviving
    workers can still trigger plateau stop.
    """
    scratch = tmp_path / "scratch"
    arts = tmp_path / "arts"
    scratch.mkdir()
    arts.mkdir()

    r_fd, w_fd = os.pipe()
    stderr_reader = os.fdopen(r_fd, "rb", buffering=0)
    stderr_writer = os.fdopen(w_fd, "wb", buffering=0)
    signals_sent: list[int] = []

    class FakeOomThenPlateauPopen:
        def __init__(self, argv: list[str], **_kw: Any) -> None:
            self.pid = 444444
            self.argv = argv
            self.stdout = io.BytesIO(b"")
            self.stderr = stderr_reader
            self.returncode: int | None = None
            self._tick = 0

        def wait(self, timeout: float | None = None) -> int:
            if self.returncode is not None:
                return self.returncode
            self._tick += 1
            if self._tick == 1:
                oom_path = arts / "oom-da39a3ee"
                oom_path.write_bytes(b"")
                (scratch / "fuzz-1.log").write_text(
                    f"#50000\tNEW cov: 50 ft: 100 corp: 5/20b exec/s: 5000 rss: 64Mb\nTest unit written to {oom_path}\n",
                    encoding="utf-8",
                )
                (scratch / "fuzz-0.log").write_text(
                    "#100000\tNEW cov: 50 ft: 100 corp: 5/20b exec/s: 5000 rss: 64Mb\n",
                    encoding="utf-8",
                )
                stderr_writer.write(b"================== Job 1 exited with exit code 71 ============\n")
                stderr_writer.flush()
                raise subprocess.TimeoutExpired(self.argv, timeout or 0.05)
            if self._tick == 2:
                # Tick 2 must still be running (crash-stop did NOT fire on 0-byte OOM).
                with (scratch / "fuzz-0.log").open("a", encoding="utf-8") as f:
                    f.write("#1700000\tpulse cov: 50 ft: 100 corp: 5/20b exec/s: 5000 rss: 64Mb\n")
                raise subprocess.TimeoutExpired(self.argv, timeout or 0.05)
            stderr_writer.close()
            self.returncode = 0
            return 0

    def _fake_signal(proc: Any, sig: int) -> None:
        signals_sent.append(sig)
        try:
            stderr_writer.close()
        except OSError:
            pass
        proc.returncode = -15

    monkeypatch.setattr(sandbox_exec, "sandbox_mode", lambda: "rlimits")
    monkeypatch.setattr(R.subprocess, "Popen", FakeOomThenPlateauPopen)
    monkeypatch.setattr(R, "_signal_process_group", _fake_signal)
    monkeypatch.setattr(R, "_live_pgid_pids", lambda _pgid: [])

    stats: dict[str, Any] = {}
    detector = R.ExecutionPlateauDetector.from_profile("quick", expected_workers=2)
    _res, plateau_stopped = R._run_sandboxed_with_plateau_monitor(
        ["fuzz_mod.san", "-jobs=2", "-workers=2"],
        writable=[scratch, arts],
        timeout_s=600,
        scratch=scratch,
        detector=detector,
        poll_interval_s=0.05,
        crash_poll_interval_s=0.05,
        sigterm_grace_s=1.0,
        stop_on_crash=True,
        artifacts_dir=arts,
        before_meta={},
        dispatch_cases=10,
        dispatch_selector="identity",
        monitor_stats=stats,
    )
    assert stats["crash_stopped"] is False
    assert plateau_stopped is True
    assert signals_sent == [signal.SIGTERM]
    assert detector.summary()["per_worker"]["fuzz-1.log"]["exited"] is True


@pytest.mark.unit
def test_run_campaign_rounds_recovers_lost_worker_budget_via_effective_fuzz_s(tmp_path: Path) -> None:
    """Even when a round runs to full wall `max_time` after losing 2 of 7 workers (e.g. with
    `FRAMAC_FUZZ_CRASH_STOP=off`), charging `effective_fuzz_s` hands the lost worker-seconds to
    round 2 with the crashed case skipped instead of stopping with `time_budget_spent`.
    """
    crash = tmp_path / "crash-72"
    crash.write_bytes(bytes([72, 1, 2]))
    budgets: list[int] = []
    envs: list[dict[str, str] | None] = []

    def campaign(_binary, seconds, _fork, *, extra_env=None):
        budgets.append(seconds)
        envs.append(extra_env)
        if len(budgets) == 1:
            return {
                "status": "crash_found",
                "returncode": 77,
                "artifacts": [{"artifact": str(crash), "kind": "crash", "sha256": "aa", "fingerprint": "fp72"}],
                "fuzz_s": 3086.0,
                "effective_fuzz_s": 2590.0,
            }
        return {"status": "clean", "returncode": 0, "artifacts": [], "fuzz_s": float(seconds)}

    res = R.run_campaign_rounds(
        Path("bin0"),
        3086,
        campaign=campaign,
        rebuild=lambda _m: pytest.fail("runtime_skip must not rebuild"),
        n_cases=244,
        runtime_skip=True,
        selector="identity",
        workers=7,
    )
    assert budgets == [3086, 496]
    assert envs[1] == {"FRAMAC_FUZZ_SKIP_CASES": "72"}
    kg = res["keep_going"]
    assert kg["skipped_cases"] == [72]
    assert kg["rounds"][0]["effective_fuzz_s"] == 2590.0
    assert kg["rounds"][1]["stopped"] == "no_new_case"
    assert kg["fuzz_seconds"] == 3086.0
    assert res["telemetry"]["fuzz_s"] == pytest.approx(3086.0 + 496.0)


@pytest.mark.unit
def test_crash_stop_runs_even_when_plateau_stop_is_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With `FRAMAC_FUZZ_PLATEAU_STOP=off` and default `FRAMAC_FUZZ_CRASH_STOP=on`, the monitor still
    runs with `detector=None` and `stop_on_crash=True`.
    """
    monkeypatch.setenv(R.FUZZ_PLATEAU_STOP_ENV, "off")
    monkeypatch.delenv(R.FUZZ_CRASH_STOP_ENV, raising=False)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    monkeypatch.setattr(R, "defined_process_launchers", lambda _b: [])
    monkeypatch.setattr(sandbox_exec, "run_sandboxed", R._ORIG_RUN_SANDBOXED)

    seen: dict[str, Any] = {}

    def fake_monitor(argv, writable, timeout_s, *, scratch, detector, stop_on_crash=False, **_kw):
        seen["detector"] = detector
        seen["stop_on_crash"] = stop_on_crash
        return SandboxResult(0, "", "", False, "rlimits", list(argv)), False

    monkeypatch.setattr(R, "_run_sandboxed_with_plateau_monitor", fake_monitor)
    binary = tmp_path / "fuzz_mod.san"
    binary.write_bytes(b"bin")
    res = R.run_fuzz_campaign(binary, tmp_path / "corpus", tmp_path / "arts", max_time=60, workers=4, dispatch_cases=10)
    assert seen == {"detector": None, "stop_on_crash": True}
    assert res["status"] == "clean"


_DOCKER_DISPATCH_HARNESS = """#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* runtime dispatch case skip */
#define FRAMAC_FUZZ_RUNTIME_SKIP_CASES 1
#define FRAMAC_FUZZ_SKIP_CASES 0ULL
static int framac_fuzz_skip_case(unsigned int c) {
    static unsigned long long skip_mask = 0ULL;
    static int init = 0;
    if (!init) {
        const char *env = getenv("FRAMAC_FUZZ_SKIP_CASES");
        if (env != NULL) {
            const char *p = env;
            while (*p) {
                while (*p == ',' || *p == ' ') p++;
                if (*p >= '0' && *p <= '9') {
                    unsigned int v = 0;
                    while (*p >= '0' && *p <= '9') { v = v * 10U + (unsigned int)(*p - '0'); p++; }
                    if (v < 64U) skip_mask |= (1ULL << v);
                }
                while (*p && *p != ',') p++;
            }
        }
        init = 1;
    }
    return (c < 64U) ? (int)((skip_mask >> c) & 1ULL) : 0;
}

/* Only job 0 (fuzz-0.log) and standalone replays (non-fuzz-N.log stdout) crash in case 1;
 * workers 1..3 keep running until max_total_time unless crash-stop interrupts them. */
static int allow_case1_crash(void) {
    static int cached = -1;
    if (cached < 0) {
        char linkbuf[256];
        ssize_t n = readlink("/proc/self/fd/1", linkbuf, sizeof(linkbuf) - 1);
        if (n > 0) {
            linkbuf[n] = '\\0';
            if (strstr(linkbuf, "fuzz-1.log") || strstr(linkbuf, "fuzz-2.log") || strstr(linkbuf, "fuzz-3.log")) {
                cached = 0;
                return 0;
            }
        }
        cached = 1;
    }
    return cached;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return -1;
    unsigned int harness_selector = data[0];
    if (harness_selector >= 4U) return -1;
    if (framac_fuzz_skip_case(harness_selector)) return -1;
    switch (harness_selector) {
    case 0:
        return 0;
    case 1:
        if (data[1] == 0x42 && allow_case1_crash()) {
            abort();
        }
        return 0;
    case 2:
        return 0;
    case 3:
        return 0;
    default:
        return -1;
    }
}
"""

_DOCKER_DRIVER = """import json, os, subprocess, sys
from pathlib import Path
sys.path.insert(0, "/opt/framac-pipeline/scripts")
import run_eacsl_fuzz as R

work = Path("/w")
src = work / "harness.c"
binp = work / "fuzz_dispatch"
subprocess.run(["clang", "-O1", "-g", "-fsanitize=fuzzer,address", str(src), "-o", str(binp)], check=True)
R.enforced_memory_mb = lambda: None
os.environ["FRAMAC_FUZZ_PLATEAU_STOP"] = "off"

def run_mode(name, crash_stop):
    corpus = work / f"corpus_{name}"
    arts = work / f"arts_{name}"
    corpus.mkdir(exist_ok=True)
    arts.mkdir(exist_ok=True)
    (corpus / "s0").write_bytes(bytes([0, 1, 2]))
    (corpus / "s2").write_bytes(bytes([2, 1, 2]))
    (corpus / "s3").write_bytes(bytes([3, 1, 2]))
    os.environ["FRAMAC_FUZZ_PLATEAU_STOP"] = "off" if crash_stop else "on"
    os.environ["FRAMAC_FUZZ_CRASH_STOP"] = "on" if crash_stop else "off"

    def _camp(binary, seconds, fork, *, extra_env=None):
        return R.run_fuzz_campaign(
            binary, corpus, arts, seconds,
            rss_limit_mb=512,
            workers=4, jobs=4, fork=fork, extra_env=extra_env,
            profile="deep",
            dispatch_cases=4, dispatch_selector="identity",
        )

    return R.run_campaign_rounds(
        binp, 18 if not crash_stop else 12,
        campaign=_camp,
        rebuild=lambda _m: (None, {}),
        n_cases=4,
        runtime_skip=True,
        selector="identity",
        workers=4,
    )

out = {
    "crash_stop_on": run_mode("on", True),
    "crash_stop_off": run_mode("off", False),
}
(work / "report.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
"""


@pytest.mark.integration
@pytest.mark.slow
def test_docker_multi_worker_dispatch_campaign_stops_on_crash_and_recovers_worker_budget(tmp_path: Path) -> None:
    """Real Clang LibFuzzer `-jobs=4 -workers=4` run inside `framac-analysis:latest` where worker 0
    crashes on case 1 while workers 1..3 keep running:
      1. With `FRAMAC_FUZZ_CRASH_STOP=on`, round 1 stops promptly (`crash_stopped=True`), skips
         case 1 via `FRAMAC_FUZZ_SKIP_CASES`, and runs round 2 clean with all 4 workers for the
         remaining budget.
      2. With `FRAMAC_FUZZ_CRASH_STOP=off`, workers 1..3 finish the 12 s wall budget, but
         `effective_fuzz_s` accounts for worker 0's early exit and still schedules round 2 with
         case 1 skipped for the recovered worker-seconds instead of stopping `time_budget_spent`.
    """
    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    (tmp_path / "harness.c").write_text(_DOCKER_DISPATCH_HARNESS, encoding="utf-8", newline="\n")
    (tmp_path / "driver.py").write_text(_DOCKER_DRIVER, encoding="utf-8", newline="\n")
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "--init", "--network", "none",
            "--cpus", "4", "--memory", "2g",
            "--label", os.environ.get("FPI_DOCKER_LABEL", "framac.test=test_fuzz_worker_crash_stop"),
            "-v", f"{tmp_path}:/w",
            "-v", f"{REPO_ROOT / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{REPO_ROOT / 'templates'}:/opt/framac-pipeline/templates:ro",
            "-v", f"{REPO_ROOT / 'schemas'}:/opt/framac-pipeline/schemas:ro",
            "--entrypoint", "python3", ANALYSIS_IMAGE, "/w/driver.py",
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    reports = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))

    # 1. Crash-stop ON: round 1 stopped early by monitor, round 2 ran clean with case 1 skipped.
    on_rep = reports["crash_stop_on"]
    kg_on = on_rep["keep_going"]
    assert kg_on["skipped_cases"] == [1], kg_on
    assert len(kg_on["rounds"]) == 2, kg_on
    assert kg_on["rounds"][0].get("crash_stopped") is True, kg_on
    assert kg_on["rounds"][0]["crashed_cases"] == [1], kg_on
    assert kg_on["rounds"][1]["skipped_cases"] == [1], kg_on
    assert kg_on["rounds"][1]["max_time"] >= 7, kg_on
    assert kg_on["rounds"][1]["stopped"] == "no_new_case", kg_on
    assert (
        minischema.validate(
            {"mode": "campaign", "module": "dispatch_mod", **on_rep}, minischema.load_schema(FUZZ_REPORT_SCHEMA)
        )
        == []
    )

    # 2. Crash-stop OFF: effective_fuzz_s still recovers worker 0's lost time for round 2.
    off_rep = reports["crash_stop_off"]
    kg_off = off_rep["keep_going"]
    assert kg_off["skipped_cases"] == [1], kg_off
    assert len(kg_off["rounds"]) == 2, kg_off
    assert not kg_off["rounds"][0].get("crash_stopped"), kg_off
    assert kg_off["rounds"][0].get("effective_fuzz_s", 18.0) < 16.0, kg_off
    assert kg_off["rounds"][1]["skipped_cases"] == [1], kg_off
    assert kg_off["rounds"][1]["max_time"] >= 2, kg_off
    assert kg_off["rounds"][1]["stopped"] == "no_new_case", kg_off
    assert (
        minischema.validate(
            {"mode": "campaign", "module": "dispatch_mod", **off_rep}, minischema.load_schema(FUZZ_REPORT_SCHEMA)
        )
        == []
    )
