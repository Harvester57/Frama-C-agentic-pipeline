"""
The Eva ladder of a module whose base run needed the recursion downgrade (nanopb run-1,
libprotobuf_nanopb_a: `pb_decode.c:100: Recursive call to pb_read without assigns clause`).

run_eva_slice.py retries a run that aborts on a recursive call without an assigns clause once, with
`-eva-warn-key assigns:missing=warning`. Before this fix every rung and loop trial repeated the first
attempt, bound to abort, under the rung limit derived from the base run's retry alone: `returns` lost
893 s of its 1,030 s that way and timed out, `slevel` and `unroll` timed out inside the first attempt.

- The plan reads the base run's `auto_recursion_fallback` and starts the rungs and the loop trials of
  `finish` with the same downgrade (EVA_TUNE_RECURSION_FALLBACK_<mod>); the base run itself, the plain
  run and the shards keep detecting it.
- A rung started with the downgrade is the same analysis as one that got there by the retry, so the
  tuning guards still combine it with the base run, and recorded decisions stay current.
- The time the aborted first attempt took is reported (`auto_recursion_fallback_first_attempt_s`).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import eva_options as eo
import eva_tuning as et
import pipeline_make as pm
import run_eva_slice
from conftest import write_json
from test_eva_shards import _merge, _row, _shard
from test_eva_tuning import COMPLETE_LOG
from test_pipeline_make import ACSL, REPO, _make_run

pytestmark = pytest.mark.unit

RECURSION_FLAG = "--allow-incomplete-recursion-specs"
TUNE_VAR = "EVA_TUNE_RECURSION_FALLBACK"
FIRST_ATTEMPT_FIELD = "auto_recursion_fallback_first_attempt_s"

# Eva's own messages (Frama-C 34; tests/fixtures/eva_assigns/b_rec_default.log).
RECURSION_ABORT_LOG = (
    "[eva:assigns:missing] workspace/work/pb_decode.c:100: User Error: \n"
    "  Recursive call to pb_read without assigns clause.\n"
    "  Generating probably incomplete assigns to interpret the call.\n"
    "[eva] Deferred error: warning as error assigns:missing:\n"
    "  workspace/work/pb_decode.c:100: Recursive call to pb_read without assigns clause.\n"
    "[kernel] Plug-in eva aborted: invalid user input.\n"
)


# ---------------------------------------------------------------------------
# The plan: modules.mk
# ---------------------------------------------------------------------------


def _tuning_base(run_dir: Path, module: str = "snmp", **fields) -> None:
    unknowns = {"parse": [{"directory": "workspace/work", "file": "a.c", "line": 1}]}
    write_json(
        run_dir / pm.TUNE_REPORT_DIR / module / "base.json",
        {
            "status": "ok",
            "unknown_obligations_by_function": unknowns,
            "elapsed_s": 128.8,
            "input_digest": "d1",
            **fields,
        },
    )


def _modules_mk(run: Path) -> str:
    pm.generate(run, templates_dir=ACSL)
    return (run / pm.MODULES_MK).read_text(encoding="utf-8")


def test_a_base_run_that_needed_the_downgrade_starts_the_rungs_with_it(tmp_path):
    run = _make_run(tmp_path)
    _tuning_base(run, auto_recursion_fallback=True)
    text = _modules_mk(run)
    assert f"{TUNE_VAR}_snmp := 1\n" in text
    # Only the module whose base run retried; the module's own switch stays off.
    assert f"{TUNE_VAR}_cfg" not in text
    assert "EVA_RECURSION_FALLBACK_snmp :=\n" in text
    plan = pm.build_plan(run, templates_dir=ACSL)
    assert plan.modules["snmp"].to_json()["tune_recursion_fallback"] is True
    # The rung limit formula is unchanged: 8 x the base run's elapsed_s.
    assert "EVA_TUNE_TIMEOUT_snmp := 1030\n" in text


def test_no_downgrade_for_the_rungs_when_the_base_run_did_not_retry(tmp_path):
    run = _make_run(tmp_path)
    _tuning_base(run)
    text = _modules_mk(run)
    assert TUNE_VAR not in text, "a module whose base run never met the recursion gets the modules.mk it always got"
    assert "tune_recursion_fallback" not in pm.build_plan(run, templates_dir=ACSL).modules["snmp"].to_json()
    # A base run that failed or left nothing to tune has no rungs to start.
    _tuning_base(run, auto_recursion_fallback=True, unknown_obligations_by_function={})
    assert TUNE_VAR not in _modules_mk(run)
    _tuning_base(run, auto_recursion_fallback=True, status="analysis_error")
    assert TUNE_VAR not in _modules_mk(run)


def test_the_module_switch_already_carries_the_downgrade(tmp_path):
    run = _make_run(tmp_path, params={"modules": {"snmp": {"eva_recursion_fallback": True}}})
    _tuning_base(run, auto_recursion_fallback=True)
    text = _modules_mk(run)
    assert "EVA_RECURSION_FALLBACK_snmp := 1\n" in text
    assert TUNE_VAR not in text, "eva_args passes the flag already"


def test_the_propagated_downgrade_keeps_recorded_decisions_current(tmp_path):
    # The settings digest is what a recorded decision is checked against: propagating the downgrade
    # changes nothing the decision rests on (same reduced checks, same inputs), so it must not move.
    run = _make_run(tmp_path)
    _tuning_base(run)
    before = pm.build_plan(run, templates_dir=ACSL).modules["snmp"].settings_digest
    _tuning_base(run, auto_recursion_fallback=True)
    after = pm.build_plan(run, templates_dir=ACSL).modules["snmp"]
    assert after.tune_recursion_fallback is True
    assert after.settings_digest == before
    record = {
        "ladder": eo.LADDER_VERSION,
        "settings_digest": before,
        "input_digest": "d1",
        "selected": "values",
        "rung": "values",
        "options": {"ilevel": 64},
        "loops": [],
        "contributors": [],
    }
    pm.record_eva_tuning(run, "snmp", record)
    text = _modules_mk(run)
    assert "EVA_REPLAY_snmp := 1\n" in text and f"{TUNE_VAR}_snmp := 1\n" in text
    assert "EVA_TUNE_RUNGS_snmp := values\n" in text


# ---------------------------------------------------------------------------
# The recipes: templates/pipeline.mk
# ---------------------------------------------------------------------------


def _pipeline_mk() -> str:
    return (REPO / "templates" / "pipeline.mk").read_text(encoding="utf-8")


def _block(text: str, start: str, end: str) -> str:
    i = text.index(start)
    return text[i : text.index(end, i)]


def test_the_rungs_and_finish_pass_the_downgrade_and_the_base_run_does_not():
    text = _pipeline_mk()
    rung = _block(text, "define EVA_RUNG_RULE", "endef")
    assert f"$$(if $$({TUNE_VAR}_$(1)),{RECURSION_FLAG})" in rung
    finish = _block(text, "eva_finish_cmd =", "\n\n")
    assert f"$(if $({TUNE_VAR}_$(1)),{RECURSION_FLAG})" in finish, "the loop trials of finish"
    # The base run detects the recursion (its report is what the plan reads); the plain run and the
    # shards share the base run's cache entry and keep its auto_recursion_fallback marker.
    for start, end in (
        ("eva_args =", "\n\n"),
        ("eva_base_run =", "\n\n"),
        ("eva_plain_cmd =", "\n\n"),
        ("define EVA_SHARD_RULE", "endef"),
    ):
        assert TUNE_VAR not in _block(text, start, end), start


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("make") is None, reason="GNU make not available")
def test_make_dry_run_starts_rungs_and_finish_downgraded(tmp_path):
    run = _make_run(tmp_path)
    scripts = f"S={(REPO / 'scripts').as_posix()}"

    def make(*args):
        proc = subprocess.run(
            ["make", "-f", pm.MAKEFILE, scripts, "-n", *args], cwd=run, capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return proc.stdout.replace("\\n", " ")

    _tuning_base(run, auto_recursion_fallback=True)
    pm.generate(run, templates_dir=ACSL)
    lines = [line for line in make("evatune-snmp").splitlines() if "run_eva_slice.py" in line or "finish" in line]
    rungs = [line for line in lines if "--out-dir workspace/eva/snmp/tune/" in line]
    assert rungs and all(RECURSION_FLAG in line for line in rungs)
    finish = [line for line in lines if "eva_tuning.py finish" in line]
    assert finish and RECURSION_FLAG in finish[0]
    base = [line for line in make("evabase-snmp").splitlines() if "run_eva_slice.py" in line]
    assert base and RECURSION_FLAG not in base[0]


# ---------------------------------------------------------------------------
# run_eva_slice: the same analysis either way, and the lost first attempt
# ---------------------------------------------------------------------------


class _Clock:
    """A monotonic clock the fake Frama-C call advances by the time each attempt takes."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def __getattr__(self, name: str):
        import time

        return getattr(time, name)


def _fake_eva(calls: list, clock: _Clock, first_s: float = 893.0, retry_s: float = 120.0, timeouts: int = 0):
    """
    An _execute_eva: a run without the downgrade aborts on the recursion after `first_s`, one with it
    finishes after `retry_s`. The first `timeouts` calls time out instead (the base run of a fallback).
    """

    def fake(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root=None):
        calls.append((list(cmd), list(reduced_checks), timeout))
        out_dir.mkdir(parents=True, exist_ok=True)
        if len(calls) <= timeouts:
            clock.now += float(timeout or 0)
            (out_dir / "eva.log").write_text("[eva] analyzing\n", encoding="utf-8")
            return {
                "status": "analysis_timeout",
                "reason": None,
                "error_summary": [f"Frama-C Eva exceeded the {timeout} s wall-clock limit"],
                "sources": sources,
                "elapsed_s": float(timeout or 0),
                "reduced_checks": reduced_checks,
            }
        if "-eva-warn-key" not in cmd:
            clock.now += first_s
            (out_dir / "eva.log").write_text(RECURSION_ABORT_LOG, encoding="utf-8")
            return {
                "status": "analysis_error",
                "reason": "exit_1",
                "error_summary": ["[eva] User Error: Deferred error message was emitted during execution."],
                "sources": sources,
                "elapsed_s": first_s,
                "reduced_checks": reduced_checks,
            }
        clock.now += retry_s
        (out_dir / "eva.log").write_text("[eva] done\n", encoding="utf-8")
        return {
            "status": "ok",
            "reason": None,
            "error_summary": [],
            "main_fn": main_fn,
            "sources": sources,
            "elapsed_s": retry_s,
            "reduced_checks": reduced_checks,
        }

    return fake


@pytest.fixture
def fake_eva(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_eva_slice, "_input_digest", lambda sources, flags: "d1")
    clock = _Clock()
    monkeypatch.setattr(run_eva_slice, "time", clock)
    calls: list = []

    def run(first_s: float = 893.0, timeouts: int = 0, **kwargs) -> dict:
        calls.clear()
        monkeypatch.setattr(run_eva_slice, "_execute_eva", _fake_eva(calls, clock, first_s=first_s, timeouts=timeouts))
        return run_eva_slice.run_eva_on_slice(
            ["workspace/work/pb_decode.c"], "eva_main", tmp_path / "out", use_cache=False, **kwargs
        )

    return run, calls


def test_a_rung_started_downgraded_is_the_analysis_the_retry_reaches(fake_eva):
    run, calls = fake_eva
    options = {"split-return": "auto", "slevel": 500}
    retried = run(timeout=1030, eva_options=options, timeout_fallback=False, flamegraph=False)
    retried_calls = list(calls)
    started = run(
        timeout=1030,
        eva_options=options,
        timeout_fallback=False,
        flamegraph=False,
        allow_incomplete_recursion_specs=True,
    )
    assert len(retried_calls) == 2 and len(calls) == 1, "started downgraded: no first attempt to abort"
    assert calls[0][0] == retried_calls[1][0], "the same Frama-C command as the retry"
    assert started["reduced_checks"] == retried["reduced_checks"]
    assert run_eva_slice.RECURSION_REDUCED_CHECK in started["reduced_checks"]
    assert started["input_digest"] == retried["input_digest"] == "d1"
    # The whole rung limit goes to the analysis, not what the first attempt left of it.
    assert calls[0][2] == 1030 and retried_calls[1][2] == 1030 - 893
    # eva_tuning combines it with a base run that got there by the retry.
    base = et.EvaRun(name="base", report={**retried, "eva_options": {}}, log_text=COMPLETE_LOG)
    rung = et.EvaRun(name="returns", report=started, log_text=COMPLETE_LOG)
    assert et.analysis_identity(rung) == et.analysis_identity(base)
    assert et.guard_reasons(rung, base) == []


def test_a_stale_downgrade_is_refused_by_the_guards(fake_eva):
    # The flag was planned from an older base run; the new base run no longer meets the recursion.
    run, _calls = fake_eva
    started = run(timeout=1030, timeout_fallback=False, allow_incomplete_recursion_specs=True)
    base = et.EvaRun(
        name="base", report={**started, "reduced_checks": ["-no-warn-unsigned-downcast"]}, log_text=COMPLETE_LOG
    )
    rung = et.EvaRun(name="values", report=started, log_text=COMPLETE_LOG)
    assert "different_analysis" in et.guard_reasons(rung, base)


def test_the_aborted_first_attempt_is_reported(fake_eva):
    run, _calls = fake_eva
    res = run(timeout=1030, timeout_fallback=False)
    assert res["auto_recursion_fallback"] is True
    assert res[FIRST_ATTEMPT_FIELD] == 893.0
    assert res["elapsed_s"] == 120.0, "elapsed_s stays the retry's"


def test_no_first_attempt_field_without_a_retry(fake_eva):
    run, _calls = fake_eva
    res = run(timeout=1030, timeout_fallback=False, allow_incomplete_recursion_specs=True)
    assert res["status"] == "ok" and FIRST_ATTEMPT_FIELD not in res and not res.get("auto_recursion_fallback")


def test_the_first_attempt_of_a_fallback_tier_is_reported(fake_eva):
    # The base run times out before meeting the recursion; the first fallback tier aborts on it.
    run, calls = fake_eva
    res = run(first_s=40.0, timeouts=1, timeout=600)
    assert len(calls) == 3 and "-eva-warn-key" in calls[2][0]
    assert res["status"] == "ok" and res.get("timeout_fallback")
    assert res["auto_recursion_fallback"] is True
    assert res[FIRST_ATTEMPT_FIELD] == 40.0


def test_a_fallback_tier_after_a_retry_that_timed_out_keeps_the_marker(tmp_path, monkeypatch):
    # The first attempt aborts on the recursion, the retry times out, the first fallback tier (started
    # downgraded) finishes: its report must still say the run needed the retry, or the plan never
    # propagates the downgrade to the rungs.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_eva_slice, "_input_digest", lambda sources, flags: "d1")
    clock = _Clock()
    monkeypatch.setattr(run_eva_slice, "time", clock)
    calls: list = []

    def fake(cmd, sources, main_fn, out_dir, reduced_checks, timeout, path_root=None):
        calls.append((list(cmd), timeout))
        out_dir.mkdir(parents=True, exist_ok=True)
        if len(calls) == 1:
            clock.now += 50.0
            (out_dir / "eva.log").write_text(RECURSION_ABORT_LOG, encoding="utf-8")
            return {"status": "analysis_error", "reason": "exit_1", "error_summary": [], "sources": sources,
                    "elapsed_s": 50.0, "reduced_checks": reduced_checks}  # fmt: skip
        (out_dir / "eva.log").write_text("[eva] done\n", encoding="utf-8")
        if len(calls) == 2:
            clock.now += float(timeout)
            return {"status": "analysis_timeout", "reason": None, "error_summary": [], "sources": sources,
                    "elapsed_s": float(timeout), "reduced_checks": reduced_checks}  # fmt: skip
        clock.now += 30.0
        return {"status": "ok", "reason": None, "error_summary": [], "main_fn": main_fn, "sources": sources,
                "elapsed_s": 30.0, "reduced_checks": reduced_checks}  # fmt: skip

    monkeypatch.setattr(run_eva_slice, "_execute_eva", fake)
    res = run_eva_slice.run_eva_on_slice(
        ["workspace/work/pb_decode.c"], "eva_main", tmp_path / "out", use_cache=False, timeout=600
    )
    assert len(calls) == 3 and all("-eva-warn-key" in cmd for cmd, _ in calls[1:])
    assert res["status"] == "ok" and res.get("timeout_fallback")
    assert res["auto_recursion_fallback"] is True
    assert res[FIRST_ATTEMPT_FIELD] == 50.0
    assert run_eva_slice.RECURSION_REDUCED_CHECK in res["reduced_checks"]


def test_merged_shards_report_their_first_attempts_not_shard_zeros(tmp_path, capsys):
    run = tmp_path
    _shard(run, 0, [_row(1, "Valid")], {"parse": 5}, reduced_checks=["-no-warn-unsigned-downcast"])
    _shard(
        run,
        1,
        [_row(1, "Valid")],
        {"parse": 5},
        reduced_checks=["-no-warn-unsigned-downcast", run_eva_slice.RECURSION_REDUCED_CHECK],
        auto_recursion_fallback=True,
        **{FIRST_ATTEMPT_FIELD: 30.5},
    )
    rc, report = _merge(run)
    capsys.readouterr()
    assert rc == 0, report.get("reason")
    assert report[FIRST_ATTEMPT_FIELD] == 30.5
    # Shard 0 is what the merged report starts from: its absence of a retry must not hide shard 1's.
    _shard(
        run,
        0,
        [_row(1, "Valid")],
        {"parse": 5},
        reduced_checks=["-no-warn-unsigned-downcast", run_eva_slice.RECURSION_REDUCED_CHECK],
        auto_recursion_fallback=True,
        **{FIRST_ATTEMPT_FIELD: 12.0},
    )
    _shard(run, 1, [_row(1, "Valid")], {"parse": 5}, reduced_checks=["-no-warn-unsigned-downcast"])
    rc, report = _merge(run)
    capsys.readouterr()
    assert rc == 0 and report[FIRST_ATTEMPT_FIELD] == 12.0
    _shard(run, 0, [_row(1, "Valid")], {"parse": 5}, reduced_checks=["-no-warn-unsigned-downcast"])
    rc, report = _merge(run)
    capsys.readouterr()
    assert rc == 0 and FIRST_ATTEMPT_FIELD not in report
