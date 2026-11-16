"""The prover's wall budget leaves out time queued for WP leases in the host resource broker.

c-ares run-1, Phase 3: with 15 provers on a 32-CPU pool, `prove-print_help_info_ahost` ran its first
WP call at 19:57:35 (about 30 s), then waited about 15 minutes for its second call's `wp` lease. Once
granted, run_wp_function.py measured `now - first_wp_at` > 900 s and refused the call before Frama-C
started: the agent ended `stalled_after_k_retries` after one real proof attempt, and the lease it
had waited for was wasted. `resources.py exec` now passes the lease's queue time into the container
(FRAMAC_LEASE_ID, FRAMAC_LEASE_WAITED_S), and the budget subtracts it.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path

import pytest

import resources as R
import run_wp_function as W

_LW_CSV = "directory\tfile\tfunction\tline\tkind\tstatus\tproperty\n.\tf.c\tf\t2\tpostcondition\tValid\tok\n"
_LW_LOG = "[wp] 1 goals scheduled\n[wp] Proved goals:    1 / 1\n"


def _fake_wp(calls: list[list[str]]):
    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        if "-wp" in cmd and "-report-csv" in cmd:
            Path(cmd[cmd.index("-report-csv") + 1]).write_text(_LW_CSV, encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout=_LW_LOG, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    return fake_run


def _prover(tmp_path: Path, budget: dict) -> tuple[Path, Path]:
    scratch = tmp_path / "agents" / "prove-f" / "scratch"
    work = scratch / "work"
    work.mkdir(parents=True)
    c_file = work / "f.c"
    c_file.write_text("int f(int x) { return x; }\n", encoding="utf-8")
    (scratch / ".prover_budget.json").write_text(json.dumps(budget), encoding="utf-8")
    return scratch, c_file


def _second_call_budget(since_first_s: float) -> dict:
    return {
        "max_wp_invocations": 6,
        "max_wall_clock_s": 900,
        "wp_invocations": 1,
        "first_wp_at": time.time() - since_first_s,
    }


def _lease_env(monkeypatch: pytest.MonkeyPatch, lease_id: str | None, waited: str | None) -> None:
    for name, value in (("FRAMAC_LEASE_ID", lease_id), ("FRAMAC_LEASE_WAITED_S", waited)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


def _run(c_file: Path, scratch: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[dict, list[list[str]]]:
    calls: list[list[str]] = []
    monkeypatch.setattr(W.subprocess, "run", _fake_wp(calls))
    res = W.run_wp_on_function(
        c_file,
        "f",
        scratch / "wp",
        cache_dir="off",
        retry_tail=False,
        retry_bitwise=False,
        retry_cast_probe=False,
    )
    return res, calls


@pytest.mark.unit
def test_time_queued_for_the_wp_lease_does_not_exhaust_the_wall_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 950 s since the first WP call, 900 s of it queued for this call's lease: 50 s of prover time.
    scratch, c_file = _prover(tmp_path, _second_call_budget(950))
    _lease_env(monkeypatch, "aaaaaaaaaaaa", "900.0")

    res, calls = _run(c_file, scratch, monkeypatch)

    assert not res.get("budget_exhausted"), res.get("wp_log_tail")
    assert any("-wp" in c for c in calls), "WP must run after the lease wait"
    # The WP wall timeout comes from the remaining budget, which the queue time no longer eats.
    assert res["sizing"]["wall_timeout_s"] >= 800
    budget = json.loads((scratch / ".prover_budget.json").read_text(encoding="utf-8"))
    assert budget["wp_invocations"] == 2
    assert 899 <= budget["lease_wait_s"] <= 900
    assert budget["lease_wait_credited"] == ["aaaaaaaaaaaa"]


@pytest.mark.unit
def test_unknown_lease_wait_keeps_the_wall_budget_as_before(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scratch, c_file = _prover(tmp_path, _second_call_budget(950))
    _lease_env(monkeypatch, None, None)

    res, calls = _run(c_file, scratch, monkeypatch)

    assert res["budget_exhausted"] is True
    assert not any("-wp" in c for c in calls)
    assert "excluding 0s queued for WP leases" in res["wp_log_tail"]


@pytest.mark.unit
def test_genuinely_spent_wall_budget_is_still_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 2000 s since the first call, only 600 s queued: 1400 s of prover time > 900 s.
    scratch, c_file = _prover(tmp_path, _second_call_budget(2000))
    _lease_env(monkeypatch, "bbbbbbbbbbbb", "600")

    res, _ = _run(c_file, scratch, monkeypatch)

    assert res["budget_exhausted"] is True
    assert "excluding 600s queued for WP leases" in res["wp_log_tail"]


@pytest.mark.unit
def test_first_call_lease_wait_is_not_credited(monkeypatch: pytest.MonkeyPatch) -> None:
    # The first call's queue time came before first_wp_at: it is outside the budget already.
    _lease_env(monkeypatch, "cccccccccccc", "500")
    budget: dict = {}
    assert W._prover_budget_lease_wait(budget, 0.0, first_call=True) == 0.0
    assert budget.get("lease_wait_s", 0) == 0
    # Recorded, so a second run of the script in the same container does not credit it either.
    assert budget["lease_wait_credited"] == ["cccccccccccc"]
    assert W._prover_budget_lease_wait(budget, 600.0, first_call=False) == 0.0


@pytest.mark.unit
def test_each_lease_is_credited_once_and_never_beyond_the_elapsed_time(monkeypatch: pytest.MonkeyPatch) -> None:
    budget: dict = {"lease_wait_s": 100.0, "lease_wait_credited": ["111111111111"]}
    _lease_env(monkeypatch, "222222222222", "300")
    assert W._prover_budget_lease_wait(budget, 1000.0, first_call=False) == pytest.approx(400.0)
    # Same container, same lease: no double credit.
    assert W._prover_budget_lease_wait(budget, 1010.0, first_call=False) == pytest.approx(400.0)
    assert budget["lease_wait_credited"] == ["111111111111", "222222222222"]
    # A clock oddity never makes the queued time larger than the time since the first call.
    _lease_env(monkeypatch, "333333333333", "5000")
    assert W._prover_budget_lease_wait(budget, 1020.0, first_call=False) == pytest.approx(1020.0)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("lease_id", "waited"),
    [("dddddddddddd", "abc"), ("dddddddddddd", "-5"), ("dddddddddddd", "nan"), ("dddddddddddd", "inf"), ("", "30")],
)
def test_garbled_lease_wait_is_ignored(monkeypatch: pytest.MonkeyPatch, lease_id: str, waited: str) -> None:
    _lease_env(monkeypatch, lease_id, waited)
    assert W._lease_wait_from_env() is None
    budget: dict = {}
    assert W._prover_budget_lease_wait(budget, 1000.0, first_call=False) == 0.0
    assert "lease_wait_s" not in budget


@pytest.mark.unit
def test_engine_argv_passes_the_lease_id_and_its_queue_time() -> None:
    argv = R.build_engine_argv(
        ["docker", "run", "--rm", "img:1"],
        lease_id="0123456789ab",
        cls_name="wp",
        cpus=2,
        mem_mb=3698,
        eng=R.EngineInfo(),
        pool_cpus=32,
        pool_mem_mb=64000,
        lease_wait_s=901.26,
    )
    pairs = set(zip(argv, argv[1:], strict=False))
    assert ("-e", "FRAMAC_LEASE_ID=0123456789ab") in pairs
    assert ("-e", "FRAMAC_LEASE_WAITED_S=901.3") in pairs
    unknown = R.build_engine_argv(
        ["docker", "run", "--rm", "img:1"],
        lease_id="0123456789ab",
        cls_name="wp",
        cpus=2,
        mem_mb=3698,
        eng=R.EngineInfo(),
        pool_cpus=32,
        pool_mem_mb=64000,
    )
    assert not any(a.startswith("FRAMAC_LEASE_WAITED_S=") for a in unknown)


@pytest.mark.unit
def test_broker_measures_how_long_a_lease_was_queued(tmp_path: Path) -> None:
    broker = R.Broker(tmp_path, lambda: R.Budget(2, 4096, "test"), poll=0.02, max_poll=0.05)
    first = broker.acquire("build", fixed_cpus=2)  # the whole pool: the next lease has to queue
    assert not first.waited and first.wait_s < 5
    releaser = threading.Timer(0.4, broker.release, [first])
    releaser.start()
    try:
        second = broker.acquire("build", fixed_cpus=2, timeout=30)
    finally:
        releaser.join()
    try:
        assert second.waited
        assert second.wait_s >= 0.3
    finally:
        broker.release(second)
