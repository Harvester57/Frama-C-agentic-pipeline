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
import workspace_overlay as WO

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


@pytest.mark.unit
def test_core_provable_standard_brief_renders_budget_and_lease_wait_text(tmp_path: Path) -> None:
    target = tmp_path / "target"
    src = target / "src"
    src.mkdir(parents=True)
    (src / "m.c").write_text("int f(int x) { return x; }\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    WO.init_overlay(target, run_dir / "workspace")
    (run_dir / "run-metadata.json").write_text(json.dumps({"profile": "standard"}), encoding="utf-8")
    reports = run_dir / "workspace" / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "callgraph_dag.json").write_text(
        json.dumps(
            {
                "functions": {
                    "src/m.c#f": {
                        "name": "f",
                        "file": "src/m.c",
                        "module": "m",
                        "verifiability": "core_provable",
                        "wp_blockers": [],
                        "wp_notes": [],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    prep = WO.prepare_agent(run_dir=run_dir, agent_id="prove-f", role="prover", c_file="src/m.c", function="f")
    brief = (run_dir / prep["brief_file"]).read_text(encoding="utf-8")

    assert "## WP Verifiability & Iteration Budget" in brief
    assert "- **Static WP Verifiability Classification:** `core_provable`" in brief
    assert "Detected WP Blockers" not in brief
    assert "Detected WP Notes" not in brief
    assert "Fast-Fail Rule" not in brief
    assert "at most `6` `run_wp_function.py` invocations and `900s` wall-clock" in brief
    assert "time your later calls spend queued for a WP lease in the host resource broker does not count." in brief


@pytest.mark.unit
def test_guardrail_lease_wait_is_credited_after_first_wp_and_not_double_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1. Before first_wp_at is set: non-wp lease waits must NOT be credited.
    scratch, c_file = _prover(
        tmp_path,
        {"max_wp_invocations": 6, "max_wall_clock_s": 900, "wp_invocations": 0, "first_wp_at": None},
    )
    guard_cmd = (
        "python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py guardrail "
        "--sources agents/prove-f/scratch/work/f.c --out-bin agents/prove-f/scratch/g"
    )
    assert R._credit_prover_budget_lease_wait(guard_cmd, tmp_path, "111111111111", 300.0) is False
    budget_before = json.loads((scratch / ".prover_budget.json").read_text(encoding="utf-8"))
    assert "lease_wait_s" not in budget_before and "lease_wait_credited" not in budget_before

    # 2. After first_wp_at is set (1000s ago): a 500s guardrail wait is credited idempotently.
    now = time.time()
    (scratch / ".prover_budget.json").write_text(
        json.dumps(
            {
                "max_wp_invocations": 6,
                "max_wall_clock_s": 900,
                "wp_invocations": 1,
                "first_wp_at": now - 1000.0,
            }
        ),
        encoding="utf-8",
    )
    assert R._credit_prover_budget_lease_wait(guard_cmd, tmp_path, "222222222222", 500.0, now=now) is True
    # Repeating the exact same lease_id is idempotent (no double-counting).
    assert R._credit_prover_budget_lease_wait(guard_cmd, tmp_path, "222222222222", 500.0, now=now) is False
    budget = json.loads((scratch / ".prover_budget.json").read_text(encoding="utf-8"))
    assert budget["lease_wait_s"] == pytest.approx(500.0)
    assert budget["lease_wait_credited"] == ["222222222222"]

    # 3. A subsequent wp lease credited by resources.py is NOT double-counted when run_wp_function.py
    #    also sees FRAMAC_LEASE_ID / FRAMAC_LEASE_WAITED_S inside the container.
    wp_cmd = (
        "python3 /opt/framac-pipeline/scripts/run_wp_function.py "
        "--file agents/prove-f/scratch/work/f.c --function f "
        "--out-dir agents/prove-f/scratch/wp --out-json agents/prove-f/scratch/wp_f.json"
    )
    assert R._credit_prover_budget_lease_wait(wp_cmd, tmp_path, "333333333333", 200.0, now=now) is True
    _lease_env(monkeypatch, "333333333333", "200.0")
    res, calls = _run(c_file, scratch, monkeypatch)
    assert not res.get("budget_exhausted"), res.get("wp_log_tail")
    assert any("-wp" in c for c in calls)
    budget_after = json.loads((scratch / ".prover_budget.json").read_text(encoding="utf-8"))
    # Total credited wait is 500 + 200 = 700 (NOT 500 + 200 + 200 = 900).
    assert budget_after["lease_wait_s"] == pytest.approx(700.0)
    assert budget_after["lease_wait_credited"] == ["222222222222", "333333333333"]

    # 4. Cap: a wait larger than since_first_s is clamped to since_first_s.
    assert R._credit_prover_budget_lease_wait(guard_cmd, tmp_path, "444444444444", 5000.0, now=now + 10.0) is True
    budget_capped = json.loads((scratch / ".prover_budget.json").read_text(encoding="utf-8"))
    assert budget_capped["lease_wait_s"] == pytest.approx(1010.0)


@pytest.mark.unit
def test_in_container_resources_run_sublease_wait_is_credited_to_prover_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    run_dir = tmp_path / "run"
    scratch, c_file = _prover(run_dir, _second_call_budget(600.0))
    (run_dir / "run-metadata.json").write_text("{}", encoding="utf-8")
    broker_dir = tmp_path / "container-broker"
    monkeypatch.setenv("FRAMAC_BROKER_DIR", str(broker_dir))
    monkeypatch.delenv("FRAMAC_SUBLEASE_ID", raising=False)
    monkeypatch.chdir(run_dir)
    monkeypatch.setattr(R, "job_budget", lambda *_a, **_kw: R.Budget(2, 8192, "test"))
    monkeypatch.setattr(R, "cgroup_stats", lambda *_a, **_kw: {})

    # Hold the entire container pool briefly so the guardrail sub-lease must queue (~0.4s).
    broker = R.Broker(broker_dir, lambda: R.Budget(2, 8192, "test"), poll=0.02, max_poll=0.05)
    blocker = broker.acquire("build", fixed_cpus=2, fixed_mem_mb=8192)
    releaser = threading.Timer(0.4, broker.release, [blocker])
    releaser.start()
    try:
        rc = R.cmd_run(
            [
                "--class",
                "guardrail",
                "--",
                sys.executable,
                "-c",
                "import sys; sys.exit(0)",
                str(c_file),
            ]
        )
    finally:
        releaser.join()

    assert rc == 0
    budget = json.loads((scratch / ".prover_budget.json").read_text(encoding="utf-8"))
    assert len(budget.get("lease_wait_credited") or []) == 1
    assert float(budget.get("lease_wait_s") or 0) >= 0.3


@pytest.mark.unit
def test_pre_lease_budget_check_detects_exhaustion_and_respects_ignore_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run"
    scratch, c_file = _prover(
        run_dir,
        {
            "max_wp_invocations": 6,
            "max_wall_clock_s": 900,
            "wp_invocations": 6,
            "first_wp_at": time.time() - 100.0,
        },
    )
    wp_cmd = (
        "python3 /opt/framac-pipeline/scripts/run_wp_function.py "
        "--file agents/prove-f/scratch/work/f.c --function f "
        "--out-dir agents/prove-f/scratch/wp --out-json agents/prove-f/scratch/wp_f.json"
    )
    exhausted, reason = R._prover_budget_already_exhausted(wp_cmd, run_dir)
    assert exhausted is True and reason is not None and "6/6" in reason

    # Shell script wrapper (both relative and /framac-run/ container path) is also inspected.
    script = scratch / "run_wp.sh"
    script.write_text(f"#!/bin/bash\n{wp_cmd}\n", encoding="utf-8")
    assert R._prover_budget_already_exhausted("bash agents/prove-f/scratch/run_wp.sh", run_dir)[0] is True
    assert R._prover_budget_already_exhausted("bash /framac-run/agents/prove-f/scratch/run_wp.sh", run_dir)[0] is True

    # --ignore-prover-budget bypasses the pre-lease downgrade (e.g. parent re-checks).
    assert R._prover_budget_already_exhausted(f"{wp_cmd} --ignore-prover-budget", run_dir) == (False, None)

    # Compound script that also runs guardrail must NOT be downgraded to light.
    compound = scratch / "run_both.sh"
    compound.write_text(
        f"#!/bin/bash\n{wp_cmd}\npython3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py guardrail --sources agents/prove-f/scratch/work/f.c\n",
        encoding="utf-8",
    )
    assert R._prover_budget_already_exhausted("bash agents/prove-f/scratch/run_both.sh", run_dir) == (False, None)

    # Wall-clock exhaustion honours credited lease_wait_s.
    now = time.time()
    (scratch / ".prover_budget.json").write_text(
        json.dumps(
            {
                "max_wp_invocations": 6,
                "max_wall_clock_s": 900,
                "wp_invocations": 1,
                "first_wp_at": now - 950.0,
                "lease_wait_s": 0.0,
            }
        ),
        encoding="utf-8",
    )
    exhausted_wall, wall_reason = R._prover_budget_already_exhausted(wp_cmd, run_dir, now=now)
    assert exhausted_wall is True and wall_reason is not None and "950s/900s" in wall_reason

    # With 200s credited from a guardrail wait, elapsed = 750s <= 900s -> NOT exhausted.
    (scratch / ".prover_budget.json").write_text(
        json.dumps(
            {
                "max_wp_invocations": 6,
                "max_wall_clock_s": 900,
                "wp_invocations": 1,
                "first_wp_at": now - 950.0,
                "lease_wait_s": 200.0,
            }
        ),
        encoding="utf-8",
    )
    assert R._prover_budget_already_exhausted(wp_cmd, run_dir, now=now) == (False, None)

    # Confirm run_wp_function.py inside a `light` 1024 MiB container still returns `budget_exhausted: True`
    # (not `insufficient_memory`) because the budget check runs before WP_MIN_MEMORY_MB.
    (scratch / ".prover_budget.json").write_text(
        json.dumps(
            {
                "max_wp_invocations": 6,
                "max_wall_clock_s": 900,
                "wp_invocations": 6,
                "first_wp_at": now - 100.0,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FRAMAC_JOB_MEM_MB", "1024")
    _lease_env(monkeypatch, None, None)
    res, calls = _run(c_file, scratch, monkeypatch)
    assert res["budget_exhausted"] is True
    assert res["status"] == "unproven_goals_remain"
    assert res.get("reason") != "insufficient_memory"
    assert not calls


@pytest.mark.unit
def test_scaled_prover_budget_allows_large_function_second_call_and_updates_scheduler_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import wp_scheduler as S

    target = tmp_path / "target"
    src = target / "src"
    src.mkdir(parents=True)
    (src / "m.c").write_text("int recv_msg(int x) { return x; }\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    WO.init_overlay(target, run_dir / "workspace")
    (run_dir / "run-metadata.json").write_text(json.dumps({"profile": "standard"}), encoding="utf-8")
    wp_dir = run_dir / "workspace" / "reports" / "wp"
    wp_dir.mkdir(parents=True, exist_ok=True)
    (wp_dir / "recv_msg.json").write_text(
        json.dumps(
            {
                "function": "recv_msg",
                "file": "workspace/work/src/m.c",
                "total_goals": 116,
                "wp_vc_stats": {"proved": 190, "total": 316, "timeouts": 126},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("FRAMAC_PROVER_WALL_BUDGET_S", raising=False)
    prep = WO.prepare_agent(
        run_dir=run_dir, agent_id="prove-recv_msg", role="prover", c_file="src/m.c", function="recv_msg"
    )
    scratch = run_dir / "agents" / "prove-recv_msg" / "scratch"
    budget_path = scratch / ".prover_budget.json"
    budget = json.loads(budget_path.read_text(encoding="utf-8"))
    assert budget["max_wall_clock_s"] == 2080
    assert budget["budget_base_s"] == 900
    assert "316 VCs" in budget["budget_scaling_reason"]

    # Scheduler reads the scaled wall budget directly from .prover_budget.json.
    monkeypatch.chdir(run_dir)
    assert S._task_wall_budget_s({"agent_id": "prove-recv_msg"}) == 2080

    # After 1100s of prover time (past the old 900s default), a second WP call still runs with ~980s remaining.
    budget["wp_invocations"] = 1
    budget["first_wp_at"] = time.time() - 1100.0
    budget_path.write_text(json.dumps(budget), encoding="utf-8")
    _lease_env(monkeypatch, None, None)
    c_file = scratch / "work" / "src" / "m.c"
    calls: list[list[str]] = []
    monkeypatch.setattr(W.subprocess, "run", _fake_wp(calls))
    res = W.run_wp_on_function(
        c_file,
        "recv_msg",
        scratch / "wp",
        cache_dir="off",
        retry_tail=False,
        retry_bitwise=False,
        retry_cast_probe=False,
    )
    assert not res.get("budget_exhausted"), res.get("wp_log_tail")
    assert any("-wp" in c for c in calls)
    assert 950 <= res["sizing"]["wall_timeout_s"] <= 985
    brief = (run_dir / prep["brief_file"]).read_text(encoding="utf-8")
    assert "`2080s` wall-clock" in brief
    assert "- **Budget Scaling:**" in brief
