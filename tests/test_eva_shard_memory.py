"""
Regression tests for Eva shard sub-lease memory sizing and pool concurrency warnings
(QCBOR v2.0-beta-1 run-2, 2026-11-23).

Before the fix, `resources.history_estimate(run_dir, "eva", "libqcbor_a:shardN")` fell through
to Tier 3 (module prefix) and matched the unsharded `libqcbor_a` records across run-local and
shared cross-run history (`/framac-cache/resource-history/eva/`): run-1's whole-harness Eva peak
of 10,697 MiB became `mem_floor_mb: 13372` for every shard in a 17,408 MiB `phase-static` pool,
forcing all 8 shards to run one at a time.
"""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import eva_shards as es
import phase0_gates as pg
import pipeline_make as pm
import resources as R
from test_eva_shards import ACSL, _mk, _sharded_run, _single_run
from test_resources import SCRIPT, Harness, _isolated_env, wait_for  # noqa: F401  (autouse fixture)

POOL_CPUS = 15
POOL_MEM_MB = 17408


def _write_harness(run_dir: Path, module: str, cases: int, extra: str = "") -> str:
    hdir = run_dir / "workspace" / "harnesses"
    hdir.mkdir(parents=True, exist_ok=True)
    sidecar = {"module": module, "entry_style": "dispatch", "dispatch_cases": [f"f_{i}();" for i in range(cases)]}
    (hdir / f"harness_{module}.json").write_text(json.dumps(sidecar), encoding="utf-8")
    (hdir / f"harness_{module}.c").write_text(
        f"/* {cases} cases {extra} */\nvoid eva_main(void) {{}}\n", encoding="utf-8"
    )
    digest = pg.harness_digest(run_dir, module, ignore_exempt=True)
    assert digest is not None
    return digest


def _write_plan(
    run_dir: Path,
    module: str,
    shards: list[list[int]],
    predicted_shard_s: list[float] | None = None,
    *,
    case_count: int | None = None,
) -> dict:
    plan: dict = {
        "format": es.SHARD_FORMAT,
        "settings_digest": "dig",
        "case_count": case_count if case_count is not None else sum(len(s) for s in shards),
        "k": len(shards),
        "shards": shards,
        "forced": False,
        "basis": {"costs": "flamegraph", "single_run_s": 7200.0, "limit_s": 5760.0},
    }
    if predicted_shard_s is not None:
        plan["predicted_shard_s"] = predicted_shard_s
        plan["predicted_makespan_s"] = max(predicted_shard_s, default=0.0)
    path = run_dir / es.SHARD_DIR / module / "plan.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan), encoding="utf-8")
    return plan


def _balanced_shards(case_count: int = 244, k: int = 8) -> list[list[int]]:
    buckets: list[list[int]] = [[] for _ in range(k)]
    for i in range(case_count):
        buckets[i % k].append(i)
    return buckets


# ---------------------------------------------------------------------------
# 1. Shard-aware and harness-digest-aware history_estimate
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_shard_plan_digest_matches_eva_shards():
    plan = {"shards": _balanced_shards(24, 4)}
    assert R._eva_shard_plan_digest(plan) == es.plan_digest(plan)


@pytest.mark.unit
def test_shard_key_never_inherits_unscaled_whole_module_peak_without_plan(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    R.write_history(run, {"class": "eva", "key": "libqcbor_a", "peak_mb": 10697, "oom_killed": False})
    assert R.history_estimate(run, "eva", "libqcbor_a") == math.ceil(1.25 * 10697)
    # Without a shard plan, a shard key must not inherit the unsharded whole-module peak.
    assert R.history_estimate(run, "eva", "libqcbor_a:shard0") is None
    assert R.history_estimate(run, "eva", "libqcbor_a:shard7") is None


@pytest.mark.unit
def test_shard_key_scales_unsharded_fallback_by_predicted_time_share(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    _write_harness(run, "libqcbor_a", 244)
    _write_plan(run, "libqcbor_a", _balanced_shards(244, 8), [904.5] * 8)
    R.write_history(run, {"class": "eva", "key": "libqcbor_a", "peak_mb": 4780, "oom_killed": False})
    # 1.25 * 4780 = 5975.0; 1/8 share = 746.875 -> 747 MiB (below class 2048 MiB floor).
    for i in range(8):
        assert R.history_estimate(run, "eva", f"libqcbor_a:shard{i}") == math.ceil(1.25 * 4780 / 8)

    # Skewed plan: dominant shard 0 holds 95% of predicted time, light shard 1 holds 5%, zero-cost shard 2 holds 0%.
    skew_run = tmp_path / "skew"
    skew_run.mkdir()
    _write_harness(skew_run, "dnsrec", 20)
    _write_plan(
        skew_run, "dnsrec", [[11], [0, 1, 2, 3, 4], list(range(5, 11)) + list(range(12, 20))], [950.0, 50.0, 0.0]
    )
    R.write_history(skew_run, {"class": "eva", "key": "dnsrec", "peak_mb": 10000, "oom_killed": False})
    assert R.history_estimate(skew_run, "eva", "dnsrec:shard0") == math.ceil(1.25 * 10000 * 0.95)
    assert R.history_estimate(skew_run, "eva", "dnsrec:shard1") == math.ceil(1.25 * 10000 * 0.05)
    assert R.history_estimate(skew_run, "eva", "dnsrec:shard2") is None


@pytest.mark.unit
def test_shard_key_falls_back_to_case_share_for_legacy_plan_without_predicted_times(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    _write_harness(run, "m", 240)
    _write_plan(run, "m", _balanced_shards(240, 8), predicted_shard_s=None, case_count=240)
    R.write_history(run, {"class": "eva", "key": "m", "peak_mb": 10000, "oom_killed": False})
    assert R.history_estimate(run, "eva", "m:shard0") == math.ceil(1.25 * 10000 * 30 / 240)


@pytest.mark.unit
def test_harness_change_prefers_current_harness_and_uses_newest_prior_harness(tmp_path, monkeypatch):
    shared = tmp_path / "shared-cache"
    shared.mkdir()
    monkeypatch.setenv("FRAMAC_SHARED_CACHE_DIR", str(shared))
    monkeypatch.setenv("FRAMAC_CACHE_MODE", "rw")

    # Run-0 (oldest harness H0): peak 15,000 MiB.
    run0 = tmp_path / "run-0"
    _write_harness(run0, "libqcbor_a", 100, extra="v0")
    R.write_history(run0, {"class": "eva", "key": "libqcbor_a", "peak_mb": 15000, "oom_killed": False})
    time.sleep(0.005)

    # Run-1 (newer harness H1): peak 10,697 MiB, followed by a tiny merge/facts record on the same harness H1.
    run1 = tmp_path / "run-1"
    _write_harness(run1, "libqcbor_a", 126, extra="v1")
    R.write_history(run1, {"class": "eva", "key": "libqcbor_a", "peak_mb": 10697, "oom_killed": False})
    time.sleep(0.005)
    R.write_history(run1, {"class": "eva", "key": "libqcbor_a", "peak_mb": 120, "oom_killed": False})
    time.sleep(0.005)

    # Run-2 (brand new 244-case harness H2): before Run-2 has its own measurement, unsharded Eva uses
    # the newest prior harness group (H1 -> 10,697), not the older H0 peak (15,000), and is not masked by H1's 120 MiB.
    run2 = tmp_path / "run-2"
    h2 = _write_harness(run2, "libqcbor_a", 244, extra="v2")
    assert R.history_estimate(run2, "eva", "libqcbor_a") == math.ceil(1.25 * 10697)

    # Even before Run-2's unsharded run, a shard scales H1's 13,372 by 1/8 -> 1,672 MiB (fits 8 in 17,408 MiB).
    _write_plan(run2, "libqcbor_a", _balanced_shards(244, 8), [904.5] * 8)
    assert R.history_estimate(run2, "eva", "libqcbor_a:shard1") == math.ceil(1.25 * 10697 / 8)

    # Once Run-2 records its own 4,780 MiB unsharded run (auto-tagged with H2), H1 is superseded completely.
    written = R.write_history(run2, {"class": "eva", "key": "libqcbor_a", "peak_mb": 4780, "oom_killed": False})
    assert written is not None
    assert json.loads(written.read_text(encoding="utf-8"))["harness_digest"] == h2
    assert R.history_estimate(run2, "eva", "libqcbor_a") == math.ceil(1.25 * 4780)
    assert R.history_estimate(run2, "eva", "libqcbor_a:shard1") == math.ceil(1.25 * 4780 / 8)


@pytest.mark.unit
def test_legacy_untagged_shared_record_does_not_override_current_local_run(tmp_path, monkeypatch):
    """Upgrading onto a live run-2 whose shared cache holds an untagged run-1 record (10,697 MiB)."""
    shared = tmp_path / "shared-cache"
    shared_eva = shared / "resource-history" / "eva"
    shared_eva.mkdir(parents=True)
    # Run-1 legacy record (no harness_digest field) written only in shared cache.
    (shared_eva / "20261122T232400000000Z-aaaa1111.json").write_text(
        json.dumps({"class": "eva", "key": "libqcbor_a", "peak_mb": 10697, "oom_killed": False}),
        encoding="utf-8",
    )
    monkeypatch.setenv("FRAMAC_SHARED_CACHE_DIR", str(shared))
    monkeypatch.setenv("FRAMAC_CACHE_MODE", "ro")

    run2 = tmp_path / "run-2"
    _write_harness(run2, "libqcbor_a", 244, extra="v2")
    _write_plan(run2, "libqcbor_a", _balanced_shards(244, 8), [904.5] * 8)
    # Run-2 local legacy record (no harness_digest, written after run-2's harness).
    local_eva = run2 / R.HISTORY_DIR / "eva"
    local_eva.mkdir(parents=True)
    local_rec = local_eva / "20261123T124800000000Z-bbbb2222.json"
    local_rec.write_text(
        json.dumps({"class": "eva", "key": "libqcbor_a", "peak_mb": 4780, "oom_killed": False}),
        encoding="utf-8",
    )
    now = time.time() + 2.0
    os.utime(local_rec, (now, now))

    assert R.history_estimate(run2, "eva", "libqcbor_a") == math.ceil(1.25 * 4780)
    assert R.history_estimate(run2, "eva", "libqcbor_a:shard1") == math.ceil(1.25 * 4780 / 8)


@pytest.mark.unit
def test_exact_shard_history_respects_plan_digest_and_oom_doubling(tmp_path, monkeypatch):
    shared = tmp_path / "shared-cache"
    shared.mkdir()
    monkeypatch.setenv("FRAMAC_SHARED_CACHE_DIR", str(shared))
    monkeypatch.setenv("FRAMAC_CACHE_MODE", "rw")

    run1 = tmp_path / "run-1"
    _write_harness(run1, "m", 16, extra="v1")
    plan1 = _write_plan(run1, "m", _balanced_shards(16, 2), [3000.0, 3000.0])
    p1 = es.plan_digest(plan1)
    R.write_history(run1, {"class": "eva", "key": "m", "peak_mb": 10000, "oom_killed": False})
    written = R.write_history(run1, {"class": "eva", "key": "m:shard0", "peak_mb": 6000, "oom_killed": False})
    assert written is not None
    assert json.loads(written.read_text(encoding="utf-8"))["shard_plan_digest"] == p1
    assert R.history_estimate(run1, "eva", "m:shard0") == math.ceil(1.25 * 6000)

    # Replanning to 8 shards invalidates the 2-shard exact record so shard0 scales from unsharded instead.
    run2 = tmp_path / "run-2"
    _write_harness(run2, "m", 16, extra="v1")
    _write_plan(run2, "m", _balanced_shards(16, 8), [750.0] * 8)
    assert R.history_estimate(run2, "eva", "m:shard0") == math.ceil(1.25 * 10000 / 8)

    # An OOM kill on shard0 under the new 8-shard plan doubles its peak for the next run.
    R.write_history(run2, {"class": "eva", "key": "m:shard0", "peak_mb": 3500, "oom_killed": True})
    assert R.history_estimate(run2, "eva", "m:shard0") == 7000

    # A small harness edit that keeps the same 8-shard plan still reuses shard0's matching-plan measurement.
    _write_harness(run2, "m", 16, extra="v2-repaired")
    assert R.history_estimate(run2, "eva", "m:shard0") == 7000


@pytest.mark.unit
def test_shard_records_never_mask_unsharded_peaks_for_tuning_rungs(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    R.write_history(run, {"class": "eva", "key": "libqcbor_a", "peak_mb": 12630, "oom_killed": False})
    time.sleep(0.002)
    for i in range(8):
        R.write_history(run, {"class": "eva", "key": f"libqcbor_a:shard{i}", "peak_mb": 1200, "oom_killed": False})
        time.sleep(0.001)
    # The 8 recent shard records must not drown out the unsharded 12,630 MiB peak for a tuning rung.
    assert R.history_estimate(run, "eva", "libqcbor_a:slevel") == math.ceil(1.25 * 12630)


# ---------------------------------------------------------------------------
# 2. Pool memory concurrency check (eva_shards.py + pipeline_make.py)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_estimate_shard_concurrency_and_memory_note():
    plan = {"k": 8, "predicted_shard_s": [904.5] * 8}

    # Fixed case: 8 shards at 2,048 MiB each fit in a 17,408 MiB, 15-CPU pool -> no warning.
    sc_ok = es.estimate_shard_concurrency([2048] * 8, POOL_MEM_MB, pool_cpus=POOL_CPUS, predicted_shard_s=[904.5] * 8)
    assert sc_ok is not None and sc_ok.max_concurrent == 8 and not sc_ok.memory_limited
    assert es.memory_concurrency_note(plan, [2048] * 8, POOL_MEM_MB, POOL_CPUS) is None

    # Serialized case: 8 shards at 13,372 MiB each in a 17,408 MiB, 15-CPU pool -> 1 at a time in series.
    sc_ser = es.estimate_shard_concurrency([13372] * 8, POOL_MEM_MB, pool_cpus=POOL_CPUS, predicted_shard_s=[904.5] * 8)
    assert sc_ser is not None and sc_ser.max_concurrent == 1 and sc_ser.memory_limited
    assert sc_ser.scheduled_makespan_s == pytest.approx(8 * 904.5)
    note_ser = es.memory_concurrency_note(plan, [13372] * 8, POOL_MEM_MB, POOL_CPUS)
    assert note_ser is not None
    assert "only 1 of 8 shards fits in the 17408 MiB pool" in note_ser
    assert "in series" in note_ser and "7236.0 s wall time instead of 904.5 s in parallel" in note_ser

    # Wave-limited case: 8 shards at 4,500 MiB each -> 3 at a time (3 waves).
    note_wave = es.memory_concurrency_note(plan, [4500] * 8, POOL_MEM_MB, POOL_CPUS)
    assert note_wave is not None
    assert "at most 3 of 8 shards fit in the 17408 MiB pool" in note_wave
    assert "in waves" in note_wave and "2713.5 s wall time instead of 904.5 s in parallel" in note_wave

    # CPU-limited only: 16 shards at 2,048 MiB on 4 CPUs / 17,408 MiB -> 4 fit on 4 CPUs, not memory-limited.
    plan16 = {"k": 16, "predicted_shard_s": [500.0] * 16}
    assert es.memory_concurrency_note(plan16, [2048] * 16, POOL_MEM_MB, pool_cpus=4) is None

    # Clamped case: per-shard memory exceeds the pool itself.
    note_clamp = es.memory_concurrency_note(plan, [20000] * 8, POOL_MEM_MB, POOL_CPUS)
    assert note_clamp is not None and "clamped to the pool" in note_clamp


@pytest.mark.unit
def test_pipeline_make_gen_warns_when_shards_serialize_and_keeps_k_fixed(tmp_path, monkeypatch):
    # 100 equal cases -> choose_shard_count picks k=8 (13 cases/shard; k=9 holds 12, < 10% gain).
    run = _sharded_run(tmp_path, cases=100)
    _single_run(run, 9000.0, [f"eva_main;snmp_call_{k} 100.0" for k in range(100)])
    # Host pool of 30 CPUs / 57,000 MiB -> phase-static nominal grant is 15 CPUs / 17,408 MiB.
    monkeypatch.setenv("FRAMAC_JOB_CLASS", "light")
    monkeypatch.setenv("FRAMAC_POOL_CPUS", "30")
    monkeypatch.setenv("FRAMAC_POOL_MEM_MB", "57000")

    # Unsharded history of 10,697 MiB scales by 1/8 -> 1,672 MiB -> class floor 2,048 MiB -> all 8 fit, no warning.
    R.write_history(run, {"class": "eva", "key": "snmp", "peak_mb": 10697, "oom_killed": False})
    _, res = _mk(run)
    plan = json.loads((run / es.SHARD_DIR / "snmp" / "plan.json").read_text(encoding="utf-8"))
    k = plan["k"]
    assert k == 8
    assert not any("memory concurrency:" in w for w in res["warnings"]), res["warnings"]

    # When exact per-shard history genuinely needs 10,000 MiB/shard (8,000 peak * 1.25), gen warns about serial
    # execution while keeping k fixed at 8 (Rule 1: hardware changes throughput, never the shard plan).
    for i in range(k):
        R.write_history(run, {"class": "eva", "key": f"snmp:shard{i}", "peak_mb": 8000, "oom_killed": False})
    _, res2 = _mk(run)
    plan2 = json.loads((run / es.SHARD_DIR / "snmp" / "plan.json").read_text(encoding="utf-8"))
    assert plan2["k"] == 8 and plan2["shards"] == plan["shards"]
    mem_warns = [w for w in res2["warnings"] if "memory concurrency:" in w]
    assert len(mem_warns) == 1
    assert "only 1 of 8 shards fits in the 17408 MiB pool" in mem_warns[0]
    assert "in series" in mem_warns[0]


@pytest.mark.unit
def test_pipeline_make_run_logs_shard_memory_concurrency_warning_to_stderr(tmp_path, monkeypatch, capsys):
    run = _sharded_run(tmp_path, cases=4)
    pm.params_set(run, "snmp", eva_shards=4)
    # Seed run-metadata.json with resources.pool (4 CPUs -> phase-static nominal 2 CPUs / 4,096 MiB).
    meta = json.loads((run / "run-metadata.json").read_text(encoding="utf-8"))
    meta["resources"] = {"pool": {"cpus": 4, "mem_mb": 8192}}
    (run / "run-metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    monkeypatch.delenv("FRAMAC_JOB_CLASS", raising=False)
    monkeypatch.delenv("FRAMAC_POOL_CPUS", raising=False)
    monkeypatch.delenv("FRAMAC_POOL_MEM_MB", raising=False)
    # First gen writes plan.json; then record 3,000 MiB exact peak per shard (3,750 MiB > 4096/2 -> serial).
    pm.generate(run, templates_dir=ACSL)
    for i in range(4):
        R.write_history(run, {"class": "eva", "key": f"snmp:shard{i}", "peak_mb": 3000, "oom_killed": False})

    rc, summary = pm.run_targets(
        ["eva-snmp"],
        run_dir=run,
        jobs=2,
        make_runner=lambda cmd, cwd, sink: 0,
        templates_dir=ACSL,
    )
    err = capsys.readouterr().err
    assert rc == 0 or summary["targets"]["eva-snmp"]["status"] == "no_output"
    assert "[pipeline_make] Warning: snmp: Eva sharding: memory concurrency:" in err
    assert "in series" in err


# ---------------------------------------------------------------------------
# 3. End-to-end container broker concurrency (real `resources.py run` processes)
# ---------------------------------------------------------------------------


@pytest.fixture
def shard_harness(tmp_path):
    h = Harness(tmp_path)
    yield h
    h.cleanup()


def test_qcbor_run2_eight_shards_run_concurrently_in_17408_mib_pool(shard_harness):
    """
    Exact QCBOR run-2 regression: shared cache has run-1's untagged 10,697 MiB whole-module Eva peak,
    run-2 has a new 244-case harness, a 4,780 MiB timed-out unsharded record, and an 8-shard plan.
    All 8 `resources.py run --class eva --key libqcbor_a:shardN` processes must be granted concurrently
    in a 15-CPU, 17,408 MiB container pool (each at 2,048 MiB) instead of serializing at 13,372 MiB.
    """
    h = shard_harness
    h.set_pool(POOL_CPUS, POOL_MEM_MB)
    shared = h.tmp / "shared-cache"
    shared_eva = shared / "resource-history" / "eva"
    shared_eva.mkdir(parents=True)
    # QCBOR run-1 legacy shared-cache peak (10,697 MiB -> 13,372 MiB unscaled).
    (shared_eva / "20261122T232400000000Z-run1peak.json").write_text(
        json.dumps({"class": "eva", "key": "libqcbor_a", "peak_mb": 10697, "oom_killed": False}),
        encoding="utf-8",
    )
    h.env["FRAMAC_SHARED_CACHE_DIR"] = str(shared)
    h.env["FRAMAC_CACHE_MODE"] = "rw"

    (h.cwd / "run-metadata.json").write_text("{}", encoding="utf-8")
    h2 = _write_harness(h.cwd, "libqcbor_a", 244, extra="qcbor-run2")
    plan = _write_plan(h.cwd, "libqcbor_a", _balanced_shards(244, 8), [904.5] * 8)
    p2 = es.plan_digest(plan)
    R.write_history(h.cwd, {"class": "eva", "key": "libqcbor_a", "peak_mb": 4780, "oom_killed": False})

    gate = h.tmp / "release.gate"
    for i in range(8):
        name = f"shard{i}"
        cmd = [
            sys.executable,
            str(SCRIPT),
            "run",
            "--class",
            "eva",
            "--key",
            f"libqcbor_a:shard{i}",
            "--",
            sys.executable,
            str(h.child),
            str(h.logs),
            name,
            "0.05",
            str(gate),
        ]
        with open(h.logs / f"{name}.broker.txt", "w", encoding="utf-8") as out:
            h.procs.append(subprocess.Popen(cmd, cwd=h.cwd, env=h.env, stdout=out, stderr=subprocess.STDOUT))
        h.names.append(name)

    # All 8 shards must start before the gate opens (proving true 8-way parallelism, never serial 1-by-1).
    wait_for(lambda: all(h.record(f"shard{i}", "start") is not None for i in range(8)), timeout=20.0)
    gate.write_text("go\n", encoding="utf-8")
    h.finish(timeout=20.0)

    assert all(p.returncode == 0 for p in h.procs), h.output()
    for i in range(8):
        rec = h.record(f"shard{i}", "end")
        assert rec is not None and rec["mem"] == R.CLASSES["eva"].mem_base_mb, h.output()

    # Each shard's recorded history carries the current harness_digest and shard_plan_digest.
    shard_recs = [
        json.loads(p.read_text(encoding="utf-8"))
        for p in sorted((h.cwd / R.HISTORY_DIR / "eva").glob("*.json"))
        if ":shard" in str(json.loads(p.read_text(encoding="utf-8")).get("key") or "")
    ]
    assert len(shard_recs) == 8
    for rec in shard_recs:
        assert rec.get("harness_digest") == h2
        assert rec.get("shard_plan_digest") == p2
