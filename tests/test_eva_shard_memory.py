"""
Regression tests for Eva shard sub-lease memory sizing, live cgroup admission, and pool
concurrency warnings (QCBOR v2.0-beta-1 run-2, 2026-11-23).

Covers both sides of Eva shard memory sizing:
1. Over-allocation (before 03523de): `history_estimate(run_dir, "eva", "libqcbor_a:shardN")`
   inherited run-1's unscaled 10,697 MiB whole-module peak (`13,372 MiB`), serializing all 8
   shards 1-at-a-time in a 17,408 MiB `phase-static` pool.
2. Under-allocation (after 03523de): pure linear `1/k` scaling dropped 4,780 MiB -> 747 MiB
   (floored to the 2,048 MiB class base) even after shard 1 had already peaked at 4,211 MiB
   (`5,264 MiB` with 1.25x), admitting 6 shards simultaneously and pushing `memory.peak` to
   18.14 GB / 18.25 GB.

Defense in depth verified here:
- Fixed-overhead floor `EVA_SHARD_MEM_FLOOR_SHARE` (0.6) on unsharded fallback (`max(0.6, share)`).
- Same-plan peer sibling shard history (`shard_plan_digest`, ignoring fast non-OOM aborts and
  skewed outliers) plus dynamic `history_fn` refresh for waiting tickets in `Broker._acquire`.
- Live cgroup working-set (`memory.current - inactive_file`) admission accounting in `plan_grant`
  and `cmd_run` (without deadlocking when no gated lease is running).
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
from test_resources import SCRIPT, Harness, _isolated_env, _ticket, wait_for  # noqa: F401  (autouse fixture)

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
# 1. Fixed-overhead floor, peer sibling shards, and harness-digest scoping
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_shard_plan_digest_matches_eva_shards():
    plan = {"shards": _balanced_shards(24, 4)}
    assert R._eva_shard_plan_digest(plan) == es.plan_digest(plan)


@pytest.mark.unit
def test_shard_key_without_plan_uses_fixed_floor_never_unscaled_whole_module(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    R.write_history(run, {"class": "eva", "key": "libqcbor_a", "peak_mb": 10697, "oom_killed": False})
    unscaled = math.ceil(1.25 * 10697)
    assert R.history_estimate(run, "eva", "libqcbor_a") == unscaled
    expected_floor = math.ceil(1.25 * 10697 * R.EVA_SHARD_MEM_FLOOR_SHARE)
    # Never inherits the unscaled 13,372 MiB peak, and retains the fixed-overhead floor (8,023 MiB).
    assert R.history_estimate(run, "eva", "libqcbor_a:shard0") == expected_floor
    assert expected_floor < unscaled


@pytest.mark.unit
def test_shard_key_scales_unsharded_fallback_with_fixed_overhead_floor(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    _write_harness(run, "libqcbor_a", 244)
    _write_plan(run, "libqcbor_a", _balanced_shards(244, 8), [904.5] * 8)
    R.write_history(run, {"class": "eva", "key": "libqcbor_a", "peak_mb": 4780, "oom_killed": False})
    # 1.25 * 4780 = 5975.0; max(0.6, 1/8) = 0.6 -> 3,585 MiB (admits 4 shards in 17,408 MiB, not 8 at 2,048).
    expected_q2 = math.ceil(1.25 * 4780 * R.EVA_SHARD_MEM_FLOOR_SHARE)
    assert expected_q2 == 3585
    for i in range(8):
        assert R.history_estimate(run, "eva", f"libqcbor_a:shard{i}") == expected_q2

    # Skewed plan: dominant shard 0 (95%) keeps 0.95; light shard 1 (5%) and zero-cost shard 2 (0%) keep floor 0.6.
    skew_run = tmp_path / "skew"
    skew_run.mkdir()
    _write_harness(skew_run, "dnsrec", 20)
    _write_plan(
        skew_run,
        "dnsrec",
        [[11], [0, 1, 2, 3, 4], list(range(5, 11)) + list(range(12, 20))],
        [950.0, 50.0, 0.0],
    )
    R.write_history(skew_run, {"class": "eva", "key": "dnsrec", "peak_mb": 10000, "oom_killed": False})
    assert R.history_estimate(skew_run, "eva", "dnsrec:shard0") == math.ceil(1.25 * 10000 * 0.95)
    assert R.history_estimate(skew_run, "eva", "dnsrec:shard1") == math.ceil(1.25 * 10000 * R.EVA_SHARD_MEM_FLOOR_SHARE)
    assert R.history_estimate(skew_run, "eva", "dnsrec:shard2") == math.ceil(1.25 * 10000 * R.EVA_SHARD_MEM_FLOOR_SHARE)


@pytest.mark.unit
def test_shard_key_falls_back_to_case_share_with_floor_for_legacy_plan(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    _write_harness(run, "m", 10)
    # 7 of 10 cases in shard0 (0.7 > 0.6 floor), 3 of 10 in shard1 (0.3 -> 0.6 floor).
    _write_plan(run, "m", [list(range(7)), [7, 8, 9]], predicted_shard_s=None, case_count=10)
    R.write_history(run, {"class": "eva", "key": "m", "peak_mb": 10000, "oom_killed": False})
    assert R.history_estimate(run, "eva", "m:shard0") == math.ceil(1.25 * 10000 * 0.7)
    assert R.history_estimate(run, "eva", "m:shard1") == math.ceil(1.25 * 10000 * R.EVA_SHARD_MEM_FLOOR_SHARE)


@pytest.mark.unit
def test_same_plan_peer_sibling_shard_sizes_remaining_shards(tmp_path):
    """QCBOR run-2 restart: once shard1 has a real 4,211 MiB peak, peer shards 2-7 size from 5,264 MiB."""
    run = tmp_path / "run"
    run.mkdir()
    _write_harness(run, "libqcbor_a", 244, extra="run2")
    _write_plan(run, "libqcbor_a", _balanced_shards(244, 8), [904.5] * 8)
    R.write_history(run, {"class": "eva", "key": "libqcbor_a", "peak_mb": 4780, "oom_killed": False})
    # Before any shard finishes: cold-start 0.6 floor -> 3,585 MiB.
    assert R.history_estimate(run, "eva", "libqcbor_a:shard2") == 3585

    # A fast non-OOM abort (rc=1, peak=120 MiB) on shard0 must not under-size peer shards.
    R.write_history(run, {"class": "eva", "key": "libqcbor_a:shard0", "rc": 1, "peak_mb": 120, "oom_killed": False})
    assert R.history_estimate(run, "eva", "libqcbor_a:shard2") == 3585

    # Once shard1 completes (rc=0, peak=4,211 MiB -> 5,264 MiB), peer shards immediately inherit 5,264 MiB.
    R.write_history(run, {"class": "eva", "key": "libqcbor_a:shard1", "rc": 0, "peak_mb": 4211, "oom_killed": False})
    assert R.history_estimate(run, "eva", "libqcbor_a:shard1") == 5264
    for i in (0, 2, 3, 4, 5, 6, 7):
        assert R.history_estimate(run, "eva", f"libqcbor_a:shard{i}") == 5264

    # An OOM-killed peer shard (rc=137, oom_killed=True, peak=4,000 MiB) doubles to 8,000 MiB for peers.
    R.write_history(run, {"class": "eva", "key": "libqcbor_a:shard3", "rc": 137, "peak_mb": 4000, "oom_killed": True})
    assert R.history_estimate(run, "eva", "libqcbor_a:shard4") == 8000


@pytest.mark.unit
def test_legacy_untagged_local_sibling_shard_sizes_peer_shards_after_upgrade(tmp_path):
    """Upgrading onto a live run-2 where shard1 ran before 03523de (no shard_plan_digest field)."""
    run = tmp_path / "run-2"
    run.mkdir()
    _write_harness(run, "libqcbor_a", 244, extra="run2")
    _write_plan(run, "libqcbor_a", _balanced_shards(244, 8), [904.5] * 8)
    local_eva = run / R.HISTORY_DIR / "eva"
    local_eva.mkdir(parents=True)
    rec_path = local_eva / "20261123T141857000000Z-shard1.json"
    rec_path.write_text(
        json.dumps({"class": "eva", "key": "libqcbor_a:shard1", "rc": 0, "peak_mb": 4211, "oom_killed": False}),
        encoding="utf-8",
    )
    later = time.time() + 2.0
    os.utime(rec_path, (later, later))
    assert R.history_estimate(run, "eva", "libqcbor_a:shard2") == 5264


@pytest.mark.unit
def test_skewed_shards_do_not_cross_contaminate_as_peers(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    _write_harness(run, "dnsrec", 20)
    _write_plan(run, "dnsrec", [[11], [0, 1, 2], list(range(3, 11)) + list(range(12, 20))], [950.0, 25.0, 25.0])
    R.write_history(run, {"class": "eva", "key": "dnsrec", "peak_mb": 10000, "oom_killed": False})
    # Light shard1 finishes at 1,500 MiB -> peer light shard2 (same 25s share) uses 1,875 MiB,
    # while dominant shard0 (950s share, >2x) ignores shard1 and keeps 0.95 * 12,500 = 11,875 MiB.
    R.write_history(run, {"class": "eva", "key": "dnsrec:shard1", "rc": 0, "peak_mb": 1500, "oom_killed": False})
    assert R.history_estimate(run, "eva", "dnsrec:shard2") == math.ceil(1.25 * 1500)
    assert R.history_estimate(run, "eva", "dnsrec:shard0") == math.ceil(1.25 * 10000 * 0.95)


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
    # the newest prior harness group (H1 -> 10,697), not H0 (15,000), and is not masked by H1's 120 MiB.
    run2 = tmp_path / "run-2"
    h2 = _write_harness(run2, "libqcbor_a", 244, extra="v2")
    assert R.history_estimate(run2, "eva", "libqcbor_a") == math.ceil(1.25 * 10697)

    # Before Run-2's unsharded run, a shard applies the 0.6 floor to H1's 13,372 -> 8,023 MiB (2 fit in 17,408).
    _write_plan(run2, "libqcbor_a", _balanced_shards(244, 8), [904.5] * 8)
    assert R.history_estimate(run2, "eva", "libqcbor_a:shard1") == math.ceil(1.25 * 10697 * R.EVA_SHARD_MEM_FLOOR_SHARE)

    # Once Run-2 records its own 4,780 MiB unsharded run (auto-tagged with H2), H1 is superseded completely.
    written = R.write_history(run2, {"class": "eva", "key": "libqcbor_a", "peak_mb": 4780, "oom_killed": False})
    assert written is not None
    assert json.loads(written.read_text(encoding="utf-8"))["harness_digest"] == h2
    assert R.history_estimate(run2, "eva", "libqcbor_a") == math.ceil(1.25 * 4780)
    assert R.history_estimate(run2, "eva", "libqcbor_a:shard1") == math.ceil(1.25 * 4780 * R.EVA_SHARD_MEM_FLOOR_SHARE)


@pytest.mark.unit
def test_legacy_untagged_shared_record_does_not_override_current_local_run(tmp_path, monkeypatch):
    """Upgrading onto a live run-2 whose shared cache holds an untagged run-1 record (10,697 MiB)."""
    shared = tmp_path / "shared-cache"
    shared_eva = shared / "resource-history" / "eva"
    shared_eva.mkdir(parents=True)
    (shared_eva / "20261122T232400000000Z-aaaa1111.json").write_text(
        json.dumps({"class": "eva", "key": "libqcbor_a", "peak_mb": 10697, "oom_killed": False}),
        encoding="utf-8",
    )
    monkeypatch.setenv("FRAMAC_SHARED_CACHE_DIR", str(shared))
    monkeypatch.setenv("FRAMAC_CACHE_MODE", "ro")

    run2 = tmp_path / "run-2"
    _write_harness(run2, "libqcbor_a", 244, extra="v2")
    _write_plan(run2, "libqcbor_a", _balanced_shards(244, 8), [904.5] * 8)
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
    assert R.history_estimate(run2, "eva", "libqcbor_a:shard1") == math.ceil(1.25 * 4780 * R.EVA_SHARD_MEM_FLOOR_SHARE)


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
    written = R.write_history(run1, {"class": "eva", "key": "m:shard0", "peak_mb": 9000, "oom_killed": False})
    assert written is not None
    assert json.loads(written.read_text(encoding="utf-8"))["shard_plan_digest"] == p1
    assert R.history_estimate(run1, "eva", "m:shard0") == math.ceil(1.25 * 9000)

    # Replanning to 8 shards invalidates the 2-shard exact and sibling records so shard0/shard1 use Tier 3.
    run2 = tmp_path / "run-2"
    _write_harness(run2, "m", 16, extra="v1")
    _write_plan(run2, "m", _balanced_shards(16, 8), [750.0] * 8)
    expected_t3 = math.ceil(1.25 * 10000 * R.EVA_SHARD_MEM_FLOOR_SHARE)
    assert R.history_estimate(run2, "eva", "m:shard0") == expected_t3
    assert R.history_estimate(run2, "eva", "m:shard1") == expected_t3

    # An OOM kill on shard0 under the new 8-shard plan doubles its peak for shard0 and its peers.
    R.write_history(run2, {"class": "eva", "key": "m:shard0", "peak_mb": 3500, "oom_killed": True})
    assert R.history_estimate(run2, "eva", "m:shard0") == 7000
    assert R.history_estimate(run2, "eva", "m:shard1") == 7000

    # A small harness edit that keeps the same 8-shard plan still reuses shard0's matching-plan measurement.
    _write_harness(run2, "m", 16, extra="v2-repaired")
    assert R.history_estimate(run2, "eva", "m:shard0") == 7000
    assert R.history_estimate(run2, "eva", "m:shard1") == 7000


@pytest.mark.unit
def test_shard_records_never_mask_unsharded_peaks_for_tuning_rungs(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    R.write_history(run, {"class": "eva", "key": "libqcbor_a", "peak_mb": 12630, "oom_killed": False})
    time.sleep(0.002)
    for i in range(8):
        R.write_history(run, {"class": "eva", "key": f"libqcbor_a:shard{i}", "peak_mb": 1200, "oom_killed": False})
        time.sleep(0.001)
    assert R.history_estimate(run, "eva", "libqcbor_a:slevel") == math.ceil(1.25 * 12630)


# ---------------------------------------------------------------------------
# 2. Live cgroup working-set admission (Layer 3)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_cgroup_current_mem_mb_subtracts_reclaimable_inactive_file(tmp_path):
    mib = 1024 * 1024
    # cgroup v2: 16,000 MiB memory.current with 1,350 MiB reclaimable inactive_file -> 14,650 MiB working set.
    v2 = tmp_path / "v2"
    cg2 = v2 / "sys/fs/cgroup"
    cg2.mkdir(parents=True)
    (cg2 / "cgroup.controllers").write_text("cpu memory\n", encoding="utf-8")
    (cg2 / "memory.current").write_text(str(16000 * mib) + "\n", encoding="utf-8")
    (cg2 / "memory.stat").write_text(f"anon {14000 * mib}\ninactive_file {1350 * mib}\n", encoding="utf-8")
    assert R.cgroup_current_mem_mb(v2) == 14650
    assert R.cgroup_stats(v2)["current_mb"] == 14650

    # Without memory.stat, falls back to raw memory.current.
    (cg2 / "memory.stat").unlink()
    assert R.cgroup_current_mem_mb(v2) == 16000

    # cgroup v1: usage_in_bytes minus total_inactive_file.
    v1 = tmp_path / "v1"
    cg1 = v1 / "sys/fs/cgroup/memory"
    cg1.mkdir(parents=True)
    (cg1 / "memory.usage_in_bytes").write_text(str(12000 * mib) + "\n", encoding="utf-8")
    (cg1 / "memory.stat").write_text(f"total_inactive_file {2000 * mib}\n", encoding="utf-8")
    assert R.cgroup_current_mem_mb(v1) == 10000


@pytest.mark.unit
def test_plan_grant_respects_live_cgroup_memory_without_deadlocking():
    # QCBOR run-2 snapshot: 5 running shards leased 5,264 + 4*2,048 = 13,456 MiB in a 17,408 MiB pool,
    # leaving 3,952 MiB by lease sum, but live working set is already 15,000 MiB (only 2,408 MiB free).
    running = [
        _ticket("111111111111", cls="eva", state="granted", cpus=1.0, mem_mb=5264),
        *(_ticket(f"{i}11111111111", cls="eva", state="granted", cpus=1.0, mem_mb=2048) for i in range(2, 6)),
    ]
    waiting = _ticket("aaaaaaaaaaaa", cls="eva", state="waiting", seq=10, floor=3585)
    # Without live_mem_mb, lease sum leaves 3,952 >= 3,585 -> would admit.
    assert R.plan_grant(waiting, [*running, waiting], POOL_CPUS, POOL_MEM_MB) is not None
    # With live_mem_mb=15000, free is 2,408 < 3,585 -> held back to prevent OOM!
    assert R.plan_grant(waiting, [*running, waiting], POOL_CPUS, POOL_MEM_MB, live_mem_mb=15000) is None
    # Once live memory drops to 13,000 MiB (max(13456, 13000) = 13456, free 3,952 >= 3,585) -> admitted.
    assert R.plan_grant(waiting, [*running, waiting], POOL_CPUS, POOL_MEM_MB, live_mem_mb=13000) is not None
    # Zero-deadlock invariant: when NO gated lease is running, even a high live_mem_mb never blocks the sole job.
    huge = _ticket("bbbbbbbbbbbb", cls="eva", state="waiting", seq=11, floor=POOL_MEM_MB)
    grant = R.plan_grant(huge, [huge], POOL_CPUS, POOL_MEM_MB, live_mem_mb=15000)
    assert grant is not None and grant.mem_mb == POOL_MEM_MB


# ---------------------------------------------------------------------------
# 3. Pool memory concurrency check (eva_shards.py + pipeline_make.py)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_estimate_shard_concurrency_and_memory_note():
    plan = {"k": 8, "predicted_shard_s": [904.5] * 8}

    sc_ok = es.estimate_shard_concurrency([2048] * 8, POOL_MEM_MB, pool_cpus=POOL_CPUS, predicted_shard_s=[904.5] * 8)
    assert sc_ok is not None and sc_ok.max_concurrent == 8 and not sc_ok.memory_limited
    assert es.memory_concurrency_note(plan, [2048] * 8, POOL_MEM_MB, POOL_CPUS) is None

    sc_ser = es.estimate_shard_concurrency([13372] * 8, POOL_MEM_MB, pool_cpus=POOL_CPUS, predicted_shard_s=[904.5] * 8)
    assert sc_ser is not None and sc_ser.max_concurrent == 1 and sc_ser.memory_limited
    assert sc_ser.scheduled_makespan_s == pytest.approx(8 * 904.5)
    note_ser = es.memory_concurrency_note(plan, [13372] * 8, POOL_MEM_MB, POOL_CPUS)
    assert note_ser is not None
    assert "only 1 of 8 shards fits in the 17408 MiB pool" in note_ser
    assert "in series" in note_ser and "7236.0 s wall time instead of 904.5 s in parallel" in note_ser

    # QCBOR run-2 cold-start: 8 shards at 3,585 MiB -> 4 at a time (2 waves, ~1809.0 s).
    note_wave = es.memory_concurrency_note(plan, [3585] * 8, POOL_MEM_MB, POOL_CPUS)
    assert note_wave is not None
    assert "at most 4 of 8 shards fit in the 17408 MiB pool" in note_wave
    assert "in waves" in note_wave and "1809.0 s wall time instead of 904.5 s in parallel" in note_wave

    # CPU-limited only: 16 shards at 2,048 MiB on 4 CPUs / 17,408 MiB -> not memory-limited.
    plan16 = {"k": 16, "predicted_shard_s": [500.0] * 16}
    assert es.memory_concurrency_note(plan16, [2048] * 16, POOL_MEM_MB, pool_cpus=4) is None

    note_clamp = es.memory_concurrency_note(plan, [20000] * 8, POOL_MEM_MB, POOL_CPUS)
    assert note_clamp is not None and "clamped to the pool" in note_clamp


@pytest.mark.unit
def test_pipeline_make_gen_warns_when_shards_wave_or_serialize_and_keeps_k_fixed(tmp_path, monkeypatch):
    # 100 equal cases -> choose_shard_count picks k=8.
    run = _sharded_run(tmp_path, cases=100)
    _single_run(run, 9000.0, [f"eva_main;snmp_call_{k} 100.0" for k in range(100)])
    # Host pool of 30 CPUs / 57,000 MiB -> phase-static nominal grant is 15 CPUs / 17,408 MiB.
    monkeypatch.setenv("FRAMAC_JOB_CLASS", "light")
    monkeypatch.setenv("FRAMAC_POOL_CPUS", "30")
    monkeypatch.setenv("FRAMAC_POOL_MEM_MB", "57000")

    # Small unsharded peak (2,500 MiB -> 0.6 * 1.25 * 2500 = 1,875 -> 2,048 MiB floor): all 8 fit, no warning.
    R.write_history(run, {"class": "eva", "key": "snmp", "peak_mb": 2500, "oom_killed": False})
    _, res = _mk(run)
    plan = json.loads((run / es.SHARD_DIR / "snmp" / "plan.json").read_text(encoding="utf-8"))
    k = plan["k"]
    assert k == 8
    assert not any("memory concurrency:" in w for w in res["warnings"]), res["warnings"]

    # QCBOR run-2 peak (4,780 MiB -> 3,585 MiB/shard): 4 of 8 fit -> accurate waves warning, k stays 8.
    R.write_history(run, {"class": "eva", "key": "snmp", "peak_mb": 4780, "oom_killed": False})
    _, res_wave = _mk(run)
    wave_warns = [w for w in res_wave["warnings"] if "memory concurrency:" in w]
    assert len(wave_warns) == 1
    assert "at most 4 of 8 shards fit in the 17408 MiB pool" in wave_warns[0]
    assert "in waves" in wave_warns[0]

    # Exact per-shard peak of 8,000 MiB (10,000 MiB with 1.25x): 1 of 8 fits -> serial warning, k still fixed at 8.
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
    meta = json.loads((run / "run-metadata.json").read_text(encoding="utf-8"))
    meta["resources"] = {"pool": {"cpus": 4, "mem_mb": 8192}}
    (run / "run-metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    monkeypatch.delenv("FRAMAC_JOB_CLASS", raising=False)
    monkeypatch.delenv("FRAMAC_POOL_CPUS", raising=False)
    monkeypatch.delenv("FRAMAC_POOL_MEM_MB", raising=False)
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
# 4. End-to-end container broker concurrency (real `resources.py run` processes)
# ---------------------------------------------------------------------------


@pytest.fixture
def shard_harness(tmp_path):
    h = Harness(tmp_path)
    yield h
    h.cleanup()


def _launch_shard(h: Harness, idx: int, hold: float, gate: Path | None) -> None:
    name = f"shard{idx}"
    cmd = [
        sys.executable,
        str(SCRIPT),
        "run",
        "--class",
        "eva",
        "--key",
        f"libqcbor_a:shard{idx}",
        "--",
        sys.executable,
        str(h.child),
        str(h.logs),
        name,
        str(hold),
        str(gate) if gate else "",
    ]
    with open(h.logs / f"{name}.broker.txt", "w", encoding="utf-8") as out:
        h.procs.append(subprocess.Popen(cmd, cwd=h.cwd, env=h.env, stdout=out, stderr=subprocess.STDOUT))
    h.names.append(name)


def test_qcbor_run2_cold_start_runs_4_shards_at_3585_mib_in_17408_mib_pool(shard_harness):
    """
    QCBOR run-2 cold start: shared cache has run-1's 10,697 MiB peak, run-2 has a 4,780 MiB unsharded
    peak and an 8-shard plan. Each shard leases 3,585 MiB (0.6 x 5,975), so 4 run concurrently (not 1
    serial and not 8 at 2,048 MiB) while the other 4 wait for a slot.
    """
    h = shard_harness
    h.set_pool(POOL_CPUS, POOL_MEM_MB)
    shared = h.tmp / "shared-cache"
    shared_eva = shared / "resource-history" / "eva"
    shared_eva.mkdir(parents=True)
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
        _launch_shard(h, i, hold=30.0, gate=gate)

    # Exactly 4 shards fit at 3,585 MiB each (4 * 3,585 = 14,340 <= 17,408; 5 * 3,585 = 17,925 > 17,408).
    wait_for(lambda: sum(h.record(f"shard{i}", "start") is not None for i in range(8)) == 4, timeout=20.0)
    wait_for(lambda: h.waiting() == 4, timeout=20.0)
    time.sleep(0.4)
    started_before_gate = [i for i in range(8) if h.record(f"shard{i}", "start") is not None]
    assert len(started_before_gate) == 4, h.output()
    for i in started_before_gate:
        assert h.record(f"shard{i}", "start")["mem"] == 3585, h.output()

    gate.write_text("go\n", encoding="utf-8")
    h.finish(timeout=20.0)
    assert all(p.returncode == 0 for p in h.procs), h.output()

    shard_recs = [
        json.loads(p.read_text(encoding="utf-8"))
        for p in sorted((h.cwd / R.HISTORY_DIR / "eva").glob("*.json"))
        if ":shard" in str(json.loads(p.read_text(encoding="utf-8")).get("key") or "")
    ]
    assert len(shard_recs) == 8
    for rec in shard_recs:
        assert rec.get("harness_digest") == h2
        assert rec.get("shard_plan_digest") == p2


def test_qcbor_run2_restart_with_shard1_measured_runs_3_shards_at_5264_mib(shard_harness):
    """
    Exact regression for the post-03523de symptom: shard1 already finished at 4,211 MiB (5,264 MiB).
    On restart, shards 2-7 must size from shard1's same-plan peer peak (5,264 MiB), admitting 3 at
    once (15,792 MiB) instead of 6 at 2,048 MiB.
    """
    h = shard_harness
    h.set_pool(POOL_CPUS, POOL_MEM_MB)
    (h.cwd / "run-metadata.json").write_text("{}", encoding="utf-8")
    _write_harness(h.cwd, "libqcbor_a", 244, extra="qcbor-run2")
    _write_plan(h.cwd, "libqcbor_a", _balanced_shards(244, 8), [904.5] * 8)
    R.write_history(h.cwd, {"class": "eva", "key": "libqcbor_a", "peak_mb": 4780, "oom_killed": False})
    R.write_history(h.cwd, {"class": "eva", "key": "libqcbor_a:shard1", "rc": 0, "peak_mb": 4211, "oom_killed": False})

    gate = h.tmp / "release.gate"
    for i in range(1, 7):
        _launch_shard(h, i, hold=30.0, gate=gate)

    # 3 * 5,264 = 15,792 <= 17,408; 4 * 5,264 = 21,056 > 17,408 -> exactly 3 admitted concurrently.
    wait_for(lambda: sum(h.record(f"shard{i}", "start") is not None for i in range(1, 7)) == 3, timeout=20.0)
    wait_for(lambda: h.waiting() == 3, timeout=20.0)
    time.sleep(0.4)
    started = [i for i in range(1, 7) if h.record(f"shard{i}", "start") is not None]
    assert len(started) == 3, h.output()
    for i in started:
        assert h.record(f"shard{i}", "start")["mem"] == 5264, h.output()

    gate.write_text("go\n", encoding="utf-8")
    h.finish(timeout=20.0)
    assert all(p.returncode == 0 for p in h.procs), h.output()


def test_waiting_shard_refreshes_demand_from_finished_sibling_and_respects_live_cgroup_mem(shard_harness):
    """
    End-to-end verification of Layers 1 + 3 together:
    - Live cgroup `memory.current` holds a second shard back while the container is near `memory.max`.
    - When a peer finishes and records a higher peak, a waiting shard refreshes its demand before grant.
    """
    h = shard_harness
    h.set_pool(POOL_CPUS, POOL_MEM_MB)
    mib = 1024 * 1024
    cg = h.root / "sys/fs/cgroup"
    mem_current = cg / "memory.current"
    mem_current.write_text(str(15000 * mib) + "\n", encoding="utf-8")

    (h.cwd / "run-metadata.json").write_text("{}", encoding="utf-8")
    _write_harness(h.cwd, "libqcbor_a", 244, extra="qcbor-run2")
    _write_plan(h.cwd, "libqcbor_a", _balanced_shards(244, 8), [904.5] * 8)
    R.write_history(h.cwd, {"class": "eva", "key": "libqcbor_a", "peak_mb": 4780, "oom_killed": False})

    # Start shard0 first: alone in the container, so live_mem_mb (15,000) does not deadlock it.
    gate0 = h.tmp / "gate0"
    _launch_shard(h, 0, hold=30.0, gate=gate0)
    wait_for(lambda: h.record("shard0", "start") is not None, timeout=15.0)
    assert h.record("shard0", "start")["mem"] == 3585

    # Launch shard2 while shard0 holds 3,585 MiB AND memory.current is 15,000 MiB (only 2,408 MiB free):
    # shard2 needs 3,585 MiB so live cgroup accounting must hold it back even though 17,408 - 3,585 = 13,823!
    _launch_shard(h, 2, hold=0.05, gate=None)
    wait_for(lambda: h.waiting() == 1, timeout=15.0)
    time.sleep(0.5)
    assert h.record("shard2", "start") is None, h.output()
    assert "15000 MiB live" in h.output()

    # Simulate shard1 completing and recording a real 4,211 MiB peak (5,264 MiB), then release shard0
    # and lower memory.current: shard2 must refresh its demand to 5,264 MiB before starting.
    R.write_history(h.cwd, {"class": "eva", "key": "libqcbor_a:shard1", "rc": 0, "peak_mb": 4211, "oom_killed": False})
    mem_current.write_text(str(500 * mib) + "\n", encoding="utf-8")
    gate0.write_text("go\n", encoding="utf-8")
    h.finish(timeout=20.0)
    assert all(p.returncode == 0 for p in h.procs), h.output()
    assert h.record("shard2", "end")["mem"] == 5264, h.output()
