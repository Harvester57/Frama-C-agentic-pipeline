"""End-to-end unit tests for P5 verifier circuit breaker, probe batching, fast repair, and supersession."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

import ledger as L
import phase0_gates
import wp_scheduler as S
from conftest import write_json
from test_wp_scheduler import Sim, ids, load, tasks

pytestmark = pytest.mark.unit


@pytest.fixture
def sim(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Sim:
    # Default all new flags off unless a test explicitly enables them.
    monkeypatch.delenv("FRAMAC_VERIFIER_BREAKER", raising=False)
    monkeypatch.delenv("FRAMAC_HARNESS_SMOKE", raising=False)
    monkeypatch.delenv("FRAMAC_FUZZ_EXPLORE_JUDGE", raising=False)
    return Sim(run_dir, monkeypatch)


def _write_sudo_harness(sim: Sim, module: str = "sudoers", body: str = "int fuzz_v1(void) { return 0; }\n") -> str:
    hdir = sim.run_dir / "workspace" / "harnesses"
    hdir.mkdir(parents=True, exist_ok=True)
    (hdir / f"harness_{module}.c").write_text(body, encoding="utf-8")
    digest = phase0_gates.harness_digest(sim.run_dir, module, ignore_exempt=True)
    assert digest is not None
    return digest


def _make_fuzz_candidate(
    sim: Sim,
    module: str,
    idx: int,
    *,
    status: str = "unverified",
    kind: str = "ubsan_runtime_error",
    prop_kind: str = "mem_access",
    predicate: str = "rte: mem_access: member access within null pointer of type 'struct sudo_user'",
    payload: bytes = b"\x00\x01",
    flat_kind: str | None = None,
) -> dict[str, Any]:
    fn = f"fn_{idx:02d}"
    file_path = f"src/{module}/{fn}.c"
    fp = f"{file_path}#{fn}::{prop_kind}::{idx + 1:010x}"
    crash_rel = f"workspace/crashes/{module}/crash-{idx:02d}"
    crash_abs = sim.run_dir / crash_rel
    crash_abs.parent.mkdir(parents=True, exist_ok=True)
    crash_abs.write_bytes(payload)
    sha = hashlib.sha256(payload).hexdigest()
    # Pre-seed a replay report so _parent_replay does not spawn a subprocess in unit tests.
    write_json(
        sim.run_dir / f"workspace/reports/replay/{S._fp_slug(fp)}.json",
        {
            "candidate_fingerprint": fp,
            "status": "reproduced",
            "fingerprint_matches": True,
            "artifacts": [{"path": crash_rel, "sha256": sha, "reproducible": True}],
        },
    )
    fuzz_out = f"workspace/reports/fuzz/{module}.json"
    cand: dict[str, Any] = {
        "fingerprint": fp,
        "status": status,
        "origin": "fuzz",
        "proposed_verdict": "confirmed",
        "module": module,
        "location": {"file": file_path, "line": 10 + idx, "function": fn},
        "property": {"kind": prop_kind, "predicate": predicate},
        "reproducers": [crash_rel],
        "tool_outputs": [fuzz_out],
        "linked_units": [f"{file_path}#{fn}::rte"],
        "first_seen": "2026-11-22T12:00:00Z",
        "observations": [
            {
                "fingerprint": fp,
                "origin": "fuzz",
                "engine": "ubsan",
                "kind": kind,
                "message": predicate,
                "tool_output": fuzz_out,
                "reproducer": crash_rel,
            }
        ],
    }
    if flat_kind is not None:
        cand["kind"] = flat_kind
    return cand


def _seed_sudo_module(
    sim: Sim,
    n_candidates: int = 38,
    *,
    module: str = "sudoers",
    with_eva_report: bool = False,
) -> tuple[str, list[dict[str, Any]]]:
    fns: dict[str, tuple[str, str, list[str]]] = {
        f"fn_{i:02d}": (f"src/{module}/fn_{i:02d}.c", module, [])
        for i in range(max(n_candidates, 2))
    }
    sim.build(fns, sidecars={module: {"entry_style": "dispatch", "dispatch_case_count": 4}})
    digest = _write_sudo_harness(sim, module)
    write_json(
        sim.run_dir / f"workspace/reports/fuzz/{module}.json",
        {"status": "ok", "module": module, "harness_digest": digest},
    )
    cands = [_make_fuzz_candidate(sim, module, i) for i in range(n_candidates)]
    write_json(sim.run_dir / "candidates.json", cands)
    if with_eva_report:
        write_json(
            sim.run_dir / f"workspace/reports/eva/{module}.json",
            {
                "status": "ok",
                "module": module,
                "harness_digest": digest,
                "unknown_obligations_by_function": {},
                "invalid_alarms": [],
                "dead_alarms": [],
                "assumed_properties": [],
                "functions_with_properties": [],
            },
        )
    return digest, cands


def _complete_verifier_as(
    sim: Sim,
    task_desc: dict[str, Any],
    decision: str,
    *,
    rejection_class: str = "harness_induced",
) -> dict[str, Any]:
    aid = str(task_desc["agent_id"])
    fp = str(task_desc["fingerprint"])
    result_path = Path(f"agents/{aid}/scratch/result.json")
    L.cmd_scaffold_verifier(fp, decision, aid, out_path=result_path)
    res = load(result_path)
    if decision == "rejected":
        res["record"]["rejection_class"] = rejection_class
        if rejection_class == "toolchain_artifact":
            res["record"]["refutation_basis"] = "located"
    elif decision == "confirmed":
        # Provide a parent replay matching the candidate's crash artifact so ledger.cmd_ingest_verifier
        # confirms the finding cleanly without spawning a subprocess.
        cands_by_fp = {c["fingerprint"]: c for c in load("candidates.json")}
        rep_rel = (cands_by_fp[fp].get("reproducers") or [None])[0]
        assert isinstance(rep_rel, str)
        raw = (sim.run_dir / rep_rel).read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        write_json(
            sim.run_dir / f"workspace/reports/replay/{S._fp_slug(fp)}.json",
            {
                "candidate_fingerprint": fp,
                "status": "reproduced",
                "fingerprint_matches": True,
                "artifacts": [{"path": rep_rel, "sha256": sha, "reproducible": True}],
            },
        )
        res["record"]["reproducers"] = [
            {
                "input": rep_rel,
                "sha256": sha,
                "size_bytes": len(raw),
                "command": f"run_eacsl_fuzz.py replay --inputs {rep_rel}",
                "observed_result": "mem_access: null pointer dereference",
            }
        ]
    write_json(result_path, res)
    return S.cmd_complete(aid)


# ---------------------------------------------------------------------------
# 1. Backwards compatibility when FRAMAC_VERIFIER_BREAKER=off
# ---------------------------------------------------------------------------


def test_breaker_off_preserves_legacy_fanout(sim: Sim) -> None:
    _seed_sudo_module(sim, n_candidates=38)
    S.cmd_init()

    nxt = S.cmd_next("auto", prepare=True)
    # Default max_agents=8: legacy fan-out fills all 8 slots immediately.
    assert len(nxt["tasks"]) == 8
    assert all(t["kind"] == "verify" for t in nxt["tasks"])

    # Two harness_induced rejections do NOT pause remaining 30 pending verify tasks when flag is off.
    out1 = _complete_verifier_as(sim, nxt["tasks"][0], "rejected", rejection_class="harness_induced")
    out2 = _complete_verifier_as(sim, nxt["tasks"][1], "rejected", rejection_class="harness_induced")
    assert "circuit_breaker" not in out1
    assert "circuit_breaker" not in out2
    sched = load("state/wp_schedule.json")
    assert not sched.get("breaker_tripped")
    assert all(t["state"] != "paused_by_breaker" for t in sched["tasks"].values())
    # repair:sudoers is created, but still waits on all 38 verifiers (not ready yet).
    assert sched["tasks"]["repair:sudoers"]["state"] == "pending"
    assert S.cmd_next("auto", prepare=True)["parent_tasks"] == []


# ---------------------------------------------------------------------------
# 2. End-to-end 38-candidate sudo-shaped module with FRAMAC_VERIFIER_BREAKER=on
# ---------------------------------------------------------------------------


def test_sudo_38_candidates_probe_trip_fast_repair_and_supersede(
    sim: Sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FRAMAC_VERIFIER_BREAKER", "on")
    old_digest, _cands = _seed_sudo_module(sim, n_candidates=38, with_eva_report=False)
    S.cmd_init()

    # Step 1: Only 2 probe verifiers dispatch initially despite 8 available slots.
    nxt1 = S.cmd_next("auto", prepare=True)
    assert len(nxt1["tasks"]) == 2
    assert nxt1["parent_tasks"] == []
    probe1, probe2 = nxt1["tasks"]

    # While both probes are running, zero additional verifiers dispatch for sudoers.
    nxt_mid = S.cmd_next("auto", prepare=True)
    assert nxt_mid["tasks"] == []
    assert nxt_mid["parent_tasks"] == []

    # Step 2: Probe 1 returns harness_induced (1/1 < min_harness_induced=2) -> does NOT trip yet.
    c1 = _complete_verifier_as(sim, probe1, "rejected", rejection_class="harness_induced")
    assert c1["decision"] == "rejected"
    assert "circuit_breaker" not in c1
    assert not load("state/wp_schedule.json").get("breaker_tripped")
    # Still waiting on probe 2 before dispatching more verifiers or repair.
    nxt_wait = S.cmd_next("auto", prepare=True)
    assert nxt_wait["tasks"] == []
    assert nxt_wait["parent_tasks"] == []

    # Step 3: Probe 2 returns harness_induced (2/2 = 100%) -> trips breaker IMMEDIATELY!
    c2 = _complete_verifier_as(sim, probe2, "rejected", rejection_class="harness_induced")
    assert c2["decision"] == "rejected"
    assert c2["circuit_breaker"]["ratio"] == pytest.approx(1.0)
    assert c2["circuit_breaker"]["harness_induced"] == 2
    assert c2["circuit_breaker"]["verified"] == 2
    assert len(c2["circuit_breaker"]["paused_tasks"]) == 36

    sched = load("state/wp_schedule.json")
    tripped = sched["breaker_tripped"]["sudoers"]
    assert tripped["ratio"] == pytest.approx(1.0)
    assert tripped["harness_induced"] == 2
    assert tripped["verified"] == 2
    assert set(tripped["probe_fingerprints"]) == {probe1["fingerprint"], probe2["fingerprint"]}

    paused = [t for t in sched["tasks"].values() if t["kind"] == "verify" and t["state"] == "paused_by_breaker"]
    assert len(paused) == 36
    # None of the 36 paused verifiers were ever dispatched.
    assert all(t["dispatches"] == 0 for t in paused)
    for t in paused:
        assert "2/2" in str(t["last_reason"])
        assert probe1["fingerprint"] in str(t["last_reason"]) or probe2["fingerprint"] in str(t["last_reason"])

    # Step 4: repair:sudoers is READY IMMEDIATELY (deps == [], not waiting on paused tasks).
    assert sched["tasks"]["repair:sudoers"]["deps"] == []
    nxt_rep = S.cmd_next("auto", prepare=True)
    assert nxt_rep["tasks"] == []
    assert [p["task"] for p in nxt_rep["parent_tasks"]] == ["repair:sudoers"]
    actions = nxt_rep["parent_tasks"][0]["actions"]
    assert any("pipeline_make.py run reach-gate" in a for a in actions)
    assert any("pipeline_make.py run build-sudoers" in a for a in actions)
    assert any("pipeline_make.py run fuzz-sudoers" in a for a in actions)
    assert not any("pipeline_make.py run module-sudoers" in a for a in actions)

    # Step 5: Repair harness (new harness_digest); refresh with old fuzz report refuses and does NOT supersede yet.
    new_digest = _write_sudo_harness(sim, "sudoers", "int fuzz_v2_fixed(void) { return 0; }\n")
    assert new_digest != old_digest
    ref_stale = S.cmd_refresh("sudoers")
    assert ref_stale["ok"] is False
    assert ref_stale["repair"] == "stale_evidence"
    assert "fuzz-sudoers" in ref_stale["targets"]
    assert "eva-sudoers" not in ref_stale["targets"]  # fast fuzz-only: no Eva report on disk
    assert load("state/wp_schedule.json")["breaker_tripped"].get("sudoers") is not None

    # Step 6: Write fresh fuzz report with new harness_digest -> refresh supersedes all 36!
    write_json(
        sim.run_dir / "workspace/reports/fuzz/sudoers.json",
        {"status": "ok", "module": "sudoers", "harness_digest": new_digest},
    )

    supersede_calls: list[tuple[Path, str, str | None, str]] = []
    real_supersede = S._supersede_ledger_candidates

    def _spy_supersede(run_dir: Path, mod: str, old_dig: str | None, reason: str) -> dict[str, Any]:
        supersede_calls.append((run_dir, mod, old_dig, reason))
        return real_supersede(run_dir, mod, old_dig, reason)

    monkeypatch.setattr(S, "_supersede_ledger_candidates", _spy_supersede)

    ref_ok = S.cmd_refresh("sudoers")
    assert ref_ok["ok"] is True
    assert ref_ok["repair"] == "done"
    assert len(ref_ok["superseded_tasks"]) == 36
    assert ref_ok["breaker_cleared"] == ["sudoers"]
    # Default soft-fail when Wave 3 ledger subcommand is not wired yet:
    assert ref_ok["ledger_supersede"]["sudoers"]["ok"] is True
    assert len(supersede_calls) == 1
    assert supersede_calls[0][1] == "sudoers"
    assert supersede_calls[0][2] == old_digest

    sched_after = load("state/wp_schedule.json")
    assert "sudoers" not in (sched_after.get("breaker_tripped") or {})
    superseded_done = [
        t
        for t in sched_after["tasks"].values()
        if t["kind"] == "verify" and t["state"] == "done" and t["outcome"] == "superseded_by_repair"
    ]
    assert len(superseded_done) == 36
    # Calling _sync again never reopens the superseded tasks.
    assert S.cmd_status()["gates"]["gate:sudoers"]["open"] is True


# ---------------------------------------------------------------------------
# 3. _describe_repair action variants (fast fuzz-only vs existing Eva report)
# ---------------------------------------------------------------------------


def test_describe_repair_fast_fuzz_only_vs_existing_eva_report(
    sim: Sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_sudo_module(sim, n_candidates=4, with_eva_report=False)
    repair_task = {"id": "repair:sudoers", "kind": "repair", "module": "sudoers", "reasons": ["harness_induced: fp1"]}

    # Flags off: legacy module-sudoers.
    actions_off = S._describe_repair(repair_task)["actions"]
    assert any(a.endswith("pipeline_make.py run module-sudoers") for a in actions_off)
    assert not any("build-sudoers" in a for a in actions_off)

    # Breaker on + smoke on + explore/judge on, NO Eva report on disk:
    monkeypatch.setenv("FRAMAC_VERIFIER_BREAKER", "on")
    monkeypatch.setenv("FRAMAC_HARNESS_SMOKE", "on")
    monkeypatch.setenv("FRAMAC_FUZZ_EXPLORE_JUDGE", "on")
    actions_fast = S._describe_repair(repair_task)["actions"]
    idx_reach = next(i for i, a in enumerate(actions_fast) if a.endswith("pipeline_make.py run reach-gate"))
    idx_build = next(i for i, a in enumerate(actions_fast) if a.endswith("pipeline_make.py run build-sudoers"))
    idx_smoke = next(i for i, a in enumerate(actions_fast) if a.endswith("pipeline_make.py run smoke-sudoers"))
    idx_fuzz = next(i for i, a in enumerate(actions_fast) if a.endswith("pipeline_make.py run fuzz-sudoers"))
    idx_judge = next(i for i, a in enumerate(actions_fast) if a.endswith("pipeline_make.py run judge-sudoers"))
    assert idx_reach < idx_build < idx_smoke < idx_fuzz < idx_judge
    assert not any("module-sudoers" in a for a in actions_fast)

    # Now place an existing Eva report on disk -> must keep module-sudoers!
    write_json(
        sim.run_dir / "workspace/reports/eva/sudoers.json",
        {"status": "ok", "module": "sudoers", "harness_digest": "0" * 64},
    )
    actions_with_eva = S._describe_repair(repair_task)["actions"]
    assert any(a.endswith("pipeline_make.py run module-sudoers") for a in actions_with_eva)
    assert not any("build-sudoers" in a for a in actions_with_eva)


# ---------------------------------------------------------------------------
# 4. Preserving confirmed findings & waiting only on running verifiers
# ---------------------------------------------------------------------------


def test_breaker_waits_only_on_running_verifiers_and_preserves_confirmed_findings(
    sim: Sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FRAMAC_VERIFIER_BREAKER", "on")
    old_digest, _cands = _seed_sudo_module(sim, n_candidates=10, with_eva_report=False)
    S.cmd_init()

    # Probe 1 -> confirmed (real bug!), Probe 2 -> harness_induced (1/2 = 50%, does not trip yet).
    nxt1 = S.cmd_next("auto", prepare=True)
    assert len(nxt1["tasks"]) == 2
    p1, p2 = nxt1["tasks"]
    c1 = _complete_verifier_as(sim, p1, "confirmed")
    assert c1["decision"] == "confirmed"
    c2 = _complete_verifier_as(sim, p2, "rejected", rejection_class="harness_induced")
    assert c2["decision"] == "rejected"
    assert "circuit_breaker" not in c2

    # Confirmed finding is recorded in findings.json.
    findings_before = load("findings.json")
    confirmed_before = [f for f in findings_before if f.get("verdict") == "confirmed"]
    assert len(confirmed_before) == 1
    assert confirmed_before[0]["fingerprint"] == p1["fingerprint"]

    # After 2 completed probes without tripping, remaining candidates release; dispatch 2 more (p3, p4).
    nxt2 = S.cmd_next("2", prepare=True)
    assert len(nxt2["tasks"]) == 2
    p3, p4 = nxt2["tasks"]

    # p3 returns harness_induced -> 2/3 (66.7%) >= 2/3 -> trips breaker while p4 is STILL RUNNING!
    c3 = _complete_verifier_as(sim, p3, "rejected", rejection_class="harness_induced")
    assert c3["circuit_breaker"]["harness_induced"] == 2
    assert c3["circuit_breaker"]["verified"] == 3
    assert len(c3["circuit_breaker"]["paused_tasks"]) == 6  # 10 total - 3 done - 1 running = 6 paused

    # repair:sudoers must wait ONLY on p4 (running), NOT on the 6 paused tasks!
    sched_mid = load("state/wp_schedule.json")
    assert sched_mid["tasks"]["repair:sudoers"]["deps"] == [p4["task"]]
    assert S.cmd_next("auto", prepare=True)["parent_tasks"] == []

    # Once p4 finishes, repair:sudoers becomes ready IMMEDIATELY!
    _complete_verifier_as(sim, p4, "rejected", rejection_class="harness_induced")
    nxt_rep = S.cmd_next("auto", prepare=True)
    assert [p["task"] for p in nxt_rep["parent_tasks"]] == ["repair:sudoers"]
    assert nxt_rep["tasks"] == []

    # Repair harness & refresh: 6 paused tasks superseded, confirmed finding UNTOUCHED!
    new_digest = _write_sudo_harness(sim, "sudoers", "int fuzz_v2(void) { return 1; }\n")
    assert new_digest != old_digest
    write_json(
        sim.run_dir / "workspace/reports/fuzz/sudoers.json",
        {"status": "ok", "module": "sudoers", "harness_digest": new_digest},
    )
    ref = S.cmd_refresh("sudoers")
    assert ref["ok"] is True
    assert ref["repair"] == "done"
    assert len(ref["superseded_tasks"]) == 6

    sched_after = load("state/wp_schedule.json")
    # The confirmed verify task was NEVER superseded or altered!
    assert sched_after["tasks"][p1["task"]]["state"] == "done"
    assert sched_after["tasks"][p1["task"]]["outcome"] == "confirmed"
    # findings.json still holds the confirmed finding untouched!
    findings_after = load("findings.json")
    confirmed_after = [f for f in findings_after if f.get("verdict") == "confirmed"]
    assert confirmed_after == confirmed_before


# ---------------------------------------------------------------------------
# 5. Real-bug control module (2/2 probes confirmed) & small module passthrough
# ---------------------------------------------------------------------------


def test_real_bug_control_2_of_2_confirmed_releases_all_remaining(
    sim: Sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FRAMAC_VERIFIER_BREAKER", "on")
    _seed_sudo_module(sim, n_candidates=38, with_eva_report=False)
    S.cmd_init()

    # Initial probe batch: only 2 probes dispatch.
    nxt1 = S.cmd_next("auto", prepare=True)
    assert len(nxt1["tasks"]) == 2
    p1, p2 = nxt1["tasks"]

    # Both probes return confirmed -> breaker does NOT trip!
    assert _complete_verifier_as(sim, p1, "confirmed")["decision"] == "confirmed"
    assert _complete_verifier_as(sim, p2, "confirmed")["decision"] == "confirmed"
    sched = load("state/wp_schedule.json")
    assert not sched.get("breaker_tripped")
    assert "repair:sudoers" not in sched["tasks"]

    # All 36 remaining candidates are now ready for full parallel verification!
    st = S.cmd_status()
    ready_verify = [r for r in st["ready"] if r["kind"] == "verify"]
    assert len(ready_verify) == 36
    nxt2 = S.cmd_next("auto", prepare=True)
    assert len(nxt2["tasks"]) == 8


def test_small_module_at_most_3_candidates_dispatches_all_immediately(
    sim: Sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FRAMAC_VERIFIER_BREAKER", "on")
    _seed_sudo_module(sim, n_candidates=3, with_eva_report=False)
    S.cmd_init()

    nxt = S.cmd_next("auto", prepare=True)
    assert len(nxt["tasks"]) == 3


# ---------------------------------------------------------------------------
# 6. Startup & smoke candidate exclusion in _sync
# ---------------------------------------------------------------------------


def test_sync_excludes_startup_quarantined_and_superseded_candidates(sim: Sim) -> None:
    _digest, _ = _seed_sudo_module(sim, n_candidates=0, with_eva_report=False)
    cands = [
        # Excluded: flat kind == toolchain_startup_error
        _make_fuzz_candidate(sim, "sudoers", 0, flat_kind="toolchain_startup_error"),
        # Excluded: nested property.kind == toolchain_startup_error
        _make_fuzz_candidate(sim, "sudoers", 1, kind="runtime_error", prop_kind="toolchain_startup_error"),
        # Excluded: status == quarantined_by_smoke
        _make_fuzz_candidate(sim, "sudoers", 2, status="quarantined_by_smoke"),
        # Excluded: status == superseded_by_repair
        _make_fuzz_candidate(sim, "sudoers", 3, status="superseded_by_repair"),
        # Included: normal unverified candidate
        _make_fuzz_candidate(sim, "sudoers", 4, status="unverified"),
    ]
    write_json(sim.run_dir / "candidates.json", cands)

    S.cmd_init()
    tmap = tasks()
    verify_tids = sorted(tid for tid, t in tmap.items() if t["kind"] == "verify")
    assert verify_tids == [f"verify:{cands[4]['fingerprint']}"]

    # If the remaining candidate later becomes quarantined_by_smoke, _sync closes its pending task cleanly.
    cands[4]["status"] = "quarantined_by_smoke"
    write_json(sim.run_dir / "candidates.json", cands)
    S.cmd_refresh()
    tmap_after = tasks()
    closed = tmap_after[f"verify:{cands[4]['fingerprint']}"]
    assert closed["state"] == "done"
    assert closed["outcome"] == "quarantined_by_smoke"
    assert ids(S.cmd_next("auto", prepare=True)) != [f"verify:{cands[4]['fingerprint']}"]


def test_supersede_ledger_candidates_helper_handles_present_and_absent_subcommand(
    sim: Sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without Wave 3's ledger subcommand wired yet: fails soft cleanly with ok=True, supported=False.
    res_soft = S._supersede_ledger_candidates(sim.run_dir, "sudoers", "a" * 64, "repaired")
    assert res_soft["ok"] is True
    assert res_soft["supported"] is False

    # When ledger.cmd_supersede_candidates is wired: delegates cleanly with matching kwargs.
    seen: list[dict[str, Any]] = []

    def _fake_cmd_supersede(*, module: str, old_harness_digest: str | None, reason: str) -> dict[str, Any]:
        seen.append({"module": module, "old_harness_digest": old_harness_digest, "reason": reason})
        return {"superseded": 36}

    monkeypatch.setattr(L, "cmd_supersede_candidates", _fake_cmd_supersede, raising=False)
    res_wired = S._supersede_ledger_candidates(sim.run_dir, "sudoers", "b" * 64, "repaired")
    assert res_wired == {"ok": True, "supported": True, "result": {"superseded": 36}}
    assert seen == [{"module": "sudoers", "old_harness_digest": "b" * 64, "reason": "repaired"}]


def test_post_repair_new_candidates_start_with_clean_breaker_generation(
    sim: Sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FRAMAC_VERIFIER_BREAKER", "on")
    old_digest, cands = _seed_sudo_module(sim, n_candidates=6, with_eva_report=False)
    S.cmd_init()

    # Trip breaker on generation 1 (2/2 harness_induced).
    p1, p2 = S.cmd_next("auto", prepare=True)["tasks"]
    _complete_verifier_as(sim, p1, "rejected", rejection_class="harness_induced")
    c2 = _complete_verifier_as(sim, p2, "rejected", rejection_class="harness_induced")
    assert c2["circuit_breaker"]["verified"] == 2
    assert S.cmd_next("auto", prepare=True)["parent_tasks"][0]["task"] == "repair:sudoers"

    # Repair harness and refresh: 4 paused tasks superseded, breaker cleared.
    new_digest = _write_sudo_harness(sim, "sudoers", "int fuzz_gen2(void) { return 2; }\n")
    assert new_digest != old_digest
    write_json(
        sim.run_dir / "workspace/reports/fuzz/sudoers.json",
        {"status": "ok", "module": "sudoers", "harness_digest": new_digest},
    )
    ref = S.cmd_refresh("sudoers")
    assert ref["ok"] is True
    assert ref["breaker_cleared"] == ["sudoers"]

    # Generation 2 introduces 2 new candidates (<= 3): old-generation harness_induced verdicts
    # must NOT leak into generation 2 or re-trip the breaker on a single rejection.
    new_cand_a = _make_fuzz_candidate(sim, "sudoers", 20, prop_kind="index_bound")
    new_cand_b = _make_fuzz_candidate(sim, "sudoers", 21, prop_kind="signed_overflow")
    write_json(sim.run_dir / "candidates.json", [*cands, new_cand_a, new_cand_b])

    nxt_gen2 = S.cmd_next("auto", prepare=True)
    gen2_verify = [t for t in nxt_gen2["tasks"] if t["kind"] == "verify"]
    assert {t["fingerprint"] for t in gen2_verify} == {new_cand_a["fingerprint"], new_cand_b["fingerprint"]}

    # 1 harness_induced in generation 2 is only 1/1 (not 3/3!), so breaker must NOT trip.
    out_gen2 = _complete_verifier_as(sim, gen2_verify[0], "rejected", rejection_class="harness_induced")
    assert "circuit_breaker" not in out_gen2
    assert not (load("state/wp_schedule.json").get("breaker_tripped") or {}).get("sudoers")

