"""Phase-3 scheduler fixes from the QCBOR run-6 review: breaker slots, stale repair evidence, contract-less callees."""

from __future__ import annotations

import os
from pathlib import Path

import function_facts
import ledger as L
import phase0_gates
import test_wp_scheduler as base
import wp_scheduler as S
from conftest import write_json
from test_wp_scheduler import Sim, ids, tasks

sim = base.sim  # the shared fixture


# ---------------------------------------------------------------------------
# Item 1: breakers get reserved slots
# ---------------------------------------------------------------------------


def _stalled_breaker_and_tall_provers(sim: Sim) -> None:
    sim.build(
        {
            "f": ("src/m/f.c", "m", []),
            "h": ("src/m/h.c", "m", ["f"]),
            "p": ("src/m/p.c", "m", []),
            "p1": ("src/m/p1.c", "m", ["p"]),
            "q": ("src/m/q.c", "m", []),
            "q1": ("src/m/q1.c", "m", ["q"]),
        },
        sidecars={"m": {}},
    )
    S.cmd_init()
    assert ids(S.cmd_next("1", prepare=True)) == ["prove:src/m/f.c#f"]
    sim.prover("prove-f", "f", "src/m/f.c", status="stalled_after_k_retries")
    assert "breaker:src/m/f.c#f" in S.cmd_complete("prove-f")["new_tasks"]


def test_a_ready_breaker_gets_a_reserved_slot_ahead_of_taller_provers(sim):
    _stalled_breaker_and_tall_provers(sim)
    t = tasks()
    assert t["prove:src/m/p.c#p"]["height"] > 0 and t["prove:src/m/q.c#q"]["height"] > 0
    assert int(t["breaker:src/m/f.c#f"]["height"] or 0) == 0
    picked = ids(S.cmd_next("2"))
    assert len(picked) == 2 and "breaker:src/m/f.c#f" in picked
    # The other slot keeps the normal order: the negotiation h waits on (f has no contract), then p.
    assert [p for p in picked if not p.startswith("breaker:")] == ["negotiate:src/m/f.c#f"]


def test_without_a_ready_breaker_the_order_is_unchanged(sim):
    sim.build(
        {
            "p": ("src/m/p.c", "m", []),
            "p1": ("src/m/p1.c", "m", ["p"]),
            "q": ("src/m/q.c", "m", []),
            "r": ("src/m/r.c", "m", []),
        }
    )
    S.cmd_init()
    assert ids(S.cmd_next("2")) == ["prove:src/m/p.c#p", "prove:src/m/q.c#q"]


# ---------------------------------------------------------------------------
# Item 2: refresh refuses to close a repair on evidence from the pre-repair harness
# ---------------------------------------------------------------------------


def _open_repair(sim: Sim) -> None:
    """repair:m dispatched to the parent after a harness_induced rejection; the harness was then edited."""
    sim.build({"f": ("src/m/f.c", "m", []), "h": ("src/m/h.c", "m", [])}, sidecars={"m": {}})
    fp = sim.eva_candidate("m", "src/m/f.c", "f")
    S.cmd_init()
    ver = S.cmd_next("auto", prepare=True)["tasks"][0]
    L.cmd_scaffold_verifier(
        fp, "rejected", ver["agent_id"], out_path=Path(f"agents/{ver['agent_id']}/scratch/result.json")
    )
    assert "repair:m" in S.cmd_complete(ver["agent_id"])["new_tasks"]
    assert [p["task"] for p in S.cmd_next("auto", prepare=True)["parent_tasks"]] == ["repair:m"]
    harness = sim.run_dir / "workspace/harnesses/harness_m.c"
    harness.write_text("int eva_main(void) { return 0; } /* repaired */\n", encoding="utf-8")
    for path in (harness, harness.with_suffix(".json")):
        os.utime(path, (1_000_000, 1_000_000))


def _digest() -> str:
    digest = phase0_gates.harness_digest(Path("."), "m", ignore_exempt=True)
    assert digest
    return digest


def _report(kind: str, digest: str | None, mtime: float = 2_000_000, **extra) -> Path:
    path = Path(f"workspace/reports/{kind}/m.json")
    data: dict = {"status": "ok", "module": "m", **extra}
    if kind == "eva":
        data.update(unknown_obligations_by_function={}, invalid_alarms=[], dead_alarms=[])
    if digest is not None:
        data["harness_digest"] = digest
    write_json(path, data)
    os.utime(path, (mtime, mtime))
    return path


def _facts(mtime: float = 2_000_100) -> None:
    path = Path("workspace/reports/facts/m.json")
    write_json(path, {"module": "m", "functions": {}})
    os.utime(path, (mtime, mtime))


def test_refresh_keeps_the_repair_open_when_the_eva_report_is_from_the_old_harness(sim):
    _open_repair(sim)
    _report("fuzz", _digest(), dispatch_case_count=3)
    _report("eva", "0" * 64)
    _facts()
    out = S.cmd_refresh("m")
    assert out["repair"] == "stale_evidence" and out["ok"] is False
    assert out["targets"] == ["eva-m", "facts-m"]
    assert [s["report"] for s in out["stale_evidence"]] == ["workspace/reports/eva/m.json"]
    assert tasks()["repair:m"]["state"] == "running"
    assert ids(S.cmd_next("auto", prepare=True)) == []  # the gate stays closed


def test_refresh_names_fuzz_and_facts_when_their_reports_are_missing_or_older(sim):
    _open_repair(sim)
    _report("eva", _digest(), mtime=2_000_000)
    _facts(mtime=1_500_000)  # facts from before the Eva re-run
    out = S.cmd_refresh("m")
    assert out["repair"] == "stale_evidence" and out["targets"] == ["fuzz-m", "facts-m"]


def test_refresh_closes_the_repair_when_fuzz_and_eva_ran_on_the_repaired_harness(sim):
    _open_repair(sim)
    _report("fuzz", _digest(), dispatch_case_count=3)
    _report("eva", _digest())
    _facts()
    out = S.cmd_refresh("m")
    assert out["repair"] == "done" and out["ok"] is True
    assert tasks()["repair:m"]["state"] == "done"
    assert sorted(ids(S.cmd_next("auto", prepare=True))) == ["prove:src/m/f.c#f", "prove:src/m/h.c#h"]


def test_refresh_accepts_legacy_reports_without_the_field_only_when_newer_than_the_harness(sim):
    _open_repair(sim)
    _report("fuzz", None, mtime=500_000)  # older than the repaired harness: stale
    _report("eva", None, mtime=2_000_000)  # written after the repair, before the field existed
    _facts()
    out = S.cmd_refresh("m")
    assert out["repair"] == "stale_evidence" and out["targets"] == ["fuzz-m"]
    _report("fuzz", None, mtime=2_000_000)
    assert S.cmd_refresh("m")["repair"] == "done"


def test_the_repair_actions_say_refresh_waits_for_eva_and_fuzz(sim):
    _open_repair(sim)
    actions = S._describe_repair(tasks()["repair:m"])["actions"]
    assert any("refresh" in a and "eva" in a.lower() and "fuzz" in a.lower() for a in actions)


# ---------------------------------------------------------------------------
# Item 3: a caller is not dispatched blind on a callee without a contract
# ---------------------------------------------------------------------------


def _requests() -> list[dict]:
    path = Path("workspace/reports/strengthen_requests.json")
    return base.load(path)["requests"] if path.is_file() else []


def _blocked_callee(sim: Sim, extra: dict | None = None) -> None:
    """f stalls (blocked, no contract); h calls f."""
    sim.build({"f": ("src/m/f.c", "m", []), "h": ("src/m/h.c", "m", ["f"]), **(extra or {})})
    write_json(
        Path("workspace/reports/facts/m.json"),
        {
            "schema": function_facts.FACTS_SCHEMA,
            "module": "m",
            "functions": {
                function_facts.function_key("src/m/f.c", "f"): {
                    "frame_skeleton": {
                        "status": "ok",
                        "separated": [],
                        "assigns": [{"loc": "*p", "from": [], "clause": "assigns *p \\from \\nothing;"}],
                    }
                }
            },
        },
    )
    S.cmd_init()
    assert ids(S.cmd_next("1", prepare=True)) == ["prove:src/m/f.c#f"]
    sim.prover("prove-f", "f", "src/m/f.c", status="stalled_after_k_retries")
    assert S.cmd_complete("prove-f")["action"] == "blocked"


def test_a_caller_of_a_blocked_contract_less_callee_waits_on_a_negotiation_the_scheduler_files(sim):
    _blocked_callee(sim)
    handed = ids(S.cmd_next("auto", prepare=True))
    assert "prove:src/m/h.c#h" not in handed and "negotiate:src/m/f.c#f" in handed
    neg = tasks()["negotiate:src/m/f.c#f"]
    assert neg["callers"] == ["prove:src/m/h.c#h"]
    h = tasks()["prove:src/m/h.c#h"]
    assert h["extra_deps"] == ["negotiate:src/m/f.c#f"] and "callees_without_contract" not in h
    [req] = _requests()
    assert (req["caller_function"], req["callee_function"], req["callee_file"]) == ("h", "f", "src/m/f.c")
    assert req["reason"] == S.CONTRACT_REQUEST_REASON and req["origin"] == "scheduler"
    assert req["needed_clause"] == "assigns *p \\from \\nothing;"  # the callee's projected frame skeleton
    assert neg["requests"] == [req["id"]]
    S.cmd_status()
    S.cmd_next("auto", prepare=True)
    assert len(_requests()) == 1  # filed once per (caller, callee), status files nothing


def test_the_caller_is_released_tagged_when_the_negotiation_ends_without_a_contract(sim):
    _blocked_callee(sim)
    S.cmd_next("auto", prepare=True)  # the negotiation and the breaker
    sim.prover("negotiate-f", "f", "src/m/f.c", status="stalled_after_k_retries")
    assert S.cmd_complete("negotiate-f")["action"] == "negotiation_rejected"
    nxt = S.cmd_next("auto", prepare=True)
    assert ids(nxt) == ["prove:src/m/h.c#h"]
    job = nxt["tasks"][0]
    assert job["callees_without_contract"] == ["src/m/f.c#f"]
    assert _requests()[0]["status"] == "rejected_by_callee"


def test_a_crash_candidate_callee_releases_its_caller_tagged_after_every_untagged_task(sim):
    sim.build(
        {
            "f": ("src/m/f.c", "m", []),
            "h": ("src/m/h.c", "m", ["f"]),
            "p": ("src/m/p.c", "m", []),
            "q": ("src/m/q.c", "m", []),
        },
        sidecars={"m": {}},
    )
    fp = sim.eva_candidate("m", "src/m/f.c", "f")
    S.cmd_init()
    ver = S.cmd_next("auto", prepare=True)["tasks"][0]
    L.cmd_scaffold_verifier(
        fp, "needs_validation", ver["agent_id"], out_path=Path(f"agents/{ver['agent_id']}/scratch/result.json")
    )
    S.cmd_complete(ver["agent_id"])
    order = [ids(S.cmd_next("1", prepare=True)) for _ in range(3)]
    assert order == [["prove:src/m/p.c#p"], ["prove:src/m/q.c#q"], ["prove:src/m/h.c#h"]]
    assert tasks()["prove:src/m/h.c#h"]["callees_without_contract"] == ["src/m/f.c#f"]
    assert "negotiate:src/m/f.c#f" not in tasks() and _requests() == []


def test_recursion_group_members_never_wait_on_each_other_for_a_contract(sim):
    sim.build({"f": ("src/r/f.c", "r", ["g"]), "g": ("src/r/g.c", "r", ["f"]), "h": ("src/r/h.c", "r", ["f"])})
    S.cmd_init()
    assert sorted(ids(S.cmd_next("auto", prepare=True))) == ["prove:src/r/f.c#f", "prove:src/r/g.c#g"]
    sim.prover("prove-f", "f", "src/r/f.c", status="stalled_after_k_retries")
    S.cmd_complete("prove-f")
    S.cmd_requeue(agent_id="prove-g")  # g is pending again while its group member f is blocked
    g = tasks()["prove:src/r/g.c#g"]
    assert "prove:src/r/g.c#g" in base.ready()
    assert not g.get("extra_deps") and "callees_without_contract" not in g
    assert "negotiate:src/r/f.c#f" not in tasks()
    assert "prove:src/r/h.c#h" not in base.ready()  # h waits for the whole group

    assert "prove:src/r/g.c#g" in ids(S.cmd_next("auto", prepare=True))
    sim.prover("prove-g-2", "g", "src/r/g.c", status="stalled_after_k_retries")
    S.cmd_complete("prove-g-2")
    # The group ended without contracts: its outside caller h waits on a negotiation for f.
    assert tasks()["negotiate:src/r/f.c#f"]["callers"] == ["prove:src/r/h.c#h"]
    assert "prove:src/r/h.c#h" not in base.ready()


def test_a_contract_only_in_the_callee_c_file_is_invisible_to_a_caller_in_another_file(sim):
    sim.build(
        {"f": ("src/m/f.c", "m", ["g"]), "g": ("src/m/g.c", "m", []), "k": ("src/m/g.c", "m", ["g"])},
    )
    work = sim.run_dir / "workspace/work/src/m/g.c"
    work.parent.mkdir(parents=True, exist_ok=True)
    work.write_text(
        "/*@ assigns \\nothing; */\nint g(void) { return 0; }\nint k(void) { return g(); }\n", encoding="utf-8"
    )
    S.cmd_init()
    t = tasks()
    assert "prove:src/m/g.c#g" in t["prove:src/m/f.c#f"]["deps"]  # f.c includes g's header, not g.c
    assert "prove:src/m/g.c#g" not in t["prove:src/m/g.c#k"]["deps"]  # k sees the contract in its own file
    ctx = S.Ctx()
    assert S.callee_has_contract(ctx, "src/m/g.c", "g", "m", caller_file="src/m/g.c")
    assert not S.callee_has_contract(ctx, "src/m/g.c", "g", "m", caller_file="src/m/f.c")


def _released_blind(job: dict) -> list[str]:
    """Contract-less callees (task terminal but not done, or absent) of a dispatched prover that its job does not name."""
    t = tasks()
    task = t[job["task"]]
    out = []
    for key in task.get("callees") or []:
        callee = t.get(f"prove:{key}")
        if callee is not None and (callee["state"] not in S.TERMINAL or callee["state"] == "done"):
            continue
        same_group = callee is not None and task.get("scc") is not None and callee.get("scc") == task.get("scc")
        if callee is not None and (callee.get("partial_contract_merged") or same_group):
            continue
        neg = t.get(f"negotiate:{key}") or {}
        if neg.get("state") == "done" and neg.get("outcome") == "applied":
            continue
        if key not in (job.get("callees_without_contract") or []):
            out.append(f"{job['task']} -> {key}")
    return out


def test_replay_no_prover_is_dispatched_blind_on_a_contract_less_callee(sim):
    """The run-6 shapes: a callee blocked merge_failed, a crash-candidate callee, a callee with no prove task."""
    # c3 is covered by its own module's Eva run (another module, so m's Eva ingest leaves it alone): no prove task.
    write_json(sim.run_dir / "workspace/reports/eva/n.json", {"status": "ok", "module": "n"})
    covered = base.unit(
        "src/n/c3.c",
        "c3",
        "rte",
        status="covered",
        module="n",
        tier=base.TIER1,
        evidence=[base.evidence(tool_output="workspace/reports/eva/n.json")],
    )
    fns = {
        "c1": ("src/m/c1.c", "m", []),
        "c2": ("src/m/c2.c", "m", []),
        "c3": ("src/n/c3.c", "n", []),
        "a1": ("src/m/a1.c", "m", ["c1"]),
        "a2": ("src/m/a2.c", "m", ["c2"]),
        "a3": ("src/m/a3.c", "m", ["c3"]),
        "a4": ("src/m/a4.c", "m", ["c1", "c3"]),
    }
    sim.build(
        fns,
        units=[
            base.unit(file, n, "rte", module="m", tier=base.TIER1) for n, (file, _m, _c) in fns.items() if n != "c3"
        ]
        + [covered],
        sidecars={"m": {}},
    )
    fp = sim.eva_candidate("m", "src/m/c2.c", "c2")
    S.cmd_init()
    blind: list[str] = []
    dispatched: list[str] = []
    for _ in range(20):
        nxt = S.cmd_next("auto", prepare=True)
        if not nxt["tasks"] and nxt["done"]:
            break
        for job in nxt["tasks"]:
            aid, kind, fn = job["agent_id"], job["kind"], job.get("function")
            if kind == "verify":
                L.cmd_scaffold_verifier(
                    fp, "needs_validation", aid, out_path=Path(f"agents/{aid}/scratch/result.json")
                )
                S.cmd_complete(aid)
            elif kind == "breaker":
                sim.breaker(aid, fn, job["file"])
                S.cmd_complete(aid)
            elif kind == "negotiate":
                sim.prover(aid, fn, job["file"], status="stalled_after_k_retries")
                S.cmd_complete(aid)
            elif kind == "prove":
                dispatched.append(job["task"])
                blind += _released_blind(job)
                if fn == "c1":
                    sim.merge_fail[aid] = "parent WP check on merged tree returned status='unproven_goals_remain'"
                sim.prover(aid, fn, job["file"])
                S.cmd_complete(aid)
        S.cmd_merge_pending(force=True)
    assert {f"prove:src/m/{a}.c#{a}" for a in ("a1", "a2", "a3", "a4")} <= set(dispatched)
    assert blind == []
    t = tasks()
    assert t["prove:src/m/c1.c#c1"]["state"] == "blocked"
    assert "prove:src/n/c3.c#c3" not in t
    assert t["prove:src/m/a4.c#a4"]["callees_without_contract"] == ["src/m/c1.c#c1", "src/n/c3.c#c3"]
    callers = {r["caller_function"] for r in _requests() if r.get("origin") == "scheduler"}
    assert callers == {"a1", "a3", "a4"}  # never for the crash candidate c2
