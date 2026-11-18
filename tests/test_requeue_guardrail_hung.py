"""`wp_scheduler.py requeue --guardrail-hung`: tasks a hanging corpus seed ended get a fresh agent (libmodbus run-1)."""

from __future__ import annotations

from pathlib import Path

import pytest

import wp_scheduler as S
from conftest import write_json
from test_wp_scheduler import Sim, load, request, request_store, tasks, units

pytestmark = pytest.mark.unit


@pytest.fixture
def sim(run_dir, monkeypatch):
    return Sim(run_dir, monkeypatch)


def hung_guard(sim, aid, fn, **changes):
    """The report of a guardrail that stopped on a hanging corpus seed."""
    report = {
        "status": "guardrail_error",
        "returncode": 70,
        "crash_input": f"agents/{aid}/scratch/guard/timeout-fff6050c11a5852f44e8a5c3af1d2ae1ee74ec4e",
        **changes,
    }
    write_json(sim.run_dir / f"agents/{aid}/scratch/guard_{fn}.json", report)


def stalled_on_a_hang(sim, n="a"):
    sim.build({n: (f"src/m/{n}.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.prover(f"prove-{n}", n, f"src/m/{n}.c", status="stalled_after_k_retries")
    hung_guard(sim, f"prove-{n}", n)
    S.cmd_complete(f"prove-{n}")
    return f"prove:src/m/{n}.c#{n}"


def negotiation_rejected_on_a_hang(sim):
    """f asked g for a clause; the negotiator of g hung on the guardrail and the request was rejected."""
    sim.build({"f": ("src/m/f.c", "m", ["g"]), "g": ("src/m/g.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.finish("prove-g", "g", "src/m/g.c")
    S.cmd_next("auto", prepare=True)
    sim.prover("prove-f", "f", "src/m/f.c", status="stalled_after_k_retries", requests=[request("g", 1)])
    S.cmd_complete("prove-f")
    S.cmd_next("auto", prepare=True)
    sim.prover("negotiate-g", "g", "src/m/g.c", status="blocked")
    hung_guard(sim, "negotiate-g", "g")
    S.cmd_complete("negotiate-g")
    assert tasks()["negotiate:src/m/g.c#g"]["outcome"] == "rejected"
    return "negotiate:src/m/g.c#g"


def test_a_stalled_prover_is_reopened_for_a_fresh_agent(sim, capsys):
    tid = stalled_on_a_hang(sim)
    assert tasks()[tid]["state"] == "blocked" and tasks()[tid]["dispatches"] == 1
    assert S.main(["requeue", "--guardrail-hung"]) == 0
    capsys.readouterr()
    task = tasks()[tid]
    assert (task["state"], task["outcome"], task["agent_id"], task["dispatches"]) == ("pending", None, None, 0)
    assert "requeued_from" not in task
    out = S.cmd_next("auto", prepare=True)
    handed = {t["task"]: t["agent_id"] for t in out["tasks"]}
    assert handed[tid] != "prove-a"  # never the old directory: its result would be read as the answer
    assert units()["src/m/a.c#a::rte"]["status"] == "in_progress"


def test_the_report_names_what_was_reopened_and_it_is_idempotent(sim):
    tid = stalled_on_a_hang(sim)
    out = S.cmd_requeue_guardrail_hung()
    assert out["ok"] is True and [r["task"] for r in out["reopened"]] == [tid]
    entry = out["reopened"][0]
    assert entry["agent_id"] == "prove-a" and "timeout-" in entry["crash_input"]
    before = tasks()
    again = S.cmd_requeue_guardrail_hung()
    assert again["reopened"] == [] and again["running_left"] == [] and tasks() == before


def set_unit_notes(sim, cid, notes):
    ledger = load("coverage-ledger.json")
    for u in ledger:
        if u["coverage_id"] == cid:
            u["unresolved"] = notes
    write_json(sim.run_dir / "coverage-ledger.json", ledger)


def test_units_parked_by_the_stall_are_released_and_other_blocks_stay(sim):
    tid = stalled_on_a_hang(sim)
    cid = "src/m/a.c#a::rte"
    assert units()[cid]["status"] == "blocked"
    set_unit_notes(sim, cid, ["prover prove-a returned stalled_after_k_retries"])
    out = S.cmd_requeue_guardrail_hung()
    assert out["reopened"][0]["units_released"] == [cid]
    assert (units()[cid]["status"], units()[cid]["unresolved"]) == ("planned", [])
    assert tasks()[tid]["state"] == "pending"


def test_a_unit_with_a_recorded_proof_gap_keeps_its_note(sim):
    stalled_on_a_hang(sim)
    parked = "prover prove-a returned stalled_after_k_retries"
    set_unit_notes(sim, "src/m/a.c#a::rte", [parked, "proof_gap: WP cannot discharge the shift"])
    out = S.cmd_requeue_guardrail_hung()
    assert out["reopened"][0]["units_released"] == []
    assert units()["src/m/a.c#a::rte"]["status"] == "blocked"  # the next dispatch claims it again


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "passed_dynamic_oracle"},
        {"returncode": 77},
        {"crash_input": "agents/prove-a/scratch/guard/crash-0123"},
        {"crash_input": None},
    ],
)
def test_any_other_guardrail_outcome_leaves_the_task_alone(sim, changes):
    tid = stalled_on_a_hang(sim)
    hung_guard(sim, "prove-a", "a", **changes)
    before = tasks()
    assert S.cmd_requeue_guardrail_hung()["reopened"] == [] and tasks() == before
    assert tasks()[tid]["state"] == "blocked"


def test_a_stall_without_a_guard_report_is_left_alone(sim):
    tid = stalled_on_a_hang(sim)
    Path("agents/prove-a/scratch/guard_a.json").unlink()
    assert S.cmd_requeue_guardrail_hung()["reopened"] == [] and tasks()[tid]["state"] == "blocked"


def test_only_the_latest_agent_of_a_task_counts(sim):
    tid = stalled_on_a_hang(sim)
    state = S.load_schedule()
    state["tasks"][tid]["agent_id"] = "prove-a-2"
    S.save_schedule(state)
    assert S.cmd_requeue_guardrail_hung()["reopened"] == []


def test_a_merged_partial_contract_is_listed_and_not_reopened(sim):
    tid = stalled_on_a_hang(sim)
    state = S.load_schedule()
    state["tasks"][tid]["partial_contract_merged"] = True
    S.save_schedule(state)
    out = S.cmd_requeue_guardrail_hung()
    assert out["reopened"] == [] and [e["task"] for e in out["left"]] == [tid]
    assert tasks()[tid]["state"] == "blocked"


def test_a_rejected_negotiation_runs_again_with_its_requests_open(sim):
    tid = negotiation_rejected_on_a_hang(sim)
    rid = request_store()[0]["id"]
    assert request_store()[0]["status"] == "rejected_by_callee"
    rounds = tasks()[tid]["dispatches"]
    out = S.cmd_requeue_guardrail_hung()
    assert [r["task"] for r in out["reopened"]] == [tid] and out["requests_restored"] == [rid]
    task = tasks()[tid]
    assert (task["state"], task["outcome"], task["dispatches"]) == ("pending", None, rounds - 1)
    assert (request_store()[0]["status"], request_store()[0]["resolution_note"]) == ("pending", "")
    assert "negotiate-g" not in (task.get("request_agents") or {}).get(rid, [])
    assert tasks()["prove:src/m/f.c#f"]["state"] == "blocked"  # requeued only by a request really applied


def test_a_negotiation_keeps_the_pair_budget(sim):
    negotiation_rejected_on_a_hang(sim)
    before = load("state/wp_schedule.json")["negotiation_counts"]
    S.cmd_requeue_guardrail_hung()
    assert load("state/wp_schedule.json")["negotiation_counts"] == before


def test_a_false_rejection_leaves_the_known_dead_ends(sim):
    negotiation_rejected_on_a_hang(sim)
    rid = request_store()[0]["id"]
    store = Path("workspace/reports/kb/obstructions.json")
    keep = {"id": "req:other", "resolution_note": "a real rejection"}
    write_json(sim.run_dir / store, {"items": [{"id": f"req:{rid}", "resolution_note": "x"}, keep]})
    out = S.cmd_requeue_guardrail_hung()
    assert out["obstructions_forgotten"] == 1 and load(store)["items"] == [keep]


def test_a_request_closed_for_another_reason_stays_closed(sim):
    tid = negotiation_rejected_on_a_hang(sim)
    rid = request_store()[0]["id"]
    S.DEPS.resolve_request(S.REQUESTS, rid, "rejected_by_callee", "a real rejection of the clause")
    out = S.cmd_requeue_guardrail_hung()
    assert out["reopened"] == [] and [e["task"] for e in out["left"]] == [tid]
    assert tasks()[tid]["state"] == "done"


def test_an_applied_negotiation_is_left_alone(sim):
    tid = stalled_on_a_hang(sim)
    state = S.load_schedule()
    state["tasks"][tid]["partial_contract_merged"] = None
    S._new_task(state, "negotiate:src/m/a.c#a", "negotiate", "a", file="src/m/a.c", function="a", module="m")
    state["tasks"]["negotiate:src/m/a.c#a"].update(state="done", outcome="applied")
    S.save_schedule(state)
    out = S.cmd_requeue_guardrail_hung()
    assert out["reopened"] == [] and "negotiate:src/m/a.c#a" in out["left"][0]["reason"]


def running_with_a_finished_hung_result(sim, status="stalled_after_k_retries"):
    sim.build({"a": ("src/m/a.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.prover("prove-a", "a", "src/m/a.c", status=status)
    hung_guard(sim, "prove-a", "a")
    return "prove:src/m/a.c#a"


def test_a_finished_uncompleted_agent_is_reopened_and_its_late_complete_is_stale(sim):
    tid = running_with_a_finished_hung_result(sim)
    assert units()["src/m/a.c#a::rte"]["status"] == "in_progress"
    out = S.cmd_requeue_guardrail_hung()
    assert [r["task"] for r in out["reopened"]] == [tid] and out["reopened"][0]["was_running"] is True
    assert (tasks()[tid]["state"], tasks()[tid]["dispatches"]) == ("pending", 0)
    assert units()["src/m/a.c#a::rte"]["status"] == "planned"
    assert S.cmd_complete("prove-a")["action"] == "stale_agent"  # the hung result can never be merged
    assert tasks()[tid]["state"] == "pending"


def test_a_running_agent_without_a_result_is_listed_and_untouched(sim):
    tid = running_with_a_finished_hung_result(sim)
    Path("agents/prove-a/scratch/result.json").unlink()
    before = tasks()
    out = S.cmd_requeue_guardrail_hung()
    assert out["reopened"] == [] and [e["task"] for e in out["running_left"]] == [tid]
    assert tasks() == before


def test_a_running_agent_that_proved_everything_is_left_to_the_parent_recheck(sim):
    tid = running_with_a_finished_hung_result(sim, status="all_proven")
    out = S.cmd_requeue_guardrail_hung()
    assert out["reopened"] == [] and [e["task"] for e in out["running_left"]] == [tid]
    assert S.cmd_complete("prove-a")["action"] == "queued_for_merge"


def test_blocked_callers_of_a_reopened_prover_are_listed(sim):
    sim.build({"f": ("src/m/f.c", "m", ["g"]), "g": ("src/m/g.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.prover("prove-g", "g", "src/m/g.c", status="stalled_after_k_retries")
    hung_guard(sim, "prove-g", "g")
    S.cmd_complete("prove-g")
    state = S.load_schedule()
    state["tasks"]["prove:src/m/f.c#f"].update(state="blocked", outcome="blocked", callees=["src/m/g.c#g"])
    S.save_schedule(state)
    out = S.cmd_requeue_guardrail_hung()
    assert [r["task"] for r in out["reopened"]] == ["prove:src/m/g.c#g"]
    assert [e["task"] for e in out["blocked_callers_to_review"]] == ["prove:src/m/f.c#f"]


def test_a_prover_that_ended_blocked_on_a_hang_is_reopened(sim):
    """Five of the provers of libmodbus run-1 returned `blocked`, not `stalled_after_k_retries`."""
    sim.build({"a": ("src/m/a.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.prover("prove-a", "a", "src/m/a.c", status="blocked")
    hung_guard(sim, "prove-a", "a")
    S.cmd_complete("prove-a")
    tid = "prove:src/m/a.c#a"
    assert (tasks()[tid]["state"], tasks()[tid]["outcome"]) == ("blocked", "blocked")
    assert [r["task"] for r in S.cmd_requeue_guardrail_hung()["reopened"]] == [tid]
    assert tasks()[tid]["state"] == "pending"


def test_any_other_ending_on_a_hang_is_listed_and_not_reopened(sim):
    tid = stalled_on_a_hang(sim)
    state = S.load_schedule()
    state["tasks"][tid]["outcome"] = "merge_failed"
    S.save_schedule(state)
    out = S.cmd_requeue_guardrail_hung()
    assert out["reopened"] == [] and [e["task"] for e in out["left"]] == [tid]
    assert "merge_failed" in out["left"][0]["reason"] and tasks()[tid]["state"] == "blocked"


def test_the_step_the_session_calls_for_a_reopened_agent_is_harmless(sim):
    tid = running_with_a_finished_hung_result(sim)
    S.cmd_requeue_guardrail_hung()
    out = S.cmd_step(complete_ids=["prove-a"], slots=1, prepare=True)
    assert out["ok"] is True and out["errors"] == []
    assert out["completed"][0]["action"] == "stale_agent"
    assert tasks()[tid]["state"] == "running" and tasks()[tid]["agent_id"] != "prove-a"


@pytest.mark.parametrize(("artifact", "promoted_as_seed"), [("timeout-0123", False), ("crash-0123", True)])
def test_a_breaker_timeout_artifact_is_not_promoted_as_a_seed(sim, monkeypatch, artifact, promoted_as_seed):
    seeds: list = []
    monkeypatch.setattr(S, "promote_file", lambda *a, **kw: seeds.append(a[2]) if kw.get("kind") == "seed" else None)
    sim.build({"a": ("src/m/a.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.prover("prove-a", "a", "src/m/a.c", status="stalled_after_k_retries")
    S.cmd_complete("prove-a")
    S.cmd_next("auto", prepare=True)
    sim.breaker("breaker-a", "a", "src/m/a.c", crash=True)
    result = load("agents/breaker-a/scratch/result.json")
    result.update(crash_artifact=f"agents/breaker-a/scratch/{artifact}", seeds=[])
    write_json(sim.run_dir / "agents/breaker-a/scratch/result.json", result)
    (sim.run_dir / f"agents/breaker-a/scratch/{artifact}").write_bytes(b"input")
    S.cmd_complete("breaker-a")
    assert seeds == ([f"agents/breaker-a/scratch/{artifact}"] if promoted_as_seed else [])


# ---------------------------------------------------------------------------
# A proved result the parent guardrail hung on at merge time
# ---------------------------------------------------------------------------

PARENT_HUNG = "parent guardrail returned status='guardrail_error'"


def hung_parent_guard(sim, aid, name, **changes):
    report = {
        "status": "guardrail_error",
        "returncode": 70,
        "crash_input": f"agents/{aid}/scratch/parent_guard/timeout-fff6050c11a5852f44e8a5c3af1d2ae1ee74ec4e",
        **changes,
    }
    write_json(sim.run_dir / f"agents/{aid}/scratch/parent_guard_{name}.json", report)


def fail_the_merge(sim, aid, reason=PARENT_HUNG):
    sim.merge_fail[aid] = reason
    S.cmd_merge_pending(force=True)
    del sim.merge_fail[aid]


@pytest.fixture
def splice(monkeypatch):
    """What the dry splice answers, per agent: the result merges unless a refusal is set."""
    refusals: dict[str, str] = {}
    monkeypatch.setattr(S.DEPS, "splice_refusal", lambda task, aid: refusals.get(aid))
    return refusals


def merge_hung(sim, name="a"):
    sim.build({"a": ("src/m/a.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.prover("prove-a", "a", "src/m/a.c")
    assert S.cmd_complete("prove-a")["action"] == "queued_for_merge"
    fail_the_merge(sim, "prove-a")
    hung_parent_guard(sim, "prove-a", name)
    tid = "prove:src/m/a.c#a"
    assert (tasks()[tid]["state"], tasks()[tid]["merge_attempts"]) == ("pending", 1)
    assert units()["src/m/a.c#a::rte"]["status"] == "planned"
    return tid


def negotiation_merge_hung(sim):
    """The negotiator of g proved the clause f asked for; the parent guardrail hung on its merge."""
    sim.build({"f": ("src/m/f.c", "m", ["g"]), "g": ("src/m/g.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.finish("prove-g", "g", "src/m/g.c")
    S.cmd_next("auto", prepare=True)
    sim.prover("prove-f", "f", "src/m/f.c", status="stalled_after_k_retries", requests=[request("g", 1)])
    S.cmd_complete("prove-f")
    S.cmd_next("auto", prepare=True)
    sim.prover("negotiate-g", "g", "src/m/g.c")
    assert S.cmd_complete("negotiate-g")["action"] == "queued_for_merge"
    fail_the_merge(sim, "negotiate-g")
    hung_parent_guard(sim, "negotiate-g", "g")
    assert tasks()["negotiate:src/m/g.c#g"]["state"] == "pending"
    return "negotiate:src/m/g.c#g"


def test_a_proved_result_goes_back_to_the_merge_queue_without_a_new_agent(sim, splice):
    tid = merge_hung(sim)
    before = tasks()[tid]
    out = S.cmd_requeue_guardrail_hung()
    assert out["ok"] is True and out["reopened"] == []
    assert out["merge_restored"] == [
        {
            "task": tid,
            "agent_id": "prove-a",
            "crash_input": out["merge_restored"][0]["crash_input"],
            "units": ["src/m/a.c#a::rte"],
        }
    ]
    task = tasks()[tid]
    assert (task["state"], task["agent_id"], task["merge"]["agent_id"]) == ("merge_queued", "prove-a", "prove-a")
    assert (task["dispatches"], task["merge_attempts"]) == (before["dispatches"], 0)
    assert task["reopened"] == before["reopened"] - 1 and task["last_reason"] is None
    assert units()["src/m/a.c#a::rte"]["status"] == "in_progress"


def test_the_restored_result_merges_and_no_prover_runs_again(sim, splice):
    tid = merge_hung(sim)
    S.cmd_requeue_guardrail_hung()
    prepared = len(sim.prepared)
    merged = S.cmd_merge_pending(force=True)
    assert [m["agent_id"] for m in merged["merged"]] == ["prove-a"]
    assert (tasks()[tid]["state"], tasks()[tid]["outcome"]) == ("done", "merged")
    assert len(sim.prepared) == prepared


def test_restoring_a_merge_is_idempotent(sim, splice):
    merge_hung(sim)
    S.cmd_requeue_guardrail_hung()
    before = tasks()
    again = S.cmd_requeue_guardrail_hung()
    assert again["merge_restored"] == [] and again["reopened"] == [] and tasks() == before


def test_a_result_that_no_longer_splices_gets_a_fresh_agent(sim, splice):
    tid = merge_hung(sim)
    splice["prove-a"] = "AcslError: the function diverged from the agent's base"
    out = S.cmd_requeue_guardrail_hung()
    assert out["merge_restored"] == [] and [r["task"] for r in out["reopened"]] == [tid]
    assert "diverged" in out["reopened"][0]["reason"]
    task = tasks()[tid]
    assert (task["state"], task["agent_id"], task["dispatches"], task["merge_attempts"]) == ("pending", None, 0, 0)
    assert units()["src/m/a.c#a::rte"]["status"] == "planned"
    before = tasks()
    assert S.cmd_requeue_guardrail_hung()["reopened"] == [] and tasks() == before
    handed = {t["task"]: t["agent_id"] for t in S.cmd_next("auto", prepare=True)["tasks"]}
    assert handed[tid] != "prove-a"


def test_the_module_wide_parent_guardrail_counts_too(sim, splice):
    tid = merge_hung(sim, name="m")
    assert [r["task"] for r in S.cmd_requeue_guardrail_hung()["merge_restored"]] == [tid]


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "code_fault"},
        {"returncode": 77},
        {"crash_input": "agents/prove-a/scratch/parent_guard/crash-0123"},
    ],
)
def test_a_parent_guardrail_that_gave_a_verdict_is_not_undone(sim, splice, changes):
    tid = merge_hung(sim)
    hung_parent_guard(sim, "prove-a", "a", **changes)
    before = tasks()
    out = S.cmd_requeue_guardrail_hung()
    assert out["merge_restored"] == [] and out["reopened"] == [] and tasks() == before
    assert tasks()[tid]["state"] == "pending"


def test_a_task_a_new_agent_has_taken_is_listed_and_untouched(sim, splice):
    tid = merge_hung(sim)
    S.cmd_next("auto", prepare=True)
    assert tasks()[tid]["state"] == "running"
    before = tasks()
    out = S.cmd_requeue_guardrail_hung()
    assert out["merge_restored"] == [] and [e["task"] for e in out["left"]] == [tid]
    assert tasks() == before


def test_a_merge_that_ended_for_good_is_listed_and_untouched(sim, splice):
    tid = merge_hung(sim)
    state = S.load_schedule()
    state["tasks"][tid].update(state="blocked", outcome="merge_failed")
    S.save_schedule(state)
    out = S.cmd_requeue_guardrail_hung()
    assert out["merge_restored"] == [] and [e["task"] for e in out["left"]] == [tid]
    assert tasks()[tid]["state"] == "blocked"


def test_a_negotiation_goes_back_to_the_queue_with_its_request_open(sim, splice):
    tid = negotiation_merge_hung(sim)
    rid = request_store()[0]["id"]
    status = request_store()[0]["status"]
    counts = load("state/wp_schedule.json")["negotiation_counts"]
    out = S.cmd_requeue_guardrail_hung()
    assert [r["task"] for r in out["merge_restored"]] == [tid] and out["merge_restored"][0]["requests"] == [rid]
    assert tasks()[tid]["state"] == "merge_queued" and request_store()[0]["status"] == status
    assert load("state/wp_schedule.json")["negotiation_counts"] == counts
    S.cmd_merge_pending(force=True)
    assert (tasks()[tid]["state"], tasks()[tid]["outcome"]) == ("done", "applied")
    assert request_store()[0]["status"] == "verified_and_applied"


def test_a_negotiation_behind_the_callees_own_proof_runs_again(sim, splice):
    tid = negotiation_merge_hung(sim)
    state = S.load_schedule()
    state["tasks"]["prove:src/m/g.c#g"].update(state="merge_queued", merge={"agent_id": "prove-g"})
    S.save_schedule(state)
    rounds = tasks()[tid]["dispatches"]
    out = S.cmd_requeue_guardrail_hung()
    assert out["merge_restored"] == [] and [r["task"] for r in out["reopened"]] == [tid]
    assert "merges first" in out["reopened"][0]["reason"]
    assert (tasks()[tid]["state"], tasks()[tid]["dispatches"]) == ("pending", rounds - 1)
