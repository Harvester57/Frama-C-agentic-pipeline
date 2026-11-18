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
