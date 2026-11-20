"""
The per-callee negotiation cap and the notes of closed requests (O5, libmnl run 1, `req_0015`).

Run 1 dispatched `negotiate:src/attr.c#mnl_attr_get_payload` five times: rounds 1 -> 2 and 3 -> 4 were follow-up
rounds, 2 -> 3 a requeue of an agent that never returned, 4 -> 5 a new request. Then the driver closed the fifth,
already assigned, round by hand with a `not dispatched:` note, which Tier 1 (`spec_kb`) reads as a structural
rejection. These tests replay that sequence against today's scheduler.
"""

from __future__ import annotations

from pathlib import Path

import spec_kb
import test_wp_scheduler as base
import wp_scheduler as S
from test_wp_scheduler import Sim, request, tasks

sim = base.sim  # the shared fixture

NEG = "negotiate:src/m/g.c#g"


def _requests() -> list[dict]:
    path = Path("workspace/reports/strengthen_requests.json")
    return base.load(path)["requests"] if path.is_file() else []


def _callers(sim: Sim, count: int) -> dict[str, str]:
    """g is proved and merged; `count` callers c1..cN of g are handed out together. Returns {function: agent id}."""
    callers = {f"c{i}": (f"src/m/c{i}.c", "m", ["g"]) for i in range(1, count + 1)}
    sim.build({**callers, "g": ("src/m/g.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.finish("prove-g", "g", "src/m/g.c")
    handed = [x for x in S.cmd_next(str(count + 4), prepare=True)["tasks"] if x["kind"] == "prove"]
    assert len(handed) == count, "the sim must hand the callers out together"
    return {x["function"]: x["agent_id"] for x in handed}


def _stall_with_request(sim: Sim, agents: dict[str, str], fn: str, n: int) -> dict:
    sim.prover(agents[fn], fn, f"src/m/{fn}.c", status="stalled_after_k_retries", requests=[request("g", n)])
    return S.cmd_complete(agents[fn])


def _dispatch_negotiation() -> str | None:
    picked = [x for x in S.cmd_next("16", prepare=True)["tasks"] if x["kind"] == "negotiate"]
    return picked[0]["agent_id"] if picked else None


def _negotiator_stalls(sim: Sim, aid: str) -> None:
    sim.prover(aid, "g", "src/m/g.c", status="stalled_after_k_retries")
    assert S.cmd_complete(aid)["action"] == "negotiation_rejected"


def _assigned(sim: Sim) -> set[str]:
    """The request ids handed to a negotiate agent, from the sim's prepare calls (the briefs)."""
    return {
        str(r.get("id"))
        for aid, _, kw in sim.prepared
        if aid.startswith("negotiate-")
        for r in kw.get("requests") or []
    }


def _check_assigned_notes(sim: Sim) -> None:
    assigned = _assigned(sim)
    assert assigned, "the replay must assign requests to a negotiate agent"
    for req in _requests():
        if req["id"] not in assigned:
            continue
        assert req["status"] != "pending", req
        note = str(req.get("resolution_note") or "")
        assert not note.startswith(spec_kb.STRUCTURAL_REJECTION_PREFIX), req
        assert spec_kb._request_obstruction(req) is not None, req  # Tier 1 lists it as a dead end


def test_the_run_1_sequence_dispatches_the_callee_at_most_cap_times(sim):
    agents = _callers(sim, 7)
    dispatched: list[str] = []

    _stall_with_request(sim, agents, "c1", 1)  # req_0004
    aid = _dispatch_negotiation()
    assert aid == "negotiate-g"
    dispatched.append(aid)
    _stall_with_request(sim, agents, "c2", 2)  # req_0005, req_0006 arrive while round 1 runs
    _stall_with_request(sim, agents, "c3", 3)
    _negotiator_stalls(sim, aid)
    aid = _dispatch_negotiation()  # the follow-up round
    assert aid == "negotiate-g-2"
    dispatched.append(aid)
    for n, fn in enumerate(("c4", "c5", "c6"), start=4):  # req_0007, req_0008, req_0010 while round 2 runs
        _stall_with_request(sim, agents, fn, n)
    assert tasks()[NEG]["followup_callers"] == ["prove:src/m/c4.c#c4", "prove:src/m/c5.c#c5", "prove:src/m/c6.c#c6"]
    assert S.cmd_requeue(aid)["requeued"], "round 2 never returned"
    aid = _dispatch_negotiation()  # the same requests again; the follow-ups survive the requeue
    assert aid == "negotiate-g-3"
    dispatched.append(aid)
    _negotiator_stalls(sim, aid)
    aid = _dispatch_negotiation()
    if aid is not None:  # run 1's fourth round, for the follow-ups
        dispatched.append(aid)
        _negotiator_stalls(sim, aid)
    _stall_with_request(sim, agents, "c7", 7)  # req_0015
    aid = _dispatch_negotiation()
    if aid is not None:  # run 1's fifth round
        dispatched.append(aid)

    neg = tasks()[NEG]
    assert dispatched == ["negotiate-g", "negotiate-g-2", "negotiate-g-3"]
    assert neg["dispatches"] <= S.MAX_NEGOTIATION_ROUNDS_PER_CALLEE
    assert len(neg["agents"]) <= S.MAX_NEGOTIATION_ROUNDS_PER_CALLEE
    reqs = _requests()
    assert len(reqs) == 7 and all(r["status"] == "rejected_by_callee" for r in reqs)
    unassigned = [r for r in reqs if r["id"] not in _assigned(sim)]
    assert {r["caller_function"] for r in unassigned} == {"c4", "c5", "c6", "c7"}
    for req in unassigned:  # never handed to an agent: a structural rejection, out of Tier 1's dead ends
        assert req["resolution_note"].startswith(spec_kb.STRUCTURAL_REJECTION_PREFIX), req
        assert "cap" in req["resolution_note"]
    _check_assigned_notes(sim)


def test_a_requeued_round_at_the_cap_is_closed_and_its_assigned_request_is_not_called_undispatched(sim):
    agents = _callers(sim, 3)
    for n, fn in enumerate(("c1", "c2"), start=1):
        _stall_with_request(sim, agents, fn, n)
        _negotiator_stalls(sim, _dispatch_negotiation() or "")
    _stall_with_request(sim, agents, "c3", 3)
    aid = _dispatch_negotiation()
    assert aid == "negotiate-g-3"
    assert S.cmd_requeue(aid)["requeued"], "the third round never returned"

    assert _dispatch_negotiation() is None  # a fourth dispatch would exceed the cap
    neg = tasks()[NEG]
    assert neg["state"] == "done" and neg["dispatches"] == S.MAX_NEGOTIATION_ROUNDS_PER_CALLEE
    [req] = [r for r in _requests() if r["caller_function"] == "c3"]
    assert req["status"] == "rejected_by_callee"
    assert aid in req["resolution_note"] and "cap" in req["resolution_note"]
    _check_assigned_notes(sim)


def test_a_requeued_round_refused_at_dispatch_does_not_call_its_assigned_request_undispatched(sim, monkeypatch):
    agents = _callers(sim, 1)
    _stall_with_request(sim, agents, "c1", 1)
    aid = _dispatch_negotiation()
    assert aid == "negotiate-g"
    assert S.cmd_requeue(aid)["requeued"]
    # The callee now has a crash candidate: the negotiation must not run again.
    monkeypatch.setattr(S, "_negotiate_skip_verdict", lambda *a, **k: "candidate")

    assert _dispatch_negotiation() is None
    assert tasks()[NEG]["state"] in S.TERMINAL
    [req] = _requests()
    assert req["status"] == "rejected_by_callee" and "candidate" in req["resolution_note"]
    _check_assigned_notes(sim)


def test_a_request_whose_only_agent_was_never_prepared_stays_undispatched(sim, monkeypatch):
    agents = _callers(sim, 1)
    _stall_with_request(sim, agents, "c1", 1)

    def fail(agent_id, role, kw):
        raise RuntimeError("overlay snapshot failed")

    monkeypatch.setattr(sim, "on_prepare", fail)
    assert _dispatch_negotiation() is None  # prepare failed: the dispatch is refunded
    neg = tasks()[NEG]
    assert neg["state"] == "pending" and neg["dispatches"] == 0 and not neg.get("request_agents")
    monkeypatch.setattr(S, "_negotiate_skip_verdict", lambda *a, **k: "candidate")

    assert _dispatch_negotiation() is None
    [req] = _requests()
    assert req["resolution_note"] == f"{spec_kb.STRUCTURAL_REJECTION_PREFIX} callee unit is candidate"


def test_closing_an_assigned_round_by_hand_never_writes_the_structural_prefix(sim):
    """Run 1's driver closed `negotiate-mnl_attr_get_payload-5` through `_resolve_negotiation` with this note."""
    agents = _callers(sim, 1)
    _stall_with_request(sim, agents, "c1", 1)
    assert _dispatch_negotiation() == "negotiate-g"

    with S.run_lock("ledger"):
        state = S.load_schedule()
        out: dict = {"errors": []}
        S._resolve_negotiation(
            state,
            state["tasks"][NEG],
            False,
            "not dispatched: callee went through 4 negotiation rounds without an accepted contract "
            "(WP Typed pointer-cast limit on the return expression)",
            out,
        )
        S.save_schedule(state)
    assert out["errors"] == []
    [req] = _requests()
    assert "WP Typed pointer-cast limit" in req["resolution_note"]
    _check_assigned_notes(sim)


def test_negotiate_claim_refused_after_prepare_refunds_dispatch_and_marks_not_dispatched(sim, monkeypatch):
    """Callee gets a skip verdict between assignment and preparation: refund dispatch and prefix `not dispatched:`."""
    agents = _callers(sim, 1)
    _stall_with_request(sim, agents, "c1", 1)

    def become_candidate(agent_id, role, kw):
        if agent_id.startswith("negotiate-"):
            sim.eva_candidate("m", "src/m/g.c", "g")

    monkeypatch.setattr(sim, "on_prepare", become_candidate)
    nxt = S.cmd_next("16", prepare=True)

    assert [t for t in nxt["tasks"] if t["kind"] == "negotiate"] == []
    assert any(s["task"] == NEG and s["reason"] == "candidate" for s in nxt["skipped"])
    neg = tasks()[NEG]
    assert neg["state"] == "skipped" and neg["outcome"] == "candidate"
    assert neg["dispatches"] == 0
    assert not neg.get("request_agents")
    [req] = _requests()
    assert req["status"] == "rejected_by_callee"
    assert req["resolution_note"].startswith(spec_kb.STRUCTURAL_REJECTION_PREFIX), req
    assert "candidate" in req["resolution_note"]
    assert spec_kb._request_obstruction(req) is None


def test_requeued_negotiate_claim_refused_after_prepare_keeps_prior_agent_attribution(sim, monkeypatch):
    """If an earlier round DID run for the request, refunding a later refused prepare still blames the earlier agent."""
    agents = _callers(sim, 1)
    _stall_with_request(sim, agents, "c1", 1)
    aid1 = _dispatch_negotiation()
    assert aid1 == "negotiate-g"
    assert S.cmd_requeue(aid1)["requeued"]

    def become_candidate(agent_id, role, kw):
        if agent_id.startswith("negotiate-"):
            sim.eva_candidate("m", "src/m/g.c", "g")

    monkeypatch.setattr(sim, "on_prepare", become_candidate)
    nxt = S.cmd_next("16", prepare=True)

    assert nxt["tasks"] == []
    neg = tasks()[NEG]
    assert neg["state"] == "skipped" and neg["dispatches"] == 1
    [req] = _requests()
    assert req["status"] == "rejected_by_callee"
    assert req["resolution_note"].startswith(f"{S.NEGOTIATION_CLOSED_AFTER_DISPATCH} to {aid1}:"), req
    assert spec_kb._request_obstruction(req) is not None
