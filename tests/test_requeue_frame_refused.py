"""`wp_scheduler.py requeue --frame-refused`: results the frame check refused by mistake merge again (libmodbus run-1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import function_facts as ff
import spec_kb
import wp_scheduler as S
from conftest import write_json
from test_wp_scheduler import Sim, load, negotiation_waiting_to_merge, request_store, tasks, units, wp_report

pytestmark = pytest.mark.unit

NEGOTIATION = "negotiate:src/m/g.c#g"
PROVER = "prove:src/m/a.c#a"
CODE = "(int *p)\n{\n    *p = 0;\n    return 0;\n}\n"
STRONG_NO_ENSURES = "/*@ requires \\valid(p);\n    assigns *p \\from \\nothing;\n*/\n"
STRONG = "/*@ requires \\valid(p);\n    assigns *p \\from \\nothing;\n    ensures R1: n >= 1;\n*/\n"
WEAK = "/*@ requires \\valid(p);\n    assigns \\nothing;\n*/\n"
REFUSAL = (
    "frame-preservation check failed:\n  src/m/g.c: projected frame clause missing or weakened: "
    "'assigns *p \\\\from \\\\nothing;' (no assigns clause covering location '*p' with \\from superset of [])"
)
FRAME = {"loc": "*p", "from": [], "clause": "assigns *p \\from \\nothing;", "source": "ast"}
ALIAS = {"loc": "ctx_tcp->t_id", "from": [], "clause": "assigns ctx_tcp->t_id \\from \\nothing;", "source": "ast"}


@pytest.fixture
def sim(run_dir, monkeypatch):
    return Sim(run_dir, monkeypatch)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def lay_out(sim, aid, fn, tree, base, work, frame=FRAME):
    """The real inputs of the frame check: the agent's scratch, the shared tree and the projected skeleton."""
    file = f"src/m/{fn}.c"
    write_text(sim.run_dir / f"agents/{aid}/scratch/base/{file}", f"{base}int {fn}{CODE}")
    write_text(sim.run_dir / f"agents/{aid}/scratch/work/{file}", f"{work}int {fn}{CODE}")
    write_text(sim.run_dir / f"workspace/work/{file}", f"{tree}int {fn}{CODE}")
    facts = sim.run_dir / "workspace/reports/facts/m.json"
    known = json.loads(facts.read_text(encoding="utf-8"))["functions"] if facts.is_file() else {}
    skeleton = {"status": "ok", "separated": [], "assigns": [frame], "notes": []}
    known[f"{file}#{fn}"] = {"name": fn, "frame_skeleton": skeleton}
    write_json(facts, {"schema": ff.FACTS_SCHEMA, "module": "m", "status": "ok", "functions": known})


def rejected_negotiation(sim, tree=STRONG, base=STRONG, work=STRONG):
    """The negotiator's merge was refused twice by the frame check; its requests were rejected."""
    negotiation_waiting_to_merge(sim)
    lay_out(sim, "negotiate-g", "g", tree, base, work)
    state = S.load_schedule()
    task = state["tasks"][NEGOTIATION]
    task["merge_attempts"] = 2
    S._resolve_negotiation(state, task, False, f"merge failed: {REFUSAL}", {"errors": []})
    S.save_schedule(state)
    return task["requests"][0]


def blocked_prover(sim, tree=STRONG, base=STRONG, work=STRONG, frame=FRAME):
    """The prover's merge was refused twice by the frame check; its unit holds WP evidence, so it is really parked."""
    sim.build({"a": ("src/m/a.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.prover("prove-a", "a", "src/m/a.c")
    S.cmd_complete("prove-a")
    lay_out(sim, "prove-a", "a", tree, base, work, frame)
    rel = "agents/prove-a/scratch/parent_wp/a.json"
    write_json(sim.run_dir / rel, wp_report("a", "workspace/work/src/m/a.c", "analysis_error", "oom_killed"))
    S.DEPS.ingest_wp([Path(rel)])
    state = S.load_schedule()
    task = state["tasks"][PROVER]
    task["merge_attempts"] = 2
    S._park_units(task, "prove-a", f"merge_failed: {REFUSAL[:160]}")
    S._finish(state, task, "blocked", "merge_failed", reason=REFUSAL)
    S.save_schedule(state)


def status_of(rid):
    return next(r for r in request_store() if r["id"] == rid)["status"]


def test_a_no_op_negotiation_the_old_check_refused_goes_back_to_the_merge_queue_and_merges(sim, capsys):
    rid = rejected_negotiation(sim)
    dispatches = tasks()[NEGOTIATION]["dispatches"]

    assert S.main(["requeue", "--frame-refused"]) == 0
    out = json.loads(capsys.readouterr().out)

    assert [(e["task"], e["agent_id"]) for e in out["merge_restored"]] == [(NEGOTIATION, "negotiate-g")]
    assert out["requests_restored"] == [rid] and out["left"] == [] and out["errors"] == []
    task = tasks()[NEGOTIATION]
    assert (task["state"], task["outcome"], task["last_reason"]) == ("merge_queued", None, None)
    assert (task["merge"]["agent_id"], task["merge_attempts"], task["dispatches"]) == ("negotiate-g", 0, dispatches)

    assert S.cmd_merge_pending(force=True)["merged"][0]["agent_id"] == "negotiate-g"
    assert tasks()[NEGOTIATION]["outcome"] == "applied"
    assert status_of(rid) == "verified_and_applied"


def test_the_requests_of_a_restored_negotiation_reopen_and_lose_their_stored_dead_ends(sim):
    rid = rejected_negotiation(sim)
    store = spec_kb.kb_dir_of(sim.run_dir / "workspace") / spec_kb.OBSTRUCTIONS_FILE
    write_json(store, {"items": [{"id": f"req:{rid}"}, {"id": "req:other"}]})
    assert status_of(rid) == "rejected_by_callee"

    S.cmd_requeue_frame_refused()

    assert status_of(rid) == "pending"
    assert [i["id"] for i in json.loads(store.read_text(encoding="utf-8"))["items"]] == ["req:other"]


def test_a_pending_caller_waits_for_the_restored_negotiation(sim):
    rejected_negotiation(sim)
    state = S.load_schedule()
    state["tasks"]["prove:src/m/f.c#f"].update(state="pending", outcome=None)
    S.save_schedule(state)

    out = S.cmd_requeue_frame_refused()

    assert out["merge_restored"][0]["callers"] == {"prove:src/m/f.c#f": "pending"}
    assert NEGOTIATION in tasks()["prove:src/m/f.c#f"]["extra_deps"]


def test_sync_and_next_preserve_hold_callers_extra_deps_when_callee_is_merged_and_filed(sim):
    """`_sync` must not drop `_hold_callers`'s hold even when the callee proof is already done and in `contract_requests`."""
    rid = rejected_negotiation(sim)
    state = S.load_schedule()
    assert state["tasks"]["prove:src/m/g.c#g"]["state"] == "done"
    state["tasks"]["prove:src/m/f.c#f"].update(
        state="pending",
        outcome=None,
        contract_requests={"src/m/g.c#g": rid},
    )
    S.save_schedule(state)

    out = S.cmd_requeue_frame_refused()

    assert out["merge_restored"][0]["callers"] == {"prove:src/m/f.c#f": "pending"}
    assert NEGOTIATION in tasks()["prove:src/m/f.c#f"]["extra_deps"]
    assert NEGOTIATION in tasks()["prove:src/m/f.c#f"]["held_negotiations"]

    # Subsequent read-only status and persisting next keep the hold and do NOT dispatch f before the merge finishes.
    assert "prove:src/m/f.c#f" not in [r["task"] for r in S.cmd_status()["ready"]]
    nxt = S.cmd_next("auto", prepare=True)
    assert nxt["tasks"] == []
    assert NEGOTIATION in tasks()["prove:src/m/f.c#f"]["extra_deps"]

    # Once the restored negotiation merges (reaches TERMINAL), the hold clears and f is dispatched.
    assert S.cmd_merge_pending(force=True)["merged"][0]["agent_id"] == "negotiate-g"
    assert tasks()[NEGOTIATION]["state"] == "done"
    nxt_after = S.cmd_next("auto", prepare=True)
    assert [t["task"] for t in nxt_after["tasks"]] == ["prove:src/m/f.c#f"]
    assert NEGOTIATION not in tasks()["prove:src/m/f.c#f"]["extra_deps"]
    assert "held_negotiations" not in tasks()["prove:src/m/f.c#f"]


def test_a_result_that_really_weakens_a_clause_stays_rejected(sim):
    rid = rejected_negotiation(sim, work=WEAK)
    before = tasks()[NEGOTIATION]

    out = S.cmd_requeue_frame_refused()

    assert out["merge_restored"] == [] and out["requests_restored"] == []
    assert [e["task"] for e in out["left"]] == [NEGOTIATION]
    assert "frame-preservation check failed" in out["left"][0]["reason"]
    assert "assigns *p" in out["left"][0]["reason"]
    assert tasks()[NEGOTIATION] == before and status_of(rid) == "rejected_by_callee"


def test_a_tree_that_lacks_the_clause_keeps_a_no_op_result_rejected(sim):
    rid = rejected_negotiation(sim, tree=WEAK, base=WEAK, work=WEAK)
    out = S.cmd_requeue_frame_refused()
    assert out["merge_restored"] == [] and "frame-preservation" in out["left"][0]["reason"]
    assert status_of(rid) == "rejected_by_callee"


def test_a_blocked_prover_whose_clause_names_a_local_alias_stays_blocked(sim):
    blocked_prover(sim, frame=ALIAS)
    before = tasks()[PROVER]
    unit_before = units()["src/m/a.c#a::rte"]

    out = S.cmd_requeue_frame_refused()

    assert out["merge_restored"] == [] and [e["task"] for e in out["left"]] == [PROVER]
    assert "ctx_tcp->t_id" in out["left"][0]["reason"]
    assert tasks()[PROVER] == before and units()["src/m/a.c#a::rte"] == unit_before


def test_a_blocked_prover_covered_by_an_applied_negotiation_stays_blocked(sim):
    blocked_prover(sim)
    state = S.load_schedule()
    prover = state["tasks"][PROVER]
    state["tasks"]["negotiate:src/m/a.c#a"] = {**prover, "id": "negotiate:src/m/a.c#a", "kind": "negotiate"}
    state["tasks"]["negotiate:src/m/a.c#a"].update(state="done", outcome="applied", last_reason=None)
    S.save_schedule(state)
    before = tasks()[PROVER]

    out = S.cmd_requeue_frame_refused()

    assert out["merge_restored"] == [] and "negotiate:src/m/a.c#a" in out["left"][0]["reason"]
    assert tasks()[PROVER] == before


def test_a_blocked_prover_that_passes_now_gets_its_units_back(sim):
    blocked_prover(sim)
    assert units()["src/m/a.c#a::rte"]["status"] == "blocked"

    out = S.cmd_requeue_frame_refused()

    assert out["merge_restored"] == [{"task": PROVER, "agent_id": "prove-a", "units": ["src/m/a.c#a::rte"]}]
    task = tasks()[PROVER]
    assert (task["state"], task["outcome"], task["merge_attempts"], task["dispatches"]) == ("merge_queued", None, 0, 1)
    assert (units()["src/m/a.c#a::rte"]["status"], units()["src/m/a.c#a::rte"]["agent_id"]) == (
        "in_progress",
        "prove-a",
    )
    assert S.cmd_merge_pending(force=True)["merged"][0]["agent_id"] == "prove-a"


def test_a_second_run_changes_nothing(sim):
    rid = rejected_negotiation(sim)
    S.cmd_requeue_frame_refused()
    before = (tasks(), load("workspace/reports/strengthen_requests.json")["requests"])

    again = S.cmd_requeue_frame_refused()

    assert again["merge_restored"] == again["requests_restored"] == again["errors"] == []
    assert (tasks(), load("workspace/reports/strengthen_requests.json")["requests"]) == before
    assert status_of(rid) == "pending"


def test_a_task_ended_for_another_reason_is_not_touched(sim):
    rid = rejected_negotiation(sim)
    state = S.load_schedule()
    state["tasks"][NEGOTIATION]["last_reason"] = "merge failed: parent WP check returned status='unproven_goals_remain'"
    S.save_schedule(state)
    before = tasks()[NEGOTIATION]

    out = S.cmd_requeue_frame_refused()

    assert out["merge_restored"] == out["left"] == [] and tasks()[NEGOTIATION] == before
    assert status_of(rid) == "rejected_by_callee"


def test_a_negotiation_whose_requests_have_moved_on_is_left_alone(sim):
    rid = rejected_negotiation(sim)
    S.DEPS.resolve_request(S.REQUESTS, rid, "pending", "")
    before = tasks()[NEGOTIATION]

    out = S.cmd_requeue_frame_refused()

    assert out["merge_restored"] == out["requests_restored"] == []
    assert [e["task"] for e in out["left"]] == [NEGOTIATION] and rid in out["left"][0]["reason"]
    assert tasks()[NEGOTIATION] == before and status_of(rid) == "pending"


@pytest.mark.parametrize("live", ["running", "merge_queued", "merging"])
def test_a_task_running_or_queued_is_left_alone(sim, live):
    rid = rejected_negotiation(sim)
    state = S.load_schedule()
    state["tasks"][NEGOTIATION].update(state=live, outcome=None)
    S.save_schedule(state)
    before = tasks()[NEGOTIATION]

    out = S.cmd_requeue_frame_refused()

    assert out["merge_restored"] == [] and live in out["left"][0]["reason"]
    assert tasks()[NEGOTIATION] == before and status_of(rid) == "rejected_by_callee"


def test_a_negotiation_is_left_while_the_callees_own_proof_is_merging(sim):
    rid = rejected_negotiation(sim)
    state = S.load_schedule()
    state["tasks"]["prove:src/m/g.c#g"]["state"] = "merge_queued"
    S.save_schedule(state)

    out = S.cmd_requeue_frame_refused()

    assert out["merge_restored"] == [] and "merges first" in out["left"][0]["reason"]
    assert status_of(rid) == "rejected_by_callee"


def test_noop_negotiation_lacking_needed_clause_marks_request_rejected_with_merge_note(sim):
    """A no-op merge whose merged contract satisfies the frame but lacks `needed_clause` must not mark the request applied."""
    rid = rejected_negotiation(sim, tree=STRONG_NO_ENSURES, base=STRONG_NO_ENSURES, work=STRONG_NO_ENSURES)

    rq = S.cmd_requeue_frame_refused()
    assert [(e["task"], e["agent_id"]) for e in rq["merge_restored"]] == [(NEGOTIATION, "negotiate-g")]

    merged = S.cmd_merge_pending(force=True)
    assert merged["merged"][0]["agent_id"] == "negotiate-g"
    task = tasks()[NEGOTIATION]
    assert task["outcome"] == "rejected"
    assert "no-op merge" in str(task.get("last_reason") or "")
    missing_notes = (task.get("merge_notes") or {}).get("noop_missing_clauses") or []
    assert len(missing_notes) == 1
    assert missing_notes[0]["request"] == rid
    assert "n >= 1" in missing_notes[0]["missing"]
    assert merged["merged"][0]["merge_notes"]["noop_missing_clauses"] == missing_notes

    req = next(r for r in request_store() if r["id"] == rid)
    assert req["status"] == "rejected_by_callee"
    assert "no-op merge" in req["resolution_note"]
    assert "n >= 1" in req["resolution_note"]
    # Caller stays blocked because its requested clause was never added.
    assert tasks()["prove:src/m/f.c#f"]["state"] == "blocked"
