"""
S19 (mpack run-4): a `negotiate:<callee>` task for a callee with no prove task (Eva closed it) was dispatched at
once, before its module's architect and gate and before the prove tasks of the callee's own callees: the
negotiating prover proved the callee against contract-less callees and stalled, burning the round caps.
"""

from __future__ import annotations

import json
from pathlib import Path

import ledger as L
import test_wp_scheduler as base
import wp_scheduler as S
from conftest import write_json
from test_wp_scheduler import Sim, ids, tasks

sim = base.sim  # the shared fixture

NEG_B = "negotiate:src/m/b.c#b"
PROVE_A = "prove:src/m/a.c#a"
PROVE_C = "prove:src/m/c.c#c"


def _eva_closed(file: str, fn: str, module: str = "m") -> dict:
    """A unit Eva covered: the function gets no prove task, but a negotiation may still give it a contract."""
    write_json(Path(f"workspace/reports/eva/{module}.json"), {"status": "ok", "module": module})
    return base.unit(
        file,
        fn,
        "rte",
        status="covered",
        module=module,
        tier=base.TIER1,
        evidence=[base.evidence(tool_output=f"workspace/reports/eva/{module}.json")],
    )


def _chain(sim: Sim, functions: dict, closed: tuple[str, ...] = ("b",), sidecars: dict | None = None) -> None:
    sim.build(
        functions,
        units=[
            _eva_closed(file, n, mod) if n in closed else base.unit(file, n, "rte", module=mod, tier=base.TIER1)
            for n, (file, mod, _c) in functions.items()
        ],
        sidecars=sidecars,
    )


CHAIN = {  # a -> b -> c; b is Eva-closed (no prove task)
    "a": ("src/m/a.c", "m", ["b"]),
    "b": ("src/m/b.c", "m", ["c"]),
    "c": ("src/m/c.c", "m", []),
}


def _drain(sim: Sim, rounds: int = 20) -> list[str]:
    """Hand out and complete every task until the run is done; returns the task ids in dispatch order."""
    order: list[str] = []
    for _ in range(rounds):
        nxt = S.cmd_next("auto", prepare=True)
        if not nxt["tasks"] and nxt["done"]:
            return order
        assert nxt["tasks"], f"the schedule stalled with nothing to hand out: {_open()}"
        for job in nxt["tasks"]:
            order.append(job["task"])
            aid, kind, fn = job["agent_id"], job["kind"], job.get("function")
            if kind == "arch":
                sim.architect(aid, job["header"])
            elif kind == "breaker":
                sim.breaker(aid, fn, job["file"])
            elif kind == "negotiate":
                sim.prover(aid, fn, job["file"], status="stalled_after_k_retries")
            else:
                sim.prover(aid, fn, job["file"])
            S.cmd_complete(aid)
        S.cmd_merge_pending(force=True)
    raise AssertionError(f"the run did not drain: {_open()}")


def _open() -> dict:
    return {tid: (t["state"], S._deps(t)) for tid, t in tasks().items() if t["state"] not in S.TERMINAL}


def test_a_negotiation_for_an_eva_closed_callee_waits_for_the_prove_task_of_its_own_callee(sim):
    _chain(sim, CHAIN)
    S.cmd_init()
    neg = tasks()[NEG_B]
    assert PROVE_C in neg["deps"] and "gate:m" in neg["deps"]
    handed = ids(S.cmd_next("auto", prepare=True))
    assert PROVE_C in handed and NEG_B not in handed
    assert NEG_B not in base.ready()

    sim.finish("prove-c", "c", "src/m/c.c")
    assert NEG_B in ids(S.cmd_next("auto", prepare=True))


def test_a_negotiation_waits_for_the_architect_and_the_gate_of_its_module(sim):
    _chain(sim, {**CHAIN, "d": ("src/m/d.c", "m", [])}, sidecars={"m": {"header": "src/m/m.h"}})
    fp = sim.eva_candidate("m", "src/m/d.c", "d")
    # The ingest of that report withdrew b's cover (the report has no property for b): restore it.
    rows = base.load("coverage-ledger.json")
    for row in rows:
        if row["function"] == "b":
            row["status"] = "covered"
            row["evidence"] = [base.evidence(tool_output="workspace/reports/eva/m.json")]
    write_json(Path("coverage-ledger.json"), rows)
    S.cmd_init()
    neg = tasks()[NEG_B]
    assert {"arch:m", "gate:m", PROVE_C} <= set(neg["deps"])

    # An open crash candidate of the module holds the gate: its verifier and the architect run, not the negotiation.
    assert sorted(ids(S.cmd_next("auto", prepare=True))) == ["arch:m", f"verify:{fp}"]
    sim.architect("arch-m", "src/m/m.h")
    S.cmd_complete("arch-m")
    assert NEG_B not in base.ready()  # the gate is still closed
    ver = tasks()[f"verify:{fp}"]["agent_id"]
    L.cmd_scaffold_verifier(fp, "needs_validation", ver, out_path=Path(f"agents/{ver}/scratch/result.json"))
    S.cmd_complete(ver)
    handed = ids(S.cmd_next("auto", prepare=True))
    assert PROVE_C in handed and NEG_B not in handed  # the gate is open, c is now being proved
    sim.finish("prove-c", "c", "src/m/c.c")
    assert NEG_B in ids(S.cmd_next("auto", prepare=True))


def test_a_negotiation_waits_for_the_architect_of_its_module(sim):
    _chain(sim, CHAIN, sidecars={"m": {"header": "src/m/m.h"}})
    S.cmd_init()
    assert "arch:m" in tasks()[NEG_B]["deps"]
    assert ids(S.cmd_next("auto", prepare=True)) == ["arch:m"]  # c waits on the architect too
    assert NEG_B not in base.ready()


def _legacy(mutate) -> None:
    path = Path("state/wp_schedule.json")
    state = json.loads(path.read_text(encoding="utf-8"))
    mutate(state["tasks"][NEG_B])
    write_json(path, state)


def test_a_reconcile_adds_the_missing_deps_to_a_pending_legacy_negotiation(sim):
    _chain(sim, CHAIN)
    S.cmd_init()
    _legacy(lambda t: t.update(deps=[]))
    assert tasks()[NEG_B]["deps"] == []
    S.cmd_init(reconcile=True)
    assert PROVE_C in tasks()[NEG_B]["deps"]
    assert NEG_B not in base.ready()


def test_a_reconcile_leaves_the_deps_of_a_running_negotiation_alone(sim):
    _chain(sim, CHAIN)
    S.cmd_init()
    _legacy(lambda t: t.update(deps=[], state="running", agent_id="negotiate-b"))
    S.cmd_init(reconcile=True)
    neg = tasks()[NEG_B]
    assert neg["state"] == "running" and neg["deps"] == []


def test_a_caller_callee_chain_drains_in_dependency_order(sim):
    _chain(sim, CHAIN)
    S.cmd_init()
    order = _drain(sim)
    assert order.index(PROVE_C) < order.index(NEG_B) < order.index(PROVE_A)


def test_a_negotiation_never_waits_on_a_callee_that_calls_back_into_it(sim):
    """b (Eva-closed) and c call each other; a calls b. c waits on negotiate:b: negotiate:b must not wait on c."""
    _chain(
        sim,
        {
            "a": ("src/m/a.c", "m", ["b"]),
            "b": ("src/m/b.c", "m", ["c"]),
            "c": ("src/m/c.c", "m", ["b"]),
        },
    )
    S.cmd_init()
    assert PROVE_C not in tasks()[NEG_B]["deps"]
    order = _drain(sim)
    assert {NEG_B, PROVE_A, PROVE_C} <= set(order)


def test_a_negotiation_never_waits_on_a_callee_whose_cone_reaches_its_waiting_caller(sim):
    """a -> b (Eva-closed) -> c -> a: c's proof waits on a, which waits on negotiate:b."""
    _chain(
        sim,
        {
            "a": ("src/m/a.c", "m", ["b"]),
            "b": ("src/m/b.c", "m", ["c"]),
            "c": ("src/m/c.c", "m", ["a"]),
        },
    )
    S.cmd_init()
    assert PROVE_C not in tasks()[NEG_B]["deps"]
    order = _drain(sim)
    assert {NEG_B, PROVE_A, PROVE_C} <= set(order)


def test_a_negotiation_waits_on_the_open_negotiation_of_an_eva_closed_callee_of_its_callee(sim):
    """a -> b -> c, both b and c Eva-closed: negotiate:b waits on negotiate:c once a's chain files it."""
    _chain(sim, {**CHAIN, "e": ("src/m/e.c", "m", ["c"])}, closed=("b", "c"))
    S.cmd_init()
    t = tasks()
    assert "negotiate:src/m/c.c#c" in t  # e asks for c's contract
    assert "negotiate:src/m/c.c#c" in t[NEG_B]["deps"]
    order = _drain(sim)
    assert order.index("negotiate:src/m/c.c#c") < order.index(NEG_B) < order.index(PROVE_A)
