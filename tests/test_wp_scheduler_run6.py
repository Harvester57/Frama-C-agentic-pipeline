"""Phase-3 scheduler fixes from the QCBOR run-6 review: breaker slots, stale repair evidence, contract-less callees."""

from __future__ import annotations

import test_wp_scheduler as base
import wp_scheduler as S
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
    assert "prove:src/m/p.c#p" in picked  # the other slot keeps the normal order


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
