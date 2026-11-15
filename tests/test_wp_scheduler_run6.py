"""Phase-3 scheduler fixes from the QCBOR run-6 review: breaker slots, stale repair evidence, contract-less callees."""

from __future__ import annotations

import os
from pathlib import Path

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
