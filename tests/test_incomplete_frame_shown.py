"""A callee frame that leaves a write out says so, and the verifier step shows what the ledger did not compare.

The frame skeleton lists under `unprojected` the writes it could not state as an `assigns` clause (a loop index
with no bound at entry, a location the kernel names through a temporary). The contract request the scheduler
files for a contract-less callee copied only the `assigns` clauses, and the brief's header called the listed
clauses "a REQUIRED minimum" with the gap only in a note below: a frame shown to a prover or a negotiator read
as the callee's whole frame.

The skeletons are computed from the facts recorded in libmodbus run-1 (tests/fixtures/libmodbus_run1_frame).
"""

from __future__ import annotations

from pathlib import Path

import pytest

import function_facts as ff
import ledger as L
import workspace_overlay
import wp_scheduler as S
from test_frame_skeleton_expressible import (
    ENABLE_QUIRKS,
    READ_REGISTERS,
    RTU_SEND_PRE,
    SET_BITS,
    _run1,
    _skeleton,
)
from test_wp_scheduler import Sim

pytestmark = pytest.mark.unit


def _clause(monkeypatch, skel: dict | None) -> str:
    monkeypatch.setattr(workspace_overlay, "_function_frame_skeleton", lambda *a, **k: skel)
    return S._callee_frame_clause(S.Ctx(), "src/m.c", "callee", "m")


# ---------------------------------------------------------------------------
# wp_scheduler._callee_frame_clause: the `needed_clause` of a filed contract request
# ---------------------------------------------------------------------------


def test_the_requested_frame_names_the_write_the_skeleton_could_not_state(monkeypatch) -> None:
    skel = _skeleton(READ_REGISTERS)
    assert [a["loc"] for a in skel["assigns"]] == ["errno"] and len(skel["unprojected"]) == 1
    clause = _clause(monkeypatch, skel)
    assert clause.startswith(skel["assigns"][0]["clause"])
    assert "INCOMPLETE" in clause and "`*(dest + i)`" in clause and "must cover" in clause


def test_a_frame_with_only_unstated_writes_is_not_the_generic_request(monkeypatch) -> None:
    skel = _skeleton(SET_BITS)
    assert skel["assigns"] == [] and [u["lval"] for u in skel["unprojected"]] == ["*(dest + i)"]
    clause = _clause(monkeypatch, skel)
    assert clause.startswith(S.DEFAULT_CONTRACT_CLAUSE) and clause != S.DEFAULT_CONTRACT_CLAUSE
    # No line of the facts' file in it: the text is the request's identity (contract_negotiator dedups on it).
    assert "also writes `*(dest + i)`, which" in clause


def test_a_write_the_kernel_names_through_a_temporary_is_named_by_its_root(monkeypatch) -> None:
    skel = _skeleton(RTU_SEND_PRE)
    assert [(u["lval"], u["root"]) for u in skel["unprojected"]] == [(None, "req")]
    assert "memory reached from `req`" in _clause(monkeypatch, skel)


def test_a_complete_frame_is_requested_as_before(monkeypatch) -> None:
    skel = _skeleton(ENABLE_QUIRKS)
    assert skel["assigns"] and skel["unprojected"] == []
    assert _clause(monkeypatch, skel) == " ".join(a["clause"] for a in skel["assigns"])
    assert _clause(monkeypatch, None) == S.DEFAULT_CONTRACT_CLAUSE


# ---------------------------------------------------------------------------
# function_facts._render_skeleton: the header of the brief's section
# ---------------------------------------------------------------------------


def _section(key: str) -> str:
    record = dict(_run1()["functions"][key])
    record["frame_skeleton"] = _skeleton(key)
    return ff.render_section(record, function=key.split("#", 1)[1])


def _header(section: str) -> str:
    return next(line for line in section.splitlines() if line.startswith("**Projected frame skeleton"))


def test_the_header_of_an_incomplete_skeleton_says_it_is_incomplete() -> None:
    header = _header(_section(READ_REGISTERS))
    assert "REQUIRED minimum" in header
    assert "INCOMPLETE" in header and "1 write" in header and "`assigns` must also cover" in header


def test_a_skeleton_with_only_unstated_writes_does_not_say_no_clause_is_required() -> None:
    record = dict(_run1()["functions"][RTU_SEND_PRE])
    record["frame_skeleton"] = _skeleton(RTU_SEND_PRE)
    assert record["frame_skeleton"]["assigns"] == [] and record["frame_skeleton"]["separated"] == []
    header = _header(ff.render_section(record, function="_modbus_rtu_send_msg_pre"))
    assert "no clause is required" not in header
    assert "INCOMPLETE" in header and "`assigns` must also cover" in header


def test_the_header_of_a_complete_skeleton_is_unchanged() -> None:
    header = _header(_section(ENABLE_QUIRKS))
    assert "REQUIRED minimum" in header and "INCOMPLETE" not in header


# ---------------------------------------------------------------------------
# wp_scheduler._complete_verifier: `reproducers_not_compared`
# ---------------------------------------------------------------------------


@pytest.fixture
def sim(run_dir, monkeypatch):
    return Sim(run_dir, monkeypatch)


def _verifier_done(sim, monkeypatch, extra: dict) -> dict:
    sim.build({"f": ("src/m/f.c", "m", [])}, sidecars={"m": {}})
    fp = sim.eva_candidate("m", "src/m/f.c", "f")
    S.cmd_init()
    ver = S.cmd_next("auto", prepare=True)["tasks"][0]
    L.cmd_scaffold_verifier(
        fp, "rejected", ver["agent_id"], out_path=Path(f"agents/{ver['agent_id']}/scratch/result.json")
    )
    real = S.DEPS.ingest_verifier
    monkeypatch.setattr(S.DEPS, "ingest_verifier", lambda *a, **k: {**real(*a, **k), **extra})
    return S.cmd_complete(ver["agent_id"])


def test_verifier_completion_shows_the_reproducers_the_ledger_did_not_compare(sim, monkeypatch) -> None:
    uncompared = ["agents/verifier-1/scratch/repro-1"]
    out = _verifier_done(sim, monkeypatch, {"reproducers_not_compared": uncompared})
    assert out["action"] == "ingested" and out["reproducers_not_compared"] == uncompared


def test_verifier_completion_without_uncompared_reproducers_has_no_such_key(sim, monkeypatch) -> None:
    out = _verifier_done(sim, monkeypatch, {})
    assert out["action"] == "ingested" and "reproducers_not_compared" not in out
