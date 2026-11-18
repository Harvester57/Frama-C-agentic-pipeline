"""wp_scheduler keeps what a merge result says beside `ok` (`merge_notes` on the task): the transient merge result
is otherwise lost when the call returns, and with it what the merged contract no longer says."""

from __future__ import annotations

import pytest

import wp_scheduler as S
from test_wp_scheduler import Sim, tasks

pytestmark = pytest.mark.unit

TASK = "prove:src/m/a.c#a"
CHANGES = {
    "function": "a",
    "files": ["src/m/a.c"],
    "available": True,
    "reason": "",
    "had_contract": True,
    "baseline_assigns_in": [],
    "candidate_assigns_in": [],
    "assigns_removed": [],
    "ensures_removed": [{"behavior": "default!", "clauses": ["\\result >= -1"]}],
    "behaviors_removed": [],
    "completeness_removed": [],
}
NO_FRAME = {"assigns_clause": "absent", "assigns_vcs_proven": False, "baseline_had_assigns": False}


@pytest.fixture
def sim(run_dir, monkeypatch):
    return Sim(run_dir, monkeypatch)


def _queue_a(sim) -> None:
    sim.build({"a": ("src/m/a.c", "m", [])})
    S.cmd_init()
    S.cmd_next("auto", prepare=True)
    sim.prover("prove-a", "a", "src/m/a.c")
    assert S.cmd_complete("prove-a")["action"] == "queued_for_merge"


def _merge_saying(sim, monkeypatch, **extra) -> dict:
    plain = sim.merge_agent_batch

    def batch(run_dir, entries, **kw):
        res = plain(run_dir, entries, **kw)
        for merged in res["merged"]:
            merged.update(extra)
        return res

    monkeypatch.setattr(S.DEPS, "merge_agent_batch", batch)
    return S.cmd_merge_pending(force=True)


def test_a_removed_ensures_and_a_missing_frame_stay_on_the_merged_task(sim, monkeypatch) -> None:
    _queue_a(sim)
    out = _merge_saying(sim, monkeypatch, contract_changes=CHANGES, frame_state=NO_FRAME)
    expected = {"contract_changes": CHANGES, "frame_state": NO_FRAME}
    assert out["merged"][0]["merge_notes"] == expected
    task = tasks()[TASK]
    assert (task["state"], task["outcome"]) == ("done", "merged")
    assert task["merge_notes"] == expected


def test_a_merge_that_removed_nothing_and_proved_its_frame_leaves_no_note(sim, monkeypatch) -> None:
    _queue_a(sim)
    unchanged = {**CHANGES, "ensures_removed": [], "baseline_assigns_in": ["default!"]}
    proved = {"assigns_clause": "present", "assigns_vcs_proven": True, "baseline_had_assigns": True}
    out = _merge_saying(sim, monkeypatch, contract_changes=unchanged, frame_state=proved)
    assert "merge_notes" not in out["merged"][0]
    assert "merge_notes" not in tasks()[TASK]
