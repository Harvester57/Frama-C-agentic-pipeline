"""
REPORT.md and FINDINGS-DETAIL.md say two things that were recorded and shown nowhere:

- a confirmed finding that counts a reproducer whose failure the parent's replay could not compare with
  the candidate's (`ledger.py ingest-verifier` writes an evidence entry starting `Failure identity not
  compared:`), and
- a merge that was accepted with a note (`merge_notes` of a task in `state/wp_schedule.json`,
  wp_scheduler._keep_merge_notes): a contract that lost an `ensures`, a behavior or a completeness clause
  against the one it replaced, a function proved without a frame, a merge no guardrail ran for.

The finding of the first part is written by the ledger itself from libmodbus run-1's recorded replay of
the timeout candidate (tests/fixtures/replay_identity, staged by tests/test_verifier_replay_identity.py).
The merge notes are hand-built: the scheduler that writes them is not on this branch. Their shapes are
the ones tests/test_scheduler_merge_notes.py and tests/test_merge_guardrail_status.py of that change
assert the scheduler stores.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import generate_report as G
import ledger as L
import test_report as trep
import test_verifier_replay_identity as tvr
from conftest import confirmed_record, sorted_findings, write_json

pytestmark = pytest.mark.unit

MN_SCHEDULE = "state/wp_schedule.json"
MN_CHANGES = {
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
MN_NO_FRAME = {"assigns_clause": "absent", "assigns_vcs_proven": False, "baseline_had_assigns": False}
MN_NOT_RUN = {"status": "not_run", "reason": "module m has no harness sidecar with sources"}


def _task(function: str, **notes: object) -> dict:
    task = {"id": f"prove:src/m/{function}.c#{function}", "kind": "prove", "function": function, "state": "done"}
    return {**task, "merge_notes": notes} if notes else task


def _schedule(run: Path, *tasks: dict) -> None:
    write_json(run / MN_SCHEDULE, {"tasks": {t["id"]: t for t in tasks}})


def _hang_finding(run_dir: Path) -> dict:
    """The record `ingest-verifier` writes for the recorded hang: confirmed, its only reproducer not compared."""
    candidates = tvr._stage(run_dir, tvr.MODBUS)
    rec = tvr._record(
        run_dir,
        candidates[tvr.HANG],
        tvr.HANG_REPORT,
        tvr.HANG_INPUT,
        fingerprint=tvr.SEND_MSG,
        location={"file": "src/modbus.c", "line": 210, "function": "send_msg"},
        property={"kind": "timeout", "predicate": "send_msg does not terminate when the backend send keeps failing"},
    )
    out = tvr._ingest(run_dir, tvr.HANG, rec, [tvr.HANG_REPORT], reason="The hang is the retry loop of send_msg.")
    assert out["decision"] == "confirmed"
    return tvr._findings(run_dir)[tvr.SEND_MSG]


# ------------------------------------------------------------------ failure identity not compared


def test_the_detail_of_a_finding_says_its_reproducer_was_not_compared(run_dir):
    rec = _hang_finding(run_dir)
    assert len(G.identity_not_compared(rec)) == 1
    detail = G.render_findings_detail([rec], run_dir)
    assert "**Failure identity not compared.** For 1 reproducer(s) the parent's replay failed, but not on" in detail
    assert "does not show that the failure is this finding's" in detail
    # The ledger's own entry stays in the evidence block, with the replay report it cites.
    assert f"`{tvr.REPLAY_DIR}/{tvr.HANG_REPORT}`: {L.IDENTITY_NOT_COMPARED}" in detail


def test_the_report_counts_and_marks_the_findings_not_compared(run_dir, tmp_path_factory):
    """REPORT.md of a whole run whose confirmed finding carries the entry the ledger wrote for the hang."""
    note = next(e for e in _hang_finding(run_dir)["evidence"] if e["description"].startswith(L.IDENTITY_NOT_COMPARED))
    run = tmp_path_factory.mktemp("report_run")
    trep.build_run(run)
    findings = json.loads((run / "findings.json").read_text(encoding="utf-8"))
    confirmed = next(r for r in findings if r["verdict"] == "confirmed")
    confirmed["evidence"].append(note)
    write_json(run / note["tool_output"], {})
    write_json(run / "findings.json", findings)
    G.generate(run, run)
    section = (run / "REPORT.md").read_text(encoding="utf-8").split("## 3. Confirmed findings")[1].split("## 4.")[0]
    assert "**1 of 1 confirmed finding(s) count a reproducer whose failure identity was not compared**" in section
    assert f"Each is marked below: `{confirmed['fingerprint']}`." in section
    assert "- **Failure identity not compared:** for 1 reproducer(s) the parent's replay failed" in section
    assert "**Failure identity not compared.**" in (run / "FINDINGS-DETAIL.md").read_text(encoding="utf-8")


def test_a_finding_whose_reproducers_were_compared_is_not_marked(tmp_path):
    """Control: the same run without the entry."""
    trep.build_run(tmp_path)
    G.generate(tmp_path, tmp_path)
    for name in ("REPORT.md", "FINDINGS-DETAIL.md"):
        text = (tmp_path / name).read_text(encoding="utf-8")
        assert "identity" not in text and "not compared" not in text, name


def test_the_mark_survives_the_merge_of_findings_at_one_sink():
    """Two records of one failure, the entry on the second: the merged record of the report keeps it."""
    first = confirmed_record()
    second = json.loads(json.dumps(first))
    second["fingerprint"] = "src/snmp/ber.c#ber_decode_len::rte::9999999999"
    second["evidence"].append(
        {**second["evidence"][0], "description": f"{L.IDENTITY_NOT_COMPARED} the parent's replay of x failed, but ..."}
    )
    merged = G.dedupe_findings_for_report(sorted_findings(first, second))
    assert len(merged) == 1 and len(G.identity_not_compared(merged[0])) == 1
    assert G.identity_not_compared(first) == [] and G.identity_not_compared_text(first) is None


# ------------------------------------------------------------------ merges accepted with a note


def test_the_report_lists_what_a_merged_contract_no_longer_states(tmp_path):
    trep.build_run(tmp_path)
    _schedule(
        tmp_path,
        _task("a", contract_changes=MN_CHANGES, frame_state=MN_NO_FRAME),
        _task("b", guardrail=MN_NOT_RUN),
        _task("clean"),
    )
    G.generate(tmp_path, tmp_path)
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    section = report.split("## 5. Assurance summary")[1].split("## 6.")[0]
    assert "Merges accepted with a note (2; `merge_notes` of the tasks in `state/wp_schedule.json`)" in section
    line_a = next(ln for ln in section.splitlines() if ln.startswith("- `a`:"))
    assert "`ensures` removed in the contract outside named behaviors: `\\result >= -1`" in line_a
    assert "shows no frame for the whole function (`assigns` clause: `absent`)" in line_a
    assert "the contract it replaced had one" not in line_a
    line_b = next(ln for ln in section.splitlines() if ln.startswith("- `b`:"))
    assert "no guardrail pass (`not_run`: module m has no harness sidecar with sources)" in line_b
    assert "`clean`" not in section


def test_a_run_without_notes_or_without_a_schedule_lists_no_merge(tmp_path, tmp_path_factory):
    """Control: no schedule file, and one whose merged tasks carry no note."""
    trep.build_run(tmp_path)
    G.generate(tmp_path, tmp_path)
    assert "Merges accepted with a note" not in (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    other = tmp_path_factory.mktemp("clean_schedule")
    trep.build_run(other)
    _schedule(other, _task("clean"))
    G.generate(other, other)
    assert "Merges accepted with a note" not in (other / "REPORT.md").read_text(encoding="utf-8")


def test_every_kind_of_removal_and_an_uncompared_contract_are_said():
    changes = {
        **MN_CHANGES,
        "assigns_removed": [{"behavior": "bad", "clauses": ["*out"]}],
        "ensures_removed": [{"behavior": "ok", "clauses": ["\\result == 0", "*out  ==\n 1"]}],
        "behaviors_removed": ["live"],
        "completeness_removed": ["complete behaviors ok, bad"],
    }
    blind = {"function": "c", "available": False, "reason": "the baseline contract did not parse"}
    lines = G.merge_notes_lines(
        [
            {"task": "t1", "function": "a", "notes": {"contract_changes": changes}},
            {"task": "t2", "function": "c", "notes": {"contract_changes": blind}},
            {"task": "t3", "function": "d", "notes": {"frame_state": {**MN_NO_FRAME, "baseline_had_assigns": True}}},
        ]
    )
    text = "\n".join(lines)
    assert "`assigns` removed in behavior `bad`: `*out`" in text
    assert "`ensures` removed in behavior `ok`: `\\result == 0`; `*out == 1`" in text
    assert "behaviors removed: `live`" in text and "removed: `complete behaviors ok, bad`" in text
    assert "- `c`: the merged contract could not be compared with the one it replaced (the baseline contract" in text
    assert "(`assigns` clause: `absent`) (the contract it replaced had one)" in text


@pytest.mark.parametrize(
    "state",
    [
        None,
        [],
        "text",
        {"tasks": None},
        {"tasks": {"t": None, "u": {"merge_notes": "x"}, "v": {"merge_notes": {}}}},
        {"tasks": [{"id": "w", "function": "f", "merge_notes": {"contract_changes": "?", "guardrail": 3}}]},
    ],
)
def test_a_schedule_of_another_shape_is_read_as_saying_nothing(tmp_path, state):
    if state is not None:
        write_json(tmp_path / MN_SCHEDULE, state)
    assert G.merge_notes_lines(G.load_merge_notes(tmp_path)) == []


def test_a_schedule_that_is_not_json_is_read_as_saying_nothing(tmp_path):
    path = tmp_path / MN_SCHEDULE
    path.parent.mkdir(parents=True)
    path.write_text("{not json", encoding="utf-8", newline="\n")
    assert G.load_merge_notes(tmp_path) == []


def test_the_tasks_may_be_a_list(tmp_path):
    write_json(tmp_path / MN_SCHEDULE, {"tasks": [_task("b", guardrail=MN_NOT_RUN)]})
    notes = G.load_merge_notes(tmp_path)
    assert [(n["function"], n["task"]) for n in notes] == [("b", "prove:src/m/b.c#b")]
    assert len(G.merge_notes_lines(notes)) == 4
