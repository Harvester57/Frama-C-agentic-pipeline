"""A Function Prover keeps its best candidate: pairing, rank, the stop rule, restore, and the oracle and scheduler hooks."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

import prover_candidates as PC
import resources
import run_eacsl_fuzz as R
import run_wp_function as W
import wp_scheduler as S
from conftest import write_json
from framac_common import ArtifactError
from resources import Budget
from test_tool_sizing import FakeFramaC
from test_wp_scheduler import Sim, tasks

AID = "prove-f"
FN = "f"
C_REL = "src/m/f.c"
H_REL = "src/m/f.h"
BASE_C = "int f(int x) { return x; }\n"
BASE_H = "int f(int x);\n"
PASSED = "passed_dynamic_oracle"
SCRIPT = Path(PC.__file__).resolve()


def annotated(tag: str) -> str:
    """The source with a contract: every tag is a distinct candidate."""
    return f"/*@ requires {tag}: x >= 0;\n  @ assigns \\nothing;\n  @*/\n{BASE_C}"


def annotated_header(tag: str) -> str:
    return f"/*@ requires {tag}: x >= 0; */\n{BASE_H}"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def note(out_json: Path, oracle: str, report: dict, digest: str | None) -> Any:
    return PC.note_oracle(out_json, oracle, report, digest)


def restore(scratch: Path) -> Any:
    return PC.restore_best(scratch)


class Prover:
    """The scratch tree of a prover, and fake oracles reporting through the real entry points."""

    def __init__(self, run_dir: Path, aid: str = AID, fn: str = FN, header: bool = True):
        self.aid, self.fn = aid, fn
        self.scratch = run_dir / "agents" / aid / "scratch"
        for tree in ("work", "base"):
            (self.scratch / tree / C_REL).parent.mkdir(parents=True, exist_ok=True)
            (self.scratch / tree / C_REL).write_text(BASE_C, encoding="utf-8")
            (self.scratch / tree / H_REL).write_text(BASE_H, encoding="utf-8")
        budget: dict[str, Any] = {
            "agent_id": aid,
            "function": fn,
            "file": C_REL,
            "max_retries": 4,
            "max_wp_invocations": 50,
            "max_wall_clock_s": 900,
            "wp_invocations": 0,
            "first_wp_at": None,
        }
        if header:
            budget["header"] = H_REL
        write_json(self.scratch / ".prover_budget.json", budget)
        self.wp_path = self.scratch / f"wp_{fn}.json"
        self.guard_path = self.scratch / f"guard_{fn}.json"

    def edit(self, text: str, rel: str = C_REL) -> None:
        (self.scratch / "work" / rel).write_text(text, encoding="utf-8")

    def read(self, rel: str = C_REL) -> str:
        return (self.scratch / "work" / rel).read_text(encoding="utf-8")

    def wp_report(
        self, status: str = "unproven_goals_remain", failed: int = 1, proved: int = 5, sound: bool = True, **extra: Any
    ) -> dict:
        return {
            "status": status,
            "function": self.fn,
            "file": str(self.scratch / "work" / C_REL),
            "total_goals": failed + proved,
            "proven_count": proved,
            "proven_under_hyp_count": 0,
            "unproven_count": failed,
            "soundness": {"ok": sound},
            "by_obligation_class": {"rte": {"proven": proved, "proven_under_hyp": 0, "unproven": failed}},
            "unproven_goals": [{"obligation_class": "rte", "kind": "assert", "line": 3, "annotation": "p != 0"}]
            * min(failed, 1),
            **extra,
        }

    def wp(self, *args: Any, **kwargs: Any) -> Any:
        digest = PC.tracked_digest(self.scratch)
        report = self.wp_report(*args, **kwargs)
        write_json(self.wp_path, report)
        return note(self.wp_path, "wp", report, digest)

    def guard(self, status: str = PASSED) -> Any:
        digest = PC.tracked_digest(self.scratch)
        report = {"mode": "guardrail", "status": status}
        write_json(self.guard_path, report)
        return note(self.guard_path, "guardrail", report, digest)

    def iterate(self, tag: str, *args: Any, guard: str = PASSED, **kwargs: Any) -> dict:
        """One iteration on new annotations; the block is the one of the oracle that finished second."""
        self.edit(annotated(tag))
        first = self.guard(guard)
        assert first is not None and first["next_action"] == "wait_for_other_oracle"
        block = self.wp(*args, **kwargs)
        assert block is not None and block["evaluated"] is True
        return block

    def state(self) -> dict:
        return load(self.scratch / "candidates" / "state.json")


@pytest.fixture
def prover(run_dir):
    return Prover(run_dir)


def tree_bytes(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


# ---------------------------------------------------------------------------
# Pairing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("first", ["wp", "guard"])
def test_a_candidate_is_evaluated_by_whichever_oracle_finishes_second(prover, first):
    prover.edit(annotated("a"))
    runs = [prover.wp, prover.guard] if first == "wp" else [prover.guard, prover.wp]
    assert runs[0]() == {
        "recorded": True,
        "candidate": 1,
        "evaluated": False,
        "eligible": None,
        "rank": None,
        "best": None,
        "best_rank": None,
        "progress": None,
        "next_action": "wait_for_other_oracle",
    }
    block = runs[1]()
    assert block == {
        "recorded": True,
        "candidate": 1,
        "evaluated": True,
        "eligible": True,
        "rank": {"failed": 1, "proved": 5, "invalid": 0},
        "best": 1,
        "best_rank": {"failed": 1, "proved": 5, "invalid": 0},
        "progress": True,
        "next_action": "continue",
    }
    json.dumps(block)
    assert (prover.scratch / "candidates/best/work" / C_REL).read_text(encoding="utf-8") == annotated("a")
    assert load(prover.scratch / f"candidates/best/wp_{FN}.json")["status"] == "unproven_goals_remain"
    assert load(prover.scratch / f"candidates/best/guard_{FN}.json")["status"] == PASSED
    assert not (prover.scratch / ".framac-locks").exists()


def test_reports_on_different_digests_never_pair(prover):
    prover.edit(annotated("a"))
    assert prover.wp(status="all_proven", failed=0, proved=9)["candidate"] == 1
    prover.edit(annotated("b"))
    block = prover.guard()
    assert (block["candidate"], block["evaluated"], block["best"]) == (2, False, None)
    assert PC.restore_best(prover.scratch) is None


def _run_oracles_in_threads(prover: Prover, failed: int, proved: int) -> dict[str, dict]:
    barrier = threading.Barrier(2)
    blocks: dict[str, dict] = {}

    def run(name: str, call: Any, **kwargs: Any) -> None:
        barrier.wait()
        blocks[name] = call(**kwargs)

    threads = [
        threading.Thread(target=run, args=("wp", prover.wp), kwargs={"failed": failed, "proved": proved}),
        threading.Thread(target=run, args=("guard", prover.guard)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return blocks


def test_parallel_oracles_in_threads_evaluate_each_candidate_exactly_once(prover):
    rounds = 6
    for n in range(rounds):
        prover.edit(annotated(f"r{n}"))
        blocks = _run_oracles_in_threads(prover, failed=rounds - n, proved=n + 1)
        assert sorted(b["evaluated"] for b in blocks.values()) == [False, True]
        assert {b["candidate"] for b in blocks.values()} == {n + 1}
        assert sum(b["next_action"] == "wait_for_other_oracle" for b in blocks.values()) == 1
    state = prover.state()
    assert state["best"] == rounds and len(state["candidates"]) == rounds
    assert len(state["history"]) == 2 * rounds  # no lost update
    assert not (prover.scratch / ".framac-locks").exists()


NOTE_IN_A_PROCESS = """
import json, sys
from pathlib import Path
import prover_candidates as PC
out, oracle, report, digest = Path(sys.argv[1]), sys.argv[2], json.loads(sys.argv[3]), sys.argv[4]
out.write_text(json.dumps(report), encoding="utf-8")
print(json.dumps(PC.note_oracle(out, oracle, report, digest)))
"""


def test_parallel_oracles_in_processes_pair_under_the_scratch_lock(prover):
    prover.edit(annotated("a"))
    digest = PC.tracked_digest(prover.scratch)
    assert digest is not None
    env = {**os.environ, "PYTHONPATH": str(SCRIPT.parent)}
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", NOTE_IN_A_PROCESS, str(path), oracle, json.dumps(report), digest],
            stdout=subprocess.PIPE,
            text=True,
            env=env,
        )
        for path, oracle, report in (
            (prover.wp_path, "wp", prover.wp_report()),
            (prover.guard_path, "guardrail", {"mode": "guardrail", "status": PASSED}),
        )
    ]
    blocks = [json.loads(p.communicate(timeout=120)[0]) for p in procs]
    assert all(p.returncode == 0 for p in procs)
    assert sorted(b["evaluated"] for b in blocks) == [False, True]
    assert prover.state()["best"] == 1 and len(prover.state()["history"]) == 2


# ---------------------------------------------------------------------------
# Eligibility and rank
# ---------------------------------------------------------------------------


def test_rejected_by_the_guardrail_is_never_best_even_with_the_best_proof_ratio(prover):
    assert prover.iterate("a", failed=4, proved=6)["best"] == 1
    # The stronger `requires` excludes inputs: everything is proved, and it is false on a real input.
    block = prover.iterate("stronger", "all_proven", 0, 10, guard="rejected_overconstrained")
    assert block["eligible"] is False and block["rank"] is None and block["progress"] is None
    assert block["best"] == 1 and block["best_rank"] == {"failed": 4, "proved": 6, "invalid": 0}
    assert block["next_action"] == "continue"  # the prover must fix it: not a stall
    assert PC.restore_best(prover.scratch) == {
        "restored": True,
        "best": 1,
        "rank": {"failed": 4, "proved": 6, "invalid": 0},
    }
    assert prover.read() == annotated("a")
    assert load(prover.guard_path)["status"] == PASSED


def _failure(predicate: str, **extra: Any) -> dict:
    return {
        "file": "/framac-run/agents/prove-f/scratch/work/src/m/f.c",
        "line": 1,
        "function": FN,
        "kind": "precondition",
        "alarm_kind": None,
        "is_rte": False,
        "label": "pos",
        "predicate": predicate,
        **extra,
    }


def guard_report(prover: Prover, tag: str, status: str, failure: dict | None) -> None:
    """One candidate whose guardrail report carries a parsed E-ACSL failure."""
    prover.edit(annotated(tag))
    digest = PC.tracked_digest(prover.scratch)
    report = {"mode": "guardrail", "status": status, "reason": f"why {tag}", "failure": failure}
    write_json(prover.guard_path, report)
    note(prover.guard_path, "guardrail", report, digest)


def test_a_refuting_guardrail_keeps_its_reason_and_the_trimmed_failure(prover):
    guard_report(prover, "a", "rejected_overconstrained", _failure("x >= 0"))
    summary = prover.state()["candidates"][PC.tracked_digest(prover.scratch)]["guardrail"]
    assert summary == {
        "status": "rejected_overconstrained",
        "reason": "why a",
        "failure": {
            "function": FN,
            "line": 1,
            "kind": "precondition",
            "label": "pos",
            "predicate": "x >= 0",
            "is_rte": False,
        },
    }
    guard_report(prover, "b", PASSED, None)
    assert prover.state()["candidates"][PC.tracked_digest(prover.scratch)]["guardrail"] == {"status": PASSED}


def test_refuted_clauses_dedupes_by_predicate_and_ignores_code_faults(prover):
    guard_report(prover, "a", "rejected_overconstrained", _failure("x >= 0"))
    guard_report(prover, "b", "rejected_overconstrained", _failure("x >= 0", line=7))
    guard_report(prover, "c", "code_fault", _failure("rte: x + 1 <= 2147483647", is_rte=True))
    guard_report(prover, "d", "rejected_overconstrained", _failure("10 / x > 0", annotation_rte=True))
    guard_report(prover, "e", "rejected_overconstrained", _failure("10 / x > 0"))
    guard_report(prover, "f", "rejected_overconstrained", None)
    clauses = PC.refuted_clauses(prover.scratch)
    assert [(c["predicate"], c["annotation_rte"], c["candidate"]) for c in clauses] == [
        ("x >= 0", False, 1),
        ("10 / x > 0", True, 4),
        ("10 / x > 0", False, 5),
    ]
    assert clauses[0] == {
        "predicate": "x >= 0",
        "label": "pos",
        "line": 1,
        "kind": "precondition",
        "annotation_rte": False,
        "candidate": 1,
    }
    assert PC.status(prover.scratch)["refuted_clauses"] == clauses


def test_refuted_clauses_reads_the_report_of_a_summary_recorded_before_failures_were_kept(prover):
    guard_report(prover, "a", "rejected_overconstrained", _failure("x >= 0"))
    state = prover.state()
    for cand in state["candidates"].values():
        cand["guardrail"] = {"status": "rejected_overconstrained"}
    write_json(prover.scratch / PC.STATE_FILE, state)
    assert [c["predicate"] for c in PC.refuted_clauses(prover.scratch)] == ["x >= 0"]


def test_refuted_clauses_is_empty_on_a_missing_or_malformed_state(prover):
    assert PC.refuted_clauses(prover.scratch) == []
    (prover.scratch / PC.CANDIDATES_DIR).mkdir(parents=True)
    (prover.scratch / PC.STATE_FILE).write_text("{not json", encoding="utf-8")
    assert PC.refuted_clauses(prover.scratch) == []
    write_json(prover.scratch / PC.STATE_FILE, {"schema": PC.SCHEMA_VERSION, "candidates": {"d": {"id": 1}}})
    assert PC.refuted_clauses(prover.scratch) == []


@pytest.mark.parametrize(
    ("guard", "wp"),
    [
        ("rejected_overconstrained", {}),
        ("code_fault", {}),
        ("guardrail_error", {}),
        ("compile_error", {}),
        ("sandbox_unavailable", {}),
        (PASSED, {"status": "analysis_error"}),
        (PASSED, {"status": "acsl_syntax_error"}),
        (PASSED, {"status": "wp_aborted", "sound": False}),
        (PASSED, {"status": "unsound_proof", "sound": False}),
        (PASSED, {"status": "unproven_goals_remain", "sound": False}),
    ],
)
def test_ineligible_candidates_are_never_best_never_compared_and_never_stalls(prover, guard, wp):
    block = prover.iterate("first", guard=guard, **wp)
    assert (block["eligible"], block["best"], block["next_action"]) == (False, None, "continue")
    assert PC.restore_best(prover.scratch) is None
    assert prover.iterate("second", failed=3, proved=3)["best"] == 2
    for tag in ("third", "fourth"):  # any number of them: only the retry budget bounds these
        block = prover.iterate(tag, guard=guard, failed=0, proved=99, **wp)
        assert (block["eligible"], block["best"], block["next_action"]) == (False, 2, "continue")
    # They do not raise the bar either: the next eligible candidate only competes with eligible ones.
    block = prover.iterate("fifth", failed=4, proved=4)
    assert (block["progress"], block["best"], block["next_action"]) == (True, 2, "continue")


def test_a_wp_report_without_counts_is_ineligible(prover):
    prover.edit(annotated("a"))
    digest = PC.tracked_digest(prover.scratch)
    report = {"status": "acsl_syntax_error", "function": FN, "file": str(prover.scratch / "work" / C_REL)}
    write_json(prover.wp_path, report)
    assert note(prover.wp_path, "wp", report, digest)["next_action"] == "wait_for_other_oracle"
    block = prover.guard()
    assert (block["eligible"], block["rank"], block["next_action"]) == (False, None, "continue")
    assert prover.state()["history"][-1]["failed"] is None


def test_a_candidate_with_no_goals_cannot_outrank_a_real_one(prover):
    prover.iterate("a", failed=3, proved=7)
    block = prover.iterate("empty", failed=0, proved=0)
    assert (block["eligible"], block["best"]) == (False, 1)


def test_rank_is_fewer_failed_then_more_proved_and_a_tie_keeps_the_earlier(prover):
    assert prover.iterate("a", failed=3, proved=5)["best"] == 1
    assert prover.iterate("b", failed=2, proved=1)["best"] == 2  # fewer failed beats more proved
    assert prover.iterate("c", failed=2, proved=4)["best"] == 3  # same failed, more proved
    block = prover.iterate("d", failed=2, proved=4)
    assert block["best"] == 3 and block["best_rank"] == {"failed": 2, "proved": 4, "invalid": 0}
    assert (prover.scratch / "candidates/best/work" / C_REL).read_text(encoding="utf-8") == annotated("c")


def test_proved_counts_goals_proved_under_hypotheses(prover):
    block = prover.iterate("a", failed=1, proved=2, proven_under_hyp_count=3)
    assert block["rank"] == {"failed": 1, "proved": 5, "invalid": 0}


def test_rank_tiebreak_prefers_fewer_invalid_invariants(prover):
    """SESpec largest-valid-subset: among equal failed counts, a candidate whose failures are
    only provability (invalid=0) outranks one carrying invalid invariants (_established/_preserved)."""
    invalid_goals = [
        {
            "obligation_class": "l2_termination",
            "kind": "loop_invariant",
            "line": 4,
            "annotation": "typed_f_loop_invariant_bad_preserved",
        },
        {
            "obligation_class": "l2_termination",
            "kind": "loop_invariant",
            "line": 4,
            "annotation": "typed_f_loop_invariant_worse_established",
        },
    ]
    block = prover.iterate("a", failed=2, proved=3, unproven_goals=invalid_goals)
    assert block["rank"] == {"failed": 2, "proved": 3, "invalid": 2} and block["best"] == 1
    # Same failed count, but only provability failures: ranks higher despite fewer proved.
    block = prover.iterate("b", failed=2, proved=1)
    assert block["rank"] == {"failed": 2, "proved": 1, "invalid": 0}
    assert block["best"] == 2 and block["best_rank"] == {"failed": 2, "proved": 1, "invalid": 0}
    assert (prover.scratch / "candidates/best/work" / C_REL).read_text(encoding="utf-8") == annotated("b")


# ---------------------------------------------------------------------------
# Progress and the stop rule
# ---------------------------------------------------------------------------


def test_identical_results_stop(prover):
    first = prover.iterate("a", failed=2, proved=5)
    assert (first["progress"], first["next_action"]) == (True, "continue")
    second = prover.iterate("b", failed=2, proved=5)
    assert (second["progress"], second["next_action"], second["best"]) == (False, "restore_best_and_finish", 1)


def test_failed_up_and_proved_up_continues_and_the_best_stays_the_lower_failed(prover):
    prover.iterate("a", failed=1, proved=10)
    block = prover.iterate("b", failed=3, proved=14)
    assert (block["progress"], block["next_action"]) == (True, "continue")
    assert block["rank"] == {"failed": 3, "proved": 14, "invalid": 0}
    assert block["best"] == 1 and block["best_rank"] == {"failed": 1, "proved": 10, "invalid": 0}


def test_failed_up_and_proved_down_stops(prover):
    prover.iterate("a", failed=1, proved=10)
    block = prover.iterate("b", failed=2, proved=9)
    assert (block["progress"], block["next_action"], block["best"]) == (False, "restore_best_and_finish", 1)


def test_proved_is_compared_with_the_highest_of_any_earlier_eligible_candidate(prover):
    prover.iterate("a", failed=1, proved=10)
    assert prover.iterate("b", failed=3, proved=14)["next_action"] == "continue"
    block = prover.iterate(
        "c", failed=2, proved=12
    )  # above the best's 10, below the highest 14, and ranks below the best
    assert (block["progress"], block["next_action"], block["best"]) == (False, "restore_best_and_finish", 1)


def test_ranking_above_the_best_is_progress_even_with_fewer_proved(prover):
    prover.iterate("a", failed=5, proved=20)
    block = prover.iterate("b", failed=4, proved=2)
    assert (block["progress"], block["next_action"], block["best"]) == (True, "continue", 2)


def test_the_first_eligible_candidate_is_progress_after_any_number_of_ineligible_ones(prover):
    prover.iterate("a", "all_proven", 0, 50, guard="rejected_overconstrained")
    block = prover.iterate("b", failed=9, proved=1)
    assert (block["progress"], block["next_action"], block["best"]) == (True, "continue", 2)


def test_all_proven_is_finished(prover):
    prover.iterate("a", failed=2, proved=5)
    block = prover.iterate("b", "all_proven", 0, 7)
    assert (block["next_action"], block["best"], block["progress"]) == ("finished", 2, True)


def test_all_proven_is_finished_even_when_the_rank_does_not_improve(prover):
    assert prover.iterate("a", "all_proven", 0, 7)["next_action"] == "finished"
    # For example the --smoke-tests run the brief asks for, on the same files.
    block = prover.wp("all_proven", 0, 7)
    assert (block["candidate"], block["progress"], block["next_action"]) == (1, False, "finished")
    assert prover.iterate("b", "all_proven", 0, 6)["next_action"] == "finished"


# ---------------------------------------------------------------------------
# Identity: the digest, and which reports count
# ---------------------------------------------------------------------------


def test_files_changed_during_a_run_are_not_recorded(prover):
    prover.edit(annotated("a"))
    before = PC.tracked_digest(prover.scratch)
    prover.edit(annotated("b"))
    report = prover.wp_report()
    block = note(prover.wp_path, "wp", report, before)
    assert block["recorded"] is False and "changed" in block["reason"]
    assert (block["candidate"], block["evaluated"], block["next_action"]) == (None, False, "continue")
    assert not (prover.scratch / "candidates").exists()


def test_a_header_changed_during_a_run_is_not_recorded_and_later_runs_still_are(prover):
    prover.iterate("a", failed=2, proved=2)
    before = PC.tracked_digest(prover.scratch)
    prover.edit(annotated_header("h"), H_REL)
    block = note(prover.guard_path, "guardrail", {"status": PASSED}, before)
    assert block["recorded"] is False and block["best"] == 1
    assert prover.guard()["candidate"] == 2


def test_no_digest_before_the_run_is_not_recorded(prover):
    block = note(prover.wp_path, "wp", prover.wp_report(), None)
    assert block["recorded"] is False and "could not be read" in block["reason"]


def test_the_digest_covers_the_header_only_when_the_budget_tracks_one(run_dir):
    with_header = Prover(run_dir, "with-header", header=True)
    without_header = Prover(run_dir, "without-header", header=False)
    for p, moves in ((with_header, True), (without_header, False)):
        before = PC.tracked_digest(p.scratch)
        assert before is not None
        p.edit(annotated_header("h"), H_REL)
        assert (PC.tracked_digest(p.scratch) != before) is moves
    budget = load(with_header.scratch / ".prover_budget.json")
    budget["header"] = None  # prepare_agent may have no header to name
    write_json(with_header.scratch / ".prover_budget.json", budget)
    assert PC.tracked_digest(with_header.scratch) == PC.tracked_digest(without_header.scratch)


@pytest.mark.parametrize(
    "budget",
    [
        {"file": ""},
        {"file": "../../../etc/passwd"},
        {"file": "/etc/passwd"},
        {"file": C_REL, "header": "../f.h"},
        {"file": "src/m/missing.c"},
        {"file": 7},
    ],
)
def test_no_digest_without_a_safe_tracked_source_file(prover, budget):
    write_json(prover.scratch / ".prover_budget.json", {"function": FN, **budget})
    assert PC.tracked_digest(prover.scratch) is None
    block = note(prover.wp_path, "wp", prover.wp_report(), "digest")
    assert block["recorded"] is False


def test_a_budget_being_rewritten_by_a_parallel_wp_run_is_read_again(prover, monkeypatch):
    budget_path = prover.scratch / ".prover_budget.json"
    good = budget_path.read_text(encoding="utf-8")
    expected = PC.tracked_digest(prover.scratch)
    budget_path.write_text("", encoding="utf-8")  # run_wp_function.py rewrites it in place
    sleeps: list[float] = []

    def the_rewrite_finishes(seconds: float) -> None:
        sleeps.append(seconds)
        budget_path.write_text(good, encoding="utf-8")

    monkeypatch.setattr(PC.time, "sleep", the_rewrite_finishes)
    assert PC.tracked_digest(prover.scratch) == expected and sleeps == [PC.BUDGET_READ_RETRY_S]


def test_a_budget_that_stays_unreadable_means_no_prover_scratch(prover, monkeypatch):
    (prover.scratch / ".prover_budget.json").write_text("{torn", encoding="utf-8")
    sleeps: list[float] = []
    monkeypatch.setattr(PC.time, "sleep", sleeps.append)
    assert PC.tracked_digest(prover.scratch) is None
    assert len(sleeps) == PC.BUDGET_READ_ATTEMPTS - 1


def test_reports_other_than_the_provers_own_are_ignored(prover, run_dir):
    report = prover.wp_report()
    digest = PC.tracked_digest(prover.scratch)
    for path, oracle in (
        (prover.scratch / "parent_wp" / f"{FN}.json", "wp"),
        (prover.scratch / f"parent_guard_{FN}.json", "guardrail"),
        (prover.scratch / f"wp_{FN}_prop.json", "wp"),
        (prover.scratch / "other.json", "wp"),
        (prover.scratch / f"guard_{FN}.json", "wp"),  # the name of the other oracle
        (prover.scratch / f"wp_{FN}.json", "guardrail"),
        (prover.scratch / "wp" / f"wp_{FN}.json", "wp"),
        (prover.scratch / "work" / f"wp_{FN}.json", "wp"),
        (prover.scratch.parent / f"wp_{FN}.json", "wp"),
        (prover.scratch.parent / "artifacts" / f"wp_{FN}.json", "wp"),
        (run_dir / "workspace" / "reports" / "wp" / f"wp_{FN}.json", "wp"),
        (run_dir / f"wp_{FN}.json", "wp"),
    ):
        assert note(path, oracle, report, digest) is None, path
    assert not (prover.scratch / "candidates").exists()


def test_reports_of_another_function_or_without_a_budget_are_ignored(prover, run_dir):
    digest = PC.tracked_digest(prover.scratch)
    other = prover.scratch / "wp_g.json"
    assert note(other, "wp", {**prover.wp_report(), "function": "g"}, digest) is None
    assert note(prover.wp_path, "wp", {**prover.wp_report(), "function": "g"}, digest) is None
    assert note(prover.scratch / "guard_g.json", "guardrail", {"status": PASSED}, digest) is None
    assert note(prover.wp_path, "wp", {**prover.wp_report(), "budget_exhausted": True}, digest) is None
    (prover.scratch / ".prover_budget.json").unlink()
    assert PC.tracked_digest(prover.scratch) is None
    assert note(prover.wp_path, "wp", prover.wp_report(), digest) is None
    assert PC.digest_before_run(prover.wp_path) is None
    assert PC.digest_before_run(run_dir / "elsewhere" / "wp_f.json") is None
    assert not (prover.scratch / "candidates").exists()


def test_an_unsafe_function_name_in_the_budget_is_ignored(prover):
    budget = load(prover.scratch / ".prover_budget.json")
    for bad in ("", "../f", "a/b", 7, None):
        write_json(prover.scratch / ".prover_budget.json", {**budget, "function": bad})
        assert note(prover.scratch / f"wp_{bad}.json", "wp", {}, "digest") is None


def test_a_wp_run_on_another_file_is_not_credited_to_the_tracked_files(prover):
    prover.iterate("a", failed=2, proved=3)
    digest = PC.tracked_digest(prover.scratch)
    report = {**prover.wp_report("all_proven", 0, 9), "file": str(prover.scratch / "work" / "src/m/copy.c")}
    block = note(prover.wp_path, "wp", report, digest)
    assert block["recorded"] is False and "copy.c" in block["reason"] and block["best_rank"]["failed"] == 2
    relative = {**prover.wp_report(), "file": f"agents/{AID}/scratch/work/{C_REL}"}
    assert note(prover.wp_path, "wp", relative, digest)["recorded"] is True


def test_an_unknown_oracle_is_a_programming_error(prover):
    with pytest.raises(ValueError):
        note(prover.wp_path, "eva", {}, None)


# ---------------------------------------------------------------------------
# Another run on the same files
# ---------------------------------------------------------------------------


def test_a_rerun_after_an_analysis_error_completes_the_same_candidate(prover):
    block = prover.iterate("a", "analysis_error", reason="oom_killed")
    assert (block["candidate"], block["eligible"], block["next_action"]) == (1, False, "continue")
    block = prover.wp(failed=2, proved=5)
    assert (block["candidate"], block["eligible"], block["progress"], block["best"]) == (1, True, True, 1)
    assert prover.state()["next_id"] == 2


def test_a_better_rerun_on_the_same_files_updates_the_reports_of_the_best(prover):
    prover.iterate("a", failed=2, proved=5)
    block = prover.wp(failed=1, proved=6)  # a longer --timeout, say
    assert (block["candidate"], block["progress"], block["best_rank"]) == (
        1,
        True,
        {"failed": 1, "proved": 6, "invalid": 0},
    )
    assert load(prover.scratch / f"candidates/best/wp_{FN}.json")["unproven_count"] == 1


def test_a_worse_rerun_on_the_same_files_keeps_the_better_reports(prover):
    prover.iterate("a", failed=1, proved=6)
    block = prover.wp(failed=3, proved=4)
    assert (block["progress"], block["next_action"], block["best"]) == (False, "restore_best_and_finish", 1)
    assert restore(prover.scratch)["rank"] == {"failed": 1, "proved": 6, "invalid": 0}
    assert load(prover.wp_path)["unproven_count"] == 1


@pytest.mark.parametrize(
    "failure",
    [
        {"status": "analysis_error", "sound": False},
        {"status": "acsl_syntax_error"},
        {"status": "wp_aborted", "sound": False},
    ],
)
def test_a_wp_rerun_that_decides_nothing_leaves_the_best_alone(prover, failure):
    prover.iterate("a", failed=1, proved=6)
    block = prover.wp(**failure)
    assert (block["eligible"], block["best"], block["next_action"]) == (False, 1, "continue")
    assert restore(prover.scratch)["rank"] == {"failed": 1, "proved": 6, "invalid": 0}


@pytest.mark.parametrize(
    "refute",
    [
        lambda p: p.wp("unsound_proof", 0, 7, sound=False),  # a failed --smoke-tests after all_proven
        lambda p: p.wp("unproven_goals_remain", 1, 6, sound=False),
        lambda p: p.guard("rejected_overconstrained"),
        lambda p: p.guard("code_fault"),
    ],
)
def test_a_later_verdict_against_the_best_files_removes_them_from_best(prover, refute):
    assert prover.iterate("a", "all_proven", 0, 7)["best"] == 1
    block = refute(prover)
    assert (block["candidate"], block["eligible"], block["best"], block["best_rank"]) == (1, False, None, None)
    assert not (prover.scratch / "candidates/best").exists()
    assert PC.restore_best(prover.scratch) is None
    # What replaces it is a first eligible candidate again, and the refuted proved count no longer sets the bar.
    block = prover.iterate("b", failed=4, proved=2)
    assert (block["progress"], block["best"], block["next_action"]) == (True, 2, "continue")
    block = prover.iterate("c", failed=5, proved=3)
    assert (block["progress"], block["best"], block["next_action"]) == (True, 2, "continue")


def test_a_refuted_candidate_that_passes_again_on_the_same_files_competes_again(prover):
    prover.iterate("a", failed=1, proved=6)
    assert prover.guard("rejected_overconstrained")["best"] is None
    block = prover.guard()  # the corpus was repaired, say
    assert (block["candidate"], block["eligible"], block["best"], block["progress"]) == (1, True, 1, True)
    assert restore(prover.scratch)["best"] == 1


def test_going_back_to_earlier_files_is_the_same_candidate_and_a_stall(prover):
    prover.iterate("a", failed=1, proved=5)
    prover.iterate("b", failed=2, proved=5)
    prover.edit(annotated("a"))
    block = prover.wp(failed=1, proved=5)  # its guardrail report still stands: the files are the same
    assert (block["candidate"], block["evaluated"], block["progress"]) == (1, True, False)
    assert block["next_action"] == "restore_best_and_finish"


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


def test_restore_puts_back_files_reports_and_patch_and_is_idempotent(prover):
    prover.edit(annotated_header("best"), H_REL)
    prover.iterate("best", failed=1, proved=9, marker="best-wp")
    best_guard, best_wp = load(prover.guard_path), load(prover.wp_path)
    prover.edit(annotated_header("last"), H_REL)
    prover.iterate("last", failed=2, proved=2, guard="code_fault")

    assert PC.restore_best(prover.scratch) == {
        "restored": True,
        "best": 1,
        "rank": {"failed": 1, "proved": 9, "invalid": 0},
    }
    assert prover.read() == annotated("best") and prover.read(H_REL) == annotated_header("best")
    assert PC.tracked_digest(prover.scratch) == prover.state()["best_digest"]
    assert load(prover.wp_path)["marker"] == "best-wp" and load(prover.wp_path) == best_wp
    assert load(prover.guard_path) == best_guard
    patch = (prover.scratch / f"{FN}.patch").read_text(encoding="utf-8")
    assert f"--- a/{C_REL}\n+++ b/{C_REL}\n" in patch and f"--- a/{H_REL}\n+++ b/{H_REL}\n" in patch
    assert "+/*@ requires best: x >= 0;\n" in patch and "last" not in patch
    # What it replaced is kept: the code_fault report of the last iteration is the evidence of a defect.
    assert load(prover.scratch / f"candidates/last/guard_{FN}.json")["status"] == "code_fault"
    assert (prover.scratch / "candidates/last/work" / C_REL).read_text(encoding="utf-8") == annotated("last")
    assert (prover.scratch / "base" / C_REL).read_text(encoding="utf-8") == BASE_C

    before = tree_bytes(prover.scratch)
    assert PC.restore_best(prover.scratch) == {
        "restored": False,
        "best": 1,
        "rank": {"failed": 1, "proved": 9, "invalid": 0},
    }
    assert tree_bytes(prover.scratch) == before
    assert not (prover.scratch / ".framac-locks").exists()


def test_restore_replaces_reports_left_by_partial_runs_even_when_the_files_are_the_best(prover):
    prover.iterate("a", failed=1, proved=9)
    write_json(prover.wp_path, {"status": "unproven_goals_remain", "function": FN, "partial": True})
    assert restore(prover.scratch)["restored"] is True
    assert "partial" not in load(prover.wp_path)


def test_restore_without_state_or_without_a_best_is_none(prover, run_dir):
    assert PC.restore_best(prover.scratch) is None
    assert PC.restore_best(run_dir / "agents" / "nobody" / "scratch") is None
    assert not (prover.scratch / ".framac-locks").exists()
    prover.edit(annotated("a"))
    prover.wp()  # one oracle only
    assert PC.restore_best(prover.scratch) is None
    prover.guard("rejected_overconstrained")
    assert PC.restore_best(prover.scratch) is None
    assert prover.read() == annotated("a")


def test_restore_refuses_a_snapshot_that_is_not_the_best_candidate(prover):
    prover.iterate("a", failed=1, proved=9)
    (prover.scratch / "candidates/best/work" / C_REL).write_text("int tampered;\n", encoding="utf-8")
    prover.edit(annotated("b"))
    with pytest.raises(ArtifactError):
        PC.restore_best(prover.scratch)
    assert prover.read() == annotated("b")


def test_restore_refuses_paths_that_leave_the_scratch_tree(prover, run_dir):
    prover.iterate("a", failed=1, proved=9)
    state = prover.state()
    state["best_files"] = ["../../../evil.c"]
    write_json(prover.scratch / "candidates/state.json", state)
    with pytest.raises(ArtifactError):
        PC.restore_best(prover.scratch)
    state["best_files"], state["function"] = [C_REL, H_REL], "../evil"
    write_json(prover.scratch / "candidates/state.json", state)
    with pytest.raises(ArtifactError):
        PC.restore_best(prover.scratch)
    assert not (run_dir / "evil.c").exists() and not (prover.scratch.parent / "evil.patch").exists()


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("this platform cannot create symlinks")


def test_restore_replaces_a_symlink_instead_of_writing_through_it(prover, run_dir):
    prover.iterate("a", failed=1, proved=9)
    outside = run_dir / "coverage-ledger.json"
    outside.write_text("[]\n", encoding="utf-8")
    prover.wp_path.unlink()
    _symlink_or_skip(prover.wp_path, outside)
    assert restore(prover.scratch)["restored"] is True
    assert outside.read_text(encoding="utf-8") == "[]\n"
    assert not prover.wp_path.is_symlink() and load(prover.wp_path)["unproven_count"] == 1


def test_restore_refuses_to_write_through_a_symlinked_directory(prover, run_dir):
    prover.iterate("a", failed=1, proved=9)
    prover.edit(annotated("b"))
    outside = run_dir / "elsewhere"
    outside.mkdir()
    (outside / "f.c").write_text("int outside;\n", encoding="utf-8")
    shutil.rmtree(prover.scratch / "work" / "src" / "m")
    _symlink_or_skip(prover.scratch / "work" / "src" / "m", outside)
    with pytest.raises(ArtifactError):
        PC.restore_best(prover.scratch)
    assert (outside / "f.c").read_text(encoding="utf-8") == "int outside;\n"


def test_a_snapshot_taken_without_the_header_removes_it_on_restore(prover):
    (prover.scratch / "work" / H_REL).unlink()
    prover.iterate("a", failed=1, proved=9)
    prover.edit(annotated_header("new"), H_REL)
    prover.iterate("b", failed=2, proved=2)
    assert restore(prover.scratch)["restored"] is True
    assert not (prover.scratch / "work" / H_REL).exists()
    assert PC.tracked_digest(prover.scratch) == prover.state()["best_digest"]


def test_a_budget_without_a_header_never_touches_the_header(run_dir):
    p = Prover(run_dir, header=False)
    p.iterate("a", failed=1, proved=9)
    p.edit(annotated_header("last"), H_REL)
    p.iterate("b", failed=2, proved=2)
    PC.restore_best(p.scratch)
    assert p.read() == annotated("a") and p.read(H_REL) == annotated_header("last")


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not available")
@pytest.mark.parametrize(
    "best",
    [
        annotated("a"),
        "/*@ assigns \\nothing; */\nint f(int x) { return x; }",  # no newline at the end of the file
        "/* page */\n\f\n/*@ assigns \\nothing; */\nint f(int x) { return x; }\n",  # a form feed is not a line end
        "/*@ assigns \\nothing; */\r\nint f(int x) { return x; }\r\n",
    ],
)
def test_the_patch_applies_to_the_base_tree(prover, tmp_path, best):
    prover.edit(best)
    prover.guard()
    prover.wp()
    prover.edit(annotated("later"))
    PC.restore_best(prover.scratch)
    applied = tmp_path / "applied"
    shutil.copytree(prover.scratch / "base", applied)
    proc = subprocess.run(
        ["git", "apply", "--whitespace=nowarn", str(prover.scratch / f"{FN}.patch")],
        cwd=applied,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert (applied / C_REL).read_bytes() == (prover.scratch / "work" / C_REL).read_bytes()


def test_the_patch_is_empty_when_the_best_changed_nothing(prover):
    prover.guard()
    prover.wp()
    PC.restore_best(prover.scratch)
    assert (prover.scratch / f"{FN}.patch").read_bytes() == b""


# ---------------------------------------------------------------------------
# The oracle hooks
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_wp(monkeypatch, run_dir):
    monkeypatch.setattr(resources, "job_budget", lambda root="/": Budget(cpus=2, mem_mb=65536, source="test"))
    monkeypatch.delenv("FRAMAC_WP_WALL_TIMEOUT", raising=False)

    def install(status: str = "Unknown") -> FakeFramaC:
        fake = FakeFramaC(status=status)
        monkeypatch.setattr(W.subprocess, "run", fake)
        return fake

    return install


def wp_argv(*extra: str) -> list[str]:
    scratch = f"agents/{AID}/scratch"
    return [
        "--file",
        f"{scratch}/work/{C_REL}",
        "--function",
        FN,
        "--out-dir",
        f"{scratch}/wp",
        "--cache-dir",
        "off",
        "--no-retry-bitwise",
        "--no-retry-tail",
        "--out-json",
        f"{scratch}/wp_{FN}.json",
        *extra,
    ]


def run_wp_main(capsys, *extra: str) -> dict:
    capsys.readouterr()
    assert W.main(wp_argv(*extra)) == 0
    return json.loads(capsys.readouterr().out)


def guard_argv(prover: Prover) -> list[str]:
    return [
        "guardrail",
        "--sources",
        str(prover.scratch / "work" / C_REL),
        "--out-bin",
        str(prover.scratch / f"guard_{FN}"),
        "--corpus-dir",
        str(prover.scratch / "corpus"),
        "--scratch-dir",
        str(prover.scratch / "guard"),
        "--out-json",
        str(prover.guard_path),
    ]


def fake_guardrail(monkeypatch, status: str = PASSED) -> None:
    monkeypatch.setattr(R, "compile_eacsl_binary", lambda *a, **k: {"returncode": 0, "binary": "guard_bin"})
    monkeypatch.setattr(R, "run_guardrail_check", lambda *a, **k: {"status": status})


def test_the_wp_cli_records_a_whole_run_and_prints_the_block(prover, fake_wp, capsys):
    fake_wp()
    prover.edit(annotated("a"))
    summary = run_wp_main(capsys)
    assert summary["status"] == "unproven_goals_remain"
    assert summary["candidate"]["recorded"] is True and summary["candidate"]["next_action"] == "wait_for_other_oracle"
    assert load(prover.wp_path)["status"] == "unproven_goals_remain"
    assert "candidate" not in load(prover.wp_path)


@pytest.mark.parametrize("flags", [("--prop", "post"), ("--dump-goal",), ("--prop", "post", "--dump-goal")])
def test_the_wp_cli_never_records_partial_runs(prover, fake_wp, capsys, flags):
    fake_wp()
    prover.edit(annotated("a"))
    summary = run_wp_main(capsys, *flags)
    assert "candidate" not in summary and "candidate_note" not in summary
    assert load(prover.wp_path)["status"] == "unproven_goals_remain"  # the report is still written
    assert not (prover.scratch / "candidates").exists()


def test_the_wp_cli_does_not_record_a_run_refused_by_the_budget(prover, fake_wp, capsys):
    fake = fake_wp()
    budget = load(prover.scratch / ".prover_budget.json")
    write_json(prover.scratch / ".prover_budget.json", {**budget, "wp_invocations": 50, "max_wp_invocations": 50})
    summary = run_wp_main(capsys)
    assert summary["next_synthesis_focus"] == "budget_exhausted_write_result_json_now"
    assert "candidate" not in summary and not fake.wp_calls()
    assert not (prover.scratch / "candidates").exists()


def test_the_wp_cli_stops_on_no_progress_in_the_summary_only(prover, fake_wp, capsys, monkeypatch):
    fake_wp()
    fake_guardrail(monkeypatch)
    prover.edit(annotated("a"))
    assert R.main(guard_argv(prover)) == 0
    capsys.readouterr()
    summary = run_wp_main(capsys)
    assert summary["candidate"]["next_action"] == "continue" and summary["candidate"]["progress"] is True
    assert summary["next_synthesis_focus"] != PC.NO_PROGRESS_FOCUS

    prover.edit(annotated("b"))
    assert R.main(guard_argv(prover)) == 0
    capsys.readouterr()
    summary = run_wp_main(capsys)
    assert summary["candidate"]["next_action"] == "restore_best_and_finish"
    assert summary["next_synthesis_focus"] == "no_progress_restore_best_and_finish"
    assert load(prover.wp_path)["next_synthesis_focus"] != "no_progress_restore_best_and_finish"


def test_the_wp_cli_ignores_reports_outside_a_prover_scratch(prover, fake_wp, capsys):
    fake_wp()
    capsys.readouterr()
    assert W.main([*wp_argv(), "--out-json", f"agents/{AID}/scratch/parent_wp/{FN}.json"]) == 0
    assert "candidate" not in json.loads(capsys.readouterr().out)
    assert not (prover.scratch / "candidates").exists()


def test_a_failing_hook_never_changes_the_wp_result(prover, fake_wp, capsys, monkeypatch):
    fake_wp()

    def boom(*a: Any, **k: Any) -> None:
        raise RuntimeError("bookkeeping is broken")

    monkeypatch.setattr(PC, "note_oracle", boom)
    monkeypatch.setattr(PC, "tracked_digest", boom)
    summary = run_wp_main(capsys)
    assert summary["status"] == "unproven_goals_remain" and "candidate" not in summary
    assert "bookkeeping is broken" in summary["candidate_note"]
    assert load(prover.wp_path)["status"] == "unproven_goals_remain"


def test_a_corrupt_state_file_is_a_note_not_a_failure(prover, fake_wp, capsys):
    fake_wp()
    (prover.scratch / "candidates").mkdir()
    (prover.scratch / "candidates/state.json").write_text("{not json", encoding="utf-8")
    summary = run_wp_main(capsys)
    assert summary["status"] == "unproven_goals_remain" and "candidate_note" in summary


def test_the_guardrail_cli_records_and_prints_the_block(prover, capsys, monkeypatch):
    fake_guardrail(monkeypatch)
    prover.edit(annotated("a"))
    assert R.main(guard_argv(prover)) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == PASSED and out["candidate"]["next_action"] == "wait_for_other_oracle"
    assert "candidate" not in load(prover.guard_path)


def test_the_guardrail_cli_finishing_second_can_stop_the_prover(prover, capsys, monkeypatch):
    fake_guardrail(monkeypatch)
    prover.iterate("a", failed=1, proved=5)
    prover.edit(annotated("b"))
    prover.wp(failed=1, proved=5)
    capsys.readouterr()
    assert R.main(guard_argv(prover)) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["candidate"]["next_action"] == "restore_best_and_finish"
    assert out["next_synthesis_focus"] == PC.NO_PROGRESS_FOCUS
    assert "next_synthesis_focus" not in load(prover.guard_path)


def test_the_guardrail_cli_keeps_its_exit_code_and_ignores_other_reports(prover, capsys, monkeypatch):
    def no_sandbox(*a: Any, **k: Any) -> dict:
        raise R.SandboxUnavailable("no sandbox here")

    monkeypatch.setattr(R, "compile_eacsl_binary", no_sandbox)
    prover.edit(annotated("a"))
    assert R.main(guard_argv(prover)) == 3
    assert json.loads(capsys.readouterr().out)["candidate"]["recorded"] is True

    fake_guardrail(monkeypatch)
    assert R.main([*guard_argv(prover), "--out-json", str(prover.scratch / f"parent_guard_{FN}.json")]) == 0
    assert "candidate" not in json.loads(capsys.readouterr().out)


def test_a_failing_hook_never_changes_the_guardrail_result(prover, capsys, monkeypatch):
    fake_guardrail(monkeypatch, "rejected_overconstrained")

    def boom(*a: Any, **k: Any) -> None:
        raise RuntimeError("bookkeeping is broken")

    monkeypatch.setattr(PC, "note_oracle", boom)
    assert R.main(guard_argv(prover)) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "rejected_overconstrained" and "bookkeeping is broken" in out["candidate_note"]


def test_a_code_fault_through_the_guardrail_cli_is_ineligible(prover, capsys, monkeypatch):
    fake_guardrail(monkeypatch, "code_fault")
    prover.edit(annotated("a"))
    prover.wp()
    capsys.readouterr()
    assert R.main(guard_argv(prover)) == 0
    block = json.loads(capsys.readouterr().out)["candidate"]
    assert (block["eligible"], block["best"], block["next_action"]) == (False, None, "continue")


# ---------------------------------------------------------------------------
# The CLI
# ---------------------------------------------------------------------------


def test_cli_restore_best_and_status(prover, capsys):
    assert PC.main(["status", "--agent-id", AID]) == 0
    empty = json.loads(capsys.readouterr().out)
    assert (empty["agent_id"], empty["iterations"], empty["best"], empty["history"]) == (AID, 0, None, [])
    assert PC.main(["restore-best", "--agent-id", AID]) == 0
    assert json.loads(capsys.readouterr().out)["restored"] is False

    prover.iterate("a", failed=1, proved=9)
    prover.iterate("b", failed=1, proved=9)
    prover.edit(annotated("unrecorded"))
    assert PC.main(["restore-best", "--agent-id", AID]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "restored": True,
        "best": 1,
        "rank": {"failed": 1, "proved": 9, "invalid": 0},
    }
    assert prover.read() == annotated("a")
    assert PC.main(["status", "--agent-id", AID]) == 0
    out = json.loads(capsys.readouterr().out)
    assert (out["function"], out["iterations"], out["best"], out["highest_proved"]) == (FN, 2, 1, 9)
    entry = out["history"][-1]
    assert {k: entry[k] for k in ("id", "oracle", "failed", "proved", "evaluated", "eligible", "progress")} == {
        "id": 2,
        "oracle": "wp",
        "failed": 1,
        "proved": 9,
        "evaluated": True,
        "eligible": True,
        "progress": False,
    }
    assert (entry["wp_status"], entry["guardrail_status"]) == ("unproven_goals_remain", PASSED) and entry["digest"]
    assert [h["evaluated"] for h in out["history"]] == [False, True, False, True]


@pytest.mark.parametrize("bad", ["../x", "UPPER", "a/b", "con", ""])
def test_cli_validates_the_agent_id(run_dir, capsys, bad):
    assert PC.main(["restore-best", "--agent-id", bad]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
    assert PC.main(["status", "--agent-id", bad]) == 1


def test_cli_reports_a_broken_snapshot_as_one_json_object(prover, capsys):
    prover.iterate("a", failed=1, proved=9)
    shutil.rmtree(prover.scratch / "candidates/best")
    assert PC.main(["restore-best", "--agent-id", AID]) == 1
    assert "ArtifactError" in json.loads(capsys.readouterr().out)["error"]


def test_the_script_runs_on_its_own_from_the_run_directory(prover, run_dir):
    prover.iterate("a", failed=1, proved=9)
    prover.edit(annotated("b"))
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "restore-best", "--agent-id", AID], cwd=run_dir, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["restored"] is True and prover.read() == annotated("a")


def test_importing_the_module_pulls_in_no_pipeline_tool():
    code = (
        "import sys, prover_candidates; "
        "loaded = {'run_wp_function', 'run_eacsl_fuzz', 'wp_scheduler', 'workspace_overlay', 'ledger'} & set(sys.modules); "
        "sys.exit(repr(loaded) if loaded else 0)"
    )
    env = {**os.environ, "PYTHONPATH": str(SCRIPT.parent)}
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr


# ---------------------------------------------------------------------------
# cmd_complete
# ---------------------------------------------------------------------------


@pytest.fixture
def sim(run_dir, monkeypatch):
    return Sim(run_dir, monkeypatch)


def dispatch(sim: Sim) -> Prover:
    sim.build({FN: (C_REL, "m", [])})
    S.cmd_init()
    aid = S.cmd_next("auto", prepare=True)["tasks"][0]["agent_id"]
    assert aid == AID
    return Prover(sim.run_dir, aid)


def write_result(prover: Prover, status: str = "stalled_after_k_retries", **fields: Any) -> Path:
    path = prover.scratch / "result.json"
    write_json(
        path,
        {
            "role": "prover",
            "agent_id": prover.aid,
            "file": C_REL,
            "function": FN,
            "status": status,
            "patch": None,
            "evidence": [{"tool_output": f"agents/{prover.aid}/scratch/wp_{FN}.json", "result": status}],
            "unproven_goals": [] if status == "all_proven" else [{"line": 3, "annotation": "p != 0"}],
            "strengthening_requests": [],
            "boundary_assumptions": [],
            "fault_hypothesis": None,
            **fields,
        },
    )
    return path


def spy_on_merge(monkeypatch, prover: Prover) -> dict:
    """What the partial merge sees in the scratch tree when it is called."""
    seen: dict[str, Any] = {}

    def merge(run_dir, agent_id, role, **kw):
        seen.update(
            source=prover.read(),
            guard=load(prover.guard_path)["status"],
            wp=load(prover.wp_path)["unproven_count"],
            role=role,
            allow_partial_wp=kw.get("allow_partial_wp"),
        )
        return {"ok": True, "agent_id": agent_id, "modified_files": [C_REL]}

    monkeypatch.setattr(S.DEPS, "merge_agent_overlay", merge)
    return seen


def test_complete_restores_the_best_candidate_before_promotion_and_the_partial_merge(sim, monkeypatch):
    prover = dispatch(sim)
    seen = spy_on_merge(monkeypatch, prover)
    prover.iterate("best", failed=1, proved=9)
    # The last iteration has a better proof ratio and is false on a real input: today it would block the partial merge.
    prover.iterate("last", "unproven_goals_remain", 1, 20, guard="rejected_overconstrained")
    write_result(prover, patch=f"agents/{AID}/scratch/{FN}.patch")

    out = S.cmd_complete(AID)

    assert out["action"] == "blocked" and out["errors"] == []
    assert out["best_candidate"] == {"restored": True, "best": 1, "rank": {"failed": 1, "proved": 9, "invalid": 0}}
    promoted = load(sim.run_dir / "agents" / AID / "artifacts" / f"wp_{FN}.json")
    assert (promoted["unproven_count"], promoted["proven_count"], promoted["file"]) == (1, 9, C_REL)
    assert out["partial_merge"]["ok"] is True and seen == {
        "source": annotated("best"),
        "guard": PASSED,
        "wp": 1,
        "role": "prover",
        "allow_partial_wp": True,
    }
    assert tasks()[f"prove:{C_REL}#{FN}"]["state"] == "blocked"
    assert tasks()[f"prove:{C_REL}#{FN}"]["partial_contract_merged"] is True
    # The result is still valid afterwards, and its patch now describes the best candidate.
    task = tasks()[f"prove:{C_REL}#{FN}"]
    _, errors = S._load_result(prover.scratch / "result.json", task, AID)
    assert errors == []
    assert "requires best" in (prover.scratch / f"{FN}.patch").read_text(encoding="utf-8")


def test_complete_merges_the_contract_of_a_fully_proved_best_candidate_without_crediting_it(sim, monkeypatch):
    prover = dispatch(sim)
    seen = spy_on_merge(monkeypatch, prover)
    prover.iterate("proved", "all_proven", 0, 9)
    prover.iterate("stronger", failed=2, proved=12)  # moving on to Layer properties, say, and stalling there
    write_result(prover)

    out = S.cmd_complete(AID)

    assert out["best_candidate"] == {"restored": True, "best": 1, "rank": {"failed": 0, "proved": 9, "invalid": 0}}
    assert out["action"] == "blocked" and "ingest_wp" not in out
    assert out["partial_merge"]["ok"] is True and seen["source"] == annotated("proved")


def test_complete_does_not_restore_for_all_proven(sim, monkeypatch):
    prover = dispatch(sim)
    prover.iterate("partial", failed=1, proved=9)
    prover.edit(annotated("complete"))
    prover.wp("all_proven", 0, 12)  # its guardrail was skipped: the parent re-verifies on merge
    write_result(prover, "all_proven")
    calls: list[Path] = []
    monkeypatch.setattr(S.DEPS, "restore_best", calls.append)

    out = S.cmd_complete(AID)

    assert out["action"] == "queued_for_merge" and calls == [] and "best_candidate" not in out
    assert prover.read() == annotated("complete") and load(prover.wp_path)["status"] == "all_proven"


def test_complete_promotes_the_restored_report_whatever_the_evidence_names(sim):
    prover = dispatch(sim)
    prover.iterate("best", failed=1, proved=9)
    prover.iterate("last", failed=5, proved=1)
    other = f"agents/{AID}/scratch/wp_{FN}_final.json"
    write_json(sim.run_dir / other, prover.wp_report(failed=7, proved=1))
    write_result(prover, evidence=[{"tool_output": other, "result": "stalled"}])

    out = S.cmd_complete(AID)

    assert out["best_candidate"]["best"] == 1
    assert load(sim.run_dir / "agents" / AID / "artifacts" / f"wp_{FN}.json")["unproven_count"] == 1


def test_complete_keeps_the_evidence_path_when_there_is_no_best_candidate(sim):
    prover = dispatch(sim)
    other = f"agents/{AID}/scratch/wp_{FN}_final.json"
    write_json(sim.run_dir / other, prover.wp_report(failed=7, proved=1))
    write_result(prover, evidence=[{"tool_output": other, "result": "stalled"}])

    out = S.cmd_complete(AID)

    assert out["best_candidate"] is None and out["action"] == "blocked"
    assert load(sim.run_dir / "agents" / AID / "artifacts" / f"wp_{FN}.json")["unproven_count"] == 7


def test_a_failing_restore_does_not_block_completion(sim, monkeypatch):
    prover = dispatch(sim)
    write_json(prover.wp_path, prover.wp_report(failed=2, proved=2))
    write_result(prover)

    def boom(scratch: Path) -> None:
        raise OSError("the disk is full")

    monkeypatch.setattr(S.DEPS, "restore_best", boom)
    out = S.cmd_complete(AID)
    assert out["action"] == "blocked" and out["best_candidate"] is None
    assert any("the disk is full" in e for e in out["errors"])
    assert load(sim.run_dir / "agents" / AID / "artifacts" / f"wp_{FN}.json")["unproven_count"] == 2


def test_a_broken_snapshot_does_not_block_completion(sim):
    prover = dispatch(sim)
    prover.iterate("best", failed=1, proved=9)
    prover.iterate("last", failed=4, proved=4)
    shutil.rmtree(prover.scratch / "candidates/best")
    write_result(prover)

    out = S.cmd_complete(AID)

    assert out["action"] == "blocked" and out["best_candidate"] is None
    assert any("restore best candidate" in e for e in out["errors"])
    assert prover.read() == annotated("last")


def test_complete_without_candidates_retries_a_final_analysis_error_as_before(sim):
    prover = dispatch(sim)
    write_json(prover.wp_path, prover.wp_report("analysis_error", reason="oom_killed"))
    write_result(prover, "blocked")
    out = S.cmd_complete(AID)
    assert out["best_candidate"] is None and out["action"] == "retry_analysis_error"


def test_an_analysis_error_keeps_its_retry_even_with_a_best_candidate(sim, monkeypatch):
    # Exceeding the WP job limit yields analysis_error: settling for the best candidate here would make
    # results depend on machine speed.
    prover = dispatch(sim)
    seen = spy_on_merge(monkeypatch, prover)
    prover.iterate("best", failed=1, proved=9)
    prover.iterate("last", "analysis_error", reason="timeout")
    write_result(prover, "blocked")

    out = S.cmd_complete(AID)

    assert out["action"] == "retry_analysis_error" and out["best_candidate"] is None
    assert prover.read() == annotated("last"), "nothing is restored while a retry is coming"
    assert "partial_merge" not in out and not seen


def test_a_task_ending_on_analysis_error_falls_back_to_its_best_candidate(sim, monkeypatch):
    prover = dispatch(sim)
    seen = spy_on_merge(monkeypatch, prover)
    prover.iterate("best", failed=1, proved=9)
    prover.iterate("last", "analysis_error", reason="timeout")
    write_result(prover, "blocked")
    state = S.load_schedule()
    state["tasks"][state["agents"][AID]]["analysis_errors"] = S.MAX_ANALYSIS_ERRORS - 1
    S.save_schedule(state)

    out = S.cmd_complete(AID)

    assert out["best_candidate"]["best"] == 1 and out["action"] == "blocked"
    assert seen["source"] == annotated("best") and out["partial_merge"]["ok"] is True


def test_a_task_ending_on_analysis_error_without_a_best_candidate_blocks_as_before(sim):
    prover = dispatch(sim)
    write_json(prover.wp_path, prover.wp_report("analysis_error", reason="timeout"))
    write_result(prover, "blocked")
    state = S.load_schedule()
    state["tasks"][state["agents"][AID]]["analysis_errors"] = S.MAX_ANALYSIS_ERRORS - 1
    S.save_schedule(state)

    out = S.cmd_complete(AID)

    assert out["best_candidate"] is None and out["action"] == "blocked_analysis_error"


def test_complete_of_a_negotiating_prover_restores_too(sim, monkeypatch):
    sim.build({FN: (C_REL, "m", []), "caller": ("src/m/caller.c", "m", [FN])})
    S.cmd_init()
    task = next(t for t in S.cmd_next("auto", prepare=True)["tasks"] if t["function"] == FN)
    state = S.load_schedule()
    state["tasks"][task["task"]]["kind"] = "negotiate"
    state["tasks"][task["task"]]["request_ids"] = []
    S.save_schedule(state)
    prover = Prover(sim.run_dir, task["agent_id"])
    prover.iterate("best", failed=1, proved=9)
    prover.iterate("last", failed=4, proved=4)
    write_result(prover)

    out = S.cmd_complete(task["agent_id"])

    assert out["best_candidate"]["best"] == 1 and out["action"] == "negotiation_rejected"
    assert prover.read() == annotated("best")
