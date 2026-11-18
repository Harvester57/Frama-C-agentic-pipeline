"""
A credited proof whose guardrail passed says which clauses the dynamic oracle never executed.

E-ACSL warns `Ignoring annotation` for a clause it cannot translate and generates no check; the
guardrail reports them as `unchecked_clauses` (run_eacsl_fuzz.dynamic_oracle_fields). The parent
guardrail's limits carry that list under `limits.dynamic_oracle.unchecked_clauses`
({function, kind, label, clause, file, line, reason, via}) and, for ignored annotations no function
could be read for, `limits.dynamic_oracle.unattributed`. `ledger.py ingest-wp` records each as an
assumption of the credited units and REPORT.md lists them.

The clause records of the `unb_*` and `via_pred` cases are computed by the guardrail's own functions from
E-ACSL's captured output (tests/fixtures/eacsl_ignored, Frama-C 34.0~beta); the limits dicts around
them are written here in the shape the overlay writes.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import eacsl_toolchain as T
import generate_report as G
import ledger as L
import run_eacsl_fuzz as R
from conftest import metadata, unit, write_json

pytestmark = pytest.mark.unit

UNCHECKED_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "eacsl_ignored"
UNCHECKED_SRC = Path("workspace") / "work" / "src"


def _captured_clauses(run_dir: Path, tag: str, function: str) -> dict:
    """dynamic_oracle_fields for the captured stage 1 output of `tag`, checked function `function`."""
    (run_dir / UNCHECKED_SRC).mkdir(parents=True, exist_ok=True)
    for name in ("probe.c", "probe.h", "violation.c", "extras.c"):
        shutil.copy(UNCHECKED_FIXTURE / name, run_dir / UNCHECKED_SRC / name)
    record = (UNCHECKED_FIXTURE / f"{tag}.stage1.log").read_text(encoding="utf-8")
    stdout = record.split("--- STDOUT ---\n", 1)[1].split("\n--- STDERR ---", 1)[0]
    entries, _frame = T.parse_ignored_annotations(stdout)
    instrumented = UNCHECKED_FIXTURE / f"{tag}.instrumented.c"
    ignored = T.attribute_ignored_annotations(entries, instrumented if instrumented.is_file() else None, cwd=run_dir)
    return R.dynamic_oracle_fields(ignored, [function])


def _limits(**oracle) -> dict:
    return {
        "vacuity": {"status": "consistent", "doomed": [], "dead_goals": 0},
        "guardrail_corpus": {"total": 2, "replayed": 2, "sampled": False, "empty": False},
        "dynamic_oracle": {"exercised": True, "hits": 4, "executed_inputs": 3, **oracle},
    }


def _ingest(run_dir: Path, function: str, limits: dict) -> dict:
    write_json(run_dir / "run-metadata.json", metadata("in_progress"))
    write_json(run_dir / "coverage-ledger.json", [unit("src/probe.c", function, "rte", module="probe")])
    report = {
        "status": "all_proven",
        "function": function,
        "file": "workspace/work/src/probe.c",
        "by_obligation_class": {"rte": {"proven": 3, "proven_under_hyp": 0, "unproven": 0}},
        "unproven_goals": [],
        "limits": limits,
    }
    path = run_dir / "workspace/reports/wp" / f"{function}.json"
    write_json(path, report)
    L.cmd_ingest_wp([path])
    return json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))[0]


def test_an_ignored_requires_becomes_an_assumption_of_the_credited_unit(run_dir):
    """`unb_requires`: an unbounded quantifier in a `requires`, and a loop variant that needs GMP."""
    fields = _captured_clauses(run_dir, "unb_requires", "unb_requires")
    clauses = fields["unchecked_clauses"]
    assert fields["dynamic_oracle_incomplete"] is True and len(clauses) == 2
    covered = _ingest(run_dir, "unb_requires", _limits(unchecked_clauses=clauses))
    assert covered["status"] == "covered"
    texts = [a["description"] for a in covered["assumptions"]]
    assert len(texts) == 2 and all(a["kind"] == "other" for a in covered["assumptions"])
    quantifier = next(t for t in texts if "unb_pre" in t)
    assert quantifier.startswith("The dynamic oracle never executed the requires `unb_pre: ")
    assert "of unb_requires" in quantifier and "workspace/work/src/probe.c:13" in quantifier
    assert "Missing upper bound for i." in quantifier and "rests on the WP proof alone" in quantifier
    assert any("workspace/work/src/probe.c:23" in t and "loop variant using GMP" in t for t in texts)
    # The evidence keeps the whole list.
    kept = covered["evidence"][-1]["details"]["limits"]["dynamic_oracle"]["unchecked_clauses"]
    assert kept == clauses


def test_a_clause_ignored_through_a_predicate_names_the_predicate(run_dir):
    fields = _captured_clauses(run_dir, "via_pred", "via_pred")
    clauses = fields["unchecked_clauses"]
    assert clauses and all(c["via"] for c in clauses)
    covered = _ingest(run_dir, "via_pred", _limits(unchecked_clauses=clauses))
    assert any(f"through `{clauses[0]['via']}`" in a["description"] for a in covered["assumptions"])


def test_the_report_lists_the_clauses_a_passed_guardrail_never_executed(run_dir):
    fields = _captured_clauses(run_dir, "unb_requires", "unb_requires")
    covered = _ingest(run_dir, "unb_requires", _limits(unchecked_clauses=fields["unchecked_clauses"]))
    text = "\n".join(G.verdict_limits_section([covered]))
    assert "the dynamic oracle never executed 2 clause(s) of 1 function(s)" in text
    assert "  - `src/probe.c#unb_requires`: requires `unb_pre: " in text
    assert "Missing upper bound for i." in text and "workspace/work/src/probe.c:23" in text
    assert "no guardrail input reached" not in text


def test_annotations_no_function_could_be_read_for_are_said_not_guessed(run_dir):
    """Hand-built: an ignored annotation the guardrail could not tie to a function."""
    loose = [{"file": "workspace/work/src/probe.h", "line": 9, "reason": "invalid E-ACSL construct `x'"}]
    covered = _ingest(run_dir, "walk", _limits(unchecked_clauses=[], unattributed=loose))
    texts = [a["description"] for a in covered["assumptions"]]
    assert len(texts) == 1 and texts[0].startswith("E-ACSL ignored 1 annotation(s) in walk's guardrail build")
    assert "workspace/work/src/probe.h:9" in texts[0] and "is not known" in texts[0]
    text = "\n".join(G.verdict_limits_section([covered]))
    assert "could not be tied to a function" in text and "`src/probe.c#walk` (1)" in text
    assert "never executed" not in text


def test_many_clauses_are_named_up_to_a_bound_and_then_counted(run_dir):
    clause = {
        "function": "walk",
        "kind": "ensures",
        "label": "",
        "clause": "\\forall integer i; i >= 0 ==> a[i] == 0",
        "file": "workspace/work/src/probe.c",
        "reason": "Missing upper bound for i.",
        "via": None,
    }
    clauses = [{**clause, "line": 100 + n} for n in range(L.UNCHECKED_CLAUSES_NAMED + 3)]
    covered = _ingest(run_dir, "walk", _limits(unchecked_clauses=clauses))
    texts = [a["description"] for a in covered["assumptions"]]
    assert len(texts) == L.UNCHECKED_CLAUSES_NAMED + 1
    assert texts[-1].startswith("The dynamic oracle never executed 3 more clause(s)")
    assert "ensures `\\forall integer i; i >= 0 ==> a[i] == 0` at workspace/work/src/probe.c:100" in texts[0]


# ------------------------------------------------------------------ controls


@pytest.mark.parametrize("oracle", [{}, {"unchecked_clauses": []}, {"unchecked_clauses": None, "unattributed": None}])
def test_a_complete_or_unreported_oracle_adds_nothing(run_dir, oracle):
    """An empty list is "every clause was executed"; a missing key or None is "not reported", and neither is guessed."""
    covered = _ingest(run_dir, "walk", _limits(**oracle))
    assert covered["status"] == "covered" and covered["assumptions"] == []
    text = "\n".join(G.verdict_limits_section([covered]))
    assert "never executed" not in text and "could not be tied" not in text


def test_the_other_limits_still_become_assumptions(run_dir):
    limits = _limits(unchecked_clauses=[])
    limits["dynamic_oracle"]["exercised"] = False
    covered = _ingest(run_dir, "walk", limits)
    assert [a["description"] for a in covered["assumptions"]] == [
        "No guardrail input reached walk: its contract was proven but not exercised at runtime."
    ]
