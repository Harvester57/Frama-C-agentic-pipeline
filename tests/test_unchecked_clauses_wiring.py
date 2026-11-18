"""What the guardrail could not execute reaches the parent WP report and the loop-seed corpus filter.

E-ACSL warns `Ignoring annotation` and generates no check; the guardrail report names those clauses
(`unchecked_clauses`, `unattributed_ignored_annotations`: tests/test_eacsl_ignored_annotations.py). A pass is
still a pass of the checks that ran, so no merge is refused for it. But the proof's limits must list the
clauses, and a loop-invariant seed whose check was never generated did not "hold on the corpus".

The clause records here are built by the guardrail's own functions from E-ACSL's captured output under
tests/fixtures/eacsl_ignored (analysis image, Frama-C 34.0~beta); `unb_requires.json` is the guardrail report
recorded there before it listed them.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import eacsl_toolchain as T
import fuzz_build
import loop_seeds as ls
import run_eacsl_fuzz as R
import workspace_overlay
import wp_scheduler as S
from test_loop_seeds import SUM_INT, FakeGuard, FakeWp, _compute, _passed, _sum_int_record
from test_wp_scheduler import Sim, _negotiate_partial_fixture

pytestmark = pytest.mark.unit

CAPTURES = Path(__file__).resolve().parent / "fixtures" / "eacsl_ignored"
RECORDED_PASS = json.loads((CAPTURES / "unb_requires.json").read_text(encoding="utf-8"))


def _ignored(tmp_path: Path, tag: str) -> list[dict]:
    """The build's `ignored_annotations` for the captured stage 1 output of `tag`, attributed on the probe sources."""
    run = tmp_path / "probe_run"
    src = run / "workspace" / "work" / "src"
    if not src.is_dir():
        src.mkdir(parents=True)
        for name in ("probe.c", "probe.h"):
            shutil.copy(CAPTURES / name, src / name)
    record = (CAPTURES / f"{tag}.stage1.log").read_text(encoding="utf-8")
    output = record.split("--- STDOUT ---\n", 1)[1].split("\n--- STDERR ---", 1)[0]
    entries, _frame = T.parse_ignored_annotations(output)
    return T.attribute_ignored_annotations(entries, None, cwd=run)


def _guard_report(tmp_path: Path, tag: str, checked: list[str]) -> dict:
    """The recorded pass, with the fields the guardrail now adds for the build of `tag`."""
    return {**RECORDED_PASS, **R.dynamic_oracle_fields(_ignored(tmp_path, tag), checked)}


# ---------------------------------------------------------------------------
# workspace_overlay._apply_guard_limits: limits.dynamic_oracle.unchecked_clauses / .unattributed
# ---------------------------------------------------------------------------


def test_the_unchecked_clauses_of_the_function_are_written_to_its_limits(tmp_path: Path) -> None:
    report = _guard_report(tmp_path, "unb_requires", ["unb_requires"])
    assert report["status"] == "passed_dynamic_oracle" and report["dynamic_oracle_incomplete"] is True
    wp: dict = {"limits": {}}
    assert workspace_overlay._apply_guard_limits(wp, "unb_requires", report) is True
    clauses = wp["limits"]["dynamic_oracle"]["unchecked_clauses"]
    assert [(c["function"], c["kind"], c["label"], c["line"]) for c in clauses] == [
        ("unb_requires", "loop variant", "", 23),
        ("unb_requires", "requires", "unb_pre", 13),
    ]
    assert set(clauses[0]) == {"function", "kind", "label", "clause", "file", "line", "reason", "via"}
    assert "unattributed" not in wp["limits"]["dynamic_oracle"]


def test_a_module_guardrail_gives_each_function_its_own_clauses(tmp_path: Path) -> None:
    """The batch: one guardrail for the module, one WP report per prover (`--reach-functions`)."""
    report = _guard_report(tmp_path, "module", ["unb_requires", "plain", "multi_line"])
    by_fn = {}
    for fn in ("unb_requires", "plain", "multi_line"):
        wp: dict = {"limits": {}}
        workspace_overlay._apply_guard_limits(wp, fn, report)
        by_fn[fn] = [(c["kind"], c["label"]) for c in wp["limits"]["dynamic_oracle"]["unchecked_clauses"]]
    assert by_fn["unb_requires"] == [("loop variant", ""), ("requires", "unb_pre")]
    assert by_fn["plain"] == []  # complete: an empty list, not a missing key
    assert ("loop invariant", "unb_inv") in by_fn["multi_line"]


def test_the_reach_fields_stay_beside_the_clauses(tmp_path: Path) -> None:
    report = _guard_report(tmp_path, "unb_requires", ["unb_requires"])
    report["reach"] = {"measured": True, "functions": {"unb_requires": 2}, "unreached": [], "executed_inputs": 2}
    wp: dict = {"limits": {}}
    workspace_overlay._apply_guard_limits(wp, "unb_requires", report)
    oracle = wp["limits"]["dynamic_oracle"]
    assert (oracle["exercised"], oracle["hits"], oracle["executed_inputs"]) == (True, 2, 2)
    assert len(oracle["unchecked_clauses"]) == 2


def test_a_guardrail_without_the_list_is_not_reported_as_complete() -> None:
    """The recorded report predates the fields: the limits say `None` (not known), never `[]` (none)."""
    assert "unchecked_clauses" not in RECORDED_PASS
    for report in (RECORDED_PASS, {**RECORDED_PASS, **R.dynamic_oracle_fields(None, ["unb_requires"])}):
        wp: dict = {"limits": {}}
        workspace_overlay._apply_guard_limits(wp, "unb_requires", report)
        assert wp["limits"]["dynamic_oracle"]["unchecked_clauses"] is None
        assert "unattributed" not in wp["limits"]["dynamic_oracle"]


def test_unattributed_ignored_annotations_are_listed_apart(tmp_path: Path) -> None:
    lost = {"file": None, "line": None, "construct": None, "reason": "r", "expected_check": True}
    ignored = T.attribute_ignored_annotations([lost], None, cwd=tmp_path)
    report = {**RECORDED_PASS, **R.dynamic_oracle_fields(ignored, ["unb_requires"])}
    assert report["dynamic_oracle_incomplete"] is False and len(report["unattributed_ignored_annotations"]) == 1
    wp: dict = {"limits": {}}
    workspace_overlay._apply_guard_limits(wp, "unb_requires", report)
    oracle = wp["limits"]["dynamic_oracle"]
    assert oracle["unchecked_clauses"] == []
    assert oracle["unattributed"] == report["unattributed_ignored_annotations"]


# ---------------------------------------------------------------------------
# loop_seeds: a seed whose check E-ACSL did not generate is not "held"
# ---------------------------------------------------------------------------


def _seed_clause(tmp_path: Path, label: str) -> dict:
    """E-ACSL's record of an ignored loop invariant (probe.c, `unb_inv`), as it would name the seed `label`."""
    report = _guard_report(tmp_path, "multi_line", ["multi_line"])
    (clause,) = [c for c in report["unchecked_clauses"] if c["kind"] == "loop invariant"]
    assert clause["label"] == "unb_inv" and "Ignoring annotation" not in (clause["reason"] or "x")
    return {**clause, "function": "sum_int", "label": label}


def _passed_with(unchecked, unattributed=()):
    return {**_passed(), "unchecked_clauses": unchecked, "unattributed_ignored_annotations": list(unattributed)}


def test_a_seed_eacsl_ignored_is_not_held_and_the_others_are(tmp_path: Path) -> None:
    cands = ls.generate_candidates(_sum_int_record(), SUM_INT)
    guard = FakeGuard([_passed_with([_seed_clause(tmp_path, "seed_2")])])
    summary = ls.corpus_filter(SUM_INT, "sum_int", tmp_path / "sum.c", cands, guard)
    assert summary["status"] == "ok" and summary["not_executed"] == ["seed_2"]
    assert [c.corpus["verdict"] for c in cands] == ["held", "not_executed", "held"]
    assert "E-ACSL generated no check" in cands[1].corpus["reason"]


def test_a_clause_of_another_function_or_kind_does_not_touch_the_seeds(tmp_path: Path) -> None:
    other_fn = {**_seed_clause(tmp_path, "seed_2"), "function": "other"}
    variant = {**_seed_clause(tmp_path, ""), "kind": "loop variant"}
    cands = ls.generate_candidates(_sum_int_record(), SUM_INT)
    ls.corpus_filter(SUM_INT, "sum_int", tmp_path / "sum.c", cands, FakeGuard([_passed_with([other_fn, variant])]))
    assert {c.corpus["verdict"] for c in cands} == {"held"}


def test_a_replay_that_cannot_say_what_was_executed_holds_nothing(tmp_path: Path) -> None:
    """No build report (`unchecked_clauses` None or absent): whether the seeds ran is not known."""
    silent = {k: v for k, v in _passed().items() if k != "unchecked_clauses"}
    for verdict in (silent, _passed_with(None)):
        cands = ls.generate_candidates(_sum_int_record(), SUM_INT)
        summary = ls.corpus_filter(SUM_INT, "sum_int", tmp_path / "sum.c", cands, FakeGuard([verdict]))
        assert {c.corpus["verdict"] for c in cands} == {"not_executed"}
        assert summary["not_executed"] == ["seed_1", "seed_2", "seed_3"]
        assert "does not say" in cands[0].corpus["reason"]


def test_a_function_no_input_reached_stays_not_reached(tmp_path: Path) -> None:
    cands = ls.generate_candidates(_sum_int_record(), SUM_INT)
    guard = FakeGuard([{**_passed(0), "unchecked_clauses": [_seed_clause(tmp_path, "seed_2")]}])
    ls.corpus_filter(SUM_INT, "sum_int", tmp_path / "sum.c", cands, guard)
    assert {c.corpus["verdict"] for c in cands} == {"not_reached"}


def test_an_unattributed_ignored_annotation_at_a_seeds_line_withholds_that_seed(tmp_path: Path) -> None:
    cands = ls.generate_candidates(_sum_int_record(), SUM_INT)
    copy = tmp_path / "sum.c"
    _seeded, lines, _skipped = ls.insert_seeds(SUM_INT, cands, path=copy.name)
    lost = {"file": str(copy), "line": lines["seed_3"], "reason": "r", "function": None}
    elsewhere = {"file": str(tmp_path / "other.c"), "line": lines["seed_1"], "reason": "r", "function": None}
    ls.corpus_filter(SUM_INT, "sum_int", copy, cands, FakeGuard([_passed_with([], [lost, elsewhere])]))
    assert [c.corpus["verdict"] for c in cands] == ["held", "held", "not_executed"]


def test_the_report_does_not_list_an_unexecuted_seed_as_held(tmp_path: Path) -> None:
    wp = FakeWp([{"seed_2": ["established"]}, {}])
    report = _compute(tmp_path, wp, FakeGuard([_passed_with([_seed_clause(tmp_path, "seed_2")])]))
    assert report["held_on_corpus_unproven"] == []
    assert [(c["name"], c["label"]) for c in report["candidates"]] == [
        ("seed_1", "proven_inductive"),
        ("seed_2", "dropped"),
        ("seed_3", "proven_inductive"),
    ]
    shown = ls.render(report)
    assert "Held on every replayed corpus input" not in shown
    assert "- `i <= len`: establishment failed; not checked on the corpus (E-ACSL generated no check for it)." in shown


# ---------------------------------------------------------------------------
# wp_scheduler: a stalled negotiation merges its contract only on a guardrail that executed it
# ---------------------------------------------------------------------------


@pytest.fixture
def sim(run_dir, monkeypatch):
    return Sim(run_dir, monkeypatch)


def _negotiation_with_guard(sim, tmp_path: Path, extra: dict):
    task, aid, report = _negotiate_partial_fixture(sim)
    guard_json = sim.run_dir / f"agents/{aid}/scratch/guard_callee.json"
    guard = json.loads(guard_json.read_text(encoding="utf-8"))
    for key in ("unchecked_clauses", "unattributed_ignored_annotations"):
        guard.pop(key, None)
    guard_json.write_text(json.dumps({**guard, **extra}), encoding="utf-8")
    return task, aid, report


def test_a_negotiated_contract_eacsl_did_not_execute_is_not_merged_partially(sim, tmp_path: Path) -> None:
    """The strengthened `requires` is what the oracle is asked about: `passed` without its check says nothing."""
    (clause, _variant) = sorted(
        _guard_report(tmp_path, "unb_requires", ["unb_requires"])["unchecked_clauses"],
        key=lambda c: c["kind"] != "requires",
    )
    assert clause["kind"] == "requires"
    task, aid, report = _negotiation_with_guard(
        sim, tmp_path, {"unchecked_clauses": [{**clause, "function": "callee"}]}
    )
    assert S._partial_contract_merge_job(task, aid, report, S.Ctx()) is None


def test_a_negotiation_whose_guardrail_does_not_say_what_it_executed_is_not_merged_partially(sim, tmp_path) -> None:
    for extra in ({}, {"unchecked_clauses": None}):
        task, aid, report = _negotiation_with_guard(sim, tmp_path, extra)
        assert S._partial_contract_merge_job(task, aid, report, S.Ctx()) is None
        shutil.rmtree(sim.run_dir / f"agents/{aid}")


def test_a_negotiation_is_merged_when_only_another_functions_clause_was_ignored(sim, tmp_path: Path) -> None:
    others = _guard_report(tmp_path, "unb_requires", ["unb_requires"])["unchecked_clauses"]
    task, aid, report = _negotiation_with_guard(sim, tmp_path, {"unchecked_clauses": others})
    assert S._partial_contract_merge_job(task, aid, report, S.Ctx()) is not None


def test_the_guard_runner_passes_the_builds_ignored_list_to_the_replay(tmp_path: Path, monkeypatch) -> None:
    src = tmp_path / "work" / "sum.c"
    src.parent.mkdir()
    src.write_text(SUM_INT, encoding="utf-8")
    ignored = _ignored(tmp_path, "multi_line")
    seen: dict = {}

    def fake_build(sources, out, **kwargs):
        return {"returncode": 0, "binary": str(out), "ignored_annotations": ignored}

    def fake_check(binary, corpus, scratch, runs, **kwargs):
        seen.update(kwargs)
        return {"status": "passed_dynamic_oracle", **R.dynamic_oracle_fields(kwargs["ignored_annotations"], ["x"])}

    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", fake_build)
    monkeypatch.setattr(R, "run_guardrail_check", fake_check)
    run = ls.default_guard_runner(src, [str(src)], "-I.", "", tmp_path, "m", tmp_path / "out")
    assert run is not None
    verdict = run(tmp_path / "copy.c", "sum_int")
    assert seen["ignored_annotations"] is ignored and seen["functions"] == ["sum_int"]
    assert verdict["unchecked_clauses"] == []  # the build's list was read: nothing of `x` was ignored
