"""
A replay report says, per input, what the ledger would make of it: `identity` (crash_replay.replay_identity).

`fingerprint_matches` of a replay report compares fingerprints only, over all artifacts at once.
`ledger.py ingest-verifier` judges each listed reproducer by more (`_judge_reproducer`: the candidate's
fingerprint, an observation's, its statement site, a related candidate's, function and kind where one
side has no statement). The two disagreed both ways on the recorded reports of libmodbus run-1 and
mpack run-4 (tests/fixtures/replay_identity, staged by tests/test_verifier_replay_identity.py): a
report with `fingerprint_matches: true` held an input the ledger refuses, and one with `false` held
inputs it accepts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import crash_replay as C
import ledger as L
import test_verifier_replay_identity as tvr

pytestmark = pytest.mark.unit

IDENTITY_OUTCOMES = ("match", "mismatch", "uncompared")


def _reports(run_dir: Path) -> list[tuple[str, dict]]:
    found = sorted((run_dir / tvr.REPLAY_DIR).glob("*.json"))
    return [(f"{tvr.REPLAY_DIR}/{p.name}", json.loads(p.read_text(encoding="utf-8"))) for p in found]


def _identity(run_dir: Path, candidates: dict[str, dict], path: str, report: dict) -> dict:
    cand = candidates[report["candidate_fingerprint"]]
    return C.replay_identity(report, cand, list(candidates.values()), path, run_dir)


def _ledger_outcomes(run_dir: Path, candidates: dict[str, dict], path: str, report: dict) -> dict[str, str]:
    """sha256 -> `_judge_reproducer`'s outcome, grouped as `ingest-verifier` groups the artifacts."""
    cand = candidates[report["candidate_fingerprint"]]
    grouped: dict[str, list[tuple[str, dict]]] = {}
    for art in report["artifacts"]:
        if art.get("reproducible") is True and art.get("sha256"):
            grouped.setdefault(art["sha256"], []).append((path, art))
    return {sha: tvr._judge(run_dir, cand, candidates, arts)[0] for sha, arts in grouped.items()}


@pytest.mark.parametrize("fixture", [tvr.MODBUS, tvr.MPACK])
def test_identity_is_the_ledgers_judgement_of_every_recorded_input(run_dir, fixture):
    candidates = tvr._stage(run_dir, fixture)
    judged = 0
    for path, report in _reports(run_dir):
        if report["candidate_fingerprint"] not in candidates:
            continue  # a report kept for its artifacts: its candidate is not among the recorded ones
        identity = _identity(run_dir, candidates, path, report)
        assert identity["compared"] is True and identity["reason"] is None and identity["rule"] == C.IDENTITY_RULE
        expected = _ledger_outcomes(run_dir, candidates, path, report)
        assert {i["sha256"]: i["outcome"] for i in identity["inputs"]} == expected, path
        assert {k: identity[k] for k in IDENTITY_OUTCOMES} == {
            k: sum(o == k for o in expected.values()) for k in IDENTITY_OUTCOMES
        }
        judged += len(expected)
    assert judged >= 2


def test_a_true_fingerprint_match_can_hold_an_input_the_ledger_refuses(run_dir):
    """
    What `replay --only` writes for two inputs a verifier lists on `modbus_get_float_abcd`, one of which
    fails in `modbus_get_float_badc`: the recorded artifacts of the two candidates' reports, in one report.
    """
    candidates = tvr._stage(run_dir, tvr.MODBUS)
    path = f"{tvr.REPLAY_DIR}/{tvr.ABCD_REPORT}"
    report = json.loads((run_dir / path).read_text(encoding="utf-8"))
    other = json.loads((run_dir / tvr.REPLAY_DIR / tvr.BADC_REPORT).read_text(encoding="utf-8"))
    report["artifacts"] = [report["artifacts"][0], other["artifacts"][0]]
    cand = candidates[tvr.ABCD]
    # crash_replay's own rule for `fingerprint_matches`: some artifact has an accepted fingerprint.
    assert any(a.get("fingerprint") in C._accepted_fingerprints(cand) for a in report["artifacts"])
    identity = _identity(run_dir, candidates, path, report)
    assert (identity["match"], identity["mismatch"], identity["uncompared"]) == (1, 1, 0)
    refused = next(i for i in identity["inputs"] if i["outcome"] == "mismatch")
    assert refused["counts"] is False and "modbus_get_float_badc" in refused["failed_at"]
    assert refused["failure"] == tvr.BADC and refused["artifact"].endswith(Path(tvr.BADC_INPUT).name)
    accepted = next(i for i in identity["inputs"] if i["outcome"] == "match")
    assert accepted["counts"] is True and accepted["basis"] == "the fingerprint of the candidate"
    assert _ledger_outcomes(run_dir, candidates, path, report) == {
        i["sha256"]: i["outcome"] for i in identity["inputs"]
    }


def test_a_false_fingerprint_match_can_hold_an_input_the_ledger_accepts(run_dir):
    """libmodbus run-1, as recorded: E-ACSL's fingerprint differs from the hypothesis's, the function and kind are its."""
    candidates = tvr._stage(run_dir, tvr.MODBUS)
    path = f"{tvr.REPLAY_DIR}/{tvr.RTU_REPORT}"
    report = json.loads((run_dir / path).read_text(encoding="utf-8"))
    assert report["fingerprint_matches"] is False
    identity = _identity(run_dir, candidates, path, report)
    assert (identity["match"], identity["mismatch"], identity["uncompared"]) == (1, 0, 0)
    only = identity["inputs"][0]
    assert only["counts"] is True and only["basis"].startswith("the function and kind of the candidate")
    assert only["failure"] != tvr.RTU


def test_an_unparsed_failure_counts_only_for_an_input_recorded_on_the_candidate(run_dir):
    candidates = tvr._stage(run_dir, tvr.MODBUS)
    path = f"{tvr.REPLAY_DIR}/{tvr.HANG_REPORT}"
    report = json.loads((run_dir / path).read_text(encoding="utf-8"))
    identity = _identity(run_dir, candidates, path, report)
    blind = [i for i in identity["inputs"] if i["outcome"] == "uncompared"]
    assert blind and all(i["what"] for i in blind)
    assert all(i["counts"] is i["own_input"] for i in blind) and any(i["own_input"] for i in blind)
    # The same replay for a candidate that did not record the input: it does not count.
    other = json.loads(json.dumps(candidates[report["candidate_fingerprint"]]))
    other["reproducers"] = []
    for art in report["artifacts"]:
        art["artifact"] = "workspace/crashes/elsewhere/" + Path(str(art.get("artifact"))).name
    foreign = C.replay_identity(report, other, list(candidates.values()), path, run_dir)
    assert [i["counts"] for i in foreign["inputs"] if i["outcome"] == "uncompared"] == [False] * len(blind)


def test_a_comparison_that_fails_is_said_and_never_raised(run_dir, monkeypatch):
    candidates = tvr._stage(run_dir, tvr.MODBUS)
    path = f"{tvr.REPLAY_DIR}/{tvr.ABCD_REPORT}"
    report = json.loads((run_dir / path).read_text(encoding="utf-8"))

    def broken(*args: object, **kwargs: object) -> object:
        raise OSError("module map unreadable")

    monkeypatch.setattr(L.ModuleMap, "load", broken)
    identity = _identity(run_dir, candidates, path, report)
    assert identity["compared"] is False and identity["inputs"] == []
    assert identity["reason"] == "not compared: OSError: module map unreadable"
    assert not any(k in identity for k in IDENTITY_OUTCOMES)


def test_without_a_dag_the_fingerprint_still_compares(tmp_path, monkeypatch):
    """Hand-built: a run directory with nothing in it. No site can be placed; a fingerprint needs none."""
    monkeypatch.chdir(tmp_path)
    fp = "x.c#f::rte::0123456789"
    cand = {"fingerprint": fp, "module": "m", "location": {"file": "x.c", "function": "f", "line": 3}}
    arts = [
        {"reproducible": True, "sha256": "ab" * 32, "fingerprint": fp},
        {"reproducible": True, "sha256": "cd" * 32, "fingerprint": "", "returncode": 70},
        {"reproducible": False, "sha256": "ef" * 32, "fingerprint": fp},
    ]
    identity = C.replay_identity({"artifacts": arts}, cand, [cand], "workspace/reports/replay/r.json", tmp_path)
    assert identity["compared"] is True
    assert [(i["outcome"], i["counts"]) for i in identity["inputs"]] == [("match", True), ("uncompared", False)]


def test_the_ledger_rule_is_what_identity_names():
    assert "_judge_reproducer" in C.IDENTITY_RULE and callable(L._judge_reproducer)
    assert "compares fingerprints only" in (C.replay_identity.__doc__ or "")
