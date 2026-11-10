"""A weak rejection does not silence later tool evidence (ledger.py, FRAMAC_REJECTION_REOPEN).

Covers the three tool-reproduced signals (breaker crash_found, guardrail code_fault, fuzz reproducer),
the reasoning-only signal that never reopens, the verdict after a reopening, the reopening bound, the
A/B switch, the validator and the report.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import ledger
from conftest import FP_REJ, needs_validation_record, write_json
from fingerprint import make_fingerprint
from generate_report import generate
from test_verifier_decision_basis import TAG_RTE, _eva_report, _rejection, _result, _seed_run
from validate_artifacts import validate_run_dir

pytestmark = pytest.mark.unit

PRED = r"\valid_read(p)"
FUZZ_REPORT = "workspace/reports/fuzz/snmp.json"


@pytest.fixture(autouse=True)
def _reopen_on(monkeypatch):
    monkeypatch.delenv(ledger.REOPEN_ENV, raising=False)


def _load(run_dir: Path, name: str):
    return json.loads((run_dir / name).read_text(encoding="utf-8"))


def _cand(run_dir: Path) -> dict:
    return next(c for c in _load(run_dir, "candidates.json") if c["fingerprint"] == FP_REJ)


def _unit(run_dir: Path) -> dict:
    return _load(run_dir, "coverage-ledger.json")[0]


def _reject(run_dir: Path, rej_class: str = "disproved_by_source", basis: str | None = None, aid: str = "verifier-4"):
    return ledger.cmd_ingest_verifier(_result(run_dir, _rejection(rej_class, basis), "rejected", aid=aid))


def _breaker(
    run_dir: Path, aid: str = "breaker-1", crash: bytes | None = b"\x04\x00", hypothesis: bool = False
) -> dict:
    scratch = run_dir / "agents" / aid / "scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    if crash is not None:
        (scratch / "crash-in").write_bytes(crash)
    res: dict = {
        "role": "breaker",
        "agent_id": aid,
        "file": "src/snmp/ber.c",
        "function": "ber_decode_tag",
        "status": "crash_found" if crash is not None else "clean",
        "seeds": [],
        "crash_artifact": f"agents/{aid}/scratch/crash-in" if crash is not None else None,
        "failing_predicate": PRED if crash is not None else None,
        "analysis": "A two-byte tag reaches the read.",
        "suggested_requires": None,
        "fault_hypothesis": (
            {"input_condition": "tag 0x04", "predicate": PRED, "why_not_reproduced": "no session state"}
            if hypothesis
            else None
        ),
    }
    write_json(scratch / "result.json", res)
    return ledger.cmd_ingest_agent_hypothesis(scratch / "result.json", module="snmp")


def _fuzz(run_dir: Path, artifact: str = "workspace/crashes/snmp/crash-new", reproducible: bool = True) -> dict:
    path = run_dir / artifact
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x04\x00")
    report = {
        "mode": "campaign",
        "module": "snmp",
        "status": "crash_found",
        "artifacts": [
            {
                "artifact": artifact,
                "kind": "crash",
                "sha256": "x",
                "size_bytes": 2,
                "reproducible": reproducible,
                "fingerprint": FP_REJ,
                "failure": {
                    "file": "/framac-run/workspace/work/src/snmp/ber.c",
                    "line": 12,
                    "function": "ber_decode_tag",
                    "kind": "assertion",
                    "alarm_kind": "mem_access",
                    "is_rte": True,
                    "predicate": PRED,
                },
            }
        ],
    }
    write_json(run_dir / FUZZ_REPORT, report)
    return ledger.cmd_ingest_fuzz([run_dir / FUZZ_REPORT])


def _sidecar(run_dir: Path, source: str = "int harness;\n", **kw) -> None:
    (run_dir / "workspace/harnesses").mkdir(parents=True, exist_ok=True)
    (run_dir / "workspace/harnesses/harness_snmp.c").write_text(source, encoding="utf-8")
    write_json(
        run_dir / "workspace/harnesses/harness_snmp.json",
        {
            "module": "snmp",
            "harness_file": "workspace/harnesses/harness_snmp.c",
            "sources": ["src/snmp/ber.c"],
            "cppflags": "-I.",
            "entry_fn": "ber_decode_tag",
            "entry_style": "buffer_len",
            "repair_attempts": 0,
            "max_repair_attempts": 2,
            **kw,
        },
    )


def _needs_validation(fp: str = FP_REJ) -> dict:
    rec = needs_validation_record(fp)
    rec["location"] = {"file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag"}
    rec["property"] = {"kind": "mem_access", "predicate": PRED}
    rec["trace"] = [
        {"kind": "sink", "file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag", "description": "*p"}
    ]
    rec["linked_units"] = [TAG_RTE]
    return rec


# ------------------------------------------------------------------ reopening


@pytest.mark.parametrize("basis", [None, "model", "located"])
def test_breaker_crash_reopens_a_rejection_without_a_checked_basis(run_dir, basis):
    _seed_run(run_dir)
    _reject(run_dir, basis=basis)
    assert _unit(run_dir)["status"] == "blocked"
    last = _cand(run_dir)["last_rejection"]
    assert (last["rejection_class"], last["refutation_basis"]) == ("disproved_by_source", basis or "unstated")

    out = _breaker(run_dir)
    assert out["candidates_added"] == 0 and out["candidates_reopened"] == 1
    cand = _cand(run_dir)
    assert cand["status"] == "unverified" and "resolved_fingerprints" not in cand
    (entry,) = cand["reopened"]
    assert entry["rejection_class"] == "disproved_by_source"
    assert entry["refutation_basis"] == (basis or "unstated")
    assert entry["rejected_fingerprints"] == [FP_REJ]
    assert entry["evidence"]["source"] == "breaker_crash_found"
    assert entry["evidence"]["artifact"].startswith("workspace/crashes/snmp/crash-")
    assert entry["evidence"]["artifact"] in cand["reproducers"]
    assert entry["at"] and "resolved" not in entry

    u = _unit(run_dir)
    assert u["status"] == "candidate" and u["result_fingerprints"] == [FP_REJ] and u["unresolved"] == []
    assert u["attempts"][-1]["decision"] == "reopened"
    assert u["attempts"][-1]["refutation_basis"] == (basis or "unstated")
    # The rejection stays in findings.json until the next verdict: nothing is deleted on reopening.
    (finding,) = _load(run_dir, "findings.json")
    assert finding["verdict"] == "rejected"
    assert validate_run_dir(run_dir) == []


def test_a_verifier_stated_checked_rejection_is_contradicted_not_reopened(run_dir):
    _seed_run(run_dir)
    _reject(run_dir, basis="checked")
    out = _breaker(run_dir)
    assert out["rejections_contradicted"] == 1 and "candidates_reopened" not in out
    cand = _cand(run_dir)
    assert cand["status"] == "verified" and "reopened" not in cand
    (entry,) = cand["contradicting_evidence"]
    assert entry["reason"] == "checked_rejection" and entry["refutation_basis"] == "checked"
    assert entry["source"] == "breaker_crash_found" and entry["artifact"].startswith("workspace/crashes/snmp/")
    u = _unit(run_dir)
    assert u["status"] == "blocked" and u["result_fingerprints"] == []
    contradicted = [e for e in u["evidence"] if e["result"] == "rejection_contradicted"]
    assert len(contradicted) == 1 and contradicted[0]["details"]["reason"] == "checked_rejection"
    assert validate_run_dir(run_dir) == []

    # The same result again adds nothing.
    _breaker(run_dir)
    assert len(_cand(run_dir)["contradicting_evidence"]) == 1


def test_a_checked_basis_raised_by_ingest_is_reopened(run_dir):
    _seed_run(run_dir)
    write_json(run_dir / "workspace/reports/eva/snmp.json", _eva_report())
    _reject(run_dir, "dead_code", "located")
    assert _cand(run_dir)["last_rejection"]["refutation_basis_source"] == "eva_dead"
    _breaker(run_dir)
    cand = _cand(run_dir)
    assert cand["status"] == "unverified"
    assert cand["reopened"][0]["refutation_basis"] == "checked"
    assert cand["reopened"][0]["refutation_basis_source"] == "eva_dead"
    assert validate_run_dir(run_dir) == []


def test_a_fault_hypothesis_never_reopens(run_dir):
    _seed_run(run_dir)
    _reject(run_dir, basis="model")
    before = _cand(run_dir)
    out = _breaker(run_dir, crash=None, hypothesis=True)
    assert "candidates_reopened" not in out and "rejections_contradicted" not in out
    cand = _cand(run_dir)
    assert cand["status"] == "verified" and "reopened" not in cand and "contradicting_evidence" not in cand
    assert cand["last_rejection"] == before["last_rejection"]
    assert _unit(run_dir)["status"] == "blocked"
    assert validate_run_dir(run_dir) == []


def test_guardrail_code_fault_with_a_crash_input_reopens(run_dir):
    _seed_run(run_dir)
    _reject(run_dir, basis="located")
    aid = "prover-cf"
    scratch = run_dir / "agents" / aid / "scratch"
    crash = scratch / "guard" / "crash-0123abcd"
    crash.parent.mkdir(parents=True)
    crash.write_bytes(b"\x30\x84\xff")
    write_json(
        scratch / "guard_ber_decode_tag.json",
        {
            "status": "code_fault",
            "reason": "An RTE assertion failed on a real input.",
            "failure": {
                "file": "/work/run/workspace/work/src/snmp/ber.c",
                "line": 12,
                "function": "ber_decode_tag",
                "kind": "Assertion",
                "alarm_kind": "mem_access",
                "predicate": PRED,
            },
            "runtime_trace": f"Test unit written to /container/run/{crash.relative_to(run_dir).as_posix()}\n",
        },
    )
    write_json(
        scratch / "result.json",
        {
            "role": "prover",
            "agent_id": aid,
            "file": "src/snmp/ber.c",
            "function": "ber_decode_tag",
            "status": "blocked",
            "patch": None,
            "evidence": [{"tool_output": f"agents/{aid}/scratch/guard_ber_decode_tag.json", "result": "code_fault"}],
            "unproven_goals": [],
            "strengthening_requests": [],
            "boundary_assumptions": [],
            "fault_hypothesis": None,
            "proof_gap": None,
        },
    )
    out = ledger.cmd_ingest_agent_hypothesis(scratch / "result.json", module="snmp")
    assert out["candidates_reopened"] == 1
    cand = _cand(run_dir)
    assert cand["status"] == "unverified" and cand["reopened"][0]["evidence"]["source"] == "guardrail_code_fault"
    assert _unit(run_dir)["status"] == "candidate"
    assert validate_run_dir(run_dir) == []


# ------------------------------------------------------------------ fuzz


def test_fuzz_reproducer_reopens_once_and_a_listed_one_is_known(run_dir):
    _seed_run(run_dir)
    _reject(run_dir, basis="model")
    out = _fuzz(run_dir)
    assert out["reopened"] == 1
    cand = _cand(run_dir)
    assert cand["status"] == "unverified" and cand["reopened"][0]["evidence"]["source"] == "fuzz_reproducer"
    assert _unit(run_dir)["status"] == "candidate"
    assert validate_run_dir(run_dir) == []

    # Rejected again, then the same report again: the reproducer is listed, nothing reopens.
    _reject(run_dir, basis="model", aid="verifier-5")
    assert _unit(run_dir)["status"] == "blocked"
    again = _fuzz(run_dir)
    assert "reopened" not in again and "contradicted" not in again
    cand = _cand(run_dir)
    assert cand["status"] == "verified" and len(cand["reopened"]) == 1
    # The rejected candidate's unit is not marked `candidate` again by evidence that changed nothing.
    assert _unit(run_dir)["status"] == "blocked"
    assert validate_run_dir(run_dir) == []


def test_fuzz_artifact_that_did_not_reproduce_does_not_reopen(run_dir):
    _seed_run(run_dir)
    _reject(run_dir, basis="model")
    _fuzz(run_dir, reproducible=False)
    cand = _cand(run_dir)
    assert cand["status"] == "verified" and "reopened" not in cand
    assert _unit(run_dir)["status"] == "blocked"
    assert validate_run_dir(run_dir) == []


# ------------------------------------------------------------------ the verdict after a reopening


@pytest.mark.parametrize("second", ["needs_validation", "rejected"])
def test_second_verdict_supersedes_the_rejection_and_keeps_it_visible(run_dir, second):
    _seed_run(run_dir)
    _reject(run_dir, basis="located")
    _breaker(run_dir)
    if second == "needs_validation":
        res = _result(run_dir, _needs_validation(), "needs_validation", aid="verifier-5")
    else:
        rec = _rejection("harness_induced", "model")
        rec["reason"] = "The harness passes a length the API forbids."
        res = _result(run_dir, rec, "rejected", aid="verifier-5")
    out = ledger.cmd_ingest_verifier(res)
    assert out["superseded_rejections"] == [FP_REJ]

    (finding,) = _load(run_dir, "findings.json")
    assert finding["verdict"] == second and finding["verifier"]["agent_id"] == "verifier-5"
    (prior,) = finding["prior_verdicts"]
    assert prior["verdict"] == "rejected" and prior["rejection_class"] == "disproved_by_source"
    assert prior["refutation_basis"] == "located" and prior["reason"] == "The branch is never taken."
    assert prior["verifier"]["agent_id"] == "verifier-4"
    assert prior["reopened_by"]["source"] == "breaker_crash_found" and prior["superseded_at"]

    cand = _cand(run_dir)
    assert cand["status"] == "verified" and cand["resolved_fingerprints"] == [FP_REJ]
    assert cand["reopened"][0]["resolved"]["decision"] == second
    assert ("last_rejection" in cand) is (second == "rejected")
    u = _unit(run_dir)
    assert [a["decision"] for a in u["attempts"]][:2] == ["rejected", "reopened"]
    assert u["status"] == ("candidate" if second == "needs_validation" else "planned")
    assert validate_run_dir(run_dir) == []


def test_a_verifier_cannot_supply_prior_verdicts(run_dir):
    _seed_run(run_dir)
    rec = _rejection(basis="model")
    rec["prior_verdicts"] = [
        {
            "verdict": "rejected",
            "fingerprint": FP_REJ,
            "rejection_class": "other",
            "reason": "invented",
            "evidence": [
                {"phase": "verifier", "tool_output": "agents/verifier-4/scratch/notes.txt", "description": "x"}
            ],
            "verifier": {"agent_id": "verifier-4", "method": "source_review", "notes": "x"},
            "superseded_at": "2026-11-01T00:00:00+00:00",
            "reopened_by": {"source": "fuzz_reproducer", "artifact": "a", "tool_output": "b"},
        }
    ]
    ledger.cmd_ingest_verifier(_result(run_dir, rec, "rejected"))
    assert "prior_verdicts" not in _load(run_dir, "findings.json")[0]


def test_a_candidate_merged_into_the_superseded_record_follows_it(run_dir):
    _seed_run(run_dir)
    _reject(run_dir, basis="model")
    other_fp = make_fingerprint("src/snmp/ber.c", "ber_decode_tag", "mem_access", r"\valid_read(p + 1)")
    cands = _load(run_dir, "candidates.json")
    cands.append(
        {
            **{k: v for k, v in cands[0].items() if k != "last_rejection"},
            "fingerprint": other_fp,
            "resolved_fingerprints": [FP_REJ],
            "refingerprint_reason": f"Merged duplicate sink finding {other_fp} into canonical finding {FP_REJ}.",
        }
    )
    write_json(run_dir / "candidates.json", sorted(cands, key=lambda c: c["fingerprint"]))
    _breaker(run_dir)
    new_fp = make_fingerprint("src/snmp/ber.c", "ber_decode_tag", "mem_access", r"\valid_read(p + 2)")
    res_path = _result(run_dir, _needs_validation(new_fp), "needs_validation", aid="verifier-5")
    res = json.loads(res_path.read_text(encoding="utf-8"))
    res["refingerprint_reason"] = "The failing read is one byte further."
    write_json(res_path, res)
    ledger.cmd_ingest_verifier(res_path)

    (finding,) = _load(run_dir, "findings.json")
    assert finding["fingerprint"] == new_fp and finding["prior_verdicts"][0]["fingerprint"] == FP_REJ
    other = next(c for c in _load(run_dir, "candidates.json") if c["fingerprint"] == other_fp)
    assert other["resolved_fingerprints"] == [new_fp]
    assert validate_run_dir(run_dir) == []


# ------------------------------------------------------------------ bound and harness repair


def test_reopenings_are_bounded_by_the_harness_repair_budget(run_dir):
    _seed_run(run_dir)
    _sidecar(run_dir, max_repair_attempts=1)
    _reject(run_dir, basis="model")
    _breaker(run_dir, aid="breaker-1", crash=b"\x01")
    assert _cand(run_dir)["status"] == "unverified"
    _reject(run_dir, basis="model", aid="verifier-5")
    out = _breaker(run_dir, aid="breaker-2", crash=b"\x02")
    assert out["rejections_contradicted"] == 1
    cand = _cand(run_dir)
    assert cand["status"] == "verified" and len(cand["reopened"]) == 1
    assert cand["contradicting_evidence"][0]["reason"] == "reopen_limit"
    assert _unit(run_dir)["status"] == "blocked"
    assert validate_run_dir(run_dir) == []


def test_the_default_bound_is_two_reopenings(run_dir):
    _seed_run(run_dir)
    for n in range(3):
        _reject(run_dir, basis="model", aid=f"verifier-{n + 4}")
        _breaker(run_dir, aid=f"breaker-{n}", crash=bytes([n + 1]))
    cand = _cand(run_dir)
    assert len(cand["reopened"]) == ledger.DEFAULT_MAX_REOPENINGS == 2
    assert cand["status"] == "verified" and cand["contradicting_evidence"][0]["reason"] == "reopen_limit"


def test_harness_induced_recurring_through_the_same_harness_does_not_loop(run_dir):
    _seed_run(run_dir)
    _sidecar(run_dir)
    _reject(run_dir, "harness_induced", "model")
    assert _unit(run_dir)["status"] == "planned"
    assert _cand(run_dir)["last_rejection"]["harness_sha256"]

    # The unrepaired harness produces the crash again, with another input: recorded, not reopened.
    _fuzz(run_dir, artifact="workspace/crashes/snmp/crash-other")
    cand = _cand(run_dir)
    assert cand["status"] == "verified" and "reopened" not in cand
    assert cand["contradicting_evidence"][0]["reason"] == "harness_unchanged"
    assert _unit(run_dir)["status"] == "planned"
    assert validate_run_dir(run_dir) == []

    # After a repair the same input still crashes: that is new information.
    _sidecar(run_dir, source="int harness_repaired;\n", repair_attempts=1)
    out = _fuzz(run_dir, artifact="workspace/crashes/snmp/crash-other")
    assert out["reopened"] == 1
    cand = _cand(run_dir)
    assert cand["status"] == "unverified" and cand["reopened"][0]["harness_changed"] is True
    assert _unit(run_dir)["status"] == "candidate"
    assert validate_run_dir(run_dir) == []


def test_a_checked_harness_induced_rejection_speaks_for_its_harness_only(run_dir):
    _seed_run(run_dir)
    _sidecar(run_dir)
    _reject(run_dir, "harness_induced", "checked")
    _fuzz(run_dir, artifact="workspace/crashes/snmp/crash-other")
    cand = _cand(run_dir)
    assert cand["status"] == "verified" and cand["contradicting_evidence"][0]["reason"] == "checked_rejection"

    _sidecar(run_dir, source="int harness_repaired;\n", repair_attempts=1)
    assert _fuzz(run_dir, artifact="workspace/crashes/snmp/crash-other")["reopened"] == 1
    assert _cand(run_dir)["status"] == "unverified"
    assert validate_run_dir(run_dir) == []


# ------------------------------------------------------------------ A/B switch


def test_flag_off_restores_the_earlier_behaviour(run_dir, monkeypatch):
    monkeypatch.setenv(ledger.REOPEN_ENV, "off")
    _seed_run(run_dir)
    _reject(run_dir, basis="model")
    assert "last_rejection" not in _cand(run_dir)

    out = _breaker(run_dir)
    assert set(out) == {
        "agent_id",
        "role",
        "seeds_promoted",
        "candidates_added",
        "strengthening_requests_added",
        "proof_gaps_recorded",
        "code_faults_recorded",
    }
    cand = _cand(run_dir)
    assert cand["status"] == "verified"
    assert not {"reopened", "contradicting_evidence", "last_rejection"} & set(cand)
    u = _unit(run_dir)
    assert u["status"] == "blocked" and u["evidence"][-1]["result"] == "breaker_crash_found"
    assert all(a["decision"] == "rejected" for a in u["attempts"])

    # The earlier fuzz behaviour, kept as it was: the units become `candidate` while the candidate
    # stays `verified` (nothing asks for a second verdict).
    _fuzz(run_dir)
    assert _cand(run_dir)["status"] == "verified"
    assert _unit(run_dir)["status"] == "candidate"


# ------------------------------------------------------------------ validator and report


def test_an_unverified_candidate_with_a_verdict_is_still_refused_unless_reopened(run_dir):
    _seed_run(run_dir)
    _reject(run_dir, basis="model")
    cands = _load(run_dir, "candidates.json")
    cands[0]["status"] = "unverified"
    write_json(run_dir / "candidates.json", cands)
    assert any("has a verdict but is still marked unverified" in e for e in validate_run_dir(run_dir))


def test_report_counts_reopened_and_contradicted_rejections(run_dir):
    _seed_run(run_dir)
    _reject(run_dir, basis="model")
    _breaker(run_dir)
    generate(run_dir, run_dir)
    summary = (run_dir / "REPORT.md").read_text(encoding="utf-8").split("## 2. Summary")[1].split("## 3.")[0]
    assert "| `disproved_by_source` | 0 | 0 | 1 | 0 |" in summary
    assert "- **Reopened rejections:** 1 candidate(s), 1 time(s) in all" in summary
    assert "1 still awaiting a verdict" in summary
    assert (
        f"`{FP_REJ}`: rejected as `disproved_by_source` (basis `model`), reopened by `breaker_crash_found`" in summary
    )
    assert "Contradicted `checked` rejections" not in summary

    ledger.cmd_ingest_verifier(_result(run_dir, _needs_validation(), "needs_validation", aid="verifier-5"))
    generate(run_dir, run_dir)
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "verdict after reopening: 1 needs_validation" in report
    assert "still awaiting a verdict" not in report


def test_report_counts_a_contradicted_checked_rejection(run_dir):
    _seed_run(run_dir)
    _reject(run_dir, basis="checked")
    _breaker(run_dir)
    generate(run_dir, run_dir)
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "- **Contradicted `checked` rejections:** 1 candidate(s)" in report
    assert "Reopened rejections" not in report
