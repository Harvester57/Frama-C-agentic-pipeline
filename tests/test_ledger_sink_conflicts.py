"""Opposite verdicts on one sink are recorded and the rejection gets one second look (ledger.py ingest-verifier).

Two candidates with different fingerprints can fail at the same sink (file, function, baseline line,
kind). When one is confirmed (or needs_validation) and the other rejected, both records name each
other in `conflicts_with`, and the rejected candidate is reopened once with a `sibling_verdict`
evidence source. A second rejection keeps the pair flagged; nothing picks a side.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import ledger
from conftest import confirmed_record, metadata, needs_validation_record, rejected_record, unit, write_json
from fingerprint import make_fingerprint
from generate_report import generate, sink_conflict_lines
from validate_artifacts import validate_run_dir

pytestmark = pytest.mark.unit

SINK = {"file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag"}
UNIT_ID = "src/snmp/ber.c#ber_decode_tag::rte"
FP_POS = make_fingerprint("src/snmp/ber.c", "ber_decode_tag", "mem_access", r"\valid_read(p + 0)")
FP_NEG = make_fingerprint("src/snmp/ber.c", "ber_decode_tag", "mem_access", r"\valid_read(p)")
FUZZ = "workspace/reports/fuzz/snmp.json"
CRASH = "workspace/crashes/snmp/crash-pos"


@pytest.fixture(autouse=True)
def _reopen_on(monkeypatch):
    monkeypatch.delenv(ledger.REOPEN_ENV, raising=False)


def _load(run_dir: Path, name: str):
    return json.loads((run_dir / name).read_text(encoding="utf-8"))


def _cands(run_dir: Path) -> dict[str, dict]:
    return {c["fingerprint"]: c for c in _load(run_dir, "candidates.json")}


def _findings(run_dir: Path) -> dict[str, dict]:
    return {r["fingerprint"]: r for r in _load(run_dir, "findings.json")}


def _candidate(fp: str, predicate: str) -> dict:
    return {
        "fingerprint": fp,
        "status": "unverified",
        "origin": "fuzz",
        "proposed_verdict": "confirmed",
        "module": "snmp",
        "location": dict(SINK),
        "property": {"kind": "mem_access", "predicate": predicate},
        "reproducers": [CRASH] if fp == FP_POS else [],
        "tool_outputs": [FUZZ],
        "linked_units": [UNIT_ID],
        "first_seen": "2026-11-15T00:00:00+00:00",
    }


def _seed(run_dir: Path) -> None:
    """Two unverified candidates of module `snmp` failing at the same sink, and the module's harness."""
    write_json(run_dir / "run-metadata.json", metadata("in_progress"))
    ev = {
        "phase": "fuzz",
        "producer": "run_eacsl_fuzz.py",
        "result": "fuzz_failure",
        "discharging": False,
        "tool_output": FUZZ,
        "summary": "E-ACSL failure",
    }
    u = unit("src/snmp/ber.c", "ber_decode_tag", "rte", status="candidate", evidence=[ev])
    u["result_fingerprints"] = sorted([FP_POS, FP_NEG])
    write_json(run_dir / "coverage-ledger.json", [u])
    crash = run_dir / CRASH
    crash.parent.mkdir(parents=True, exist_ok=True)
    crash.write_bytes(b"\x04\x00\x01")
    sha = hashlib.sha256(crash.read_bytes()).hexdigest()
    # The artifact says what it failed on, as run_eacsl_fuzz.py writes it: ingest-verifier compares it.
    art = {"artifact": CRASH, "sha256": sha, "reproducible": True, "failure": None, "fingerprint": FP_POS}
    write_json(run_dir / FUZZ, {"status": "eacsl_violation", "artifacts": [art]})
    write_json(
        run_dir / "candidates.json",
        [_candidate(fp, pred) for fp, pred in sorted([(FP_POS, r"\valid_read(p + 0)"), (FP_NEG, r"\valid_read(p)")])],
    )
    harness = run_dir / "workspace/harnesses/harness_snmp.c"
    harness.parent.mkdir(parents=True, exist_ok=True)
    harness.write_text("int harness;\n", encoding="utf-8")
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
        },
    )


def _result(run_dir: Path, cand_fp: str, record: dict, aid: str) -> Path:
    notes = run_dir / "agents" / aid / "scratch" / "notes.txt"
    notes.parent.mkdir(parents=True, exist_ok=True)
    notes.write_text("notes", encoding="utf-8")
    record["evidence"] = [
        {"phase": "verifier", "tool_output": f"agents/{aid}/scratch/notes.txt", "description": "Source review."}
    ]
    record["verifier"] = {"agent_id": aid, "method": "source_review", "notes": "Reviewed."}
    path = run_dir / "agents" / aid / "scratch" / "res.json"
    write_json(
        path,
        {
            "role": "crash_verifier",
            "agent_id": aid,
            "candidate_fingerprint": cand_fp,
            "decision": record["verdict"],
            "refingerprint_reason": None,
            "record": record,
        },
    )
    return path


def _positive(run_dir: Path, verdict: str = "confirmed", aid: str = "verifier-pos", fp: str = FP_POS) -> dict:
    if verdict == "confirmed":
        rec = confirmed_record(fp)
        rec["reproducers"][0].update(
            input=CRASH,
            sha256=hashlib.sha256((run_dir / CRASH).read_bytes()).hexdigest(),
            size_bytes=(run_dir / CRASH).stat().st_size,
        )
        rec["trace"][-1].update(file=SINK["file"], line=SINK["line"], function=SINK["function"])
    else:
        rec = needs_validation_record(fp)
        rec["trace"] = [{"kind": "sink", **SINK, "description": "*p"}]
    rec["location"] = dict(SINK)
    rec["property"] = {"kind": "mem_access", "predicate": r"\valid_read(p + 0)" if fp == FP_POS else r"\valid_read(p)"}
    rec["linked_units"] = [UNIT_ID]
    return ledger.cmd_ingest_verifier(_result(run_dir, fp, rec, aid))


def _negative(
    run_dir: Path, rej_class: str = "harness_induced", basis: str | None = "located", aid: str = "verifier-neg"
) -> dict:
    rec = rejected_record(FP_NEG)
    rec["rejection_class"] = rej_class
    if basis is not None:
        rec["refutation_basis"] = basis
    return ledger.cmd_ingest_verifier(_result(run_dir, FP_NEG, rec, aid))


def _assert_reopened_by_sibling(run_dir: Path) -> None:
    neg = _cands(run_dir)[FP_NEG]
    assert neg["status"] == "unverified" and "resolved_fingerprints" not in neg
    entry = neg["reopened"][-1]
    assert entry["evidence"]["source"] == "sibling_verdict"
    assert entry["rejected_fingerprints"] == [FP_NEG] and "resolved" not in entry
    assert _cands(run_dir)[FP_POS]["status"] == "verified"
    findings = _findings(run_dir)
    assert findings[FP_POS]["conflicts_with"] == [FP_NEG]
    assert findings[FP_NEG]["conflicts_with"] == [FP_POS]
    (u,) = _load(run_dir, "coverage-ledger.json")
    assert u["status"] == "candidate" and FP_NEG in u["result_fingerprints"]
    assert u["attempts"][-1]["decision"] == "reopened"
    assert validate_run_dir(run_dir) == []


# ------------------------------------------------------------------ detection and reopening


@pytest.mark.parametrize("verdict", ["confirmed", "needs_validation"])
def test_a_rejection_after_a_positive_verdict_on_its_sink_is_reopened(run_dir, verdict):
    _seed(run_dir)
    assert "sink_conflicts" not in _positive(run_dir, verdict)
    out = _negative(run_dir)
    assert out["sink_conflicts"] == [{"positive": FP_POS, "negative": FP_NEG, "outcome": "reopened"}]
    _assert_reopened_by_sibling(run_dir)
    evidence = _cands(run_dir)[FP_NEG]["reopened"][-1]["evidence"]
    # The sibling's reproducer goes to the re-verification (a needs_validation sibling has none).
    assert evidence["artifact"] == (CRASH if verdict == "confirmed" else "agents/verifier-pos/artifacts/notes.txt")


def test_a_positive_verdict_after_a_rejection_on_its_sink_reopens_the_rejection(run_dir):
    _seed(run_dir)
    assert "sink_conflicts" not in _negative(run_dir)
    assert _cands(run_dir)[FP_NEG]["status"] == "verified"
    out = _positive(run_dir)
    assert out["sink_conflicts"] == [{"positive": FP_POS, "negative": FP_NEG, "outcome": "reopened"}]
    _assert_reopened_by_sibling(run_dir)
    assert _cands(run_dir)[FP_NEG]["reopened"][-1]["evidence"]["artifact"] == CRASH


def test_a_second_rejection_is_not_reopened_again_and_the_pair_stays_flagged(run_dir):
    _seed(run_dir)
    _positive(run_dir)
    _negative(run_dir)
    out = _negative(run_dir, aid="verifier-neg-2")
    assert out["superseded_rejections"] == [FP_NEG]
    assert out["sink_conflicts"] == [{"positive": FP_POS, "negative": FP_NEG, "outcome": "already_reverified"}]
    neg = _cands(run_dir)[FP_NEG]
    assert neg["status"] == "verified" and len(neg["reopened"]) == 1
    assert neg["reopened"][0]["resolved"]["decision"] == "rejected"
    findings = _findings(run_dir)
    assert findings[FP_POS]["conflicts_with"] == [FP_NEG]
    assert findings[FP_NEG]["conflicts_with"] == [FP_POS]
    assert findings[FP_NEG]["prior_verdicts"][0]["reopened_by"]["source"] == "sibling_verdict"
    assert validate_run_dir(run_dir) == []


def test_a_confirming_second_verdict_merges_and_clears_the_conflict(run_dir):
    _seed(run_dir)
    _positive(run_dir)
    _negative(run_dir)
    out = _positive(run_dir, aid="verifier-neg-2", fp=FP_NEG)
    assert "sink_conflicts" not in out and out["resolved_fingerprints"] == [FP_POS]
    findings = _findings(run_dir)
    assert set(findings) == {FP_POS} and "conflicts_with" not in findings[FP_POS]
    assert validate_run_dir(run_dir) == []


def test_a_duplicate_rejection_is_not_a_conflict(run_dir):
    _seed(run_dir)
    _positive(run_dir)
    out = _negative(run_dir, rej_class="duplicate")
    assert "sink_conflicts" not in out
    assert _cands(run_dir)[FP_NEG]["status"] == "verified"
    assert not any("conflicts_with" in r for r in _findings(run_dir).values())
    assert validate_run_dir(run_dir) == []


def test_a_checked_rejection_is_re_verified_against_a_confirmed_sibling(run_dir):
    """QCBOR run-6, EncodeHead: a reproduced crash and a `checked` harness_induced rejection at one sink."""
    _seed(run_dir)
    _positive(run_dir, "confirmed")
    out = _negative(run_dir, basis="checked")
    assert out["sink_conflicts"] == [{"positive": FP_POS, "negative": FP_NEG, "outcome": "reopened"}]
    _assert_reopened_by_sibling(run_dir)


def test_a_checked_rejection_is_kept_against_a_needs_validation_sibling(run_dir):
    _seed(run_dir)
    _positive(run_dir, "needs_validation")
    out = _negative(run_dir, basis="checked")
    assert out["sink_conflicts"] == [
        {"positive": FP_POS, "negative": FP_NEG, "outcome": "contradicted", "reason": "checked_rejection"}
    ]
    neg = _cands(run_dir)[FP_NEG]
    assert neg["status"] == "verified" and "reopened" not in neg
    (entry,) = neg["contradicting_evidence"]
    assert entry["source"] == "sibling_verdict" and entry["reason"] == "checked_rejection"
    assert _findings(run_dir)[FP_NEG]["conflicts_with"] == [FP_POS]
    assert validate_run_dir(run_dir) == []


def test_conflicts_are_recorded_with_reopening_switched_off(run_dir, monkeypatch):
    monkeypatch.setenv(ledger.REOPEN_ENV, "off")
    _seed(run_dir)
    _positive(run_dir)
    out = _negative(run_dir)
    assert out["sink_conflicts"] == [{"positive": FP_POS, "negative": FP_NEG, "outcome": "not_reopened"}]
    assert _cands(run_dir)[FP_NEG]["status"] == "verified"
    assert _findings(run_dir)[FP_POS]["conflicts_with"] == [FP_NEG]


def test_a_verifier_cannot_supply_conflicts_with(run_dir):
    _seed(run_dir)
    rec = rejected_record(FP_NEG)
    rec["conflicts_with"] = [FP_POS]
    ledger.cmd_ingest_verifier(_result(run_dir, FP_NEG, rec, "verifier-neg"))
    assert "conflicts_with" not in _findings(run_dir)[FP_NEG]


# ------------------------------------------------------------------ report


def test_report_and_needs_validation_list_the_conflicting_pair(run_dir):
    _seed(run_dir)
    _positive(run_dir, "needs_validation")
    _negative(run_dir, basis="checked")
    generate(run_dir, run_dir)
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "- **Opposite verdicts at one sink:** 1 pair(s)" in report
    assert f"`{FP_POS}` (needs_validation) vs `{FP_NEG}` (rejected as `harness_induced`, basis `checked`)" in report
    needs = (run_dir / "NEEDS-VALIDATION.md").read_text(encoding="utf-8")
    assert f"**Conflicting verdict.** `{FP_NEG}`: rejected as `harness_induced`" in needs


def test_report_finds_a_reopened_candidate_by_its_reopening(run_dir):
    """A candidate refingerprinted onto the rejected record loses resolved_fingerprints when reopened."""
    _seed(run_dir)
    _positive(run_dir)
    _negative(run_dir)
    findings = _load(run_dir, "findings.json")
    cand = _cands(run_dir)[FP_NEG]
    other = {**cand, "fingerprint": make_fingerprint("src/snmp/ber.c", "ber_decode_tag", "mem_access", "q")}
    lines = sink_conflict_lines(findings, [other])
    assert lines[1].endswith(": the rejection is reopened and awaits re-verification")


def test_report_flags_a_confirmed_finding_with_a_conflicting_rejection(run_dir):
    _seed(run_dir)
    _positive(run_dir)
    _negative(run_dir)
    _negative(run_dir, aid="verifier-neg-2")
    generate(run_dir, run_dir)
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert f"- **Conflicting verdict:** `{FP_NEG}`: rejected as `harness_induced`" in report
    assert "re-verified after reopening, still opposite" in report
