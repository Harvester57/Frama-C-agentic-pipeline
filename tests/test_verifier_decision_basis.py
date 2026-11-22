"""Decision point on confirmed / needs_validation records and evidence basis on rejections.

Covers schemas/findings.schema.json, ledger.py (scaffold-verifier, ingest-verifier) and generate_report.py.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import ledger
from conftest import (
    FP_EVA,
    FP_PARSE,
    FP_REJ,
    confirmed_record,
    evidence,
    metadata,
    needs_validation_record,
    rejected_record,
    sorted_findings,
    unit,
    write_json,
)
from fingerprint import make_fingerprint
from generate_report import generate
from validate_artifacts import validate_agent_result, validate_findings, validate_run_dir

pytestmark = pytest.mark.unit

FP_PARSE_2 = make_fingerprint("src/snmp/ber.c", "ber_copy_value", "mem_access", r"\valid(dst + i)")
TAG_RTE = "src/snmp/ber.c#ber_decode_tag::rte"


def decision_point(**overrides) -> dict:
    return {
        "file": "src/snmp/ber.c",
        "line": 31,
        "function": "ber_decode_len",
        "controlled_by": "attacker_input",
        "description": "Length octets are taken from the packet without comparing them with the buffer size.",
        **overrides,
    }


# ------------------------------------------------------------------ schema


@pytest.mark.parametrize("make", [confirmed_record, needs_validation_record])
def test_decision_point_is_optional_and_validates(make):
    without = make()
    assert "decision_point" not in without
    assert validate_findings([without]) == []
    assert validate_findings([{**make(), "decision_point": decision_point()}]) == []


@pytest.mark.parametrize(
    "bad",
    [
        decision_point(controlled_by="developer"),
        decision_point(line=0),
        decision_point(file="/abs/ber.c"),
        {k: v for k, v in decision_point().items() if k != "controlled_by"},
        {**decision_point(), "extra": 1},
    ],
    ids=["bad-controlled-by", "line-zero", "absolute-file", "missing-controlled-by", "extra-key"],
)
def test_malformed_decision_point_is_refused(bad):
    assert validate_findings([{**confirmed_record(), "decision_point": bad}])
    assert validate_findings([{**needs_validation_record(), "decision_point": bad}])


def test_decision_point_is_not_a_field_of_rejected_records():
    assert validate_findings([{**rejected_record(), "decision_point": decision_point()}])


@pytest.mark.parametrize("basis", ["checked", "located", "model"])
def test_refutation_basis_is_optional_and_validates(basis):
    assert validate_findings([rejected_record()]) == []
    assert validate_findings([{**rejected_record(), "refutation_basis": basis}]) == []


def test_bad_refutation_basis_is_refused():
    assert validate_findings([{**rejected_record(), "refutation_basis": "verified"}])
    assert validate_findings([{**confirmed_record(), "refutation_basis": "checked"}])


# ------------------------------------------------------------------ ledger fixtures


def _seed_run(run_dir: Path, status: str = "candidate", discharging: bool = False) -> None:
    """One unit carrying the unverified candidate FP_REJ of module `snmp`."""
    write_json(run_dir / "run-metadata.json", metadata("in_progress"))
    ev = [
        {
            "phase": "fuzz",
            "producer": "run_eacsl_fuzz.py",
            "result": "fuzz_failure",
            "discharging": False,
            "tool_output": "workspace/reports/fuzz/snmp.json",
            "summary": "E-ACSL failure",
        }
    ]
    if discharging:
        ev.append(
            {
                "phase": "eva",
                "producer": "run_eva_slice.py",
                "result": "eva_all_valid",
                "discharging": True,
                "tool_output": "workspace/reports/fuzz/snmp.json",
                "summary": "All valid",
            }
        )
    u_tag = unit("src/snmp/ber.c", "ber_decode_tag", "rte", status=status, evidence=ev, result_fingerprints=[FP_REJ])
    write_json(run_dir / "coverage-ledger.json", [u_tag])
    write_json(run_dir / "workspace/reports/fuzz/snmp.json", {"status": "eacsl_violation"})
    write_json(
        run_dir / "candidates.json",
        [
            {
                "fingerprint": FP_REJ,
                "status": "unverified",
                "origin": "fuzz",
                "proposed_verdict": "confirmed",
                "module": "snmp",
                "location": {"file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag"},
                "property": {"kind": "mem_access", "predicate": r"\valid_read(p)"},
                "reproducers": [],
                "tool_outputs": ["workspace/reports/fuzz/snmp.json"],
                "linked_units": [TAG_RTE],
                "first_seen": "2026-10-29T00:00:00+00:00",
            }
        ],
    )


def _result(run_dir: Path, record: dict, decision: str, aid: str = "verifier-4") -> Path:
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
            "candidate_fingerprint": FP_REJ,
            "decision": decision,
            "refingerprint_reason": None,
            "record": record,
        },
    )
    return path


def _rejection(rej_class: str = "disproved_by_source", basis: str | None = None) -> dict:
    rec = rejected_record(FP_REJ)
    rec["rejection_class"] = rej_class
    rec["reason"] = "The branch is never taken."
    if basis is not None:
        rec["refutation_basis"] = basis
    return rec


def _state(run_dir: Path) -> tuple[dict, dict]:
    units = json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    return units[0], findings[0]


# ------------------------------------------------------------------ scaffold


def test_scaffold_emits_decision_point_and_basis(run_dir):
    _seed_run(run_dir)
    confirmed = ledger.cmd_scaffold_verifier(FP_REJ, "confirmed", "verifier-1")["record"]
    assert confirmed["decision_point"]["controlled_by"] == "attacker_input"
    assert confirmed["decision_point"]["file"] == "src/snmp/ber.c"

    needs = ledger.cmd_scaffold_verifier(FP_REJ, "needs_validation", "verifier-1")
    assert needs["record"]["decision_point"]["line"] == 12
    assert validate_agent_result(needs) == []

    rejected = ledger.cmd_scaffold_verifier(FP_REJ, "rejected", "verifier-1")
    assert rejected["record"]["refutation_basis"] == "model"
    assert "decision_point" not in rejected["record"]
    assert validate_agent_result(rejected) == []


# ------------------------------------------------------------------ ingest: decision point


@pytest.mark.parametrize("with_field", [False, True], ids=["without", "with"])
def test_ingest_needs_validation_with_and_without_decision_point(run_dir, with_field):
    _seed_run(run_dir)
    rec = needs_validation_record(FP_REJ)
    rec["location"] = {"file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag"}
    rec["trace"] = [
        {"kind": "sink", "file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag", "description": "*p"}
    ]
    rec["linked_units"] = [TAG_RTE]
    if with_field:
        rec["decision_point"] = decision_point(controlled_by="environment")
    ledger.cmd_ingest_verifier(_result(run_dir, rec, "needs_validation"))
    _, finding = _state(run_dir)
    assert ("decision_point" in finding) is with_field
    if with_field:
        assert finding["decision_point"]["controlled_by"] == "environment"
    assert validate_run_dir(run_dir) == []


def test_ingest_refuses_a_bad_controlled_by(run_dir):
    _seed_run(run_dir)
    rec = needs_validation_record(FP_REJ)
    rec["location"] = {"file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag"}
    rec["linked_units"] = [TAG_RTE]
    rec["decision_point"] = decision_point(controlled_by="nobody")
    # The refusal names the field: the generic prefix alone would pass on any other invalid part of the result.
    with pytest.raises(
        ledger.LedgerError, match=r"(?s)invalid crash_verifier result:.*\.decision_point\.controlled_by: "
    ):
        ledger.cmd_ingest_verifier(_result(run_dir, rec, "needs_validation"))
    assert not (run_dir / "findings.json").exists() or json.loads((run_dir / "findings.json").read_text()) == []


# ------------------------------------------------------------------ ingest: refutation basis


@pytest.mark.parametrize("basis", [None, "model", "located", "checked"])
@pytest.mark.parametrize("discharging", [False, True], ids=["no-proof", "proof"])
def test_basis_is_recorded_and_never_changes_the_unit_status(run_dir, basis, discharging):
    _seed_run(run_dir, discharging=discharging)
    ledger.cmd_ingest_verifier(_result(run_dir, _rejection(basis=basis), "rejected"))
    u, finding = _state(run_dir)
    # The same status whatever the basis: `covered` with discharging evidence, `blocked` without.
    assert u["status"] == ("covered" if discharging else "blocked")
    attempt = u["attempts"][-1]
    assert attempt["rejection_class"] == "disproved_by_source"
    assert attempt["refutation_basis"] == (basis or "unstated")
    assert "refutation_basis_stated" not in attempt
    note = [e["summary"] for e in u["evidence"] if e["phase"] == "verifier"][-1]
    assert note.startswith(f"Rejected (disproved_by_source, basis {basis or 'unstated'}): ")
    assert finding.get("refutation_basis") == basis
    assert validate_run_dir(run_dir) == []


def test_ingest_refuses_a_bad_refutation_basis(run_dir):
    _seed_run(run_dir)
    with pytest.raises(ledger.LedgerError, match=r"(?s)invalid crash_verifier result:.*\.refutation_basis: "):
        ledger.cmd_ingest_verifier(_result(run_dir, _rejection(basis="proven"), "rejected"))


def _eva_row(line: int = 12, file: str = "ber.c", directory: str = "src/snmp", bucket: str = "Dead") -> dict:
    return {
        "directory": directory,
        "file": file,
        "function": "ber_decode_tag",
        "line": line,
        "kind": "mem_access",
        "status": bucket,
        "status_bucket": bucket,
        "annotation": r"\valid_read(p)",
    }


def _eva_report(**kw) -> dict:
    return {"module": "snmp", "status": "ok", "dead_alarms": [_eva_row()], **kw}


@pytest.mark.parametrize("stated", [None, "model", "located"])
def test_dead_code_is_raised_to_checked_when_eva_reports_the_line_dead(run_dir, stated):
    _seed_run(run_dir)
    write_json(run_dir / "workspace/reports/eva/snmp.json", _eva_report())
    ledger.cmd_ingest_verifier(_result(run_dir, _rejection("dead_code", stated), "rejected"))
    u, finding = _state(run_dir)
    attempt = u["attempts"][-1]
    assert attempt["refutation_basis"] == "checked"
    assert attempt["refutation_basis_stated"] == (stated or "unstated")
    assert attempt["refutation_basis_source"] == "eva_dead"
    assert finding["refutation_basis"] == "checked"
    # `checked` means a cited tool output: the Eva report is added to the record's evidence.
    assert "workspace/reports/eva/snmp.json" in [e["tool_output"] for e in finding["evidence"]]
    assert u["status"] == "blocked"
    assert validate_run_dir(run_dir) == []


@pytest.mark.parametrize(
    "report",
    [
        None,
        _eva_report(status="analysis_error"),
        _eva_report(dead_alarms=[_eva_row(line=13)]),
        _eva_report(dead_alarms=[_eva_row(file="other.c")]),
        _eva_report(invalid_alarms=[_eva_row(bucket="Invalid")]),
        _eva_report(unknown_obligations_by_function={"ber_decode_tag": [_eva_row(bucket="Unknown")]}),
        _eva_report(dead_alarms="corrupt"),
    ],
    ids=["no-report", "eva-failed", "other-line", "other-file", "invalid-there", "unknown-there", "bad-shape"],
)
def test_dead_code_basis_stays_as_stated_when_eva_does_not_agree(run_dir, report):
    _seed_run(run_dir)
    if report is not None:
        write_json(run_dir / "workspace/reports/eva/snmp.json", report)
    ledger.cmd_ingest_verifier(_result(run_dir, _rejection("dead_code", "located"), "rejected"))
    u, finding = _state(run_dir)
    assert u["attempts"][-1]["refutation_basis"] == "located"
    assert "refutation_basis_source" not in u["attempts"][-1]
    assert finding["refutation_basis"] == "located"
    assert len(finding["evidence"]) == 1


def test_only_dead_code_is_checked_against_the_reports(run_dir):
    _seed_run(run_dir)
    write_json(run_dir / "workspace/reports/eva/snmp.json", _eva_report())
    ledger.cmd_ingest_verifier(_result(run_dir, _rejection("disproved_by_source", "located"), "rejected"))
    u, _ = _state(run_dir)
    assert u["attempts"][-1]["refutation_basis"] == "located"


def _coverage(executions: int, status: str = "ok", file: str = "src/snmp/ber.c") -> dict:
    return {
        "module": "snmp",
        "status": status,
        "functions": [
            {"function": "ber_decode_tag", "file": file, "line": 10, "executions": executions},
            {"function": "ber_decode_len", "file": "src/snmp/ber.c", "line": 30, "executions": 5},
        ],
    }


def test_dead_code_is_raised_to_checked_when_no_input_executed_the_function(run_dir):
    _seed_run(run_dir)
    write_json(run_dir / "workspace/reports/coverage/snmp.json", _coverage(0))
    ledger.cmd_ingest_verifier(_result(run_dir, _rejection("dead_code", "model"), "rejected"))
    u, finding = _state(run_dir)
    assert u["attempts"][-1]["refutation_basis"] == "checked"
    assert u["attempts"][-1]["refutation_basis_source"] == "fuzz_coverage"
    assert "workspace/reports/coverage/snmp.json" in [e["tool_output"] for e in finding["evidence"]]
    assert validate_run_dir(run_dir) == []


@pytest.mark.parametrize(
    "coverage",
    [_coverage(3), _coverage(0, status="partial"), _coverage(0, file="src/other/ber.c"), {"status": "ok"}],
    ids=["executed", "partial-replay", "other-file", "no-functions"],
)
def test_dead_code_basis_stays_as_stated_when_coverage_does_not_agree(run_dir, coverage):
    _seed_run(run_dir)
    write_json(run_dir / "workspace/reports/coverage/snmp.json", coverage)
    ledger.cmd_ingest_verifier(_result(run_dir, _rejection("dead_code", "model"), "rejected"))
    u, _ = _state(run_dir)
    assert u["attempts"][-1]["refutation_basis"] == "model"


# ------------------------------------------------------------------ report


def _report_run(run: Path, findings: list[dict], units: list[dict]) -> None:
    for p in (
        "workspace/reports/fuzz/snmp.json",
        "workspace/reports/eva/log.json",
        "agents/verifier-3/artifacts/notes.txt",
    ):
        write_json(run / p, {})
    crash = run / "workspace/crashes/snmp/crash-1"
    crash.parent.mkdir(parents=True, exist_ok=True)
    crash.write_bytes(b"abc")
    for rec in findings:
        for rep in rec.get("reproducers", []):
            rep["sha256"] = hashlib.sha256(b"abc").hexdigest()
    write_json(run / "run-metadata.json", metadata("incomplete", "candidate_validation_not_run"))
    write_json(run / "coverage-ledger.json", sorted(units, key=lambda u: u["coverage_id"]))
    write_json(run / "candidates.json", [])
    write_json(run / "findings.json", sorted_findings(*findings))


def _cand_unit(file: str, fn: str, fp: str, module: str = "snmp") -> dict:
    ev = [
        evidence(phase="fuzz", result="fuzz_failure", discharging=False, tool_output="workspace/reports/fuzz/snmp.json")
    ]
    return unit(file, fn, "rte", "candidate", evidence=ev, result_fingerprints=[fp], module=module)


def _second_confirmed() -> dict:
    rec = confirmed_record(FP_PARSE_2)
    rec["title"] = "Out-of-bounds write in BER value copy"
    rec["location"] = {"file": "src/snmp/ber.c", "line": 90, "function": "ber_copy_value"}
    rec["property"] = {"kind": "mem_access", "predicate": r"\valid(dst + i)"}
    rec["linked_units"] = ["src/snmp/ber.c#ber_copy_value::rte"]
    return rec


def test_report_prints_the_decision_point_and_lists_shared_ones(tmp_path):
    first = {**confirmed_record(), "decision_point": decision_point()}
    second = {**_second_confirmed(), "decision_point": decision_point(description="Same unchecked length.")}
    needs = {**needs_validation_record(), "decision_point": decision_point(line=40, controlled_by="environment")}
    _report_run(
        tmp_path,
        [first, second, needs],
        [
            _cand_unit("src/snmp/ber.c", "ber_decode_len", FP_PARSE),
            _cand_unit("src/snmp/ber.c", "ber_copy_value", FP_PARSE_2),
            _cand_unit("src/log/emit.c", "emit_field", FP_EVA, module="log"),
        ],
    )
    generate(tmp_path, tmp_path)
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    line = "- **Decision point:** `src/snmp/ber.c:31` in `ber_decode_len`, controlled by `attacker_input`: "
    assert report.count(line) == 2
    assert report.index("- **Root cause:**") < report.index(line) < report.index("- **Reproduce:**")
    assert "share a decision point (possibly one defect" in report
    assert f"- `src/snmp/ber.c:31`: `{min(FP_PARSE, FP_PARSE_2)}`, `{max(FP_PARSE, FP_PARSE_2)}`" in report
    # Report only: both findings stay separate records.
    assert "- **Confirmed findings:** 2" in report

    detail = (tmp_path / "FINDINGS-DETAIL.md").read_text(encoding="utf-8")
    assert detail.count("**Decision point.** `src/snmp/ber.c:31`") == 2
    nv = (tmp_path / "NEEDS-VALIDATION.md").read_text(encoding="utf-8")
    assert "**Decision point.** `src/snmp/ber.c:40` in `ber_decode_len`, controlled by `environment`" in nv


def test_report_without_decision_points_has_no_such_lines(tmp_path):
    second = {**_second_confirmed(), "decision_point": decision_point(line=88)}
    _report_run(
        tmp_path,
        [confirmed_record(), second, needs_validation_record()],
        [
            _cand_unit("src/snmp/ber.c", "ber_decode_len", FP_PARSE),
            _cand_unit("src/snmp/ber.c", "ber_copy_value", FP_PARSE_2),
            _cand_unit("src/log/emit.c", "emit_field", FP_EVA, module="log"),
        ],
    )
    generate(tmp_path, tmp_path)
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    assert report.count("- **Decision point:**") == 1
    assert "share a decision point" not in report  # one finding per decision point
    assert "Decision point" not in (tmp_path / "NEEDS-VALIDATION.md").read_text(encoding="utf-8")
    assert "Rejected candidates by class" not in report  # no rejection, no table


def test_report_counts_rejections_by_class_and_basis(tmp_path):
    def rej(fn: str, cls: str, basis: str | None) -> dict:
        rec = rejected_record(make_fingerprint("src/snmp/ber.c", fn, "mem_access", r"\valid_read(p)"))
        rec["location"] = {"file": "src/snmp/ber.c", "line": 12, "function": fn}
        rec["rejection_class"] = cls
        rec["linked_units"] = []
        if basis:
            rec["refutation_basis"] = basis
        return rec

    findings = [
        rej("f_a", "dead_code", "checked"),
        rej("f_b", "dead_code", "checked"),
        rej("f_c", "dead_code", "model"),
        rej("f_d", "disproved_by_source", "located"),
        rej("f_e", "harness_induced", None),
    ]
    _report_run(tmp_path, findings, [unit("src/snmp/ber.c", "ber_decode_tag", "rte", "planned")])
    generate(tmp_path, tmp_path)
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    summary = report.split("## 2. Summary")[1].split("## 3.")[0]
    assert "- **Rejected candidates:** 5" in summary
    assert "| Rejection class | checked | located | model | unstated |" in summary
    assert "| `dead_code` | 2 | 0 | 1 | 0 |" in summary
    assert "| `disproved_by_source` | 0 | 1 | 0 | 0 |" in summary
    assert "| `harness_induced` | 0 | 0 | 0 | 1 |" in summary
