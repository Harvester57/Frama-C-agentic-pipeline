import hashlib
import json

import pytest

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
from framac_common import ArtifactError
from generate_report import generate


def build_run(run, status="incomplete", reason="candidate_validation_not_run", unverified=True):
    for p in (
        "workspace/reports/fuzz/snmp.json",
        "workspace/reports/eva/log.json",
        "workspace/reports/eva/snmp.json",
        "agents/verifier-3/artifacts/notes.txt",
    ):
        write_json(run / p, {})
    crash = run / "workspace/crashes/snmp/crash-1"
    crash.parent.mkdir(parents=True, exist_ok=True)
    crash.write_bytes(b"abc")
    rec = confirmed_record()
    rec["reproducers"][0]["sha256"] = hashlib.sha256(b"abc").hexdigest()
    findings = sorted_findings(rec, needs_validation_record(), rejected_record())
    ev = [
        evidence(phase="fuzz", result="fuzz_failure", discharging=False, tool_output="workspace/reports/fuzz/snmp.json")
    ]
    ledger = [
        unit("src/snmp/ber.c", "ber_decode_len", "rte", "candidate", evidence=ev, result_fingerprints=[FP_PARSE]),
        unit(
            "src/log/emit.c", "emit_field", "rte", "candidate", evidence=ev, result_fingerprints=[FP_EVA], module="log"
        ),
        unit("src/snmp/ber.c", "ber_decode_tag", "rte", "candidate", evidence=ev, result_fingerprints=[FP_REJ]),
        unit(
            "src/snmp/pdu.c",
            "snmp_parse_pdu",
            "rte",
            "covered",
            evidence=[evidence(tool_output="workspace/reports/eva/snmp.json")],
            assumptions=[{"kind": "boundary_assumption", "description": "Eva context", "related_units": []}],
        ),
        unit(
            "src/snmp/pdu.c",
            "snmp_free",
            "rte",
            "covered",
            evidence=[evidence(tool_output="workspace/reports/eva/snmp.json")],
        ),
        unit(
            "src/snmp/pdu.c",
            "snmp_parse_pdu",
            "l2_termination",
            "blocked",
            evidence=[
                evidence(
                    phase="wp", result="wp_unproven", discharging=False, tool_output="workspace/reports/eva/snmp.json"
                )
            ],
            unresolved=["unproven loop variant at line 7"],
        ),
        unit("src/glue/init.c", "glue_init", "rte", "deferred", unresolved=["tier3_not_scheduled"], module="glue"),
    ]
    cands = []
    if unverified:
        cands.append(
            {
                "fingerprint": "src/snmp/pdu.c#snmp_parse_pdu::timeout::0123456789",
                "status": "unverified",
                "origin": "fuzz",
                "proposed_verdict": "needs_validation",
                "module": "snmp",
                "location": {"file": "src/snmp/pdu.c", "line": 0, "function": "snmp_parse_pdu"},
                "property": {"kind": "timeout", "predicate": ""},
                "reproducers": [],
                "tool_outputs": ["workspace/reports/fuzz/snmp.json"],
                "linked_units": [],
                "first_seen": "t",
            }
        )
    write_json(run / "run-metadata.json", metadata(status, reason if status == "incomplete" else None))
    write_json(run / "coverage-ledger.json", sorted(ledger, key=lambda u: u["coverage_id"]))
    write_json(run / "candidates.json", cands)
    write_json(run / "findings.json", findings)


def test_report_renders_status_first_and_separates_verdicts(tmp_path):
    build_run(tmp_path)
    res = generate(tmp_path, tmp_path)
    assert res["unverified_candidates"] == 1
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    first_section = report.split("## 2.")[0]
    assert "**incomplete (reason: candidate_validation_not_run)**" in first_section
    assert "partial pass" in first_section
    assert "have not been independently verified" in first_section
    assert "| high | Out-of-bounds read in BER length decoder" in report
    assert "Possible signed overflow" in report.split("## 4. Needs validation")[1]
    assert "Harness passed NULL" not in report  # rejected records are not findings
    assert "1 unit(s) proven unconditionally, 1 proven under open assumptions" in report
    assert "unproven loop variant at line 7" in report
    assert "tier3_not_scheduled" in report

    detail = (tmp_path / "FINDINGS-DETAIL.md").read_text(encoding="utf-8")
    assert "Out-of-bounds read" in detail and "contract respected" in detail
    nv = (tmp_path / "NEEDS-VALIDATION.md").read_text(encoding="utf-8")
    assert "No input reaching" in nv

    sarif = json.loads((tmp_path / "report.sarif").read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    assert {r["level"] for r in results} == {"error", "warning"}
    assert len(results) == 2
    assert all("framacFingerprint/v1" in r["partialFingerprints"] for r in results)


def test_report_aborts_on_invalid_input(tmp_path):
    build_run(tmp_path)
    data = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    data[0]["severity"] = "catastrophic"
    write_json(tmp_path / "findings.json", data)
    with pytest.raises(ArtifactError):
        generate(tmp_path, tmp_path)
    assert not (tmp_path / "REPORT.md").exists()


def test_complete_run_with_unverified_candidates_is_rejected(tmp_path):
    build_run(tmp_path, status="complete")
    with pytest.raises(ArtifactError):
        generate(tmp_path, tmp_path)


def test_report_dedupes_same_sink_findings_and_shows_work_line_shift(tmp_path):
    build_run(tmp_path)
    # Create baseline and work files where merged ACSL shifted line 42 to line 45
    base_f = tmp_path / "workspace/baseline/src/snmp/ber.c"
    work_f = tmp_path / "workspace/work/src/snmp/ber.c"
    base_f.parent.mkdir(parents=True, exist_ok=True)
    work_f.parent.mkdir(parents=True, exist_ok=True)
    base_lines = [f"int line_{i} = {i};" for i in range(1, 50)]
    work_lines = base_lines[:40] + ["/*@ requires x >= 0;", "    assigns \\nothing;", "*/"] + base_lines[40:]
    base_f.write_text("\n".join(base_lines) + "\n", encoding="utf-8")
    work_f.write_text("\n".join(work_lines) + "\n", encoding="utf-8")

    findings = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    orig = next(r for r in findings if r["verdict"] == "confirmed")
    orig["location"]["line"] = 45  # work line 45 corresponds to baseline line 42
    dup_fp = "src/snmp/ber.c#ber_decode_len::rte::9999999999"
    dup = json.loads(json.dumps(orig))
    dup["fingerprint"] = dup_fp
    dup["location"]["line"] = 42  # baseline line 42
    dup["property"]["predicate"] = "\\valid(heap + len)"
    findings.append(dup)
    write_json(tmp_path / "findings.json", sorted_findings(*findings))

    ledger = json.loads((tmp_path / "coverage-ledger.json").read_text(encoding="utf-8"))
    for u in ledger:
        if u["coverage_id"] == "src/snmp/ber.c#ber_decode_len::rte":
            u["result_fingerprints"].append(dup_fp)
    write_json(tmp_path / "coverage-ledger.json", ledger)

    generate(tmp_path, tmp_path)
    report = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    assert "- **Confirmed findings:** 1 (1 high)" in report
    assert "also merged:" in report
    assert "work: `src/snmp/ber.c:45`" in report
