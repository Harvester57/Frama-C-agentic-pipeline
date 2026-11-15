"""A WP proof is credited only under an accepted memory model, and an experimental one is an assumption.

ledger.py `ingest-wp` asks framac_common.wp_model_problem / wp_model_assumption about the report's
model (or the model of its triggered bitwise retry); generate_report.py counts the result.
"""

from __future__ import annotations

import pytest

import ledger as L
from conftest import metadata, write_json
from framac_common import WP_EXPERIMENTAL_MODEL_ASSUMPTION
from generate_report import assurance_table, generate
from test_ledger import load, seed, wp_report
from validate_artifacts import validate_ledger

pytestmark = pytest.mark.unit

REPORT = "workspace/reports/wp/snmp_parse_pdu.json"
PROVEN = {"rte": {"proven": 3, "proven_under_hyp": 0, "unproven": 0}}


def _ingest(run_dir, **kw) -> dict:
    seed(run_dir)
    write_json(run_dir / REPORT, wp_report(by_obligation_class=PROVEN, **kw))
    L.cmd_ingest_wp([run_dir / REPORT])
    ledger = load(run_dir / "coverage-ledger.json")
    assert list(validate_ledger(ledger, run_dir)) == []
    return next(u for u in ledger if u["function"] == "snmp_parse_pdu" and u["obligation_class"] == "rte")


def _assurance_row(unit: dict) -> list[str]:
    """generate_report's own assurance row for the unit's class: [unconditional, with assumptions, ...]."""
    row = next(line for line in assurance_table([unit]) if line.startswith("| `rte` |"))
    return [c.strip() for c in row.strip("|").split("|")][1:]


@pytest.mark.parametrize(
    "kw",
    [
        {"wp_model": "Bytes"},
        {"wp_model": "Bytes+int"},
        {"bitwise_retry": {"triggered": True, "wp_model": "Bytes", "timeout": 10, "initial_unproven_count": 2}},
    ],
    ids=["bytes", "bytes-int", "bitwise-retry-bytes"],
)
def test_a_bytes_proof_is_credited_under_an_assumption(run_dir, kw):
    unit = _ingest(run_dir, **kw)
    assert unit["status"] == "covered"
    assert {"kind": "other", "description": WP_EXPERIMENTAL_MODEL_ASSUMPTION, "related_units": []} in unit[
        "assumptions"
    ]
    unconditional, with_assumptions = _assurance_row(unit)[:2]
    assert (unconditional, with_assumptions) == ("0", "1")


@pytest.mark.parametrize(
    "kw",
    [
        {"wp_model": "Hoare"},
        {"wp_model": "Typed+nat"},
        {"wp_model": "Region"},
        {"bitwise_retry": {"triggered": True, "wp_model": "Typed+real", "timeout": 10, "initial_unproven_count": 2}},
    ],
    ids=["hoare", "nat", "region", "bitwise-retry-real"],
)
def test_a_proof_under_a_rejected_model_is_not_credited(run_dir, kw):
    unit = _ingest(run_dir, **kw)
    assert unit["status"] == "blocked"
    last = unit["evidence"][-1]
    assert last["result"] == "wp_unsound_proof" and not last["discharging"]
    assert any("not accepted as evidence" in r for r in unit["unresolved"])


@pytest.mark.parametrize(
    "kw", [{}, {"wp_model": "Typed"}, {"wp_model": "Typed+ref+int"}], ids=["none", "typed", "typed-ref-int"]
)
def test_a_typed_proof_is_unchanged(run_dir, kw):
    unit = _ingest(run_dir, **kw)
    assert unit["status"] == "covered" and unit["assumptions"] == []
    assert _assurance_row(unit)[:2] == ["1", "0"]


def test_the_report_counts_a_bytes_proof_as_conditional_and_names_the_model(run_dir):
    _ingest(run_dir, wp_model="Bytes")
    write_json(run_dir / "run-metadata.json", metadata("in_progress"))
    # test_ledger's DAG and security properties are seeding stubs, not full reports.
    (run_dir / "workspace/reports/callgraph_dag.json").unlink()
    (run_dir / "workspace/reports/security_props.json").unlink()
    generate(run_dir, run_dir)
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "- **Proof coverage:** 0 unit(s) proven unconditionally, 1 proven under open assumptions" in report
    assert f"- of these, 1 unit(s) {WP_EXPERIMENTAL_MODEL_ASSUMPTION}" in report


def test_an_untriggered_bitwise_retry_model_is_ignored(run_dir):
    retry = {"triggered": False, "wp_model": "Hoare", "timeout": 10, "initial_unproven_count": 2}
    unit = _ingest(run_dir, bitwise_retry=retry)
    assert unit["status"] == "covered" and unit["assumptions"] == []
