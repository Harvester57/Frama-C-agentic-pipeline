"""
Step S7 (F7, F9): what a fuzz campaign ran, per function and per engine, is recorded as ledger evidence.

Ingest follows `tests/test_r2_ledger_seed_fuzz.py`: a seeded ledger in a run directory, then `cmd_ingest_fuzz`.
"""

import pytest

import ledger as L
from conftest import write_json
from test_ledger import load, seed, units_by_id
from validate_artifacts import validate_ledger

pytestmark = pytest.mark.unit

T1A = "Tier 1A (Untrusted Binary / Network Parser)"
EVIDENCE_DAG_REL = "workspace/reports/callgraph_dag.json"
FUZZ_EVIDENCE_RESULTS = ("fuzz_clean", "fuzz_not_executed", "fuzz_fuzzer_error")

# Two functions named `helper`, one in each file: a coverage row must match its unit by file as well.
EVIDENCE_DAG = {
    "callgraph_source": "frama_c",
    "modules": {"snmp": {"tier": T1A}},
    "functions": {
        "helper_a": {
            "name": "helper",
            "file": "src/a.c",
            "module": "snmp",
            "wave": 0,
            "has_loops": False,
            "security_properties": [],
        },
        "helper_b": {
            "name": "helper",
            "file": "src/b.c",
            "module": "snmp",
            "wave": 0,
            "has_loops": False,
            "security_properties": [],
        },
    },
}


def _row(function: str, file: str, executions: int) -> dict:
    return {
        "function": function,
        "file": file,
        "line": 1,
        "executions": executions,
        "regions": {"total": 1, "covered": 1 if executions else 0},
    }


def _coverage(run_dir, status: str | None, functions=(), inputs=None) -> None:
    """Write workspace/reports/coverage/snmp.json; `status=None` writes no report at all."""
    if status is None:
        return
    report = {
        "mode": "coverage",
        "module": "snmp",
        "status": status,
        "inputs": inputs or {"total": 5, "replayed": 5, "failed": 0, "not_replayed": 0, "known_crash": 0},
        "functions": list(functions),
    }
    write_json(run_dir / "workspace/reports/coverage/snmp.json", report)


def _clean_ingest(run_dir) -> None:
    write_json(
        run_dir / "workspace/reports/fuzz/snmp.json",
        {"mode": "campaign", "module": "snmp", "status": "clean", "artifacts": []},
    )
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/snmp.json"])


def _fuzz_evidence(run_dir) -> dict[str, list[dict]]:
    return {
        u["coverage_id"]: [e for e in u["evidence"] if e["result"] in FUZZ_EVIDENCE_RESULTS]
        for u in load(run_dir / "coverage-ledger.json")
    }


def test_a_function_no_input_reached_gets_fuzz_not_executed(run_dir):
    seed(run_dir)
    _coverage(
        run_dir,
        "ok",
        [_row("ber_decode_len", "src/snmp/ber.c", 0), _row("ber_decode_tag", "src/snmp/ber.c", 5)],
    )
    _clean_ingest(run_dir)
    units = units_by_id(run_dir)
    not_run = units["src/snmp/ber.c#ber_decode_len::rte"]["evidence"][-1]
    assert not_run["result"] == "fuzz_not_executed" and not_run["discharging"] is False
    assert not_run["summary"] == (
        "E-ACSL + LibFuzzer campaign: no replayed input executed this function (not evidence of anything)."
    )
    assert units["src/snmp/ber.c#ber_decode_tag::rte"]["evidence"][-1]["result"] == "fuzz_clean"
    assert list(validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


def test_a_function_the_coverage_report_does_not_list_gets_fuzz_not_executed(run_dir):
    seed(run_dir)
    _coverage(run_dir, "ok", [_row("ber_decode_tag", "src/snmp/ber.c", 5)])
    _clean_ingest(run_dir)
    fuzz = _fuzz_evidence(run_dir)
    assert [e["result"] for e in fuzz["src/snmp/ber.c#ber_decode_len::rte"]] == ["fuzz_not_executed"]
    assert [e["result"] for e in fuzz["src/snmp/ber.c#ber_decode_tag::rte"]] == ["fuzz_clean"]


def test_the_same_function_name_in_two_files_is_matched_by_file(run_dir):
    write_json(run_dir / EVIDENCE_DAG_REL, EVIDENCE_DAG)
    write_json(run_dir / "workspace/reports/security_props.json", {"obligations": {}})
    L.cmd_seed(run_dir / EVIDENCE_DAG_REL, [], "frama_c")
    # helper in a.c never ran; helper in b.c ran 4 times. A match on the name alone would credit both.
    _coverage(run_dir, "ok", [_row("helper", "src/a.c", 0), _row("helper", "src/b.c", 4)])
    _clean_ingest(run_dir)
    fuzz = _fuzz_evidence(run_dir)
    assert [e["result"] for e in fuzz["src/a.c#helper::rte"]] == ["fuzz_not_executed"]
    assert [e["result"] for e in fuzz["src/b.c#helper::rte"]] == ["fuzz_clean"]


def test_a_partial_report_with_every_input_replayed_is_usable(run_dir):
    seed(run_dir)
    _coverage(
        run_dir,
        "partial",
        [_row("ber_decode_len", "src/snmp/ber.c", 0), _row("ber_decode_tag", "src/snmp/ber.c", 5)],
        inputs={"total": 5, "replayed": 4, "failed": 1, "not_replayed": 0, "known_crash": 0},
    )
    _clean_ingest(run_dir)
    fuzz = _fuzz_evidence(run_dir)
    assert [e["result"] for e in fuzz["src/snmp/ber.c#ber_decode_len::rte"]] == ["fuzz_not_executed"]
    assert [e["result"] for e in fuzz["src/snmp/ber.c#ber_decode_tag::rte"]] == ["fuzz_clean"]


@pytest.mark.parametrize(
    "status, inputs, reason",
    [
        (None, None, "no coverage report"),  # no coverage report written
        ("no_inputs", None, "coverage report status no_inputs"),
        ("compile_error", None, "coverage report status compile_error"),
        ("coverage_error", None, "coverage report status coverage_error"),
        (
            "partial",
            {"total": 5, "replayed": 2, "failed": 0, "not_replayed": 3, "known_crash": 0},
            "partial coverage: 3 of 5 inputs not replayed",
        ),
    ],
    ids=["missing", "no_inputs", "compile_error", "coverage_error", "partial_not_replayed"],
)
def test_without_a_usable_coverage_report_the_clean_evidence_says_unmeasured(run_dir, status, inputs, reason):
    seed(run_dir)
    # The rows would make ber_decode_len `fuzz_not_executed` if the report were usable.
    _coverage(run_dir, status, [_row("ber_decode_len", "src/snmp/ber.c", 0)], inputs=inputs)
    _clean_ingest(run_dir)
    snmp = {k: v for k, v in _fuzz_evidence(run_dir).items() if k.startswith("src/snmp/")}
    assert snmp["src/snmp/ber.c#ber_decode_len::rte"], "the clean campaign is still ingested"
    for coverage_id, evidence in snmp.items():
        assert [e["result"] for e in evidence] == ["fuzz_clean"], coverage_id
        summary = evidence[0]["summary"]
        assert summary.startswith("E-ACSL + LibFuzzer campaign found no failure (not a proof).")
        assert summary.endswith(f"Which functions ran was not measured ({reason}).")
