"""Remediation plan P1 recall (docs/remediation-plan.md, H7 and H8) for scripts/ledger.py."""

import json

import pytest

import ledger as L
from conftest import write_json
from fingerprint import make_fingerprint
from test_ledger import DAG, eva_report, load, seed, units_by_id
from validate_artifacts import validate_candidates, validate_ledger

pytestmark = pytest.mark.unit


def assert_valid(run_dir):
    assert list(validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []
    assert list(validate_candidates(load(run_dir / "candidates.json"))) == []


# ------------------------------------------------------------------ H7


def test_eva_invalid_in_deferred_unit_becomes_linked_candidate(run_dir):
    seed(run_dir, "quick")  # glue_init is Tier 3: its rte unit is deferred under quick.
    alarm = {
        "file": "workspace/work/src/glue/init.c",
        "function": "glue_init",
        "line": 7,
        "kind": "mem_access",
        "annotation": r"\valid(p)",
    }
    write_json(run_dir / "workspace/reports/eva/snmp.json", eva_report(invalid_alarms=[alarm]))
    out = L.cmd_ingest_eva([run_dir / "workspace/reports/eva/snmp.json"])
    assert out["candidates"] == 1
    fp = make_fingerprint("src/glue/init.c", "glue_init", "mem_access", r"\valid(p)")
    (cand,) = load(run_dir / "candidates.json")
    assert cand["fingerprint"] == fp
    assert cand["origin"] == "eva" and cand["proposed_verdict"] == "needs_validation"
    # The harness that found it (the Tier 3 module has none): replay and verification go through it.
    assert cand["module"] == "snmp"
    assert cand["linked_units"] == ["src/glue/init.c#glue_init::rte"]
    glue = units_by_id(run_dir)["src/glue/init.c#glue_init::rte"]
    assert glue["status"] == "candidate" and glue["result_fingerprints"] == [fp]
    assert glue["evidence"][-1]["result"] == "eva_invalid"
    assert_valid(run_dir)
    # Re-ingesting the same report changes nothing.
    before = (load(run_dir / "coverage-ledger.json"), load(run_dir / "candidates.json"))
    L.cmd_ingest_eva([run_dir / "workspace/reports/eva/snmp.json"])
    assert (load(run_dir / "coverage-ledger.json"), load(run_dir / "candidates.json")) == before


@pytest.mark.parametrize(
    ("file", "function"),
    [
        ("workspace/work/src/snmp/ber.c", "ber_decode_tag"),  # out_of_scope via --scope
        ("workspace/work/src/snmp/unseeded.c", "never_seeded"),  # no unit at all
    ],
)
def test_eva_invalid_without_eligible_unit_becomes_unlinked_candidate(run_dir, file, function):
    write_json(run_dir / "workspace/reports/callgraph_dag.json", DAG)
    L.cmd_seed(run_dir / "workspace/reports/callgraph_dag.json", ["src/snmp/pdu.c", "src/glue"], "regex")
    alarm = {"file": file, "function": function, "line": 3, "kind": "index_bound", "annotation": "i < 4"}
    write_json(run_dir / "workspace/reports/eva/snmp.json", eva_report(invalid_alarms=[alarm]))
    assert L.cmd_ingest_eva([run_dir / "workspace/reports/eva/snmp.json"])["candidates"] == 1
    (cand,) = load(run_dir / "candidates.json")
    nf = file.removeprefix("workspace/work/")
    assert cand["fingerprint"] == make_fingerprint(nf, function, "index_bound", "i < 4")
    assert cand["linked_units"] == [] and cand["proposed_verdict"] == "needs_validation"
    assert cand["location"] == {"file": nf, "line": 3, "function": function}
    assert all(not u["result_fingerprints"] for u in units_by_id(run_dir).values())
    assert_valid(run_dir)


def test_eva_valid_unknown_dead_unchanged_for_deferred_units(run_dir):
    seed(run_dir, "quick")
    rep = eva_report(
        invalid_alarms=[],
        unknown_obligations_by_function={"glue_init": [{"line": 1}]},
        dead_alarms=[{"function": "glue_init", "line": 2}],
        functions_with_properties=["glue_init"],
    )
    write_json(run_dir / "workspace/reports/eva/snmp.json", rep)
    assert L.cmd_ingest_eva([run_dir / "workspace/reports/eva/snmp.json"])["candidates"] == 0
    glue = units_by_id(run_dir)["src/glue/init.c#glue_init::rte"]
    assert glue["status"] == "deferred" and glue["evidence"] == []


# ------------------------------------------------------------------ H8 (a)


def _prover_result(aid, evidence, **kw):
    res = {
        "role": "prover",
        "agent_id": aid,
        "file": "src/snmp/ber.c",
        "function": "ber_decode_len",
        "status": "blocked",
        "patch": None,
        "evidence": evidence,
        "unproven_goals": [],
        "strengthening_requests": [],
        "boundary_assumptions": [],
        "fault_hypothesis": None,
        "proof_gap": None,
    }
    res.update(kw)
    return res


def _code_fault_report(crash_abs):
    return {
        "status": "code_fault",
        "reason": "An RTE assertion failed on a real input.",
        "fingerprint": "ignored",
        "failure": {
            "file": "/work/run/workspace/work/src/snmp/ber.c",
            "line": 42,
            "function": "ber_decode_len",
            "kind": "Assertion",
            "alarm_kind": "mem_access",
            "is_rte": True,
            "label": "rte/mem_access",
            "predicate": r"\valid_read(buf + off)",
        },
        "runtime_trace": f"==1== ERROR: libFuzzer: deadly signal\nTest unit written to {crash_abs}\n",
    }


@pytest.mark.parametrize("with_crash", [True, False])
def test_prover_guardrail_code_fault_becomes_candidate(run_dir, with_crash):
    seed(run_dir)
    aid = "prover-cf"
    scratch = run_dir / "agents" / aid / "scratch"
    crash = scratch / "guard" / "crash-0123abcd"
    if with_crash:
        crash.parent.mkdir(parents=True)
        crash.write_bytes(b"\x30\x84\xff")
    write_json(
        scratch / "guard_ber_decode_len.json",
        _code_fault_report(f"/container/run/{crash.relative_to(run_dir).as_posix()}"),
    )
    write_json(scratch / "wp_ber_decode_len.json", {"status": "unproven_goals_remain"})
    res_path = scratch / "result.json"
    write_json(
        res_path,
        _prover_result(
            aid,
            [
                {"tool_output": f"agents/{aid}/scratch/wp_ber_decode_len.json", "result": "unproven_goals_remain"},
                {"tool_output": f"agents/{aid}/scratch/guard_ber_decode_len.json", "result": "code_fault"},
            ],
        ),
    )
    out = L.cmd_ingest_agent_hypothesis(res_path, module="snmp")
    assert out["code_faults_recorded"] == 1 and out["candidates_added"] == 1

    fp = make_fingerprint("src/snmp/ber.c", "ber_decode_len", "mem_access", r"\valid_read(buf + off)")
    (cand,) = load(run_dir / "candidates.json")
    assert cand["fingerprint"] == fp and cand["origin"] == "prover"
    assert cand["linked_units"] == ["src/snmp/ber.c#ber_decode_len::rte"]
    assert cand["tool_outputs"] == [f"agents/{aid}/artifacts/code_fault_scratch_guard_ber_decode_len.json"]
    assert (run_dir / cand["tool_outputs"][0]).is_file()
    if with_crash:
        assert cand["proposed_verdict"] == "confirmed"
        (repro,) = cand["reproducers"]
        assert repro.startswith("workspace/crashes/snmp/crash-")
        assert (run_dir / repro).read_bytes() == b"\x30\x84\xff"
    else:
        assert cand["proposed_verdict"] == "needs_validation" and cand["reproducers"] == []
    units = units_by_id(run_dir)
    rte = units["src/snmp/ber.c#ber_decode_len::rte"]
    assert rte["status"] == "candidate" and rte["result_fingerprints"] == [fp]
    assert rte["evidence"][-1]["result"] == "guardrail_code_fault"
    assert units["src/snmp/ber.c#ber_decode_len::l2_termination"]["status"] == "planned"
    assert_valid(run_dir)

    # Re-ingesting the same result adds no second candidate.
    again = L.cmd_ingest_agent_hypothesis(res_path, module="snmp")
    assert again["candidates_added"] == 0 and len(load(run_dir / "candidates.json")) == 1


def test_prover_without_code_fault_creates_no_candidate(run_dir):
    seed(run_dir)
    aid = "prover-ok"
    scratch = run_dir / "agents" / aid / "scratch"
    write_json(scratch / "guard_ber_decode_len.json", {"status": "passed_dynamic_oracle"})
    res_path = scratch / "result.json"
    write_json(
        res_path,
        _prover_result(
            aid,
            [{"tool_output": f"agents/{aid}/scratch/guard_ber_decode_len.json", "result": "passed"}],
            status="stalled_after_k_retries",
            unproven_goals=["rte: mem_access"],
        ),
    )
    out = L.cmd_ingest_agent_hypothesis(res_path, module="snmp")
    assert out["code_faults_recorded"] == 0 and out["candidates_added"] == 0
    assert load(run_dir / "candidates.json") == []


# ------------------------------------------------------------------ H8 (b)


def test_record_boundary_assumptions_prover_is_idempotent(run_dir, capsys):
    seed(run_dir)
    aid = "prover-ba"
    res_path = run_dir / "agents" / aid / "scratch" / "result.json"
    write_json(run_dir / "agents" / aid / "scratch" / "wp.json", {})
    write_json(
        res_path,
        _prover_result(
            aid,
            [{"tool_output": f"agents/{aid}/scratch/wp.json", "result": "all_proven"}],
            status="all_proven",
            boundary_assumptions=["Callers pass len <= sizeof(buf).", "Callers pass len <= sizeof(buf).", "x != 0"],
        ),
    )
    out = L.cmd_record_boundary_assumptions(res_path)
    ids = [
        "src/snmp/ber.c#ber_decode_len::l2_termination",
        "src/snmp/ber.c#ber_decode_len::l6_secret",
        "src/snmp/ber.c#ber_decode_len::rte",
    ]
    assert out["units"] == ids and out["added"] == 6
    units = units_by_id(run_dir)
    for cid in ids:
        assert [a["description"] for a in units[cid]["assumptions"] if a["kind"] == "boundary_assumption"] == [
            "Callers pass len <= sizeof(buf).",
            "x != 0",
        ]
    assert_valid(run_dir)
    before = load(run_dir / "coverage-ledger.json")
    assert L.main(["record-boundary-assumptions", str(res_path)]) == 0
    assert json.loads(capsys.readouterr().out)["added"] == 0
    assert load(run_dir / "coverage-ledger.json") == before


def test_record_boundary_assumptions_architect_names_no_function(run_dir):
    seed(run_dir)
    aid = "architect-1"
    write_json(run_dir / "agents" / aid / "scratch" / "guard.json", {})
    res_path = run_dir / "agents" / aid / "scratch" / "result.json"
    write_json(
        res_path,
        {
            "role": "architect",
            "agent_id": aid,
            "header": "src/snmp/ber.h",
            "status": "passed",
            "patch": None,
            "evidence": [{"tool_output": f"agents/{aid}/scratch/guard.json", "result": "passed"}],
            "boundary_assumptions": ["Buffers are never aliased."],
            "notes": "",
        },
    )
    before = load(run_dir / "coverage-ledger.json")
    out = L.cmd_record_boundary_assumptions(res_path)
    assert out["added"] == 0 and out["units"] == [] and "skipped_reason" in out
    assert load(run_dir / "coverage-ledger.json") == before


def test_record_boundary_assumptions_skips_deferred_units(run_dir):
    seed(run_dir, "quick")
    aid = "prover-glue"
    write_json(run_dir / "agents" / aid / "scratch" / "wp.json", {})
    res_path = run_dir / "agents" / aid / "scratch" / "result.json"
    write_json(
        res_path,
        _prover_result(
            aid,
            [{"tool_output": f"agents/{aid}/scratch/wp.json", "result": "all_proven"}],
            file="src/glue/init.c",
            function="glue_init",
            status="all_proven",
            boundary_assumptions=["Called once at startup."],
        ),
    )
    out = L.cmd_record_boundary_assumptions(res_path)
    assert out["added"] == 0 and out["units"] == [] and "skipped_reason" in out
    assert units_by_id(run_dir)["src/glue/init.c#glue_init::rte"]["assumptions"] == []
