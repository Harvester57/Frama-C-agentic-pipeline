"""Remediation plan P1 recall (docs/remediation-plan.md, H7 and H8) for scripts/ledger.py."""

import json

import pytest

import ledger as L
from conftest import FP_REJ, evidence, metadata, rejected_record, unit, write_json
from fingerprint import make_fingerprint
from test_ledger import DAG, eva_report, load, seed, units_by_id
from validate_artifacts import (
    validate_agent_result,
    validate_candidates,
    validate_findings,
    validate_ledger,
    validate_run_dir,
)

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
    L.cmd_seed(run_dir / "workspace/reports/callgraph_dag.json", ["src/snmp/pdu.c", "src/glue"], "frama_c")
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
        "src/snmp/ber.c#ber_decode_len::l6_wiped",
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


# ------------------------------------------------------------------ O1 (verifier records, 8936217)

LIBC_FREE = ("FRAMAC_SHARE/libc/stdlib.h", "free", "mem_access", "\\freeable(p)")
HARNESS_CRASH_FP = "harness_snmp.c#unknown_function::unparsed_crash::0123456789"
FUZZ_REPORT = "workspace/reports/fuzz/snmp.json"
TAG_RTE = "src/snmp/ber.c#ber_decode_tag::rte"
TAG_L2 = "src/snmp/ber.c#ber_decode_tag::l2_termination"
TAG_L3 = "src/snmp/ber.c#ber_decode_tag::l3_frame"
DEFERRAL = "tier3_not_scheduled: Tier 3 is deferred under the quick profile"


def _verifier_run(run_dir, units, candidates):
    """A run directory with these ledger units and candidates, and the fuzz report they cite."""
    write_json(run_dir / "run-metadata.json", metadata("in_progress"))
    write_json(run_dir / "coverage-ledger.json", sorted(units, key=lambda u: u["coverage_id"]))
    write_json(run_dir / "candidates.json", sorted(candidates, key=lambda c: c["fingerprint"]))
    write_json(run_dir / FUZZ_REPORT, {"module": "snmp", "status": "eacsl_violation"})


def _candidate(fp, file, function, kind, predicate, linked):
    return {
        "fingerprint": fp,
        "status": "unverified",
        "origin": "fuzz",
        "proposed_verdict": "needs_validation",
        "module": "snmp",
        "location": {"file": file, "line": 3, "function": function},
        "property": {"kind": kind, "predicate": predicate},
        "reproducers": [],
        "tool_outputs": [FUZZ_REPORT],
        "linked_units": linked,
        "first_seen": "2026-10-29T00:00:00+00:00",
    }


def _unlinked_candidate(where):
    """A candidate with no target unit: in a libc stub, or in generated harness code."""
    if where == "libc_stub":
        return _candidate(make_fingerprint(*LIBC_FREE), *LIBC_FREE, [])
    return _candidate(HARNESS_CRASH_FP, "harness_snmp.c", "unknown_function", "crash", "", [])


def _tag_candidate():
    return _candidate(FP_REJ, "src/snmp/ber.c", "ber_decode_tag", "mem_access", "\\valid_read(p)", [TAG_RTE])


def _tag_units(rte_status="candidate"):
    """ber_decode_tag: an rte unit (holding the candidate), a deferred l2 unit, an out-of-scope l3 unit."""
    rte = unit("src/snmp/ber.c", "ber_decode_tag", "rte", status=rte_status)
    if rte_status == "candidate":
        rte["evidence"] = [evidence(phase="fuzz", result="fuzz_failure", discharging=False, tool_output=FUZZ_REPORT)]
        rte["result_fingerprints"] = [FP_REJ]
    l2 = unit("src/snmp/ber.c", "ber_decode_tag", "l2_termination", status="deferred", unresolved=[DEFERRAL])
    l3 = unit("src/snmp/ber.c", "ber_decode_tag", "l3_frame", status="out_of_scope", unresolved=["outside --scope"])
    return [rte, l2, l3]


def _write_result(run_dir, res):
    path = run_dir / "agents" / res["agent_id"] / "scratch" / "result.json"
    write_json(path, res)
    return path


@pytest.mark.parametrize("where", ["libc_stub", "harness_code"])
def test_rejected_record_without_target_unit_validates_and_ingests(run_dir, where):
    """Troubleshooting `linked_units: fewer than 1 items` (fixed in 8936217): a rejected record may link no unit."""
    cand = _unlinked_candidate(where)
    _verifier_run(run_dir, [unit("src/snmp/ber.c", "ber_decode_len", "rte")], [cand])
    res = L.cmd_scaffold_verifier(cand["fingerprint"], "rejected", "verifier-1")
    assert res["record"]["linked_units"] == []
    assert list(validate_findings([res["record"]])) == []
    assert list(validate_agent_result(res)) == []

    out = L.cmd_ingest_verifier(_write_result(run_dir, res))
    assert out["decision"] == "rejected"
    (finding,) = load(run_dir / "findings.json")
    assert finding["verdict"] == "rejected" and finding["linked_units"] == []
    assert load(run_dir / "candidates.json")[0]["status"] == "verified"
    assert units_by_id(run_dir)["src/snmp/ber.c#ber_decode_len::rte"]["status"] == "planned"
    assert validate_run_dir(run_dir) == []


def test_scaffold_rejected_links_only_the_candidate_units(run_dir):
    """Troubleshooting `deferred unit must not hide evidence` (fixed in 8936217): the scaffold's links."""
    _verifier_run(run_dir, _tag_units(), [_tag_candidate()])

    # Only a confirmed bug claims the whole function (every unit not out of scope) to keep it from WP.
    confirmed = L.cmd_scaffold_verifier(FP_REJ, "confirmed", "verifier-1")
    assert sorted(confirmed["record"]["linked_units"]) == [TAG_L2, TAG_RTE]
    res = L.cmd_scaffold_verifier(FP_REJ, "rejected", "verifier-1")
    assert res["record"]["linked_units"] == [TAG_RTE]
    assert list(validate_agent_result(res)) == []

    L.cmd_ingest_verifier(_write_result(run_dir, res))
    units = units_by_id(run_dir)
    assert units[TAG_RTE]["status"] == "planned"  # harness_induced, and the harness repair is not exhausted
    assert units[TAG_L2]["status"] == "deferred" and units[TAG_L2]["evidence"] == []
    assert validate_run_dir(run_dir) == []


def test_rejection_evidence_on_a_deferred_unit_blocks_it(run_dir):
    """The ingest-verifier safety net: a NO_EVIDENCE_STATES unit that receives rejection evidence becomes blocked."""
    _verifier_run(run_dir, _tag_units(), [_tag_candidate()])
    write_json(run_dir / "agents/verifier-3/artifacts/notes.txt", {"notes": "bounds checked by every caller"})
    rec = rejected_record(FP_REJ)
    rec["rejection_class"] = "disproved_by_source"
    rec["linked_units"] = [TAG_RTE, TAG_L2]  # hand-written, or scaffolded before 8936217
    res = {
        "role": "crash_verifier",
        "agent_id": "verifier-3",
        "candidate_fingerprint": FP_REJ,
        "decision": "rejected",
        "refingerprint_reason": None,
        "record": rec,
    }
    assert list(validate_agent_result(res)) == []

    L.cmd_ingest_verifier(_write_result(run_dir, res))
    units = units_by_id(run_dir)
    l2 = units[TAG_L2]
    assert l2["status"] == "blocked" and l2["agent_id"] is None
    assert [e["result"] for e in l2["evidence"]] == ["rejected:disproved_by_source"]
    assert any(a.get("decision") == "rejected" and a["result_fingerprints"] == [FP_REJ] for a in l2["attempts"])
    # The rejection explains the blocked unit; its old deferral reason follows it.
    assert l2["unresolved"] == [f"candidate_rejected (disproved_by_source): {rec['reason']}", DEFERRAL]
    assert units[TAG_RTE]["status"] == "blocked"
    assert units[TAG_RTE]["unresolved"] == [f"candidate_rejected (disproved_by_source): {rec['reason']}"]
    assert units[TAG_L3]["status"] == "out_of_scope" and units[TAG_L3]["evidence"] == []
    assert validate_run_dir(run_dir) == []


@pytest.mark.parametrize("where", ["libc_stub", "harness_code", "resolved_to_target_function"])
def test_scaffold_needs_validation_for_unlinked_candidate_is_ingestible(run_dir, where):
    cand = _unlinked_candidate("harness_code" if where == "resolved_to_target_function" else where)
    _verifier_run(run_dir, _tag_units(rte_status="planned"), [cand])
    overrides: dict = {}
    if where == "resolved_to_target_function":
        overrides = {"file_override": "src/snmp/ber.c", "fn_override": "ber_decode_tag", "line_override": 12}
    res = L.cmd_scaffold_verifier(cand["fingerprint"], "needs_validation", "verifier-1", **overrides)
    if where == "resolved_to_target_function":
        # Linked to the resolved function's units that may carry evidence, as before 8936217.
        assert res["record"]["linked_units"] == [TAG_RTE]
    else:
        assert res["record"]["linked_units"] == []
    L.cmd_ingest_verifier(_write_result(run_dir, res))
    assert load(run_dir / "findings.json")[0]["verdict"] == "needs_validation"
    assert validate_run_dir(run_dir) == []
