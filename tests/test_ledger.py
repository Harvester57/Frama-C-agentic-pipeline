import json

import pytest

import ledger as L
from conftest import write_json
from validate_artifacts import validate_candidates, validate_ledger

DAG = {
    "callgraph_source": "regex",
    "modules": {
        "snmp": {"tier": "Tier 1A (Untrusted Binary / Network Parser)"},
        "glue": {"tier": "Tier 3 (Internal State / Glue Module)"},
    },
    "functions": {
        "ber_decode_len": {"name": "ber_decode_len", "file": "src/snmp/ber.c", "module": "snmp", "wave": 0, "has_loops": True,
                           "security_properties": [{"layer": 2, "reason": "loops"}, {"layer": 6, "reason": "touches auth_key"}]},
        "ber_decode_tag": {"name": "ber_decode_tag", "file": "src/snmp/ber.c", "module": "snmp", "wave": 0, "has_loops": False, "security_properties": []},
        "snmp_parse_pdu": {"name": "snmp_parse_pdu", "file": "src/snmp/pdu.c", "module": "snmp", "wave": 1, "has_loops": False, "security_properties": []},
        "glue_init": {"name": "glue_init", "file": "src/glue/init.c", "module": "glue", "wave": 0, "has_loops": False, "security_properties": []},
    },
}


def load(path):
    return json.loads(open(path, encoding="utf-8").read())


def seed(run_dir):
    write_json(run_dir / "workspace/reports/callgraph_dag.json", DAG)
    return L.cmd_seed(run_dir / "workspace/reports/callgraph_dag.json", [], "regex")


def units_by_id(run_dir):
    return {u["coverage_id"]: u for u in load(run_dir / "coverage-ledger.json")}


def test_seed_policy(run_dir):
    out = seed(run_dir)
    units = units_by_id(run_dir)
    assert out["added_units"] == 6
    assert units["src/snmp/ber.c#ber_decode_len::rte"]["status"] == "planned"
    assert units["src/snmp/ber.c#ber_decode_len::l2_termination"]["status"] == "planned"
    assert units["src/snmp/ber.c#ber_decode_len::l6_secret"]["inference_reason"] == "touches auth_key"
    assert "src/snmp/ber.c#ber_decode_tag::l2_termination" not in units
    glue = units["src/glue/init.c#glue_init::rte"]
    assert glue["status"] == "deferred" and glue["unresolved"][0].startswith("tier3_not_scheduled")
    # Seeding again is idempotent.
    assert seed(run_dir)["added_units"] == 0


def test_seed_scope_marks_out_of_scope(run_dir):
    write_json(run_dir / "dag.json", DAG)
    L.cmd_seed(run_dir / "dag.json", ["src/snmp/pdu.c"], "regex")
    units = units_by_id(run_dir)
    assert units["src/snmp/pdu.c#snmp_parse_pdu::rte"]["status"] == "planned"
    assert units["src/snmp/ber.c#ber_decode_tag::rte"]["status"] == "out_of_scope"


def eva_report(**kw):
    r = {
        "status": "ok", "module": "snmp",
        "unknown_obligations_by_function": {"snmp_parse_pdu": [{"line": 5}]},
        "invalid_alarms": [{"file": "workspace/work/src/snmp/ber.c", "function": "ber_decode_len", "line": 42, "kind": "assertion",
                            "annotation": "mem_access: \\valid_read(buf + off)"}],
        "dead_alarms": [],
        "assumed_properties": [{"function": "ber_decode_tag"}],
        "functions_with_properties": ["ber_decode_len", "ber_decode_tag", "snmp_parse_pdu"],
    }
    r.update(kw)
    return r


def test_ingest_eva(run_dir):
    seed(run_dir)
    write_json(run_dir / "workspace/reports/eva/snmp.json", eva_report())
    out = L.cmd_ingest_eva([run_dir / "workspace/reports/eva/snmp.json"])
    assert out == {"reports": 1, "covered": 1, "candidates": 1}
    units = units_by_id(run_dir)
    tag = units["src/snmp/ber.c#ber_decode_tag::rte"]
    assert tag["status"] == "covered"
    assert {a["kind"] for a in tag["assumptions"]} == {"stub_contract", "boundary_assumption"}
    assert tag["evidence"][0]["tool_output"] == "workspace/reports/eva/snmp.json"
    ln = units["src/snmp/ber.c#ber_decode_len::rte"]
    assert ln["status"] == "candidate" and len(ln["result_fingerprints"]) == 1
    pdu = units["src/snmp/pdu.c#snmp_parse_pdu::rte"]
    assert pdu["status"] == "planned" and pdu["evidence"][0]["result"] == "eva_unknown"
    cands = load(run_dir / "candidates.json")
    assert cands[0]["origin"] == "eva" and cands[0]["proposed_verdict"] == "needs_validation"
    assert cands[0]["location"]["file"] == "src/snmp/ber.c"
    assert list(validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


def test_ingest_eva_analysis_error_never_covers(run_dir):
    seed(run_dir)
    write_json(run_dir / "workspace/reports/eva/snmp.json", eva_report(status="analysis_error"))
    L.cmd_ingest_eva([run_dir / "workspace/reports/eva/snmp.json"])
    assert all(u["status"] != "covered" for u in units_by_id(run_dir).values())


def test_ingest_fuzz_crash_and_clean(run_dir):
    seed(run_dir)
    crash = run_dir / "workspace/crashes/snmp/crash-abc"
    crash.parent.mkdir(parents=True)
    crash.write_bytes(b"\x30\x84")
    from fingerprint import make_fingerprint
    fp = make_fingerprint("src/snmp/ber.c", "ber_decode_len", "mem_access", "mem_access: \\valid_read(buf + off)")
    report = {
        "mode": "campaign", "module": "snmp", "status": "crash_found",
        "artifacts": [{
            "artifact": str(crash), "kind": "crash", "sha256": "x", "size_bytes": 2, "reproducible": True, "fingerprint": fp,
            "failure": {"file": "/framac-run/workspace/work/src/snmp/ber.c", "line": 42, "function": "ber_decode_len",
                        "kind": "assertion", "alarm_kind": "mem_access", "is_rte": True, "predicate": "mem_access: \\valid_read(buf + off)"},
        }],
    }
    write_json(run_dir / "workspace/reports/fuzz/snmp.json", report)
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/snmp.json"])
    units = units_by_id(run_dir)
    assert units["src/snmp/ber.c#ber_decode_len::rte"]["result_fingerprints"] == [fp]
    cands = {c["fingerprint"]: c for c in load(run_dir / "candidates.json")}
    assert cands[fp]["proposed_verdict"] == "confirmed"
    assert cands[fp]["reproducers"] == ["workspace/crashes/snmp/crash-abc"]

    # Eva later reports the same predicate: same fingerprint, one candidate.
    write_json(run_dir / "workspace/reports/eva/snmp.json", eva_report())
    L.cmd_ingest_eva([run_dir / "workspace/reports/eva/snmp.json"])
    cands = load(run_dir / "candidates.json")
    assert len(cands) == 1 and cands[0]["proposed_verdict"] == "confirmed"
    assert set(cands[0]["tool_outputs"]) == {"workspace/reports/fuzz/snmp.json", "workspace/reports/eva/snmp.json"}
    assert list(validate_candidates(cands)) == []


def test_ingest_fuzz_unparsed_crash_gets_triage_candidate(run_dir):
    seed(run_dir)
    report = {"module": "snmp", "status": "crash_found",
              "artifacts": [{"artifact": "workspace/crashes/snmp/crash-1", "kind": "crash", "sha256": "ab", "size_bytes": 1,
                             "reproducible": True, "fingerprint": None, "failure": None}]}
    write_json(run_dir / "workspace/reports/fuzz/snmp.json", report)
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/snmp.json"])
    cand = load(run_dir / "candidates.json")[0]
    assert "::unparsed_crash::" in cand["fingerprint"] and cand["linked_units"] == []


def wp_report(**kw):
    r = {
        "status": "all_proven", "function": "snmp_parse_pdu", "file": "workspace/work/src/snmp/pdu.c",
        "by_obligation_class": {"rte": {"proven": 3, "proven_under_hyp": 2, "unproven": 0}},
        "unproven_goals": [],
    }
    r.update(kw)
    return r


def test_ingest_wp_proven_with_hypotheses_and_unproven(run_dir):
    seed(run_dir)
    write_json(run_dir / "workspace/reports/wp/snmp_parse_pdu.json", wp_report())
    L.cmd_ingest_wp([run_dir / "workspace/reports/wp/snmp_parse_pdu.json"])
    u = units_by_id(run_dir)["src/snmp/pdu.c#snmp_parse_pdu::rte"]
    assert u["status"] == "covered"
    assert any(a["kind"] == "valid_under_hyp" for a in u["assumptions"])

    write_json(run_dir / "workspace/reports/wp/ber_decode_len.json", wp_report(
        status="unproven_goals_remain", function="ber_decode_len", file="workspace/work/src/snmp/ber.c",
        by_obligation_class={"l2_termination": {"proven": 0, "proven_under_hyp": 0, "unproven": 1}, "rte": {"proven": 4, "proven_under_hyp": 0, "unproven": 0}},
        unproven_goals=[{"obligation_class": "l2_termination", "kind": "loop variant", "line": 7, "annotation": "len - i"}],
    ))
    L.cmd_ingest_wp([run_dir / "workspace/reports/wp/ber_decode_len.json"])
    units = units_by_id(run_dir)
    l2 = units["src/snmp/ber.c#ber_decode_len::l2_termination"]
    assert l2["status"] == "blocked" and "loop variant" in l2["unresolved"][0]
    # The function is not fully proven, so its RTE unit is not credited.
    assert units["src/snmp/ber.c#ber_decode_len::rte"]["status"] == "planned"
    l6 = units["src/snmp/ber.c#ber_decode_len::l6_secret"]
    assert l6["status"] == "planned" and "L6_" in l6["evidence"][-1]["summary"]


def test_transition_rules(run_dir):
    seed(run_dir)
    cid = "src/snmp/pdu.c#snmp_parse_pdu::rte"
    with pytest.raises(L.LedgerError):
        L.cmd_transition(cid, "in_progress", None, None)
    assert L.cmd_transition(cid, "in_progress", "prover-1", None)["agent_id"] == "prover-1"
    write_json(run_dir / "workspace/reports/eva/snmp.json", eva_report())
    L.cmd_ingest_eva([run_dir / "workspace/reports/eva/snmp.json"])
    with pytest.raises(L.LedgerError):
        L.cmd_transition(cid, "deferred", None, "budget")
    assert L.cmd_transition(cid, "blocked", None, "budget_exhausted")["status"] == "blocked"


def test_commit_refuses_invalid_state(run_dir):
    seed(run_dir)
    units, cands = L.load_state()
    units["src/snmp/pdu.c#snmp_parse_pdu::rte"]["status"] = "covered"
    with pytest.raises(L.LedgerError):
        L.commit(units, cands)


def test_ingest_wp_rejects_unsound_proof_and_records_reduced_checks(run_dir):
    seed(run_dir)
    # 1. An unsound_proof report (e.g. Missing assigns clause or Memory model hypotheses) must block, never cover.
    write_json(run_dir / "workspace/reports/wp/pdu_unsound.json", wp_report(
        status="unsound_proof",
        function="snmp_parse_pdu",
        file="workspace/work/src/snmp/pdu.c",
        soundness={
            "sound": False,
            "tier_a_abort_errors": [],
            "tier_b_unsound_warnings": ["[wp] warning: Missing assigns clause (assigns 'everything' instead)"],
            "memory_model_hypotheses": ["[wp] warning: Memory model hypotheses for function 'snmp_parse_pdu':"],
            "unproven_global_lemmas": [],
            "reduced_checks": [],
        },
    ))
    out = L.cmd_ingest_wp([run_dir / "workspace/reports/wp/pdu_unsound.json"])
    assert out["covered"] == 0 and out["blocked"] == 1
    u = units_by_id(run_dir)["src/snmp/pdu.c#snmp_parse_pdu::rte"]
    assert u["status"] == "blocked"
    assert any("Missing assigns clause" in msg for msg in u["unresolved"])

    # 2. A sound all_proven report with reduced_checks records the assumption and covers the unit.
    write_json(run_dir / "workspace/reports/wp/pdu_proven.json", wp_report(
        status="all_proven",
        function="snmp_parse_pdu",
        file="workspace/work/src/snmp/pdu.c",
        soundness={
            "sound": True,
            "tier_a_abort_errors": [],
            "tier_b_unsound_warnings": [],
            "memory_model_hypotheses": [],
            "unproven_global_lemmas": [],
            "reduced_checks": ["-no-warn-unsigned-overflow"],
            "assumed_function_pointer_goals": ["\\valid_function(cb)"],
        },
    ))
    out2 = L.cmd_ingest_wp([run_dir / "workspace/reports/wp/pdu_proven.json"])
    assert out2["covered"] == 1
    u2 = units_by_id(run_dir)["src/snmp/pdu.c#snmp_parse_pdu::rte"]
    assert u2["status"] == "covered"
    descriptions = " ".join(a["description"] for a in u2["assumptions"])
    assert "-no-warn-unsigned-overflow" in descriptions
    assert "\\valid_function" in descriptions
    assert list(validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []
