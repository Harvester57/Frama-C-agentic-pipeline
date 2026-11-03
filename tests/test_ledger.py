import json

import pytest

import ledger as L
from conftest import write_json
from fingerprint import make_fingerprint
from validate_artifacts import validate_candidates, validate_ledger

DAG = {
    "callgraph_source": "regex",
    "modules": {
        "snmp": {"tier": "Tier 1A (Untrusted Binary / Network Parser)"},
        "glue": {"tier": "Tier 3 (Internal State / Glue Module)"},
    },
    "functions": {
        "ber_decode_len": {
            "name": "ber_decode_len",
            "file": "src/snmp/ber.c",
            "module": "snmp",
            "wave": 0,
            "has_loops": True,
            "security_properties": [{"layer": 2, "reason": "loops"}, {"layer": 6, "reason": "touches auth_key"}],
        },
        "ber_decode_tag": {
            "name": "ber_decode_tag",
            "file": "src/snmp/ber.c",
            "module": "snmp",
            "wave": 0,
            "has_loops": False,
            "security_properties": [],
        },
        "snmp_parse_pdu": {
            "name": "snmp_parse_pdu",
            "file": "src/snmp/pdu.c",
            "module": "snmp",
            "wave": 1,
            "has_loops": False,
            "security_properties": [],
        },
        "glue_init": {
            "name": "glue_init",
            "file": "src/glue/init.c",
            "module": "glue",
            "wave": 0,
            "has_loops": False,
            "security_properties": [],
        },
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
        "status": "ok",
        "module": "snmp",
        "unknown_obligations_by_function": {"snmp_parse_pdu": [{"line": 5}]},
        "invalid_alarms": [
            {
                "file": "workspace/work/src/snmp/ber.c",
                "function": "ber_decode_len",
                "line": 42,
                "kind": "assertion",
                "annotation": "mem_access: \\valid_read(buf + off)",
            }
        ],
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


def test_ingest_eva_keys_alarms_by_directory_and_file(run_dir):
    seed(run_dir)
    # Frama-C's CSV keeps the directory apart from the bare file name; an alarm of a same-named
    # function in another file belongs to that file's unit, never to this one.
    alarm = {
        "directory": "workspace/work/src/snmp",
        "file": "ber.c",
        "function": "ber_decode_len",
        "line": 42,
        "kind": "index_bound",
        "annotation": "i < 8",
    }
    elsewhere = {**alarm, "directory": "workspace/work/src/other", "annotation": "j < 4"}
    write_json(run_dir / "workspace/reports/eva/snmp.json", eva_report(invalid_alarms=[alarm, elsewhere]))
    assert L.cmd_ingest_eva([run_dir / "workspace/reports/eva/snmp.json"])["candidates"] == 1
    (cand,) = load(run_dir / "candidates.json")
    assert cand["fingerprint"] == make_fingerprint("src/snmp/ber.c", "ber_decode_len", "index_bound", "i < 8")
    assert cand["location"]["file"] == "src/snmp/ber.c"


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
        "mode": "campaign",
        "module": "snmp",
        "status": "crash_found",
        "artifacts": [
            {
                "artifact": str(crash),
                "kind": "crash",
                "sha256": "x",
                "size_bytes": 2,
                "reproducible": True,
                "fingerprint": fp,
                "failure": {
                    "file": "/framac-run/workspace/work/src/snmp/ber.c",
                    "line": 42,
                    "function": "ber_decode_len",
                    "kind": "assertion",
                    "alarm_kind": "mem_access",
                    "is_rte": True,
                    "predicate": "mem_access: \\valid_read(buf + off)",
                },
            }
        ],
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
    report = {
        "module": "snmp",
        "status": "crash_found",
        "artifacts": [
            {
                "artifact": "workspace/crashes/snmp/crash-1",
                "kind": "crash",
                "sha256": "ab",
                "size_bytes": 1,
                "reproducible": True,
                "fingerprint": None,
                "failure": None,
            }
        ],
    }
    write_json(run_dir / "workspace/reports/fuzz/snmp.json", report)
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/snmp.json"])
    cand = load(run_dir / "candidates.json")[0]
    assert "::unparsed_crash::" in cand["fingerprint"] and cand["linked_units"] == []


def wp_report(**kw):
    r = {
        "status": "all_proven",
        "function": "snmp_parse_pdu",
        "file": "workspace/work/src/snmp/pdu.c",
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

    write_json(
        run_dir / "workspace/reports/wp/ber_decode_len.json",
        wp_report(
            status="unproven_goals_remain",
            function="ber_decode_len",
            file="workspace/work/src/snmp/ber.c",
            by_obligation_class={
                "l2_termination": {"proven": 0, "proven_under_hyp": 0, "unproven": 1},
                "rte": {"proven": 4, "proven_under_hyp": 0, "unproven": 0},
            },
            unproven_goals=[
                {"obligation_class": "l2_termination", "kind": "loop variant", "line": 7, "annotation": "len - i"}
            ],
        ),
    )
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
    write_json(
        run_dir / "workspace/reports/wp/pdu_unsound.json",
        wp_report(
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
        ),
    )
    out = L.cmd_ingest_wp([run_dir / "workspace/reports/wp/pdu_unsound.json"])
    assert out["covered"] == 0 and out["blocked"] == 1
    u = units_by_id(run_dir)["src/snmp/pdu.c#snmp_parse_pdu::rte"]
    assert u["status"] == "blocked"
    assert any("Missing assigns clause" in msg for msg in u["unresolved"])

    # 2. A sound all_proven report with reduced_checks records the assumption and covers the unit.
    write_json(
        run_dir / "workspace/reports/wp/pdu_proven.json",
        wp_report(
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
        ),
    )
    out2 = L.cmd_ingest_wp([run_dir / "workspace/reports/wp/pdu_proven.json"])
    assert out2["covered"] == 1
    u2 = units_by_id(run_dir)["src/snmp/pdu.c#snmp_parse_pdu::rte"]
    assert u2["status"] == "covered"
    descriptions = " ".join(a["description"] for a in u2["assumptions"])
    assert "-no-warn-unsigned-overflow" in descriptions
    assert "\\valid_function" in descriptions
    assert list(validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


def test_ingest_wp_analysis_error_records_evidence_without_status_change(run_dir):
    seed(run_dir)
    write_json(
        run_dir / "workspace/reports/wp/snmp_parse_pdu.json",
        wp_report(
            status="analysis_error",
            reason="oom_killed",
            by_obligation_class={},
            unproven_goals=[],
        ),
    )
    L.cmd_ingest_wp([run_dir / "workspace/reports/wp/snmp_parse_pdu.json"])
    u = units_by_id(run_dir)["src/snmp/pdu.c#snmp_parse_pdu::rte"]
    assert u["status"] == "planned"
    ev = u["evidence"][-1]
    assert ev["result"] == "wp_analysis_error" and not ev["discharging"]
    assert ev["details"] == {"reason": "oom_killed"} and "oom_killed" in ev["summary"]
    assert list(validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


def test_ingest_fuzz_not_run_is_recorded_not_ignored(run_dir):
    seed(run_dir)
    write_json(
        run_dir / "workspace/reports/fuzz/snmp.json",
        {"mode": "campaign", "module": "snmp", "status": "not_run", "reason": "job killed"},
    )
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/snmp.json"])
    u = units_by_id(run_dir)["src/snmp/pdu.c#snmp_parse_pdu::rte"]
    assert u["status"] == "planned"
    assert u["evidence"][-1]["result"] == "fuzz_not_run" and "job killed" in u["evidence"][-1]["summary"]


def test_transition_compare_and_set_protects_fresh_candidate(run_dir):
    seed(run_dir)
    cid = "src/snmp/ber.c#ber_decode_len::rte"
    write_json(run_dir / "workspace/reports/eva/snmp.json", eva_report())
    L.cmd_ingest_eva([run_dir / "workspace/reports/eva/snmp.json"])
    assert units_by_id(run_dir)[cid]["status"] == "candidate"
    with pytest.raises(L.LedgerError, match="expected one of"):
        L.cmd_transition(cid, "in_progress", "prover-1", None, expected=["planned"])
    assert units_by_id(run_dir)[cid]["status"] == "candidate"
    pdu = "src/snmp/pdu.c#snmp_parse_pdu::rte"
    assert L.cmd_transition(pdu, "in_progress", "prover-2", None, expected=["planned"])["status"] == "in_progress"
    # The CLI exposes the same compare-and-set.
    assert L.main(["transition", "--id", pdu, "--status", "planned", "--expect", "covered"]) == 1


def test_ledger_commands_hold_the_run_lock_and_release_it(run_dir):
    from framac_common import run_lock

    seed(run_dir)
    with run_lock("ledger", run_dir) as lock_dir:
        # Reentrant within one process: a scheduler holding the lock can call ledger commands.
        L.cmd_transition("src/snmp/pdu.c#snmp_parse_pdu::rte", "in_progress", "prover-1", None)
        assert lock_dir.is_dir()
    assert not (run_dir / ".framac-locks").exists()


def test_ingest_fuzz_insufficient_memory_records_evidence_and_unresolved(run_dir):
    seed(run_dir)
    write_json(
        run_dir / "workspace/reports/fuzz/snmp.json",
        {"mode": "campaign", "module": "snmp", "status": "insufficient_memory", "error_summary": ["need 2560 MiB"]},
    )
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/snmp.json"])
    u = units_by_id(run_dir)["src/snmp/pdu.c#snmp_parse_pdu::rte"]
    assert u["status"] == "planned"
    assert u["unresolved"] == []
    assert u["evidence"][-1]["result"] == "fuzz_insufficient_memory"
    assert u["evidence"][-1]["discharging"] is False
    assert "need 2560 MiB" in u["evidence"][-1]["summary"]


def test_ingest_eva_disambiguates_same_named_statics_across_files(run_dir):
    dag = {
        "modules": {"m": {"tier": "Tier 1", "files": ["src/a.c", "src/b.c"]}},
        "functions": {
            "src/a.c#helper": {"name": "helper", "file": "src/a.c", "module": "m", "tier": "Tier 1"},
            "src/b.c#helper": {"name": "helper", "file": "src/b.c", "module": "m", "tier": "Tier 1"},
        },
    }
    write_json(run_dir / "workspace/reports/callgraph_dag.json", dag)
    L.cmd_seed(run_dir / "workspace/reports/callgraph_dag.json", [], "frama_c")
    rep = eva_report(
        module="m",
        sources=["workspace/work/src/a.c", "workspace/work/src/b.c"],
        functions_with_properties=["helper"],
        functions_with_properties_by_file={"src/a.c": ["helper"], "src/b.c": ["helper"]},
        unknown_obligations=[
            {
                "file": "workspace/work/src/a.c",
                "function": "helper",
                "line": 12,
                "kind": "mem_access",
                "property": "\\valid(p)",
            },
        ],
        unknown_obligations_by_function={
            "helper": [
                {
                    "file": "workspace/work/src/a.c",
                    "function": "helper",
                    "line": 12,
                    "kind": "mem_access",
                    "property": "\\valid(p)",
                },
            ],
        },
        invalid_alarms=[],
        dead_alarms=[],
    )
    write_json(run_dir / "workspace/reports/eva/m.json", rep)
    L.cmd_ingest_eva([run_dir / "workspace/reports/eva/m.json"])
    by_id = units_by_id(run_dir)
    assert by_id["src/a.c#helper::rte"]["status"] == "planned"
    assert by_id["src/a.c#helper::rte"]["evidence"][-1]["result"] == "eva_unknown"
    assert by_id["src/b.c#helper::rte"]["status"] == "covered"
    assert by_id["src/b.c#helper::rte"]["evidence"][-1]["result"] == "eva_all_valid"


def test_transition_many_commits_atomically_or_rolls_back_all(run_dir):
    seed(run_dir)
    c1 = "src/snmp/pdu.c#snmp_parse_pdu::rte"
    c2 = "src/snmp/ber.c#ber_decode_len::rte"
    res = L.cmd_transition_many(
        [
            {"id": c1, "status": "in_progress", "agent_id": "prover-1", "expected": ["planned"]},
            {"id": c2, "status": "in_progress", "agent_id": "prover-2", "expected": ["planned"]},
        ]
    )
    assert len(res) == 2
    by_id = units_by_id(run_dir)
    assert by_id[c1]["status"] == "in_progress" and by_id[c2]["status"] == "in_progress"
    # If the second item fails compare-and-set, the first item is not committed either.
    with pytest.raises(L.LedgerError, match="expected one of"):
        L.cmd_transition_many(
            [
                {"id": c1, "status": "planned", "expected": ["in_progress"]},
                {"id": c2, "status": "planned", "expected": ["covered"]},
            ]
        )
    by_id = units_by_id(run_dir)
    assert by_id[c1]["status"] == "in_progress" and by_id[c2]["status"] == "in_progress"


def test_transition_rejects_manual_covered(run_dir):
    seed(run_dir)
    c1 = "src/snmp/pdu.c#snmp_parse_pdu::rte"
    with pytest.raises(L.LedgerError, match="cannot manually transition"):
        L.cmd_transition(c1, "covered", None, None)
    with pytest.raises(L.LedgerError, match="cannot manually transition"):
        L.cmd_transition_many([{"id": c1, "status": "covered"}])


def test_commit_clears_snapshot_manifest_on_reopen(run_dir):
    seed(run_dir)
    c1 = "src/snmp/pdu.c#snmp_parse_pdu::rte"
    meta_path = run_dir / "run-metadata.json"
    meta = {
        "schema_version": 1,
        "run_id": "run-1",
        "repo": "test",
        "run_status": "complete",
        "snapshot_manifest": "state/snapshot-manifest.json",
        "snapshot_digest": "deadbeef" * 8,
    }
    write_json(meta_path, meta)
    snap_path = run_dir / "state/snapshot-manifest.json"
    snap_path.parent.mkdir(parents=True, exist_ok=True)
    snap_path.write_text("{}", encoding="utf-8")

    units, cands = L.load_state()
    # Setting unit back to planned reopens the run
    units[c1]["status"] = "planned"
    L.commit(units, cands, run_dir=run_dir)

    new_meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert new_meta["run_status"] == "in_progress"
    assert new_meta["snapshot_manifest"] is None
    assert new_meta["snapshot_digest"] is None
    assert not snap_path.exists()


def test_ingest_fuzz_publishes_corpus_to_shared_cache_when_rw(run_dir, tmp_path, monkeypatch):
    seed(run_dir)
    shared_cache = tmp_path / "shared_cache"
    shared_cache.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("FRAMAC_SHARED_CACHE_DIR", str(shared_cache))
    monkeypatch.setenv("FRAMAC_CACHE_MODE", "rw")
    monkeypatch.setenv("FRAMAC_CACHE", "on")

    corpus_dir = run_dir / "workspace/corpus/snmp"
    corpus_dir.mkdir(parents=True, exist_ok=True)
    (corpus_dir / "seed1").write_bytes(b"\x30\x00")
    (corpus_dir / "seed2").write_bytes(b"\x30\x02\x01\x05")

    write_json(
        run_dir / "workspace/reports/fuzz/snmp.json",
        {"mode": "campaign", "module": "snmp", "status": "clean", "artifacts": []},
    )
    out = L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/snmp.json"])
    assert out.get("published_corpora") == {"snmp": 2}
    shared_mod_dir = shared_cache / "corpora" / "snmp"
    assert shared_mod_dir.is_dir()
    assert len(list(shared_mod_dir.iterdir())) == 2


def test_ingest_wp_credits_qed_simplified_l2_and_l3_but_requires_explicit_l4_to_l6(run_dir):
    seed(run_dir)
    # ber_decode_len has rte, l2_termination, and l6_secret units.
    # If WP reports status="all_proven" with only rte goals (e.g. Qed simplified l2_termination),
    # l2_termination is credited with wp_qed_simplified, while l6_secret stays planned.
    write_json(
        run_dir / "workspace/reports/wp/ber_decode_len.json",
        wp_report(
            function="ber_decode_len",
            file="workspace/work/src/snmp/ber.c",
            by_obligation_class={"rte": {"proven": 4, "proven_under_hyp": 0, "unproven": 0}},
        ),
    )
    L.cmd_ingest_wp([run_dir / "workspace/reports/wp/ber_decode_len.json"])
    by_id = units_by_id(run_dir)
    assert by_id["src/snmp/ber.c#ber_decode_len::rte"]["status"] == "covered"
    assert by_id["src/snmp/ber.c#ber_decode_len::l2_termination"]["status"] == "covered"
    assert by_id["src/snmp/ber.c#ber_decode_len::l2_termination"]["evidence"][-1]["result"] == "wp_qed_simplified"
    assert by_id["src/snmp/ber.c#ber_decode_len::l6_secret"]["status"] == "planned"


def test_audit_hypotheses_discharges_proven_callees_and_flags_unverified_callees(run_dir):
    dag_with_callees = {
        **DAG,
        "functions": {
            **DAG["functions"],
            "snmp_parse_pdu": {
                **DAG["functions"]["snmp_parse_pdu"],
                "internal_callees": ["ber_decode_tag", "ber_decode_len"],
            },
        },
    }
    write_json(run_dir / "workspace/reports/callgraph_dag.json", dag_with_callees)
    L.cmd_seed(run_dir / "workspace/reports/callgraph_dag.json", [], "regex")

    # snmp_parse_pdu is proven by WP with valid_under_hyp
    write_json(run_dir / "workspace/reports/wp/snmp_parse_pdu.json", wp_report())
    L.cmd_ingest_wp([run_dir / "workspace/reports/wp/snmp_parse_pdu.json"])

    # Case 1: callees are not WP-proven -> valid_under_hyp becomes callee_contract_hypothesis
    res1 = L.cmd_audit_hypotheses(run_dir / "workspace/reports/callgraph_dag.json")
    assert res1["conditional"] == 1 and res1["discharged"] == 0
    pdu_u = units_by_id(run_dir)["src/snmp/pdu.c#snmp_parse_pdu::rte"]
    cch = [a for a in pdu_u["assumptions"] if a["kind"] == "callee_contract_hypothesis"]
    assert len(cch) == 1
    assert "src/snmp/ber.c#ber_decode_tag::rte" in cch[0]["related_units"]
    assert list(validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []

    # Case 2: both callees are now WP-proven -> hypothesis is discharged!
    for fn in ("ber_decode_tag", "ber_decode_len"):
        write_json(
            run_dir / f"workspace/reports/wp/{fn}.json",
            wp_report(
                function=fn,
                file="workspace/work/src/snmp/ber.c",
                by_obligation_class={
                    "rte": {"proven": 2, "proven_under_hyp": 0, "unproven": 0},
                    "l6_secret": {"proven": 1, "proven_under_hyp": 0, "unproven": 0},
                },
            ),
        )
    L.cmd_ingest_wp(
        [
            run_dir / "workspace/reports/wp/ber_decode_tag.json",
            run_dir / "workspace/reports/wp/ber_decode_len.json",
        ]
    )
    res2 = L.cmd_audit_hypotheses(run_dir / "workspace/reports/callgraph_dag.json")
    assert res2["discharged"] == 1 and res2["conditional"] == 0
    pdu_u2 = units_by_id(run_dir)["src/snmp/pdu.c#snmp_parse_pdu::rte"]
    assert not any(a["kind"] in ("valid_under_hyp", "callee_contract_hypothesis") for a in pdu_u2["assumptions"])
    assert pdu_u2["evidence"][-1]["result"] == "hypotheses_discharged"
    assert list(validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


def test_ingest_eva_include_source_harness_extracts_target_sources(run_dir):
    """When include_source: true is used, report['sources'] lists only harness_<mod>.c; target units must still ingest."""
    seed(run_dir)
    rep = eva_report(
        sources=["workspace/harnesses/harness_snmp.c"],
        functions_with_properties_by_file={
            "workspace/work/src/snmp/ber.c": ["ber_decode_len", "ber_decode_tag"],
            "workspace/work/src/snmp/pdu.c": ["snmp_parse_pdu"],
        },
    )
    write_json(run_dir / "workspace/reports/eva/snmp.json", rep)
    out = L.cmd_ingest_eva([run_dir / "workspace/reports/eva/snmp.json"])
    assert out == {"reports": 1, "covered": 1, "candidates": 1}
    units = units_by_id(run_dir)
    assert units["src/snmp/ber.c#ber_decode_tag::rte"]["status"] == "covered"
    assert units["src/snmp/ber.c#ber_decode_len::rte"]["status"] == "candidate"


def test_status_subcommand_alias(run_dir, capsys):
    seed(run_dir)
    rc = L.main(["status"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["units"] == 6
