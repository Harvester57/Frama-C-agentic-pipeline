"""Remediation step R2 (docs/phase0-remediation-plan.md): ledger seed checks, --refresh, fuzz ingest by line."""

import copy
import json

import pytest

import ledger as L
import phase0_gates
from conftest import write_json
from fingerprint import make_fingerprint
from test_ledger import DAG, SECURITY_PROPS, load, seed, units_by_id, wp_report
from validate_artifacts import validate_candidates, validate_ledger

pytestmark = pytest.mark.unit

DAG_REL = "workspace/reports/callgraph_dag.json"
PRED = "mem_access: \\valid_read(buf + off)"


def _fuzz_report(run_dir, function, line):
    crash = run_dir / "workspace/crashes/snmp/crash-abc"
    crash.parent.mkdir(parents=True, exist_ok=True)
    crash.write_bytes(b"\x30\x84")
    failure = {
        "file": "/framac-run/workspace/work/src/snmp/ber.c",
        "function": function,
        "kind": "assertion",
        "alarm_kind": "mem_access",
        "is_rte": True,
        "predicate": PRED,
    }
    if line is not None:
        failure["line"] = line
    fp = make_fingerprint("src/snmp/ber.c", function, "mem_access", PRED)
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
                "failure": failure,
            }
        ],
    }
    write_json(run_dir / "workspace/reports/fuzz/snmp.json", report)
    return fp


def _with_extents(dag):
    dag = copy.deepcopy(dag)
    dag["functions"]["ber_decode_tag"].update(line=10, end_line=25)
    dag["functions"]["ber_decode_len"].update(line=30, end_line=60)
    return dag


# --------------------------------------------------------------- fuzz ingest (defect 11)


def test_fuzz_failure_in_a_renamed_static_lands_on_its_unit_by_line(run_dir):
    seed(run_dir)
    write_json(run_dir / DAG_REL, _with_extents(DAG))
    fp = _fuzz_report(run_dir, "ber_decode_len_0", 42)
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/snmp.json"])
    unit = units_by_id(run_dir)["src/snmp/ber.c#ber_decode_len::rte"]
    assert unit["status"] == "candidate" and unit["result_fingerprints"] == [fp]
    cand = {c["fingerprint"]: c for c in load(run_dir / "candidates.json")}[fp]
    # Replay matches the reported name: the fingerprint and the location keep it.
    assert cand["location"]["function"] == "ber_decode_len_0"
    assert cand["linked_units"] == ["src/snmp/ber.c#ber_decode_len::rte"]
    assert any("ber_decode_len_0" in n and "ber_decode_len in the source" in n for n in cand["notes"])
    assert list(validate_candidates(load(run_dir / "candidates.json"))) == []
    assert list(validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


def test_fuzz_line_wins_over_the_reported_name(run_dir):
    seed(run_dir)
    write_json(run_dir / DAG_REL, _with_extents(DAG))
    _fuzz_report(run_dir, "ber_decode_len", 12)  # line 12 lies in ber_decode_tag
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/snmp.json"])
    units = units_by_id(run_dir)
    assert units["src/snmp/ber.c#ber_decode_tag::rte"]["status"] == "candidate"
    assert units["src/snmp/ber.c#ber_decode_len::rte"]["status"] == "planned"


def test_fuzz_failure_without_a_line_uses_the_models_kernel_names(run_dir):
    seed(run_dir)
    model = {
        "functions": {
            "src/snmp/ber.c#ber_decode_len": {
                "name": "ber_decode_len",
                "file": "src/snmp/ber.c",
                "kernel_names": {"libsnmp.a": "ber_decode_len_0"},
            }
        }
    }
    write_json(run_dir / "workspace/reports/phase0_model.json", model)
    fp = _fuzz_report(run_dir, "ber_decode_len_0", None)
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/snmp.json"])
    assert units_by_id(run_dir)["src/snmp/ber.c#ber_decode_len::rte"]["result_fingerprints"] == [fp]


def test_fuzz_failure_without_a_line_or_a_rename_keeps_the_reported_name(run_dir):
    seed(run_dir)
    fp = _fuzz_report(run_dir, "ber_decode_len_0", None)
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/snmp.json"])
    cand = {c["fingerprint"]: c for c in load(run_dir / "candidates.json")}[fp]
    assert cand["linked_units"] == []
    assert any("no ledger unit for src/snmp/ber.c#ber_decode_len_0::rte" in n for n in cand["notes"])


# ----------------------------------------------------------------- seed --refresh (defect 12)


def _changed_dag():
    dag = copy.deepcopy(DAG)
    fns = dag["functions"]
    del fns["snmp_parse_pdu"]  # left the DAG
    del fns["glue_init"]  # left the DAG, but carries evidence
    fns["ber_decode_len"].update(has_loops=False, security_properties=[], wave=2)  # l2 no longer derived
    fns["ber_decode_tag"].update(has_loops=True)  # gains l2
    fns["ber_new"] = {"name": "ber_new", "file": "src/snmp/ber.c", "module": "snmp", "wave": 0, "has_loops": False}
    return dag


def test_plain_seed_never_rewinds(run_dir):
    seed(run_dir)
    write_json(run_dir / DAG_REL, _changed_dag())
    out = L.cmd_seed(run_dir / DAG_REL, [], "frama_c")
    assert "refresh" not in out and out["added_units"] == 2
    units = units_by_id(run_dir)
    assert units["src/snmp/pdu.c#snmp_parse_pdu::rte"]["status"] == "planned"
    assert units["src/snmp/ber.c#ber_decode_len::rte"]["wave"] == 0


def test_refresh_follows_the_current_dag_and_never_touches_evidence(run_dir):
    seed(run_dir)
    write_json(run_dir / "workspace/reports/fuzz/glue.json", {"module": "glue", "status": "clean"})
    L.cmd_ingest_fuzz([run_dir / "workspace/reports/fuzz/glue.json"])
    glue_before = units_by_id(run_dir)["src/glue/init.c#glue_init::rte"]
    assert glue_before["evidence"]

    write_json(run_dir / DAG_REL, _changed_dag())
    out = L.cmd_seed(run_dir / DAG_REL, [], "frama_c", refresh=True)
    units = units_by_id(run_dir)

    assert units["src/snmp/ber.c#ber_new::rte"]["status"] == "planned"
    assert units["src/snmp/ber.c#ber_decode_tag::l2_termination"]["status"] == "planned"
    gone = units["src/snmp/pdu.c#snmp_parse_pdu::rte"]
    assert gone["status"] == "out_of_scope" and gone["unresolved"] == [L.LEFT_DAG]
    l2 = units["src/snmp/ber.c#ber_decode_len::l2_termination"]
    assert l2["status"] == "out_of_scope" and l2["unresolved"] == [L.CLASS_NOT_DERIVED]
    assert units["src/snmp/ber.c#ber_decode_len::rte"]["wave"] == 2
    # The MetAcsl class still comes from security_props.json: re-derived, kept.
    assert units["src/snmp/ber.c#ber_decode_len::l6_wiped"]["status"] == "planned"
    assert units["src/glue/init.c#glue_init::rte"] == glue_before

    refresh = out["refresh"]
    assert refresh["added"] == 2 and refresh["retired"] == 2 and refresh["kept_with_evidence"] == 1
    assert refresh["units"]["kept_with_evidence"] == ["src/glue/init.c#glue_init::rte"]
    assert "src/snmp/ber.c#ber_decode_len::rte" in refresh["units"]["updated"]
    assert list(validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []

    # A function back in the DAG is planned again; a second refresh changes nothing more.
    write_json(run_dir / DAG_REL, DAG)
    L.cmd_seed(run_dir / DAG_REL, [], "frama_c", refresh=True)
    assert units_by_id(run_dir)["src/snmp/pdu.c#snmp_parse_pdu::rte"]["status"] == "planned"
    again = L.cmd_seed(run_dir / DAG_REL, [], "frama_c", refresh=True)["refresh"]
    assert again["added"] == again["updated"] == again["retired"] == 0


def test_refresh_keeps_non_seed_bookkeeping(run_dir):
    seed(run_dir)
    units = load(run_dir / "coverage-ledger.json")
    for u in units:
        if u["coverage_id"] == "src/snmp/ber.c#ber_decode_len::rte":
            u["bookkeeping"] = {"note": "kept", "wp_notes": ["stale"]}
    write_json(run_dir / "coverage-ledger.json", units)
    L.cmd_seed(run_dir / DAG_REL, [], "frama_c", refresh=True)
    assert units_by_id(run_dir)["src/snmp/ber.c#ber_decode_len::rte"]["bookkeeping"] == {"note": "kept"}


# ------------------------------------------------------------------------- seed input checks


def _seed_cli(capsys, *extra):
    rc = L.main(["seed", "--dag", DAG_REL, *extra])
    return rc, json.loads(capsys.readouterr().out)


def _pass_reach(run_dir):
    phase0_gates.record_reach(run_dir, {"modules": [{"module": "snmp", "passed": True, "gaps": []}]})


def test_seed_refuses_a_missing_or_failed_reach_gate(run_dir, capsys):
    write_json(run_dir / DAG_REL, DAG)
    rc, out = _seed_cli(capsys)
    assert rc == 1 and "reach has not run" in " ".join(out["reasons"])
    phase0_gates.record_reach(run_dir, {"modules": [{"module": "snmp", "passed": False, "gaps": ["snmp_parse_pdu"]}]})
    rc, out = _seed_cli(capsys)
    assert rc == 1 and "reach failed for snmp" in " ".join(out["reasons"])
    assert not (run_dir / "coverage-ledger.json").exists()
    _pass_reach(run_dir)
    rc, out = _seed_cli(capsys)
    assert rc == 0 and out["added_units"] > 0


def test_seed_refuses_missing_security_props_under_a_threat_model(run_dir, capsys):
    write_json(run_dir / DAG_REL, DAG)
    _pass_reach(run_dir)
    write_json(
        run_dir / "workspace/reports/phase0_model.json",
        {"functions": {}, "trust": {"threat_model": {"status": "ok", "path": "workspace/THREAT_MODEL.md"}}},
    )
    rc, out = _seed_cli(capsys)
    assert rc == 1 and "security_props.json is missing" in " ".join(out["reasons"])
    write_json(run_dir / "workspace/reports/security_props.json", SECURITY_PROPS)
    rc, out = _seed_cli(capsys, "--refresh")
    assert rc == 0 and out["security_props"]["status"] == "ok" and "refresh" in out


def test_seed_without_a_threat_model_needs_no_security_props(run_dir, capsys):
    write_json(run_dir / DAG_REL, DAG)
    _pass_reach(run_dir)
    write_json(
        run_dir / "workspace/reports/phase0_model.json",
        {"functions": {}, "trust": {"threat_model": {"status": "no_threat_model"}}},
    )
    rc, out = _seed_cli(capsys)
    assert rc == 0 and out["security_props"]["status"] == "absent"


# --------------------------------------------------------------- audit-hypotheses fallback


def test_audit_hypotheses_warns_on_a_callee_without_a_dag_record(run_dir, capsys):
    dag = copy.deepcopy(DAG)
    dag["functions"]["snmp_parse_pdu"]["internal_callees"] = ["ber_decode_tag"]
    write_json(run_dir / DAG_REL, dag)
    L.cmd_seed(run_dir / DAG_REL, [], "frama_c")
    write_json(run_dir / "workspace/reports/wp/snmp_parse_pdu.json", wp_report())
    L.cmd_ingest_wp([run_dir / "workspace/reports/wp/snmp_parse_pdu.json"])
    del dag["functions"]["ber_decode_tag"]  # a stale DAG: the callee key has no record
    write_json(run_dir / DAG_REL, dag)
    res = L.cmd_audit_hypotheses(run_dir / DAG_REL)
    assert res["conditional"] == 1
    assert res["warnings"] == [
        "callee ber_decode_tag of src/snmp/pdu.c#snmp_parse_pdu has no DAG record: its units are matched by name"
    ]
    assert "rebuild the DAG" in capsys.readouterr().err


def test_old_classes_are_gone():
    assert set(L.LAYER_TO_CLASS.values()) == {"l2_termination", "l3_frame"}
    assert not hasattr(L, "LAYER_CLASSES")
