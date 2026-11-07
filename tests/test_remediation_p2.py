"""Regression tests for the P2 items of docs/remediation-plan.md owned by the ledger, overlay and scheduler."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import ledger as L
import workspace_overlay
import wp_scheduler as S
from conftest import write_json
from framac_common import PROVER_WALL_BUDGET_S
from test_ledger import eva_report, load, seed, units_by_id
from validate_artifacts import validate_agent_result, validate_ledger

pytestmark = pytest.mark.unit


def _architect(**kw):
    r = {
        "role": "architect",
        "agent_id": "arch-snmp",
        "header": "src/snmp/ber.h",
        "status": "passed",
        "patch": "agents/arch-snmp/scratch/snmp_header.patch",
        "evidence": [{"tool_output": "agents/arch-snmp/scratch/header_guard_snmp.json", "result": "passed"}],
        "boundary_assumptions": ["the caller owns buf for len bytes"],
        "notes": "",
    }
    r.update(kw)
    return r


def test_m10_a_later_eva_report_withdraws_eva_only_cover(run_dir):
    seed(run_dir)
    write_json(run_dir / "workspace/reports/eva/snmp.json", eva_report())
    L.cmd_ingest_eva([run_dir / "workspace/reports/eva/snmp.json"])
    assert units_by_id(run_dir)["src/snmp/ber.c#ber_decode_tag::rte"]["status"] == "covered"

    # The repaired harness reaches new contexts: Eva no longer proves everything in ber_decode_tag.
    later = eva_report(
        invalid_alarms=[],
        unknown_obligations_by_function={"ber_decode_tag": [{"line": 9}]},
        assumed_properties=[],
    )
    write_json(run_dir / "workspace/reports/eva/snmp-2.json", later)
    out = L.cmd_ingest_eva([run_dir / "workspace/reports/eva/snmp-2.json"])
    tag = units_by_id(run_dir)["src/snmp/ber.c#ber_decode_tag::rte"]
    assert tag["status"] == "planned" and out["reopened"] == 1
    assert tag["evidence"][-1]["result"] == "eva_cover_withdrawn"
    assert not any(a["description"].startswith("Eva result holds") for a in tag["assumptions"])
    assert list(validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


def test_m17_architect_boundary_assumptions_reach_the_functions_it_names(run_dir):
    seed(run_dir)
    res = _architect(functions=[{"file": "src/snmp/ber.c", "function": "ber_decode_len"}])
    assert list(validate_agent_result(res)) == []
    path = run_dir / "agents/arch-snmp/scratch/result.json"
    write_json(path, res)
    out = L.cmd_record_boundary_assumptions(path)
    assert out["added"] >= 1
    len_rte = units_by_id(run_dir)["src/snmp/ber.c#ber_decode_len::rte"]
    assert any(a["description"] == "the caller owns buf for len bytes" for a in len_rte["assumptions"])
    # Without the list the result still validates, and records nothing.
    write_json(path, _architect())
    assert L.cmd_record_boundary_assumptions(path)["added"] == 0


def test_m17_architect_functions_must_be_safe_paths():
    bad = _architect(functions=[{"file": "/etc/passwd", "function": "f"}])
    assert list(validate_agent_result(bad))


def test_m16_guardrail_crash_input_field_wins_over_the_trace(run_dir):
    crash = run_dir / "agents/prover-1/scratch/guard/crash-abc"
    crash.parent.mkdir(parents=True)
    crash.write_bytes(b"\x00")
    report = {"crash_input": "agents/prover-1/scratch/guard/crash-abc", "runtime_trace": "truncated..."}
    assert L._guardrail_crash_input(report, "prover-1") == "agents/prover-1/scratch/guard/crash-abc"
    # A path outside the agent's scratch is never taken.
    assert L._guardrail_crash_input({"crash_input": "workspace/corpus/m/x"}, "prover-1") is None


def test_m7_one_prover_wall_budget_for_brief_and_scheduler():
    assert S.DEFAULT_WALL_BUDGET_S is PROVER_WALL_BUDGET_S
    assert PROVER_WALL_BUDGET_S["quick"] == 600


def test_m15_contracts_manifest_marks_unproven_contracts(tmp_path):
    run = tmp_path / "run-1"
    overlay = run / "workspace"
    (overlay / "baseline" / "src").mkdir(parents=True)
    (overlay / "work" / "src").mkdir(parents=True)
    (overlay / "baseline" / "src" / "m.h").write_text("int f(int x);\nint g(int x);\n", encoding="utf-8")
    (overlay / "work" / "src" / "m.h").write_text(
        "/*@ requires x >= 0; */\nint f(int x);\n/*@ requires x >= 0; */\nint g(int x);\n", encoding="utf-8"
    )
    write_json(
        run / "coverage-ledger.json",
        [
            {"function": "f", "status": "covered", "assumptions": []},
            {"function": "g", "status": "blocked", "assumptions": []},
        ],
    )
    out = workspace_overlay.export_diff(overlay, run / "workspace/reports/verified_acsl.patch")
    manifest = json.loads(Path(out["contracts_manifest"]).read_text(encoding="utf-8"))
    assert manifest["headers"]["src/m.h"] == [
        {"function": "f", "status": "proven"},
        {"function": "g", "status": "unproven"},
    ]
    assert out["contracts_by_status"] == {"proven": 1, "unproven": 1}
