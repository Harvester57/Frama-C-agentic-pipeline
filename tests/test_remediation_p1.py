"""Regression tests for the P1 items of docs/remediation-plan.md owned outside the ledger and guardrail."""

from __future__ import annotations

import json
from pathlib import Path

import checkpoint
import generate_harness
import resources as R
from validate_artifacts import validate_agent_result


def _prover(**kw):
    r = {
        "role": "prover",
        "agent_id": "prover-1",
        "file": "src/a.c",
        "function": "f",
        "status": "blocked",
        "patch": None,
        "evidence": [{"tool_output": "agents/prover-1/scratch/guard_f.json", "result": "code_fault"}],
        "unproven_goals": [],
        "strengthening_requests": [],
        "boundary_assumptions": [],
        "fault_hypothesis": None,
    }
    r.update(kw)
    return r


def test_h3_blocked_prover_result_needs_no_goal_list():
    # The brief's code_fault / repeated analysis_error exits decide no goal.
    assert list(validate_agent_result(_prover())) == []
    # A stall still has to say which goals it could not prove.
    assert any("unproven_goals" in e for e in validate_agent_result(_prover(status="stalled_after_k_retries")))


def test_h4_regenerating_a_harness_keeps_the_repair_count(tmp_path):
    out_dir = tmp_path / "harnesses"

    def generate():
        generate_harness.generate_module_harness(
            module_name="snmp",
            sources=["src/snmp/pdu.c"],
            header_include="snmp/pdu.h",
            entry_fn="snmp_parse_pdu",
            max_input_size=64,
            cppflags="-Isrc",
            out_dir=out_dir,
            auto_prelude=False,
        )

    generate()
    sidecar = out_dir / "harness_snmp.json"
    first = generate_harness.record_harness_repair(sidecar, "harness passed NULL")
    assert first["repair_attempts"] == 1
    generate()  # the repair regenerates the harness
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    assert meta["repair_attempts"] == 1 and len(meta["repair_history"]) == 1
    second = generate_harness.record_harness_repair(sidecar, "still wrong length")
    assert second["repair_attempts"] == 2


def test_h5_checkpoint_init_never_rewinds_progress(tmp_path, capsys):
    state = tmp_path / "state"
    checkpoint.cmd_init(state, "/target", "verify")
    checkpoint.cmd_save_phase(state, 2, None)
    checkpoint.cmd_init(state, "/target", "verify")  # Phase 0 re-run on a resumed run
    progress = json.loads((state / "progress.json").read_text(encoding="utf-8"))
    assert progress["phase_done"] == 2
    checkpoint.cmd_init(state, "/target", "verify", force=True)
    assert json.loads((state / "progress.json").read_text(encoding="utf-8"))["phase_done"] == -1


def test_h5_wp_queue_records_phase_two():
    mk = (Path(R.__file__).resolve().parent.parent / "templates" / "pipeline.mk").read_text(encoding="utf-8")
    recipe = mk.split("\nwp-queue: ingest facts wp-replay\n", 1)[1].split("\n\n", 1)[0]
    assert "checkpoint.py save-phase state --phase 2" in recipe


def test_h10_minimize_runs_target_code():
    assert R.is_known_static_command("python3 $S/pipeline_make.py run minimize") is False
    assert R.is_known_static_command("python3 $S/pipeline_make.py run eva") is True
