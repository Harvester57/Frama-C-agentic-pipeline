import hashlib
import json
from pathlib import Path
from typing import Any

import validate_artifacts
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
from validate_artifacts import (
    validate_agent_result,
    validate_findings,
    validate_ledger,
    validate_metadata,
    validate_run_dir,
)


def good_findings():
    return sorted_findings(confirmed_record(), needs_validation_record(), rejected_record())


def test_valid_findings_pass():
    assert list(validate_findings(good_findings())) == []


def test_findings_must_be_sorted_and_unique():
    recs = good_findings()[::-1]
    assert any("sorted" in e for e in validate_findings(recs))
    dup = sorted_findings(confirmed_record(), confirmed_record())
    assert any("duplicate" in e for e in validate_findings(dup))


def test_needs_validation_cannot_carry_severity():
    rec = needs_validation_record()
    rec["severity"] = "high"
    assert any("unexpected property" in e for e in validate_findings([rec]))


def test_internal_api_caps_severity():
    rec = confirmed_record()
    rec["reachability"] = "internal_api"
    rec["severity"] = "critical"
    assert any("caps severity" in e for e in validate_findings([rec]))


def test_trace_order_and_harness_contract_flag():
    rec = confirmed_record()
    rec["trace"] = list(reversed(rec["trace"]))
    assert any("multi-entry trace" in e for e in validate_findings([rec]))
    rec = confirmed_record()
    rec["harness"]["contract_respected"] = False
    assert validate_findings([rec])


def test_needs_validation_requires_blockers_and_plan():
    rec = needs_validation_record()
    rec["blockers"] = []
    rec["validation_plan"] = {}
    errs = validate_findings([rec])
    assert any("blockers" in e for e in errs)
    assert any("validation_plan" in e for e in errs)


def test_unsafe_paths_and_fingerprint_mismatch():
    rec = confirmed_record()
    rec["location"]["file"] = "/etc/passwd"
    assert validate_findings([rec])
    rec = confirmed_record()
    rec["location"]["function"] = "other_fn"
    assert any("function part" in e for e in validate_findings([rec]))


def test_reproducer_hash_checked_against_run_dir(tmp_path):
    rec = confirmed_record()
    crash = tmp_path / "workspace/crashes/snmp/crash-1"
    crash.parent.mkdir(parents=True)
    crash.write_bytes(b"abc")
    write_json(tmp_path / "workspace/reports/fuzz/snmp.json", {})
    errs = validate_findings([rec], tmp_path)
    assert any("sha256" in e for e in errs)
    rec["reproducers"][0]["sha256"] = hashlib.sha256(b"abc").hexdigest()
    assert list(validate_findings([rec], tmp_path)) == []


def test_ledger_state_table():
    good = [
        unit("src/a.c", "f", "rte", "covered", evidence=[evidence()]),
        unit("src/a.c", "g", "rte", "deferred", unresolved=["tier3"]),
        unit("src/a.c", "h", "rte", "planned", evidence=[evidence(result="eva_unknown", discharging=False)]),
    ]
    assert list(validate_ledger(sorted(good, key=lambda u: u["coverage_id"]))) == []

    cases = [
        (unit("src/a.c", "f", "rte", "covered", evidence=[evidence(discharging=False)]), "discharging"),
        (unit("src/a.c", "f", "rte", "deferred", evidence=[evidence()], unresolved=["x"]), "must not hide evidence"),
        (unit("src/a.c", "f", "rte", "deferred"), "nonempty reason"),
        (unit("src/a.c", "f", "rte", "blocked", evidence=[evidence()]), "blocker"),
        (unit("src/a.c", "f", "rte", "in_progress"), "agent_id"),
        (unit("src/a.c", "f", "rte", "candidate", evidence=[evidence()]), "result_fingerprints"),
        (
            unit("src/a.c", "f", "rte", "covered", evidence=[evidence()], result_fingerprints=[FP_PARSE]),
            "only 'candidate'",
        ),
    ]
    for u, needle in cases:
        errs = validate_ledger([u])
        assert any(needle in e for e in errs), (needle, errs)


def test_ledger_id_must_match_fields_and_assumption_links():
    u = unit("src/a.c", "f", "rte")
    u["coverage_id"] = "src/a.c#g::rte"
    assert any("must equal" in e for e in validate_ledger([u]))
    u = unit(
        "src/a.c",
        "f",
        "rte",
        "covered",
        evidence=[evidence()],
        assumptions=[
            {
                "kind": "caller_requires_unverified",
                "description": "caller unverified",
                "related_units": ["src/b.c#main::rte"],
            }
        ],
    )
    assert any("not in ledger" in e for e in validate_ledger([u]))


def test_metadata_incomplete_reason():
    assert list(validate_metadata(metadata())) == []
    assert any("required" in e for e in validate_metadata(metadata("incomplete", None)))
    assert any("must be null" in e for e in validate_metadata(metadata("complete", "x")))


def test_run_metadata_init_respects_framac_run_id_env(tmp_path, monkeypatch):
    import run_metadata

    container_cwd = tmp_path / "framac-run"
    container_cwd.mkdir()
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    monkeypatch.chdir(container_cwd)
    monkeypatch.setenv("FRAMAC_RUN_ID", "run-1")

    rc = run_metadata.main(["init", "--repo", "demo", "--target", str(target_dir), "--profile", "quick"])
    assert rc == 0
    meta = run_metadata.json.loads((container_cwd / "run-metadata.json").read_text(encoding="utf-8"))
    assert meta["run_id"] == "run-1"
    assert list(validate_metadata(meta)) == []


def test_run_metadata_worktree_fallback_to_host_git_env(tmp_path, monkeypatch):
    import run_metadata

    container_cwd = tmp_path / "run-3"
    container_cwd.mkdir()
    worktree_target = tmp_path / "target_wt"
    worktree_target.mkdir()
    # Simulate a git worktree whose .git file points to an unmounted host path
    (worktree_target / ".git").write_text("gitdir: /unmounted/host/repo/.git/worktrees/wt1\n", encoding="utf-8")

    monkeypatch.chdir(container_cwd)
    # Git exports these to a hook run from a linked worktree: `git -C` would read that repository instead.
    for var in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("FRAMAC_TARGET_COMMIT", "94e33bb58ce66295073d5e8275d81148ab5ad829")
    monkeypatch.setenv("FRAMAC_TARGET_DIRTY", "0")

    rc = run_metadata.main(["init", "--repo", "ptf", "--target", str(worktree_target), "--profile", "quick"])
    assert rc == 0
    meta = run_metadata.json.loads((container_cwd / "run-metadata.json").read_text(encoding="utf-8"))
    assert meta["source_ref"] == {
        "vcs": "git",
        "commit": "94e33bb58ce66295073d5e8275d81148ab5ad829",
        "dirty": False,
    }
    assert list(validate_metadata(meta)) == []


def prover_result(**kw):
    r = {
        "role": "prover",
        "agent_id": "prover-1",
        "file": "src/a.c",
        "function": "f",
        "status": "all_proven",
        "patch": "agents/prover-1/artifacts/f.patch",
        "evidence": [{"tool_output": "agents/prover-1/scratch/wp_f.json", "result": "all_proven"}],
        "unproven_goals": [],
        "strengthening_requests": [],
        "boundary_assumptions": [],
        "fault_hypothesis": None,
    }
    r.update(kw)
    return r


def test_agent_results():
    assert list(validate_agent_result(prover_result())) == []
    assert any("agents/prover-1/" in e for e in validate_agent_result(prover_result(patch="workspace/work/a.h")))
    assert any("unproven_goals" in e for e in validate_agent_result(prover_result(status="stalled_after_k_retries")))
    assert any("unexpected property" in e for e in validate_agent_result(prover_result(extra=1)))

    verifier = {
        "role": "crash_verifier",
        "agent_id": "verifier-1",
        "candidate_fingerprint": FP_PARSE,
        "decision": "confirmed",
        "refingerprint_reason": None,
        "record": confirmed_record(),
    }
    assert list(validate_agent_result(verifier)) == []
    verifier["decision"] = "rejected"
    assert any("must equal decision" in e for e in validate_agent_result(verifier))
    verifier["decision"] = "confirmed"
    verifier["candidate_fingerprint"] = FP_EVA
    assert any("refingerprint_reason" in e for e in validate_agent_result(verifier))

    critic = {
        "role": "critic",
        "agent_id": "critic-1",
        "phase": "eva",
        "missing_units": [],
        "reassign_ids": ["src/a.c#f::rte"],
        "harness_gaps": [],
        "stop": True,
    }
    assert any("stop" in e for e in validate_agent_result(critic))


def _write_run(run, findings, candidates, ledger, meta):
    write_json(run / "run-metadata.json", meta)
    write_json(run / "coverage-ledger.json", sorted(ledger, key=lambda u: u["coverage_id"]))
    write_json(run / "candidates.json", candidates)
    write_json(run / "findings.json", findings)


def test_run_dir_cross_checks(tmp_path):
    run = tmp_path
    write_json(run / "workspace/reports/fuzz/snmp.json", {})
    write_json(run / "workspace/reports/eva/log.json", {})
    write_json(run / "agents/verifier-3/artifacts/notes.txt", {})
    write_json(run / "workspace/reports/eva/snmp.json", {})
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
    ]
    cand = {
        "fingerprint": FP_PARSE,
        "status": "verified",
        "origin": "fuzz",
        "proposed_verdict": "confirmed",
        "module": "snmp",
        "location": {"file": "src/snmp/ber.c", "line": 42, "function": "ber_decode_len"},
        "property": {"kind": "mem_access", "predicate": "x"},
        "reproducers": [],
        "tool_outputs": ["workspace/reports/fuzz/snmp.json"],
        "linked_units": ["src/snmp/ber.c#ber_decode_len::rte"],
        "first_seen": "t",
    }
    _write_run(run, findings, [cand], ledger, metadata("complete"))
    assert list(validate_run_dir(run)) == []

    cand_unverified = dict(cand, status="unverified")
    _write_run(run, findings, [cand_unverified], ledger, metadata("complete"))
    errs = validate_run_dir(run)
    assert any("still marked unverified" in e for e in errs)
    assert any("cannot be complete" in e for e in errs)

    ledger[0]["result_fingerprints"] = []
    ledger[0]["status"] = "blocked"
    ledger[0]["unresolved"] = ["x"]
    _write_run(run, findings, [cand], ledger, metadata("in_progress"))
    assert any("not recorded in result_fingerprints" in e for e in validate_run_dir(run))


def test_snapshot_manifest_and_prior_run_tamper_detection(tmp_path, monkeypatch):
    import run_metadata
    from validate_artifacts import validate_snapshot_manifest

    run1 = tmp_path / "run-1"
    run1.mkdir()
    work_file = run1 / "workspace/work/src/a.c"
    work_file.parent.mkdir(parents=True)
    work_file.write_text("int f(int x) { return x; }\n", encoding="utf-8")
    write_json(run1 / "workspace/reports/eva/a.json", {"ok": True})
    ev = [evidence(phase="eva", result="eva_all_valid", discharging=True, tool_output="workspace/reports/eva/a.json")]
    ledger = [unit("src/a.c", "f", "rte", "covered", evidence=ev)]
    _write_run(run1, [], [], ledger, metadata("complete"))

    manifest = run_metadata.cmd_snapshot(run1)
    assert manifest["schema_version"] == 1
    assert "coverage-ledger.json" in manifest["files"]
    assert "workspace/work/src/a.c" in manifest["files"]
    assert "workspace/reports/eva/a.json" in manifest["files"]
    assert list(validate_snapshot_manifest(manifest, run1)) == []
    assert list(validate_run_dir(run1)) == []

    # Initializing a new run with --prior-run pointing to intact run1 succeeds.
    run2 = tmp_path / "run-2"
    run2.mkdir()
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    monkeypatch.chdir(run2)
    assert (
        run_metadata.main(
            [
                "init",
                "--repo",
                "demo",
                "--target",
                str(target_dir),
                "--prior-run",
                str(run1),
            ]
        )
        == 0
    )

    # Tampering with workspace/work/src/a.c in run1 is caught by validate_run_dir and --prior-run verification.
    work_file.write_text("int f(int x) { return x + 999; }\n", encoding="utf-8")
    errs = validate_run_dir(run1)
    assert any("snapshot" in e and "src/a.c" in e for e in errs)

    run3 = tmp_path / "run-3"
    run3.mkdir()
    monkeypatch.chdir(run3)
    assert (
        run_metadata.main(
            [
                "init",
                "--repo",
                "demo",
                "--target",
                str(target_dir),
                "--prior-run",
                str(run1),
            ]
        )
        == 1
    )


def test_cli_aliases_for_checkpoint_and_run_metadata(tmp_path, monkeypatch):
    import checkpoint
    import run_metadata

    state_dir = tmp_path / "state"
    assert checkpoint.main(["save", str(state_dir), "--phase-done", "0"]) == 0
    prog = checkpoint.load_json(state_dir / "progress.json")
    assert prog["phase_done"] == 0

    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    monkeypatch.chdir(run_dir)
    assert run_metadata.main(["init", "--repo", "demo", "--target", str(target_dir)]) == 0
    assert run_metadata.main(["finalize", "--status", "complete"]) == 0
    meta = run_metadata.json.loads((run_dir / "run-metadata.json").read_text(encoding="utf-8"))
    assert meta["run_status"] == "complete"


def test_validate_agent_result_proof_gap():
    prover_base = {
        "role": "prover",
        "agent_id": "prover-1",
        "file": "src/a.c",
        "function": "f",
        "status": "stalled_after_k_retries",
        "patch": None,
        "evidence": [{"tool_output": "agents/prover-1/scratch/wp.json", "result": "wp_timeout"}],
        "unproven_goals": ["rte: mem_access"],
        "strengthening_requests": [],
        "boundary_assumptions": [],
        "fault_hypothesis": None,
        "proof_gap": {
            "predicate": "\\valid_read(p)",
            "reason": "Missing callee contract lemma for buffer range",
        },
    }
    # Valid proof_gap on stalled prover passes
    assert list(validate_agent_result(prover_base)) == []

    # proof_gap is forbidden when status is all_proven
    all_proven = dict(prover_base, status="all_proven", unproven_goals=[], proof_gap={"predicate": "x", "reason": "y"})
    errs = list(validate_agent_result(all_proven))
    assert any("proof_gap" in e and "all_proven" in e for e in errs)

    # Valid proof_gap on breaker passes
    breaker_base: dict[str, Any] = {
        "role": "breaker",
        "agent_id": "breaker-1",
        "file": "src/a.c",
        "function": "f",
        "status": "clean",
        "seeds": [],
        "crash_artifact": None,
        "failing_predicate": None,
        "analysis": "No crash found within fuzz budget.",
        "fault_hypothesis": None,
        "proof_gap": {
            "predicate": "0 <= x",
            "reason": "Invariant cannot be violated under current precondition",
        },
    }
    assert list(validate_agent_result(breaker_base)) == []

    # Invalid proof_gap (missing reason) fails schema validation
    bad_gap = dict(prover_base, proof_gap={"predicate": "\\valid(p)"})
    assert any("proof_gap" in e for e in validate_agent_result(bad_gap))


def _run_agent_result_cli(capsys, argv: list[str]) -> tuple[int, dict[str, Any]]:
    rc = validate_artifacts.main(["agent-result", *argv])
    out = json.loads(capsys.readouterr().out)
    assert (rc == 0) == out["ok"]
    return rc, out


def _schedule_fixture(run_dir: Path) -> None:
    write_json(
        run_dir / "state" / "wp_schedule.json",
        {
            "agents": {
                "prove-f": "prove:src/a.c#f",
                "negotiate-g": "negotiate:src/a.c#g",
                "breaker-f": "breaker:src/a.c#f",
                "arch-m": "arch:m",
                "verify-1": "verify:rej",
            },
            "tasks": {
                "prove:src/a.c#f": {"id": "prove:src/a.c#f", "kind": "prove", "file": "src/a.c", "function": "f"},
                "negotiate:src/a.c#g": {
                    "id": "negotiate:src/a.c#g",
                    "kind": "negotiate",
                    "file": "src/a.c",
                    "function": "g",
                },
                "breaker:src/a.c#f": {
                    "id": "breaker:src/a.c#f",
                    "kind": "breaker",
                    "file": "src/a.c",
                    "function": "f",
                },
                "arch:m": {"id": "arch:m", "kind": "arch", "module": "m"},
                "verify:rej": {"id": "verify:rej", "kind": "verify", "fingerprint": FP_REJ},
            },
        },
    )


def test_agent_result_task_identity_from_schedule_and_agent_dir(tmp_path: Path, capsys) -> None:
    run = tmp_path / "run"
    _schedule_fixture(run)

    # Matching prover result (including normalized scratch/work/dot-slash paths matching wp_scheduler.norm_path).
    for file_val in ("src/a.c", "./src/a.c", "workspace/work/src/a.c", "agents/prove-f/scratch/work/src/a.c"):
        p_path = run / "agents" / "prove-f" / "scratch" / "result.json"
        write_json(
            p_path,
            prover_result(
                agent_id="prove-f",
                file=file_val,
                function="f",
                patch="agents/prove-f/artifacts/f.patch",
                evidence=[{"tool_output": "agents/prove-f/scratch/wp_f.json", "result": "all_proven"}],
            ),
        )
        rc, out = _run_agent_result_cli(capsys, [str(p_path)])
        assert rc == 0, out

    # Matching negotiate (role prover), breaker, architect, and crash_verifier results pass.
    neg_path = run / "agents" / "negotiate-g" / "scratch" / "result.json"
    write_json(
        neg_path,
        prover_result(
            agent_id="negotiate-g",
            file="src/a.c",
            function="g",
            patch="agents/negotiate-g/artifacts/g.patch",
            evidence=[{"tool_output": "agents/negotiate-g/scratch/wp_g.json", "result": "all_proven"}],
        ),
    )
    assert _run_agent_result_cli(capsys, [str(neg_path)])[0] == 0

    brk_path = run / "agents" / "breaker-f" / "scratch" / "result.json"
    write_json(
        brk_path,
        {
            "role": "breaker",
            "agent_id": "breaker-f",
            "file": "src/a.c",
            "function": "f",
            "status": "clean",
            "seeds": [],
            "crash_artifact": None,
            "failing_predicate": None,
            "analysis": "No crash found.",
            "fault_hypothesis": None,
        },
    )
    assert _run_agent_result_cli(capsys, [str(brk_path)])[0] == 0

    arch_path = run / "agents" / "arch-m" / "scratch" / "result.json"
    write_json(
        arch_path,
        {
            "role": "architect",
            "agent_id": "arch-m",
            "header": "src/m.h",
            "status": "passed",
            "patch": "agents/arch-m/artifacts/m.patch",
            "evidence": [{"tool_output": "agents/arch-m/scratch/guard.json", "result": "passed_dynamic_oracle"}],
            "boundary_assumptions": [],
            "notes": "ok",
        },
    )
    assert _run_agent_result_cli(capsys, [str(arch_path)])[0] == 0

    ev_rel = "agents/verify-1/scratch/replay.log"
    (run / ev_rel).parent.mkdir(parents=True, exist_ok=True)
    (run / ev_rel).write_text("ok\n", encoding="utf-8")
    rec = rejected_record()
    rec["evidence"] = [{"phase": "verifier", "tool_output": ev_rel, "description": "replay"}]
    rec["verifier"]["agent_id"] = "verify-1"
    ver_path = run / "agents" / "verify-1" / "scratch" / "result.json"
    ver_res = {
        "role": "crash_verifier",
        "agent_id": "verify-1",
        "candidate_fingerprint": FP_REJ,
        "decision": "rejected",
        "refingerprint_reason": None,
        "record": rec,
    }
    write_json(ver_path, ver_res)
    assert _run_agent_result_cli(capsys, [str(ver_path)])[0] == 0

    # Mismatched agent_id (e.g. copied from another attempt) catches both agent_id and task mismatches.
    p_path = run / "agents" / "prove-f" / "scratch" / "result.json"
    write_json(
        p_path,
        prover_result(
            agent_id="prove-other",
            file="src/other.c",
            function="other_fn",
            patch="agents/prove-other/artifacts/other_fn.patch",
            evidence=[{"tool_output": "agents/prove-other/scratch/wp.json", "result": "all_proven"}],
        ),
    )
    rc, out = _run_agent_result_cli(capsys, [str(p_path)])
    assert rc == 1
    assert any("$.agent_id" in e and "prove-other" in e and "prove-f" in e for e in out["errors"])
    assert any("$.function" in e and "other_fn" in e and "'f'" in e for e in out["errors"])
    assert any("$.file" in e and "src/other.c" in e and "src/a.c" in e for e in out["errors"])

    # Mismatched role (breaker result written for a prove task).
    write_json(
        p_path,
        {
            "role": "breaker",
            "agent_id": "prove-f",
            "file": "src/a.c",
            "function": "f",
            "status": "clean",
            "seeds": [],
            "crash_artifact": None,
            "failing_predicate": None,
            "analysis": "No crash found.",
            "fault_hypothesis": None,
        },
    )
    rc, out = _run_agent_result_cli(capsys, [str(p_path)])
    assert rc == 1
    assert any("$.role" in e and "breaker" in e and "prover" in e for e in out["errors"])

    # Mismatched function alone.
    write_json(
        p_path,
        prover_result(
            agent_id="prove-f",
            file="src/a.c",
            function="wrong_fn",
            patch="agents/prove-f/artifacts/f.patch",
            evidence=[{"tool_output": "agents/prove-f/scratch/wp_f.json", "result": "all_proven"}],
        ),
    )
    rc, out = _run_agent_result_cli(capsys, [str(p_path)])
    assert rc == 1
    assert any("$.function" in e and "wrong_fn" in e and "'f'" in e for e in out["errors"])

    # Mismatched file alone.
    write_json(
        p_path,
        prover_result(
            agent_id="prove-f",
            file="src/wrong.c",
            function="f",
            patch="agents/prove-f/artifacts/f.patch",
            evidence=[{"tool_output": "agents/prove-f/scratch/wp_f.json", "result": "all_proven"}],
        ),
    )
    rc, out = _run_agent_result_cli(capsys, [str(p_path)])
    assert rc == 1
    assert any("$.file" in e and "src/wrong.c" in e and "src/a.c" in e for e in out["errors"])

    # Mismatched candidate_fingerprint on a verify task.
    write_json(
        ver_path,
        {**ver_res, "candidate_fingerprint": FP_PARSE, "refingerprint_reason": "re-fingerprinted"},
    )
    rc, out = _run_agent_result_cli(capsys, [str(ver_path)])
    assert rc == 1
    assert any("$.candidate_fingerprint" in e and FP_PARSE in e and FP_REJ in e for e in out["errors"])


def test_agent_result_standalone_and_explicit_expected_flags(tmp_path: Path, capsys) -> None:
    # Standalone result.json without agents/<id>/scratch/ or state/wp_schedule.json still passes.
    standalone = tmp_path / "result.json"
    write_json(standalone, prover_result())
    rc, out = _run_agent_result_cli(capsys, [str(standalone)])
    assert rc == 0, out

    # Matching explicit --expected-* flags pass (including unnormalized file path).
    rc, out = _run_agent_result_cli(
        capsys,
        [
            str(standalone),
            "--expected-agent-id",
            "prover-1",
            "--expected-role",
            "prover",
            "--expected-function",
            "f",
            "--expected-file",
            "./src/a.c",
        ],
    )
    assert rc == 0, out

    # Mismatched explicit --expected-* flags report every mismatch.
    rc, out = _run_agent_result_cli(
        capsys,
        [
            str(standalone),
            "--expected-agent-id",
            "prover-2",
            "--expected-role",
            "breaker",
            "--expected-function",
            "g",
            "--expected-file",
            "src/b.c",
        ],
    )
    assert rc == 1
    assert any("$.agent_id" in e and "prover-2" in e for e in out["errors"])
    assert any("$.role" in e and "breaker" in e for e in out["errors"])
    assert any("$.function" in e and "'g'" in e for e in out["errors"])
    assert any("$.file" in e and "src/b.c" in e for e in out["errors"])

    # Python API kwargs behave identically.
    assert (
        list(
            validate_agent_result(
                prover_result(),
                expected_agent_id="prover-1",
                expected_role="prover",
                expected_function="f",
                expected_file="src/a.c",
            )
        )
        == []
    )
    errs = list(validate_agent_result(prover_result(), expected_function="other", expected_file="src/b.c"))
    assert any("$.function" in e for e in errs) and any("$.file" in e for e in errs)


def test_agent_result_in_agent_dir_without_schedule_checks_directory_agent_id(tmp_path: Path, capsys) -> None:
    run = tmp_path / "run-no-sched"
    p_path = run / "agents" / "prover-1" / "scratch" / "result.json"
    write_json(p_path, prover_result(agent_id="prover-1"))
    assert _run_agent_result_cli(capsys, [str(p_path)])[0] == 0

    # Copied result with a different agent_id is caught even when state/wp_schedule.json does not exist.
    write_json(
        p_path,
        prover_result(
            agent_id="prover-old",
            patch="agents/prover-old/artifacts/f.patch",
            evidence=[{"tool_output": "agents/prover-old/scratch/wp_f.json", "result": "all_proven"}],
        ),
    )
    rc, out = _run_agent_result_cli(capsys, [str(p_path)])
    assert rc == 1
    assert any("$.agent_id" in e and "prover-old" in e and "prover-1" in e for e in out["errors"])

    # A malformed or unrelated wp_schedule.json does not break standalone/unscheduled agent validation.
    (run / "state").mkdir(parents=True, exist_ok=True)
    (run / "state" / "wp_schedule.json").write_text("{corrupt", encoding="utf-8")
    write_json(p_path, prover_result(agent_id="prover-1"))
    assert _run_agent_result_cli(capsys, [str(p_path)])[0] == 0


def _sample_build_capture() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": "2026-11-20T00:00:00Z",
        "status": "ok",
        "target": "/target",
        "compiles": [
            {
                "source": "src/a.c",
                "object": "a.o",
                "cwd": ".",
                "compiler": "cc",
                "arguments": ["cc", "-c", "src/a.c"],
                "flags": [],
                "system_flags": [],
                "headers": [],
            },
            {
                "source": "src/b.c",
                "object": "b.o",
                "cwd": ".",
                "compiler": "cc",
                "arguments": ["cc", "-c", "src/b.c"],
                "flags": [],
                "system_flags": [],
                "headers": [],
            },
        ],
        "units": {
            "liba.a": {
                "kind": "static_lib",
                "test": False,
                "test_reason": None,
                "files": ["src/a.c", "src/b.c"],
                "objects": ["a.o", "b.o"],
                "links": [],
                "external_libs": [],
                "compiler": None,
                "cppflags": [],
                "entry_points": [],
                "embedded_api": [],
            }
        },
        "warnings": [],
    }


def test_validate_build_capture_semantic_flags_invariants():
    # Legacy capture without semantic_flags stays valid.
    base = _sample_build_capture()
    assert list(validate_artifacts.validate_build_capture(base)) == []

    # Empty semantic_flags is valid.
    empty = json.loads(json.dumps(base))
    for c in empty["compiles"]:
        c["semantic_flags"] = []
    empty["units"]["liba.a"]["semantic_flags"] = []
    assert list(validate_artifacts.validate_build_capture(empty)) == []

    # Populated valid semantic_flags (all + partial) passes.
    good = json.loads(json.dumps(empty))
    good["compiles"][0]["semantic_flags"] = ["-fwrapv", "-fpack-struct=2"]
    good["compiles"][1]["semantic_flags"] = ["-fwrapv"]
    good["units"]["liba.a"]["semantic_flags"] = [
        {"flag": "-fwrapv", "family": "wrapv", "category": "overflow", "scope": "all", "files": ["src/a.c", "src/b.c"]},
        {
            "flag": "-fpack-struct=2",
            "family": "pack_struct",
            "category": "layout",
            "scope": "partial",
            "files": ["src/a.c"],
        },
    ]
    assert list(validate_artifacts.validate_build_capture(good)) == []

    # Unknown flag token rejected by schema pattern.
    bad_tok = json.loads(json.dumps(good))
    bad_tok["compiles"][0]["semantic_flags"] = ["-fpack-struct=0"]
    assert any("pattern" in e for e in validate_artifacts.validate_build_capture(bad_tok))

    # Duplicate family on one compile rejected (-fpack-struct and -fpack-struct=2 violate last-flag-wins).
    bad_fam = json.loads(json.dumps(good))
    bad_fam["compiles"][0]["semantic_flags"] = ["-fpack-struct", "-fpack-struct=2"]
    assert any("duplicate semantic flag family" in e for e in validate_artifacts.validate_build_capture(bad_fam))

    # Mismatched family / category rejected.
    bad_meta = json.loads(json.dumps(good))
    bad_meta["units"]["liba.a"]["semantic_flags"][0]["family"] = "no_strict_overflow"
    bad_meta["units"]["liba.a"]["semantic_flags"][0]["category"] = "layout"
    errs = list(validate_artifacts.validate_build_capture(bad_meta))
    assert any(".family:" in e for e in errs) and any(".category:" in e for e in errs)

    # Duplicate flag in same unit rejected.
    bad_dup = json.loads(json.dumps(good))
    bad_dup["units"]["liba.a"]["semantic_flags"].append(dict(bad_dup["units"]["liba.a"]["semantic_flags"][0]))
    assert any("duplicate semantic flag" in e for e in validate_artifacts.validate_build_capture(bad_dup))

    # File not in unit files rejected.
    bad_file = json.loads(json.dumps(good))
    bad_file["units"]["liba.a"]["semantic_flags"][1]["files"] = ["src/missing.c"]
    assert any("not in unit files" in e for e in validate_artifacts.validate_build_capture(bad_file))

    # scope: "all" with proper subset of unit files rejected.
    bad_scope = json.loads(json.dumps(good))
    bad_scope["units"]["liba.a"]["semantic_flags"][0]["files"] = ["src/a.c"]
    assert any("'all' must cover every file" in e for e in validate_artifacts.validate_build_capture(bad_scope))


def test_validate_phase0_model_parse_warnings_invariants():
    base_model: dict[str, Any] = {
        "schema_version": 2,
        "generated_at": "2026-11-20T00:00:00Z",
        "status": "ok",
        "capture": "workspace/reports/build_capture.json",
        "units": {
            "liba.a": {
                "kind": "static_lib",
                "test": False,
                "files": ["src/a.c"],
                "links": [],
                "parse": {"status": "ok", "job": "abc", "seconds": 0.2},
                "concurrent": False,
            }
        },
        "parse_jobs": [{"key": "abc", "units": ["liba.a"], "sources": ["src/a.c"], "status": "ok", "seconds": 0.2}],
        "warnings": [],
    }
    # Legacy model without parse_warnings passes.
    assert list(validate_artifacts.validate_phase0_model(base_model)) == []

    pw_loss = {
        "asm_clobber": {"count": 1, "project_count": 1, "samples": ["src/a.c:10"]},
        "attrs_unknown": {
            "semantic": {"transparent_union": 1},
            "benign": {"cold": 2},
            "unclassified": {},
            "semantic_samples": ["src/a.c:4: transparent_union"],
            "unclassified_samples": [],
        },
        "benign_categories": {"typing:variadic": 1},
        "unclassified_categories": {
            "typing:implicit-function-declaration": {"count": 2, "project_count": 1, "sample": "src/a.c:5: Calling f"}
        },
        "no_annot_libc_skipped": 1,
        "has_parse_loss": True,
    }
    good = json.loads(json.dumps(base_model))
    good["parse_jobs"][0]["parse_warnings"] = pw_loss
    good["units"]["liba.a"]["parse"]["warnings"] = pw_loss
    assert list(validate_artifacts.validate_phase0_model(good)) == []

    # project_count > count on asm_clobber and unclassified_categories rejected.
    bad_counts = json.loads(json.dumps(good))
    bad_counts["parse_jobs"][0]["parse_warnings"]["asm_clobber"]["project_count"] = 2
    bad_counts["units"]["liba.a"]["parse"]["warnings"]["unclassified_categories"][
        "typing:implicit-function-declaration"
    ]["project_count"] = 3
    errs = list(validate_artifacts.validate_phase0_model(bad_counts))
    assert any("asm_clobber: project_count" in e for e in errs)
    assert any("unclassified_categories['typing:implicit-function-declaration']: project_count" in e for e in errs)

    # Mismatched has_parse_loss rejected (both directions).
    bad_flag = json.loads(json.dumps(good))
    bad_flag["parse_jobs"][0]["parse_warnings"]["has_parse_loss"] = False
    assert any("has_parse_loss" in e for e in validate_artifacts.validate_phase0_model(bad_flag))

    clean_pw = {
        "asm_clobber": {"count": 0, "project_count": 0, "samples": []},
        "attrs_unknown": {
            "semantic": {},
            "benign": {"cold": 3},
            "unclassified": {},
            "semantic_samples": [],
            "unclassified_samples": [],
        },
        "benign_categories": {"typing:implicit-conv-void-ptr": 2},
        "unclassified_categories": {
            "typing:incompatible-types-call": {"count": 10, "project_count": 0, "sample": "/usr/include/x.h:1: warn"}
        },
        "no_annot_libc_skipped": 2,
        "has_parse_loss": True,  # wrong: no project-code parse loss
    }
    bad_clean = json.loads(json.dumps(base_model))
    bad_clean["units"]["liba.a"]["parse"]["warnings"] = clean_pw
    assert any("has_parse_loss: must be False" in e for e in validate_artifacts.validate_phase0_model(bad_clean))
