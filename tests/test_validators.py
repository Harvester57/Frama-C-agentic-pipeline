import hashlib

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
