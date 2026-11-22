"""Unit tests for Wave 3-B: ledger P3/P4/P5 ingestion & supersession, artifact validation, and REPORT.md sections."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import generate_report as R
import ledger as L
import validate_artifacts as V
import wp_scheduler as S
from conftest import confirmed_record, evidence, metadata, unit, write_json
from fingerprint import make_fingerprint
from test_ledger import load, seed, units_by_id

pytestmark = pytest.mark.unit

OLD_DIGEST = "a" * 64
NEW_DIGEST = "b" * 64
PRED_MEM = "mem_access: \\valid_read(buf + off)"
PRED_OVF = "signed_overflow: x + 1 <= 2147483647"


def _write_coverage(run_dir: Path, module: str, rows: list[dict[str, Any]], *, status: str = "ok") -> None:
    write_json(
        run_dir / f"workspace/reports/coverage/{module}.json",
        {
            "mode": "coverage",
            "module": module,
            "status": status,
            "inputs": {"total": 10, "replayed": 10, "failed": 0, "not_replayed": 0, "known_crash": 0},
            "functions": rows,
        },
    )


def _cov_row(function: str, file_path: str, executions: int) -> dict[str, Any]:
    return {
        "function": function,
        "file": file_path,
        "line": 10,
        "executions": executions,
        "regions": {"total": 2, "covered": 2 if executions else 0},
    }


def _valid_smoke_report(
    module: str = "snmp",
    *,
    status: str = "degraded",
    startup_ok: bool = True,
    quarantined: list[int] | None = None,
    failing_engine: str | None = None,
    startup_reason: str | None = None,
) -> dict[str, Any]:
    q = sorted(quarantined if quarantined is not None else ([1] if status == "degraded" else []))
    case_results = [
        {"case": 0, "entry": "ber_decode_len", "status": "passed", "probes_run": 2},
    ]
    for idx in q:
        case_results.append(
            {
                "case": idx,
                "entry": "ber_decode_tag",
                "status": "quarantined",
                "probes_run": 1,
                "classification": "harness_setup_fault",
                "probe_kind": "empty",
                "payload_len": 0,
                "reason": "attempting free on non-malloc address",
            }
        )
    return {
        "schema_version": 1,
        "generated_at": "2026-11-22T12:00:00Z",
        "module": module,
        "harness_digest": OLD_DIGEST,
        "entry_style": "dispatch",
        "dispatch_case_count": max(2, len(case_results)),
        "status": status,
        "startup": {
            "ok": startup_ok,
            "engines_checked": ["sanitizers", "eacsl"],
            "failing_engine": failing_engine,
            "reason": startup_reason,
            "stack_trace": None,
            "results": {
                "sanitizers": {
                    "ok": startup_ok or failing_engine != "sanitizers",
                    "binary": f"workspace/build/fuzz_{module}.san",
                    "returncode": 0 if (startup_ok or failing_engine != "sanitizers") else 134,
                    "timed_out": False,
                    "reason": startup_reason if failing_engine == "sanitizers" else None,
                    "stack_trace": None,
                    "failure": None,
                }
            },
        },
        "quarantined_cases": q,
        "candidate_warning_cases": [],
        "skip_cases_env": ",".join(str(x) for x in q),
        "case_results": case_results,
        "counts": {
            "total": len(case_results),
            "passed": sum(1 for c in case_results if c["status"] == "passed"),
            "quarantined": len(q),
            "candidate_warning": 0,
        },
        "wall_s": 0.42,
    }


def _valid_judge_report(
    module: str = "snmp",
    *,
    status: str = "clean",
    passed: int = 10,
    failed: int = 0,
    not_judged_breakdown: dict[str, int] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    batch_state_only: list[dict[str, Any]] | None = None,
    blinded_cases: list[dict[str, Any]] | None = None,
    partial_blinded: bool = False,
    smoke_skipped_cases: list[int] | None = None,
    cross_engine_links: list[dict[str, Any]] | None = None,
    harness_digest: str = OLD_DIGEST,
) -> dict[str, Any]:
    bd = {
        "cap": 0,
        "timeout": 0,
        "blinded": 0,
        "smoke_skipped": 0,
        "error": 0,
        **(not_judged_breakdown or {}),
    }
    judged = passed + failed
    not_judged = sum(bd.values())
    total = judged + not_judged
    return {
        "schema_version": 1,
        "mode": "judge",
        "module": module,
        "generated_at": "2026-11-22T12:05:00Z",
        "discovering_step": "judge",
        "engine_used": "eacsl",
        "profile": "standard",
        "status": status,
        "binary": f"workspace/build/fuzz_{module}.e-acsl",
        "corpus_cap": 2048,
        "inputs": {
            "total": total,
            "mandatory": min(total, 2),
            "grown_total": max(0, total - 2),
            "grown_selected": max(0, total - 2 - bd["cap"]),
            "selected": max(0, total - bd["cap"] - bd["smoke_skipped"]),
            "judged": judged,
            "passed": passed,
            "failed": failed,
            "not_judged": not_judged,
            "not_judged_breakdown": bd,
        },
        "not_judged": not_judged,
        "artifacts": list(artifacts or []),
        "batch_state_only": list(batch_state_only or []),
        "cross_engine_links": list(cross_engine_links or []),
        "smoke_skipped_cases": list(smoke_skipped_cases or []),
        "blinded_cases": list(blinded_cases or []),
        "partial_blinded": partial_blinded,
        "telemetry": {
            "judge_s": 1.25,
            "batch_s": 1.0,
            "confirm_s": 0.25,
            "inputs_per_s": 8.0,
            "batches_run": 1,
            "fresh_confirmations": len(artifacts or []),
        },
        "harness_digest": harness_digest,
        "dispatch_case_count": 2,
        "dispatch_selector": "identity",
    }


def _valid_explore_report(
    module: str = "snmp",
    *,
    status: str = "clean",
    mode: str = "campaign",
    discovering_step: str = "explore",
    engine_used: str = "sanitizers",
    total_executions: int = 12000,
    max_cov: int = 145,
    blinded_cases: list[dict[str, Any]] | None = None,
    partial_blinded: bool = False,
    unspent_budget_s: float | None = None,
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "mode": mode,
        "module": module,
        "status": status,
        "engine_used": engine_used,
        "discovering_step": discovering_step,
        "blinded_cases": list(blinded_cases or []),
        "partial_blinded": partial_blinded,
        "telemetry": {
            "build_s": 0.0,
            "fuzz_s": 12.5,
            "replay_s": 0.4,
            "series": [{"cov": max_cov, "ft": max_cov * 2, "corp": 18, "exec_s": 960.0, "rss_mb": 62.0}],
            "total_executions": total_executions,
            "max_cov": max_cov,
            "max_ft": max_cov * 2,
            "max_corp": 18,
            "exec_s": 960.0,
            "peak_rss_mb": 62.0,
            "jobs_observed": 2,
        },
        "artifacts": [],
        "harness_digest": OLD_DIGEST,
        "dispatch_case_count": 2,
        "dispatch_selector": "identity",
    }
    if unspent_budget_s is not None:
        doc["unspent_budget_s"] = unspent_budget_s
    return doc


# ---------------------------------------------------------------------------
# 1. Startup error & smoke-quarantined artifact filtering
# ---------------------------------------------------------------------------


def test_startup_errors_and_smoke_quarantined_never_create_candidates(run_dir: Path) -> None:
    seed(run_dir)
    c_dir = run_dir / "workspace/crashes/snmp"
    c_dir.mkdir(parents=True, exist_ok=True)
    for name in ("crash-startup-kind", "crash-startup-stack", "crash-smoke-status", "crash-smoke-case", "crash-real"):
        (c_dir / name).write_bytes(name.encode("utf-8"))

    fp_startup = make_fingerprint("src/snmp/ber.c", "LLVMFuzzerInitialize", "mem_access", "init fail")
    fp_smoke = make_fingerprint("src/snmp/ber.c", "ber_decode_tag", "freeable", "bad free")
    fp_real = make_fingerprint("src/snmp/ber.c", "ber_decode_len", "mem_access", PRED_MEM)

    report = {
        "mode": "campaign",
        "module": "snmp",
        "status": "crash_found",
        "engine_used": "sanitizers",
        "discovering_step": "explore",
        "harness_digest": OLD_DIGEST,
        "smoke_skipped_cases": [3],
        "artifacts": [
            # 1) Explicit toolchain_startup_error kind
            {
                "artifact": str(c_dir / "crash-startup-kind"),
                "kind": "toolchain_startup_error",
                "sha256": "1" * 64,
                "size_bytes": 18,
                "reproducible": True,
                "fingerprint": fp_startup,
                "failure": {
                    "file": "src/snmp/ber.c",
                    "line": 1,
                    "function": "ber_decode_len",
                    "kind": "toolchain_startup_error",
                    "alarm_kind": "mem_access",
                    "predicate": "init fail",
                },
            },
            # 2) Startup failure detected via failure_identity.is_startup_failure()
            {
                "artifact": str(c_dir / "crash-startup-stack"),
                "kind": "crash",
                "sha256": "2" * 64,
                "size_bytes": 19,
                "reproducible": True,
                "fingerprint": fp_startup,
                "replay_log_tail": (
                    "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
                    "    #0 0x401000 in __e_acsl_globals_init /share/e-acsl/init.c:12\n"
                    "    #1 0x401100 in __libc_start_main\n"
                ),
                "failure": {
                    "file": "src/snmp/ber.c",
                    "line": 1,
                    "function": "LLVMFuzzerInitialize",
                    "kind": "asan_segv",
                    "alarm_kind": "mem_access",
                    "predicate": "SEGV in init",
                },
            },
            # 3) Smoke-quarantined by explicit status
            {
                "artifact": str(c_dir / "crash-smoke-status"),
                "kind": "crash",
                "status": "quarantined_by_smoke",
                "sha256": "3" * 64,
                "size_bytes": 18,
                "reproducible": True,
                "fingerprint": fp_smoke,
                "failure": {
                    "file": "src/snmp/ber.c",
                    "line": 12,
                    "function": "ber_decode_tag",
                    "kind": "asan_bad_free",
                    "alarm_kind": "freeable",
                    "predicate": "bad free",
                },
            },
            # 4) Smoke-quarantined because dispatch case is in smoke_skipped_cases
            {
                "artifact": str(c_dir / "crash-smoke-case"),
                "kind": "crash",
                "case": 3,
                "sha256": "4" * 64,
                "size_bytes": 16,
                "reproducible": True,
                "fingerprint": fp_smoke,
                "failure": {
                    "file": "src/snmp/ber.c",
                    "line": 12,
                    "function": "ber_decode_tag",
                    "kind": "asan_bad_free",
                    "alarm_kind": "freeable",
                    "predicate": "bad free",
                },
            },
            # 5) Genuine target crash: MUST still become a candidate
            {
                "artifact": str(c_dir / "crash-real"),
                "kind": "crash",
                "case": 0,
                "sha256": "5" * 64,
                "size_bytes": 10,
                "reproducible": True,
                "fingerprint": fp_real,
                "failure": {
                    "file": "src/snmp/ber.c",
                    "line": 42,
                    "function": "ber_decode_len",
                    "kind": "asan_heap_buffer_overflow",
                    "alarm_kind": "mem_access",
                    "predicate": PRED_MEM,
                },
            },
        ],
    }
    fuzz_path = run_dir / "workspace/reports/fuzz/snmp.json"
    write_json(fuzz_path, report)

    stats = L.cmd_ingest_fuzz([fuzz_path])
    assert stats["startup_errors"] == 2
    assert stats["smoke_quarantined"] == 2
    assert stats["candidates"] == 1

    cands = load(run_dir / "candidates.json")
    assert [c["fingerprint"] for c in cands] == [fp_real]
    assert cands[0]["harness_digest"] == OLD_DIGEST
    assert cands[0]["discovering_step"] == "explore"

    # Module units record fuzz_startup_error and harness_smoke_quarantined evidence instead.
    units = units_by_id(run_dir)
    tag_results = {e["result"] for e in units["src/snmp/ber.c#ber_decode_tag::rte"]["evidence"]}
    assert "fuzz_startup_error" in tag_results
    assert "harness_smoke_quarantined" in tag_results
    assert units["src/snmp/ber.c#ber_decode_tag::rte"]["status"] == "planned"
    assert list(V.validate_candidates(cands)) == []
    assert list(V.validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


def test_report_level_startup_error_creates_zero_candidates(run_dir: Path) -> None:
    seed(run_dir)
    fuzz_path = run_dir / "workspace/reports/fuzz/snmp.json"
    write_json(
        fuzz_path,
        {
            "mode": "campaign",
            "module": "snmp",
            "status": "startup_error",
            "reason": "e-acsl binary aborted in __e_acsl_globals_init",
            "artifacts": [{"artifact": "workspace/crashes/snmp/ignored", "kind": "crash", "sha256": "0" * 64}],
        },
    )
    stats = L.cmd_ingest_fuzz([fuzz_path])
    assert stats["startup_errors"] == 1
    assert stats["candidates"] == 0
    assert load(run_dir / "candidates.json") == []
    units = units_by_id(run_dir)
    assert any(e["result"] == "fuzz_startup_error" for e in units["src/snmp/ber.c#ber_decode_len::rte"]["evidence"])


# ---------------------------------------------------------------------------
# 2. Judge ingestion: F7 supersession, P2c E-ACSL fuzz_clean, auto-discovery
# ---------------------------------------------------------------------------


def test_ingest_judge_supersedes_prior_phase1_evidence_and_gates_eacsl_fuzz_clean(run_dir: Path) -> None:
    seed(run_dir)
    # Coverage: ber_decode_tag executed (5), ber_decode_len executed (0), snmp_parse_pdu executed (3).
    _write_coverage(
        run_dir,
        "snmp",
        [
            _cov_row("ber_decode_tag", "src/snmp/ber.c", 5),
            _cov_row("ber_decode_len", "src/snmp/ber.c", 0),
            _cov_row("snmp_parse_pdu", "src/snmp/pdu.c", 3),
        ],
    )
    judge_path = run_dir / "workspace/reports/judge/snmp.json"

    # Run 1: blinded judge -> records fuzz_blinded, NEVER grants fuzz_clean.
    write_json(
        judge_path,
        _valid_judge_report(
            "snmp",
            status="blinded",
            passed=0,
            failed=16,
            not_judged_breakdown={"blinded": 4},
            blinded_cases=[{"case": 0, "fingerprint": "fp_blind", "crashes": 16}],
        ),
    )
    L.cmd_ingest_judge([judge_path])
    units = units_by_id(run_dir)
    for cid in ("src/snmp/ber.c#ber_decode_tag::rte", "src/snmp/ber.c#ber_decode_len::rte"):
        results = [e["result"] for e in units[cid]["evidence"] if e["phase"] == "fuzz"]
        assert results == ["fuzz_blinded"]

    # Run 2 (partial with not_judged cap > 0): supersedes fuzz_blinded, records fuzz_not_judged, NO fuzz_clean.
    write_json(
        judge_path,
        _valid_judge_report(
            "snmp",
            status="partial",
            passed=10,
            failed=0,
            not_judged_breakdown={"cap": 5},
        ),
    )
    stats_partial = L.cmd_ingest_judge([judge_path])
    assert stats_partial["superseded_phase1_evidence"] > 0
    units = units_by_id(run_dir)
    for cid in ("src/snmp/ber.c#ber_decode_tag::rte", "src/snmp/ber.c#ber_decode_len::rte"):
        results = [e["result"] for e in units[cid]["evidence"] if e["phase"] == "fuzz"]
        assert results == ["fuzz_not_judged"], f"stale fuzz_blinded must be superseded on {cid}: {results}"

    # Run 3 (clean after fix, not_judged == 0): supersedes fuzz_not_judged; grants E-ACSL fuzz_clean
    # ONLY to dynamically executed functions (ber_decode_tag, snmp_parse_pdu), NOT ber_decode_len (0 execs)!
    write_json(judge_path, _valid_judge_report("snmp", status="clean", passed=12, failed=0))
    stats_clean = L.cmd_ingest_judge([judge_path])
    assert stats_clean["superseded_phase1_evidence"] > 0
    units = units_by_id(run_dir)
    tag_ev = [e for e in units["src/snmp/ber.c#ber_decode_tag::rte"]["evidence"] if e["phase"] == "fuzz"]
    len_ev = [e for e in units["src/snmp/ber.c#ber_decode_len::rte"]["evidence"] if e["phase"] == "fuzz"]
    pdu_ev = [e for e in units["src/snmp/pdu.c#snmp_parse_pdu::rte"]["evidence"] if e["phase"] == "fuzz"]

    assert [e["result"] for e in tag_ev] == ["fuzz_clean"]
    assert "E-ACSL judge" in tag_ev[0]["summary"]
    assert [e["result"] for e in pdu_ev] == ["fuzz_clean"]
    assert [e["result"] for e in len_ev] == ["fuzz_not_executed"]
    assert list(V.validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


def test_ingest_judge_partial_blinded_isolates_healthy_case_and_excludes_batch_state_only(run_dir: Path) -> None:
    seed(run_dir)
    # Dispatch sidecar: case 0 calls ber_decode_len, case 1 calls ber_decode_tag.
    write_json(
        run_dir / "workspace/harnesses/harness_snmp.json",
        {
            "module": "snmp",
            "harness_file": "workspace/harnesses/harness_snmp.c",
            "sources": ["src/snmp/ber.c", "src/snmp/pdu.c"],
            "cppflags": "",
            "entry_fn": "LLVMFuzzerTestOneInput",
            "entry_style": "dispatch",
            "dispatch_case_count": 2,
            "dispatch_cases": ["ber_decode_len(buf, len);", "ber_decode_tag(buf, len);"],
            "api_harness": True,
            "api_cases": [
                {"selector": 0, "kind": "single", "calls": ["ber_decode_len"], "slots": [], "rest": None, "entry": "ber_decode_len"},
                {"selector": 1, "kind": "single", "calls": ["ber_decode_tag"], "slots": [], "rest": None, "entry": "ber_decode_tag"},
            ],
        },
    )
    _write_coverage(
        run_dir,
        "snmp",
        [
            _cov_row("ber_decode_len", "src/snmp/ber.c", 10),
            _cov_row("ber_decode_tag", "src/snmp/ber.c", 8),
            _cov_row("snmp_parse_pdu", "src/snmp/pdu.c", 4),
        ],
    )
    # Case 0 is blinded; case 1 is healthy; u_bso is batch_state_only (must NOT become a candidate).
    judge_path = run_dir / "workspace/reports/judge/snmp.json"
    write_json(
        judge_path,
        _valid_judge_report(
            "snmp",
            status="partial_blinded",
            passed=8,
            failed=16,
            not_judged_breakdown={"blinded": 4},
            blinded_cases=[{"case": 0, "fingerprint": "fp_c0_blind", "crashes": 16}],
            partial_blinded=True,
            batch_state_only=[
                {
                    "input": "workspace/corpus/snmp/u_bso",
                    "sha256": "c" * 64,
                    "case": 1,
                    "batch_failure": {"file": "src/snmp/ber.c", "line": 20, "function": "ber_decode_tag"},
                    "batch_fingerprint": "src/snmp/ber.c#ber_decode_tag::mem_access::0123456789",
                    "standalone_returncode": 0,
                    "standalone_timed_out": False,
                }
            ],
        ),
    )

    # Also test unified ingest auto-discovery: ingest-fuzz on explore report auto-ingests judge/snmp.json!
    fuzz_path = run_dir / "workspace/reports/fuzz/snmp.json"
    write_json(fuzz_path, _valid_explore_report("snmp", status="clean"))
    stats = L.cmd_ingest_fuzz([fuzz_path])
    assert stats["judge_reports"] == 1
    assert load(run_dir / "candidates.json") == []  # batch_state_only never creates candidates

    units = units_by_id(run_dir)
    # Case 1 (ber_decode_tag): healthy, dynamically executed -> gets E-ACSL judge fuzz_clean!
    tag_judge = [
        e for e in units["src/snmp/ber.c#ber_decode_tag::rte"]["evidence"] if e.get("tool_output") == "workspace/reports/judge/snmp.json"
    ]
    assert [e["result"] for e in tag_judge] == ["fuzz_clean"]

    # Case 0 (ber_decode_len): blinded -> gets fuzz_blinded, NEVER E-ACSL fuzz_clean!
    len_judge = [
        e for e in units["src/snmp/ber.c#ber_decode_len::rte"]["evidence"] if e.get("tool_output") == "workspace/reports/judge/snmp.json"
    ]
    assert [e["result"] for e in len_judge] == ["fuzz_blinded"]

    # snmp_parse_pdu (not mapped to any isolated healthy case): fails closed -> fuzz_blinded, NOT fuzz_clean!
    pdu_judge = [
        e for e in units["src/snmp/pdu.c#snmp_parse_pdu::rte"]["evidence"] if e.get("tool_output") == "workspace/reports/judge/snmp.json"
    ]
    assert [e["result"] for e in pdu_judge] == ["fuzz_blinded"]


def test_ingest_judge_cli_and_cross_engine_link(run_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    seed(run_dir)
    c_dir = run_dir / "workspace/crashes/snmp"
    c_dir.mkdir(parents=True, exist_ok=True)
    crash = c_dir / "crash-shared"
    crash.write_bytes(b"\x01\x02")
    sha = hashlib.sha256(b"\x01\x02").hexdigest()

    fp_asan = make_fingerprint("src/snmp/ber.c", "ber_decode_len", "mem_access", PRED_MEM)
    fp_eacsl = make_fingerprint("src/snmp/ber.c", "ber_decode_len", "signed_overflow", PRED_OVF)

    fuzz_path = run_dir / "workspace/reports/fuzz/snmp.json"
    write_json(
        fuzz_path,
        {
            **_valid_explore_report("snmp", status="crash_found"),
            "artifacts": [
                {
                    "artifact": str(crash),
                    "kind": "crash",
                    "sha256": sha,
                    "size_bytes": 2,
                    "reproducible": True,
                    "engine": "sanitizers",
                    "fingerprint": fp_asan,
                    "failure": {
                        "file": "src/snmp/ber.c",
                        "line": 42,
                        "function": "ber_decode_len",
                        "kind": "asan_heap_buffer_overflow",
                        "alarm_kind": "mem_access",
                        "predicate": PRED_MEM,
                    },
                }
            ],
        },
    )
    L.cmd_ingest_fuzz([fuzz_path])

    judge_path = run_dir / "workspace/reports/judge/snmp.json"
    write_json(
        judge_path,
        _valid_judge_report(
            "snmp",
            status="crash_found",
            passed=5,
            failed=1,
            artifacts=[
                {
                    "artifact": str(crash),
                    "kind": "crash",
                    "sha256": sha,
                    "size_bytes": 2,
                    "case": 0,
                    "engine": "eacsl",
                    "discovering_step": "judge",
                    "reproducible": True,
                    "standalone_confirmed": True,
                    "returncode": 134,
                    "timed_out": False,
                    "failure": {
                        "file": "src/snmp/ber.c",
                        "line": 43,
                        "function": "ber_decode_len",
                        "kind": "assertion",
                        "alarm_kind": "signed_overflow",
                        "predicate": PRED_OVF,
                    },
                    "fingerprint": fp_eacsl,
                    "cross_engine_links": [
                        {
                            "judge_fingerprint": fp_eacsl,
                            "explore_fingerprint": fp_asan,
                            "explore_engine": "sanitizers",
                            "match": "same_artifact",
                            "artifact_sha256": sha,
                        }
                    ],
                }
            ],
        ),
    )

    rc = L.main(["ingest-judge", str(judge_path)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["judge_reports"] == 1
    assert out["candidates"] == 1

    cands = {c["fingerprint"]: c for c in load(run_dir / "candidates.json")}
    assert cands[fp_eacsl]["discovering_step"] == "judge"
    assert any(r["fingerprint"] == fp_asan for r in cands[fp_eacsl].get("related") or [])
    assert any(r["fingerprint"] == fp_eacsl for r in cands[fp_asan].get("related") or [])
    assert list(V.validate_candidates(list(cands.values()))) == []


# ---------------------------------------------------------------------------
# 3. supersede-candidates & wp_scheduler interoperability
# ---------------------------------------------------------------------------


def test_supersede_candidates_preserves_confirmed_and_fresh_digest_and_interops_with_scheduler(
    run_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seed(run_dir)
    fuzz_rel = "workspace/reports/fuzz/snmp.json"
    write_json(run_dir / fuzz_rel, _valid_explore_report("snmp", status="crash_found"))
    crash = run_dir / "workspace/crashes/snmp/crash-1"
    crash.parent.mkdir(parents=True, exist_ok=True)
    crash.write_bytes(b"abc")

    fp_old_stale = make_fingerprint("src/snmp/ber.c", "ber_decode_len", "mem_access", PRED_MEM)
    fp_old_confirmed = make_fingerprint("src/snmp/ber.c", "ber_decode_tag", "mem_access", PRED_MEM)
    fp_fresh = make_fingerprint("src/snmp/pdu.c", "snmp_parse_pdu", "signed_overflow", PRED_OVF)
    fp_other_mod = make_fingerprint("src/glue/init.c", "glue_init", "mem_access", PRED_MEM)

    # Seed confirmed finding in findings.json for fp_old_confirmed.
    confirmed = confirmed_record(fp_old_confirmed)
    confirmed["location"] = {"file": "src/snmp/ber.c", "line": 15, "function": "ber_decode_tag"}
    confirmed["linked_units"] = ["src/snmp/ber.c#ber_decode_tag::rte"]
    confirmed["reproducers"][0]["sha256"] = hashlib.sha256(b"abc").hexdigest()
    write_json(run_dir / "findings.json", [confirmed])
    findings_bytes_before = (run_dir / "findings.json").read_bytes()

    # Seed candidates: stale unverified (OLD_DIGEST), confirmed (OLD_DIGEST), fresh unverified (NEW_DIGEST), other module (OLD_DIGEST).
    def _cand(fp: str, mod: str, fn: str, file_p: str, status: str, digest: str, linked: list[str]) -> dict[str, Any]:
        return {
            "fingerprint": fp,
            "status": status,
            "origin": "fuzz",
            "proposed_verdict": "confirmed",
            "module": mod,
            "location": {"file": file_p, "line": 10, "function": fn},
            "property": {"kind": "mem_access", "predicate": PRED_MEM},
            "reproducers": ["workspace/crashes/snmp/crash-1"],
            "tool_outputs": [fuzz_rel],
            "linked_units": linked,
            "first_seen": "2026-11-22T12:00:00Z",
            "harness_digest": digest,
        }

    cands = [
        _cand(fp_old_stale, "snmp", "ber_decode_len", "src/snmp/ber.c", "unverified", OLD_DIGEST, ["src/snmp/ber.c#ber_decode_len::rte"]),
        _cand(fp_old_confirmed, "snmp", "ber_decode_tag", "src/snmp/ber.c", "verified", OLD_DIGEST, ["src/snmp/ber.c#ber_decode_tag::rte"]),
        _cand(fp_fresh, "snmp", "snmp_parse_pdu", "src/snmp/pdu.c", "unverified", NEW_DIGEST, ["src/snmp/pdu.c#snmp_parse_pdu::rte"]),
        _cand(fp_other_mod, "glue", "glue_init", "src/glue/init.c", "unverified", OLD_DIGEST, ["src/glue/init.c#glue_init::rte"]),
    ]
    write_json(run_dir / "candidates.json", sorted(cands, key=lambda c: c["fingerprint"]))

    # Put ber_decode_len::rte and ber_decode_tag::rte into candidate status to verify unit cleanup.
    ledger_rows = load(run_dir / "coverage-ledger.json")
    for u in ledger_rows:
        if u["coverage_id"] == "src/snmp/ber.c#ber_decode_len::rte":
            u["status"] = "candidate"
            u["result_fingerprints"] = [fp_old_stale]
            u["evidence"] = [evidence(phase="fuzz", result="fuzz_failure", discharging=False, tool_output=fuzz_rel)]
        elif u["coverage_id"] == "src/snmp/ber.c#ber_decode_tag::rte":
            u["status"] = "candidate"
            u["result_fingerprints"] = [fp_old_confirmed]
            u["evidence"] = [evidence(phase="fuzz", result="fuzz_failure", discharging=False, tool_output=fuzz_rel)]
    write_json(run_dir / "coverage-ledger.json", ledger_rows)

    # Invoke through wp_scheduler._supersede_ledger_candidates (direct interoperability!).
    res = S._supersede_ledger_candidates(run_dir, "snmp", OLD_DIGEST, "harness snmp repaired")
    assert res["ok"] is True
    assert res["supported"] is True
    assert res["result"]["superseded"] == 1
    assert res["result"]["superseded_fingerprints"] == [fp_old_stale]
    assert res["result"]["untouched_confirmed"] == 1

    # CRITICAL INVARIANT: findings.json is byte-identical!
    assert (run_dir / "findings.json").read_bytes() == findings_bytes_before

    after = {c["fingerprint"]: c for c in load(run_dir / "candidates.json")}
    assert after[fp_old_stale]["status"] == "superseded_by_repair"
    assert after[fp_old_stale]["superseded_reason"] == "harness snmp repaired"
    assert after[fp_old_stale]["superseded_at"]
    assert after[fp_old_stale]["superseded_from_harness_digest"] == OLD_DIGEST
    assert after[fp_old_confirmed]["status"] == "verified"
    assert after[fp_fresh]["status"] == "unverified"
    assert after[fp_other_mod]["status"] == "unverified"

    # Linked unit of superseded candidate returned to planned; confirmed unit untouched!
    units = units_by_id(run_dir)
    assert units["src/snmp/ber.c#ber_decode_len::rte"]["status"] == "planned"
    assert units["src/snmp/ber.c#ber_decode_len::rte"]["result_fingerprints"] == []
    assert units["src/snmp/ber.c#ber_decode_tag::rte"]["status"] == "candidate"
    assert units["src/snmp/ber.c#ber_decode_tag::rte"]["result_fingerprints"] == [fp_old_confirmed]

    # CLI subcommand also works cleanly (idempotent second call supersedes 0).
    rc = L.main(["supersede-candidates", "--module", "snmp", "--old-harness-digest", OLD_DIGEST, "--reason", "recheck"])
    assert rc == 0
    cli_out = json.loads(capsys.readouterr().out)
    assert cli_out["superseded"] == 0
    assert cli_out["untouched_confirmed"] == 1
    assert list(V.validate_candidates(list(after.values()))) == []
    assert list(V.validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


# ---------------------------------------------------------------------------
# 4. validate_artifacts.py run-dir with smoke, judge, fuzz & Phase 0 artifacts
# ---------------------------------------------------------------------------


def _seed_valid_run_dir(run_dir: Path) -> None:
    write_json(run_dir / "run-metadata.json", metadata("complete", None))
    write_json(
        run_dir / "coverage-ledger.json",
        [unit("src/snmp/ber.c", "ber_decode_len", "rte", "covered", evidence=[evidence(tool_output="workspace/reports/eva/snmp.json")])],
    )
    write_json(run_dir / "workspace/reports/eva/snmp.json", {})
    write_json(run_dir / "findings.json", [])
    write_json(
        run_dir / "candidates.json",
        [
            {
                "fingerprint": make_fingerprint("src/snmp/ber.c", "ber_decode_len", "mem_access", PRED_MEM),
                "status": "superseded_by_repair",
                "origin": "fuzz",
                "proposed_verdict": "confirmed",
                "module": "snmp",
                "location": {"file": "src/snmp/ber.c", "line": 42, "function": "ber_decode_len"},
                "property": {"kind": "mem_access", "predicate": PRED_MEM},
                "reproducers": [],
                "tool_outputs": ["workspace/reports/fuzz/snmp.json"],
                "linked_units": ["src/snmp/ber.c#ber_decode_len::rte"],
                "first_seen": "2026-11-22T12:00:00Z",
                "harness_digest": OLD_DIGEST,
                "superseded_at": "2026-11-22T12:10:00Z",
                "superseded_reason": "harness repaired",
            }
        ],
    )
    write_json(
        run_dir / "workspace/reports/harness_reach.json",
        {
            "generated_at": "2026-11-22T12:00:00Z",
            "dag": "workspace/reports/callgraph_dag.json",
            "passed": True,
            "modules": [{"module": "snmp", "passed": True, "gaps": []}],
        },
    )
    write_json(run_dir / "workspace/reports/smoke/snmp.json", _valid_smoke_report("snmp", status="degraded", quarantined=[1]))
    write_json(run_dir / "workspace/reports/fuzz/snmp.json", _valid_explore_report("snmp", status="clean"))
    write_json(run_dir / "workspace/reports/judge/snmp.json", _valid_judge_report("snmp", status="clean", passed=12))


def test_validate_run_dir_passes_and_rejects_invalid_smoke_and_judge(tmp_path: Path) -> None:
    _seed_valid_run_dir(tmp_path)
    assert list(V.validate_run_dir(tmp_path)) == []

    # Reject invalid smoke report (bad status & mismatched skip_cases_env).
    bad_smoke = _valid_smoke_report("snmp", status="degraded", quarantined=[1])
    bad_smoke["skip_cases_env"] = ""
    write_json(tmp_path / "workspace/reports/smoke/snmp.json", bad_smoke)
    errs_smoke = list(V.validate_run_dir(tmp_path))
    assert any("workspace/reports/smoke/snmp.json" in e and "skip_cases_env" in e for e in errs_smoke)

    # Restore valid smoke, break judge report (not_judged mismatch + invalid status).
    write_json(tmp_path / "workspace/reports/smoke/snmp.json", _valid_smoke_report("snmp", status="ok", quarantined=[]))
    bad_judge = _valid_judge_report("snmp", status="clean", passed=5)
    bad_judge["not_judged"] = 99
    write_json(tmp_path / "workspace/reports/judge/snmp.json", bad_judge)
    errs_judge = list(V.validate_run_dir(tmp_path))
    assert any("workspace/reports/judge/snmp.json" in e and "not_judged" in e for e in errs_judge)

    # Restore valid judge, break fuzz report with campaign mode + bogus status.
    write_json(tmp_path / "workspace/reports/judge/snmp.json", _valid_judge_report("snmp", status="clean", passed=5))
    write_json(tmp_path / "workspace/reports/fuzz/snmp.json", {"mode": "campaign", "module": "snmp", "status": "bogus"})
    errs_fuzz = list(V.validate_run_dir(tmp_path))
    assert any("workspace/reports/fuzz/snmp.json" in e for e in errs_fuzz)

    # Legacy dummy fuzz report `{}` without `mode` still passes validate_run_dir cleanly.
    write_json(tmp_path / "workspace/reports/fuzz/snmp.json", {})
    assert list(V.validate_run_dir(tmp_path)) == []

    # Deep eacsl-fuzz reports live under workspace/reports/eacsl-fuzz/ and are validated against fuzz_report.schema.json.
    write_json(
        tmp_path / "workspace/reports/eacsl-fuzz/snmp.json",
        _valid_explore_report(
            "snmp",
            status="clean",
            mode="eacsl-fuzz",
            discovering_step="eacsl_fuzz",
            engine_used="eacsl",
            total_executions=1000,
            max_cov=40,
            unspent_budget_s=0.0,
        ),
    )
    assert list(V.validate_run_dir(tmp_path)) == []

    write_json(
        tmp_path / "workspace/reports/eacsl-fuzz/snmp.json",
        {"mode": "eacsl-fuzz", "module": "snmp", "status": "bogus"},
    )
    errs_ef = list(V.validate_run_dir(tmp_path))
    assert any("workspace/reports/eacsl-fuzz/snmp.json" in e for e in errs_ef)


def test_ingest_fuzz_clean_refuses_fuzz_clean_for_smoke_quarantined_cases(run_dir: Path) -> None:
    seed(run_dir)
    # 1) Without coverage (executions is None), smoke_skipped_cases must fail closed: NO fuzz_clean.
    fuzz_path = run_dir / "workspace/reports/fuzz/snmp.json"
    write_json(
        fuzz_path,
        {
            **_valid_explore_report("snmp", status="clean"),
            "smoke_skipped_cases": [0],
        },
    )
    L.cmd_ingest_fuzz([fuzz_path])
    units = units_by_id(run_dir)
    for cid in (
        "src/snmp/ber.c#ber_decode_len::rte",
        "src/snmp/ber.c#ber_decode_tag::rte",
        "src/snmp/pdu.c#snmp_parse_pdu::rte",
    ):
        results = [e["result"] for e in units[cid]["evidence"] if e["phase"] == "fuzz"]
        assert results == ["harness_smoke_quarantined"], f"{cid} must not get fuzz_clean without coverage: {results}"

    # 2) With dispatch sidecar + coverage: case 0 -> ber_decode_len (quarantined),
    #    case 1 -> ber_decode_tag (healthy), snmp_parse_pdu (unisolatable -> fail closed).
    write_json(
        run_dir / "workspace/harnesses/harness_snmp.json",
        {
            "module": "snmp",
            "harness_file": "workspace/harnesses/harness_snmp.c",
            "sources": ["src/snmp/ber.c", "src/snmp/pdu.c"],
            "cppflags": "",
            "entry_fn": "LLVMFuzzerTestOneInput",
            "entry_style": "dispatch",
            "dispatch_case_count": 2,
            "dispatch_cases": ["ber_decode_len(buf, len);", "ber_decode_tag(buf, len);"],
            "api_harness": True,
            "api_cases": [
                {"selector": 0, "kind": "single", "calls": ["ber_decode_len"], "slots": [], "rest": None, "entry": "ber_decode_len"},
                {"selector": 1, "kind": "single", "calls": ["ber_decode_tag"], "slots": [], "rest": None, "entry": "ber_decode_tag"},
            ],
        },
    )
    _write_coverage(
        run_dir,
        "snmp",
        [
            _cov_row("ber_decode_len", "src/snmp/ber.c", 5),
            _cov_row("ber_decode_tag", "src/snmp/ber.c", 8),
            _cov_row("snmp_parse_pdu", "src/snmp/pdu.c", 3),
        ],
    )
    L.cmd_ingest_fuzz([fuzz_path])
    units = units_by_id(run_dir)
    assert [e["result"] for e in units["src/snmp/ber.c#ber_decode_tag::rte"]["evidence"] if e["phase"] == "fuzz"] == [
        "fuzz_clean"
    ]
    assert [e["result"] for e in units["src/snmp/ber.c#ber_decode_len::rte"]["evidence"] if e["phase"] == "fuzz"] == [
        "harness_smoke_quarantined"
    ]
    assert [e["result"] for e in units["src/snmp/pdu.c#snmp_parse_pdu::rte"]["evidence"] if e["phase"] == "fuzz"] == [
        "harness_smoke_quarantined"
    ]

    # 3) If quarantined case 0 had 0 executions in coverage, it still records harness_smoke_quarantined (never fuzz_clean).
    _write_coverage(
        run_dir,
        "snmp",
        [
            _cov_row("ber_decode_len", "src/snmp/ber.c", 0),
            _cov_row("ber_decode_tag", "src/snmp/ber.c", 8),
            _cov_row("snmp_parse_pdu", "src/snmp/pdu.c", 0),
        ],
    )
    L.cmd_ingest_fuzz([fuzz_path])
    units = units_by_id(run_dir)
    assert [e["result"] for e in units["src/snmp/ber.c#ber_decode_len::rte"]["evidence"] if e["phase"] == "fuzz"] == [
        "harness_smoke_quarantined"
    ]
    assert [e["result"] for e in units["src/snmp/ber.c#ber_decode_tag::rte"]["evidence"] if e["phase"] == "fuzz"] == [
        "fuzz_clean"
    ]
    assert [e["result"] for e in units["src/snmp/pdu.c#snmp_parse_pdu::rte"]["evidence"] if e["phase"] == "fuzz"] == [
        "fuzz_not_executed"
    ]
    assert list(V.validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


def test_ingest_fuzz_clean_refuses_fuzz_clean_for_deep_eacsl_fuzz_judge_skipped_cases(run_dir: Path) -> None:
    seed(run_dir)
    ef_path = run_dir / "workspace/reports/eacsl-fuzz/snmp.json"
    write_json(
        ef_path,
        {
            **_valid_explore_report(
                "snmp",
                status="clean",
                mode="eacsl-fuzz",
                discovering_step="eacsl_fuzz",
                engine_used="eacsl",
            ),
            "judge_skipped_cases": [0],
        },
    )

    # 1) Without coverage (executions is None), judge_skipped_cases fails closed with fuzz_not_judged.
    L.cmd_ingest_fuzz([ef_path])
    units = units_by_id(run_dir)
    for cid in (
        "src/snmp/ber.c#ber_decode_len::rte",
        "src/snmp/ber.c#ber_decode_tag::rte",
        "src/snmp/pdu.c#snmp_parse_pdu::rte",
    ):
        results = [e["result"] for e in units[cid]["evidence"] if e["phase"] == "fuzz"]
        assert results == ["fuzz_not_judged"], f"{cid} must not get fuzz_clean without coverage: {results}"

    # 2) With dispatch sidecar + coverage: case 0 -> ber_decode_len (judge-skipped),
    #    case 1 -> ber_decode_tag (healthy -> fuzz_clean), snmp_parse_pdu (unisolatable -> fuzz_not_judged).
    write_json(
        run_dir / "workspace/harnesses/harness_snmp.json",
        {
            "module": "snmp",
            "harness_file": "workspace/harnesses/harness_snmp.c",
            "sources": ["src/snmp/ber.c", "src/snmp/pdu.c"],
            "cppflags": "",
            "entry_fn": "LLVMFuzzerTestOneInput",
            "entry_style": "dispatch",
            "dispatch_case_count": 2,
            "dispatch_cases": ["ber_decode_len(buf, len);", "ber_decode_tag(buf, len);"],
            "api_harness": True,
            "api_cases": [
                {"selector": 0, "kind": "single", "calls": ["ber_decode_len"], "slots": [], "rest": None, "entry": "ber_decode_len"},
                {"selector": 1, "kind": "single", "calls": ["ber_decode_tag"], "slots": [], "rest": None, "entry": "ber_decode_tag"},
            ],
        },
    )
    _write_coverage(
        run_dir,
        "snmp",
        [
            _cov_row("ber_decode_len", "src/snmp/ber.c", 5),
            _cov_row("ber_decode_tag", "src/snmp/ber.c", 8),
            _cov_row("snmp_parse_pdu", "src/snmp/pdu.c", 3),
        ],
    )
    L.cmd_ingest_fuzz([ef_path])
    units = units_by_id(run_dir)
    assert [e["result"] for e in units["src/snmp/ber.c#ber_decode_tag::rte"]["evidence"] if e["phase"] == "fuzz"] == [
        "fuzz_clean"
    ]
    assert [e["result"] for e in units["src/snmp/ber.c#ber_decode_len::rte"]["evidence"] if e["phase"] == "fuzz"] == [
        "fuzz_not_judged"
    ]
    assert [e["result"] for e in units["src/snmp/pdu.c#snmp_parse_pdu::rte"]["evidence"] if e["phase"] == "fuzz"] == [
        "fuzz_not_judged"
    ]
    assert list(V.validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


# ---------------------------------------------------------------------------
# 5. generate_report.py: smoke gate, explore/judge/eacsl-fuzz, circuit breaker
# ---------------------------------------------------------------------------


def test_generate_report_renders_new_sections_and_keeps_legacy_clean(tmp_path: Path) -> None:
    # Part A: Legacy run without smoke/judge/P4/superseded data has NONE of the new sections.
    legacy = tmp_path / "legacy"
    write_json(legacy / "run-metadata.json", metadata("complete", None))
    write_json(
        legacy / "coverage-ledger.json",
        [unit("src/snmp/ber.c", "ber_decode_len", "rte", "covered", evidence=[evidence(tool_output="workspace/reports/eva/snmp.json")])],
    )
    write_json(legacy / "workspace/reports/eva/snmp.json", {})
    write_json(legacy / "workspace/reports/fuzz/snmp.json", {})
    write_json(legacy / "findings.json", [])
    write_json(legacy / "candidates.json", [])

    R.generate(legacy, legacy)
    legacy_md = (legacy / "REPORT.md").read_text(encoding="utf-8")
    assert "### Harness Smoke Gate" not in legacy_md
    assert "### Phase 1 Explore / Judge Breakdown" not in legacy_md
    assert "### Verifier Circuit Breaker" not in legacy_md

    # Part B: Full P3/P4/P5 run renders all three sections cleanly.
    modern = tmp_path / "modern"
    _seed_valid_run_dir(modern)
    # Add a second smoke report with startup_error, partial_blinded explore, batch_state_only judge, and deep eacsl-fuzz.
    write_json(
        modern / "workspace/reports/smoke/cli.json",
        _valid_smoke_report(
            "cli",
            status="startup_error",
            startup_ok=False,
            quarantined=[],
            failing_engine="eacsl",
            startup_reason="abort in __e_acsl_globals_init",
        ),
    )
    write_json(
        modern / "workspace/reports/fuzz/snmp.json",
        _valid_explore_report(
            "snmp",
            status="partial_blinded",
            total_executions=54321,
            max_cov=210,
            blinded_cases=[{"case": 1, "fingerprint": "fp_b", "crashes": 16}],
            partial_blinded=True,
        ),
    )
    write_json(
        modern / "workspace/reports/eacsl-fuzz/snmp.json",
        _valid_explore_report(
            "snmp",
            status="clean",
            mode="eacsl-fuzz",
            discovering_step="eacsl_fuzz",
            engine_used="eacsl",
            total_executions=4200,
            max_cov=95,
            unspent_budget_s=0.0,
        ),
    )
    write_json(
        modern / "workspace/reports/judge/snmp.json",
        _valid_judge_report(
            "snmp",
            status="partial_blinded",
            passed=40,
            failed=16,
            not_judged_breakdown={"blinded": 8},
            blinded_cases=[{"case": 1, "fingerprint": "fp_b", "crashes": 16}],
            partial_blinded=True,
            batch_state_only=[
                {
                    "input": "workspace/corpus/snmp/b1",
                    "sha256": "d" * 64,
                    "case": 0,
                    "batch_failure": None,
                    "batch_fingerprint": None,
                    "standalone_returncode": 0,
                    "standalone_timed_out": False,
                }
            ],
        ),
    )

    R.generate(modern, modern)
    report_md = (modern / "REPORT.md").read_text(encoding="utf-8")

    # 1) Harness Smoke Gate section
    assert "### Harness Smoke Gate" in report_md
    assert "| `snmp` | `degraded` | ok | 1 |" in report_md
    assert "| `cli` | `startup_error` | failed (`eacsl`) |" in report_md
    assert "abort in __e_acsl_globals_init" in report_md

    # 2) Phase 1 Explore / Judge Breakdown section (explore, judge, eacsl_fuzz)
    assert "### Phase 1 Explore / Judge Breakdown" in report_md
    assert "**Explore:**" in report_md
    assert "| `snmp` | `partial_blinded` | 54321 | 210 | partial: 1 |" in report_md
    assert "**Judge (E-ACSL):**" in report_md
    assert "| `snmp` | `partial_blinded` | 56 | 16 | 8 | 1 | partial: 1 |" in report_md
    assert "**E-ACSL Fuzz (`deep`):**" in report_md
    assert "| `snmp` | `clean` | 4200 | 95 | 0.0 |" in report_md

    # 3) Verifier Circuit Breaker section
    assert "### Verifier Circuit Breaker" in report_md
    assert "1 candidate(s) (vs. 0 verified candidate(s))" in report_md
    assert "`snmp`: 1 superseded: harness repaired" in report_md
