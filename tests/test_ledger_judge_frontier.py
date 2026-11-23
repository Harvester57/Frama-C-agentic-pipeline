"""Unit tests for W2-A: granular E-ACSL frontier ledger credit and pure-harness auto-rejection."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import crash_replay
import failure_identity as FI
import ledger as L
import run_eacsl_fuzz as RF
import sandbox_exec
import validate_artifacts as V
import wp_scheduler as S
from conftest import write_json
from fingerprint import make_fingerprint
from sandbox_exec import SandboxResult
from test_ledger import load, seed, units_by_id

pytestmark = pytest.mark.unit

HARNESS_DIGEST = "d" * 64

# Verbatim replay log from QCBOR run-1 Case 116 (`seed-17a8a928db558c9c`):
# unguarded memcpy(dst, fuzz_buf + 31, 0) in LLVMFuzzerTestOneInput with zero target frames.
_QCBOR_CASE116_EACSL_LOG = """\
Running: /framac-run/workspace/seeds/libqcbor_a/seed-17a8a928db558c9c
memcpy: unallocated (or insufficient) space in source space
==14== ERROR: libFuzzer: deadly signal
    #0 0x00000046d818 in __sanitizer_print_stack_trace (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x46d818)
    #1 0x0000004403ec in fuzzer::PrintStackTrace() (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x4403ec)
    #2 0x000000425367 in fuzzer::Fuzzer::CrashCallback() (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x425367)
    #3 0x78eefb65bc41 in raise (/lib/x86_64-linux-gnu/libc.so.6+0x3fc41)
    #4 0x00000058cb90 in raise_abort /framac-run/workspace/harnesses/eacsl_share/e-acsl/internals/e_acsl_private_assert.c:26:3
    #5 0x00000058cb90 in private_abort_fail /framac-run/workspace/harnesses/eacsl_share/e-acsl/internals/e_acsl_private_assert.c:43:3
    #6 0x0000005a0dee in validate_allocated_space /framac-run/workspace/harnesses/eacsl_share/e-acsl/libc_replacements/e_acsl_string.c:102:5
    #7 0x0000005a0dee in __e_acsl_builtin_memcpy /framac-run/workspace/harnesses/eacsl_share/e-acsl/libc_replacements/e_acsl_string.c:222:3
    #8 0x00000056739b in LLVMFuzzerTestOneInput /framac-run/workspace/harnesses/fuzz_libqcbor_a.instrumented.c:189684:13
    #9 0x000000426a6a in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x426a6a)
    #10 0x000000440f56 in main (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x440f56)
SUMMARY: libFuzzer: deadly signal
"""

_TARGET_CALLER_EACSL_LOG = """\
Running: /framac-run/workspace/seeds/libqcbor_a/seed-target
memcpy: unallocated (or insufficient) space in source space
==14== ERROR: libFuzzer: deadly signal
    #0 0x00000046d818 in __sanitizer_print_stack_trace (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x46d818)
    #1 0x00000058cb90 in raise_abort /framac-run/workspace/harnesses/eacsl_share/e-acsl/internals/e_acsl_private_assert.c:26:3
    #2 0x0000005a0dee in __e_acsl_builtin_memcpy /framac-run/workspace/harnesses/eacsl_share/e-acsl/libc_replacements/e_acsl_string.c:222:3
    #3 0x000000550120 in __gen_e_acsl_ber_decode_len /framac-run/workspace/harnesses/fuzz_libqcbor_a.instrumented.c:44102:9
    #4 0x00000056739b in LLVMFuzzerTestOneInput /framac-run/workspace/harnesses/fuzz_libqcbor_a.instrumented.c:189684:13
    #5 0x000000440f56 in main (/framac-run/workspace/harnesses/fuzz_libqcbor_a.e-acsl+0x440f56)
SUMMARY: libFuzzer: deadly signal
"""


def _write_coverage(run_dir: Path, module: str, rows: list[dict[str, Any]]) -> None:
    write_json(
        run_dir / f"workspace/reports/coverage/{module}.json",
        {
            "mode": "coverage",
            "module": module,
            "status": "ok",
            "inputs": {"total": 20, "replayed": 20, "failed": 0, "not_replayed": 0, "known_crash": 0},
            "functions": rows,
        },
    )


def _cov_row(function: str, file_path: str, executions: int) -> dict[str, Any]:
    return {
        "function": function,
        "file": file_path,
        "line": 10,
        "executions": executions,
        "regions": {"total": 4, "covered": 4 if executions else 0},
    }


def _write_dispatch_sidecar(run_dir: Path, module: str = "snmp", cases: list[dict[str, Any]] | None = None) -> None:
    api_cases = cases or [
        {
            "selector": 0,
            "kind": "single",
            "calls": ["ber_decode_len"],
            "slots": [],
            "rest": None,
            "entry": "ber_decode_len",
        },
        {
            "selector": 1,
            "kind": "single",
            "calls": ["ber_decode_tag"],
            "slots": [],
            "rest": None,
            "entry": "ber_decode_tag",
        },
    ]
    write_json(
        run_dir / f"workspace/harnesses/harness_{module}.json",
        {
            "module": module,
            "harness_file": f"workspace/harnesses/harness_{module}.c",
            "sources": ["src/snmp/ber.c", "src/snmp/pdu.c"],
            "cppflags": "",
            "entry_fn": "LLVMFuzzerTestOneInput",
            "entry_style": "dispatch",
            "dispatch_case_count": len(api_cases),
            "dispatch_cases": [f"{c['entry']}(buf, len);" for c in api_cases],
            "api_harness": True,
            "api_cases": api_cases,
        },
    )


def _make_judge_report(
    module: str = "snmp",
    *,
    status: str = "clean",
    passed: int = 3768,
    failed: int = 0,
    not_judged_breakdown: dict[str, int] | None = None,
    frontier_total: int | None = None,
    frontier_judged: int | None = None,
    not_judged_by_case: dict[str, int] | None = None,
    frontier_in_inputs_only: bool = False,
    artifacts: list[dict[str, Any]] | None = None,
    blinded_cases: list[dict[str, Any]] | None = None,
    partial_blinded: bool = False,
    dispatch_case_count: int = 2,
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
    mandatory = min(judged, 1177)
    grown_total = max(0, total - mandatory)
    grown_selected = max(0, grown_total - bd["cap"])
    selected = max(0, total - bd["cap"] - bd["smoke_skipped"])
    inputs: dict[str, Any] = {
        "total": total,
        "mandatory": mandatory,
        "grown_total": grown_total,
        "grown_selected": grown_selected,
        "selected": selected,
        "judged": judged,
        "passed": passed,
        "failed": failed,
        "not_judged": not_judged,
        "not_judged_breakdown": bd,
    }
    doc: dict[str, Any] = {
        "schema_version": 1,
        "mode": "judge",
        "module": module,
        "generated_at": "2026-11-22T23:30:00Z",
        "discovering_step": "judge",
        "engine_used": "eacsl",
        "profile": "standard",
        "status": status,
        "binary": f"workspace/build/fuzz_{module}.e-acsl",
        "corpus_cap": 2048,
        "inputs": inputs,
        "not_judged": not_judged,
        "artifacts": list(artifacts or []),
        "batch_state_only": [],
        "cross_engine_links": [],
        "smoke_skipped_cases": [],
        "blinded_cases": list(blinded_cases or []),
        "partial_blinded": partial_blinded,
        "telemetry": {
            "judge_s": 27.0,
            "batch_s": 26.5,
            "confirm_s": 0.5,
            "inputs_per_s": 119.5,
            "batches_run": 16,
            "fresh_confirmations": len(artifacts or []),
        },
        "harness_digest": HARNESS_DIGEST,
        "dispatch_case_count": dispatch_case_count,
        "dispatch_selector": "identity",
    }
    if frontier_total is not None:
        inputs["frontier_total"] = frontier_total
        if not frontier_in_inputs_only:
            doc["frontier_total"] = frontier_total
    if frontier_judged is not None:
        inputs["frontier_judged"] = frontier_judged
        if not frontier_in_inputs_only:
            doc["frontier_judged"] = frontier_judged
    if not_judged_by_case is not None:
        inputs["not_judged_by_case"] = dict(not_judged_by_case)
        if not frontier_in_inputs_only:
            doc["not_judged_by_case"] = dict(not_judged_by_case)
    return doc


def _judge_ev(units: dict[str, dict], cid: str, report_rel: str = "workspace/reports/judge/snmp.json") -> list[dict]:
    return [e for e in units[cid]["evidence"] if e.get("tool_output") == report_rel]


# ---------------------------------------------------------------------------
# (a) Complete coverage frontier with large cap overflow grants E-ACSL credit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("inputs_only", [False, True])
def test_complete_frontier_with_cap_overflow_grants_eacsl_credit(run_dir: Path, inputs_only: bool) -> None:
    seed(run_dir)
    _write_coverage(
        run_dir,
        "snmp",
        [
            _cov_row("ber_decode_len", "src/snmp/ber.c", 142),
            _cov_row("ber_decode_tag", "src/snmp/ber.c", 87),
            _cov_row("snmp_parse_pdu", "src/snmp/pdu.c", 0),
        ],
    )
    report = _make_judge_report(
        "snmp",
        status="clean",
        passed=3768,
        failed=0,
        not_judged_breakdown={"cap": 40240},
        frontier_total=2591,
        frontier_judged=2591,
        not_judged_by_case={"0": 20000, "1": 20240},
        frontier_in_inputs_only=inputs_only,
    )
    assert list(V.validate_judge_report(report, "snmp")) == []

    judge_path = run_dir / "workspace/reports/judge/snmp.json"
    write_json(judge_path, report)
    L.cmd_ingest_judge([judge_path])

    units = units_by_id(run_dir)
    for cid in ("src/snmp/ber.c#ber_decode_len::rte", "src/snmp/ber.c#ber_decode_tag::rte"):
        evs = _judge_ev(units, cid)
        assert [e["result"] for e in evs] == ["fuzz_clean"]
        det = evs[0]["details"]
        assert det["judge_frontier_complete"] is True
        assert det["overflow_not_judged"] == 40240
        assert det["frontier_total"] == 2591
        assert det["frontier_judged"] == 2591
        assert "2591/2591" in evs[0]["summary"]
        assert "40240" in evs[0]["summary"]

    # Unexecuted function still gets fuzz_not_executed, never fuzz_clean.
    pdu_evs = _judge_ev(units, "src/snmp/pdu.c#snmp_parse_pdu::rte")
    assert [e["result"] for e in pdu_evs] == ["fuzz_not_executed"]
    assert list(V.validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


# ---------------------------------------------------------------------------
# (b) Incomplete frontier: per-case not_judged_by_case isolation
# ---------------------------------------------------------------------------


def test_incomplete_frontier_grants_only_fully_judged_reaching_cases(run_dir: Path) -> None:
    seed(run_dir)
    # Case 0 -> ber_decode_len; Case 1 -> ber_decode_tag; snmp_parse_pdu has no reaching case (fail closed).
    _write_dispatch_sidecar(run_dir, "snmp")
    _write_coverage(
        run_dir,
        "snmp",
        [
            _cov_row("ber_decode_len", "src/snmp/ber.c", 50),
            _cov_row("ber_decode_tag", "src/snmp/ber.c", 35),
            _cov_row("snmp_parse_pdu", "src/snmp/pdu.c", 12),
        ],
    )
    report = _make_judge_report(
        "snmp",
        status="clean",
        passed=2000,
        failed=0,
        not_judged_breakdown={"cap": 500},
        frontier_total=2591,
        frontier_judged=2000,
        not_judged_by_case={"0": 500},
    )
    assert list(V.validate_judge_report(report, "snmp")) == []

    judge_path = run_dir / "workspace/reports/judge/snmp.json"
    write_json(judge_path, report)
    L.cmd_ingest_judge([judge_path])

    units = units_by_id(run_dir)
    # Case 0 (ber_decode_len): capped (not_judged_by_case["0"] == 500) -> denied.
    len_evs = _judge_ev(units, "src/snmp/ber.c#ber_decode_len::rte")
    assert [e["result"] for e in len_evs] == ["fuzz_not_judged"]
    assert len_evs[0]["details"]["capped_cases"] == [0]
    assert len_evs[0]["details"]["overflow_not_judged"] == 500
    assert len_evs[0]["details"]["judge_frontier_complete"] is False

    # Case 1 (ber_decode_tag): not_judged_by_case.get("1", 0) == 0 -> granted fuzz_clean!
    tag_evs = _judge_ev(units, "src/snmp/ber.c#ber_decode_tag::rte")
    assert [e["result"] for e in tag_evs] == ["fuzz_clean"]
    assert tag_evs[0]["details"]["overflow_not_judged"] == 500
    assert "judge_frontier_complete" not in tag_evs[0]["details"]

    # Unmapped function (snmp_parse_pdu): fails closed -> fuzz_not_judged.
    pdu_evs = _judge_ev(units, "src/snmp/pdu.c#snmp_parse_pdu::rte")
    assert [e["result"] for e in pdu_evs] == ["fuzz_not_judged"]
    assert pdu_evs[0]["details"]["overflow_not_judged"] == 500
    assert list(V.validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


def test_incomplete_frontier_denies_function_reached_by_both_capped_and_clean_cases(run_dir: Path) -> None:
    seed(run_dir)
    # Both case 0 (capped) and case 1 (clean) call ber_decode_len; only case 1 calls ber_decode_tag.
    _write_dispatch_sidecar(
        run_dir,
        "snmp",
        cases=[
            {
                "selector": 0,
                "kind": "single",
                "calls": ["ber_decode_len"],
                "slots": [],
                "rest": None,
                "entry": "ber_decode_len",
            },
            {
                "selector": 1,
                "kind": "sequence",
                "calls": ["ber_decode_tag", "ber_decode_len"],
                "slots": [],
                "rest": None,
                "entry": "ber_decode_tag",
            },
        ],
    )
    _write_coverage(
        run_dir,
        "snmp",
        [
            _cov_row("ber_decode_len", "src/snmp/ber.c", 50),
            _cov_row("ber_decode_tag", "src/snmp/ber.c", 35),
        ],
    )
    report = _make_judge_report(
        "snmp",
        status="clean",
        passed=100,
        failed=0,
        not_judged_breakdown={"cap": 25},
        frontier_total=120,
        frontier_judged=100,
        not_judged_by_case={"0": 25},
    )
    judge_path = run_dir / "workspace/reports/judge/snmp.json"
    write_json(judge_path, report)
    L.cmd_ingest_judge([judge_path])

    units = units_by_id(run_dir)
    # ber_decode_len is reached by {0, 1} and case 0 is capped -> denied.
    assert [e["result"] for e in _judge_ev(units, "src/snmp/ber.c#ber_decode_len::rte")] == ["fuzz_not_judged"]
    # ber_decode_tag is reached only by {1} which has 0 not_judged -> granted.
    assert [e["result"] for e in _judge_ev(units, "src/snmp/ber.c#ber_decode_tag::rte")] == ["fuzz_clean"]


def test_legacy_cap_report_without_frontier_or_case_map_still_denies_module_wide(run_dir: Path) -> None:
    seed(run_dir)
    _write_coverage(
        run_dir,
        "snmp",
        [
            _cov_row("ber_decode_len", "src/snmp/ber.c", 50),
            _cov_row("ber_decode_tag", "src/snmp/ber.c", 35),
        ],
    )
    report = _make_judge_report(
        "snmp",
        status="clean",
        passed=100,
        failed=0,
        not_judged_breakdown={"cap": 25},
    )
    judge_path = run_dir / "workspace/reports/judge/snmp.json"
    write_json(judge_path, report)
    L.cmd_ingest_judge([judge_path])

    units = units_by_id(run_dir)
    for cid in ("src/snmp/ber.c#ber_decode_len::rte", "src/snmp/ber.c#ber_decode_tag::rte"):
        assert [e["result"] for e in _judge_ev(units, cid)] == ["fuzz_not_judged"]


# ---------------------------------------------------------------------------
# (c) timeout, error, blinded, and judged == 0 still withhold E-ACSL credit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "kwargs", "expected_result"),
    [
        (
            "timeout",
            {
                "status": "partial",
                "passed": 2591,
                "not_judged_breakdown": {"timeout": 1, "cap": 100},
                "frontier_total": 2591,
                "frontier_judged": 2591,
                "not_judged_by_case": {"0": 101},
            },
            "fuzz_not_judged",
        ),
        (
            "timeout_even_if_status_clean",
            {
                "status": "clean",
                "passed": 2591,
                "not_judged_breakdown": {"timeout": 2},
                "frontier_total": 2591,
                "frontier_judged": 2591,
            },
            "fuzz_not_judged",
        ),
        (
            "error",
            {
                "status": "clean",
                "passed": 2591,
                "not_judged_breakdown": {"error": 1},
                "frontier_total": 2591,
                "frontier_judged": 2591,
            },
            "fuzz_not_judged",
        ),
        (
            "blinded",
            {
                "status": "blinded",
                "passed": 0,
                "failed": 16,
                "not_judged_breakdown": {"blinded": 10},
                "blinded_cases": [{"case": 0, "fingerprint": "fp_b", "crashes": 16}],
                "frontier_total": 10,
                "frontier_judged": 10,
            },
            "fuzz_blinded",
        ),
        (
            "judged_zero",
            {
                "status": "clean",
                "passed": 0,
                "failed": 0,
                "not_judged_breakdown": {"cap": 50},
                "frontier_total": 0,
                "frontier_judged": 0,
            },
            "fuzz_not_judged",
        ),
    ],
)
def test_hard_gaps_always_withhold_eacsl_credit(
    run_dir: Path, label: str, kwargs: dict[str, Any], expected_result: str
) -> None:
    seed(run_dir)
    _write_dispatch_sidecar(run_dir, "snmp")
    _write_coverage(
        run_dir,
        "snmp",
        [
            _cov_row("ber_decode_len", "src/snmp/ber.c", 50),
            _cov_row("ber_decode_tag", "src/snmp/ber.c", 35),
        ],
    )
    report = _make_judge_report("snmp", **kwargs)
    assert list(V.validate_judge_report(report, "snmp")) == []

    judge_path = run_dir / "workspace/reports/judge/snmp.json"
    write_json(judge_path, report)
    L.cmd_ingest_judge([judge_path])

    units = units_by_id(run_dir)
    for cid in ("src/snmp/ber.c#ber_decode_len::rte", "src/snmp/ber.c#ber_decode_tag::rte"):
        results = [e["result"] for e in _judge_ev(units, cid)]
        assert results == [expected_result], f"{label}: unexpected results on {cid}: {results}"


# ---------------------------------------------------------------------------
# (d) Pure-harness fault auto-rejection (0 verifier tasks) + run_eacsl_fuzz tagging
# ---------------------------------------------------------------------------


def test_case116_pure_harness_artifact_auto_rejects_with_zero_verifier_tasks(run_dir: Path) -> None:
    seed(run_dir)
    _write_dispatch_sidecar(
        run_dir,
        "snmp",
        cases=[
            {
                "selector": 0,
                "kind": "single",
                "calls": ["ber_decode_len"],
                "slots": [],
                "rest": None,
                "entry": "ber_decode_len",
            },
            {
                "selector": 116,
                "kind": "single",
                "calls": ["ber_decode_tag"],
                "slots": [],
                "rest": None,
                "entry": "ber_decode_tag",
            },
        ],
    )
    _write_coverage(
        run_dir,
        "snmp",
        [
            _cov_row("ber_decode_len", "src/snmp/ber.c", 120),
            _cov_row("ber_decode_tag", "src/snmp/ber.c", 5),
        ],
    )

    seed_path = run_dir / "workspace/seeds/snmp/seed-17a8a928db558c9c"
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    raw = bytes([116]) + b"\x00" * 31
    seed_path.write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()

    failure = FI.parse_runtime_failure(_QCBOR_CASE116_EACSL_LOG)
    assert failure is not None
    assert failure["function"] == "LLVMFuzzerTestOneInput"
    assert failure.get("harness_self_fault") is True
    fp = make_fingerprint(
        failure["file"],
        failure["function"],
        failure["alarm_kind"] or failure["kind"],
        failure["predicate"],
    )

    judge_report = _make_judge_report(
        "snmp",
        status="crash_found",
        passed=3767,
        failed=1,
        not_judged_breakdown={"cap": 40240},
        frontier_total=2591,
        frontier_judged=2591,
        dispatch_case_count=126,
        artifacts=[
            {
                "artifact": seed_path.as_posix(),
                "kind": "crash",
                "sha256": sha,
                "size_bytes": len(raw),
                "case": 116,
                "engine": "eacsl",
                "discovering_step": "judge",
                "reproducible": True,
                "standalone_confirmed": True,
                "returncode": 134,
                "timed_out": False,
                "failure": failure,
                "failure_source": "primary",
                "fingerprint": fp,
                "frames": FI.stack_frames(_QCBOR_CASE116_EACSL_LOG),
                "replay_log_tail": _QCBOR_CASE116_EACSL_LOG[-2000:],
                "harness_self_fault": True,
                "cross_engine_links": [],
                "harness_digest": HARNESS_DIGEST,
                "dispatch_case_count": 126,
                "dispatch_selector": "identity",
            }
        ],
    )
    assert list(V.validate_judge_report(judge_report, "snmp")) == []

    judge_path = run_dir / "workspace/reports/judge/snmp.json"
    write_json(judge_path, judge_report)
    stats = L.cmd_ingest_judge([judge_path])

    assert stats["auto_rejected_harness_faults"] == 1
    assert stats["candidates"] == 0
    assert len(stats["repair_hints"]) == 1
    hint = stats["repair_hints"][0]
    assert hint["case"] == 116
    assert hint["fingerprint"] == fp
    assert hint["rejection_class"] == "harness_induced"
    assert hint["evidence_basis"] == "pure_harness_stack_frame"
    assert "harness_snmp.c" in hint["hint"]
    assert "dispatch case 116" in hint["hint"]

    # findings.json carries the auto-rejected verdict record directly.
    findings = load(run_dir / "findings.json")
    assert len(findings) == 1
    rec = findings[0]
    assert rec["verdict"] == "rejected"
    assert rec["fingerprint"] == fp
    assert rec["rejection_class"] == "harness_induced"
    assert rec["evidence_basis"] == "pure_harness_stack_frame"
    assert rec["refutation_basis"] == "checked"
    assert "harness_snmp.c" in rec["repair_hint"]
    assert rec["linked_units"] == []
    assert rec["verifier"]["agent_id"] == "pre_triage"

    # candidates.json marks the candidate verified -> 0 unverified candidates.
    cands = load(run_dir / "candidates.json")
    assert len(cands) == 1
    assert cands[0]["fingerprint"] == fp
    assert cands[0]["status"] == "verified"
    assert cands[0]["resolved_fingerprints"] == [fp]
    assert L.cmd_summary()["candidates_unverified"] == 0

    # wp_scheduler queues 0 pending verifier tasks.
    sched_state: dict[str, Any] = S._empty_state()
    ctx = S.Ctx()
    S._sync(sched_state, ctx, persist=False)
    verify_tasks = [t for t in sched_state["tasks"].values() if t["kind"] == "verify"]
    assert verify_tasks == []

    # Case 0 (ber_decode_len) was clean with complete frontier -> granted fuzz_clean;
    # Case 116 (ber_decode_tag) hit harness_self_fault -> gets harness_self_fault_rejected, NOT fuzz_clean.
    units = units_by_id(run_dir)
    len_evs = _judge_ev(units, "src/snmp/ber.c#ber_decode_len::rte")
    assert [e["result"] for e in len_evs] == ["fuzz_clean"]
    assert len_evs[0]["details"]["judge_frontier_complete"] is True
    assert len_evs[0]["details"]["overflow_not_judged"] == 40240

    tag_evs = _judge_ev(units, "src/snmp/ber.c#ber_decode_tag::rte")
    assert [e["result"] for e in tag_evs] == ["harness_self_fault_rejected"]
    assert tag_evs[0]["details"]["rejection_class"] == "harness_induced"
    assert tag_evs[0]["details"]["evidence_basis"] == "pure_harness_stack_frame"
    assert tag_evs[0]["details"]["repair_hints"]

    # Full run-dir artifact validation passes with 0 errors.
    assert list(V.validate_findings(findings, run_dir)) == []
    assert list(V.validate_candidates(cands)) == []
    assert list(V.validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


def test_explore_pure_harness_fault_auto_rejects_even_without_explicit_flag(run_dir: Path) -> None:
    """`cmd_ingest_fuzz` auto-rejects pure-harness explore artifacts (both tagged and via
    `is_pure_harness_crash(failure, frames)` fallback) with 0 pending verifier tasks.
    """
    seed(run_dir)
    crash = run_dir / "workspace/crashes/snmp/crash-case116"
    crash.parent.mkdir(parents=True, exist_ok=True)
    raw = bytes([116]) + b"\x00" * 31
    crash.write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()

    pred = "memcpy: unallocated (or insufficient) space in source space"
    failure: dict[str, Any] = {
        "file": "unknown",
        "line": 0,
        "function": "LLVMFuzzerTestOneInput",
        "kind": "eacsl_libc_error",
        "alarm_kind": "mem_access",
        "is_rte": True,
        "predicate": pred,
    }
    fp = make_fingerprint("unknown", "LLVMFuzzerTestOneInput", "mem_access", pred)
    fuzz_report = {
        "mode": "campaign",
        "module": "snmp",
        "status": "crash_found",
        "engine_used": "eacsl",
        "discovering_step": "explore",
        "harness_digest": HARNESS_DIGEST,
        "artifacts": [
            {
                "artifact": crash.as_posix(),
                "kind": "crash",
                "sha256": sha,
                "size_bytes": len(raw),
                "case": 116,
                "reproducible": True,
                "failure": failure,
                "fingerprint": fp,
                "frames": FI.stack_frames(_QCBOR_CASE116_EACSL_LOG),
            }
        ],
    }
    assert list(V.validate_fuzz_report(fuzz_report)) == []

    fuzz_path = run_dir / "workspace/reports/fuzz/snmp.json"
    write_json(fuzz_path, fuzz_report)
    stats = L.cmd_ingest_fuzz([fuzz_path])

    assert stats["auto_rejected_harness_faults"] == 1
    assert stats["candidates"] == 0
    assert len(stats["repair_hints"]) == 1
    assert L.cmd_summary()["candidates_unverified"] == 0

    findings = load(run_dir / "findings.json")
    assert len(findings) == 1
    assert findings[0]["verdict"] == "rejected"
    assert findings[0]["rejection_class"] == "harness_induced"
    assert findings[0]["evidence_basis"] == "pure_harness_stack_frame"
    assert findings[0]["repair_hint"]
    assert list(V.validate_findings(findings, run_dir)) == []
    assert list(V.validate_candidates(load(run_dir / "candidates.json"))) == []
    assert list(V.validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []


def test_run_eacsl_fuzz_tags_pure_harness_explore_and_judge_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify run_eacsl_fuzz.py tags pure-harness explore and judge crash artifacts with
    `harness_self_fault: True`, while leaving genuine target crashes untagged.
    """
    # 1. Explore / campaign path (`run_fuzz_campaign`)
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    binary = tmp_path / "fuzz_mod.e-acsl"
    binary.write_bytes(b"#!/bin/sh\nexit 0\n")

    def _fake_campaign_sandbox(cmd: list[str], **_kwargs: Any) -> SandboxResult:
        # LibFuzzer writes a pure-harness crash and a target crash into artifacts_dir.
        (artifacts_dir / "crash-pure").write_bytes(bytes([116]) + b"\x00" * 31)
        (artifacts_dir / "crash-target").write_bytes(bytes([0]) + b"\x01" * 15)
        return SandboxResult(returncode=77, stdout="", stderr="", timed_out=False, sandbox="fake")

    def _fake_replay(_binary: Path, artifact: Path, _scratch: Path, **_kwargs: Any) -> dict[str, Any]:
        log = _QCBOR_CASE116_EACSL_LOG if "pure" in artifact.name else _TARGET_CALLER_EACSL_LOG
        return {
            "reproduced": True,
            "returncode": 134,
            "timed_out": False,
            "failure": FI.parse_runtime_failure(log),
            "link_stub_abort": None,
            "resource_abort": None,
            "out_of_memory": False,
            "sandbox": "fake",
            "seed": 1,
            "log_tail": log[-3000:],
            "frames": FI.stack_frames(log),
        }

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", _fake_campaign_sandbox)
    monkeypatch.setattr(crash_replay, "replay_artifact", _fake_replay)

    explore_res = RF.run_fuzz_campaign(
        binary,
        corpus_dir,
        artifacts_dir,
        max_time=5,
        workers=1,
        jobs=1,
    )
    by_name = {Path(a["artifact"]).name: a for a in explore_res["artifacts"]}
    assert by_name["crash-pure"].get("harness_self_fault") is True
    assert by_name["crash-pure"]["failure"]["function"] == "LLVMFuzzerTestOneInput"
    assert "harness_self_fault" not in by_name["crash-target"]
    assert by_name["crash-target"]["failure"]["function"] == "ber_decode_len"

    explore_report = {
        "mode": "campaign",
        "module": "mod",
        "status": explore_res["status"],
        "engine_used": "eacsl",
        "discovering_step": "explore",
        "artifacts": explore_res["artifacts"],
        "telemetry": explore_res["telemetry"],
    }
    assert list(V.validate_fuzz_report(explore_report)) == []

    # 2. Judge path (`run_judge`)
    judge_corpus = tmp_path / "judge_corpus"
    judge_corpus.mkdir()
    pure_seed = judge_corpus / "seed-pure"
    pure_seed.write_bytes(bytes([116]) + b"\x00" * 31)
    target_seed = judge_corpus / "seed-target"
    target_seed.write_bytes(bytes([0]) + b"\x01" * 15)

    build_json = tmp_path / "mod.build.json"
    build_json.write_text(
        json.dumps(
            {
                "mode": "build",
                "module": "mod",
                "status": "built",
                "engine_used": "eacsl",
                "binary": str(binary),
                "sources": [],
                "binaries": {"eacsl": str(binary), "sanitizers": None},
                "compile": {"returncode": 0, "binary": str(binary), "engine": "eacsl"},
            }
        ),
        encoding="utf-8",
    )

    def _fake_judge_sandbox(cmd: list[str], **_kwargs: Any) -> SandboxResult:
        # First positional path argument after flags is the input being executed in batch_size=1.
        inputs_in_cmd = [arg for arg in cmd[1:] if not arg.startswith("-")]
        assert len(inputs_in_cmd) == 1
        inp = Path(inputs_in_cmd[0])
        if inp.name == "seed-pure":
            log = _QCBOR_CASE116_EACSL_LOG.replace(
                "/framac-run/workspace/seeds/libqcbor_a/seed-17a8a928db558c9c", str(inp)
            )
            return SandboxResult(returncode=134, stdout="", stderr=log, timed_out=False, sandbox="fake")
        log = _TARGET_CALLER_EACSL_LOG.replace("/framac-run/workspace/seeds/libqcbor_a/seed-target", str(inp))
        return SandboxResult(returncode=134, stdout="", stderr=log, timed_out=False, sandbox="fake")

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", _fake_judge_sandbox)

    judge_report = RF.run_judge(
        "mod",
        build_json,
        judge_corpus,
        profile="standard",
        batch_size=1,
        scratch_dir=tmp_path / "judge_scratch",
    )
    assert list(V.validate_judge_report(judge_report, "mod")) == []
    judge_by_name = {Path(a["artifact"]).name: a for a in judge_report["artifacts"]}
    assert judge_by_name["seed-pure"].get("harness_self_fault") is True
    assert judge_by_name["seed-pure"]["failure"]["function"] == "LLVMFuzzerTestOneInput"
    assert "harness_self_fault" not in judge_by_name["seed-target"]
    assert judge_by_name["seed-target"]["failure"]["function"] == "ber_decode_len"


def test_ledger_propagates_frontier_status_when_frontier_merge_failed(run_dir: Path) -> None:
    """When a judge report falls back to uniform cap with `frontier_total == 0` and
    `frontier_status == "timed_out"`, `ledger.py` preserves `frontier_status` on the
    `fuzz_not_judged` evidence so callers see why frontier discovery produced 0 files.
    """
    seed(run_dir)
    _write_coverage(
        run_dir,
        "snmp",
        [
            _cov_row("ber_decode_len", "src/snmp/ber.c", 142),
            _cov_row("ber_decode_tag", "src/snmp/ber.c", 87),
        ],
    )
    report = _make_judge_report(
        "snmp",
        status="clean",
        passed=3283,
        failed=0,
        not_judged_breakdown={"cap": 58419},
        frontier_total=0,
        frontier_judged=0,
        not_judged_by_case={"0": 500, "1": 1200},
    )
    report["frontier_status"] = "timed_out"
    report["frontier_merge"] = {
        "status": "timed_out",
        "returncode": -9,
        "timed_out": True,
        "timeout_s": 202,
        "elapsed_s": 202.1,
        "stage_s": 1.2,
        "staged_locally": True,
        "corpus_files": 60467,
        "merged_files": 0,
        "matched_files": 0,
        "stderr_tail": "MERGE-INNER: slow",
    }
    assert list(V.validate_judge_report(report, "snmp")) == []

    judge_path = run_dir / "workspace/reports/judge/snmp.json"
    write_json(judge_path, report)
    L.cmd_ingest_judge([judge_path])

    units = units_by_id(run_dir)
    evs = _judge_ev(units, "src/snmp/ber.c#ber_decode_len::rte")
    assert len(evs) == 1
    assert evs[0]["result"] == "fuzz_not_judged"
    assert evs[0]["details"]["frontier_status"] == "timed_out"
    assert "frontier_status=timed_out" in evs[0]["summary"]
    assert list(V.validate_ledger(load(run_dir / "coverage-ledger.json"), run_dir)) == []
