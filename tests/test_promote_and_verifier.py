"""Tests for M2 scripts/promote_artifact.py, scripts/ledger.py (ingest-verifier & hypotheses), and scripts/generate_harness.py."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import generate_harness
import ledger
from conftest import (
    FP_EVA,
    FP_PARSE,
    FP_REJ,
    confirmed_record,
    metadata,
    needs_validation_record,
    rejected_record,
    unit,
    write_json,
)
from fingerprint import make_fingerprint
from promote_artifact import (
    MAX_ARTIFACT_BYTES,
    MAX_SEED_BYTES,
    MAX_SEEDS_PER_AGENT,
    PromotionError,
    promote_file,
    promote_seeds,
)
from validate_artifacts import validate_agent_result, validate_run_dir


class TestPromoteArtifact:
    """Tests for safe parent-side promotion from agents/<id>/scratch/."""

    @pytest.mark.parametrize(
        "bad_agent_id,bad_src",
        [
            ("BadUpper", "agents/BadUpper/scratch/a.txt"),
            ("prover-1", "../outside.txt"),
            ("prover-1", "workspace/work/parser.c"),
            ("prover-1", "agents/prover-2/scratch/other.txt"),
            ("prover-1", "agents/prover-1/artifacts/already_promoted.txt"),
        ],
        ids=[
            "uppercase-agent-id",
            "dotdot-traversal",
            "outside-agents-dir",
            "wrong-agent-scratch",
            "not-in-scratch-subdir",
        ],
    )
    def test_promote_file_blocks_outside_scratch_and_traversal(
        self,
        run_dir: Path,
        bad_agent_id: str,
        bad_src: str,
    ) -> None:
        """Paths outside agents/<id>/scratch/ or with unsafe agent IDs are rejected."""
        with pytest.raises(PromotionError):
            promote_file(run_dir, bad_agent_id, bad_src, kind="artifact")

    def test_promote_file_blocks_oversized_seed_and_artifact(self, run_dir: Path) -> None:
        """Seeds exceeding 64 KiB and artifacts exceeding 1 MiB are rejected."""
        scratch = run_dir / "agents" / "breaker-1" / "scratch"
        scratch.mkdir(parents=True)

        big_seed = scratch / "huge_seed.bin"
        big_seed.write_bytes(b"A" * (MAX_SEED_BYTES + 1))
        with pytest.raises(PromotionError, match="exceeds limit"):
            promote_file(run_dir, "breaker-1", "agents/breaker-1/scratch/huge_seed.bin", kind="seed", module="snmp")

        big_art = scratch / "huge.patch"
        big_art.write_bytes(b"B" * (MAX_ARTIFACT_BYTES + 1))
        with pytest.raises(PromotionError, match="exceeds limit"):
            promote_file(run_dir, "breaker-1", "agents/breaker-1/scratch/huge.patch", kind="artifact")

    def test_promote_seeds_content_addressed_and_count_capped(self, run_dir: Path) -> None:
        """Seeds are promoted to workspace/corpus/<mod>/seed-<sha256[:16]> and capped at 32."""
        seeds_dir = run_dir / "agents" / "breaker-1" / "scratch" / "seeds"
        seeds_dir.mkdir(parents=True)

        s1 = seeds_dir / "s1.bin"
        s2 = seeds_dir / "s2_dup.bin"
        s1.write_bytes(b"\x30\x03\x02\x01\x00")
        s2.write_bytes(b"\x30\x03\x02\x01\x00")  # identical content -> deduplicated destination

        res = promote_seeds(
            run_dir,
            "breaker-1",
            "snmp",
            [
                "agents/breaker-1/scratch/seeds/s1.bin",
                "agents/breaker-1/scratch/seeds/s2_dup.bin",
            ],
        )
        assert len(res["promoted"]) == 2
        assert res["promoted"][0]["dest"] == res["promoted"][1]["dest"]
        dest_file = run_dir / res["promoted"][0]["dest"]
        assert dest_file.is_file()
        assert dest_file.name.startswith("seed-")

        # Exceeding MAX_SEEDS_PER_AGENT (32) raises PromotionError
        too_many = []
        for idx in range(MAX_SEEDS_PER_AGENT + 1):
            p = seeds_dir / f"extra_{idx}.bin"
            p.write_bytes(f"seed-{idx}".encode())
            too_many.append(f"agents/breaker-1/scratch/seeds/extra_{idx}.bin")
        with pytest.raises(PromotionError, match="too many seeds"):
            promote_seeds(run_dir, "breaker-1", "snmp", too_many)


class TestVerifierIngestionAndHypotheses:
    """Tests for ledger.py ingest-agent-hypothesis and ingest-verifier."""

    def test_ingest_agent_hypothesis_creates_unverified_candidate(self, run_dir: Path) -> None:
        """A breaker or prover with fault_hypothesis creates an unverified candidate in candidates.json."""
        write_json(run_dir / "run-metadata.json", metadata("in_progress"))
        u_rte = unit(
            "src/snmp/ber.c",
            "ber_decode_len",
            "rte",
            status="blocked",
            evidence=[
                {
                    "phase": "wp",
                    "producer": "run_wp_function.py",
                    "result": "wp_unproven",
                    "discharging": False,
                    "tool_output": "workspace/reports/wp/ber_decode_len.json",
                    "summary": "1 unproven goal",
                }
            ],
            unresolved=["unproven mem_access"],
        )
        write_json(run_dir / "coverage-ledger.json", [u_rte])
        write_json(run_dir / "workspace/reports/wp/ber_decode_len.json", {"status": "unproven_goals_remain"})

        seed_path = run_dir / "agents" / "breaker-1" / "scratch" / "seeds" / "s1"
        seed_path.parent.mkdir(parents=True)
        seed_path.write_bytes(b"\x82\xff\xff")

        breaker_res_path = run_dir / "agents" / "breaker-1" / "scratch" / "result.json"
        breaker_res = {
            "role": "breaker",
            "agent_id": "breaker-1",
            "file": "src/snmp/ber.c",
            "function": "ber_decode_len",
            "status": "clean",
            "seeds": ["agents/breaker-1/scratch/seeds/s1"],
            "crash_artifact": None,
            "failing_predicate": None,
            "analysis": "Requires multi-packet session state not set up by single-shot harness.",
            "suggested_requires": None,
            "fault_hypothesis": {
                "input_condition": "Long-form length byte 0x84 with 2-byte payload",
                "predicate": r"\valid_read(buf + off)",
                "why_not_reproduced": "Outer dispatcher drops packets without session cookie.",
            },
        }
        write_json(breaker_res_path, breaker_res)

        out = ledger.cmd_ingest_agent_hypothesis(breaker_res_path, module="snmp")
        assert out["candidates_added"] == 1
        assert len(out["seeds_promoted"]) == 1

        cands = json.loads((run_dir / "candidates.json").read_text(encoding="utf-8"))
        assert len(cands) == 1
        assert cands[0]["status"] == "unverified"
        assert cands[0]["origin"] == "breaker"
        assert cands[0]["proposed_verdict"] == "needs_validation"

        units = json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
        assert units[0]["status"] == "candidate"
        assert cands[0]["fingerprint"] in units[0]["result_fingerprints"]

    def test_ingest_verifier_confirmed_requires_reproducible_replay_and_marks_all_fn_units_candidate(
        self,
        run_dir: Path,
    ) -> None:
        """
        A confirmed verdict:
        1. Promotes reproducer from scratch to workspace/crashes/<mod>/
        2. Verifies parent replay report has reproducible=True for that sha256
        3. Promotes remediation.fix_patch to agents/<id>/artifacts/ without touching workspace/work/
        4. Marks ALL active units of the buggy function (both rte and l2_termination) as candidate
        5. Passes validate_run_dir
        """
        write_json(run_dir / "run-metadata.json", metadata("in_progress"))
        u_rte = unit(
            "src/snmp/ber.c",
            "ber_decode_len",
            "rte",
            status="candidate",
            evidence=[
                {
                    "phase": "fuzz",
                    "producer": "run_eacsl_fuzz.py",
                    "result": "fuzz_failure",
                    "discharging": False,
                    "tool_output": "workspace/reports/fuzz/snmp.json",
                    "summary": "E-ACSL failure",
                }
            ],
            result_fingerprints=[FP_PARSE],
        )
        u_l2 = unit("src/snmp/ber.c", "ber_decode_len", "l2_termination", status="planned")
        write_json(run_dir / "coverage-ledger.json", sorted([u_rte, u_l2], key=lambda u: u["coverage_id"]))

        crash_bytes = b"\x30\x84\xff"
        crash_sha = hashlib.sha256(crash_bytes).hexdigest()
        scratch_crash = run_dir / "agents" / "verifier-1" / "scratch" / "crashes" / "min-crash"
        scratch_crash.parent.mkdir(parents=True)
        scratch_crash.write_bytes(crash_bytes)

        scratch_fix = run_dir / "agents" / "verifier-1" / "scratch" / "ber.fix.patch"
        scratch_fix.write_text(
            "--- a/src/snmp/ber.c\n+++ b/src/snmp/ber.c\n@@ -40 +40 @@\n-if (n > 4)\n+if (n > 4 || off + n > len)\n",
            encoding="utf-8",
        )

        fuzz_report_path = run_dir / "workspace" / "reports" / "fuzz" / "snmp.json"
        write_json(
            fuzz_report_path,
            {
                "module": "snmp",
                "status": "eacsl_violation",
                "artifacts": [
                    {
                        "artifact": "agents/verifier-1/scratch/crashes/min-crash",
                        "sha256": crash_sha,
                        "size_bytes": len(crash_bytes),
                        "reproducible": True,
                        "fingerprint": FP_PARSE,
                    }
                ],
            },
        )

        write_json(
            run_dir / "candidates.json",
            [
                {
                    "fingerprint": FP_PARSE,
                    "status": "unverified",
                    "origin": "fuzz",
                    "proposed_verdict": "confirmed",
                    "module": "snmp",
                    "location": {"file": "src/snmp/ber.c", "line": 42, "function": "ber_decode_len"},
                    "property": {"kind": "mem_access", "predicate": r"\valid_read(buf + off)"},
                    "reproducers": ["agents/verifier-1/scratch/crashes/min-crash"],
                    "tool_outputs": ["workspace/reports/fuzz/snmp.json"],
                    "linked_units": ["src/snmp/ber.c#ber_decode_len::rte"],
                    "first_seen": "2026-10-29T00:00:00+00:00",
                }
            ],
        )

        rec = confirmed_record(FP_PARSE)
        rec["reproducers"] = [
            {
                "input": "agents/verifier-1/scratch/crashes/min-crash",
                "sha256": crash_sha,
                "size_bytes": len(crash_bytes),
                "command": "fuzz_snmp min-crash",
                "observed_result": "E-ACSL: mem_access failed at ber.c:42",
            }
        ]
        rec["remediation"]["fix_patch"] = "agents/verifier-1/scratch/ber.fix.patch"

        verifier_res_path = run_dir / "agents" / "verifier-1" / "scratch" / "verifier_result.json"
        write_json(
            verifier_res_path,
            {
                "role": "crash_verifier",
                "agent_id": "verifier-1",
                "candidate_fingerprint": FP_PARSE,
                "decision": "confirmed",
                "refingerprint_reason": None,
                "record": rec,
            },
        )

        out = ledger.cmd_ingest_verifier(verifier_res_path, replay_reports=[fuzz_report_path])
        assert out["decision"] == "confirmed"

        findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
        assert len(findings) == 1
        f0 = findings[0]
        assert f0["verdict"] == "confirmed"
        assert f0["reproducers"][0]["input"].startswith("workspace/crashes/snmp/crash-")
        assert f0["remediation"]["fix_patch"].startswith("agents/verifier-1/artifacts/")
        assert (run_dir / f0["remediation"]["fix_patch"]).is_file()
        assert set(f0["linked_units"]) == {
            "src/snmp/ber.c#ber_decode_len::rte",
            "src/snmp/ber.c#ber_decode_len::l2_termination",
        }

        units = {
            u["coverage_id"]: u for u in json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
        }
        assert units["src/snmp/ber.c#ber_decode_len::rte"]["status"] == "candidate"
        assert units["src/snmp/ber.c#ber_decode_len::l2_termination"]["status"] == "candidate"
        assert FP_PARSE in units["src/snmp/ber.c#ber_decode_len::l2_termination"]["result_fingerprints"]

        assert validate_run_dir(run_dir) == []

    def test_ingest_verifier_rejects_unreproduced_confirmed_verdict(self, run_dir: Path) -> None:
        """A confirmed verdict whose reproducer sha256 was not reproduced in any parent fuzz report fails."""
        write_json(run_dir / "run-metadata.json", metadata("in_progress"))
        u_rte = unit(
            "src/snmp/ber.c",
            "ber_decode_len",
            "rte",
            status="candidate",
            evidence=[
                {
                    "phase": "fuzz",
                    "producer": "run_eacsl_fuzz.py",
                    "result": "fuzz_failure",
                    "discharging": False,
                    "tool_output": "workspace/reports/fuzz/snmp.json",
                    "summary": "E-ACSL failure",
                }
            ],
            result_fingerprints=[FP_PARSE],
        )
        write_json(run_dir / "coverage-ledger.json", [u_rte])
        write_json(run_dir / "workspace/reports/fuzz/snmp.json", {"module": "snmp", "status": "clean", "artifacts": []})

        crash_bytes = b"\x00\x01"
        crash_sha = hashlib.sha256(crash_bytes).hexdigest()
        crash_file = run_dir / "workspace" / "crashes" / "snmp" / "crash-unrep"
        crash_file.parent.mkdir(parents=True)
        crash_file.write_bytes(crash_bytes)

        write_json(
            run_dir / "candidates.json",
            [
                {
                    "fingerprint": FP_PARSE,
                    "status": "unverified",
                    "origin": "fuzz",
                    "proposed_verdict": "confirmed",
                    "module": "snmp",
                    "location": {"file": "src/snmp/ber.c", "line": 42, "function": "ber_decode_len"},
                    "property": {"kind": "mem_access", "predicate": r"\valid_read(buf + off)"},
                    "reproducers": ["workspace/crashes/snmp/crash-unrep"],
                    "tool_outputs": ["workspace/reports/fuzz/snmp.json"],
                    "linked_units": ["src/snmp/ber.c#ber_decode_len::rte"],
                    "first_seen": "2026-10-29T00:00:00+00:00",
                }
            ],
        )

        rec = confirmed_record(FP_PARSE)
        rec["reproducers"] = [
            {
                "input": "workspace/crashes/snmp/crash-unrep",
                "sha256": crash_sha,
                "size_bytes": len(crash_bytes),
                "command": "fuzz_snmp crash-unrep",
                "observed_result": "E-ACSL: mem_access",
            }
        ]
        verifier_res_path = run_dir / "agents" / "verifier-1" / "scratch" / "res.json"
        write_json(
            verifier_res_path,
            {
                "role": "crash_verifier",
                "agent_id": "verifier-1",
                "candidate_fingerprint": FP_PARSE,
                "decision": "confirmed",
                "refingerprint_reason": None,
                "record": rec,
            },
        )

        with pytest.raises(ledger.LedgerError, match="reproducible"):
            ledger.cmd_ingest_verifier(verifier_res_path, replay_reports=[])

    def test_ingest_verifier_harness_induced_returns_units_to_planned_until_cap(self, run_dir: Path) -> None:
        """
        First harness_induced rejection returns unit from candidate to planned and records fp in attempts;
        when harness repair_attempts >= 2, module units transition to blocked.
        """
        write_json(run_dir / "run-metadata.json", metadata("in_progress"))
        notes_scratch = run_dir / "agents" / "verifier-3" / "scratch" / "notes.txt"
        notes_scratch.parent.mkdir(parents=True)
        notes_scratch.write_text("Harness passed uninitialized ctx pointer.", encoding="utf-8")

        u_tag = unit(
            "src/snmp/ber.c",
            "ber_decode_tag",
            "rte",
            status="candidate",
            evidence=[
                {
                    "phase": "fuzz",
                    "producer": "run_eacsl_fuzz.py",
                    "result": "fuzz_failure",
                    "discharging": False,
                    "tool_output": "workspace/reports/fuzz/snmp.json",
                    "summary": "E-ACSL failure",
                }
            ],
            result_fingerprints=[FP_REJ],
        )
        write_json(run_dir / "coverage-ledger.json", [u_tag])
        write_json(run_dir / "workspace/reports/fuzz/snmp.json", {"status": "eacsl_violation"})
        write_json(
            run_dir / "candidates.json",
            [
                {
                    "fingerprint": FP_REJ,
                    "status": "unverified",
                    "origin": "fuzz",
                    "proposed_verdict": "confirmed",
                    "module": "snmp",
                    "location": {"file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag"},
                    "property": {"kind": "mem_access", "predicate": r"\valid_read(p)"},
                    "reproducers": [],
                    "tool_outputs": ["workspace/reports/fuzz/snmp.json"],
                    "linked_units": ["src/snmp/ber.c#ber_decode_tag::rte"],
                    "first_seen": "2026-10-29T00:00:00+00:00",
                }
            ],
        )

        harness_meta_path = run_dir / "workspace" / "harnesses" / "harness_snmp.json"
        write_json(
            harness_meta_path,
            {
                "module": "snmp",
                "repair_attempts": 1,
                "max_repair_attempts": 2,
            },
        )

        rej = rejected_record(FP_REJ)
        rej["evidence"] = [
            {"phase": "verifier", "tool_output": "agents/verifier-3/scratch/notes.txt", "description": "Harness bug."}
        ]
        res_path = run_dir / "agents" / "verifier-3" / "scratch" / "res.json"
        write_json(
            res_path,
            {
                "role": "crash_verifier",
                "agent_id": "verifier-3",
                "candidate_fingerprint": FP_REJ,
                "decision": "rejected",
                "refingerprint_reason": None,
                "record": rej,
            },
        )

        # Attempt 1 (< 2): unit returns to planned, fp moved to attempts
        ledger.cmd_ingest_verifier(res_path, harness_meta_path=harness_meta_path)
        units = json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
        assert units[0]["status"] == "planned"
        assert units[0]["result_fingerprints"] == []
        assert any(FP_REJ in a.get("result_fingerprints", []) for a in units[0]["attempts"])
        assert validate_run_dir(run_dir) == []

        # Attempt 2 (== max_repair_attempts): re-mark candidate, set repair_attempts=2, ingest again -> blocked
        units[0]["status"] = "candidate"
        units[0]["result_fingerprints"] = [FP_REJ]
        write_json(run_dir / "coverage-ledger.json", units)
        cands = json.loads((run_dir / "candidates.json").read_text(encoding="utf-8"))
        cands[0]["status"] = "unverified"
        write_json(run_dir / "candidates.json", cands)
        write_json(run_dir / "findings.json", [])
        write_json(harness_meta_path, {"module": "snmp", "repair_attempts": 2, "max_repair_attempts": 2})

        ledger.cmd_ingest_verifier(res_path, harness_meta_path=harness_meta_path)
        units2 = json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
        assert units2[0]["status"] == "blocked"
        assert any("harness_repair_exhausted" in r for r in units2[0]["unresolved"])
        assert validate_run_dir(run_dir) == []

    def test_ingest_verifier_refingerprint_and_split(self, run_dir: Path) -> None:
        """A candidate with an unknown_function fingerprint can be split and refingerprinted into two findings."""
        write_json(run_dir / "run-metadata.json", metadata("in_progress"))
        u1 = unit("src/snmp/ber.c", "ber_decode_len", "rte", status="planned")
        u2 = unit("src/log/emit.c", "emit_field", "rte", status="planned")
        write_json(run_dir / "coverage-ledger.json", sorted([u1, u2], key=lambda u: u["coverage_id"]))
        write_json(run_dir / "workspace/reports/eva/log.json", {"status": "ok"})
        write_json(run_dir / "agents/verifier-3/artifacts/notes.txt", {"notes": "ok"})

        fp_raw = "harness_snmp.c#unknown_function::unparsed_crash::0123456789"
        write_json(
            run_dir / "candidates.json",
            [
                {
                    "fingerprint": fp_raw,
                    "status": "unverified",
                    "origin": "fuzz",
                    "proposed_verdict": "needs_validation",
                    "module": "snmp",
                    "location": {"file": "harness_snmp.c", "line": 0, "function": "unknown_function"},
                    "property": {"kind": "crash", "predicate": ""},
                    "reproducers": [],
                    "tool_outputs": ["workspace/reports/eva/log.json"],
                    "linked_units": [],
                    "first_seen": "2026-10-29T00:00:00+00:00",
                }
            ],
        )

        rec1 = needs_validation_record(FP_EVA)
        rec2 = rejected_record(FP_REJ)
        rec2["linked_units"] = ["src/snmp/ber.c#ber_decode_len::rte"]

        res_obj = {
            "role": "crash_verifier",
            "agent_id": "verifier-2",
            "candidate_fingerprint": fp_raw,
            "decision": "needs_validation",
            "refingerprint_reason": "Triaged unknown_function crash into emit_field overflow and rejected ber_decode_len false alarm.",
            "record": rec1,
            "additional_records": [rec2],
        }
        assert validate_agent_result(res_obj) == []

        res_path = run_dir / "agents" / "verifier-2" / "scratch" / "split_res.json"
        write_json(res_path, res_obj)

        ledger.cmd_ingest_verifier(res_path)
        cands = json.loads((run_dir / "candidates.json").read_text(encoding="utf-8"))
        assert cands[0]["status"] == "verified"
        assert set(cands[0]["resolved_fingerprints"]) == {FP_EVA, FP_REJ}
        assert cands[0]["refingerprint_reason"] is not None

        findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
        assert {f["fingerprint"] for f in findings} == {FP_EVA, FP_REJ}
        assert validate_run_dir(run_dir) == []


class TestHarnessLegitimacyAndMetadata:
    """Tests for exact-size buffer allocation and harness metadata sidecars."""

    def test_generate_harness_exact_size_and_sidecar_json(self, tmp_path: Path) -> None:
        """generate_module_harness emits malloc(size) + size==0 sentinel in C and harness_<mod>.json sidecar."""
        out_dir = tmp_path / "harnesses"
        meta = generate_harness.generate_module_harness(
            module_name="snmpv3",
            sources=["src/snmp/pdu.c", "src/snmp/ber.c"],
            header_include="snmp/pdu.h",
            entry_fn="snmp_parse_pdu",
            max_input_size=1500,
            cppflags="-Isrc",
            out_dir=out_dir,
            reachability="untrusted_surface",
            contract_notes=["buf must be valid for size bytes"],
        )

        harness_c = (out_dir / "harness_snmpv3.c").read_text(encoding="utf-8")
        # 1. Exact-size malloc + free in LLVMFuzzerTestOneInput
        assert "malloc(size > 0 ? size : 1U)" in harness_c
        assert "free(alloc_ptr);" in harness_c
        # 2. Allows size == 0 with non-NULL zero-valid-bytes pointer (alloc_ptr + 1)
        assert "(size > 0) ? alloc_ptr : (alloc_ptr + 1)" in harness_c
        # 3. eva_main initializes only input_len bytes, not MAX_INPUT_SIZE
        assert "Frama_C_make_unknown((char *)input_buf, input_len);" in harness_c

        sidecar = out_dir / "harness_snmpv3.json"
        assert sidecar.is_file()
        sidecar_data = json.loads(sidecar.read_text(encoding="utf-8"))
        assert sidecar_data["module"] == "snmpv3"
        assert sidecar_data["entry_fn"] == "snmp_parse_pdu"
        assert sidecar_data["reachability"] == "untrusted_surface"
        assert sidecar_data["repair_attempts"] == 0
        assert sidecar_data["max_repair_attempts"] == 2
        assert meta["harness_meta"] == str(sidecar)

        # Record 2 repairs and verify exhaustion flag
        r1 = generate_harness.record_harness_repair(sidecar, "initialize pdu struct")
        assert r1["repair_attempts"] == 1
        assert r1["exhausted"] is False

        r2 = generate_harness.record_harness_repair(sidecar, "bound max_pdu_len")
        assert r2["repair_attempts"] == 2
        assert r2["exhausted"] is True

    def test_generate_harness_entry_styles_and_include_source(self, tmp_path: Path) -> None:
        """Tests global_buffer, struct_arg, void_call entry styles and --include-source for static entry functions."""
        out_dir = tmp_path / "harnesses_styles"

        # 1. global_buffer + include_source + stubbed_callees
        generate_harness.generate_module_harness(
            module_name="sync",
            sources=["src/SyncMem.c"],
            header_include="SyncMem.h",
            entry_fn="UpdateSyncMem",
            max_input_size=1500,
            cppflags="-Isrc",
            out_dir=out_dir,
            entry_style="global_buffer",
            global_buf="g_rx_buf",
            global_len="g_rx_len",
            include_source=True,
            stubbed_callees=["SendCommand"],
        )
        sync_c = (out_dir / "harness_sync.c").read_text(encoding="utf-8")
        assert '#include "SyncMem.c"' in sync_c
        assert "memcpy((void *)g_rx_buf, input_buf, input_len);" in sync_c
        assert "memcpy((void *)g_rx_buf, bounded_buf, size);" in sync_c
        assert "g_rx_len = input_len;" in sync_c
        assert "UpdateSyncMem();" in sync_c
        sync_meta = json.loads((out_dir / "harness_sync.json").read_text(encoding="utf-8"))
        assert sync_meta["entry_style"] == "global_buffer"
        assert sync_meta["stubbed_callees"] == ["SendCommand"]

        # 2. struct_arg
        generate_harness.generate_module_harness(
            module_name="msg",
            sources=["src/PtfMsg.c"],
            header_include="PtfMsg.h",
            entry_fn="CheckMessageValidity",
            max_input_size=1500,
            cppflags="-Isrc",
            out_dir=out_dir,
            entry_style="struct_arg",
            struct_type="T_PtfMsg",
        )
        msg_c = (out_dir / "harness_msg.c").read_text(encoding="utf-8")
        assert "T_PtfMsg target_arg;" in msg_c
        assert "CheckMessageValidity(&target_arg);" in msg_c
        assert "Frama_C_make_unknown((char *)&target_arg, sizeof(target_arg));" in msg_c

        # 3. Header path normalization + extra_includes + custom call_expr + null_terminate
        res_ev = generate_harness.generate_module_harness(
            module_name="events",
            sources=["workspace/work/src/LibPtfCom/Events.c"],
            header_include="workspace/work/src/LibPtfCom/Events.h",
            entry_fn="SendEvent",
            max_input_size=1500,
            cppflags="-Iworkspace/stubs",
            out_dir=out_dir,
            entry_style="custom",
            extra_includes=["workspace/work/src/LibPtfCom/CmdHandler.h"],
            call_expr='SendEvent("TEST_EVT", "harness", 0, "%s", (char *)fuzz_buf);',
            null_terminate=True,
        )
        ev_c = (out_dir / "harness_events.c").read_text(encoding="utf-8")
        assert '#include "Events.h"' in ev_c
        assert '#include "CmdHandler.h"' in ev_c
        assert "workspace/work/src/LibPtfCom/Events.h" not in ev_c
        assert "-Iworkspace/work/src/LibPtfCom" in res_ev["cppflags"]
        assert "cstr_buf[size] = 0;" in ev_c
        assert 'SendEvent("TEST_EVT", "harness", 0, "%s", (char *)fuzz_buf);' in ev_c
        assert "#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)" in ev_c

    def test_deferred_unit_promotion_scaffold_verifier_and_close_remaining(self, run_dir: Path) -> None:
        """
        Verifies run-3 ledger workflows:
        1. A Tier 3 unit seeded as 'deferred' cleanly promotes to 'candidate' when reached by a crash.
        2. scaffold-verifier builds a schema-valid crash_verifier result (with refingerprinting).
        3. close-remaining transitions planned units with evidence to 'blocked' and without evidence to 'deferred'.
        """
        write_json(run_dir / "run-metadata.json", metadata("in_progress"))
        u_tier3_def = unit(
            "src/LibPtfCom/Events.c",
            "SendEvent",
            "rte",
            status="deferred",
            module="events",
            tier="Tier 3 (Internal Glue)",
            unresolved=["tier3_not_scheduled"],
        )
        u_with_ev = unit(
            "src/LibPtfCom/SyncMem.c",
            "ReadSyncMem",
            "rte",
            status="planned",
            module="syncmem",
            evidence=[
                {
                    "phase": "eva",
                    "producer": "run_eva_slice.py",
                    "result": "eva_unknown",
                    "discharging": False,
                    "tool_output": "workspace/reports/eva/syncmem.json",
                    "summary": "2 unknown RTE obligations",
                }
            ],
        )
        u_untouched = unit(
            "src/LibPtfCom/SyncMem.c",
            "InitSyncMem",
            "rte",
            status="planned",
            module="syncmem",
        )
        write_json(
            run_dir / "coverage-ledger.json",
            sorted([u_tier3_def, u_with_ev, u_untouched], key=lambda u: u["coverage_id"]),
        )
        write_json(run_dir / "workspace/reports/eva/syncmem.json", {"status": "ok"})

        crash_bytes = b"ABCD"
        crash_sha = hashlib.sha256(crash_bytes).hexdigest()
        crash_file = run_dir / "workspace" / "crashes" / "events" / "crash-1"
        crash_file.parent.mkdir(parents=True)
        crash_file.write_bytes(crash_bytes)

        cand_fp = make_fingerprint("src/LibPtfCom/Events.c", "unknown_function", "index_bound", "index 5 out of bounds")
        fuzz_report = run_dir / "workspace" / "reports" / "fuzz" / "events.json"
        write_json(
            fuzz_report,
            {
                "module": "events",
                "status": "crash_found",
                "artifacts": [
                    {
                        "artifact": "workspace/crashes/events/crash-1",
                        "sha256": crash_sha,
                        "size_bytes": len(crash_bytes),
                        "reproducible": True,
                        "fingerprint": cand_fp,
                    }
                ],
            },
        )
        write_json(
            run_dir / "candidates.json",
            [
                {
                    "fingerprint": cand_fp,
                    "status": "unverified",
                    "origin": "fuzz",
                    "proposed_verdict": "confirmed",
                    "module": "events",
                    "location": {"file": "src/LibPtfCom/Events.c", "line": 545, "function": "unknown_function"},
                    "property": {"kind": "index_bound", "predicate": "index 5 out of bounds"},
                    "reproducers": ["workspace/crashes/events/crash-1"],
                    "tool_outputs": ["workspace/reports/fuzz/events.json"],
                    "linked_units": [],
                    "first_seen": "2026-10-29T00:00:00+00:00",
                }
            ],
        )

        scaf_path = run_dir / "agents" / "verifier-1" / "scratch" / "res.json"
        scaf_obj = ledger.cmd_scaffold_verifier(
            cand_fp,
            decision="confirmed",
            agent_id="verifier-1",
            file_override="src/LibPtfCom/Events.c",
            fn_override="SendEvent",
            line_override=545,
            out_path=scaf_path,
        )
        assert validate_agent_result(scaf_obj) == []
        assert scaf_obj["refingerprint_reason"] is not None
        # The reproducer command replays on the module's own build, as the fuzz report names it.
        expected_bin = (
            json.loads((run_dir / "workspace/reports/fuzz/events.json").read_text(encoding="utf-8"))
            .get("compile", {})
            .get("binary")
            or "workspace/harnesses/fuzz_events.e-acsl"
        )
        assert scaf_obj["record"]["reproducers"][0]["command"] == (
            "python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py replay --module events "
            f"--inputs workspace/crashes/events/crash-1 --binary {expected_bin}"
        )

        ledger.cmd_ingest_verifier(scaf_path, replay_reports=[fuzz_report])
        close_res = ledger.cmd_close_remaining("quick_profile_wp_not_scheduled")
        assert close_res == {"transitioned_to_blocked": 1, "transitioned_to_deferred": 1}

        write_json(run_dir / "run-metadata.json", metadata("complete"))
        assert validate_run_dir(run_dir) == []

    def test_m2_cli_entrypoints(self, run_dir: Path, tmp_path: Path) -> None:
        """Exercises CLI main() entrypoints of generate_harness, workspace_overlay, promote_artifact, and ledger."""
        import promote_artifact as pa_mod
        import workspace_overlay as wo_mod

        target = tmp_path / "target_cli"
        target.mkdir()
        (target / "mod.c").write_text("int foo(int x) {\n    return x;\n}\n", encoding="utf-8")
        (target / "mod.h").write_text("int foo(int x);\n", encoding="utf-8")

        assert wo_mod.main(["init", "--target", str(target), "--overlay", str(run_dir / "workspace")]) == 0
        assert wo_mod.main(["init-agent", "--run-dir", str(run_dir), "--agent-id", "prover-cli"]) == 0
        assert wo_mod.main(["check-acsl-only", "--overlay", str(run_dir / "workspace")]) == 0

        scratch_c = run_dir / "agents" / "prover-cli" / "scratch" / "work" / "mod.c"
        scratch_c.write_text("/*@ ensures \\result == x; */\nint foo(int x) {\n    return x;\n}\n", encoding="utf-8")
        assert (
            wo_mod.main(
                [
                    "merge-agent",
                    "--run-dir",
                    str(run_dir),
                    "--agent-id",
                    "prover-cli",
                    "--role",
                    "prover",
                    "--file",
                    "mod.c",
                    "--function",
                    "foo",
                    "--header",
                    "mod.h",
                    "--skip-reverify",
                ]
            )
            == 0
        )

        note_file = run_dir / "agents" / "prover-cli" / "scratch" / "note.txt"
        note_file.write_text("verified foo", encoding="utf-8")
        assert (
            pa_mod.main(
                [
                    "--run-dir",
                    str(run_dir),
                    "promote-artifact",
                    "--agent-id",
                    "prover-cli",
                    "--src",
                    "agents/prover-cli/scratch/note.txt",
                ]
            )
            == 0
        )

        assert (
            generate_harness.main(
                [
                    "--module",
                    "mod",
                    "--sources",
                    "mod.c",
                    "--header",
                    "mod.h",
                    "--entry-fn",
                    "foo",
                    "--out-dir",
                    str(run_dir / "workspace" / "harnesses"),
                ]
            )
            == 0
        )
        assert (
            generate_harness.main(
                [
                    "--record-repair",
                    str(run_dir / "workspace" / "harnesses" / "harness_mod.json"),
                    "--reason",
                    "bound input range",
                ]
            )
            == 0
        )

    def test_load_agent_result_json_repairs_unescaped_acsl_backslashes(self, run_dir: Path) -> None:
        """
        Hand-written result.json containing unescaped ACSL backslashes (\\valid_read, \\forall,
        \\false, \\base_addr, \\at) is automatically repaired on load and passes schema validation.
        """
        from framac_common import load_agent_result_json

        res_file = run_dir / "agents" / "prover-esc" / "scratch" / "result.json"
        res_file.parent.mkdir(parents=True)
        # Raw JSON text with unescaped \valid_read (\v -> invalid JSON escape) and \forall/\false (\f -> formfeed)
        raw_bad_json = (
            "{\n"
            '  "role": "prover",\n'
            '  "agent_id": "prover-esc",\n'
            '  "file": "src/snmp/ber.c",\n'
            '  "function": "ber_decode_len",\n'
            '  "status": "stalled_after_k_retries",\n'
            '  "patch": null,\n'
            '  "evidence": [{"tool_output": "workspace/reports/wp/ber.json", "result": "unproven_goals_remain"}],\n'
            '  "unproven_goals": ["rte: mem_access: \\valid_read(buf + i) && \\forall integer k; \\false || \\at(x, Pre) == 0"],\n'
            '  "strengthening_requests": [\n'
            "    {\n"
            '      "callee": "helper_fn",\n'
            '      "callee_file": "src/snmp/helper.c",\n'
            '      "header_file": "src/snmp/helper.h",\n'
            '      "needed_clause": "ensures \\valid(\\result) && \\base_addr(\\result) == \\base_addr(buf);",\n'
            '      "reason": "caller needs pointer validity"\n'
            "    }\n"
            "  ],\n"
            '  "boundary_assumptions": [],\n'
            '  "fault_hypothesis": null\n'
            "}\n"
        )
        res_file.write_text(raw_bad_json, encoding="utf-8")

        loaded = load_agent_result_json(res_file)
        assert r"\valid_read(buf + i)" in loaded["unproven_goals"][0]
        assert r"\forall integer k;" in loaded["unproven_goals"][0]
        assert r"\false" in loaded["unproven_goals"][0]
        assert r"\at(x, Pre)" in loaded["unproven_goals"][0]
        assert r"\valid(\result)" in loaded["strengthening_requests"][0]["needed_clause"]
        assert r"\base_addr(\result)" in loaded["strengthening_requests"][0]["needed_clause"]
        assert validate_agent_result(loaded) == []

    def test_prover_strengthening_requests_auto_ingested_and_run_status_flipped(self, run_dir: Path) -> None:
        """
        1. ingest-agent-hypothesis automatically records prover strengthening_requests into
           workspace/reports/strengthen_requests.json (inferring callee_file when omitted).
        2. Adding an unverified candidate when run_status is 'complete' automatically flips
           run-metadata.json back to 'in_progress'.
        """
        import contract_negotiator

        write_json(run_dir / "run-metadata.json", metadata("complete"))
        u_caller = unit(
            "src/LibPtfCom/SyncMem.c",
            "GetInt",
            "rte",
            status="blocked",
            module="syncmem",
            evidence=[
                {
                    "phase": "wp",
                    "producer": "run_wp_function.py",
                    "result": "wp_unproven",
                    "discharging": False,
                    "tool_output": "workspace/reports/wp/GetInt.json",
                    "summary": "1 unproven goal",
                }
            ],
            unresolved=["unproven index_bound"],
        )
        u_callee = unit(
            "src/LibPtfCom/SyncMem.c",
            "Hash",
            "rte",
            status="covered",
            module="syncmem",
            evidence=[
                {
                    "phase": "wp",
                    "producer": "run_wp_function.py",
                    "result": "wp_all_proved",
                    "discharging": True,
                    "tool_output": "workspace/reports/wp/GetInt.json",
                    "summary": "All goals proved",
                }
            ],
        )
        write_json(
            run_dir / "coverage-ledger.json",
            sorted([u_caller, u_callee], key=lambda u: u["coverage_id"]),
        )
        write_json(run_dir / "workspace/reports/wp/GetInt.json", {"status": "unproven_goals_remain"})

        prover_res_path = run_dir / "agents" / "prover-getint" / "scratch" / "result.json"
        prover_res = {
            "role": "prover",
            "agent_id": "prover-getint",
            "file": "src/LibPtfCom/SyncMem.c",
            "function": "GetInt",
            "status": "stalled_after_k_retries",
            "patch": None,
            "evidence": [{"tool_output": "workspace/reports/wp/GetInt.json", "result": "unproven_goals_remain"}],
            "unproven_goals": ["rte: index_bound: 0 <= HashIndex < 256"],
            "strengthening_requests": [
                {
                    "callee": "Hash",
                    "header_file": "src/LibPtfCom/SyncMem.h",
                    "needed_clause": r"ensures 0 <= \result < MaxValue;",
                    "reason": "GetInt indexes G_HashTable[HashIndex] without checking negative return.",
                }
            ],
            "boundary_assumptions": [],
            "fault_hypothesis": {
                "input_condition": "Name with high-bit bytes causing negative signed char sum in Hash()",
                "predicate": "0 <= HashIndex",
                "why_not_reproduced": "UpdateSyncMem crashes at line 828 before reaching HashTableUpdateInt.",
            },
        }
        write_json(prover_res_path, prover_res)

        out = ledger.cmd_ingest_agent_hypothesis(prover_res_path, module="syncmem")
        assert out["candidates_added"] == 1
        assert out["strengthening_requests_added"] == 1

        # Verify strengthening_requests.json was populated and callee_file was auto-inferred
        req_file = run_dir / "workspace/reports/strengthen_requests.json"
        assert req_file.is_file()
        listed = contract_negotiator.cmd_list(req_file, status_filter="pending")
        assert listed["count"] == 1
        assert listed["requests"][0]["callee_function"] == "Hash"
        assert listed["requests"][0]["callee_file"] == "src/LibPtfCom/SyncMem.c"

        # Verify run-metadata.json was automatically transitioned from 'complete' to 'in_progress'
        meta_after = json.loads((run_dir / "run-metadata.json").read_text(encoding="utf-8"))
        assert meta_after["run_status"] == "in_progress"
        assert validate_run_dir(run_dir) == []

    def test_prepare_agent_renders_brief_and_initializes_overlay(self, run_dir: Path, tmp_path: Path) -> None:
        """workspace_overlay.prepare_agent initializes the agent overlay and renders a populated brief.md."""
        import workspace_overlay as wo_mod

        target = tmp_path / "target_prep"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src/SyncMem.c").write_text(
            "int Hash(const char *Name, int MaxValue) { return 0; }\n", encoding="utf-8"
        )
        (target / "src/SyncMem.h").write_text("int Hash(const char *Name, int MaxValue);\n", encoding="utf-8")

        wo_mod.init_overlay(target, run_dir / "workspace")
        write_json(
            run_dir / "workspace/reports/callgraph_dag.json",
            {
                "functions": {
                    "Hash": {
                        "name": "Hash",
                        "file": "src/SyncMem.c",
                        "module": "syncmem",
                        "wave": 0,
                        "security_properties": [],
                    }
                },
                "modules": {"syncmem": {"tier": "Tier 1"}},
            },
        )
        write_json(
            run_dir / "coverage-ledger.json",
            [unit("src/SyncMem.c", "Hash", "rte", status="planned", module="syncmem")],
        )
        write_json(
            run_dir / "workspace/harnesses/harness_syncmem.json",
            {
                "module": "syncmem",
                "sources": ["workspace/work/src/SyncMem.c", "workspace/stubs/ptf_stubs.c"],
                "header": "src/SyncMem.h",
                "cppflags": "-Iworkspace/work/src",
                "ldflags": "-lbsd",
                "entry_fn": "UpdateSyncMem",
                "reachability": "untrusted_surface",
            },
        )
        stubs_dir = run_dir / "workspace/stubs"
        stubs_dir.mkdir(parents=True, exist_ok=True)
        (stubs_dir / "ptf_stubs.c").write_text("int ptf_stub(void) { return 0; }\n", encoding="utf-8")
        write_json(
            run_dir / "workspace/reports/eva/syncmem.json",
            {
                "status": "ok",
                "unknown_obligations_by_function": {
                    "Hash": [{"kind": "signed_overflow", "line": 42, "annotation": "x + y <= 2147483647"}]
                },
            },
        )

        prep = wo_mod.prepare_agent(
            run_dir=run_dir,
            agent_id="prover-hash",
            role="prover",
            module="syncmem",
            function="Hash",
        )
        assert prep["ok"] is True
        assert prep["file"] == "src/SyncMem.c"
        assert prep["header"] == "src/SyncMem.h"
        # `--ldflags='-lbsd'`: a separate dash-leading value would be rejected by argparse.
        assert "--ldflags='-lbsd'" in prep["merge_command"]
        brief_text = (run_dir / prep["brief_file"]).read_text(encoding="utf-8")
        assert "prover-hash" in brief_text
        assert "Hash" in brief_text
        assert "--ldflags='-lbsd'" in brief_text
        assert "agents/prover-hash/scratch/work/src/SyncMem.c" in brief_text
        assert "workspace/stubs/ptf_stubs.c" in brief_text
        assert "scratch/work/workspace/stubs/ptf_stubs.c" not in brief_text

        # Also test prepare_agent with role="verifier" and candidate_fp
        write_json(
            run_dir / "candidates.json",
            [
                {
                    "fingerprint": r"src/SyncMem.c#GetStr::rte: mem_access: \valid(OutValue)",
                    "module": "syncmem",
                    "status": "unverified",
                }
            ],
        )
        prep_ver = wo_mod.prepare_agent(
            run_dir=run_dir,
            agent_id="verifier-1",
            role="verifier",
            candidate_fp=r"src/SyncMem.c#GetStr::rte: mem_access: \valid(OutValue)",
        )
        assert prep_ver["ok"] is True
        ver_brief = (run_dir / prep_ver["brief_file"]).read_text(encoding="utf-8")
        assert "{candidate_short}" not in ver_brief
        assert "--ldflags='-lbsd'" in ver_brief
        assert "workspace/stubs/ptf_stubs.c" in ver_brief
        assert "workspace/work/workspace/stubs/ptf_stubs.c" not in ver_brief

    def test_load_agent_result_json_repairs_json_dumps_unicode_control_escapes(self, tmp_path: Path) -> None:
        """
        When a subagent uses json.dumps() on a non-raw Python string containing \\valid, \\at,
        \\base_addr, \\forall, or \\false, json.dumps serializes \\x0b as \\u000b and \\x07 as \\u0007.
        load_agent_result_json must repair those back to \\valid, \\at, \\base_addr, \\forall, \\false.
        """
        from framac_common import load_agent_result_json

        # Deliberately non-raw string passed to json.dumps
        non_raw_payload = {
            "clause": "ensures \valid(p) && \valid_read(q) && \at(x, Old) == 0 && \base_addr(p) == \base_addr(q) && \forall integer i; \false == \false;"
        }
        p = tmp_path / "result_unicode_ctrl.json"
        p.write_text(json.dumps(non_raw_payload), encoding="utf-8")
        raw_on_disk = p.read_text(encoding="utf-8")
        assert "\\u000balid" in raw_on_disk
        assert "\\u0007t" in raw_on_disk

        loaded = load_agent_result_json(p)
        assert loaded["clause"] == (
            r"ensures \valid(p) && \valid_read(q) && \at(x, Old) == 0 && "
            r"\base_addr(p) == \base_addr(q) && \forall integer i; \false == \false;"
        )

    def test_generate_harness_auto_prototype_for_internal_api_functions(self, tmp_path: Path) -> None:
        """
        Tests --auto-args / --entry-style=auto_prototype on:
        1. int Hash(const char *Name, int MaxValue)
        2. int GetInt(const char *Name, int *Value)
        3. int ParsePacket(const uint8_t *buf, size_t len, uint16_t flags)
        4. int GetStr(const char *Name, char *OutValue) -> secondary char* gets distinct stack buffer
        5. Static function in .c file preceded by a caller invoking it inside a function body
        """
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        hdr = src_dir / "SyncMem.h"
        hdr.write_text(
            "#ifdef __cplusplus\n"
            'extern "C" {\n'
            "#endif\n"
            '#define CALL_DEFAULT RegisterCallback("x", 0, 0);\n'
            "int Hash(const char *Name, int MaxValue);\n"
            "int GetInt(const char *Name, int *Value);\n"
            "int GetStr(const char *Name, char *OutValue);\n"
            "int ParsePacket(const uint8_t *buf, size_t len, unsigned short flags);\n"
            "int RegisterCallback(const char *Name, int (*cb)(int, int), int Flags) __attribute__((nonnull(1)));\n"
            "const char* DispatchRaw(const uint8_t *, size_t, int (*)(void *), unsigned short, struct Ctx, int x __attribute__((unused)));\n"
            "#ifdef __cplusplus\n"
            "}\n"
            "#endif\n",
            encoding="utf-8",
        )
        c_file = src_dir / "SyncMem.c"
        c_file.write_text(
            "void CallerBeforeDef(int x) {\n"
            "    InternalHelper(x + 1, 42);\n"
            "}\n"
            "static int InternalHelper(const char *Name, int MaxValue) {\n"
            "    return MaxValue;\n"
            "}\n",
            encoding="utf-8",
        )
        out_dir = tmp_path / "harnesses"

        # 1. Hash(const char *Name, int MaxValue) via CLI --auto-args
        rc = generate_harness.main(
            [
                "--module",
                "sync_hash",
                "--sources",
                str(c_file),
                "--header",
                str(hdr),
                "--entry-fn",
                "Hash",
                "--auto-args",
                "--no-auto-prelude",
                "--out-dir",
                str(out_dir),
            ]
        )
        assert rc == 0
        hash_c = (out_dir / "harness_sync_hash.c").read_text(encoding="utf-8")
        hash_meta = json.loads((out_dir / "harness_sync_hash.json").read_text(encoding="utf-8"))
        assert hash_meta["entry_style"] == "auto_prototype"
        assert hash_meta["reachability"] == "internal_api"
        assert hash_meta["null_terminate"] is True
        assert "cstr_buf[size] = 0;" in hash_c
        assert "int arg_1;" in hash_c
        assert "Hash((const char *)(fuzz_buf + fuzz_off), arg_1);" in hash_c

        # 2. GetInt(const char *Name, int *Value)
        res_get = generate_harness.generate_module_harness(
            module_name="sync_getint",
            sources=[str(c_file)],
            header_include=str(hdr),
            entry_fn="GetInt",
            max_input_size=512,
            cppflags=f"-I{src_dir.as_posix()}",
            out_dir=out_dir,
            auto_args=True,
            auto_prelude=False,
        )
        get_c = (out_dir / "harness_sync_getint.c").read_text(encoding="utf-8")
        assert res_get["null_terminate"] is True
        assert res_get["reachability"] == "internal_api"
        assert "int arg_1;" in get_c
        assert "GetInt((const char *)(fuzz_buf + fuzz_off), &arg_1);" in get_c

        # 3. ParsePacket(const uint8_t *buf, size_t len, unsigned short flags)
        res_pkt = generate_harness.generate_module_harness(
            module_name="sync_pkt",
            sources=[str(c_file)],
            header_include=str(hdr),
            entry_fn="ParsePacket",
            max_input_size=512,
            cppflags=f"-I{src_dir.as_posix()}",
            out_dir=out_dir,
            auto_args=True,
            auto_prelude=False,
        )
        pkt_c = (out_dir / "harness_sync_pkt.c").read_text(encoding="utf-8")
        assert res_pkt["null_terminate"] is False
        assert "unsigned short arg_2;" in pkt_c
        assert "ParsePacket((const uint8_t *)(fuzz_buf + fuzz_off), (size_t)(fuzz_len - fuzz_off), arg_2);" in pkt_c

        # 4. GetStr(const char *Name, char *OutValue) -> distinct stack buffer for OutValue
        res_str = generate_harness.generate_module_harness(
            module_name="sync_getstr",
            sources=[str(c_file)],
            header_include=str(hdr),
            entry_fn="GetStr",
            max_input_size=512,
            cppflags=f"-I{src_dir.as_posix()}",
            out_dir=out_dir,
            auto_args=True,
            auto_prelude=False,
        )
        str_c = (out_dir / "harness_sync_getstr.c").read_text(encoding="utf-8")
        assert res_str["null_terminate"] is True
        assert "char arg_1[MAX_INPUT_SIZE + 1];" in str_c
        assert "GetStr((const char *)(fuzz_buf + fuzz_off), (char *)arg_1);" in str_c

        # 5. InternalHelper defined in .c after a caller invoking InternalHelper(x + 1, 42);
        params_helper = generate_harness.extract_function_prototype(
            "InternalHelper",
            header_include=str(hdr),
            sources=[str(c_file)],
        )
        assert len(params_helper) == 2
        assert params_helper[0]["type"] == "const char *"
        assert params_helper[1]["type"] == "int"

        # 6. RegisterCallback(const char *Name, int (*cb)(int, int), int Flags) -> nested parens & fn pointer
        params_cb = generate_harness.extract_function_prototype(
            "RegisterCallback",
            header_include=str(hdr),
            sources=[str(c_file)],
        )
        assert len(params_cb) == 3
        assert params_cb[1]["name"] == "cb"
        assert params_cb[1]["type"] == "int (*)(int, int)"
        assert params_cb[1]["is_fn_pointer"] is True
        assert params_cb[2]["name"] == "Flags"
        assert params_cb[2]["type"] == "int"

        res_cb = generate_harness.generate_module_harness(
            module_name="sync_cb",
            sources=[str(c_file)],
            header_include=str(hdr),
            entry_fn="RegisterCallback",
            max_input_size=512,
            cppflags=f"-I{src_dir.as_posix()}",
            out_dir=out_dir,
            auto_args=True,
            auto_prelude=False,
        )
        cb_c = (out_dir / "harness_sync_cb.c").read_text(encoding="utf-8")
        assert res_cb["null_terminate"] is True
        assert "int arg_2;" in cb_c
        assert "RegisterCallback((const char *)fuzz_buf, NULL, arg_2);" in cb_c
        assert "RegisterCallback((const char *)(fuzz_buf + fuzz_off), NULL, arg_2);" in cb_c

        # 7. DispatchRaw: attached pointer return type, unnamed params (size_t, int (*)(void *), unsigned short, struct Ctx), and param __attribute__((unused))
        params_raw = generate_harness.extract_function_prototype(
            "DispatchRaw",
            header_include=str(hdr),
            sources=[str(c_file)],
        )
        assert len(params_raw) == 6
        assert params_raw[0]["type"] == "const uint8_t *"
        assert params_raw[1]["type"] == "size_t"
        assert params_raw[1]["name"] == "arg_1"
        assert params_raw[2]["type"] == "int (*)(void *)"
        assert params_raw[2]["is_fn_pointer"] is True
        assert params_raw[2]["name"] == "arg_2"
        assert params_raw[3]["type"] == "unsigned short"
        assert params_raw[3]["pointee_type"] == "unsigned short"
        assert params_raw[4]["type"] == "struct Ctx"
        assert params_raw[4]["pointee_type"] == "struct Ctx"
        assert params_raw[5]["type"] == "int"
        assert params_raw[5]["name"] == "x"
        assert params_raw[5]["is_fn_pointer"] is False

    def test_run_fuzz_campaign_parallel_workers_and_jobs(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """
        run_fuzz_campaign coordinates -jobs and -workers when either is > 1, scales CPU/wall
        timeouts, and reads worker logs (fuzz-*.log) from the scratch directory.
        """
        import run_eacsl_fuzz as fuzz_mod
        import sandbox_exec as sb_mod

        bin_path = tmp_path / "fuzz_bin"
        bin_path.write_text("", encoding="utf-8")
        corpus_dir = tmp_path / "corpus"
        artifacts_dir = tmp_path / "crashes"

        captured: dict = {}

        def fake_run_sandboxed(cmd, writable, timeout_s, limits=None, extra_env=None):
            captured["cmd"] = list(cmd)
            captured["timeout_s"] = timeout_s
            captured["cpu_seconds"] = limits.cpu_seconds if limits else None
            scratch_dir = writable[0]
            crash_file = artifacts_dir / "crash-deadbeef"
            crash_file.write_bytes(b"ABCD")
            (scratch_dir / "fuzz-0.log").write_text(
                f"Test unit written to {crash_file}\nSUMMARY: AddressSanitizer:Frama-C-E-ACSL\n",
                encoding="utf-8",
            )
            return sb_mod.SandboxResult(returncode=77, stdout="", stderr="", timed_out=False, sandbox="rlimits")

        def fake_replay(binary, input_file, scratch_dir, timeout_s=30, **kwargs):
            # Crash replays use the campaign's fixed per-input timeout.
            captured["replay_per_input_timeout"] = kwargs.get("per_input_timeout")
            return {
                "reproduced": True,
                "reproducible": True,
                "returncode": 77,
                "log_tail": "",
                "failure": {
                    "file": "src/SyncMem.c",
                    "line": 42,
                    "function": "Hash",
                    "kind": "rte: mem_access",
                    "alarm_kind": "rte: mem_access",
                    "predicate": r"\valid(p)",
                    "raw_message": "Assertion failed",
                },
            }

        monkeypatch.setattr(fuzz_mod, "run_sandboxed", fake_run_sandboxed)
        monkeypatch.setattr(fuzz_mod, "replay_artifact", fake_replay)

        report = fuzz_mod.run_fuzz_campaign(
            binary=bin_path,
            corpus_dir=corpus_dir,
            artifacts_dir=artifacts_dir,
            max_time=30,
            workers=4,
            jobs=1,
        )
        assert "-jobs=4" in captured["cmd"]
        assert "-workers=4" in captured["cmd"]
        assert "-rss_limit_mb=2048" in captured["cmd"]  # fixed, whatever the worker count
        assert captured["timeout_s"] == 30 + 180
        assert captured["cpu_seconds"] == (30 + 180) * 5
        assert captured["replay_per_input_timeout"] == 10
        assert report["status"] == "crash_found"
        assert len(report["artifacts"]) == 1

    def test_wp_unsigned_downcast_and_bitwise_retry(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """
        Tests Workstream 3:
        1. scan_wp_log_soundness records '-no-warn-unsigned-downcast' when warn_unsigned_downcast=False.
        2. run_wp_on_function tags unsigned_downcast goals with c11_modulo_candidate=True and
           automatically retries unproven bitwise/shift goals with -wp-model Typed+ref+int.
        """
        import subprocess

        import run_wp_function as wp_mod

        snd = wp_mod.scan_wp_log_soundness("", warn_unsigned_downcast=False)
        assert "-no-warn-unsigned-downcast" in snd["reduced_checks"]

        c_file = tmp_path / "cksum.c"
        c_file.write_text(
            "unsigned short InCksum(unsigned int sum) { return (unsigned short)~(sum >> 16); }\n", encoding="utf-8"
        )
        out_dir = tmp_path / "wp_out"

        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            # The bitwise retry writes its own artifacts (wp_<fn>_retry.*): honor -report-csv.
            csv_file = Path(cmd[cmd.index("-report-csv") + 1]) if "-report-csv" in cmd else out_dir / "wp_InCksum.csv"
            if "-wp" in cmd:
                model_idx = cmd.index("-wp-model") + 1
                model = cmd[model_idx]
                out_dir.mkdir(parents=True, exist_ok=True)
                if model == "Typed":
                    # First attempt under Typed fails on a shift/downcast goal
                    csv_file.write_text(
                        "directory\tfile\tfunction\tline\tkind\tstatus\tproperty\n"
                        ".\tcksum.c\tInCksum\t1\trte: unsigned_downcast\tUnknown\t(sum >> 16) <= 65535\n",
                        encoding="utf-8",
                    )
                else:
                    # Retry under Typed+ref+int discharges the goal!
                    csv_file.write_text(
                        "directory\tfile\tfunction\tline\tkind\tstatus\tproperty\n"
                        ".\tcksum.c\tInCksum\t1\trte: unsigned_downcast\tValid\t(sum >> 16) <= 65535\n",
                        encoding="utf-8",
                    )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(wp_mod.subprocess, "run", fake_run)

        # First test without retry to verify c11_modulo_candidate tagging
        res_no_retry = wp_mod.run_wp_on_function(
            c_file=c_file,
            fn_name="InCksum",
            out_dir=out_dir,
            retry_bitwise=False,
            warn_unsigned_downcast=False,
        )
        assert res_no_retry["status"] == "unproven_goals_remain"
        assert res_no_retry["unproven_goals"][0]["c11_modulo_candidate"] is True
        assert "-no-warn-unsigned-downcast" in res_no_retry["soundness"]["reduced_checks"]

        # Now test with retry_bitwise=True -> automatically retries with Typed+ref+int and proves the goal
        res_retry = wp_mod.run_wp_on_function(
            c_file=c_file,
            fn_name="InCksum",
            out_dir=out_dir,
            retry_bitwise=True,
        )
        assert res_retry["status"] == "all_proven"
        assert res_retry["bitwise_retry"]["triggered"] is True
        assert res_retry["bitwise_retry"]["wp_model"] == "Typed+ref+int"
        assert res_retry["bitwise_retry"]["timeout"] == 30

    def test_ingest_verifier_disproved_by_source_parks_to_blocked(self, run_dir: Path) -> None:
        """
        When a verifier rejects a candidate with disproved_by_source, the linked unit
        parks to 'blocked' with rejection reason instead of returning to 'planned'.
        """
        write_json(run_dir / "run-metadata.json", metadata("in_progress"))
        notes_scratch = run_dir / "agents" / "verifier-4" / "scratch" / "notes.txt"
        notes_scratch.parent.mkdir(parents=True)
        notes_scratch.write_text("Source inspect proves loop counter cannot exceed buffer bound.", encoding="utf-8")

        u_tag = unit(
            "src/snmp/ber.c",
            "ber_decode_tag",
            "rte",
            status="candidate",
            evidence=[
                {
                    "phase": "fuzz",
                    "producer": "run_eacsl_fuzz.py",
                    "result": "fuzz_failure",
                    "discharging": False,
                    "tool_output": "workspace/reports/fuzz/snmp.json",
                    "summary": "E-ACSL failure",
                }
            ],
            result_fingerprints=[FP_REJ],
        )
        write_json(run_dir / "coverage-ledger.json", [u_tag])
        write_json(run_dir / "workspace/reports/fuzz/snmp.json", {"status": "eacsl_violation"})
        write_json(
            run_dir / "candidates.json",
            [
                {
                    "fingerprint": FP_REJ,
                    "status": "unverified",
                    "origin": "fuzz",
                    "proposed_verdict": "confirmed",
                    "module": "snmp",
                    "location": {"file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag"},
                    "property": {"kind": "mem_access", "predicate": r"\valid_read(p)"},
                    "reproducers": [],
                    "tool_outputs": ["workspace/reports/fuzz/snmp.json"],
                    "linked_units": ["src/snmp/ber.c#ber_decode_tag::rte"],
                    "first_seen": "2026-10-29T00:00:00+00:00",
                }
            ],
        )

        rej = rejected_record(FP_REJ)
        rej["rejection_class"] = "disproved_by_source"
        rej["reason"] = "Loop counter bound guarantees safety."
        rej["evidence"] = [
            {
                "phase": "verifier",
                "tool_output": "agents/verifier-4/scratch/notes.txt",
                "description": "Manual proof in source.",
            }
        ]
        res_path = run_dir / "agents" / "verifier-4" / "scratch" / "res.json"
        write_json(
            res_path,
            {
                "role": "crash_verifier",
                "agent_id": "verifier-4",
                "candidate_fingerprint": FP_REJ,
                "decision": "rejected",
                "refingerprint_reason": None,
                "record": rej,
            },
        )

        ledger.cmd_ingest_verifier(res_path)
        units = json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
        assert units[0]["status"] == "blocked"
        assert units[0]["result_fingerprints"] == []
        assert any("candidate_rejected (disproved_by_source)" in u for u in units[0]["unresolved"])
        assert validate_run_dir(run_dir) == []

    def test_ingest_agent_hypothesis_proof_gap_does_not_promote_candidate(self, run_dir: Path) -> None:
        """
        Proof gap in agent result records evidence and unresolved note on linked unit,
        sets unit status to blocked, and does NOT add a candidate to candidates.json.
        """
        write_json(run_dir / "run-metadata.json", metadata("in_progress"))
        u_init = unit("src/snmp/ber.c", "ber_decode_len", "rte", status="planned", evidence=[])
        write_json(run_dir / "coverage-ledger.json", [u_init])
        write_json(run_dir / "candidates.json", [])

        prover_scratch = run_dir / "agents" / "prover-gap" / "scratch"
        prover_scratch.mkdir(parents=True)
        wp_report = prover_scratch / "wp.json"
        wp_report.write_text("{}", encoding="utf-8")

        res_path = prover_scratch / "result.json"
        write_json(
            res_path,
            {
                "role": "prover",
                "agent_id": "prover-gap",
                "file": "src/snmp/ber.c",
                "function": "ber_decode_len",
                "status": "stalled_after_k_retries",
                "patch": None,
                "evidence": [{"tool_output": "agents/prover-gap/scratch/wp.json", "result": "wp_timeout"}],
                "unproven_goals": ["rte: mem_access"],
                "strengthening_requests": [],
                "boundary_assumptions": [],
                "fault_hypothesis": None,
                "proof_gap": {
                    "predicate": "\\valid_read(buf + off)",
                    "reason": "Missing callee contract lemma for multi-byte buffer framing",
                },
            },
        )

        out = ledger.cmd_ingest_agent_hypothesis(res_path, module="snmp")
        assert out["candidates_added"] == 0
        assert out["proof_gaps_recorded"] == 1

        cands = json.loads((run_dir / "candidates.json").read_text(encoding="utf-8"))
        assert len(cands) == 0  # No non-defect candidate created!

        units = json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
        assert units[0]["status"] == "blocked"
        assert units[0]["result_fingerprints"] == []
        assert any(e["result"] == "proof_gap" for e in units[0]["evidence"])
        assert any("proof_gap: \\valid_read" in u for u in units[0]["unresolved"])
        assert validate_run_dir(run_dir) == []
