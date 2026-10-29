"""Tests for M2 scripts/promote_artifact.py, scripts/ledger.py (ingest-verifier & hypotheses), and scripts/generate_harness.py."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

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
import generate_harness
import ledger
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
            p.write_bytes(f"seed-{idx}".encode("utf-8"))
            too_many.append(f"agents/breaker-1/scratch/seeds/extra_{idx}.bin")
        with pytest.raises(PromotionError, match="too many seeds"):
            promote_seeds(run_dir, "breaker-1", "snmp", too_many)


class TestVerifierIngestionAndHypotheses:
    """Tests for ledger.py ingest-agent-hypothesis and ingest-verifier."""

    def test_ingest_agent_hypothesis_creates_unverified_candidate(self, run_dir: Path) -> None:
        """A breaker or prover with fault_hypothesis creates an unverified candidate in candidates.json."""
        write_json(run_dir / "run-metadata.json", metadata("in_progress"))
        u_rte = unit("src/snmp/ber.c", "ber_decode_len", "rte", status="blocked",
                     evidence=[{"phase": "wp", "producer": "run_wp_function.py", "result": "wp_unproven",
                                "discharging": False, "tool_output": "workspace/reports/wp/ber_decode_len.json",
                                "summary": "1 unproven goal"}],
                     unresolved=["unproven mem_access"])
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
            evidence=[{
                "phase": "fuzz",
                "producer": "run_eacsl_fuzz.py",
                "result": "fuzz_failure",
                "discharging": False,
                "tool_output": "workspace/reports/fuzz/snmp.json",
                "summary": "E-ACSL failure",
            }],
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
        scratch_fix.write_text("--- a/src/snmp/ber.c\n+++ b/src/snmp/ber.c\n@@ -40 +40 @@\n-if (n > 4)\n+if (n > 4 || off + n > len)\n", encoding="utf-8")

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

        units = {u["coverage_id"]: u for u in json.loads((run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))}
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
            evidence=[{
                "phase": "fuzz",
                "producer": "run_eacsl_fuzz.py",
                "result": "fuzz_failure",
                "discharging": False,
                "tool_output": "workspace/reports/fuzz/snmp.json",
                "summary": "E-ACSL failure",
            }],
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
            evidence=[{
                "phase": "fuzz",
                "producer": "run_eacsl_fuzz.py",
                "result": "fuzz_failure",
                "discharging": False,
                "tool_output": "workspace/reports/fuzz/snmp.json",
                "summary": "E-ACSL failure",
            }],
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
        rej["evidence"] = [{"phase": "verifier", "tool_output": "agents/verifier-3/scratch/notes.txt", "description": "Harness bug."}]
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

