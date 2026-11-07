import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from fingerprint import make_fingerprint  # noqa: E402

PHASE0_FIXTURES = ROOT / "tests" / "fixtures" / "phase0"
DOCKER_IMAGE = os.environ.get("FRAMAC_TEST_IMAGE", "framac-pipeline:latest")


@pytest.fixture
def docker_fixture_run():
    """
    Run a shell command in the pipeline image on a copy of a fixture project (mounted read-only,
    network off), as `run(fixture_dir, command) -> CompletedProcess`. Opt-in, as these tests start
    containers: set FRAMAC_DOCKER_TESTS=1. Skipped when Docker or the image is missing.
    """
    if os.environ.get("FRAMAC_DOCKER_TESTS") != "1":
        pytest.skip("Docker-backed test: set FRAMAC_DOCKER_TESTS=1")
    if not shutil.which("docker"):
        pytest.skip("docker not found")
    probe = subprocess.run(["docker", "image", "inspect", DOCKER_IMAGE], capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip(f"image {DOCKER_IMAGE} not built")

    def run(fixture: Path, command: str, timeout: int = 600) -> subprocess.CompletedProcess:
        argv = [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{fixture.resolve()}:/fixture:ro",
            "--entrypoint", "sh", DOCKER_IMAGE,
            "-c", f"cp -r /fixture /tmp/p && cd /tmp/p && {command}",
        ]  # fmt: skip
        return subprocess.run(
            argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False
        )

    return run


@pytest.fixture(autouse=True)
def _no_inherited_git_location(monkeypatch):
    """
    Git exports these to hooks (GIT_DIR always, in a linked worktree). A test that runs git, with the
    pre-commit hook running pytest, would otherwise act on the real repository instead of its own.
    """
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_PREFIX"):
        monkeypatch.delenv(name, raising=False)


FP_PARSE = make_fingerprint("src/snmp/ber.c", "ber_decode_len", "mem_access", r"\valid_read(buf + off)")
FP_EVA = make_fingerprint("src/log/emit.c", "emit_field", "signed_overflow", "pos + n <= 2147483647")
FP_REJ = make_fingerprint("src/snmp/ber.c", "ber_decode_tag", "mem_access", r"\valid_read(p)")


def unit(file, function, cls, status="planned", **kw):
    u = {
        "coverage_id": f"{file}#{function}::{cls}",
        "file": file,
        "function": function,
        "obligation_class": cls,
        "module": kw.pop("module", "snmp"),
        "tier": kw.pop("tier", "Tier 1A (Untrusted Binary / Network Parser)"),
        "wave": kw.pop("wave", 0),
        "callgraph_source": "regex",
        "status": status,
        "agent_id": None,
        "evidence": [],
        "result_fingerprints": [],
        "unresolved": [],
        "assumptions": [],
        "attempts": [],
    }
    u.update(kw)
    return u


def evidence(phase="eva", result="eva_all_valid", discharging=True, tool_output="workspace/reports/eva/snmp.json"):
    return {
        "phase": phase,
        "producer": "run_eva_slice.py",
        "result": result,
        "discharging": discharging,
        "tool_output": tool_output,
        "summary": "summary text",
    }


def verifier():
    return {"agent_id": "verifier-1", "method": "reproduced_and_source_review", "notes": "Re-ran and traced."}


def confirmed_record(fp=FP_PARSE):
    return {
        "verdict": "confirmed",
        "fingerprint": fp,
        "title": "Out-of-bounds read in BER length decoder",
        "description": "Long-form length bytes are read past the end of the input buffer.",
        "location": {"file": "src/snmp/ber.c", "line": 42, "function": "ber_decode_len"},
        "property": {"kind": "mem_access", "predicate": r"\valid_read(buf + off)"},
        "root_cause": "Length-of-length byte count is not checked against remaining input.",
        "intended_behavior": "Reject encodings whose length field exceeds the remaining buffer.",
        "trace": [
            {
                "kind": "entrypoint",
                "file": "src/snmp/pdu.c",
                "line": 10,
                "function": "snmp_parse_pdu",
                "description": "Untrusted UDP payload enters.",
            },
            {
                "kind": "propagation",
                "file": "src/snmp/ber.c",
                "line": 30,
                "function": "ber_decode_tlv",
                "description": "Calls length decoder.",
            },
            {
                "kind": "sink",
                "file": "src/snmp/ber.c",
                "line": 42,
                "function": "ber_decode_len",
                "description": "Reads buf[off] past len.",
            },
        ],
        "evidence": [
            {
                "phase": "fuzz",
                "tool_output": "workspace/reports/fuzz/snmp.json",
                "description": "E-ACSL mem_access failure.",
            }
        ],
        "reachability": "untrusted_surface",
        "harness": {
            "file": "workspace/harnesses/harness_snmp.c",
            "entry_function": "snmp_parse_pdu",
            "contract_respected": True,
            "notes": "Exact-size buffer, len within documented max.",
        },
        "reproducers": [
            {
                "input": "workspace/crashes/snmp/crash-1",
                "sha256": "0" * 64,
                "size_bytes": 3,
                "command": "fuzz_snmp crash-1",
                "observed_result": "E-ACSL: mem_access failed at ber.c:42",
            }
        ],
        "severity": "high",
        "severity_rationale": "Unauthenticated out-of-bounds read; no write shown.",
        "remediation": {
            "summary": "Check length-of-length against remaining bytes.",
            "invariant": "off + nbytes <= len",
            "fix_patch": None,
        },
        "linked_units": ["src/snmp/ber.c#ber_decode_len::rte"],
        "verifier": verifier(),
    }


def needs_validation_record(fp=FP_EVA):
    return {
        "verdict": "needs_validation",
        "fingerprint": fp,
        "title": "Possible signed overflow in cursor advance",
        "description": "Eva reports Invalid for pos + n without a witness.",
        "location": {"file": "src/log/emit.c", "line": 77, "function": "emit_field"},
        "property": {"kind": "signed_overflow", "predicate": "pos + n <= 2147483647"},
        "origin": "eva_invalid_no_witness",
        "claimed_root_cause": "snprintf would-have-written length added to pos.",
        "trace": [
            {"kind": "sink", "file": "src/log/emit.c", "line": 77, "function": "emit_field", "description": "pos += n"}
        ],
        "evidence": [
            {"phase": "eva", "tool_output": "workspace/reports/eva/log.json", "description": "Invalid status."}
        ],
        "reachability": "unknown",
        "blockers": ["No input reaching n > cap - pos found by the breaker within budget."],
        "validation_plan": {"local": "Craft a field longer than cap and replay through harness_log."},
        "linked_units": ["src/log/emit.c#emit_field::rte"],
        "verifier": {"agent_id": "verifier-2", "method": "source_review", "notes": "Path plausible."},
    }


def rejected_record(fp=FP_REJ):
    return {
        "verdict": "rejected",
        "fingerprint": fp,
        "title": "Harness passed NULL to tag decoder",
        "description": "Crash caused by the harness violating the documented non-NULL contract.",
        "location": {"file": "src/snmp/ber.c", "line": 12, "function": "ber_decode_tag"},
        "property": {"kind": "mem_access", "predicate": r"\valid_read(p)"},
        "claimed_root_cause": "NULL dereference.",
        "evidence": [
            {"phase": "verifier", "tool_output": "agents/verifier-3/artifacts/notes.txt", "description": "Harness bug."}
        ],
        "rejection_class": "harness_induced",
        "reason": "ber_decode_tag documents p != NULL; all real callers check it.",
        "linked_units": ["src/snmp/ber.c#ber_decode_tag::rte"],
        "verifier": {"agent_id": "verifier-3", "method": "source_review", "notes": "Harness bug."},
    }


def sorted_findings(*records):
    return sorted(records, key=lambda r: r["fingerprint"])


def metadata(status="in_progress", reason=None):
    return {
        "schema_version": 1,
        "run_id": "run-1",
        "repo": "demo",
        "target": "/target",
        "source_ref": {"vcs": "git", "commit": "abc123", "dirty": False},
        "profile": "standard",
        "scope_paths": [],
        "budget": None,
        "execution_policy": "sandboxed-local-only",
        "sandbox": {"outer": "docker-hardened", "inner": "rlimits"},
        "prior_runs": [],
        "toolchain": {},
        "run_status": status,
        "incomplete_reason": reason,
        "created_at": "2026-10-29T00:00:00+00:00",
        "updated_at": "2026-10-29T00:00:00+00:00",
    }


def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    d = tmp_path / "run-1"
    d.mkdir()
    monkeypatch.chdir(d)
    return d


@pytest.fixture
def deep():
    return copy.deepcopy


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT
