"""Unit tests for scripts/repro_bundle.py (scaffold, try, package) and schemas/repro_expected.schema.json."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import failure_identity
import fuzz_build
import minischema
import repro_bundle
import sandbox_exec
from sandbox_exec import SandboxResult

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "repro_expected.schema.json"

SAMPLE_ASAN_HEAP_OUTPUT = (
    "==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014 at pc 0x555555555200\n"
    "READ of size 4 at 0x602000000014 thread T0\n"
    "    #0 0x555555555200 in parse src/foo.c:142:9\n"
    "    #1 0x555555555300 in decode_entry src/foo.c:210:5\n"
    "    #2 0x555555555400 in main repro.c:25:5\n"
)

SAMPLE_ASAN_HEAP_LINE_SHIFTED = (
    "==99==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014 at pc 0x555555555200\n"
    "READ of size 4 at 0x602000000014 thread T0\n"
    "    #0 0x555555555200 in parse /tmp/other/dir/foo.c:188:9\n"
    "    #1 0x555555555400 in main repro.c:18:5\n"
)

SAMPLE_ASAN_DIFFERENT_OUTPUT = (
    "==77==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffc00000010 at pc 0x555555556100\n"
    "WRITE of size 8 at 0x7ffc00000010 thread T0\n"
    "    #0 0x555555556100 in other_fn src/bar.c:55:3\n"
)


def _sample_fingerprint() -> str:
    parsed = failure_identity.parse_runtime_failure(SAMPLE_ASAN_HEAP_OUTPUT)
    assert parsed is not None
    fp = failure_identity.failure_fingerprint(parsed)
    assert fp is not None
    return fp


def _make_run_dir(
    tmp_path: Path,
    *,
    module: str = "libfoo",
    entry_style: str = "dispatch",
    dispatch_selector: str = "identity",
    n_cases: int = 4,
    artifact_bytes: bytes = b"\x03\xaa\xbb\xcc",
    use_min_sibling: bool = False,
    min_bytes: bytes = b"\x03\xde\xad",
    confirmed: bool = True,
) -> tuple[Path, str]:
    run_dir = tmp_path / "run"
    harnesses_dir = run_dir / "workspace" / "harnesses"
    reports_dir = run_dir / "workspace" / "reports"
    crashes_dir = run_dir / "workspace" / "crashes" / module
    work_src_dir = run_dir / "workspace" / "work" / "src"
    for d in (harnesses_dir, reports_dir, crashes_dir, work_src_dir):
        d.mkdir(parents=True, exist_ok=True)

    (work_src_dir / "foo.c").write_text(
        "int parse(const unsigned char *p, unsigned n) { return p[n]; }\n", encoding="utf-8"
    )

    artifact_path = crashes_dir / "crash-001"
    artifact_path.write_bytes(artifact_bytes)
    if use_min_sibling:
        (crashes_dir / "crash-001.min").write_bytes(min_bytes)

    harness_c = harnesses_dir / f"harness_{module}.c"
    if entry_style == "dispatch":
        marker = "dispatch selector: identity16" if dispatch_selector == "identity16" else "dispatch selector: identity"
        cases_c = "\n".join(
            f"    case {i}U: {{ parse(fuzz_buf, (unsigned)fuzz_len); /* case_{i}_marker */ }} break;"
            for i in range(n_cases)
        )
        harness_text = (
            "#include <stdint.h>\n"
            "#include <stddef.h>\n"
            '#include "foo.h"\n'
            "#define FRAMAC_FUZZ_COPY(buf, off) ((buf) + (off))\n"
            "#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)\n"
            "int eva_main(void) { return 0; }\n"
            "#endif\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            f"    switch (harness_selector) {{ /* {marker}, {n_cases} cases */\n"
            f"{cases_c}\n"
            "    default: FRAMAC_FUZZ_REJECT(); break;\n"
            "    }\n"
            "    return 0;\n"
            "}\n"
        )
        sidecar: dict[str, Any] = {
            "module": module,
            "harness_file": f"workspace/harnesses/harness_{module}.c",
            "sources": [f"workspace/harnesses/harness_{module}.c", "workspace/work/src/foo.c"],
            "header": "foo.h",
            "cppflags": "-Iworkspace/work/src",
            "ldflags": "-lm",
            "entry_fn": "parse",
            "entry_style": "dispatch",
            "dispatch_selector": dispatch_selector,
            "dispatch_case_count": n_cases,
            "dispatch_cases": [f"parse(fuzz_buf, (unsigned)fuzz_len); /* case_{i}_marker */" for i in range(n_cases)],
        }
    else:
        harness_text = (
            "#include <stdint.h>\n"
            "#include <stddef.h>\n"
            '#include "foo.h"\n'
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            "    parse(data, (unsigned)size);\n"
            "    return 0;\n"
            "}\n"
        )
        sidecar = {
            "module": module,
            "harness_file": f"workspace/harnesses/harness_{module}.c",
            "sources": [f"workspace/harnesses/harness_{module}.c", "workspace/work/src/foo.c"],
            "header": "foo.h",
            "cppflags": "-Iworkspace/work/src",
            "ldflags": "",
            "entry_fn": "parse",
            "entry_style": "buffer_len",
        }

    harness_c.write_text(harness_text, encoding="utf-8")
    (harnesses_dir / f"harness_{module}.json").write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

    build_capture = {
        "schema_version": 1,
        "generated_at": "2026-01-01T00:00:00Z",
        "status": "ok",
        "target": "/target",
        "warnings": [],
        "recipe": {
            "command": "make -j2",
            "workdir": "/target",
            "packages": ["zlib1g-dev"],
            "env": {},
            "test_command": None,
            "origin": "user",
        },
    }
    (reports_dir / "build_capture.json").write_text(json.dumps(build_capture, indent=2), encoding="utf-8")

    fp = _sample_fingerprint()
    art_sha = hashlib.sha256(artifact_bytes).hexdigest()
    if confirmed:
        findings = [
            {
                "verdict": "confirmed",
                "fingerprint": fp,
                "title": "Heap buffer overflow in parse",
                "description": "Out-of-bounds read in parse().",
                "location": {"file": "src/foo.c", "line": 142, "function": "parse"},
                "property": {"kind": "heap-buffer-overflow", "predicate": "heap-buffer-overflow READ of size 4"},
                "root_cause": "Missing bounds check.",
                "intended_behavior": "Reject short buffers.",
                "trace": [
                    {
                        "kind": "entrypoint",
                        "file": "src/foo.c",
                        "line": 210,
                        "function": "decode_entry",
                        "description": "Receives untrusted input.",
                    },
                    {
                        "kind": "sink",
                        "file": "src/foo.c",
                        "line": 142,
                        "function": "parse",
                        "description": "Reads 4 bytes past end.",
                    },
                ],
                "evidence": [{"phase": "fuzz", "tool_output": "workspace/reports/fuzz.json", "description": "ASan"}],
                "reachability": "untrusted_surface",
                "harness": {
                    "file": f"workspace/harnesses/harness_{module}.c",
                    "entry_function": "parse",
                    "contract_respected": True,
                    "notes": "Valid buffer.",
                },
                "reproducers": [
                    {
                        "input": f"workspace/crashes/{module}/crash-001",
                        "sha256": art_sha,
                        "size_bytes": len(artifact_bytes),
                        "command": f"fuzz_{module}.san crash-001",
                        "observed_result": SAMPLE_ASAN_HEAP_OUTPUT,
                    }
                ],
                "severity": "high",
                "severity_rationale": "OOB read on untrusted input.",
                "remediation": {"summary": "Check length.", "invariant": "len >= 4", "fix_patch": None},
                "linked_units": ["src/foo.c#parse::rte"],
                "verifier": {"agent_id": "v1", "method": "reproduced", "notes": "Confirmed."},
            }
        ]
        (run_dir / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    else:
        candidates = [
            {
                "fingerprint": fp,
                "status": "unverified",
                "origin": "fuzz",
                "proposed_verdict": "confirmed",
                "module": module,
                "location": {"file": "src/foo.c", "line": 142, "function": "parse"},
                "property": {"kind": "heap-buffer-overflow", "predicate": "heap-buffer-overflow READ of size 4"},
                "reproducers": [f"workspace/crashes/{module}/crash-001"],
                "tool_outputs": ["workspace/reports/fuzz.json"],
                "linked_units": ["src/foo.c#parse::rte"],
                "first_seen": "2026-01-01T00:00:00Z",
            }
        ]
        (run_dir / "candidates.json").write_text(json.dumps(candidates, indent=2), encoding="utf-8")

    return run_dir, fp


@pytest.mark.unit
def test_expected_schema_validates_contract3() -> None:
    schema = minischema.load_schema(SCHEMA_PATH)
    valid_doc = {
        "schema_version": 1,
        "fingerprint": "src/foo.c#parse::mem_access::a1b2c3d4e5",
        "module": "libfoo",
        "engine": "sanitizers",
        "kind": "heap-buffer-overflow",
        "file": "src/foo.c",
        "line": 142,
        "function": "parse",
        "predicate": "heap-buffer-overflow READ of size 4",
        "frames_top": ["parse", "decode_entry"],
        "case_selector": 3,
        "artifact_sha256": "a" * 64,
    }
    assert minischema.validate(valid_doc, schema) == []

    # Null case_selector is allowed for non-dispatch harnesses.
    valid_non_dispatch = {**valid_doc, "case_selector": None}
    assert minischema.validate(valid_non_dispatch, schema) == []

    # Invalid engine and missing required field must fail.
    bad_engine = {**valid_doc, "engine": "coverage"}
    assert minischema.validate(bad_engine, schema)
    bad_missing = {k: v for k, v in valid_doc.items() if k != "artifact_sha256"}
    assert minischema.validate(bad_missing, schema)


@pytest.mark.unit
def test_scaffold_dispatch_1byte_and_min_sibling(tmp_path: Path) -> None:
    run_dir, fp = _make_run_dir(
        tmp_path,
        dispatch_selector="identity",
        n_cases=5,
        artifact_bytes=b"\x02\x11\x22\x33",
        use_min_sibling=True,
        min_bytes=b"\x03\xde\xad",
    )
    out_dir = tmp_path / "out_1byte"
    res = repro_bundle.scaffold_reproducer(run_dir=run_dir, fingerprint=fp, out_dir=out_dir)

    assert res["status"] == "ok"
    assert res["case_selector"] == 3
    assert res["fallback"] is False

    expected = json.loads((out_dir / "expected.json").read_text(encoding="utf-8"))
    schema = minischema.load_schema(SCHEMA_PATH)
    assert minischema.validate(expected, schema) == []
    assert expected["case_selector"] == 3
    assert expected["artifact_sha256"] == hashlib.sha256(b"\x03\xde\xad").hexdigest()
    assert expected["frames_top"] == ["parse", "decode_entry"]

    repro_c = (out_dir / "repro.c").read_text(encoding="utf-8")
    assert "int main(void)" in repro_c
    assert "0xde, 0xad" in repro_c
    assert "0x03" not in repro_c.split("repro_input[]")[1].split("};")[0]
    assert "case_3_marker" in repro_c
    assert "malloc(repro_len > 0U ? repro_len : 1U)" in repro_c

    build_spec = json.loads((out_dir / "build_spec.json").read_text(encoding="utf-8"))
    assert build_spec["sources"] == ["workspace/work/src/foo.c"]
    assert build_spec["ldflags"] == "-lm"


@pytest.mark.unit
def test_scaffold_dispatch_2byte_identity16(tmp_path: Path) -> None:
    # Little-endian 2-byte selector for case 260 = 0x0104 -> bytes 0x04, 0x01
    artifact_bytes = (260).to_bytes(2, "little") + b"\xca\xfe"
    run_dir, fp = _make_run_dir(
        tmp_path,
        dispatch_selector="identity16",
        n_cases=270,
        artifact_bytes=artifact_bytes,
    )
    out_dir = tmp_path / "out_2byte"
    res = repro_bundle.scaffold_reproducer(run_dir=run_dir, fingerprint=fp, out_dir=out_dir)

    assert res["case_selector"] == 260
    assert res["fallback"] is False
    expected = json.loads((out_dir / "expected.json").read_text(encoding="utf-8"))
    assert expected["case_selector"] == 260
    repro_c = (out_dir / "repro.c").read_text(encoding="utf-8")
    assert "0xca, 0xfe" in repro_c
    assert "case_260_marker" in repro_c


@pytest.mark.unit
def test_scaffold_non_dispatch_fallback_and_allow_candidate(tmp_path: Path) -> None:
    run_dir, fp = _make_run_dir(
        tmp_path,
        entry_style="buffer_len",
        artifact_bytes=b"\x01\x02\x03",
        confirmed=False,
    )
    # Without --allow-candidate, scaffolding a candidate fails.
    assert (
        repro_bundle.main(["scaffold", "--run-dir", str(run_dir), "--fingerprint", fp, "--out", str(tmp_path / "x")])
        == 2
    )

    out_dir = tmp_path / "out_fallback"
    rc = repro_bundle.main(
        [
            "scaffold",
            "--run-dir",
            str(run_dir),
            "--fingerprint",
            fp,
            "--out",
            str(out_dir),
            "--allow-candidate",
        ]
    )
    assert rc == 0
    expected = json.loads((out_dir / "expected.json").read_text(encoding="utf-8"))
    assert expected["case_selector"] is None
    repro_c = (out_dir / "repro.c").read_text(encoding="utf-8")
    assert "LLVMFuzzerTestOneInput" in repro_c
    assert "0x01, 0x02, 0x03" in repro_c


@pytest.mark.unit
def test_try_all_four_outcomes_and_line_shifted_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir, fp = _make_run_dir(tmp_path)
    out_dir = tmp_path / "scaf"
    repro_bundle.scaffold_reproducer(run_dir=run_dir, fingerprint=fp, out_dir=out_dir)

    repro_c = out_dir / "repro.c"
    expected_json = out_dir / "expected.json"
    build_spec_json = out_dir / "build_spec.json"

    compile_calls: list[dict[str, Any]] = []

    def fake_compile_ok(sources, out_bin, **kwargs):
        compile_calls.append({"sources": list(sources), "kwargs": kwargs})
        Path(out_bin).write_bytes(b"fake-bin")
        return {"engine": "sanitizers", "returncode": 0, "binary": str(out_bin), "stdout": "", "stderr": ""}

    monkeypatch.setattr(fuzz_build, "compile_sanitizer_binary", fake_compile_ok)

    # 1. Exact SAME_CRASH -> exit 0
    monkeypatch.setattr(
        sandbox_exec,
        "run_sandboxed",
        lambda *a, **kw: SandboxResult(1, "", SAMPLE_ASAN_HEAP_OUTPUT, False, "rlimits", ["repro"]),
    )
    rc = repro_bundle.main(
        [
            "try",
            "--file",
            str(repro_c),
            "--expected",
            str(expected_json),
            "--build-spec",
            str(build_spec_json),
            "--json",
        ]
    )
    assert rc == 0
    assert compile_calls[-1]["kwargs"]["fuzzer_flag"] is False
    assert compile_calls[-1]["kwargs"]["use_cache"] is False

    # 2. Line-shifted / path-shifted SAME_CRASH -> exit 0
    monkeypatch.setattr(
        sandbox_exec,
        "run_sandboxed",
        lambda *a, **kw: SandboxResult(1, "", SAMPLE_ASAN_HEAP_LINE_SHIFTED, False, "rlimits", ["repro"]),
    )
    res_shifted = repro_bundle.try_reproducer(
        c_file=repro_c, expected_path=expected_json, build_spec_path=build_spec_json
    )
    assert res_shifted["status"] == repro_bundle.STATUS_SAME_CRASH
    assert res_shifted["exit_code"] == 0

    # 3. DIFFERENT_CRASH -> exit 1
    monkeypatch.setattr(
        sandbox_exec,
        "run_sandboxed",
        lambda *a, **kw: SandboxResult(1, "", SAMPLE_ASAN_DIFFERENT_OUTPUT, False, "rlimits", ["repro"]),
    )
    res_diff = repro_bundle.try_reproducer(c_file=repro_c, expected_path=expected_json, build_spec_path=build_spec_json)
    assert res_diff["status"] == repro_bundle.STATUS_DIFFERENT_CRASH
    assert res_diff["exit_code"] == 1

    # 4. NO_CRASH -> exit 1
    monkeypatch.setattr(
        sandbox_exec,
        "run_sandboxed",
        lambda *a, **kw: SandboxResult(0, "ok\n", "", False, "rlimits", ["repro"]),
    )
    res_no = repro_bundle.try_reproducer(c_file=repro_c, expected_path=expected_json, build_spec_path=build_spec_json)
    assert res_no["status"] == repro_bundle.STATUS_NO_CRASH
    assert res_no["exit_code"] == 1

    # 5. COMPILE_ERROR -> exit 2
    monkeypatch.setattr(
        fuzz_build,
        "compile_sanitizer_binary",
        lambda *a, **kw: {"engine": "sanitizers", "returncode": 1, "stdout": "", "stderr": "error: syntax"},
    )
    res_comp = repro_bundle.try_reproducer(c_file=repro_c, expected_path=expected_json, build_spec_path=build_spec_json)
    assert res_comp["status"] == repro_bundle.STATUS_COMPILE_ERROR
    assert res_comp["exit_code"] == 2


@pytest.mark.unit
def test_package_fail_closed_and_lf_bundle_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir, fp = _make_run_dir(tmp_path)
    scaf_dir = tmp_path / "scaf"
    repro_bundle.scaffold_reproducer(run_dir=run_dir, fingerprint=fp, out_dir=scaf_dir)

    repro_c = scaf_dir / "repro.c"
    expected_json = scaf_dir / "expected.json"
    build_spec_json = scaf_dir / "build_spec.json"
    findings_json = run_dir / "findings.json"

    monkeypatch.setattr(
        fuzz_build,
        "compile_sanitizer_binary",
        lambda sources, out_bin, **kw: {
            "engine": "sanitizers",
            "returncode": 0,
            "binary": str(out_bin),
            "stdout": "",
            "stderr": "",
        },
    )

    # Fail-closed: NO_CRASH must refuse to package and not create bundle files.
    monkeypatch.setattr(
        sandbox_exec,
        "run_sandboxed",
        lambda *a, **kw: SandboxResult(0, "", "", False, "rlimits", ["repro"]),
    )
    refused_dir = tmp_path / "bundle_refused"
    rc_refused = repro_bundle.main(
        [
            "package",
            "--file",
            str(repro_c),
            "--expected",
            str(expected_json),
            "--build-spec",
            str(build_spec_json),
            "--out",
            str(refused_dir),
        ]
    )
    assert rc_refused == 1
    assert not (refused_dir / "repro.c").exists()

    # Verified SAME_CRASH: writes all 4 files with LF line endings.
    monkeypatch.setattr(
        sandbox_exec,
        "run_sandboxed",
        lambda *a, **kw: SandboxResult(1, "", SAMPLE_ASAN_HEAP_OUTPUT, False, "rlimits", ["repro"]),
    )
    bundle_dir = tmp_path / "bundle_ok"
    rc_ok = repro_bundle.main(
        [
            "package",
            "--file",
            str(repro_c),
            "--expected",
            str(expected_json),
            "--build-spec",
            str(build_spec_json),
            "--out",
            str(bundle_dir),
            "--finding-json",
            str(findings_json),
        ]
    )
    assert rc_ok == 0

    for fname in ("repro.c", "Dockerfile", "run.sh", "ISSUE.md"):
        fpath = bundle_dir / fname
        assert fpath.is_file(), f"missing {fname}"
        raw = fpath.read_bytes()
        assert b"\r\n" not in raw, f"{fname} contains CRLF line endings"

    assert (bundle_dir / "repro.c").read_bytes() == repro_c.read_bytes()
    issue_md = (bundle_dir / "ISSUE.md").read_text(encoding="utf-8")
    assert "Heap buffer overflow in parse" in issue_md
    assert "<details>" in issue_md
    assert "AddressSanitizer: heap-buffer-overflow" in issue_md
    run_sh = (bundle_dir / "run.sh").read_text(encoding="utf-8")
    assert "#!/usr/bin/env bash" in run_sh
    assert "docker build" in run_sh
