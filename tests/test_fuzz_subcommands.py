"""run_eacsl_fuzz.py build / replay / replay-candidates, and the replay report's ingest-verifier contract."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

import ledger
import run_eacsl_fuzz as R
from conftest import FP_PARSE, confirmed_record, metadata, unit, write_json
from sandbox_exec import SandboxResult, SandboxUnavailable

EACSL_MARKER_BYTES = b"\x7fELF...__e_acsl_assert...eacsl_store_block"
EACSL_FAILURE = (
    "src/snmp/ber.c: In function 'ber_decode_len'\n"
    "src/snmp/ber.c:42: Error: Assertion failed:\n"
    "\tThe failing predicate is:\n"
    "\tmem_access: \\valid_read(buf + off).\n"
)


def _eacsl_ok(binary: Path, cache=None):
    def fake(*args, **kwargs):
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(EACSL_MARKER_BYTES)
        return {
            "engine": "eacsl",
            "returncode": 0,
            "binary": str(binary),
            "reduced_checks": [],
            "cache": cache or {"hit": True, "key": "k" * 64},
        }

    return fake


class FakeSandbox:
    """Replays: inputs whose bytes start with CRASH fail with an E-ACSL report."""

    def __init__(self):
        self.calls: list[list[str]] = []

    def __call__(self, cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        self.calls.append(list(cmd))
        data = Path(cmd[-1]).read_bytes()
        if data.startswith(b"CRASH"):
            return SandboxResult(1, "", EACSL_FAILURE, False, "rlimits", list(cmd))
        return SandboxResult(0, "", "Executed 1 inputs\n", False, "rlimits", list(cmd))


def _no_sandbox(*a, **k):
    raise AssertionError("build must never execute target code")


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


def test_build_compiles_only_and_reports_the_cache(tmp_path, monkeypatch):
    out_bin = tmp_path / "bin" / "fuzz_mod"
    fake = _eacsl_ok(out_bin.with_name("fuzz_mod.e-acsl"))
    seen = {}

    def compile_eacsl(*a, **k):
        seen.update(k)
        return fake(*a, **k)

    monkeypatch.setattr(R, "compile_eacsl_binary", compile_eacsl)
    monkeypatch.setattr(R, "run_sandboxed", _no_sandbox)
    out_json = tmp_path / "build.json"
    rc = R.main(
        [
            "build",
            "--module",
            "mod",
            "--sources",
            "mod.c",
            "harness_mod.c",
            "--out-bin",
            str(out_bin),
            "--cppflags=-Iinc",
            "--functions",
            "entry",
            "--no-rte-initialized",
            "--selftest-json",
            str(tmp_path / "none.json"),
            "--out-json",
            str(out_json),
        ]
    )
    res = json.loads(out_json.read_text(encoding="utf-8"))
    assert rc == 0 and res["mode"] == "build" and res["status"] == "built" and res["module"] == "mod"
    assert res["engine_used"] == "eacsl" and res["binary"].endswith("fuzz_mod.e-acsl")
    assert res["cache"] == {"hit": True, "key": "k" * 64}
    assert seen["functions"] == ["entry"] and seen["rte_initialized"] is False


def test_build_falls_back_to_sanitizers_and_fails_cleanly(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "run_sandboxed", _no_sandbox)
    monkeypatch.setattr(
        R,
        "compile_eacsl_binary",
        lambda *a, **k: {"engine": "eacsl", "returncode": 1, "reason": "eacsl_instrumentation_failed"},
    )
    monkeypatch.setattr(
        R,
        "compile_sanitizer_binary",
        lambda *a, **k: {"engine": "sanitizers", "returncode": 0, "binary": str(tmp_path / "fuzz_mod")},
    )
    argv = [
        "build",
        "--module",
        "mod",
        "--sources",
        "mod.c",
        "--out-bin",
        str(tmp_path / "fuzz_mod"),
        "--selftest-json",
        str(tmp_path / "none.json"),
        "--out-json",
        str(tmp_path / "b.json"),
    ]
    assert R.main(argv) == 0
    res = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    assert res["engine_used"] == "sanitizers" and res["engine_fallback_reason"] == "eacsl_instrumentation_failed"
    assert res["eacsl_compile_attempt"]["returncode"] == 1

    monkeypatch.setattr(R, "compile_sanitizer_binary", lambda *a, **k: {"engine": "sanitizers", "returncode": 1})
    assert R.main(argv) == 1
    res = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    assert res["status"] == "compile_error" and res["binary"] is None


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


def test_replay_report_shape_flags_and_determinism(tmp_path, monkeypatch):
    binary = tmp_path / "fuzz_snmp.e-acsl"
    binary.write_bytes(EACSL_MARKER_BYTES)
    crash = tmp_path / "crash-1"
    crash.write_bytes(b"CRASH\x30\x84")
    inputs_dir = tmp_path / "more"
    inputs_dir.mkdir()
    (inputs_dir / "benign").write_bytes(b"fine")
    (inputs_dir / ".hidden").write_bytes(b"CRASH")
    sandbox = FakeSandbox()
    monkeypatch.setattr(R, "run_sandboxed", sandbox)
    out_json = tmp_path / "replay.json"
    rc = R.main(
        [
            "replay",
            "--module",
            "snmp",
            "--inputs",
            str(crash),
            str(inputs_dir),
            str(crash),
            str(tmp_path / "gone"),
            "--binary",
            str(binary),
            "--out-json",
            str(out_json),
        ]
    )
    rep = json.loads(out_json.read_text(encoding="utf-8"))
    assert rc == 0 and rep["mode"] == "replay" and rep["module"] == "snmp" and rep["status"] == "reproduced"
    assert rep["missing_inputs"] == [str(tmp_path / "gone")]
    assert len(sandbox.calls) == 2  # every input exactly once; hidden files skipped
    by_name = {Path(a["artifact"]).name: a for a in rep["artifacts"]}
    hit, clean = by_name["crash-1"], by_name["benign"]
    assert hit["kind"] == "crash" and hit["reproducible"] is True
    assert hit["sha256"] == hashlib.sha256(b"CRASH\x30\x84").hexdigest() and hit["size_bytes"] == 7
    assert hit["failure"]["function"] == "ber_decode_len" and hit["fingerprint"].startswith(
        "src/snmp/ber.c#ber_decode_len::"
    )
    assert clean["reproducible"] is False and clean["failure"] is None and clean["fingerprint"] is None
    seed = R.derive_seed(binary, "snmp")
    for cmd in sandbox.calls:
        assert "-runs=1" in cmd and "-timeout=10" in cmd and "-rss_limit_mb=2048" in cmd and f"-seed={seed}" in cmd
    assert rep["seed"] == seed and 1 <= seed < 2**31
    assert R.derive_seed(binary, "snmp") == seed and R.derive_seed(binary, "other") != seed

    (tmp_path / "gone").write_bytes(b"fine")
    assert (
        R.main(
            [
                "replay",
                "--module",
                "snmp",
                "--inputs",
                str(tmp_path / "gone"),
                "--binary",
                str(binary),
                "--out-json",
                str(out_json),
            ]
        )
        == 0
    )
    assert json.loads(out_json.read_text(encoding="utf-8"))["status"] == "not_reproduced"


def test_replay_builds_through_the_cache_and_reports_errors(tmp_path, monkeypatch):
    crash = tmp_path / "crash-1"
    crash.write_bytes(b"CRASH")
    binary = tmp_path / "workspace" / "harnesses" / "fuzz_snmp.e-acsl"
    monkeypatch.setattr(R, "compile_eacsl_binary", _eacsl_ok(binary))
    monkeypatch.setattr(R, "run_sandboxed", FakeSandbox())
    argv = [
        "replay",
        "--module",
        "snmp",
        "--inputs",
        str(crash),
        "--sources",
        "ber.c",
        "harness_snmp.c",
        "--out-bin",
        str(binary.with_suffix("")),
        "--selftest-json",
        str(tmp_path / "none.json"),
        "--out-json",
        str(tmp_path / "r.json"),
    ]
    assert R.main(argv) == 0
    rep = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert rep["status"] == "reproduced" and rep["engine_used"] == "eacsl" and rep["cache"]["hit"] is True
    assert rep["binary"] == str(binary) and rep["compile"]["returncode"] == 0

    monkeypatch.setattr(R, "compile_eacsl_binary", lambda *a, **k: {"engine": "eacsl", "returncode": 1, "reason": "x"})
    monkeypatch.setattr(R, "compile_sanitizer_binary", lambda *a, **k: {"engine": "sanitizers", "returncode": 1})
    assert R.main(argv) == 1
    rep = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert rep["status"] == "error" and rep["reason"].startswith("compile_error") and rep["artifacts"] == []

    def unavailable(*a, **k):
        raise SandboxUnavailable("no POSIX host")

    monkeypatch.setattr(R, "run_sandboxed", unavailable)
    assert (
        R.main(
            [
                "replay",
                "--module",
                "snmp",
                "--inputs",
                str(crash),
                "--binary",
                str(crash),
                "--out-json",
                str(tmp_path / "r.json"),
            ]
        )
        == 3
    )
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["status"] == "error"

    with pytest.raises(SystemExit):
        R.main(["replay", "--module", "snmp", "--inputs", str(crash), "--out-json", str(tmp_path / "r.json")])


def _verifier_case(run_dir: Path, crash_bytes: bytes):
    """Ledger state with a fuzz candidate whose own report does NOT mark the crash reproducible."""
    write_json(run_dir / "run-metadata.json", metadata("in_progress"))
    write_json(
        run_dir / "coverage-ledger.json",
        [unit("src/snmp/ber.c", "ber_decode_len", "rte", status="candidate", result_fingerprints=[FP_PARSE])],
    )
    crash = run_dir / "agents" / "verifier-1" / "scratch" / "crashes" / "min-crash"
    crash.parent.mkdir(parents=True)
    crash.write_bytes(crash_bytes)
    write_json(
        run_dir / "workspace" / "reports" / "fuzz" / "snmp.json",
        {"module": "snmp", "status": "crash_found", "engine_used": "eacsl", "artifacts": []},
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
            "sha256": hashlib.sha256(crash_bytes).hexdigest(),
            "size_bytes": len(crash_bytes),
            "command": "run_eacsl_fuzz.py replay --inputs min-crash",
            "observed_result": "E-ACSL: mem_access failed at ber.c:42",
        }
    ]
    result = run_dir / "agents" / "verifier-1" / "scratch" / "verifier_result.json"
    write_json(
        result,
        {
            "role": "crash_verifier",
            "agent_id": "verifier-1",
            "candidate_fingerprint": FP_PARSE,
            "decision": "confirmed",
            "refingerprint_reason": None,
            "record": rec,
        },
    )
    return result


def test_replay_report_is_accepted_by_ingest_verifier(run_dir, monkeypatch):
    result = _verifier_case(run_dir, b"CRASH\x30\x84\xff")
    binary = run_dir / "workspace" / "harnesses" / "fuzz_snmp.e-acsl"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(EACSL_MARKER_BYTES)
    monkeypatch.setattr(R, "run_sandboxed", FakeSandbox())
    report = Path("workspace/reports/replay/snmp_verify.json")
    assert (
        R.main(
            [
                "replay",
                "--module",
                "snmp",
                "--inputs",
                "agents/verifier-1/scratch/crashes/min-crash",
                "--binary",
                str(binary),
                "--out-json",
                str(report),
            ]
        )
        == 0
    )

    with pytest.raises(ledger.LedgerError, match="parent-verified reproducible"):
        ledger.cmd_ingest_verifier(result)  # the candidate's own report never reproduced it
    out = ledger.cmd_ingest_verifier(result, replay_reports=[report])
    assert out["decision"] == "confirmed"
    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    assert findings[0]["verdict"] == "confirmed"


def test_unreproduced_replay_does_not_confirm(run_dir, monkeypatch):
    result = _verifier_case(run_dir, b"benign bytes")
    binary = run_dir / "fuzz_snmp.e-acsl"
    binary.write_bytes(EACSL_MARKER_BYTES)
    monkeypatch.setattr(R, "run_sandboxed", FakeSandbox())
    report = Path("replay.json")
    R.main(
        [
            "replay",
            "--module",
            "snmp",
            "--inputs",
            "agents/verifier-1/scratch/crashes/min-crash",
            "--binary",
            str(binary),
            "--out-json",
            str(report),
        ]
    )
    assert json.loads(report.read_text(encoding="utf-8"))["status"] == "not_reproduced"
    with pytest.raises(ledger.LedgerError):
        ledger.cmd_ingest_verifier(result, replay_reports=[report])


# ---------------------------------------------------------------------------
# replay-candidates
# ---------------------------------------------------------------------------


def _replay_candidates_run(run_dir: Path) -> tuple[str, str]:
    """Two Make-runnable modules (DAG, sidecars, harness sources), crashes and candidates."""
    write_json(
        run_dir / "workspace/reports/callgraph_dag.json",
        {
            "modules": {
                "snmp": {"run_eacsl_fuzz": True, "run_eva": True},
                "logm": {"run_eacsl_fuzz": True, "run_eva": False},
            }
        },
    )
    write_json(
        run_dir / "workspace/harnesses/harness_snmp.json",
        {
            "module": "snmp",
            "harness_file": "workspace/harnesses/harness_snmp.c",
            "sources": ["src/snmp/ber.c", "/framac-run/workspace/work/src/snmp/pdu.c"],
            "cppflags": "-Iworkspace/work/src",
            "ldflags": "-lm",
            "include_source": False,
        },
    )
    write_json(
        run_dir / "workspace/harnesses/harness_logm.json",
        {
            "module": "logm",
            "harness_file": "workspace/harnesses/harness_logm.c",
            "sources": ["src/log/emit.c"],
            "cppflags": "-I.",
            "include_source": True,
        },
    )
    for mod in ("snmp", "logm"):
        (run_dir / f"workspace/harnesses/harness_{mod}.c").write_text(
            "int LLVMFuzzerTestOneInput(void);\n", encoding="utf-8"
        )
    write_json(run_dir / "workspace/reports/fuzz/logm.json", {"module": "logm", "engine_used": "sanitizers"})
    crashes = run_dir / "workspace" / "crashes"
    (crashes / "snmp").mkdir(parents=True)
    (crashes / "logm").mkdir(parents=True)
    (crashes / "snmp" / "crash-a").write_bytes(b"CRASH a")
    (crashes / "snmp" / "crash-b").write_bytes(b"fine b")
    (crashes / "logm" / "crash-c").write_bytes(b"CRASH c")
    fp_b = "src/snmp/pdu.c#pdu_parse::mem_access::0123456789"
    fp_c = "src/log/emit.c#emit_field::signed_overflow::abcdef0123"
    write_json(
        run_dir / "candidates.json",
        [
            {
                "fingerprint": FP_PARSE,
                "status": "unverified",
                "module": "snmp",
                "reproducers": ["workspace/crashes/snmp/crash-a"],
                "tool_outputs": [],
            },
            {
                "fingerprint": fp_b,
                "status": "unverified",
                "module": "snmp",
                "reproducers": ["workspace/crashes/snmp/crash-b"],
            },
            {
                "fingerprint": fp_c,
                "status": "unverified",
                "module": "logm",
                "reproducers": [{"input": "workspace/crashes/logm/crash-c"}],
                "tool_outputs": ["workspace/reports/fuzz/logm.json"],
            },
            {
                "fingerprint": "x#y::z::1",
                "status": "verified",
                "module": "snmp",
                "reproducers": ["workspace/crashes/snmp/crash-a"],
            },
            {"fingerprint": "x#y::z::2", "status": "unverified", "module": "snmp", "reproducers": []},
            {
                "fingerprint": "x#y::z::3",
                "status": "unverified",
                "module": "ghost",
                "reproducers": ["workspace/crashes/snmp/crash-a"],
            },
        ],
    )
    return fp_b, fp_c


def _fake_builds(monkeypatch, run_dir: Path) -> tuple[list, list]:
    eacsl_calls: list = []
    san_calls: list = []
    eacsl_bin = run_dir / "workspace/harnesses/fuzz_snmp.e-acsl"

    def compile_eacsl(sources, out_bin, machdep, cppflags, *a, **k):
        eacsl_calls.append((list(sources), Path(out_bin), cppflags, k.get("ldflags_extra")))
        return _eacsl_ok(eacsl_bin)()

    def compile_san(sources, out_bin, cppflags="-I.", fuzzer_flag=True, ldflags_extra="", **k):
        san_calls.append((list(sources), Path(out_bin), cppflags, ldflags_extra))
        Path(out_bin).parent.mkdir(parents=True, exist_ok=True)
        Path(out_bin).write_bytes(b"\x7fELF asan")
        return {
            "engine": "sanitizers",
            "returncode": 0,
            "binary": str(out_bin),
            "cache": {"hit": False, "key": "s" * 64},
        }

    monkeypatch.setattr(R, "compile_eacsl_binary", compile_eacsl)
    monkeypatch.setattr(R, "compile_sanitizer_binary", compile_san)
    monkeypatch.setattr(R, "run_sandboxed", FakeSandbox())
    return eacsl_calls, san_calls


def test_replay_candidates_build_with_makes_spec_and_write_an_index(run_dir, monkeypatch):
    import pipeline_make

    fp_b, fp_c = _replay_candidates_run(run_dir)
    eacsl_calls, san_calls = _fake_builds(monkeypatch, run_dir)
    snmp_spec = pipeline_make.module_build_spec("snmp", run_dir)
    logm_spec = pipeline_make.module_build_spec("logm", run_dir)
    assert R.main(["replay-candidates", "--selftest-json", "none.json"]) == 1  # `ghost` is not a Make module

    # Exactly what `make build` passes: one build per module, at the Makefile's binary path.
    assert eacsl_calls == [(snmp_spec["sources"], Path("workspace/harnesses/fuzz_snmp"), snmp_spec["cppflags"], "-lm")]
    assert snmp_spec["sources"] == [
        "workspace/work/src/snmp/ber.c",
        "workspace/work/src/snmp/pdu.c",
        "workspace/harnesses/harness_snmp.c",
    ]
    assert san_calls == [
        (["workspace/harnesses/harness_logm.c"], Path("workspace/harnesses/fuzz_logm"), logm_spec["cppflags"], "")
    ]  # the campaign's engine (sanitizers) is reused

    index = json.loads((run_dir / "workspace/reports/replay/index.json").read_text(encoding="utf-8"))["by_fingerprint"]
    assert set(index) == {FP_PARSE, fp_b, fp_c, "x#y::z::3"}
    assert index[FP_PARSE]["status"] == "reproduced" and index[fp_b]["status"] == "not_reproduced"
    assert index[fp_c]["status"] == "reproduced" and index["x#y::z::3"]["status"] == "error"
    rep = json.loads(Path(index[FP_PARSE]["report"]).read_text(encoding="utf-8"))
    assert rep["mode"] == "replay" and rep["candidate_fingerprint"] == FP_PARSE and rep["fingerprint_matches"] is True
    assert rep["artifacts"][0]["sha256"] == hashlib.sha256(b"CRASH a").hexdigest()
    assert Path(index[fp_c]["report"]).name.startswith("src_log_emit.c_emit_field")
    ghost = json.loads(Path(index["x#y::z::3"]["report"]).read_text(encoding="utf-8"))
    assert "not runnable" in ghost["reason"] and ghost["artifacts"] == []


def test_replay_candidates_fall_back_to_the_sidecar_without_pipeline_make(run_dir, monkeypatch):
    _replay_candidates_run(run_dir)
    eacsl_calls, _ = _fake_builds(monkeypatch, run_dir)
    monkeypatch.setitem(sys.modules, "pipeline_make", None)  # `import pipeline_make` raises ImportError
    acsl_dir = R.acsl_include_dir()
    assert acsl_dir is not None
    acsl = acsl_dir.as_posix()
    sidecar = run_dir / "workspace/harnesses/harness_snmp.json"
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    meta["cppflags"] = f"-Iworkspace/work/src -I{acsl}"  # already names the ACSL dir: never appended twice
    write_json(sidecar, meta)
    R.main(["replay-candidates", "--selftest-json", "none.json"])
    sources, out_bin, cppflags, _ = eacsl_calls[0]
    assert sources == ["src/snmp/ber.c", "workspace/work/src/snmp/pdu.c", "workspace/harnesses/harness_snmp.c"]
    assert out_bin == Path("workspace/harnesses/fuzz_snmp") and cppflags == f"-Iworkspace/work/src -I{acsl}"


# ---------------------------------------------------------------------------
# guardrail corpus replay capping (Item 6)
# ---------------------------------------------------------------------------


def test_guardrail_caps_corpus_replay_to_max_inputs(tmp_path, monkeypatch):
    binary = tmp_path / "guard_mod.e-acsl"
    binary.write_bytes(EACSL_MARKER_BYTES)
    corpus = tmp_path / "corpus"
    corpus.mkdir(parents=True, exist_ok=True)
    # Create 100 corpus files
    for i in range(100):
        (corpus / f"seed_{i:03d}").write_bytes(f"input_{i}".encode())
    scratch = tmp_path / "scratch"

    calls: list[list[str]] = []

    def fake_sandbox(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        calls.append(list(cmd))
        return SandboxResult(0, "", "", False, "rlimits", list(cmd))

    monkeypatch.setattr(R, "run_sandboxed", fake_sandbox)

    # 1. Default max_corpus_inputs=64
    verdict = R.run_guardrail_check(binary, corpus, scratch, runs=50, module="mod", use_cache=False)
    assert verdict["status"] == "passed_dynamic_oracle"
    assert len(calls) == 1
    cmd = calls[0]
    replay_dir_arg = Path(cmd[-1])
    assert replay_dir_arg == scratch / "replay_corpus"
    staged_files = sorted(f.name for f in replay_dir_arg.iterdir())
    assert len(staged_files) == 64
    expected_first_64 = sorted(f"seed_{i:03d}" for i in range(100))[:64]
    assert staged_files == expected_first_64

    # 2. Custom max_corpus_inputs=10
    scratch2 = tmp_path / "scratch2"
    verdict2 = R.run_guardrail_check(
        binary, corpus, scratch2, runs=50, module="mod", use_cache=False, max_corpus_inputs=10
    )
    assert verdict2["status"] == "passed_dynamic_oracle"
    replay_dir_arg2 = Path(calls[-1][-1])
    assert replay_dir_arg2 == scratch2 / "replay_corpus"
    staged_files2 = sorted(f.name for f in replay_dir_arg2.iterdir())
    assert len(staged_files2) == 10
    assert staged_files2 == sorted(f"seed_{i:03d}" for i in range(100))[:10]

    # 3. Small corpus with 5 files (less than cap) is NOT staged into replay_corpus
    small_corpus = tmp_path / "small_corpus"
    small_corpus.mkdir()
    for i in range(5):
        (small_corpus / f"seed_{i}").write_bytes(b"data")
    scratch3 = tmp_path / "scratch3"
    R.run_guardrail_check(binary, small_corpus, scratch3, runs=50, module="mod", use_cache=False)
    replay_dir_arg3 = Path(calls[-1][-1])
    assert replay_dir_arg3 == small_corpus.resolve()
    assert not (scratch3 / "replay_corpus").exists()


def test_guardrail_cli_max_corpus_inputs(tmp_path, monkeypatch):
    binary = tmp_path / "guard_mod.e-acsl"
    binary.write_bytes(EACSL_MARKER_BYTES)
    corpus = tmp_path / "corpus"
    corpus.mkdir(parents=True, exist_ok=True)
    for i in range(80):
        (corpus / f"seed_{i:03d}").write_bytes(b"x")
    out_bin = tmp_path / "guard_mod"
    out_json = tmp_path / "guard.json"

    seen_max_corpus = {}

    def fake_compile(*a, **k):
        return {
            "engine": "eacsl",
            "returncode": 0,
            "binary": str(binary),
            "reduced_checks": [],
        }

    def fake_run_guardrail(bin_path, corpus_dir, scratch, runs, **kwargs):
        seen_max_corpus.update(kwargs)
        return {"status": "passed_dynamic_oracle", "corpus_dir": str(corpus_dir)}

    monkeypatch.setattr(R, "compile_eacsl_binary", fake_compile)
    monkeypatch.setattr(R, "run_guardrail_check", fake_run_guardrail)

    rc = R.main(
        [
            "guardrail",
            "--sources",
            "mod.c",
            "--out-bin",
            str(out_bin),
            "--corpus-dir",
            str(corpus),
            "--max-corpus-inputs",
            "32",
            "--out-json",
            str(out_json),
        ]
    )
    assert rc == 0
    assert seen_max_corpus.get("max_corpus_inputs") == 32
