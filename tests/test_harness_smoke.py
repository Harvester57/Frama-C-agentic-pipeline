"""Unit and mock-runner tests for P3 startup failure classification and standalone harness smoke gate."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import failure_identity as FI
import harness_smoke as HS
import minischema
import sandbox_exec
from sandbox_exec import SandboxResult

pytestmark = pytest.mark.unit

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "harness_smoke.schema.json"
_SMOKE_SCHEMA = minischema.load_schema(_SCHEMA_PATH)


def _assert_valid_smoke_report(report: dict[str, Any]) -> None:
    errors = minischema.validate(report, _SMOKE_SCHEMA)
    assert errors == [], f"schema validation failed: {errors}"


def _write_sidecar(
    tmp_path: Path,
    module: str,
    *,
    entry_style: str = "dispatch",
    dispatch_case_count: int = 4,
    dispatch_selector: str | None = "identity",
    dispatch_selector_bytes: int | None = None,
    api_cases: list[dict[str, Any]] | None = None,
    entry_fn: str = "fuzz_entry",
) -> Path:
    hdir = tmp_path / "workspace" / "harnesses"
    hdir.mkdir(parents=True, exist_ok=True)
    sidecar: dict[str, Any] = {
        "module": module,
        "harness_file": f"workspace/harnesses/harness_{module}.c",
        "sources": ["src/demo.c"],
        "cppflags": "-I.",
        "entry_fn": entry_fn,
        "entry_style": entry_style,
    }
    if entry_style == "dispatch":
        sidecar["dispatch_case_count"] = dispatch_case_count
        sidecar["dispatch_cases"] = [f"case_{k}();" for k in range(dispatch_case_count)]
        if dispatch_selector is not None:
            sidecar["dispatch_selector"] = dispatch_selector
        if dispatch_selector_bytes is not None:
            sidecar["dispatch_selector_bytes"] = dispatch_selector_bytes
        if api_cases is not None:
            sidecar["api_cases"] = api_cases
    sidecar_path = hdir / f"harness_{module}.json"
    sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
    (hdir / f"harness_{module}.c").write_text("/* synthetic harness */\n", encoding="utf-8")
    return sidecar_path


def _make_fake_bin(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELFfake")
    return path


# ---------------------------------------------------------------------------
# Sample sanitizer / E-ACSL failure outputs
# ---------------------------------------------------------------------------

_LOG_STARTUP_LLVM_INIT = """\
==101==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x5555 bp 0x7fff sp 0x7ffe T0)
==101==The signal is caused by a READ memory access.
    #0 0x55551000 in LLVMFuzzerInitialize templates/eacsl_runtime/fuzz_init.c:24:5
    #1 0x55552000 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long))
    #2 0x55553000 in main
"""

_LOG_STARTUP_EACSL_GLOBALS = """\
==202==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x000000000000 (pc 0x5555 bp 0x7fff sp 0x7ffe T0)
    #0 0x55551000 in shadow_alloca /usr/share/frama-c/e-acsl/e_acsl_segment_tracking.c:112
    #1 0x55551100 in __e_acsl_globals_init harness_mod.instrumented.c:901
    #2 0x55551200 in __e_acsl_memory_init /usr/share/frama-c/e-acsl/e_acsl_rtl.c:45
    #3 0x55551300 in LLVMFuzzerInitialize templates/eacsl_runtime/fuzz_init.c:30
    #4 0x55552000 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long))
"""

_LOG_NULL_MEMBER_UBSAN = """\
Running: {probe_path}
src/ctx.c:42:12: runtime error: member access within null pointer of type 'struct ctx_t'
    #0 0x55551000 in ctx_process src/ctx.c:42:12
    #1 0x55551100 in LLVMFuzzerTestOneInput workspace/harnesses/harness_demo.c:180:5
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/ctx.c:42:12
"""

_LOG_SEGV_ZERO_PAGE = """\
Running: {probe_path}
==303==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000018 (pc 0x5555 bp 0x7fff sp 0x7ffe T0)
==303==The signal is caused by a READ memory access.
==303==Hint: address points to the zero page.
    #0 0x55551000 in ctx_read src/ctx.c:55:9
    #1 0x55551100 in LLVMFuzzerTestOneInput workspace/harnesses/harness_demo.c:182:5
"""

_LOG_NON_MALLOC_FREE = """\
Running: {probe_path}
==404==ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed: 0x7fff12345600 in thread T0
    #0 0x55550000 in __interceptor_free
    #1 0x55551000 in obj_destroy src/obj.c:88:5
    #2 0x55551100 in LLVMFuzzerTestOneInput workspace/harnesses/harness_demo.c:195:5
"""

_LOG_STACK_OVERFLOW_HARNESS_VAR = """\
Running: {probe_path}
==505==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff12345620 at pc 0x5555 bp 0x7fff sp 0x7ffe
WRITE of size 16 at 0x7fff12345620 thread T0
    #0 0x55551000 in fill_out src/out.c:31:5
    #1 0x55551100 in LLVMFuzzerTestOneInput workspace/harnesses/harness_demo.c:140:5

Address 0x7fff12345620 is located in stack of thread T0 at offset 32 in frame
    #0 0x555510ff in LLVMFuzzerTestOneInput workspace/harnesses/harness_demo.c:120

  This frame has 2 object(s):
    [32, 40) 'c0a1' (line 130) <== Memory access at offset 40 overflows this variable
    [64, 72) 'c0a2' (line 131)
"""

_LOG_STACK_OVERFLOW_TARGET_VAR = """\
Running: {probe_path}
==506==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff12345620 at pc 0x5555 bp 0x7fff sp 0x7ffe
WRITE of size 16 at 0x7fff12345620 thread T0
    #0 0x55551000 in parse_hdr src/parser.c:31:5
    #1 0x55551100 in LLVMFuzzerTestOneInput workspace/harnesses/harness_demo.c:140:5

Address 0x7fff12345620 is located in stack of thread T0 at offset 32 in frame
    #0 0x55550fff in parse_hdr src/parser.c:20

  This frame has 1 object(s):
    [32, 40) 'local_buf' (line 22) <== Memory access at offset 40 overflows this variable
"""

_LOG_EMPTY_HEAP_OVERFLOW = """\
Running: {probe_path}
==606==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000011 at pc 0x5555 bp 0x7fff sp 0x7ffe
READ of size 1 at 0x502000000011 thread T0
    #0 0x55551000 in parse_header src/parser.c:19:14
    #1 0x55551100 in LLVMFuzzerTestOneInput workspace/harnesses/harness_demo.c:187:5
"""

_LOG_EMPTY_SIGNED_OVERFLOW = """\
Running: {probe_path}
src/math.c:14:9: runtime error: signed integer overflow: -2147483648 - 1 cannot be represented in type 'int'
    #0 0x55551000 in calc_delta src/math.c:14:9
    #1 0x55551100 in LLVMFuzzerTestOneInput workspace/harnesses/harness_demo.c:187:5
"""

_LOG_LSAN_DIRECT_LEAK = """\
Running: {probe_path}
Executed {probe_path} in 1 ms
==707==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0x55550000 in malloc
    #1 0x55551000 in make_ctx src/ctx.c:15:12
    #2 0x55551100 in LLVMFuzzerTestOneInput workspace/harnesses/harness_demo.c:160:5
"""


# ---------------------------------------------------------------------------
# Feature flag tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "val,expected",
    [
        (None, False),
        ("", False),
        ("off", False),
        ("0", False),
        ("false", False),
        ("on", True),
        ("1", True),
        ("true", True),
        ("ON", True),
        (" True ", True),
    ],
)
def test_harness_smoke_enabled_flag(monkeypatch, val, expected):
    if val is None:
        monkeypatch.delenv("FRAMAC_HARNESS_SMOKE", raising=False)
    else:
        monkeypatch.setenv("FRAMAC_HARNESS_SMOKE", val)
    assert HS.harness_smoke_enabled() is expected


# ---------------------------------------------------------------------------
# failure_identity: is_startup_failure & classify_smoke_failure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fn",
    [
        "LLVMFuzzerInitialize",
        "__e_acsl_globals_init",
        "__e_acsl_memory_init",
        "__e_acsl_argv_alloca",
        "shadow_alloca",
    ],
)
def test_is_startup_failure_detects_known_startup_functions(fn):
    ok, reason = FI.is_startup_failure({"function": fn, "file": "unknown", "line": 0, "kind": "asan_segv"})
    assert ok is True
    assert reason and fn in reason


def test_is_startup_failure_from_log_without_parsed_failure():
    ok, reason = FI.is_startup_failure(None, _LOG_STARTUP_EACSL_GLOBALS)
    assert ok is True
    assert reason is not None

    ctor_log = (
        "==99==ERROR: AddressSanitizer: global-buffer-overflow\n"
        "    #0 0x1000 in init_tables src/init.c:12\n"
        "    #1 0x2000 in __libc_csu_init\n"
        "    #2 0x3000 in __libc_start_main\n"
    )
    ok2, reason2 = FI.is_startup_failure(None, ctor_log)
    assert ok2 is True
    assert reason2 is not None

    banner_abort = "INFO: Seed: 42\n==99==ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
    ok3, reason3 = FI.is_startup_failure(None, banner_abort)
    assert ok3 is True
    assert reason3 is not None

    loader_err = "./fuzz_mod: error while loading shared libraries: libfoo.so: cannot open shared object file\n"
    ok4, reason4 = FI.is_startup_failure(None, loader_err)
    assert ok4 is True
    assert reason4 is not None


def test_is_startup_failure_false_for_normal_target_crashes():
    log = _LOG_EMPTY_HEAP_OVERFLOW.format(probe_path="/tmp/p0.bin")
    failure = FI.parse_runtime_failure(log)
    assert failure is not None
    assert FI.is_startup_failure(failure, log) == (False, None)

    minimal_log = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "READ of size 1\n"
        "    #0 0x1 in parse_hdr src/parser.c:12:5\n"
    )
    f_min = FI.parse_runtime_failure(minimal_log)
    assert FI.is_startup_failure(f_min, minimal_log) == (False, None)

    lsan_log = _LOG_LSAN_DIRECT_LEAK.format(probe_path="/tmp/p0.bin")
    f_lsan = FI.parse_runtime_failure(lsan_log)
    assert FI.is_startup_failure(f_lsan, lsan_log) == (False, None)


def test_classify_smoke_failure_distinguishes_setup_faults_and_real_candidates():
    # 1. Startup error
    f_init = FI.parse_runtime_failure(_LOG_STARTUP_LLVM_INIT)
    assert FI.classify_smoke_failure(f_init, 0, _LOG_STARTUP_LLVM_INIT) == "startup_error"

    # 2. Non-malloc free -> harness_setup_fault for both payload_len == 0 and payload_len > 0
    log_free = _LOG_NON_MALLOC_FREE.format(probe_path="/tmp/p.bin")
    f_free = FI.parse_runtime_failure(log_free)
    assert FI.classify_smoke_failure(f_free, 0, log_free) == "harness_setup_fault"
    assert FI.classify_smoke_failure(f_free, 64, log_free) == "harness_setup_fault"

    # 3. Stack-buffer-overflow on harness frame var c0a1 -> harness_setup_fault
    log_sbo_h = _LOG_STACK_OVERFLOW_HARNESS_VAR.format(probe_path="/tmp/p.bin")
    f_sbo_h = FI.parse_runtime_failure(log_sbo_h)
    assert FI.classify_smoke_failure(f_sbo_h, 0, log_sbo_h) == "harness_setup_fault"
    assert FI.classify_smoke_failure(f_sbo_h, 64, log_sbo_h) == "harness_setup_fault"

    # 4. Stack-buffer-overflow on target local var -> NOT quarantined
    log_sbo_t = _LOG_STACK_OVERFLOW_TARGET_VAR.format(probe_path="/tmp/p.bin")
    f_sbo_t = FI.parse_runtime_failure(log_sbo_t)
    assert FI.classify_smoke_failure(f_sbo_t, 0, log_sbo_t) == "empty_input_candidate"
    assert FI.classify_smoke_failure(f_sbo_t, 64, log_sbo_t) == "target_crash_candidate"

    # 5. Direct leak on setup (payload_len == 0) vs target leak on non-empty payload
    log_lsan = _LOG_LSAN_DIRECT_LEAK.format(probe_path="/tmp/p.bin")
    f_lsan = FI.parse_runtime_failure(log_lsan)
    assert FI.classify_smoke_failure(f_lsan, 0, log_lsan) == "harness_setup_fault"
    assert FI.classify_smoke_failure(f_lsan, 64, log_lsan) == "target_crash_candidate"

    # 6. NULL member access / zero-page SEGV on payload_len == 0 -> harness_setup_fault; on payload_len > 0 -> candidate
    log_null = _LOG_NULL_MEMBER_UBSAN.format(probe_path="/tmp/p.bin")
    f_null = FI.parse_runtime_failure(log_null)
    assert FI.classify_smoke_failure(f_null, 0, log_null) == "harness_setup_fault"
    assert FI.classify_smoke_failure(f_null, 64, log_null) == "target_crash_candidate"

    log_zp = _LOG_SEGV_ZERO_PAGE.format(probe_path="/tmp/p.bin")
    f_zp = FI.parse_runtime_failure(log_zp)
    assert FI.classify_smoke_failure(f_zp, 0, log_zp) == "harness_setup_fault"
    assert FI.classify_smoke_failure(f_zp, 64, log_zp) == "target_crash_candidate"

    # 7. Genuine empty-input bugs (buffer/arithmetic) -> empty_input_candidate (NEVER quarantined)
    log_hbo = _LOG_EMPTY_HEAP_OVERFLOW.format(probe_path="/tmp/p.bin")
    f_hbo = FI.parse_runtime_failure(log_hbo)
    assert FI.classify_smoke_failure(f_hbo, 0, log_hbo) == "empty_input_candidate"
    assert FI.classify_smoke_failure(f_hbo, 64, log_hbo) == "target_crash_candidate"

    log_ovf = _LOG_EMPTY_SIGNED_OVERFLOW.format(probe_path="/tmp/p.bin")
    f_ovf = FI.parse_runtime_failure(log_ovf)
    assert FI.classify_smoke_failure(f_ovf, 0, log_ovf) == "empty_input_candidate"


# ---------------------------------------------------------------------------
# Mock-runner smoke gate tests
# ---------------------------------------------------------------------------


def _extract_probe_paths(argv: list[str]) -> list[Path]:
    return [Path(a) for a in argv[1:] if not a.startswith("-")]


def test_smoke_startup_crash_san_llvm_fuzzer_initialize(tmp_path, monkeypatch):
    sidecar = _write_sidecar(tmp_path, "mod_init_fail", dispatch_case_count=3)
    san_bin = _make_fake_bin(tmp_path / "fuzz_mod_init_fail.san")
    out_json = tmp_path / "workspace" / "reports" / "smoke" / "mod_init_fail.json"
    calls: list[list[str]] = []

    def fake_run(argv, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        calls.append(list(argv))
        return SandboxResult(
            returncode=-11,
            stdout="",
            stderr=_LOG_STARTUP_LLVM_INIT,
            timed_out=False,
            sandbox="rlimits",
            command=list(argv),
        )

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    report, rc = HS.run_smoke(module="mod_init_fail", sidecar_path=sidecar, out_json=out_json, san_bin=san_bin)

    assert rc != 0
    assert report["status"] == "startup_error"
    assert report["startup"]["ok"] is False
    assert report["startup"]["failing_engine"] == "sanitizers"
    assert "LLVMFuzzerInitialize" in (report["startup"]["stack_trace"] or "")
    assert report["case_results"] == []
    assert len(calls) == 1  # Stopped before per-case probes
    assert out_json.is_file()
    _assert_valid_smoke_report(json.loads(out_json.read_text(encoding="utf-8")))


def test_smoke_startup_crash_eacsl_globals_init(tmp_path, monkeypatch):
    sidecar = _write_sidecar(tmp_path, "mod_eacsl_init", dispatch_case_count=2)
    san_bin = _make_fake_bin(tmp_path / "fuzz_mod_eacsl_init.san")
    eacsl_bin = _make_fake_bin(tmp_path / "fuzz_mod_eacsl_init.e-acsl")
    out_json = tmp_path / "smoke_eacsl.json"

    def fake_run(argv, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        if Path(argv[0]).name.endswith(".e-acsl"):
            return SandboxResult(
                returncode=-11,
                stdout="",
                stderr=_LOG_STARTUP_EACSL_GLOBALS,
                timed_out=False,
                sandbox="rlimits",
                command=list(argv),
            )
        return SandboxResult(returncode=0, stdout="", stderr="", timed_out=False, sandbox="rlimits", command=list(argv))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    report, rc = HS.run_smoke(
        module="mod_eacsl_init",
        sidecar_path=sidecar,
        out_json=out_json,
        san_bin=san_bin,
        eacsl_bin=eacsl_bin,
    )

    assert rc != 0
    assert report["status"] == "startup_error"
    assert report["startup"]["engines_checked"] == ["sanitizers", "eacsl"]
    assert report["startup"]["failing_engine"] == "eacsl"
    assert report["startup"]["results"]["sanitizers"]["ok"] is True
    assert report["startup"]["results"]["eacsl"]["ok"] is False
    assert "__e_acsl_globals_init" in (report["startup"]["stack_trace"] or "")
    _assert_valid_smoke_report(report)


def test_smoke_partial_degraded_preserves_empty_input_bug_and_quarantines_setup_faults(tmp_path, monkeypatch):
    api_cases = [
        {"selector": 0, "kind": "single", "calls": ["api_ok"], "slots": [], "rest": None, "entry": "src/a.c::api_ok"},
        {
            "selector": 1,
            "kind": "single",
            "calls": ["ctx_process"],
            "slots": [],
            "rest": None,
            "entry": "src/ctx.c::ctx_process",
        },
        {
            "selector": 2,
            "kind": "single",
            "calls": ["parse_header"],
            "slots": [],
            "rest": None,
            "entry": "src/parser.c::parse_header",
        },
        {
            "selector": 3,
            "kind": "single",
            "calls": ["obj_destroy"],
            "slots": [],
            "rest": None,
            "entry": "src/obj.c::obj_destroy",
        },
    ]
    sidecar = _write_sidecar(tmp_path, "mod_mix", dispatch_case_count=4, api_cases=api_cases)
    san_bin = _make_fake_bin(tmp_path / "fuzz_mod_mix.san")
    seeds_dir = tmp_path / "seeds"
    seeds_dir.mkdir()
    # Provide 3 seeds for case 0 (smoke should cap at 2 per case) and 1 seed for case 3.
    (seeds_dir / "seed_0a").write_bytes(b"\x00hello")
    (seeds_dir / "seed_0b").write_bytes(b"\x00world")
    (seeds_dir / "seed_0c").write_bytes(b"\x00extra")
    (seeds_dir / "seed_3a").write_bytes(b"\x03payload")

    out_json = tmp_path / "workspace" / "reports" / "smoke" / "mod_mix.json"
    only_case_envs: list[str] = []

    def fake_run(argv, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        probes = _extract_probe_paths(argv)
        if extra_env and "FRAMAC_FUZZ_ONLY_CASE" in extra_env:
            only_case_envs.append(extra_env["FRAMAC_FUZZ_ONLY_CASE"])
        for p in probes:
            raw = p.read_bytes()
            if not raw or raw == b"\xff":
                continue  # Startup out-of-range selector -> rejected cleanly
            sel = raw[0]
            payload = raw[1:]
            if extra_env and "FRAMAC_FUZZ_ONLY_CASE" in extra_env and str(sel) != extra_env["FRAMAC_FUZZ_ONLY_CASE"]:
                continue
            if sel == 1 and len(payload) == 0:
                return SandboxResult(
                    returncode=1,
                    stdout="",
                    stderr=_LOG_NULL_MEMBER_UBSAN.format(probe_path=p),
                    timed_out=False,
                    sandbox="rlimits",
                    command=list(argv),
                )
            if sel == 2 and len(payload) == 0:
                return SandboxResult(
                    returncode=1,
                    stdout="",
                    stderr=_LOG_EMPTY_HEAP_OVERFLOW.format(probe_path=p),
                    timed_out=False,
                    sandbox="rlimits",
                    command=list(argv),
                )
            if sel == 3 and len(payload) == 64:
                return SandboxResult(
                    returncode=1,
                    stdout="",
                    stderr=_LOG_NON_MALLOC_FREE.format(probe_path=p),
                    timed_out=False,
                    sandbox="rlimits",
                    command=list(argv),
                )
        return SandboxResult(returncode=0, stdout="", stderr="", timed_out=False, sandbox="rlimits", command=list(argv))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    report, rc = HS.run_smoke(
        module="mod_mix",
        sidecar_path=sidecar,
        out_json=out_json,
        san_bin=san_bin,
        seeds_dir=seeds_dir,
    )

    assert rc == 0  # Degraded exits 0
    assert report["status"] == "degraded"
    assert report["quarantined_cases"] == [1, 3]
    assert report["skip_cases_env"] == "1,3"
    assert report["candidate_warning_cases"] == [2]
    assert {"1", "2", "3"}.issubset(set(only_case_envs))

    by_case = {c["case"]: c for c in report["case_results"]}
    assert by_case[0]["status"] == "passed"
    assert by_case[0]["probes_run"] == 4  # empty + zero64 + 2 capped seeds
    assert by_case[1]["status"] == "quarantined"
    assert by_case[1]["classification"] == "harness_setup_fault"
    assert by_case[1]["payload_len"] == 0
    assert by_case[1]["fingerprint"] is not None

    # Genuine empty-input heap-buffer-overflow stays active as candidate_warning!
    assert by_case[2]["status"] == "candidate_warning"
    assert by_case[2]["classification"] == "empty_input_candidate"
    assert by_case[2]["payload_len"] == 0
    assert by_case[2]["fingerprint"] is not None

    assert by_case[3]["status"] == "quarantined"
    assert by_case[3]["classification"] == "harness_setup_fault"
    assert by_case[3]["payload_len"] == 64
    assert by_case[3]["kind"] == "asan_attempting_free_on_address_which_was_not_malloc_ed"

    assert report["counts"] == {"total": 4, "passed": 1, "quarantined": 2, "candidate_warning": 1}
    _assert_valid_smoke_report(report)


def test_smoke_all_cases_quarantined_fails_nonzero(tmp_path, monkeypatch):
    sidecar = _write_sidecar(tmp_path, "mod_all_bad", dispatch_case_count=2)
    san_bin = _make_fake_bin(tmp_path / "fuzz_mod_all_bad.san")
    out_json = tmp_path / "all_bad.json"

    def fake_run(argv, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        for p in _extract_probe_paths(argv):
            raw = p.read_bytes()
            if raw == b"\xff":
                continue
            sel = raw[0]
            if sel == 0:
                return SandboxResult(
                    returncode=1,
                    stdout="",
                    stderr=_LOG_NULL_MEMBER_UBSAN.format(probe_path=p),
                    timed_out=False,
                    sandbox="rlimits",
                    command=list(argv),
                )
            if sel == 1:
                return SandboxResult(
                    returncode=1,
                    stdout="",
                    stderr=_LOG_STACK_OVERFLOW_HARNESS_VAR.format(probe_path=p),
                    timed_out=False,
                    sandbox="rlimits",
                    command=list(argv),
                )
        return SandboxResult(returncode=0, stdout="", stderr="", timed_out=False, sandbox="rlimits", command=list(argv))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    report, rc = HS.run_smoke(module="mod_all_bad", sidecar_path=sidecar, out_json=out_json, san_bin=san_bin)

    assert rc != 0
    assert report["status"] == "failed"
    assert report["quarantined_cases"] == [0, 1]
    assert report["skip_cases_env"] == "0,1"
    _assert_valid_smoke_report(report)


def test_smoke_lsan_batch_bisection_pinpoints_leaking_case(tmp_path, monkeypatch):
    sidecar = _write_sidecar(tmp_path, "mod_lsan", dispatch_case_count=4)
    san_bin = _make_fake_bin(tmp_path / "fuzz_mod_lsan.san")
    out_json = tmp_path / "lsan.json"

    def fake_run(argv, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        probes = _extract_probe_paths(argv)
        leaked = False
        for p in probes:
            raw = p.read_bytes()
            if raw == b"\xff":
                continue
            if raw[0] == 2 and len(raw) == 1:
                leaked = True
        if leaked:
            # LSan prints at process exit after Running the LAST probe in the batch (case 3),
            # not case 2; bisection must still pinpoint case 2 cleanly.
            return SandboxResult(
                returncode=1,
                stdout="",
                stderr=_LOG_LSAN_DIRECT_LEAK.format(probe_path=probes[-1]),
                timed_out=False,
                sandbox="rlimits",
                command=list(argv),
            )
        return SandboxResult(returncode=0, stdout="", stderr="", timed_out=False, sandbox="rlimits", command=list(argv))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    report, rc = HS.run_smoke(module="mod_lsan", sidecar_path=sidecar, out_json=out_json, san_bin=san_bin)

    assert rc == 0
    assert report["status"] == "degraded"
    assert report["quarantined_cases"] == [2]
    assert report["skip_cases_env"] == "2"
    _assert_valid_smoke_report(report)


def test_smoke_two_byte_selector_encoding_and_seeds(tmp_path, monkeypatch):
    sidecar = _write_sidecar(
        tmp_path,
        "mod_wide",
        dispatch_case_count=3,
        dispatch_selector="identity16",
        dispatch_selector_bytes=2,
    )
    san_bin = _make_fake_bin(tmp_path / "fuzz_mod_wide.san")
    seeds_dir = tmp_path / "seeds_wide"
    seeds_dir.mkdir()
    (seeds_dir / "s1").write_bytes((2).to_bytes(2, "little") + b"ABCD")
    out_json = tmp_path / "wide.json"

    seen_startup: list[bytes] = []
    seen_case_probes: list[bytes] = []

    def fake_run(argv, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        probes = _extract_probe_paths(argv)
        for p in probes:
            raw = p.read_bytes()
            if p.name == "startup_probe.bin":
                seen_startup.append(raw)
            else:
                seen_case_probes.append(raw)
        return SandboxResult(returncode=0, stdout="", stderr="", timed_out=False, sandbox="rlimits", command=list(argv))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    report, rc = HS.run_smoke(
        module="mod_wide",
        sidecar_path=sidecar,
        out_json=out_json,
        san_bin=san_bin,
        seeds_dir=seeds_dir,
    )

    assert rc == 0
    assert report["status"] == "ok"
    assert seen_startup == [b"\xff\xff"]
    assert (2).to_bytes(2, "little") in seen_case_probes
    assert (2).to_bytes(2, "little") + b"ABCD" in seen_case_probes
    _assert_valid_smoke_report(report)


def test_smoke_non_dispatch_harness_ok_empty_bug_and_setup_fault(tmp_path, monkeypatch):
    # 1. Clean non-dispatch (argv) with 6 seeds -> capped at 4 seeds + 1 empty = 5 probes
    sidecar = _write_sidecar(tmp_path, "mod_argv", entry_style="argv", entry_fn="cli_main")
    san_bin = _make_fake_bin(tmp_path / "fuzz_mod_argv.san")
    seeds_dir = tmp_path / "seeds_nd"
    seeds_dir.mkdir()
    for i in range(6):
        (seeds_dir / f"seed_{i}").write_bytes(f"input-{i}".encode())

    def fake_ok(argv, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        return SandboxResult(returncode=0, stdout="", stderr="", timed_out=False, sandbox="rlimits", command=list(argv))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_ok)
    rep_ok, rc_ok = HS.run_smoke(
        module="mod_argv",
        sidecar_path=sidecar,
        out_json=tmp_path / "nd_ok.json",
        san_bin=san_bin,
        seeds_dir=seeds_dir,
    )
    assert rc_ok == 0
    assert rep_ok["status"] == "ok"
    assert rep_ok["case_results"][0]["probes_run"] == 5
    assert rep_ok["quarantined_cases"] == []
    assert rep_ok["skip_cases_env"] == ""
    _assert_valid_smoke_report(rep_ok)

    # 2. Non-dispatch hitting genuine empty-input heap-buffer-overflow -> candidate_warning, status=ok, rc=0
    def fake_empty_bug(argv, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        for p in _extract_probe_paths(argv):
            if p.read_bytes() == b"":
                return SandboxResult(
                    returncode=1,
                    stdout="",
                    stderr=_LOG_EMPTY_HEAP_OVERFLOW.format(probe_path=p),
                    timed_out=False,
                    sandbox="rlimits",
                    command=list(argv),
                )
        return SandboxResult(returncode=0, stdout="", stderr="", timed_out=False, sandbox="rlimits", command=list(argv))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_empty_bug)
    rep_bug, rc_bug = HS.run_smoke(
        module="mod_argv",
        sidecar_path=sidecar,
        out_json=tmp_path / "nd_bug.json",
        san_bin=san_bin,
    )
    assert rc_bug == 0
    assert rep_bug["status"] == "ok"
    assert rep_bug["startup"]["ok"] is True
    assert rep_bug["case_results"][0]["status"] == "candidate_warning"
    assert rep_bug["case_results"][0]["classification"] == "empty_input_candidate"
    _assert_valid_smoke_report(rep_bug)

    # 3. Non-dispatch hitting unambiguous harness setup fault -> status=failed, rc=1
    def fake_setup_fault(argv, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        for p in _extract_probe_paths(argv):
            return SandboxResult(
                returncode=1,
                stdout="",
                stderr=_LOG_NON_MALLOC_FREE.format(probe_path=p),
                timed_out=False,
                sandbox="rlimits",
                command=list(argv),
            )
        return SandboxResult(returncode=0, stdout="", stderr="", timed_out=False, sandbox="rlimits", command=list(argv))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_setup_fault)
    rep_fail, rc_fail = HS.run_smoke(
        module="mod_argv",
        sidecar_path=sidecar,
        out_json=tmp_path / "nd_fail.json",
        san_bin=san_bin,
    )
    assert rc_fail != 0
    assert rep_fail["status"] == "failed"
    assert rep_fail["case_results"][0]["status"] == "quarantined"
    assert rep_fail["quarantined_cases"] == []
    assert rep_fail["skip_cases_env"] == ""
    _assert_valid_smoke_report(rep_fail)


def test_smoke_cli_resolves_binaries_from_build_json(tmp_path, monkeypatch):
    sidecar = _write_sidecar(tmp_path, "mod_build", dispatch_case_count=2)
    san_bin = _make_fake_bin(tmp_path / "workspace" / "harnesses" / "fuzz_mod_build.san")
    eacsl_bin = _make_fake_bin(tmp_path / "workspace" / "harnesses" / "fuzz_mod_build.e-acsl")
    build_json = tmp_path / "workspace" / "reports" / "fuzz" / "mod_build.build.json"
    build_json.parent.mkdir(parents=True, exist_ok=True)
    build_json.write_text(
        json.dumps(
            {
                "mode": "build",
                "module": "mod_build",
                "status": "built",
                "engine_used": "eacsl",
                "binary": str(eacsl_bin),
                "sanitizer_compile": {"returncode": 0, "binary": str(san_bin)},
            }
        ),
        encoding="utf-8",
    )
    out_json = tmp_path / "workspace" / "reports" / "smoke" / "mod_build.json"
    seen_bins: list[str] = []

    def fake_run(argv, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        seen_bins.append(Path(argv[0]).name)
        return SandboxResult(returncode=0, stdout="", stderr="", timed_out=False, sandbox="rlimits", command=list(argv))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake_run)
    rc = HS.main(
        [
            "run",
            "--module",
            "mod_build",
            "--build-json",
            str(build_json),
            "--sidecar",
            str(sidecar),
            "--out-json",
            str(out_json),
            "--timeout",
            "5",
        ]
    )
    assert rc == 0
    assert "fuzz_mod_build.san" in seen_bins
    assert "fuzz_mod_build.e-acsl" in seen_bins
    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert report["status"] == "ok"
    assert report["startup"]["engines_checked"] == ["sanitizers", "eacsl"]
    _assert_valid_smoke_report(report)


def test_smoke_schema_rejects_malformed_reports():
    valid = {
        "schema_version": 1,
        "module": "m",
        "harness_digest": "a" * 64,
        "status": "ok",
        "startup": {
            "ok": True,
            "engines_checked": ["sanitizers"],
            "failing_engine": None,
            "reason": None,
            "stack_trace": None,
            "results": {},
        },
        "quarantined_cases": [],
        "case_results": [],
        "skip_cases_env": "",
        "wall_s": 0.1,
    }
    assert minischema.validate(valid, _SMOKE_SCHEMA) == []

    bad_status = {**valid, "status": "bogus"}
    assert minischema.validate(bad_status, _SMOKE_SCHEMA)

    bad_digest = {**valid, "harness_digest": "not-a-sha256"}
    assert minischema.validate(bad_digest, _SMOKE_SCHEMA)

    bad_skip = {**valid, "skip_cases_env": "1,abc"}
    assert minischema.validate(bad_skip, _SMOKE_SCHEMA)

    extra_prop = {**valid, "unexpected_key": 123}
    assert minischema.validate(extra_prop, _SMOKE_SCHEMA)
