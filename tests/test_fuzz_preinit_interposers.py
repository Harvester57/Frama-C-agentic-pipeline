"""Target code that replaces libc or runs before main must not break the fuzz driver (sudo run-1).

Bug A: a module defining the functions libFuzzer starts its worker processes with (sudo_noexec.c's
`system`/`execve`, sudo_intercept.c's) ended both engines' multi-process campaigns at once as
`fuzzer_error`. Bug B: an E-ACSL binary crashed in `shadow_alloca` when target constructors, or an
instrumented `getenv` a shared library's constructor calls, ran before LLVMFuzzerInitialize set the
runtime up.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

import fuzz_build
import run_eacsl_fuzz as R
import sandbox_exec
from generate_harness import _build_invocations
from sandbox_exec import SandboxResult

FPI_REPO = Path(__file__).resolve().parent.parent
FPI_FUZZ_INIT = FPI_REPO / "templates" / "eacsl_runtime" / "fuzz_init.c"
FPI_CASES = ["(void)fuzz_buf;", "(void)fuzz_len;", "(void)0;"]
# `nm --defined-only` of run-1's fuzz_sudo_noexec_so (ASan+UBSan build), launcher lines: the target's own
# strong definitions, and the sanitizer runtime's interceptors (weak, with `__interceptor_` siblings).
FPI_NM_NOEXEC = (
    "00000000000dd940 T ___interceptor_popen\n"
    "00000000000997d0 T ___interceptor_posix_spawn\n"
    "0000000000119f14 T ___interceptor_vfork\n"
    "00000000000dd940 W __interceptor_popen\n"
    "00000000000997d0 W __interceptor_posix_spawn\n"
    "0000000000119f14 W __interceptor_vfork\n"
    "000000000014ade8 T execl\n"
    "000000000014b108 T execve\n"
    "000000000014b4c8 T popen\n"
    "000000000014b2e8 T posix_spawn\n"
    "000000000014b428 T system\n"
    "0000000000119f49 W vfork\n"
    "0000000000001130 T LLVMFuzzerTestOneInput\n"
)
# The same lines of run-1's fuzz_cvtsudoers, which replaces no libc function: interceptors only.
FPI_NM_PLAIN_ASAN = (
    "000000000018ce60 T ___interceptor_popen\n"
    "0000000000148cf0 T ___interceptor_posix_spawn\n"
    "00000000001c9434 T ___interceptor_vfork\n"
    "000000000018ce60 W __interceptor_popen\n"
    "0000000000148cf0 W __interceptor_posix_spawn\n"
    "00000000001c9434 W __interceptor_vfork\n"
    "000000000013097b W popen\n"
    "0000000000130372 W posix_spawn\n"
    "00000000001c9469 W vfork\n"
)
FPI_NM_OUTPUT = (
    "0000000000001130 T LLVMFuzzerTestOneInput\n"
    "0000000000001250 W system\n"
    "0000000000001290 t popen\n"
    "00000000000012a0 T system_checked\n"
    "0000000000004010 B popen_mode\n"
    "0000000000001300 T execve\n"
)
# libFuzzer -jobs output when system() cannot start a single worker (sudo_noexec_so, run-1).
FPI_JOBS_NEVER_STARTED = (
    "INFO: Running with entropic power schedule (0xFF, 100).\n"
    "fuzz_mod -max_total_time=30 corpus >fuzz-0.log 2>&1\n"
    "================== Job 0 exited with exit code -1 ============\n"
    "================== Job 1 exited with exit code -1 ============\n"
)
# libFuzzer -fork output when the inner process never ran (sudo_intercept_so, run-1).
FPI_FORK_NEVER_STARTED = (
    "INFO: -fork=2: fuzzing in separate process(s)\n"
    "fuzz_mod: intercept port not set\n"
    "INFO: log from the inner process:\n"
    "INFO: exiting: 127 time: 0s\n"
)
FPI_RAN_INPUTS = (
    "#2\tINITED cov: 12 ft: 13 corp: 1/1b exec/s: 0 rss: 30Mb\n"
    "#4096\tpulse  cov: 12 ft: 13 corp: 1/1b lim: 4 exec/s: 2048 rss: 30Mb\n"
    "Done 9000 runs in 3 second(s)\n"
    "stat::number_of_executed_units: 9000\n"
)


def _fake_sandbox(monkeypatch, outputs: list[tuple[int, str]]) -> list[list[str]]:
    """run_sandboxed returning `outputs` in turn (returncode, stderr); records each command."""
    calls: list[list[str]] = []

    def fake(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        calls.append(list(cmd))
        rc, err = outputs[min(len(calls), len(outputs)) - 1]
        return SandboxResult(rc, "", err, False, "rlimits", list(cmd))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    return calls


def _binary(tmp_path: Path) -> Path:
    binary = tmp_path / "fuzz_mod"
    binary.write_bytes(b"\x7fELF")
    return binary


def _multi_process_flags(cmd: list[str]) -> list[str]:
    return [a for a in cmd if a.startswith(("-fork=", "-jobs=", "-workers=", "-ignore_crashes="))]


# --- Bug A: which link defines the process launchers ----------------------------------------------


def test_nm_output_names_the_launchers_libfuzzer_uses_that_the_target_replaced():
    # libFuzzer starts its processes with system() (and popen); exec*/posix_spawn the target replaces do
    # not reach it (glibc's system() spawns internally), and the no-input rerun catches anything else.
    assert R.parse_defined_process_launchers(FPI_NM_NOEXEC) == ["popen", "system"]
    # A sanitizer build defines popen as a weak interceptor: no replacement, every worker still starts.
    assert R.parse_defined_process_launchers(FPI_NM_PLAIN_ASAN) == []
    # A global definition counts (a weak one without interceptor too), a static one or a data symbol does not.
    assert R.parse_defined_process_launchers(FPI_NM_OUTPUT) == ["system"]
    assert R.parse_defined_process_launchers("") == []


def test_defined_process_launchers_runs_nm_on_the_binary_and_is_none_when_nm_fails(tmp_path):
    seen: list[list[str]] = []

    def runner(cmd, **kwargs):
        seen.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout=FPI_NM_OUTPUT, stderr="")

    binary = _binary(tmp_path)
    assert R.defined_process_launchers(binary, runner=runner) == ["system"]
    assert seen[0][0] == "nm" and "--defined-only" in seen[0] and seen[0][-1] == str(binary)

    def broken(cmd, **kwargs):
        raise OSError("nm: not found")

    assert R.defined_process_launchers(binary, runner=broken) is None
    failing = lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad file")  # noqa: E731
    assert R.defined_process_launchers(binary, runner=failing) is None


def test_libfuzzer_output_says_whether_any_input_ran():
    assert not R.libfuzzer_executed_inputs(FPI_JOBS_NEVER_STARTED)
    assert not R.libfuzzer_executed_inputs(FPI_FORK_NEVER_STARTED)
    assert R.libfuzzer_executed_inputs(FPI_RAN_INPUTS)
    # Fork mode's progress lines.
    assert R.libfuzzer_executed_inputs("#5298767: cov: 254 ft: 1129 corp: 461 exec/s: 47821 time: 17s job: 12\n")
    assert not R.libfuzzer_executed_inputs("stat::number_of_executed_units: 0\n")


# --- Bug A: the campaign runs single-process -----------------------------------------------------


def test_a_binary_defining_system_is_fuzzed_single_process_from_the_start(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "defined_process_launchers", lambda binary, **kw: ["popen", "system"])
    calls = _fake_sandbox(monkeypatch, [(0, FPI_RAN_INPUTS)])
    for fork in (True, False):
        calls.clear()
        res = R.run_fuzz_campaign(_binary(tmp_path), tmp_path / "corpus", tmp_path / "arts", 30, workers=4, fork=fork)
        assert len(calls) == 1 and _multi_process_flags(calls[0]) == []
        # NEW_FUNC lines are symbolized by a child process too (sudo_noexec's seccomp filter denies execve).
        assert "-print_funcs=0" in calls[0]
        assert res["status"] == "clean" and "fork" not in res
        assert "system" in res["single_process_reason"] and "popen" in res["single_process_reason"]
        assert res["workers_used"] == 1


def test_a_multi_process_campaign_whose_workers_never_start_is_retried_single_process(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "defined_process_launchers", lambda binary, **kw: [])
    for fork, never in ((False, FPI_JOBS_NEVER_STARTED), (True, FPI_FORK_NEVER_STARTED)):
        calls = _fake_sandbox(monkeypatch, [(1, never), (0, FPI_RAN_INPUTS)])
        res = R.run_fuzz_campaign(_binary(tmp_path), tmp_path / "corpus", tmp_path / "arts", 30, workers=4, fork=fork)
        assert len(calls) == 2
        assert _multi_process_flags(calls[0]) != [] and _multi_process_flags(calls[1]) == []
        assert "-print_funcs=0" in calls[1]
        assert res["status"] == "clean" and res["workers_used"] == 1
        assert "before any input ran" in res["single_process_reason"]
        assert res["multi_process_attempt"]["returncode"] == 1
        assert "exit" in res["multi_process_attempt"]["log_tail"]


def test_a_multi_process_campaign_that_ran_inputs_or_was_asked_single_is_never_retried(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "defined_process_launchers", lambda binary, **kw: [])
    calls = _fake_sandbox(monkeypatch, [(1, FPI_RAN_INPUTS)])
    res = R.run_fuzz_campaign(_binary(tmp_path), tmp_path / "corpus", tmp_path / "arts", 30, workers=4)
    assert len(calls) == 1 and res["status"] == "fuzzer_error" and "single_process_reason" not in res
    calls = _fake_sandbox(monkeypatch, [(1, FPI_JOBS_NEVER_STARTED)])
    res = R.run_fuzz_campaign(_binary(tmp_path), tmp_path / "corpus", tmp_path / "arts", 30, workers=1)
    assert len(calls) == 1 and "single_process_reason" not in res


def test_a_campaign_still_failing_single_process_says_the_workers_were_not_the_cause(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "defined_process_launchers", lambda binary, **kw: [])
    _fake_sandbox(monkeypatch, [(1, FPI_JOBS_NEVER_STARTED), (1, "ERROR: startup crash\n")])
    res = R.run_fuzz_campaign(_binary(tmp_path), tmp_path / "corpus", tmp_path / "arts", 30, workers=4)
    assert res["status"] == "fuzzer_error" and "single_process_reason" in res
    assert any("single-process" in line for line in res["error_summary"])


def test_a_given_single_process_reason_skips_the_multi_process_attempt(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "defined_process_launchers", lambda binary, **kw: [])
    calls = _fake_sandbox(monkeypatch, [(0, FPI_RAN_INPUTS)])
    res = R.run_fuzz_campaign(
        _binary(tmp_path),
        tmp_path / "corpus",
        tmp_path / "arts",
        30,
        workers=4,
        fork=True,
        single_process_reason="earlier round",
    )
    assert len(calls) == 1 and _multi_process_flags(calls[0]) == []
    assert res["single_process_reason"] == "earlier round"


def test_fuzz_binaries_run_with_sigpipe_ignored_so_a_crash_survives_a_symbolizer_that_cannot_start(
    tmp_path, monkeypatch
):
    # sudo_noexec's seccomp filter denies execve: the symbolizer never starts, and the first write to its
    # pipe killed the fuzzer (rc -13) before the crash input was saved.
    import crash_replay

    monkeypatch.setattr(R, "defined_process_launchers", lambda binary, **kw: [])
    seen: list[object] = []

    def fake(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        seen.append(limits)
        return SandboxResult(0, "", FPI_RAN_INPUTS, False, "rlimits", list(cmd))

    monkeypatch.setattr(sandbox_exec, "run_sandboxed", fake)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)
    R.run_fuzz_campaign(_binary(tmp_path), tmp_path / "corpus", tmp_path / "arts", 30, workers=4)
    crash = tmp_path / "crash-1"
    crash.write_bytes(b"x")
    crash_replay.replay_artifact(_binary(tmp_path), crash, tmp_path / "scratch")
    assert len(seen) == 2 and all(getattr(lim, "ignore_sigpipe", False) for lim in seen)


def test_the_sandbox_preexec_ignores_sigpipe_only_when_asked(monkeypatch):
    pytest.importorskip("resource")
    import signal

    import sandbox_exec as S

    monkeypatch.setattr("resource.setrlimit", lambda which, value: None)
    calls: list[tuple] = []
    monkeypatch.setattr(signal, "signal", lambda sig, handler: calls.append((sig, handler)))
    S._make_preexec(S.Limits())()
    assert calls == []
    S._make_preexec(S.Limits(ignore_sigpipe=True))()
    assert calls == [(signal.SIGPIPE, signal.SIG_IGN)]


# --- Bug A: what the keep-going report says ------------------------------------------------------


def test_rounds_record_the_single_process_reason_and_the_cpu_really_spent():
    def campaign(binary, seconds, fork, **kwargs):
        return {"status": "clean", "returncode": 0, "artifacts": [], "single_process_reason": "defines system"}

    res = R.run_campaign_rounds(Path("b"), 30, campaign=campaign, rebuild=None, n_cases=3, workers=9)
    kg = res["keep_going"]
    assert kg["single_process_reason"] == "defines system" and kg["workers"] == 1
    assert kg["cpu_seconds_spent"] == kg["fuzz_seconds"]
    res = R.run_campaign_rounds(Path("b"), 30, campaign=campaign, rebuild=None, n_cases=None, workers=9)
    # Without fork mode a single process stops at its first crash.
    assert res["keep_going"] == {
        "mode": "fork",
        "single_process_reason": "defines system",
        "stops_at_first_crash": True,
    }


def test_merged_engines_keep_each_engines_single_process_reason():
    runs = {
        "sanitizers": {"status": "clean", "returncode": 0, "artifacts": [], "single_process_reason": "defines system"},
        "eacsl": {"status": "clean", "returncode": 0, "artifacts": []},
    }
    out = R.merge_engine_campaigns(runs)
    assert out["engines"]["sanitizers"]["single_process_reason"] == "defines system"
    assert "single_process_reason" not in out["engines"]["eacsl"]


def _dispatch_harness(tmp_path: Path) -> Path:
    _, fuzz = _build_invocations("f", "dispatch", dispatch_cases=FPI_CASES)
    path = tmp_path / "harness_mod.c"
    path.write_text(
        "#include <stddef.h>\n#include <stdint.h>\n"
        "#ifndef FRAMAC_FUZZ_REJECT\n#define FRAMAC_FUZZ_REJECT() ((void)0)\n#endif\n"
        f"int run(uint8_t *fuzz_buf, size_t fuzz_len) {{\n    {fuzz}\n    return 0;\n}}\n",
        encoding="utf-8",
    )
    return path


def test_an_engine_decides_single_process_once_and_keeps_it_for_every_round(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src.c").write_text("int f(void) { return 0; }\n", encoding="utf-8")
    harness = _dispatch_harness(tmp_path)
    monkeypatch.setattr(R, "enforced_memory_mb", lambda: None)

    def fake_build(sources, out_bin, **opts):
        return {
            "compile": {"returncode": 0, "binary": str(tmp_path / "bin.sanitizers")},
            "engine_used": "sanitizers",
            "engine_fallback_reason": None,
            "eacsl_compile_attempt": None,
        }

    seen: list[str | None] = []

    def fake_campaign(binary, corpus, artifacts, max_time, *a, single_process_reason=None, **k):
        seen.append(single_process_reason)
        arts = []
        if len(seen) == 1:
            crash = tmp_path / "crash-0"
            crash.write_bytes(b"\x00abc")
            arts = [{"artifact": str(crash), "kind": "crash", "sha256": "00", "fingerprint": "fp0"}]
        return {
            "status": "crash_found" if arts else "clean",
            "returncode": 1 if arts else 0,
            "artifacts": arts,
            "single_process_reason": single_process_reason or "the binary defines system",
        }

    monkeypatch.setattr(fuzz_build, "build_module_binary", fake_build)
    monkeypatch.setattr(R, "run_fuzz_campaign", fake_campaign)
    out_json = tmp_path / "out.json"
    argv = ["campaign", "--module", "mod", "--sources", "src.c", str(harness), "--out-bin", "fuzz_mod"]
    argv += ["--corpus-dir", "corpus", "--artifacts-dir", "crashes", "--workers", "4", "--max-time", "100"]
    argv += ["--no-cache", "--no-attribution-replay", "--no-auto-dict", "--engine", "sanitizers"]
    argv += ["--out-json", str(out_json)]
    R.main(argv)
    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert len(seen) >= 2 and seen[0] is None and all(s == "the binary defines system" for s in seen[1:])
    assert report["keep_going"]["single_process_reason"] == "the binary defines system"
    assert report["keep_going"]["workers"] == 1


# --- Bug B: the E-ACSL runtime is up before any target code runs ---------------------------------


def _strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def test_fuzz_init_sets_the_runtime_up_from_the_executables_preinit_array():
    src = _strip_comments(FPI_FUZZ_INIT.read_text(encoding="utf-8"))
    # An entry in .preinit_array runs before every shared library's constructor (libcrypto calling an
    # instrumented getenv) and before the executable's own constructors (noexec_ctor, sudo_interposer_init).
    entry = re.search(
        r'__attribute__\(\(\s*section\("\.preinit_array"\)\s*,\s*used\s*\)\)\s*static\s+void\s*'
        r"\(\*\s*const\s+\w+\)\(int,\s*char\s*\*\*,\s*char\s*\*\*\)\s*=\s*(\w+);",
        src,
    )
    assert entry, "fuzz_init.c has no .preinit_array entry"
    preinit = entry.group(1)
    body = re.search(rf"static void {preinit}\(int argc, char \*\*argv, char \*\*envp\)\s*\{{(.*?)\n\}}", src, re.S)
    assert body, f"{preinit} not defined with the (argc, argv, envp) preinit signature"
    # libc has not set `environ` yet at preinit; the runtime reads the stack's end from it.
    assert "environ = envp" in body.group(1)
    # argc/argv the runtime registers must outlive the preinit call: static storage, not its frame.
    assert re.search(r"static int \w+;", src) and re.search(r"static char \*\*\w+;", src)
    # LLVMFuzzerInitialize still sets the runtime up when the preinit entry did not run (run once).
    init = re.search(r"int LLVMFuzzerInitialize\(int \*argc, char \*\*\*argv\)\s*\{(.*?)\n\}", src, re.S)
    assert init and "__e_acsl_memory_init" not in init.group(1)
    runtime_init = re.search(r"static void (\w+)\(int \*argc, char \*\*\*argv\)\s*\{(.*?)\n\}", src, re.S)
    assert runtime_init and runtime_init.group(1) in init.group(1) and runtime_init.group(1) in body.group(1)
    once = runtime_init.group(2)
    assert "if (__fc_eacsl_runtime_ready)" in once and "return;" in once
    assert "__e_acsl_memory_init(argc, argv, sizeof(void *))" in once
    assert "__e_acsl_globals_init()" in once and "__fc_eacsl_runtime_ready = 1;" in once
    # The runtime's argv_alloca advances `environ` to its end: it is put back.
    assert re.search(r"char \*\*(\w+) = environ;.*environ = \1;", once, re.S)


class _FpiFakeEacslGcc:
    """Both e-acsl-gcc stages and the shim compiles, recording each command."""

    def __init__(self, stage2_error=None) -> None:
        self.calls: list[list[str]] = []
        # cmd -> linker stderr that fails this stage 2, or None.
        self.stage2_error = stage2_error

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if cmd[0] == "clang" and "-c" in cmd:
            Path(cmd[cmd.index("-o") + 1]).write_bytes(b"obj")
        elif "-C" in cmd:
            error = self.stage2_error(cmd) if self.stage2_error else None
            if error:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=error)
            out = Path(cmd[cmd.index("-O") + 1])
            out.write_bytes(b"plain build")
            out.with_name(out.name + ".e-acsl").write_bytes(b"\x7fELF...__e_acsl_assert...eacsl_store_block")
        else:
            Path(cmd[cmd.index("-o") + 1]).write_text("int f(void) { return 0; }\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


def test_the_eacsl_build_record_says_the_runtime_is_set_up_at_preinit(tmp_path, monkeypatch):
    import eacsl_toolchain as T

    monkeypatch.setattr(fuzz_build, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))
    monkeypatch.setattr(T.shutil, "which", lambda name: None)
    src = tmp_path / "mod.c"
    src.write_text("int entry(int x) { return x; }\n", encoding="utf-8")
    fake = _FpiFakeEacslGcc()
    res = R.compile_eacsl_binary([str(src)], tmp_path / "out" / "fuzz_mod", runner=fake)
    assert res["returncode"] == 0, res
    assert res["runtime_init"] == {
        "hook": "preinit_array",
        "source": res["init_hook"],
        "fallback": "LLVMFuzzerInitialize",
    }


# Library-owned globals (sudo run-1: tf_fuzz_iolog_json, libsudo_util_so_0_0_0, ... crashed in
# `__e_acsl_globals_init` on `__e_acsl_store_block((void *)(& __progname),8UL)`): in a PIE that address is
# libc's, outside every segment the runtime shadows. A position-dependent link copies the data into the
# executable's own globals (R_X86_64_COPY), decided by the linker for every library-owned object.

# `readelf -rW` of a position-dependent binary referencing environ and __progname (x86_64, glibc 2.39).
FPI_READELF_NON_PIE = (
    "\n"
    "Relocation section '.rela.dyn' at offset 0x6d8 contains 4 entries:\n"
    "    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend\n"
    "0000000000403fd8  0000000200000006 R_X86_64_GLOB_DAT      0000000000000000 __libc_start_main@GLIBC_2.34 + 0\n"
    "0000000000403fe0  0000000400000006 R_X86_64_GLOB_DAT      0000000000000000 __gmon_start__ + 0\n"
    "0000000000404040  0000000700000005 R_X86_64_COPY          0000000000404040 __progname@GLIBC_2.2.5 + 0\n"
    "0000000000404048  0000000800000005 R_X86_64_COPY          0000000000404048 environ@GLIBC_2.2.5 + 0\n"
    "\n"
    "Relocation section '.rela.plt' at offset 0x738 contains 1 entry:\n"
    "    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend\n"
    "0000000000404000  0000000300000007 R_X86_64_JUMP_SLOT     0000000000000000 strlen@GLIBC_2.2.5 + 0\n"
)
FPI_PROTECTED_COPY_ERROR = (
    "/usr/bin/ld: /tmp/fuzz_mod-1a2b.o: copy relocation against non-copyable protected symbol `lib_table' "
    "in libtable.so\nclang: error: linker command failed with exit code 1 (use -v to see invocation)\n"
)


def _fpi_eacsl_build(tmp_path: Path, monkeypatch, fake: _FpiFakeEacslGcc) -> dict:
    import eacsl_toolchain as T

    monkeypatch.setattr(fuzz_build, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))
    monkeypatch.setattr(T.shutil, "which", lambda name: None)
    src = tmp_path / "mod.c"
    src.write_text("extern const char *__progname;\nint entry(void) { return __progname[0]; }\n", encoding="utf-8")
    return R.compile_eacsl_binary([str(src)], tmp_path / "out" / "fuzz_mod", runner=fake, use_cache=False)


def _fpi_stage2(fake: _FpiFakeEacslGcc) -> list[list[str]]:
    return [c for c in fake.calls if c[0] == "e-acsl-gcc" and "-C" in c]


def test_fuzz_init_registers_the_environment_pointer_array_the_runtime_leaves_out():
    # E-ACSL's argv_alloca registers each environment string, never the array of pointers to them:
    # walking `environ` in target code failed `\initialized(e)` on its first element.
    body = _strip_comments(FPI_FUZZ_INIT.read_text(encoding="utf-8"))
    init = body[body.index("static void fc_eacsl_runtime_init(") : body.index("static void fc_eacsl_preinit(")]
    memory_init = init.index("__e_acsl_memory_init(argc, argv")
    store = init.index("__e_acsl_store_block(fc_env, (fc_env_count + 1) * sizeof(char *));")
    initialize = init.index("__e_acsl_initialize(fc_env, (fc_env_count + 1) * sizeof(char *));")
    assert memory_init < store < initialize < init.index("__e_acsl_globals_init();")


def test_readelf_copy_relocations_name_the_library_globals_the_executable_owns():
    assert fuzz_build.parse_copy_relocations(FPI_READELF_NON_PIE) == ["__progname", "environ"]
    # A PIE has no copy relocation: its library data stays in the library.
    pie = FPI_READELF_NON_PIE.replace("R_X86_64_COPY ", "R_X86_64_GLOB_DAT")
    assert fuzz_build.parse_copy_relocations(pie) == []


def test_the_eacsl_binary_is_linked_position_dependent_so_library_globals_are_copied_in(tmp_path, monkeypatch):
    monkeypatch.setattr(fuzz_build, "copied_library_globals", lambda binary: ["__progname", "environ"])
    fake = _FpiFakeEacslGcc()
    res = _fpi_eacsl_build(tmp_path, monkeypatch, fake)
    assert res["returncode"] == 0, res
    (stage2,) = _fpi_stage2(fake)
    assert "-fno-pie" in stage2[stage2.index("-e") + 1].split()
    assert stage2[stage2.index("-l") + 1].split()[-1] == "-no-pie"
    # Nothing is left out of tracking: the record lists what the linker copied into the executable.
    assert res["position_dependent"] == {
        "pie": False,
        "compile": "-fno-pie",
        "link": "-no-pie",
        "copied_library_globals": ["__progname", "environ"],
    }


def test_a_link_that_cannot_be_position_dependent_falls_back_to_a_pie_and_says_why(tmp_path, monkeypatch):
    fake = _FpiFakeEacslGcc(stage2_error=lambda cmd: FPI_PROTECTED_COPY_ERROR if "-no-pie" in " ".join(cmd) else None)
    res = _fpi_eacsl_build(tmp_path, monkeypatch, fake)
    assert res["returncode"] == 0, res
    first, second = _fpi_stage2(fake)
    assert "-no-pie" in first[first.index("-l") + 1] and "-fno-pie" in first[first.index("-e") + 1]
    assert "-no-pie" not in " ".join(second) and "-fno-pie" not in " ".join(second)
    record = res["position_dependent"]
    assert record["pie"] is True and record["compile"] is None and record["link"] is None
    assert "non-copyable protected symbol `lib_table'" in record["fallback_reason"]
    assert "copied_library_globals" not in record
    assert "linking a PIE" in Path(res["compile_log"]).read_text(encoding="utf-8")


def test_an_unrelated_link_error_keeps_the_binary_position_dependent(tmp_path, monkeypatch):
    error = "/usr/bin/ld: fuzz_mod.o: undefined reference to `missing_fn'\n"
    fake = _FpiFakeEacslGcc(stage2_error=lambda cmd: error)
    res = _fpi_eacsl_build(tmp_path, monkeypatch, fake)
    assert res["returncode"] != 0
    (stage2,) = _fpi_stage2(fake)
    assert "-no-pie" in stage2[stage2.index("-l") + 1]
    assert res["position_dependent"]["pie"] is False and "fallback_reason" not in res["position_dependent"]


# Two units: the harness, and a module reading libc's `environ` and `__progname` (a PIE build crashed in
# __e_acsl_globals_init registering them, before any input ran).
FPI_LIBC_GLOBALS_HARNESS = """#include <stddef.h>
#include <stdint.h>
#include <string.h>

size_t fpi_env_weight(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned char buf[8];
  size_t n = size < sizeof buf ? size : sizeof buf;
  if (n == 0)
    return 0;
  memcpy(buf, data, n);
  return (int)((fpi_env_weight() + buf[0]) & 0u);
}
"""
FPI_LIBC_GLOBALS_MODULE = """#include <stddef.h>

extern char **environ;
extern const char *__progname;

size_t fpi_env_weight(void) {
  size_t n = 0;
  if (__progname != NULL && __progname[0] != '\\0')
    n++;
  for (char **e = environ; e != NULL && *e != NULL; e++)
    n++;
  return n;
}
"""
FPI_LIBC_GLOBALS_DRIVER = """import json, sys
from pathlib import Path
sys.path.insert(0, "/opt/framac-pipeline/scripts")
import fuzz_build
res = fuzz_build.compile_eacsl_binary(["harness.c", "module.c"], Path("/w/out/fuzz_fpi"), use_cache=False)
keep = ("returncode", "binary", "position_dependent", "runtime_init", "compile_log")
Path("/w/build.json").write_text(json.dumps({k: res.get(k) for k in keep}), encoding="utf-8")
"""


@pytest.mark.integration
@pytest.mark.slow
def test_an_eacsl_binary_reading_libc_globals_starts_and_runs_inputs(tmp_path):
    import os

    from conftest import ANALYSIS_IMAGE, require_docker_images

    require_docker_images(ANALYSIS_IMAGE)
    files = {
        "harness.c": FPI_LIBC_GLOBALS_HARNESS,
        "module.c": FPI_LIBC_GLOBALS_MODULE,
        "driver.py": FPI_LIBC_GLOBALS_DRIVER,
    }
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    script = (
        "cd /w && timeout 900 python3 driver.py > driver.log 2>&1; echo driver=$?; "
        'B=$(python3 -c \'import json; print(json.load(open("build.json"))["binary"])\'); '
        'mkdir -p corpus && printf "abc" > corpus/a && '
        'timeout 120 "$B" -runs=200 -seed=1 corpus > run.log 2>&1; echo run=$?'
    )
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "--label", os.environ.get("FPI_DOCKER_LABEL", "framac.test=test_fuzz_preinit_interposers"),
            "-v", f"{tmp_path}:/w",
            "-v", f"{FPI_REPO / 'scripts'}:/opt/framac-pipeline/scripts:ro",
            "-v", f"{FPI_REPO / 'templates'}:/opt/framac-pipeline/templates:ro",
            "-v", f"{FPI_REPO / 'schemas'}:/opt/framac-pipeline/schemas:ro",
            "--entrypoint", "bash", ANALYSIS_IMAGE, "-c", script,
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200, check=False,
    )  # fmt: skip
    log = proc.stdout + proc.stderr
    driver_log = (tmp_path / "driver.log").read_text(encoding="utf-8", errors="replace")
    assert "driver=0" in log, (log, driver_log)
    build = json.loads((tmp_path / "build.json").read_text(encoding="utf-8"))
    assert build["returncode"] == 0, build
    assert build["position_dependent"]["pie"] is False, build
    copied = set(build["position_dependent"]["copied_library_globals"])
    # glibc's `environ` is an alias of `__environ`; readelf names the relocation after either.
    assert "__progname" in copied and copied & {"environ", "__environ"}, build
    run_log = (tmp_path / "run.log").read_text(encoding="utf-8", errors="replace")
    assert "run=0" in log, run_log
    assert "__e_acsl_globals_init" not in run_log and "Done 200 runs" in run_log, run_log
