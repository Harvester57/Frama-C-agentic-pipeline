"""Tests for the E-ACSL toolchain contract (round 3: run-4 E-ACSL lessons learned)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

import eacsl_toolchain as T
import ledger
import run_eacsl_fuzz as R
from framac_common import scan_undeclared_functions
from sandbox_exec import SandboxResult

REPO = Path(__file__).resolve().parent.parent
EACSL_MARKER_BYTES = b"\x7fELF...__e_acsl_assert...eacsl_store_block"


def _cp(cmd, rc=0, out="", err=""):
    return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr=err)


# ---------------------------------------------------------------------------
# WS1.2 passthrough normalizer
# ---------------------------------------------------------------------------


def test_normalizer_rewrites_g_and_joins_short_options():
    assert T.normalize_passthrough("-fsanitize=fuzzer -g -O1") == "-fsanitize=fuzzer -gline-tables-only -O1"
    assert T.normalize_passthrough("-I dir -D FOO=1 -l bsd -L /opt/lib") == "-Idir -DFOO=1 -lbsd -L/opt/lib"
    assert T.normalize_passthrough("-include stub.h -g3") == "-include stub.h -g3"


@pytest.mark.parametrize("value", ["-c", "-O1 -o out", "'-I/a b/c'", "-I 'a b'", "-I"])
def test_normalizer_rejects_unsafe_tokens(value):
    with pytest.raises(T.UnsafePassthroughError):
        T.normalize_passthrough(value)


# ---------------------------------------------------------------------------
# WS1.1 frontend / backend split
# ---------------------------------------------------------------------------


def test_flag_sets_keep_preprocessor_flags_on_frontend_only(tmp_path):
    stubs = tmp_path / "fc_stubs"
    stubs.mkdir()
    flags = T.build_eacsl_flag_sets(
        "-Isrc -include workspace/stubs/net.h -DFOO -std=gnu99 -fcommon",
        fuzzer=True,
        fc_stubs=stubs,
    )
    front, back = flags["frontend"].split(), flags["backend"].split()
    assert front[:2] == ["-D__FRAMAC_EACSL__", "-D_Float128=double"]
    stubs_flag = f"-I{stubs.as_posix()}"
    assert front.index(stubs_flag) < front.index("-Isrc"), "fc_stubs must precede target include dirs"
    assert f"{stubs.as_posix()}/fc_compat_types.h" in front
    assert "workspace/stubs/net.h" in front and "-DFOO" in front and "-std=gnu99" in front
    assert not any(t.startswith(("-I", "-D")) or t == "-include" for t in back)
    assert back[:2] == ["-fsanitize=fuzzer", "-gline-tables-only"]
    assert "-g" not in back and "-std=gnu99" in back


def test_flag_sets_reject_paths_with_spaces(tmp_path):
    with pytest.raises(T.UnsafePassthroughError):
        T.build_eacsl_flag_sets("-I '/my src'", fc_stubs=None)


# ---------------------------------------------------------------------------
# WS1 two-stage compile, binary selection and instrumentation invariant
# ---------------------------------------------------------------------------


class FakeEacslGcc:
    """Simulates e-acsl-gcc stages and records the calls."""

    def __init__(
        self,
        instrumented_text="int f(void) { return 0; }\n",
        instrumented=True,
        stage1_failures=None,
        stage2_failures=None,
    ):
        self.calls: list[list[str]] = []
        self.instrumented_text = instrumented_text
        self.instrumented = instrumented
        self.stage1_failures = list(stage1_failures or [])
        self.stage2_failures = list(stage2_failures or [])

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if cmd[0] == "clang" and "-c" in cmd:
            Path(cmd[cmd.index("-o") + 1]).write_bytes(b"obj")
            return _cp(cmd)
        if "-C" in cmd:
            if self.stage2_failures:
                return _cp(cmd, 1, "", self.stage2_failures.pop(0))
            out = Path(cmd[cmd.index("-O") + 1])
            out.write_bytes(b"plain build")
            out.with_name(out.name + ".e-acsl").write_bytes(EACSL_MARKER_BYTES if self.instrumented else b"plain")
            return _cp(cmd)
        if self.stage1_failures:
            return _cp(cmd, 1, "", self.stage1_failures.pop(0))
        Path(cmd[cmd.index("-o") + 1]).write_text(self.instrumented_text, encoding="utf-8")
        return _cp(cmd)


@pytest.fixture
def modern_cli(monkeypatch):
    monkeypatch.setattr(R, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))
    monkeypatch.setattr(T.shutil, "which", lambda name: None)  # no clang preprocessing in unit tests


def _src(tmp_path):
    src = tmp_path / "mod.c"
    src.write_text("int entry(int x) { return x; }\n", encoding="utf-8")
    return src


def test_two_stage_compile_routes_flags_and_selects_instrumented_binary(tmp_path, modern_cli):
    fake = FakeEacslGcc()
    res = R.compile_eacsl_binary(
        [str(_src(tmp_path))],
        tmp_path / "out" / "fuzz_mod",
        cppflags="-Isrc -include stub.h",
        ldflags_extra="-lbsd",
        runner=fake,
    )
    assert res["returncode"] == 0, res
    stage1, stage2 = fake.calls
    assert "-E" in stage1 and "-e" not in stage1 and "-C" not in stage1
    # -n: instrument only. Without it e-acsl-gcc also links the original main-less harness and fails.
    assert stage1[1] == "-n"
    fc_flags = stage1[stage1.index("-F") + 1]
    assert "-e-acsl-assert-print-data" in fc_flags and "-e-acsl-full-mtracking" in fc_flags
    assert "-rte-initialized @all" in fc_flags and res["reduced_checks"] == []
    assert "-include stub.h" in stage1[stage1.index("-E") + 1]
    backend = stage2[stage2.index("-e") + 1]
    assert "-C" in stage2 and "-n" not in stage2 and "-E" not in stage2
    assert "-include" not in backend and "-I" not in backend.split()[0]
    assert " -g " not in f" {backend} " and "-gline-tables-only" in backend
    assert stage2[stage2.index("-l") + 1] == "-fsanitize=fuzzer -lbsd"
    # The runtime init hook is linked right before the instrumented file.
    assert stage2[-2].endswith("eacsl_runtime/fuzz_init.c") and res["init_hook"] == stage2[-2]
    assert stage2[-1].endswith("fuzz_mod.instrumented.c")
    assert res["binary"].endswith("fuzz_mod.e-acsl")
    assert res["undeclared_functions"] == []


def test_slice_defining_llvmfuzzerinitialize_is_refused(tmp_path, modern_cli):
    fake = FakeEacslGcc(instrumented_text="int LLVMFuzzerInitialize(int *argc, char ***argv)\n{\n  return 0;\n}\n")
    res = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "fuzz_mod", runner=fake)
    assert res["returncode"] == 1 and res["reason"] == "eacsl_init_hook_conflict"
    assert len(fake.calls) == 1  # stage 2 never runs


def test_init_hook_detection_and_source():
    assert T.defines_fuzzer_initialize("int LLVMFuzzerInitialize(int *argc, char ***argv) {")
    assert not T.defines_fuzzer_initialize("int LLVMFuzzerInitialize(int *argc, char ***argv);")
    hook = T.resolve_fuzz_init_source().read_text(encoding="utf-8")
    assert "int LLVMFuzzerInitialize(int *argc, char ***argv)" in hook
    assert "__e_acsl_memory_init(argc, argv, sizeof(void *));" in hook
    assert "void __e_acsl_globals_init(void) __attribute__((weak));" in hook


WRAPPER_C = """\
int __gen_e_acsl_checksum(uint8_t const *buf, size_t len);

int checksum(uint8_t const *buf, size_t len)
{
  int __retres;
  __e_acsl_store_block((void *)(& __retres),4UL);
  __retres = 0;
  return __retres;
}

int __gen_e_acsl_checksum(uint8_t const *buf,
                          size_t len)
{
  int __retres;
  __e_acsl_store_block((void *)(& __retres),4UL);
  __retres = checksum(buf,
                      len);
  {
    int __gen_e_acsl_initialized_2;
    __gen_e_acsl_initialized_2 = __e_acsl_initialized((void *)(& __retres),sizeof(int));
  }
  return __retres;
}

void __gen_e_acsl_reset(int *p)
{
  reset(p);
  return;
}
"""


def test_contract_wrappers_mark_their_result_initialized():
    patched, n = T.mark_wrapper_results_initialized(WRAPPER_C)
    assert n == 1
    lines = patched.split("\n")
    i = lines.index("                      len);")
    assert lines[i + 1] == "  " + T.WRAPPER_RESULT_INIT  # right after the multi-line call, before any check
    assert patched.count(T.WRAPPER_RESULT_INIT) == 1  # not in the prototype, the user function or a void wrapper
    # Idempotent when run a second time or when upstream Frama-C already emits __e_acsl_initialize.
    assert T.mark_wrapper_results_initialized(patched) == (patched, 0)
    upstream_fixed = WRAPPER_C.replace(
        "                      len);\n",
        "                      len);\n  __e_acsl_initialize((void *)(& __retres),sizeof(int));\n",
    )
    assert T.mark_wrapper_results_initialized(upstream_fixed) == (upstream_fixed, 0)
    assert T.mark_wrapper_results_initialized("int f(void)\n{\n  int __retres;\n  __retres = 1;\n}\n") == (
        "int f(void)\n{\n  int __retres;\n  __retres = 1;\n}\n",
        0,
    )


def test_the_build_patches_wrappers_only_when_uninitialized_reads_are_checked(tmp_path, modern_cli):
    res = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "fuzz_mod", runner=FakeEacslGcc(WRAPPER_C))
    assert res["returncode"] == 0 and res["wrapper_result_inits"] == 1
    assert T.WRAPPER_RESULT_INIT in (tmp_path / "fuzz_mod.instrumented.c").read_text(encoding="utf-8")
    res = R.compile_eacsl_binary(
        [str(_src(tmp_path))], tmp_path / "plain_mod", rte_initialized=False, runner=FakeEacslGcc(WRAPPER_C)
    )
    assert "wrapper_result_inits" not in res
    assert T.WRAPPER_RESULT_INIT not in (tmp_path / "plain_mod.instrumented.c").read_text(encoding="utf-8")


def test_rte_initialized_opt_out_is_recorded(tmp_path, modern_cli):
    fake = FakeEacslGcc()
    res = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "fuzz_mod", rte_initialized=False, runner=fake)
    assert res["returncode"] == 0
    assert "-rte-initialized" not in fake.calls[0][fake.calls[0].index("-F") + 1]
    assert res["reduced_checks"] == ["-no-rte-initialized"]


def test_campaign_cli_threads_no_rte_initialized(tmp_path, monkeypatch):
    seen = {}

    def fake_compile(*a, **k):
        seen.update(k)
        return {
            "engine": "eacsl",
            "returncode": 0,
            "binary": str(tmp_path / "fuzz_mod.e-acsl"),
            "reduced_checks": ["-no-rte-initialized"],
        }

    monkeypatch.setattr(R, "compile_eacsl_binary", fake_compile)
    monkeypatch.setattr(R, "run_fuzz_campaign", lambda *a, **k: {"status": "clean", "artifacts": []})
    monkeypatch.setattr(sys, "argv", _campaign_argv(tmp_path, "--no-rte-initialized"))
    R.main()
    out = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert seen["rte_initialized"] is False and out["reduced_checks"] == ["-no-rte-initialized"]
    assert "reduced checks: -no-rte-initialized" in ledger.fuzz_engine_note(out)


def test_non_fuzzer_build_links_no_init_hook(tmp_path, modern_cli):
    fake = FakeEacslGcc()
    res = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "prog", fuzzer_flag=False, runner=fake)
    assert res["returncode"] == 0 and "init_hook" not in res
    assert not any(a.endswith("fuzz_init.c") for a in fake.calls[-1])


def test_uninstrumented_binary_is_refused(tmp_path, modern_cli):
    res = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "fuzz_mod", runner=FakeEacslGcc(instrumented=False))
    assert res["returncode"] != 0 and res["reason"] == "eacsl_binary_not_instrumented"


def test_unsafe_cppflags_never_reach_eacsl_gcc(tmp_path, modern_cli):
    fake = FakeEacslGcc()
    res = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "fuzz_mod", cppflags="-Isrc -c", runner=fake)
    assert res["returncode"] == 2 and res["reason"] == "eacsl_argv_unsafe"
    assert fake.calls == []


def test_rte_select_retry_drops_unknown_functions(tmp_path, modern_cli):
    fake = FakeEacslGcc(stage1_failures=["[kernel] User Error: no function 'ghost'\n"])
    res = R.compile_eacsl_binary(
        [str(_src(tmp_path))], tmp_path / "fuzz_mod", functions=["entry", "ghost"], runner=fake
    )
    assert res["returncode"] == 0
    assert res["rte_select_dropped"] == ["ghost"]
    retry_flags = fake.calls[1][fake.calls[1].index("-F") + 1]
    assert "ghost" not in retry_flags and "-rte-select entry" in retry_flags


def test_variadic_fallbacks_are_linked_from_a_separate_object(tmp_path, modern_cli):
    instrumented = (
        "typedef unsigned int mode_t;\n"
        "int open_fallback_1(char const *filename, int flags, mode_t mode);\n"
        "int f(char const *p) { int __retres; __retres = open_fallback_1(p, 0, 0); return __retres; }\n"
        "int g(char const *p) { return open_fallback_1(p, 0, 0); }\n"
    )
    fake = FakeEacslGcc(
        instrumented_text=instrumented, stage2_failures=["/usr/bin/ld: x.o: undefined reference to `open_fallback_1'\n"]
    )
    out_bin = tmp_path / "fuzz_mod"
    res = R.compile_eacsl_binary([str(_src(tmp_path))], out_bin, runner=fake)
    assert res["returncode"] == 0, res
    assert res["variadic_fallbacks"] == [{"name": "open_fallback_1", "base": "open", "mode": "forward"}]
    gen = (tmp_path / "fuzz_mod_fallbacks" / "eacsl_fallbacks.c").read_text(encoding="utf-8")
    assert "#include <fcntl.h>" in gen
    assert (
        "int open_fallback_1(char const *filename, int flags, mode_t mode) { return open(filename, flags, mode); }"
        in gen
    )
    final_stage2 = fake.calls[-1]
    assert final_stage2[final_stage2.index("-l") + 1].endswith("eacsl_fallbacks.o")
    # The instrumented source is never modified (fallback numbering stays stable).
    assert out_bin.with_suffix(".instrumented.c").read_text(encoding="utf-8") == instrumented


def test_legacy_cli_also_normalizes(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc.sh", False))
    monkeypatch.setattr(T.shutil, "which", lambda name: None)
    calls = []

    def runner(cmd, **kw):
        calls.append(cmd)
        Path(cmd[cmd.index("-o") + 1]).write_bytes(EACSL_MARKER_BYTES)
        return _cp(cmd)

    res = R.compile_eacsl_binary([str(_src(tmp_path))], tmp_path / "fuzz_mod", runner=runner)
    assert res["returncode"] == 0
    cflag = next(a for a in calls[0] if a.startswith("--cflag="))
    assert " -g " not in f" {cflag[len('--cflag=') :]} "


# ---------------------------------------------------------------------------
# WS2 fallback generation units
# ---------------------------------------------------------------------------


def test_fallback_generation_modes():
    fbs = T.find_variadic_fallbacks(
        "int ioctl_fallback_2(int, unsigned long);\n"
        "char *weird_fallback_1(char const *fmt);\n"
        "void logx_fallback_3(void);\n"
        "int open_fallback_9(char const *p, int f) { return 0; }\n"
    )
    assert [f["name"] for f in fbs] == ["ioctl_fallback_2", "logx_fallback_3", "weird_fallback_1"]
    src, records = T.generate_fallback_source(fbs)
    modes = {r["name"]: r["mode"] for r in records}
    assert modes == {"ioctl_fallback_2": "forward", "logx_fallback_3": "enosys", "weird_fallback_1": "enosys"}
    assert "int ioctl_fallback_2(int a0, unsigned long a1) { return ioctl(a0, a1); }" in src
    assert "void *weird_fallback_1() { errno = ENOSYS; return 0; }" in src
    assert "void logx_fallback_3() { errno = ENOSYS; }" in src
    forced_src, forced = T.generate_fallback_source(fbs, force_enosys=True)
    assert all(r["mode"] == "enosys" for r in forced) and "return ioctl(" not in forced_src


def test_link_and_frama_c_log_parsers():
    assert T.parse_undefined_fallbacks(
        "undefined reference to `open_fallback_1'\nundefined reference to 'open_fallback_1'"
    ) == ["open_fallback_1"]
    assert T.parse_missing_functions("no function 'a'\nfunction 'b' not found") == ["a", "b"]


# ---------------------------------------------------------------------------
# WS5 preprocessed function discovery
# ---------------------------------------------------------------------------


def test_discovery_uses_preprocessed_source(tmp_path, monkeypatch):
    src = tmp_path / "mod.c"
    src.write_text("#if 0\nint disabled(void) { return 1; }\n#endif\nint live(void) { return 0; }\n", encoding="utf-8")
    pre = (
        '# 1 "/usr/include/hdr.h"\nstatic int from_header(void) { return 2; }\n'
        f'# 1 "{src.as_posix()}"\n\n\n\nint live(void) {{ return 0; }}\n'
    )
    monkeypatch.setattr(T.shutil, "which", lambda name: "clang")
    fns = R._discover_slice_functions([str(src)], cppflags="-I.", runner=lambda cmd, **kw: _cp(cmd, 0, pre))
    assert fns == ["live"]
    # Without clang, raw scanning is the fallback.
    monkeypatch.setattr(T.shutil, "which", lambda name: None)
    assert R._discover_slice_functions([str(src)], cppflags="-I.") == sorted(["disabled", "live"])


# ---------------------------------------------------------------------------
# WS6 failure attribution
# ---------------------------------------------------------------------------

SEGMENT_LOG = (
    "Use of invalid address 0x7ffd1234 in unsafe_initialize\n"
    "    #0 0x1 in __e_acsl_store_block /opt/frama-c/share/frama-c/e-acsl/rtl.c:10:3\n"
    "    #1 0x2 in UpdateSyncMem /framac-run/workspace/work/src/LibPtfCom/SyncMem.c:292:9\n"
)


def test_segment_model_message_is_parsed_and_runtime_frames_skipped():
    f = R.parse_eacsl_failure(SEGMENT_LOG)
    assert f is not None
    assert f["function"] == "UpdateSyncMem" and f["line"] == 292 and f["kind"] == "eacsl_runtime_error"
    assert not R.needs_attribution(f)
    bare = R.parse_eacsl_failure("Use of invalid address 0x7ffd1234 in unsafe_initialize\n")
    assert bare is not None and bare["function"] == "unknown_function" and R.needs_attribution(bare)
    assert R.needs_attribution(None)


def test_differential_replay_attributes_unlocated_eacsl_crash(tmp_path, monkeypatch):
    eacsl_bin = tmp_path / "fuzz.e-acsl"
    eacsl_bin.write_bytes(EACSL_MARKER_BYTES)
    san_bin = tmp_path / "fuzz.sanreplay"
    san_bin.write_bytes(b"san")
    artifacts = tmp_path / "artifacts"
    ubsan = (
        "src/LibPtfCom/PtfMsg.c:91:28: runtime error: signed integer overflow: 2147483640 + 100 cannot be represented in type 'int'\n"
        "    #0 0x5 in CheckMessageValidity /framac-run/workspace/work/src/LibPtfCom/PtfMsg.c:91:28\n"
    )

    def fake_run(cmd, writable, timeout_s, cwd=None, limits=None, extra_env=None):
        if "-runs=1" in cmd:
            out = ubsan if cmd[0].endswith("sanreplay") else "Use of invalid address 0x1 in unsafe_initialize\n"
            return SandboxResult(1, "", out, False, "rlimits", list(cmd))
        (artifacts / "crash-abc").write_bytes(b"FC33")
        return SandboxResult(1, "", "==1== ERROR: libFuzzer: deadly signal\n", False, "rlimits", list(cmd))

    monkeypatch.setattr(R, "run_sandboxed", fake_run)
    built = []

    def builder():
        built.append(1)
        return san_bin

    res = R.run_fuzz_campaign(eacsl_bin, tmp_path / "corpus", artifacts, attribution_builder=builder)
    art = res["artifacts"][0]
    assert res["status"] == "crash_found"
    assert art["failure_source"] == "sanitizer_replay"
    assert art["failure"]["function"] == "CheckMessageValidity" and art["fingerprint"]
    assert art["attribution"]["source"] == "sanitizer_replay"
    assert built == [1]


def test_guardrail_refuses_uninstrumented_binary(tmp_path):
    plain = tmp_path / "plain_bin"
    plain.write_bytes(b"\x7fELF plain")
    res = R.run_guardrail_check(plain, tmp_path / "corpus", tmp_path / "scratch")
    assert res["status"] == "guardrail_error" and "not E-ACSL-instrumented" in res["reason"]


# ---------------------------------------------------------------------------
# main(): binary threading, fallback reason, selftest gating
# ---------------------------------------------------------------------------


def _campaign_argv(tmp_path, *extra):
    return [
        "run_eacsl_fuzz.py",
        "campaign",
        "--sources",
        "mod.c",
        "--out-bin",
        str(tmp_path / "fuzz_mod"),
        "--corpus-dir",
        str(tmp_path / "corpus"),
        "--artifacts-dir",
        str(tmp_path / "artifacts"),
        "--out-json",
        str(tmp_path / "out.json"),
        "--selftest-json",
        str(tmp_path / "selftest.json"),
        *extra,
    ]


def test_main_fuzzes_the_instrumented_binary(tmp_path, monkeypatch):
    seen = {}
    instrumented = tmp_path / "fuzz_mod.e-acsl"
    monkeypatch.setattr(
        R, "compile_eacsl_binary", lambda *a, **k: {"engine": "eacsl", "returncode": 0, "binary": str(instrumented)}
    )

    def fake_campaign(binary, *a, **k):
        seen["binary"] = binary
        seen["builder"] = k.get("attribution_builder")
        return {"status": "clean", "artifacts": []}

    monkeypatch.setattr(R, "run_fuzz_campaign", fake_campaign)
    monkeypatch.setattr(sys, "argv", _campaign_argv(tmp_path))
    assert R.main() == 0
    assert seen["binary"] == instrumented and callable(seen["builder"])
    out = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert out["engine_used"] == "eacsl" and "engine_fallback_reason" not in out


def test_main_records_engine_fallback_reason(tmp_path, monkeypatch):
    monkeypatch.setattr(
        R,
        "compile_eacsl_binary",
        lambda *a, **k: {"engine": "eacsl", "returncode": 1, "reason": "eacsl_binary_not_instrumented"},
    )
    monkeypatch.setattr(
        R,
        "compile_sanitizer_binary",
        lambda *a, **k: {"engine": "sanitizers", "returncode": 0, "binary": str(tmp_path / "fuzz_mod")},
    )
    monkeypatch.setattr(
        R,
        "run_fuzz_campaign",
        lambda binary, *a, **k: {"status": "clean", "artifacts": [], "builder": k.get("attribution_builder")},
    )
    monkeypatch.setattr(sys, "argv", _campaign_argv(tmp_path))
    R.main()
    out = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert out["engine_used"] == "sanitizers"
    assert out["engine_fallback_reason"] == "eacsl_binary_not_instrumented"
    assert out["builder"] is None  # no differential replay for a sanitizer-only campaign


def test_failed_selftest_skips_eacsl_for_same_version(tmp_path, monkeypatch):
    st = tmp_path / "selftest.json"
    st.write_text(
        json.dumps(
            {
                "ok": False,
                "frama_c_version": "33.0 (Arsenic)",
                "checks": {"compiled": True, "instrumented_binary": False, "attributes_line": False},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(R, "framac_version", lambda runner=None: "33.0 (Arsenic)")
    assert R.selftest_blocks_eacsl(st) == "eacsl_selftest_failed: instrumented_binary"
    monkeypatch.setattr(R, "framac_version", lambda runner=None: "34.0")
    assert R.selftest_blocks_eacsl(st) is None
    assert R.selftest_blocks_eacsl(tmp_path / "missing.json") is None

    monkeypatch.setattr(R, "framac_version", lambda runner=None: "33.0 (Arsenic)")
    called = []
    monkeypatch.setattr(R, "compile_eacsl_binary", lambda *a, **k: called.append(1))
    monkeypatch.setattr(
        R, "compile_sanitizer_binary", lambda *a, **k: {"engine": "sanitizers", "returncode": 0, "binary": "b"}
    )
    monkeypatch.setattr(R, "run_fuzz_campaign", lambda *a, **k: {"status": "clean", "artifacts": []})
    monkeypatch.setattr(sys, "argv", _campaign_argv(tmp_path))
    R.main()
    out = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert called == [] and out["engine_fallback_reason"].startswith("eacsl_selftest_failed")


def test_selftest_with_fake_toolchain(tmp_path, modern_cli, monkeypatch):
    monkeypatch.setattr(R, "framac_version", lambda runner=None: "33.0")
    canary = R.resolve_canary_source()
    expected = next(
        i for i, ln in enumerate(canary.read_text(encoding="utf-8").splitlines(), 1) if "/* CANARY_OOB */" in ln
    )
    assert (
        "heap[len] = 0;" in canary.read_text(encoding="utf-8").splitlines()[expected - 1]
    )  # the statement, not the header

    def fake_replay(binary, artifact, scratch, timeout_s=60):
        data = Path(artifact).read_bytes()
        if data == R.CANARY_BENIGN_INPUT:
            return {"reproduced": False, "failure": None}
        if data == R.CANARY_UNINIT_INPUT:
            return {
                "reproduced": True,
                "failure": {"file": "canary.c", "line": 47, "function": "canary_pick", "alarm_kind": "initialization"},
            }
        return {
            "reproduced": True,
            "failure": {"file": "canary.c", "line": expected, "function": "canary_process", "alarm_kind": "mem_access"},
        }

    res = R.run_selftest(tmp_path / "st", runner=FakeEacslGcc(), replay=fake_replay)
    assert res["ok"] and all(res["checks"].values()) and res["warnings"] == []
    assert res["compile"]["init_hook"].endswith("fuzz_init.c")
    bad = R.run_selftest(tmp_path / "st2", runner=FakeEacslGcc(instrumented=False), replay=fake_replay)
    assert not bad["ok"] and not bad["checks"]["instrumented_binary"]

    # A binary that fails on every input (uninitialized runtime, false alarms) must not pass.
    def crash_on_everything(binary, artifact, scratch, timeout_s=60):
        return {"reproduced": True, "failure": None, "log_tail": "SEGV in shadow_alloca"}

    crashy = R.run_selftest(tmp_path / "st3", runner=FakeEacslGcc(), replay=crash_on_everything)
    assert crashy["checks"]["detects_overflow"] and not crashy["checks"]["benign_input_clean"]
    assert not crashy["ok"] and crashy["benign_failure"] == "SEGV in shadow_alloca"
    assert not crashy["checks"]["detects_uninitialized"]  # a crash is not an initialization report

    # A build without initialization checks misses the canary's uninitialized read.
    def no_init_checks(binary, artifact, scratch, timeout_s=60):
        if Path(artifact).read_bytes() in (R.CANARY_BENIGN_INPUT, R.CANARY_UNINIT_INPUT):
            return {"reproduced": False, "failure": None}
        return fake_replay(binary, artifact, scratch)

    blind = R.run_selftest(tmp_path / "st4", runner=FakeEacslGcc(), replay=no_init_checks)
    assert not blind["ok"] and not blind["checks"]["detects_uninitialized"] and blind["checks"]["detects_overflow"]


# ---------------------------------------------------------------------------
# WS3 header environment, stubs, canary, undeclared functions
# ---------------------------------------------------------------------------


def _strip_c_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def test_compat_header_is_empty_outside_framac_and_uses_glibc_in_host_mode():
    text = _strip_c_comments((REPO / "templates/fc_stubs/fc_compat_types.h").read_text(encoding="utf-8"))
    head, _, body = text.partition("#if defined(__FRAMAC__)")
    assert body, "all content must be guarded by __FRAMAC__"
    assert "typedef" not in head and "#include" not in head
    eacsl_branch = body.split("#if defined(__FRAMAC_EACSL__)", 1)[1].split("#else", 1)[0]
    assert "#include <sys/types.h>" in eacsl_branch and "typedef" not in eacsl_branch
    assert "typedef __INT64_TYPE__ __int64_t;" in body and "typedef unsigned short u_short;" in body


def test_json_stub_completes_opaque_handles_and_declares_from_fd():
    text = (REPO / "templates/fc_stubs/json-c/json.h").read_text(encoding="utf-8")
    assert "json_object *json_object_from_fd(int fd);" in text
    for name in ("json_object", "array_list", "lh_table"):
        assert re.search(rf"struct {name} \{{ int _fc_opaque; \}};", text)


def test_fc_stubs_readme_documents_rules():
    text = (REPO / "templates/fc_stubs/README.md").read_text(encoding="utf-8")
    for needle in (
        "Never C function bodies",
        "Opaque handle types must be complete",
        "belong to the target",
        "force-included into the backend compile",
        "undeclared_functions",
    ):
        assert needle in text


def test_canary_exercises_contract():
    text = (REPO / "templates/eacsl_canary/canary.c").read_text(encoding="utf-8")
    assert text.count("CANARY_OOB") >= 2  # documented in the header and placed on the statement
    assert "open(" in text and "u_short" in text and "__int32_t" in text and "/*@ requires" in text
    assert "int LLVMFuzzerTestOneInput(" in text and "LLVMFuzzerInitialize" not in text.split("*/", 1)[1]
    assert "canary_fill(local," in text  # stack buffer written through a callee on every input
    assert "memcpy(copy, data, size);" in text and "canary_process(copy, size)" in text  # never reads libFuzzer's data
    assert "return picked; /* CANARY_UNINIT" in text
    assert R.CANARY_INPUT.startswith(b"FC33") and len(R.CANARY_INPUT) >= 8
    assert R.CANARY_BENIGN_INPUT[:1] not in (b"O", b"F", b"U") and len(R.CANARY_BENIGN_INPUT) <= 64
    assert R.CANARY_UNINIT_INPUT.startswith(b"UNIN") and R.CANARY_UNINIT_INPUT[4:5] != b"S"


def test_scan_undeclared_functions_formats():
    log = (
        "[kernel:typing:implicit-function-declaration] a.c:3: Warning: Calling undeclared function json_object_from_fd. Old style K&R code?\n"
        "b.c:9:5: error: call to undeclared function 'strlcpy'; ISO C99 and later do not support implicit function declarations\n"
        "c.c:1:1: warning: implicit declaration of function 'foo' is invalid in C99\n"
    )
    assert scan_undeclared_functions(log) == ["foo", "json_object_from_fd", "strlcpy"]
    assert scan_undeclared_functions("") == []


# ---------------------------------------------------------------------------
# Ledger engine qualification
# ---------------------------------------------------------------------------


def test_pipeline_makefile_builds_only_through_the_pipeline_scripts():
    # The two-stage E-ACSL contract lives in run_eacsl_fuzz.py only: the Make phases call it (and
    # every other tool) through the container broker instead of re-implementing the build.
    assert not (REPO / "templates/GNUmakefile.template").exists()
    text = (REPO / "templates/pipeline.mk").read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "e-acsl-gcc" not in code and re.search(r"\bframa-c\b", code) is None and "FRAMAC" not in code

    # Logical recipe lines: a tab-led line plus its backslash continuations.
    recipes = [re.sub(r"\s*\\\n\s*", " ", r) for r in re.findall(r"^\t((?:[^\n]*\\\n)*[^\n]*)", text, re.MULTILINE)]
    invocations = 0
    for line in recipes:
        if line == "$(PM) sweep":  # the coordinator; it leases one `wp` job per function itself
            continue
        for m in re.finditer(r"\$\(PY\) \$\(S\)/\w+\.py|\$\(PM\)", line):
            invocations += 1
            prefix = line[: m.start()]
            assert re.search(r"\$\(RUN\) --class [\w-]+ --key \S+(?: --output \S+)? -- $", prefix), line
    assert invocations >= 15

    # fuzz depends on the selftest and the module's build; the static build never runs the canary.
    assert re.search(r"^\$\(FUZZ_TARGETS\): fuzz-%: selftest build-%$", text, re.MULTILINE)
    assert re.search(r"^\$\(BUILD_TARGETS\): build-%:$", text, re.MULTILINE)
    fuzz = next(r for r in recipes if "campaign" in r)
    assert "--class fuzz" in fuzz and "--workers auto --fuzz-budget $(FUZZ_BUDGET_$*)" in fuzz
    assert "--selftest-json $(SELFTEST_JSON)" in fuzz and "--cppflags=$(CPPFLAGS_$*)" in fuzz
    m_phony = re.search(r"^\.PHONY:((?:[^\n]*\\\n)*[^\n]*)", text, re.MULTILINE)
    assert m_phony is not None
    phony = set(m_phony.group(1).replace("\\", " ").split())
    assert {
        "slice-init",
        "seed",
        "build",
        "selftest",
        "fuzz",
        "eva",
        "ingest",
        "replay",
        "wp-queue",
        "wp-sweep",
        "report",
        "$(BUILD_TARGETS)",
        "$(FUZZ_TARGETS)",
        "$(EVA_TARGETS)",
        "$(MODULE_TARGETS)",
    } <= phony


def test_ledger_fuzz_engine_note():
    assert ledger.fuzz_engine_note({"engine_used": "eacsl"}) == "E-ACSL + LibFuzzer"
    note = ledger.fuzz_engine_note({"engine_used": "sanitizers", "engine_fallback_reason": "eacsl_compile_failed"})
    assert "no E-ACSL contract checks" in note and "eacsl_compile_failed" in note
