"""Tests for Wave 1 Track 2A: fuzz-only probe telemetry in harness template, api_harness, and fuzz_build."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
import fuzz_build

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = REPO_ROOT / "templates" / "harness_dual.c.template"
SPARE = ah.spare_bytes(64)


def _formals(*kinds: str) -> list[dict[str, str]]:
    return [{"name": f"p{i}", "kind": k} for i, k in enumerate(kinds)]


# --- template checks --------------------------------------------------------------------------------


def test_harness_dual_template_has_guarded_probe_telemetry_block():
    text = TEMPLATE_PATH.read_text(encoding="utf-8")
    skip_end = text.index("framac_fuzz_rt_skip_words[c >> 6U]")
    probe_guard = text.index("#if !defined(__FRAMAC__) && defined(FRAMAC_FUZZ_PROBE_TELEMETRY)")
    eva_guard = text.index("#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)\n")
    assert skip_end < probe_guard < eva_guard

    block = text[probe_guard:eva_guard]
    for expected in (
        "#define FRAMAC_PROBE_MAX_CASES 4096U",
        "#define FRAMAC_PROBE_MAX_UNIQUE 8U",
        "framac_probe_slot_t",
        'getenv("FRAMAC_PROBE_OUT")',
        "atexit(framac_probe_flush)",
        r"\"schema_version\":1",
        r"\"cases\":{",
        r"\"runs\":",
        r"\"init_fail\":",
        r"\"ret_kind\":",
        r"\"unique_overflow\":",
        r"\"unique_vals\":[",
        "#define FRAMAC_PROBE_CASE_START(c)",
        "#define FRAMAC_PROBE_INIT_FAIL(c)",
        "#define FRAMAC_PROBE_RET_I64(c, v)",
        "#define FRAMAC_PROBE_RET_PTR(c, p)",
        "#define FRAMAC_PROBE_CASE_START(c) ((void)0)",
        "#define FRAMAC_PROBE_INIT_FAIL(c)  ((void)0)",
        "#define FRAMAC_PROBE_RET_I64(c, v) ((void)0)",
        "#define FRAMAC_PROBE_RET_PTR(c, p) ((void)0)",
    ):
        assert expected in block, expected


# --- api_harness emission checks --------------------------------------------------------------------


def test_probe_telemetry_off_by_default_emits_no_probe_macros(monkeypatch):
    monkeypatch.delenv("FRAMAC_HARNESS_PROBE", raising=False)
    assert not ah.harness_probe_enabled()
    stmt, layout, why = ah.single_case(
        "parse",
        {"signature": "int(unsigned char *,unsigned long)", "formals": _formals("const_pointer", "value")},
        SPARE,
    )
    assert why is None and stmt is not None and layout is not None
    assert "FRAMAC_PROBE_" not in stmt
    assert "\n" not in stmt and "\r" not in stmt


@pytest.mark.parametrize(
    "sig,expected_macro",
    [
        ("char *(int)", "FRAMAC_PROBE_RET_PTR(harness_selector,"),
        ("const void *(unsigned long)", "FRAMAC_PROBE_RET_PTR(harness_selector,"),
        ("struct item *(int)", "FRAMAC_PROBE_RET_PTR(harness_selector,"),
        ("int(int)", "FRAMAC_PROBE_RET_I64(harness_selector,"),
        ("unsigned long long(int)", "FRAMAC_PROBE_RET_I64(harness_selector,"),
        ("_Bool(int)", "FRAMAC_PROBE_RET_I64(harness_selector,"),
        ("enum status_code(int)", "FRAMAC_PROBE_RET_I64(harness_selector,"),
        ("enum __anonenum_rc_1(int)", "FRAMAC_PROBE_RET_I64(harness_selector,"),
    ],
)
def test_single_case_emits_single_line_probe_macros_for_ptr_int_enum_bool(sig, expected_macro):
    stmt, layout, why = ah.single_case(
        "entry_fn",
        {"signature": sig, "formals": _formals("value")},
        SPARE,
        probe_telemetry=True,
    )
    assert why is None and stmt is not None and layout is not None
    assert "\n" not in stmt and "\r" not in stmt
    assert stmt.startswith("FRAMAC_PROBE_CASE_START(harness_selector);")
    assert expected_macro in stmt
    assert "entry_fn(" in stmt


@pytest.mark.parametrize(
    "sig",
    [
        "void(int)",
        "struct pair(int)",
        "double(int)",
        "float(int)",
    ],
)
def test_single_case_void_struct_float_omit_return_macro(sig):
    stmt, layout, why = ah.single_case(
        "entry_fn",
        {"signature": sig, "formals": _formals("value")},
        SPARE,
        probe_telemetry=True,
    )
    assert why is None and stmt is not None and layout is not None
    assert "\n" not in stmt and "\r" not in stmt
    assert stmt.startswith("FRAMAC_PROBE_CASE_START(harness_selector);")
    assert "FRAMAC_PROBE_RET_" not in stmt
    assert "(void)entry_fn(" in stmt


def test_outparam_constructor_guard_records_init_fail():
    h = "struct rec *"
    recs: dict[str, dict[str, Any]] = {
        "rec_create": {
            "signature": "int(struct rec **,int)",
            "formals": _formals("pointer", "value"),
        },
        "rec_destroy": {
            "signature": "void(struct rec *)",
            "formals": _formals("pointer"),
        },
        "rec_get_id": {
            "signature": "int(struct rec *)",
            "formals": _formals("const_pointer"),
        },
    }
    api = ah.ApiInfo(
        records=recs,
        handles={"rec_get_id": {0: h}, "rec_destroy": {0: h}},
        dtors={h: "rec_destroy"},
        dtor_names={h: {"rec_destroy"}},
        outs={"rec_create": {0: h}},
        out_ctors={h: ("rec_create", 0)},
        out_ctor_names={h: {"rec_create"}},
        probe_telemetry=True,
    )
    stmt, layout, why = ah.single_case("rec_get_id", recs["rec_get_id"], SPARE, api)
    assert why is None and stmt is not None and layout is not None
    assert "\n" not in stmt and "\r" not in stmt
    assert stmt.startswith("FRAMAC_PROBE_CASE_START(harness_selector);")
    assert "if (c0a0 != 0) {" in stmt
    assert "FRAMAC_PROBE_RET_I64(harness_selector," in stmt
    assert "else { FRAMAC_PROBE_INIT_FAIL(harness_selector); }" in stmt

    # Lifecycle case on the same handle also records CASE_START and INIT_FAIL on NULL handle.
    lstmt, llay, lwhy = ah.lifecycle_case(h, ["rec_get_id"], recs, SPARE, api)
    assert lwhy is None and lstmt is not None and llay is not None
    assert "\n" not in lstmt and "\r" not in lstmt
    assert lstmt.startswith("FRAMAC_PROBE_CASE_START(harness_selector);")
    assert "else { FRAMAC_PROBE_INIT_FAIL(harness_selector); }" in lstmt


def test_sequence_case_emits_case_start_and_records_final_entry_return():
    records: dict[str, dict[str, Any]] = {
        "keypair": {
            "signature": "int(unsigned char *,unsigned char *)",
            "formals": _formals("pointer", "pointer"),
            "param_sizes": {"0": {"max": 32}, "1": {"max": 32}},
        },
        "verify": {
            "signature": "char *(unsigned char *,unsigned char *)",
            "formals": _formals("const_pointer", "const_pointer"),
            "param_sizes": {"0": {"max": 32}, "1": {"max": 32}},
        },
    }
    trace = [
        {"fn": "keypair", "args": {}, "addrs": {"0": "100", "1": "200"}},
        {"fn": "verify", "args": {}, "addrs": {"0": "100", "1": "200"}},
    ]
    stmt, layout, why = ah.sequence_case(trace, [0, 1], records, SPARE, probe_telemetry=True)
    assert why is None and stmt is not None and layout is not None
    assert "\n" not in stmt and "\r" not in stmt
    assert stmt.startswith("FRAMAC_PROBE_CASE_START(harness_selector);")
    # Earlier call does not emit a return macro; final entry call emits RET_PTR.
    assert "(void)keypair(" in stmt
    assert "FRAMAC_PROBE_RET_I64" not in stmt
    assert "FRAMAC_PROBE_RET_PTR(harness_selector," in stmt


def test_plan_respects_framac_harness_probe_env(monkeypatch):
    dag = {
        "module_kind": "link_unit",
        "modules": {"lib": {"candidate_entry_points": ["a", "b"], "functions": ["a", "b"]}},
        "functions": {
            "a": {"name": "a", "file": "lib.c", "is_static": False, "module": "lib"},
            "b": {"name": "b", "file": "lib.c", "is_static": False, "module": "lib"},
        },
    }
    model = {
        "status": "ok",
        "functions": {
            "lib.c#a": {"signature": "int(int)", "formals": _formals("value")},
            "lib.c#b": {"signature": "void(int)", "formals": _formals("value")},
        },
    }
    monkeypatch.setenv("FRAMAC_HARNESS_PROBE", "on")
    p = ah.plan(dag, model, "lib", "lib", 64)
    assert len(p["cases"]) == 2
    for stmt in p["cases"]:
        assert "\n" not in stmt and "\r" not in stmt
        assert stmt.startswith("FRAMAC_PROBE_CASE_START(harness_selector);")
    assert "FRAMAC_PROBE_RET_I64(harness_selector," in p["cases"][0]
    assert "FRAMAC_PROBE_RET_" not in p["cases"][1]


# --- fuzz_build flag gating checks ------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, False),
        ("", False),
        ("off", False),
        ("0", False),
        ("false", False),
        ("no", False),
        ("on", True),
        ("ON", True),
        ("1", True),
        ("true", True),
        ("True", True),
        ("yes", True),
        (" YES ", True),
    ],
)
def test_fuzz_build_harness_probe_enabled_values(raw, expected):
    env = {} if raw is None else {"FRAMAC_HARNESS_PROBE": raw}
    assert fuzz_build.harness_probe_enabled(env) is expected


def _fake_runner(captured: list[list[str]]):
    class _Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    def _run(cmd, **_kwargs):
        captured.append(list(cmd))
        return _Proc()

    return _run


def test_sanitizer_fuzzer_build_adds_probe_define_only_when_enabled(monkeypatch, tmp_path):
    src = tmp_path / "harness_mod.c"
    src.write_text("int LLVMFuzzerTestOneInput(void) { return 0; }\n", encoding="utf-8")

    # Off by default: no -DFRAMAC_FUZZ_PROBE_TELEMETRY
    monkeypatch.delenv("FRAMAC_HARNESS_PROBE", raising=False)
    cmds_off: list[list[str]] = []
    fuzz_build.compile_sanitizer_binary(
        [str(src)], tmp_path / "mod.san", fuzzer_flag=True, runner=_fake_runner(cmds_off), use_cache=False
    )
    assert cmds_off and "-DFRAMAC_FUZZ_PROBE_TELEMETRY" not in cmds_off[0]

    # Enabled + fuzzer_flag=True: adds -DFRAMAC_FUZZ_PROBE_TELEMETRY
    monkeypatch.setenv("FRAMAC_HARNESS_PROBE", "on")
    cmds_on: list[list[str]] = []
    fuzz_build.compile_sanitizer_binary(
        [str(src)], tmp_path / "mod.san", fuzzer_flag=True, runner=_fake_runner(cmds_on), use_cache=False
    )
    assert cmds_on and "-DFRAMAC_FUZZ_PROBE_TELEMETRY" in cmds_on[0]

    # Enabled + fuzzer_flag=False (standalone reproducer build): never adds it
    cmds_nofuzz: list[list[str]] = []
    fuzz_build.compile_sanitizer_binary(
        [str(src)], tmp_path / "repro.san", fuzzer_flag=False, runner=_fake_runner(cmds_nofuzz), use_cache=False
    )
    assert cmds_nofuzz and "-DFRAMAC_FUZZ_PROBE_TELEMETRY" not in cmds_nofuzz[0]

    # Coverage build never adds it
    cmds_cov: list[list[str]] = []
    fuzz_build.compile_coverage_binary([str(src)], tmp_path / "mod.cov", runner=_fake_runner(cmds_cov), use_cache=False)
    assert cmds_cov and "-DFRAMAC_FUZZ_PROBE_TELEMETRY" not in cmds_cov[0]

    # E-ACSL cache material / flags never include it
    mat = fuzz_build._eacsl_cache_material(
        sources=[str(src)],
        out_bin=tmp_path / "mod.eacsl",
        machdep="gcc_x86_64",
        cppflags="-I.",
        rte_flags="-rte",
        fuzzer_flag=True,
        functions=None,
        ldflags_extra="",
        variadic_translation=True,
        warn_unsigned_downcast=False,
        rte_initialized=True,
    )
    assert mat is not None
    assert "FRAMAC_FUZZ_PROBE_TELEMETRY" not in str(mat)
