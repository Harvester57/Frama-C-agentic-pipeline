"""
The build module (fuzz_build) and the helpers it shares with the other fuzz modules (fuzz_common), S3 (D3, D12, D13).
"""

from __future__ import annotations

import argparse
import ast
import json
import shutil
from pathlib import Path

import pytest

import fuzz_build
import fuzz_common
import run_eacsl_fuzz as R
from test_cache import FakeToolchain, _module  # the fake E-ACSL and sanitizer toolchain of the cache tests

pytestmark = pytest.mark.unit

BUILD_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def test_run_eacsl_fuzz_reexports_every_moved_name():
    build_names = [
        "_decode",
        "_discover_slice_functions",
        "_resolve_eacsl_gcc",
        "_run_tool",
        "_note_cache_restore",
        "_eacsl_cache_material",
        "_check_options",
        "_runtime_patches",
        "_PATCHED_STDIO_ERROR_RE",
        "_format_runtime_share",
        "_GETENV_CALL_RE",
        "_ENVIRON_KEEP_SOURCE",
        "_build_environ_keep_object",
        "compile_eacsl_binary",
        "_compile_eacsl_binary_uncached",
        "_compile_clang_binary",
        "compile_sanitizer_binary",
        "compile_coverage_binary",
        "framac_version",
        "selftest_blocks_eacsl",
        "_UNDEFINED_REF_RE",
        "parse_undefined_references",
        "_dag_symbol_files",
        "_normalize_dag_source",
        "LINK_GLOBALS_FILE",
        "LINK_GLOBALS_ASSUMPTION",
        "_GLOBAL_TYPE_CHARS_RE",
        "_GLOBAL_TAG_RE",
        "_GLOBAL_POINTER_SLOT_RE",
        "_GLOBAL_ARRAY_RE",
        "_model_global_variables",
        "global_definition_text",
        "_declaring_header",
        "link_globals_source",
        "_dag_tree_path",
        "_link_unit_context",
        "_place_global",
        "repair_sources_for_link",
        "build_module_binary",
        "_sanitizer_attribution_builder",
    ]
    common_names = [
        "BUILD_TIMEOUT_S",
        "DEFAULT_PER_INPUT_TIMEOUT_S",
        "DUAL_ENGINE",
        "SANITIZER_RUNTIME_ENV",
        "ARTIFACT_KINDS",
        "_artifact_kind",
        "sha256_file",
        "derive_seed",
        "_in_agent_scratch",
        "replay_artifact_dir",
        "_collect_inputs",
        "DEFAULT_SELFTEST_JSON",
    ]
    assert len(build_names) == 40 and len(common_names) == 12
    for name in build_names:
        assert getattr(R, name) is getattr(fuzz_build, name), name
    for name in common_names:
        assert getattr(R, name) is getattr(fuzz_common, name), name


def test_the_moved_build_functions_are_defined_in_fuzz_build_only():
    text = (BUILD_SCRIPTS / "run_eacsl_fuzz.py").read_text(encoding="utf-8")
    tree = ast.parse(text)
    defined_here = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    for name in ("compile_eacsl_binary", "build_module_binary", "repair_sources_for_link", "framac_version"):
        assert name not in defined_here, name
        assert getattr(fuzz_build, name).__module__ == "fuzz_build", name


@pytest.mark.parametrize("module", ["fuzz_build", "fuzz_common"])
def test_fuzz_build_and_fuzz_common_do_not_import_run_eacsl_fuzz(module):
    imports = _imported_modules(BUILD_SCRIPTS / f"{module}.py")
    assert "run_eacsl_fuzz" not in imports


def test_fuzz_common_imports_nothing_from_fuzz_build():
    assert "fuzz_build" not in _imported_modules(BUILD_SCRIPTS / "fuzz_common.py")


def _built(returncode: int, engine: str) -> dict:
    return {"returncode": returncode, "binary": f"{engine}.bin", "engine": engine, "cache": {"hit": False, "key": None}}


def _build_args(out: Path, engine: str) -> argparse.Namespace:
    return argparse.Namespace(
        module="mod",
        sources=["mod.c"],
        out_bin=out / "fuzz_mod",
        engine=engine,
        machdep="gcc_x86_64",
        cppflags="-Iinc",
        ldflags="",
        rte="all",
        functions=None,
        no_variadic_translation=False,
        warn_unsigned_downcast=False,
        no_rte_initialized=False,
        no_libc_checks=False,
        selftest_json=out / "no-selftest.json",
    )


def test_build_ignores_a_failed_selftest(monkeypatch, tmp_path):
    # D8: `build` compiles what --engine asks for and does not apply a failed selftest; the campaign does.
    monkeypatch.setattr(fuzz_build, "selftest_blocks_eacsl", lambda *a, **k: "eacsl_selftest_failed: canary")
    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", lambda *a, **k: _built(0, "eacsl"))
    monkeypatch.setattr(fuzz_build, "compile_sanitizer_binary", lambda *a, **k: _built(0, "sanitizers"))
    res = R._run_build_mode(_build_args(tmp_path, "auto"))
    assert res["status"] == "built" and res["engine_used"] == "eacsl"
    assert "engine_fallback_reason" not in res


def test_build_auto_records_both_builds(monkeypatch, tmp_path):
    monkeypatch.setattr(fuzz_build, "selftest_blocks_eacsl", lambda *a, **k: None)
    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", lambda *a, **k: _built(0, "eacsl"))
    monkeypatch.setattr(fuzz_build, "compile_sanitizer_binary", lambda *a, **k: _built(0, "sanitizers"))
    auto = R._run_build_mode(_build_args(tmp_path, "auto"))
    assert auto["sanitizer_compile"]["returncode"] == 0
    for engine in ("eacsl", "sanitizers"):
        assert "sanitizer_compile" not in R._run_build_mode(_build_args(tmp_path, engine))


def test_campaign_still_applies_the_selftest(monkeypatch, tmp_path):
    monkeypatch.setattr(fuzz_build, "selftest_blocks_eacsl", lambda *a, **k: "eacsl_selftest_failed: canary")
    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", lambda *a, **k: _built(0, "eacsl"))
    monkeypatch.setattr(fuzz_build, "compile_sanitizer_binary", lambda *a, **k: _built(0, "sanitizers"))
    campaign = fuzz_build.build_module_binary(["m.c"], tmp_path / "fuzz_m", engine="auto")
    assert campaign["engine_used"] == "sanitizers"
    assert campaign["engine_fallback_reason"] == "eacsl_selftest_failed: canary"


def test_a_campaign_after_build_compiles_nothing(tmp_path, monkeypatch):
    # The real cache, with the cache tests' fake toolchain: the campaign's builds restore what `build` compiled.
    run = tmp_path / "run-1"
    run.mkdir()
    (run / "run-metadata.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.chdir(run)
    monkeypatch.setenv("FRAMAC_IMAGE_ID", "sha256:test-image")
    monkeypatch.delenv("FRAMAC_CACHE", raising=False)
    monkeypatch.delenv("FRAMAC_SHARED_CACHE_DIR", raising=False)
    monkeypatch.setattr(fuzz_build, "_resolve_eacsl_gcc", lambda: ("e-acsl-gcc", True))
    monkeypatch.setattr(shutil, "which", lambda name: None)
    _module(run)
    fake = FakeToolchain(deps=["inc/mod.h"])
    real_eacsl, real_sanitizer = fuzz_build.compile_eacsl_binary, fuzz_build.compile_sanitizer_binary
    monkeypatch.setattr(fuzz_build, "compile_eacsl_binary", lambda *a, **k: real_eacsl(*a, **{"runner": fake, **k}))
    monkeypatch.setattr(
        fuzz_build, "compile_sanitizer_binary", lambda *a, **k: real_sanitizer(*a, **{"runner": fake, **k})
    )
    args = _build_args(Path("workspace/harnesses"), "auto")

    built = R._run_build_mode(args)
    assert built["status"] == "built" and built["engine_used"] == "eacsl"
    assert built["sanitizer_compile"]["returncode"] == 0
    builds = len(fake.builds())

    # the campaign's two builds, with its arguments, restore from the cache
    options = R._build_options(args)
    campaign = fuzz_build.build_module_binary(args.sources, args.out_bin, **options)
    second = fuzz_build.build_module_binary(args.sources, args.out_bin, **{**options, "engine": "sanitizers"})
    assert campaign["compile"]["cache"]["hit"] and second["compile"]["cache"]["hit"]
    assert len(fake.builds()) == builds

    only_eacsl = R._run_build_mode(argparse.Namespace(**{**vars(args), "engine": "eacsl"}))
    assert "sanitizer_compile" not in only_eacsl
    only_sanitizers = R._run_build_mode(argparse.Namespace(**{**vars(args), "engine": "sanitizers"}))
    assert "sanitizer_compile" not in only_sanitizers


def _header_entry_run(tmp_path: Path, with_dag: bool = True) -> list[str]:
    """An `--api` harness with a case for an exported, a public header and a source-static entry point."""
    hdir = tmp_path / "workspace/harnesses"
    hdir.mkdir(parents=True)
    (tmp_path / "workspace/reports").mkdir()
    src = tmp_path / "lib.c"
    src.write_text("int lib_decode(int x) { return x; }\n", encoding="utf-8")
    harness = hdir / "harness_lib.c"
    harness.write_text("int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }\n")
    cases = [{"kind": "single", "selector": i, "calls": [n], "entry": n} for i, n in enumerate(["lib_decode", "h_get"])]
    cases.append({"kind": "single", "selector": 2, "calls": ["s_one"], "entry": "s_one"})
    (hdir / "harness_lib.json").write_text(json.dumps({"api_harness": True, "api_cases": cases}), encoding="utf-8")
    if with_dag:
        functions = {
            "lib_decode": {"name": "lib_decode", "file": "lib.c", "is_static": False, "header": False},
            "h_get": {"name": "h_get", "file": "inc/lib.h", "is_static": True, "header": True},
            "s_one": {"name": "s_one", "file": "lib.c", "is_static": True, "header": False},
        }
        (tmp_path / "workspace/reports/callgraph_dag.json").write_text(json.dumps({"functions": functions}))
    return [str(src), str(harness)]


def test_the_function_list_adds_the_header_entry_points_the_harness_calls(tmp_path):
    """HD8: `-rte-select` / `-e-acsl-functions` cover a public header entry point the harness calls."""
    sources = _header_entry_run(tmp_path)
    assert fuzz_build._discover_slice_functions(sources) == ["h_get", "lib_decode"]
    # An explicit list is the caller's choice, as before.
    assert fuzz_build._discover_slice_functions(sources, ["lib_decode"]) == ["lib_decode"]


def test_the_function_list_without_a_dag_is_the_scan_of_the_sources(tmp_path):
    sources = _header_entry_run(tmp_path, with_dag=False)
    assert fuzz_build._discover_slice_functions(sources) == ["lib_decode"]
