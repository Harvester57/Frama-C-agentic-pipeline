"""
The build module (fuzz_build) and the helpers it shares with the other fuzz modules (fuzz_common), S3 (D3, D12, D13).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import fuzz_build
import fuzz_common
import run_eacsl_fuzz as R

pytestmark = pytest.mark.unit

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


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
    text = (SCRIPTS / "run_eacsl_fuzz.py").read_text(encoding="utf-8")
    tree = ast.parse(text)
    defined_here = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    for name in ("compile_eacsl_binary", "build_module_binary", "repair_sources_for_link", "framac_version"):
        assert name not in defined_here, name
        assert getattr(fuzz_build, name).__module__ == "fuzz_build", name


@pytest.mark.parametrize("module", ["fuzz_build", "fuzz_common"])
def test_the_new_modules_do_not_import_run_eacsl_fuzz(module):
    imports = _imported_modules(SCRIPTS / f"{module}.py")
    assert "run_eacsl_fuzz" not in imports


def test_fuzz_common_imports_nothing_from_fuzz_build():
    assert "fuzz_build" not in _imported_modules(SCRIPTS / "fuzz_common.py")
