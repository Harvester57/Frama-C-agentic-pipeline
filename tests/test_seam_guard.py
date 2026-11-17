"""
Seam guard (D12): a function that moved out of run_eacsl_fuzz has one home, and is called and patched there.

Scripts call a seam function as `<home>.<name>(...)`, so a test patch on the home module applies to every
caller. A bare call to a seam name, or a test patch of a seam name on run_eacsl_fuzz, would make the patch
silently stop applying: this guard fails instead.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SEAM_ROOT = Path(__file__).resolve().parent.parent
SEAM_SCRIPTS = SEAM_ROOT / "scripts"
SEAM_TESTS = SEAM_ROOT / "tests"
# The homes of moved functions (D12). A module joins when its first function moves.
SEAM_MODULES = ("sandbox_exec", "fuzz_build")
SEAM_MOVED_FROM = "run_eacsl_fuzz"


def seam_functions(module_name: str) -> set[str]:
    """Names of the functions defined in a seam module (not imported into it)."""
    module = importlib.import_module(module_name)
    return {name for name, obj in vars(module).items() if inspect.isfunction(obj) and obj.__module__ == module_name}


def seam_bare_calls(source: str) -> list[str]:
    """Calls, by name, of seam functions that a module-level `from <seam> import ...` binds to a bare name."""
    tree = ast.parse(source)
    bound: dict[str, str] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.ImportFrom) and stmt.module in SEAM_MODULES:
            functions = seam_functions(stmt.module)
            for alias in stmt.names:
                if alias.name in functions:
                    bound[alias.asname or alias.name] = stmt.module
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in bound:
            calls.append(node.func.id)
    return calls


def seam_patches_on_moved_from(source: str) -> list[str]:
    """Names of seam functions that a test patches on run_eacsl_fuzz (through any alias of it)."""
    tree = ast.parse(source)
    aliases = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == SEAM_MOVED_FROM:
                    aliases.add(alias.asname or alias.name)
    names = set().union(*(seam_functions(m) for m in SEAM_MODULES))
    found = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "setattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in aliases
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in names
        ):
            found.append(node.args[1].value)
    return found


def test_the_guard_sees_a_bare_call():
    assert seam_bare_calls("from sandbox_exec import run_sandboxed\nrun_sandboxed([], [], 1)\n") == ["run_sandboxed"]


def test_the_guard_accepts_a_module_attribute_call():
    assert seam_bare_calls("import sandbox_exec\nsandbox_exec.run_sandboxed([], [], 1)\n") == []


def test_the_guard_sees_a_patch_on_run_eacsl_fuzz():
    source = "import run_eacsl_fuzz as R\nmonkeypatch.setattr(R, 'run_sandboxed', fake)\n"
    assert seam_patches_on_moved_from(source) == ["run_sandboxed"]


def test_the_guard_accepts_a_patch_on_the_home():
    source = (
        "import run_eacsl_fuzz as R\nimport sandbox_exec\nmonkeypatch.setattr(sandbox_exec, 'run_sandboxed', fake)\n"
    )
    assert seam_patches_on_moved_from(source) == []


@pytest.mark.parametrize("script", sorted(p.name for p in SEAM_SCRIPTS.glob("*.py")))
def test_no_script_calls_a_seam_function_by_its_bare_name(script):
    if script[:-3] in SEAM_MODULES:
        pytest.skip("the home itself")
    source = (SEAM_SCRIPTS / script).read_text(encoding="utf-8")
    assert seam_bare_calls(source) == [], f"{script} calls a seam function by a bare name; call <home>.<name>"


@pytest.mark.parametrize("test_file", sorted(p.name for p in SEAM_TESTS.glob("test_*.py")))
def test_no_test_patches_a_seam_function_on_run_eacsl_fuzz(test_file):
    source = (SEAM_TESTS / test_file).read_text(encoding="utf-8")
    assert seam_patches_on_moved_from(source) == [], (
        f"{test_file} patches a moved name on run_eacsl_fuzz; patch the home"
    )
