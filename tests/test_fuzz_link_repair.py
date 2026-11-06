"""Regression tests for PB-1/PB-3 hardening in scripts/run_eacsl_fuzz.py:
type-keyword filtering in slice-function discovery and the undefined-reference
link-probe repair driven by the DAG."""

from __future__ import annotations

import json
from pathlib import Path

import run_eacsl_fuzz as R


def test_parse_undefined_references() -> None:
    log = (
        "/usr/bin/ld: harness.o: in function `libssh2_session_init_ex':\n"
        "session.c:426: undefined reference to `ssh2_init_if_needed'\n"
        "/usr/bin/ld: userauth.o: undefined reference to 'userauth_keyboard_interactive_decode_info_request'\n"
        "clang: error: linker command failed\n"
    )
    assert R.parse_undefined_references(log) == [
        "ssh2_init_if_needed",
        "userauth_keyboard_interactive_decode_info_request",
    ]
    assert R.parse_undefined_references("") == []


def test_repair_sources_for_link_maps_symbols_via_dag(tmp_path: Path) -> None:
    work_src = tmp_path / "workspace" / "work" / "src"
    work_src.mkdir(parents=True)
    (work_src / "session.c").write_text("int a;\n", encoding="utf-8")
    (work_src / "global.c").write_text("int b;\n", encoding="utf-8")
    dag_path = tmp_path / "callgraph_dag.json"
    dag_path.write_text(
        json.dumps(
            {
                "functions": {
                    "libssh2_session_init_ex": {"name": "libssh2_session_init_ex", "file": "src/session.c"},
                    "ssh2_init_if_needed": {"name": "ssh2_init_if_needed", "file": "src/global.c"},
                }
            }
        ),
        encoding="utf-8",
    )
    sources = ["workspace/work/src/session.c"]
    log = "undefined reference to `ssh2_init_if_needed'\nundefined reference to `not_in_dag'\n"
    repaired, info = R.repair_sources_for_link(sources, log, dag_path, tmp_path)
    assert repaired == ["workspace/work/src/session.c", "workspace/work/src/global.c"]
    assert info == {"symbols": ["ssh2_init_if_needed"], "added_sources": ["workspace/work/src/global.c"]}
    # No repair info when nothing maps.
    repaired2, info2 = R.repair_sources_for_link(sources, "undefined reference to `not_in_dag'", dag_path, tmp_path)
    assert repaired2 == sources and info2 == {}


def test_repair_sources_for_link_resolves_bare_dag_names(tmp_path: Path) -> None:
    """Old DAGs store bare file names; the repair must still find them in the overlay."""
    work_src = tmp_path / "workspace" / "work" / "src"
    work_src.mkdir(parents=True)
    (work_src / "global.c").write_text("int b;\n", encoding="utf-8")
    dag_path = tmp_path / "dag.json"
    dag_path.write_text(
        json.dumps({"functions": {"ssh2_init_if_needed": {"name": "ssh2_init_if_needed", "file": "global.c"}}}),
        encoding="utf-8",
    )
    repaired, info = R.repair_sources_for_link(
        ["workspace/work/src/session.c"], "undefined reference to `ssh2_init_if_needed'", dag_path, tmp_path
    )
    assert repaired[-1] == "workspace/work/src/global.c"
    assert info["symbols"] == ["ssh2_init_if_needed"]


def test_discover_slice_functions_never_returns_type_keywords(tmp_path: Path) -> None:
    """PB-1: a function-pointer-returning definition must not yield 'void' for -rte-select."""
    src = tmp_path / "session.c"
    src.write_text(
        "static void (*(ssh2_default_alloc)(size_t count, void **abstract)) { return; }\n"
        "int normal_fn(int x) { return x; }\n",
        encoding="utf-8",
    )
    names = R._discover_slice_functions([str(src)], None, cppflags=None)
    assert "ssh2_default_alloc" in names
    assert "normal_fn" in names
    assert "void" not in names
    for kw in ("char", "int", "unsigned", "struct", "const"):
        assert kw not in names
