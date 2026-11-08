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


def test_repair_places_symbols_only_the_build_defines(tmp_path: Path) -> None:
    """libpng's png_target_init: under __SSE2__, which Frama-C does not define, so not in the DAG's functions."""
    work = tmp_path / "workspace" / "work"
    work.mkdir(parents=True)
    (work / "png.c").write_text("int a;\n", encoding="utf-8")
    (work / "pngsimd.c").write_text("int b;\n", encoding="utf-8")
    dag_path = tmp_path / "callgraph_dag.json"
    dag_path.write_text(
        json.dumps(
            {
                "functions": {"png_init_io": {"name": "png_init_io", "file": "png.c"}},
                "build_only_functions": {"pngsimd.c": ["png_target_init", "png_init_io"]},
            }
        ),
        encoding="utf-8",
    )
    log = "undefined reference to `png_target_init'\n"
    repaired, info = R.repair_sources_for_link(["workspace/work/png.c"], log, dag_path, tmp_path)
    assert repaired == ["workspace/work/png.c", "workspace/work/pngsimd.c"]
    assert info["symbols"] == ["png_target_init"]
    # The DAG's own functions win over the build-only list.
    assert R._dag_symbol_files(dag_path)["png_init_io"] == "png.c"


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


def _chain_dag(tmp_path: Path) -> Path:
    """a.c calls b_fn (b.c), b.c calls c_fn (c.c): closing a.c takes two repair rounds."""
    work = tmp_path / "workspace" / "work"
    work.mkdir(parents=True)
    for name in ("a.c", "b.c", "c.c"):
        (work / name).write_text("int x;\n", encoding="utf-8")
    dag_path = tmp_path / "callgraph_dag.json"
    dag_path.write_text(
        json.dumps(
            {
                "functions": {
                    "a_fn": {"name": "a_fn", "file": "a.c"},
                    "b_fn": {"name": "b_fn", "file": "b.c"},
                    "c_fn": {"name": "c_fn", "file": "c.c"},
                }
            }
        ),
        encoding="utf-8",
    )
    return dag_path


def _fake_linker(monkeypatch, missing_after: dict[str, str]) -> list[list[str]]:
    """Sanitizer build that fails with `undefined reference` while a needed file is absent."""
    calls: list[list[str]] = []

    def fake_compile(srcs, out_bin, *a, **k):
        calls.append(list(srcs))
        names = {Path(s).name for s in srcs}
        undefined = [sym for needer, sym in missing_after.items() if needer in names]
        undefined = [sym for sym in undefined if f"{sym[0]}.c" not in names]
        if undefined:
            log = "".join(f"/usr/bin/ld: x.o: undefined reference to `{sym}'\n" for sym in undefined)
            return {"engine": "sanitizers", "returncode": 1, "stderr": log}
        return {"engine": "sanitizers", "returncode": 0, "binary": str(out_bin)}

    monkeypatch.setattr(R, "compile_sanitizer_binary", fake_compile)
    return calls


def test_build_module_binary_repairs_until_the_link_closes(tmp_path: Path, monkeypatch) -> None:
    """A file added in round 1 references another file: round 2 adds it and the link succeeds."""
    dag_path = _chain_dag(tmp_path)
    monkeypatch.chdir(tmp_path)
    calls = _fake_linker(monkeypatch, {"a.c": "b_fn", "b.c": "c_fn"})
    out = R.build_module_binary(
        ["workspace/work/a.c", "harness.c"], tmp_path / "bin", engine="sanitizers", dag_path=dag_path
    )
    assert out["compile"]["returncode"] == 0
    assert len(calls) == 3
    assert out["sources"] == ["workspace/work/a.c", "harness.c", "workspace/work/b.c", "workspace/work/c.c"]
    assert out["link_repair"] == {
        "symbols": ["b_fn", "c_fn"],
        "added_sources": ["workspace/work/b.c", "workspace/work/c.c"],
        "rounds": [
            {"symbols": ["b_fn"], "added_sources": ["workspace/work/b.c"]},
            {"symbols": ["c_fn"], "added_sources": ["workspace/work/c.c"]},
        ],
    }


def test_build_module_binary_stops_when_a_round_adds_nothing(tmp_path: Path, monkeypatch) -> None:
    """A symbol the DAG does not define (a system library) ends the repair; the failure stays."""
    dag_path = _chain_dag(tmp_path)
    monkeypatch.chdir(tmp_path)
    # b.c needs `z_fn`, which no DAG file defines (e.g. zlib's inflate without -lz).
    calls = _fake_linker(monkeypatch, {"a.c": "b_fn", "b.c": "z_fn"})
    out = R.build_module_binary(["workspace/work/a.c"], tmp_path / "bin", engine="sanitizers", dag_path=dag_path)
    assert out["compile"]["returncode"] == 1
    assert len(calls) == 2
    assert [r["added_sources"] for r in out["link_repair"]["rounds"]] == [["workspace/work/b.c"]]
    assert out["sources"] == ["workspace/work/a.c", "workspace/work/b.c"]


def test_build_module_binary_without_repair_keeps_the_result_shape(tmp_path: Path, monkeypatch) -> None:
    dag_path = _chain_dag(tmp_path)
    monkeypatch.chdir(tmp_path)
    calls = _fake_linker(monkeypatch, {})
    out = R.build_module_binary(["workspace/work/a.c"], tmp_path / "bin", engine="sanitizers", dag_path=dag_path)
    assert out["compile"]["returncode"] == 0 and len(calls) == 1
    assert "link_repair" not in out
    assert out["sources"] == ["workspace/work/a.c"]
