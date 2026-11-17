"""Both reach gates hold a library to the functions it defines in its public headers once the DAG lists
them as entry points (docs/plans/header-entry-points-plan.md, H1), with no change to harness_reach.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import build_callgraph_dag as bcd
import harness_reach
import phase0_model as pm

pytestmark = pytest.mark.unit

HRH_UNIT = "liblib.a"
HRH_MODULE = "liblib_a"
HRH_LIB_C = '#include "lib.h"\nint lib_decode(int x) { return x; }\n'
HRH_LIB_H = (
    "int lib_decode(int x);\n"
    "static inline int lib_get_int(int x) { return lib_decode(x); }\n"
    "static inline int lib_get_uint(int x) { return lib_decode(x); }\n"
    "static inline int lib_inner(int x) { return x; }\n"
    "static inline int lib_wrap(int x) { return lib_inner(x); }\n"
)


def _hrh_fn(file: str, name: str, static: bool = False) -> dict:
    return {
        "file": file,
        "name": name,
        "line": 1,
        "end_line": 1,
        "lines": 1,
        "static": static,
        "inline": static,
        "header": file.endswith(".h"),
        "signature": "int (int)",
        "loops": 0,
        "cyclomatic": 1,
        "address_taken": False,
        "source": "frama-c-kernel",
        "units": [HRH_UNIT],
        "kernel_names": {},
    }


def _hrh_dag(tmp_path: Path) -> dict:
    (tmp_path / "src").mkdir()
    (tmp_path / "inc").mkdir()
    (tmp_path / "src/lib.c").write_text(HRH_LIB_C, encoding="utf-8")
    (tmp_path / "inc/lib.h").write_text(HRH_LIB_H, encoding="utf-8")
    functions = {"src/lib.c#lib_decode": _hrh_fn("src/lib.c", "lib_decode")}
    for name in ("lib_get_int", "lib_get_uint", "lib_inner", "lib_wrap"):
        functions[f"inc/lib.h#{name}"] = _hrh_fn("inc/lib.h", name, static=True)
    units = {
        HRH_UNIT: {
            "kind": "static_lib",
            "test": False,
            "files": ["src/lib.c"],
            "links": [],
            "entry_points": ["src/lib.c#lib_decode"],
            "embedded_api": [],
            "parse": {"status": "ok"},
            "concurrent": False,
        }
    }
    for name, ids in pm.header_api(units, functions, {"method": "outside_source_dirs", "files": ["inc/lib.h"]}).items():
        units[name]["header_api"] = ids
    model = {
        "status": "ok",
        "schema_version": 2,
        "generated_at": "2026-11-17T00:00:00Z",
        "functions": functions,
        "edges": [
            {"caller": "inc/lib.h#lib_get_int", "callee": "src/lib.c#lib_decode", "kind": "direct"},
            {"caller": "inc/lib.h#lib_get_uint", "callee": "src/lib.c#lib_decode", "kind": "direct"},
            {"caller": "inc/lib.h#lib_wrap", "callee": "inc/lib.h#lib_inner", "kind": "direct"},
        ],
        "units": units,
        "macro_aliases": {},
        "entry_points": ["src/lib.c#lib_decode"],
        "thread_entries": [],
    }
    return bcd.build_dag(tmp_path, model)


def _hrh_key(dag: dict, name: str) -> str:
    return next(k for k, f in dag["functions"].items() if f["name"] == name)


def test_the_static_gate_reports_an_uncalled_header_entry_point(tmp_path: Path) -> None:
    dag = _hrh_dag(tmp_path)
    entries = dag["modules"][HRH_MODULE]["candidate_entry_points"]
    assert entries[0] == _hrh_key(dag, "lib_decode") and len(entries) == 5
    text = "void drive(int x) { (void)lib_decode(x); (void)lib_get_int(x); (void)lib_wrap(x); }\n"
    row = harness_reach.check_module(HRH_MODULE, dag, {}, text, [])
    assert row["entry_points"] == 5
    assert row["gaps"] == [_hrh_key(dag, "lib_get_uint")] and row["passed"] is False
    # A limit of the gate, not changed by H1: the harness follows header inline wrappers, so a header
    # entry point a called header entry point calls (lib_inner, below lib_wrap) counts as reached.
    assert _hrh_key(dag, "lib_inner") not in row["unreached_entry_points"]


def _hrh_sub_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sub: str, scope: list[str] | None) -> dict:
    dag = _hrh_dag(tmp_path)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "workspace/reports").mkdir(parents=True)
    dag_path = tmp_path / "workspace/reports/callgraph_dag.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    hdir = tmp_path / "workspace/harnesses"
    hdir.mkdir(parents=True)
    (hdir / f"harness_{sub}.c").write_text("void drive(int x) { (void)lib_decode(x); }\n", encoding="utf-8")
    sidecar: dict[str, Any] = {
        "module": sub,
        "unit": HRH_MODULE,
        "harness_file": f"workspace/harnesses/harness_{sub}.c",
        "cppflags": "-I.",
    }
    if scope is not None:
        sidecar["scope_files"] = scope
    (hdir / f"harness_{sub}.json").write_text(json.dumps(sidecar), encoding="utf-8")
    report = harness_reach.run_check(dag_path, hdir, None)
    return {row["module"]: row for row in report["modules"]}


def test_a_sub_module_is_held_to_the_header_entry_points_in_its_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "probe").mkdir()
    dag = _hrh_dag(tmp_path / "probe")  # the directory module that holds the header functions
    lexer = str(dag["functions"][_hrh_key(dag, "lib_get_uint")]["lexer_module"])
    rows = _hrh_sub_run(tmp_path, monkeypatch, lexer, None)
    assert rows[lexer]["entry_points"] == 5 and _hrh_key(dag, "lib_get_uint") in rows[lexer]["gaps"]


def test_a_header_entry_point_outside_every_harness_scope_is_held_only_by_its_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    A gap H1 leaves open: a harness scoped to the sources answers only for the exported function, and
    the unit's own row (`check_unit`) asks only for Tier 1/2 entry points. A public header function
    stays Tier 3 here, since trust.py does not count `header_api` as API.
    """
    rows = _hrh_sub_run(tmp_path, monkeypatch, "srconly", ["src/lib.c"])
    assert rows["srconly"]["entry_points"] == 1 and rows["srconly"]["passed"] is True
    assert HRH_MODULE not in rows


def test_the_dynamic_gate_reports_a_header_entry_point_never_executed(tmp_path: Path) -> None:
    dag = _hrh_dag(tmp_path)
    hdir = tmp_path / "workspace/harnesses"
    hdir.mkdir(parents=True)
    sidecar = {"module": HRH_MODULE, "unit": HRH_MODULE, "entry_fn": "lib_decode", "reach_exempt": {}}
    (hdir / f"harness_{HRH_MODULE}.json").write_text(json.dumps(sidecar), encoding="utf-8")
    mm = harness_reach.ModuleMap(dag, harness_reach.load_sidecars(hdir))

    def row_for(get_uint: int | None) -> dict[str, Any]:
        rows = [
            {"function": "lib_decode", "file": "src/lib.c", "executions": 9},
            {"function": "lib_get_int", "file": "inc/lib.h", "executions": 3},
            {"function": "lib_inner", "file": "inc/lib.h", "executions": 1},
            {"function": "lib_wrap", "file": "inc/lib.h", "executions": 1},
        ]
        if get_uint is not None:
            rows.append({"function": "lib_get_uint", "file": "inc/lib.h", "executions": get_uint})
        return harness_reach.check_dynamic(HRH_MODULE, dag, mm, {"functions": rows}, harnesses_dir=hdir)

    key = _hrh_key(dag, "lib_get_uint")
    row = row_for(0)
    assert row["executions"][key] == 0 and row["gaps"] == [key] and row["passed"] is False
    # A header function no translation unit of the coverage build instantiated is not listed at all.
    assert row_for(None)["gaps"] == [key]
    assert row_for(2)["passed"] is True
