"""
The DAG against what the real build compiles (nettle run-3, 2026-11-09): a module's `required_sources`
hold only compiled sources, and functions only Frama-C's configuration compiles are marked `model_only`.

nettle's root getopt.c is a wrapper: `#include "lib/getopt.c"` unless glibc already provides getopt
(`ELIDE_CODE` under `__GLIBC__ >= 2`). Frama-C's libc has no `__GLIBC__`, so the model attributes
getopt's functions to lib/getopt.c; the glibc build compiles getopt.c to an empty object.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_callgraph_dag as bcd  # noqa: E402
import build_capture as bc  # noqa: E402
import generate_harness as gh  # noqa: E402
import generate_report as R  # noqa: E402
import harness_reach  # noqa: E402

pytestmark = pytest.mark.unit


def _fn(file: str, name: str, line: int, **kw: object) -> dict:
    rec = {
        "file": file,
        "name": name,
        "line": line,
        "end_line": line,
        "lines": 1,
        "static": False,
        "inline": False,
        "header": False,
        "loops": 0,
        "cyclomatic": 1,
        "source": "frama-c-kernel",
        "units": ["prog"],
    }
    rec.update(kw)
    return rec


@pytest.fixture()
def target(tmp_path: Path) -> Path:
    root = tmp_path / "work"
    (root / "lib").mkdir(parents=True)
    (root / "prog.c").write_text("int main(int c, char **v) { return getopt_long(c, v); }\n", encoding="utf-8")
    (root / "getopt.c").write_text('#ifndef ELIDE_CODE\n#include "lib/getopt.c"\n#endif\n', encoding="utf-8")
    (root / "lib/getopt.c").write_text(
        '#include "gettext.h"\nstatic int exchange(void) { return 0; }\nint getopt_long(int c, char **v) '
        "{ return exchange(); }\n",
        encoding="utf-8",
    )
    return root


def _model(extra: dict | None = None) -> dict:
    """Frama-C's view: getopt.c took the include branch, so lib/getopt.c defines getopt."""
    fns = {
        "prog.c#main": _fn("prog.c", "main", 1),
        "lib/getopt.c#exchange": _fn("lib/getopt.c", "exchange", 2, static=True),
        "lib/getopt.c#getopt_long": _fn("lib/getopt.c", "getopt_long", 3),
        **(extra or {}),
    }
    return {
        "status": "ok",
        "generated_at": "2026-11-09T00:00:00Z",
        "functions": fns,
        "edges": [
            {"caller": "prog.c#main", "callee": "lib/getopt.c#getopt_long", "kind": "direct"},
            {"caller": "lib/getopt.c#getopt_long", "callee": "lib/getopt.c#exchange", "kind": "direct"},
        ],
        "units": {
            "prog": {
                "kind": "executable",
                "test": False,
                "files": ["prog.c", "getopt.c"],
                "parse": {"status": "ok"},
                "entry_points": ["prog.c#main"],
                "embedded_api": ["lib/getopt.c#getopt_long"],
            }
        },
        "macro_aliases": {},
        "entry_points": ["prog.c#main"],
        "thread_entries": [],
    }


def _capture(getopt: dict, prog_defines: list[str] | None = None, **prog: object) -> dict:
    """The glibc build: prog.c and the getopt.c wrapper, as the capture records them."""
    return {
        "units": {"prog": {"kind": "executable", "test": False, "files": ["prog.c", "getopt.c"],
                           "objects": ["prog.o", "getopt.o"]}},
        "compiles": [
            {"source": "prog.c", "object": "prog.o", "headers": [], "probe_errors": {},
             "defined_functions": prog_defines if prog_defines is not None else ["prog.c#main"], **prog},
            {"source": "getopt.c", "object": "getopt.o", **getopt},
        ],
    }  # fmt: skip


# The wrapper elided (glibc has getopt): an empty object, both probes ran.
ELIDED = {"headers": [], "defined_functions": [], "probe_errors": {}}
# The wrapper included lib/getopt.c (a libc without getopt): `cc -M` lists it, nm sees getopt_long.
INCLUDED = {
    "headers": ["lib/getopt.c"],
    "defined_functions": ["getopt.c#getopt_long", "getopt.c#exchange"],
    "probe_errors": {},
}


def _all_required(dag: dict) -> set[str]:
    return {
        s
        for section in ("modules", "lexer_modules", "submodules")
        for rec in (dag.get(section) or {}).values()
        for s in rec.get("required_sources") or []
    }


def _all_entries(dag: dict) -> set[str]:
    return {
        e
        for section in ("modules", "lexer_modules", "submodules")
        for rec in (dag.get(section) or {}).values()
        for e in rec.get("candidate_entry_points") or []
    }


# ---------------------------------------------------------------------------------------------------
# required_sources hold compiled sources only
# ---------------------------------------------------------------------------------------------------


def test_an_included_c_file_is_replaced_by_the_source_including_it(target: Path) -> None:
    dag = bcd.build_dag(target, _model(), _capture(INCLUDED))
    assert "lib/getopt.c" not in _all_required(dag)
    assert dag["lexer_modules"]["lib"]["required_sources"] == ["getopt.c"]
    # The build defines getopt (through the wrapper): nothing is model-only.
    assert not any(f.get("model_only") for f in dag["functions"].values())
    assert "model_only_functions" not in dag


def test_an_elided_wrapper_drops_the_file_and_marks_its_functions(target: Path) -> None:
    dag = bcd.build_dag(target, _model(), _capture(ELIDED))
    assert "lib/getopt.c" not in _all_required(dag)
    assert dag["lexer_modules"]["lib"]["required_sources"] == []
    assert dag["modules"]["prog"]["required_sources"] == ["prog.c", "getopt.c"]
    fns = dag["functions"]
    assert "lib/getopt.c is not compiled by the build" in fns["getopt_long"]["model_only"]
    assert fns["exchange"]["model_only"]  # static too: its whole file is out of the build
    assert "model_only" not in fns["main"]
    assert dag["model_only_functions"] == {"lib/getopt.c": ["exchange", "getopt_long"]}
    assert any(w.startswith("lib/getopt.c: the real build does not define 2 function(s)") for w in dag["warnings"])
    # Not an entry point anywhere (the unit's embedded API names it), so no reach gate waits on it.
    assert "getopt_long" not in _all_entries(dag)


def test_without_a_capture_required_sources_are_the_models(target: Path) -> None:
    dag = bcd.build_dag(target, _model(), None)
    assert dag["lexer_modules"]["lib"]["required_sources"] == ["lib/getopt.c"]
    assert not any(f.get("model_only") for f in dag["functions"].values())


def test_a_failed_dependency_probe_does_not_decide_that_a_file_is_out_of_the_build(target: Path) -> None:
    deps_failed = {"headers": [], "defined_functions": [], "probe_errors": {"deps": "the dependency probe exited 1"}}
    fns = bcd.build_dag(target, _model(), _capture(deps_failed))["functions"]
    # The symbol probe still ran: nm decides for the non-static function, nothing for the static one.
    assert "do not define it (nm)" in fns["getopt_long"]["model_only"]
    assert not fns["exchange"].get("model_only")
    both_failed = {**deps_failed, "probe_errors": {"deps": "exited 1", "symbols": "nm exited 1"}}
    fns = bcd.build_dag(target, _model(), _capture(both_failed))["functions"]
    assert not fns["getopt_long"].get("model_only")


def test_compiled_sources_map_prefers_an_includer_already_listed() -> None:
    capture = {
        "compiles": [
            {"source": "a.c", "object": "a.o", "headers": ["x.c", "x.h"]},
            {"source": "b.c", "object": "b.o", "headers": ["x.c"]},
        ]
    }
    compiled = bcd.CompiledSources(capture)
    assert compiled.map(["b.c", "x.c"]) == ["b.c"]
    assert compiled.map(["x.c"]) == ["a.c"]
    assert compiled.map(["gone.c", "a.c"]) == ["a.c"]
    assert bcd.CompiledSources(None).map(["gone.c"]) == ["gone.c"]


# ---------------------------------------------------------------------------------------------------
# model_only from the build's defined_functions
# ---------------------------------------------------------------------------------------------------


def _with_glibc_only() -> dict:
    """prog.c defines `fallback_strdup` and `pad` only without __GLIBC__ (Frama-C's view)."""
    return _model(
        {
            "prog.c#fallback_strdup": _fn("prog.c", "fallback_strdup", 2),
            "prog.c#pad": _fn("prog.c", "pad", 3, static=True),
        }
    )


def test_a_non_static_function_the_objects_do_not_define_is_model_only(target: Path) -> None:
    marked = bcd.model_only_functions(_with_glibc_only(), _capture(INCLUDED))
    assert "objects of prog do not define it" in marked["prog.c#fallback_strdup"]
    # A static function may just have been inlined away: never marked from nm.
    assert "prog.c#pad" not in marked
    assert "prog.c#main" not in marked


def test_a_failed_symbol_probe_marks_nothing(target: Path) -> None:
    capture = _capture(INCLUDED, probe_errors={"symbols": "nm exited 1"})
    assert "prog.c#fallback_strdup" not in bcd.model_only_functions(_with_glibc_only(), capture)


def test_an_old_capture_trusts_only_non_empty_symbol_lists(target: Path) -> None:
    capture = _capture(INCLUDED, prog_defines=[])
    for c in capture["compiles"]:
        c.pop("probe_errors")
    assert "prog.c#fallback_strdup" not in bcd.model_only_functions(_with_glibc_only(), capture)


def test_build_only_ignores_the_functions_of_an_included_c_file() -> None:
    """nettle's eccdata.c includes mini-gmp.c: nm names mini-gmp's functions in eccdata.c."""
    model = {"functions": {"mini-gmp.c#mpz_init": _fn("mini-gmp.c", "mpz_init", 1)}}
    capture = {
        "compiles": [
            {"source": "eccdata.c", "object": "eccdata.o", "headers": ["mini-gmp.c"],
             "defined_functions": ["eccdata.c#mpz_init", "eccdata.c#simd_only"]}
        ]
    }  # fmt: skip
    assert bcd.build_only_functions(model, capture) == {"eccdata.c": ["simd_only"]}


# ---------------------------------------------------------------------------------------------------
# Consumers: harness sources, reach gate, ledger, report
# ---------------------------------------------------------------------------------------------------


def test_harness_sources_skip_a_model_only_callee(target: Path, tmp_path: Path) -> None:
    run = tmp_path / "run" / "workspace"
    (run / "reports").mkdir(parents=True)
    (run / "harness").mkdir()
    dag = bcd.build_dag(target, _model(), _capture(ELIDED))
    (run / "reports" / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    merged = gh._merge_dag_harness_sources(run / "harness", ["prog.c"], False, "getopt_long(argc, argv);")
    assert merged == ["prog.c"]


def test_reach_gate_entries_leave_out_model_only_functions() -> None:
    functions = {"getopt_long": {"model_only": "not compiled"}, "main": {}}
    assert harness_reach.built_entries(["getopt_long", "main", "unknown"], functions) == ["main", "unknown"]


def test_the_ledger_and_the_report_show_the_mark(target: Path) -> None:
    import ledger

    dag = bcd.build_dag(target, _model(), _capture(ELIDED))
    assert "model_only" in ledger.SEED_BOOKKEEPING
    units = [
        {"file": "lib/getopt.c", "function": "getopt_long", "bookkeeping": {"model_only": "not compiled"}},
        {"file": "prog.c", "function": "main"},
    ]
    lines = R.model_only_lines(units)
    assert lines[0] == "Functions the real build does not compile:"
    assert any("getopt_long (lib/getopt.c): not compiled" in ln for ln in lines)
    assert R.model_only_lines([{"function": "main"}]) == []
    assert dag["functions"]["getopt_long"]["model_only"]


# ---------------------------------------------------------------------------------------------------
# The capture's probe diagnostics
# ---------------------------------------------------------------------------------------------------


def _entry(tmp_path: Path) -> dict:
    return {"source": "getopt.c", "object": "getopt.o", "cwd": ".", "arguments": ["cc", "-c", "getopt.c"],
            "implicit": False}  # fmt: skip


def test_a_failed_dependency_probe_is_told_apart_from_no_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bc, "run_tool", lambda *a, **k: (1, "", "\ngetopt.c:1: fatal error: x.h: No such file\n"))
    deps, err = bc.compile_deps(_entry(tmp_path), str(tmp_path))
    assert deps == []
    assert err == "the dependency probe (-M) exited 1: getopt.c:1: fatal error: x.h: No such file"
    monkeypatch.setattr(bc, "run_tool", lambda *a, **k: (0, f"getopt.o: {tmp_path}/getopt.c\n", ""))
    deps, err = bc.compile_deps(_entry(tmp_path), str(tmp_path))
    assert err is None


def test_a_failed_symbol_probe_is_told_apart_from_an_empty_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    syms, err = bc.compile_symbols(_entry(tmp_path), str(tmp_path), tmp_path, 0)
    assert syms == {} and err == "no object file getopt.o after the build"
    (tmp_path / "getopt.o").write_bytes(b"")
    monkeypatch.setattr(bc, "run_tool", lambda *a, **k: (0, "", ""))
    assert bc.compile_symbols(_entry(tmp_path), str(tmp_path), tmp_path, 0) == ({}, None)
    monkeypatch.setattr(bc, "run_tool", lambda *a, **k: (2, "", "nm: getopt.o: file format not recognized"))
    syms, err = bc.compile_symbols(_entry(tmp_path), str(tmp_path), tmp_path, 0)
    assert syms == {} and err == "nm exited 2: nm: getopt.o: file format not recognized"
