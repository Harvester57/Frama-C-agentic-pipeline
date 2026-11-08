"""The call-graph DAG built from the Phase 0 model (step I5a): build_callgraph_dag.model_view,
the ledger seed's use of it, and the macro aliases in harness_reach."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_callgraph_dag as bcd  # noqa: E402
import harness_reach  # noqa: E402

pytestmark = pytest.mark.unit

A_C = """\
#include "h.h"
static int helper(int x) { return x + 1; }
static int cb(int v) { return v; }
int api_run(int n) {
    int (*fp)(int) = cb;
    int s = 0;
    for (int i = 0; i < n; i++) s += helper(i);
    return s + fp(n) + hin(n);
}
"""
B_C = """\
static int helper(int x) { return x * 2; }
int api_other(int x) { return helper(x); }
"""
H_H = """\
static inline int hin(int x) { return x; }
static inline int hdead(int x) { return x - 1; }
"""
# Never compiled by the build (an alternative backend): the lexer sees it, the model does not.
T_C = "int template_only(int x) { return x; }\n"


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
        "units": ["lib"],
    }
    rec.update(kw)
    return rec


@pytest.fixture()
def target(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "include").mkdir()
    (tmp_path / "alt").mkdir()
    (tmp_path / "src/a.c").write_text(A_C, encoding="utf-8")
    (tmp_path / "src/b.c").write_text(B_C, encoding="utf-8")
    (tmp_path / "include/h.h").write_text(H_H, encoding="utf-8")
    (tmp_path / "alt/t.c").write_text(T_C, encoding="utf-8")
    return tmp_path


def _model(fallback: bool = False) -> dict:
    fns = {
        "src/a.c#helper": _fn("src/a.c", "helper", 2, static=True),
        "src/a.c#cb": _fn("src/a.c", "cb", 3, static=True, address_taken=True),
        "src/a.c#api_run": _fn("src/a.c", "api_run", 4, loops=1, lines=6),
        "src/b.c#helper": _fn("src/b.c", "helper", 1, static=True),
        "src/b.c#api_other": _fn("src/b.c", "api_other", 2),
        "include/h.h#hin": _fn("include/h.h", "hin", 1, static=True, inline=True, header=True),
        "include/h.h#hdead": _fn("include/h.h", "hdead", 2, static=True, inline=True, header=True),
    }
    if fallback:
        fns["src/b.c#helper"]["source"] = "gcc-callgraph-info"
        fns["src/b.c#api_other"]["source"] = "gcc-callgraph-info"
    edges = [
        {"caller": "src/a.c#api_run", "callee": "src/a.c#helper", "kind": "direct"},
        {"caller": "src/a.c#api_run", "callee": "src/a.c#cb", "kind": "indirect"},
        {"caller": "src/a.c#api_run", "callee": "include/h.h#hin", "kind": "direct"},
        {"caller": "src/b.c#api_other", "callee": "src/b.c#helper", "kind": "direct"},
    ]
    parse = {"status": "gcc_fallback", "error": "b.c:1: syntax error"} if fallback else {"status": "ok"}
    return {
        "status": "ok",
        "generated_at": "2026-11-08T00:00:00Z",
        "functions": fns,
        "edges": edges,
        "units": {"lib": {"kind": "library", "test": False, "files": ["src/a.c", "src/b.c"], "parse": parse}},
        "macro_aliases": {
            "run_api": {"function": "api_run", "ids": ["src/a.c#api_run"], "via": "define", "defined_in": "x.h"}
        },
        "entry_points": ["src/a.c#api_run", "src/b.c#api_other"],
        "thread_entries": [],
    }


def _dag(target: Path, model: dict | None) -> dict:
    return bcd.build_dag(target, target / "compile_commands.json", model=model)


def test_functions_and_edges_come_from_the_model(target: Path) -> None:
    lexer = _dag(target, None)
    assert "template_only" in lexer["functions"]
    dag = _dag(target, _model())

    assert dag["callgraph_source"] == "frama_c"
    assert set(dag["functions"]) == {
        "src/a.c#helper",
        "src/b.c#helper",
        "cb",
        "api_run",
        "api_other",
        "hin",
        "hdead",
    }
    assert "template_only" in dag["model"]["lexer_only_functions"]
    run = dag["functions"]["api_run"]
    assert run["internal_callees"] == ["cb", "hin", "src/a.c#helper"]
    assert run["indirect_callees"] == ["cb"]
    assert run["callgraph_source"] == "frama_c"
    assert run["has_loops"] and run["loop_count"] == 1
    assert dag["functions"]["src/b.c#helper"]["internal_callers"] == ["api_other"]
    # The lexer's analysis of the same definition is kept.
    assert "params" in run
    # The indirect edge orders the waves: cb is below api_run.
    assert dag["functions"]["cb"]["wave"] < run["wave"]
    assert {c["function"] for c in dag["name_collisions"]} == {"helper"}
    assert dag["macro_aliases"] == {"run_api": ["api_run"]}


def test_header_functions_are_reached_only_from_entry_points(target: Path) -> None:
    dag = _dag(target, _model())
    assert dag["functions"]["hin"]["header"] and dag["functions"]["hin"]["reached"]
    assert dag["functions"]["hdead"]["header"] and not dag["functions"]["hdead"]["reached"]
    assert "reached" not in dag["functions"]["api_run"]


def test_modules_are_held_and_recounted(target: Path) -> None:
    lexer = _dag(target, None)
    dag = _dag(target, _model())
    for name, mod in dag["modules"].items():
        assert mod["function_count"] == len(mod["functions"])
        if name in lexer["modules"]:
            assert mod["tier"] == lexer["modules"][name]["tier"]
    every = [k for m in dag["modules"].values() for k in m["functions"]]
    assert sorted(every) == sorted(dag["functions"])
    for mod in dag["modules"].values():
        assert set(mod["candidate_entry_points"]) <= set(mod["functions"])


def test_fallback_units_are_flagged(target: Path) -> None:
    dag = _dag(target, _model(fallback=True))
    assert dag["model"]["gcc_fallback_units"] == ["lib"]
    assert dag["functions"]["api_other"]["callgraph_source"] == "gcc_callgraph"
    assert dag["functions"]["api_other"]["callgraph_fallback"] == "b.c:1: syntax error"
    assert any("GCC" in w for w in dag["warnings"])


def test_load_model_refuses_a_failed_model(tmp_path: Path) -> None:
    missing, why = bcd.load_model(tmp_path / "none.json")
    assert missing is None and "not found" in str(why)
    bad = tmp_path / "m.json"
    bad.write_text(json.dumps({"status": "failed"}), encoding="utf-8")
    assert bcd.load_model(bad)[0] is None
    bad.write_text(json.dumps(_model()), encoding="utf-8")
    assert bcd.load_model(bad)[0] is not None


def test_seed_uses_the_model_view(target: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import ledger

    dag = _dag(target, _model(fallback=True))
    dag_path = tmp_path / "dag.json"
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    run = tmp_path / "run"
    (run / "workspace/reports").mkdir(parents=True)
    monkeypatch.chdir(run)
    out = ledger.cmd_seed(dag_path, [], "frama_c")
    units, _ = ledger.load_state()
    fns = {(u["file"], u["function"]) for u in units.values()}
    assert ("include/h.h", "hin") in fns
    by_fn = {(u["file"], u["function"], u["obligation_class"]): u for u in units.values()}
    dead = by_fn[("include/h.h", "hdead", "rte")]
    assert dead["status"] == "deferred" and dead["unresolved"] == [ledger.HEADER_UNREACHED]
    assert by_fn[("include/h.h", "hin", "rte")]["status"] == "planned"
    assert out["deferred_unreached_header_units"] == 1
    assert ("src/a.c", "helper") in fns and ("src/b.c", "helper") in fns
    assert by_fn[("src/a.c", "api_run", "rte")]["callgraph_source"] == "frama_c"
    other = by_fn[("src/b.c", "api_other", "rte")]
    assert other["callgraph_source"] == "gcc_callgraph"
    assert other["bookkeeping"]["callgraph_fallback"] == "b.c:1: syntax error"


def test_harness_reach_follows_keys_and_aliases(target: Path) -> None:
    dag = _dag(target, _model())
    module = dag["functions"]["api_run"]["module"]
    # The harness calls the API through the build's macro alias only.
    res = harness_reach.check_module(module, dag, {}, "int main(void){ return run_api(3); }", [])
    assert "api_run" in res["roots"]
    reached = harness_reach.callee_closure({"api_run"}, harness_reach._functions_by_name(dag), module)
    # The colliding static helper is named by its key in the edges and reached under it.
    assert {"src/a.c#helper", "cb", "hin"} <= reached
    assert "src/b.c#helper" not in reached
