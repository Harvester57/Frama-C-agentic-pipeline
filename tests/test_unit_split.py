"""
Step I8: oversized link units split into clusters anchored on entry points (scripts/unit_split.py),
and the clusters as sub-modules for the module map, the reach gate and the seeded harness policy.
"""

from __future__ import annotations

import pytest

import benchmark_seeded as BS
import harness_reach as HR
import tiers as T
import unit_split as U
from module_map import ModuleMap, infer_unit

pytestmark = pytest.mark.unit


def _fn(name: str, file: str, callees: list[str], loc: int = 10, tier: str = T.TIER_1A) -> dict:
    return {
        "name": name,
        "file": file,
        "module": "libbig_a",
        "lexer_module": "big",
        "internal_callees": callees,
        "loc": loc,
        "tier": tier,
        "is_static": False,
    }


def big_dag() -> dict:
    """
    One unit: `tc_apply` and `tc_process` share most of a 12-function TC core; `tm_apply` has its own
    10-function TM core; `get_a`/`get_b` are one-function getters in tc.c; `orphan` is reached by nothing.
    """
    fns: dict[str, dict] = {}
    tc_core = [f"tc_h{i}" for i in range(12)]
    tm_core = [f"tm_h{i}" for i in range(10)]
    for i, k in enumerate(tc_core):
        fns[k] = _fn(k, "src/tc.c", [tc_core[i + 1]] if i + 1 < len(tc_core) else [])
    for i, k in enumerate(tm_core):
        fns[k] = _fn(k, "src/tm.c", [tm_core[i + 1]] if i + 1 < len(tm_core) else [], tier=T.TIER_3)
    fns["tc_apply"] = _fn("tc_apply", "src/tc.c", ["tc_h0"])
    fns["tc_process"] = _fn("tc_process", "src/tc.c", ["tc_h1"])
    fns["tm_apply"] = _fn("tm_apply", "src/tm.c", ["tm_h0"], tier=T.TIER_3)
    fns["get_a"] = _fn("get_a", "src/tc.c", [])
    fns["get_b"] = _fn("get_b", "src/tc.c", [])
    fns["orphan"] = _fn("orphan", "src/misc.c", [])
    entries = ["tc_apply", "tc_process", "tm_apply", "get_a", "get_b"]
    return {
        "module_kind": "link_unit",
        "functions": fns,
        "modules": {
            "libbig_a": {
                "module": "libbig_a",
                "unit": "libbig.a",
                "functions": sorted(fns),
                "candidate_entry_points": entries,
                "tier": T.TIER_1A,
                "required_sources": ["src/tc.c", "src/tm.c", "src/misc.c"],
            }
        },
        "lexer_modules": {"big": {"module": "big", "tier": T.TIER_1A}},
        "unit_of_lexer_module": {"big": "libbig_a"},
    }


def test_a_unit_under_the_threshold_is_not_split():
    d = U.apply(big_dag())
    assert d["submodules"] == {}
    assert d["unit_split"]["units"]["libbig_a"] == {
        "functions": 28,
        "reached": 27,
        "lines": 270,
        "split": False,
        "reach": U.REACH_CALLS,
    }


def test_clusters_are_anchored_on_entry_points_merged_on_overlap_and_small_ones_packed():
    d = U.apply(big_dag(), max_functions=20, max_lines=10_000, min_functions=5)
    subs = d["submodules"]
    assert sorted(subs) == ["libbig_a__tc", "libbig_a__tm"]
    tc, tm = subs["libbig_a__tc"], subs["libbig_a__tm"]
    # tc_process's reach lies inside tc_apply's: merged; the getters of tc.c are packed with them.
    assert tc["anchors"] == ["tc_apply", "tc_process", "get_a", "get_b"]
    assert tc["function_count"] == 16 and tc["kind"] == "cluster" and tc["unit"] == "libbig_a"
    assert tm["anchors"] == ["tm_apply"] and tm["function_count"] == 11
    assert tm["tier"] == T.TIER_3 and tm["deferred_profiles"] == ["quick"] and not tm["run_eacsl_fuzz"]
    assert tc["tier"] == T.TIER_1A and tc["run_eacsl_fuzz"]
    split = d["modules"]["libbig_a"]["split"]
    assert split["submodules"] == ["libbig_a__tc", "libbig_a__tm"]
    assert split["unclustered"] == ["orphan"] and split["reason"] == "27 reached functions > 20"


def test_a_line_count_above_the_threshold_splits_too():
    d = U.apply(big_dag(), max_functions=1000, max_lines=100, min_functions=5)
    assert d["unit_split"]["units"]["libbig_a"]["split"]
    assert "270 lines > 100" in d["modules"]["libbig_a"]["split"]["reason"]


def test_overlap_merging_stays_within_the_limits():
    fns = {"a": _fn("a", "a.c", ["s1", "s2", "s3"]), "b": _fn("b", "b.c", ["s1", "s2", "x"])}
    for k in ("s1", "s2", "s3", "x"):
        fns[k] = _fn(k, "s.c", [])
    clusters = U.cluster(fns, sorted(fns), ["a", "b"], max_functions=5, overlap=0.5, min_functions=1)
    # |{a,s1,s2,s3} & {b,s1,s2,x}| = 2 of 4: not above 50%, so two clusters.
    assert [c["anchors"] for c in clusters] == [["a"], ["b"]]
    fns["b"]["internal_callees"] = ["s1", "s2", "s3"]
    clusters = U.cluster(fns, sorted(fns), ["a", "b"], max_functions=5, overlap=0.5, min_functions=1)
    assert [c["anchors"] for c in clusters] == [["a", "b"]]  # 3 of 4 shared, 5 functions merged
    # The same overlap over the limit (nginx run-5: every cluster folded into one of 1650): apart.
    clusters = U.cluster(fns, sorted(fns), ["a", "b"], max_functions=4, overlap=0.5, min_functions=1)
    assert [c["anchors"] for c in clusters] == [["a"], ["b"]]
    clusters = U.cluster(fns, sorted(fns), ["a", "b"], max_functions=5, overlap=0.5, min_functions=1, max_lines=40)
    assert [c["anchors"] for c in clusters] == [["a"], ["b"]]  # 50 lines merged > 40


def test_an_entry_inside_an_oversized_cluster_is_not_folded_into_it():
    """The subset rule only joins a cluster that fits: an oversized single entry stays alone."""
    fns = {"big": _fn("big", "big.c", [f"h{i}" for i in range(6)] + ["small"])}
    fns["small"] = _fn("small", "small.c", ["h0", "h1"])
    for i in range(6):
        fns[f"h{i}"] = _fn(f"h{i}", "h.c", [])
    clusters = U.cluster(fns, sorted(fns), ["big", "small"], max_functions=5, overlap=0.5, min_functions=10)
    assert [c["anchors"] for c in clusters] == [["big"], ["small"]]
    d = {
        "module_kind": "link_unit",
        "functions": fns,
        "modules": {"u": {"functions": sorted(fns), "candidate_entry_points": ["big", "small"], "tier": T.TIER_1A}},
    }
    U.apply(d, max_functions=5, min_functions=10)
    subs = d["submodules"]
    assert subs["u__big"]["over_limit"] == "8 functions > 5" and "over_limit" not in subs["u__small"]
    assert d["modules"]["u"]["split"]["over_limit"] == ["u__big"]
    assert d["unit_split"]["units"]["u"]["over_limit"] == 1


# --- Address-flow reach (docs/plans/unit-split-address-flow.md) -------------------------------------


def _ffn(
    name: str,
    callees: list[str] = (),  # type: ignore[assignment]
    indirect: list[str] = (),  # type: ignore[assignment]
    addr: list[str] = (),  # type: ignore[assignment]
    globs: list[str] = (),  # type: ignore[assignment]
    file: str | None = None,
    static: bool = False,
) -> dict:
    rec = _fn(name, file or f"src/{name}.c", [*callees, *indirect])
    rec.update(indirect_callees=list(indirect), address_refs=list(addr), global_refs=list(globs), is_static=static)
    return rec


def flow_dag() -> dict:
    """
    `run` calls through a `void (*)(void)` pointer whose type matches `h1`, `h2`, `h3` and `h4`:
      - `h1`'s address is taken by `register1`, which `run` calls;
      - `h2`'s address is in the initializer of `table`, which `run_table` reads; `h3`'s in that of
        `inner`, which `table`'s initializer names;
      - `h4`'s address is taken only by `elsewhere`, an entry of its own;
    `spawn` passes `worker` to the library (a callback edge, never an indirect site's type match).
    """
    fns = {
        "run": _ffn("run", ["register1"], ["h1", "h2", "h3", "h4"]),
        "register1": _ffn("register1", addr=["h1"]),
        "run_table": _ffn("run_table", ["run"], globs=["src/table.c#table"]),
        "elsewhere": _ffn("elsewhere", addr=["h4"]),
        "spawn": _ffn("spawn", ["worker"], addr=["worker"]),
        "worker": _ffn("worker", ["w1"]),
        "w1": _ffn("w1"),
        **{h: _ffn(h, [f"{h}_leaf"]) for h in ("h1", "h2", "h3", "h4")},
        **{f"{h}_leaf": _ffn(f"{h}_leaf", file=f"src/{h}.c", static=True) for h in ("h1", "h2", "h3", "h4")},
    }
    global_vars = {
        "src/table.c#table": {
            "name": "table",
            "file": "src/table.c",
            "static": False,
            "init_functions": ["h2"],
            "init_globals": ["src/inner.c#inner"],
        },
        "src/inner.c#inner": {
            "name": "inner",
            "file": "src/inner.c",
            "static": False,
            "init_functions": ["h3"],
            "init_globals": [],
        },
    }
    return {
        "module_kind": "link_unit",
        "functions": fns,
        "global_variables": global_vars,
        "modules": {
            "prog": {
                "functions": sorted(fns),
                "candidate_entry_points": ["run", "run_table", "elsewhere", "spawn"],
                "tier": T.TIER_1A,
            }
        },
    }


def test_an_indirect_callee_is_reached_only_when_its_address_flows_into_the_reached_code():
    d = flow_dag()
    fns, gv, within = d["functions"], d["global_variables"], set(d["functions"])
    reached, globs = U.flow_reach(fns, gv, ["run"], within)
    assert reached == {"run", "register1", "h1", "h1_leaf"} and globs == set()
    # Through the initializers of the globals the code reads, transitively.
    reached, globs = U.flow_reach(fns, gv, ["run_table"], within)
    assert reached == {
        "run_table",
        "run",
        "register1",
        *(f"h{i}" for i in (1, 2, 3)),
        *(f"h{i}_leaf" for i in (1, 2, 3)),
    }
    assert globs == {"src/table.c#table", "src/inner.c#inner"}
    # An address taken by another entry joins the pool only when both are in one harness.
    assert "h4" not in U.flow_reach(fns, gv, ["run"], within)[0]
    assert "h4_leaf" in U.flow_reach(fns, gv, ["run", "elsewhere"], within)[0]
    # A callback passed to the library is followed like a call.
    assert U.flow_reach(fns, gv, ["spawn"], within)[0] == {"spawn", "worker", "w1"}
    # Over every call edge (an older model), `run` reaches every candidate.
    assert {"h2", "h3", "h4"} <= U.reach(fns, "run", within)


def test_the_split_uses_address_flow_reach_when_every_function_has_the_facts():
    d = U.apply(flow_dag(), max_functions=6, min_functions=1)
    row = d["unit_split"]["units"]["prog"]
    assert row["reach"] == U.REACH_FLOW and row["split"]
    subs = {tuple(s["anchors"]): s for s in d["submodules"].values()}
    run_table = subs[("run_table",)]
    assert sorted(subs) == [("elsewhere",), ("run",), ("run_table",), ("spawn",)]
    assert run_table["over_limit"] == "9 functions > 6"
    # `run` lies inside `run_table`'s reach, which is over the limit: not folded into it.
    assert subs[("run",)]["functions"] == ["h1", "h1_leaf", "register1", "run"]
    assert run_table["globals"] == ["src/inner.c#inner", "src/table.c#table"]
    # Its builds compile its functions' files and the files of the globals it reads; what those files
    # name but do not define (h4, only through `run`'s type match, is no reference) is not a stub.
    assert run_table["build_sources"] == sorted(
        ["src/run.c", "src/register1.c", "src/run_table.c", "src/table.c", "src/inner.c"]
        + [f"src/h{i}.c" for i in (1, 2, 3)]
    )
    assert run_table["link_stubs"] == {"functions": [], "globals": []}
    # `run`'s files call `register1`, defined in its own file: compiled, no stub; h4 is a type match only.
    assert subs[("run",)]["link_stubs"] == {"functions": [], "globals": []}
    assert subs[("elsewhere",)]["link_stubs"] == {"functions": ["h4"], "globals": []}
    # Without the facts of one function, the unit falls back to the call graph's reach.
    d = flow_dag()
    del d["functions"]["w1"]["address_refs"]
    assert U.apply(d, max_functions=6, min_functions=1)["unit_split"]["units"]["prog"]["reach"] == U.REACH_CALLS


def test_a_cluster_lists_the_unit_symbols_its_files_name_without_defining_them_as_link_stubs():
    fns = {
        "api": _ffn("api", ["helper"], file="src/a.c"),
        "helper": _ffn("helper", file="src/a.c", static=True),
        # Same file, never reached from `api`: what it names is linked as stubs.
        "unused": _ffn("unused", ["far"], addr=["far_cb"], globs=["src/g.c#counter", "src/a.c#own"], file="src/a.c"),
        "far": _ffn("far", file="src/far.c"),
        "far_cb": _ffn("far_cb", file="src/far.c"),
    }
    gv = {
        "src/g.c#counter": {
            "name": "counter",
            "file": "src/g.c",
            "static": False,
            "init_functions": [],
            "init_globals": [],
        },
        "src/a.c#own": {
            "name": "own",
            "file": "src/a.c",
            "static": True,
            "init_functions": ["far"],
            "init_globals": [],
        },
    }
    plan = U.build_plan(fns, gv, sorted(fns), {"api", "helper"}, set())
    assert plan == {
        "build_sources": ["src/a.c"],
        "link_stubs": {"functions": ["far", "far_cb"], "globals": ["src/g.c#counter"]},
    }


def test_a_cluster_harness_compiles_the_address_flow_build_sources(tmp_path):
    """
    generate_harness takes a cluster's `build_sources`, not its callees' lexer closures (the whole
    program on nginx); a function the harness names outside the cluster joins the reach.
    """
    import json

    import generate_harness as GH

    d = U.apply(flow_dag(), max_functions=6, min_functions=1)
    name = next(n for n, s in d["submodules"].items() if s["anchors"] == ["run"])
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "callgraph_dag.json").write_text(json.dumps(d), encoding="utf-8")
    out_dir = tmp_path / "harnesses"
    src = ["workspace/work/src/run.c"]
    merged = GH._merge_dag_harness_sources(out_dir, src, False, "run", module_name=name)
    assert merged == ["workspace/work/src/run.c", "workspace/work/src/h1.c", "workspace/work/src/register1.c"]
    # `elsewhere` takes h4's address: with both in one harness, `run`'s pointer can reach h4.
    merged = GH._merge_dag_harness_sources(out_dir, src, False, "run(); elsewhere();", module_name=name)
    assert merged == [
        "workspace/work/src/run.c",
        *(f"workspace/work/src/{f}.c" for f in ("elsewhere", "h1", "h4", "register1")),
    ]
    assert GH._flow_harness_sources(d, "no_such_cluster", {"run"}) is None


def test_a_single_cluster_is_not_a_split():
    d = big_dag()
    d["modules"]["libbig_a"]["candidate_entry_points"] = ["tc_apply"]
    U.apply(d, max_functions=5)
    assert d["submodules"] == {}
    assert "single cluster" in d["unit_split"]["units"]["libbig_a"]["note"]


def test_lexer_dags_are_never_split():
    d = big_dag()
    d.pop("module_kind")
    assert U.apply(d, max_functions=5)["submodules"] == {}


def test_the_module_map_treats_clusters_as_sub_modules():
    d = U.apply(big_dag(), max_functions=20, min_functions=5)
    mm = ModuleMap(d, {"libbig_a__tm": {"module": "libbig_a__tm"}})
    assert mm.unit_of("libbig_a__tc") == "libbig_a" and mm.is_submodule("libbig_a__tc")
    assert mm.splits("libbig_a") == ["libbig_a__tc", "libbig_a__tm"]
    assert mm.scope_functions("libbig_a__tm") == sorted(["tm_apply", *[f"tm_h{i}" for i in range(10)]])
    assert mm.scope_entry_points("libbig_a__tc") == ["tc_apply", "tc_process", "get_a", "get_b"]
    assert mm.tier_of("libbig_a__tm") == T.TIER_3
    assert mm.run_flags("libbig_a__tm") == {"run_eva": True, "run_eacsl_fuzz": False, "run_wp_full": False}
    assert mm.submodules("libbig_a") == ["libbig_a__tm"]
    assert infer_unit(d, "libbig_a__tc") == "libbig_a"


def test_the_reach_gate_checks_a_cluster_harness_against_its_anchors():
    d = U.apply(big_dag(), max_functions=20, min_functions=5)
    sidecars = {"libbig_a__tc": {"module": "libbig_a__tc", "unit": "libbig_a"}}
    mm = ModuleMap(d, sidecars)
    row = HR.check_module(
        "libbig_a__tc", d, sidecars["libbig_a__tc"], "void h(void){ tc_apply(); get_a(); }", [], mm=mm
    )
    assert row["unit"] == "libbig_a" and row["entry_points"] == 4
    assert row["gaps"] == ["get_b", "tc_process"]
    # tm_apply is outside every harnessed scope: Tier 3, so the unit has no gap for it.
    assert HR.check_unit("libbig_a", mm, ["libbig_a__tc"], {}) is None


def test_the_seeded_policy_harnesses_each_cluster():
    d = U.apply(big_dag(), max_functions=20, min_functions=5)
    plans = BS.plan_harnesses(d)
    assert sorted(plans) == ["libbig_a__tc", "libbig_a__tm"]
    assert plans["libbig_a__tc"]["entries"] == ["tc_apply", "tc_process", "get_a", "get_b"]
    assert plans["libbig_a__tc"]["submodule"] and plans["libbig_a__tc"]["unit"] == "libbig_a"
    assert plans["libbig_a__tm"]["run_flags"] == {"run_eva": True, "run_eacsl_fuzz": False}
