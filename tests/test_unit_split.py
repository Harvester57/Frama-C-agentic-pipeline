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
    assert d["unit_split"]["units"]["libbig_a"] == {"functions": 28, "reached": 27, "lines": 270, "split": False}


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


def test_overlap_merging_ignores_size_but_packing_respects_it():
    fns = {"a": _fn("a", "a.c", ["s1", "s2", "s3"]), "b": _fn("b", "b.c", ["s1", "s2", "x"])}
    for k in ("s1", "s2", "s3", "x"):
        fns[k] = _fn(k, "s.c", [])
    clusters = U.cluster(fns, sorted(fns), ["a", "b"], max_functions=4, overlap=0.5, min_functions=1)
    # |{a,s1,s2,s3} & {b,s1,s2,x}| = 2 of 4: not above 50%, so two clusters.
    assert [c["anchors"] for c in clusters] == [["a"], ["b"]]
    fns["b"]["internal_callees"] = ["s1", "s2", "s3"]
    clusters = U.cluster(fns, sorted(fns), ["a", "b"], max_functions=4, overlap=0.5, min_functions=1)
    assert [c["anchors"] for c in clusters] == [["a", "b"]]  # 3 of 4 shared: merged though 5 > 4


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
