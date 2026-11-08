"""
Step I8: per-function tiers from trust and structure (scripts/tiers.py), module tiers, the quick-profile
deferral of Tier 3 in pipeline_make, and the DAG builder wiring.
"""

from __future__ import annotations

import pytest

import pipeline_make as pm
import tiers as T
from conftest import write_json
from module_map import ModuleMap

pytestmark = pytest.mark.unit


def fn(name: str, *, trust: str | None = "trusted", boundary: bool = False, callees=(), **facts) -> dict:
    rec = {
        "name": name,
        "file": f"src/{name}.c",
        "module": "libx_a",
        "lexer_module": "x",
        "tier": "Tier 1A (Untrusted Binary / Network Parser)",
        "internal_callees": list(callees),
        "cyclomatic": 6,
        "has_loops": True,
        "const_ptr_params": 1,
        "mutable_ptr_params": 0,
        **facts,
    }
    if trust is not None:
        rec["trust"] = {"value": trust, "source": "default", "boundary": boundary}
    return rec


def dag(functions: dict) -> dict:
    return {
        "module_kind": "link_unit",
        "functions": functions,
        "modules": {"libx_a": {"module": "libx_a", "functions": sorted(functions), "tier": T.TIER_1A}},
        "lexer_modules": {"x": {"module": "x", "tier": T.TIER_1A}},
        "unit_of_lexer_module": {"x": "libx_a"},
    }


def test_function_tiers_follow_the_rules():
    d = dag(
        {
            "parse": fn("parse", trust="untrusted", boundary=True, callees=["walk", "alloc_tree", "emit", "add"]),
            "walk": fn("walk"),
            "alloc_tree": fn("alloc_tree", has_dynamic_alloc=True),
            "emit": fn("emit", writes_bounded_buffer=True, takes_bounded_buffer=False),
            "add": fn("add", cyclomatic=1, has_loops=False, const_ptr_params=0, params="int a, int b"),
            "self_test": fn("self_test"),
        }
    )
    T.apply(d)
    f = d["functions"]
    assert f["parse"]["tier"] == T.TIER_1A
    assert f["walk"]["tier"] == T.TIER_1A and f["walk"]["tier_reasons"][0] == "reached from parse"
    assert f["alloc_tree"]["tier"] == T.TIER_2
    assert f["emit"]["tier"] == T.TIER_1B
    assert f["add"]["tier"] == T.TIER_3 and "scalar helper" in f["add"]["tier_reasons"][-1]
    assert f["self_test"]["tier"] == T.TIER_3 and f["self_test"]["tier_reasons"][0].startswith("no untrusted path")
    assert not f["self_test"]["untrusted_path"]
    assert d["tiers"]["source"] == "trust"
    assert d["tiers"]["tier3_no_untrusted_path"] == 1 and d["tiers"]["tier3_scalar_helpers"] == 1
    mod = d["modules"]["libx_a"]
    assert mod["tier"] == T.TIER_1A and mod["run_eacsl_fuzz"] and mod["deferred_profiles"] == []
    assert mod["tier_counts"] == {"Tier 1A": 2, "Tier 1B": 1, "Tier 2": 1, "Tier 3": 2}
    assert "lexer_tier" not in mod


def test_a_parameterless_getter_on_the_trust_boundary_is_tier_3():
    d = dag(
        {
            "get_iface": fn(
                "get_iface",
                trust="untrusted",
                boundary=True,
                cyclomatic=1,
                has_loops=False,
                const_ptr_params=0,
                params="void",
            )
        }
    )
    T.apply(d)
    assert d["functions"]["get_iface"]["tier"] == T.TIER_3
    assert "without parameters" in d["functions"]["get_iface"]["tier_reasons"][-1]


def test_a_scalar_function_on_the_trust_boundary_stays_tier_1():
    d = dag(
        {
            "api_add": fn(
                "api_add",
                trust="untrusted",
                boundary=True,
                cyclomatic=1,
                has_loops=False,
                const_ptr_params=0,
                params="int a",
            )
        }
    )
    T.apply(d)
    assert d["functions"]["api_add"]["tier"] == T.TIER_1A


def test_trusted_callers_override_keeps_the_untrusted_path():
    rec = fn("helper")
    rec["trust"]["overridden"] = ["default"]
    d = dag({"helper": rec, "leaf": fn("leaf")})
    d["functions"]["helper"]["internal_callees"] = ["leaf"]
    T.apply(d)
    assert d["functions"]["helper"]["tier"] == T.TIER_1A
    assert d["functions"]["leaf"]["untrusted_path"]


def test_module_tier_is_the_highest_of_its_functions_and_tier3_defers_under_quick():
    d = dag({"a": fn("a"), "b": fn("b")})
    T.apply(d)
    mod = d["modules"]["libx_a"]
    assert mod["tier"] == T.TIER_3 and not mod["run_eacsl_fuzz"] and mod["run_eva"]
    assert mod["deferred_profiles"] == ["quick"]
    assert d["lexer_modules"]["x"]["tier"] == T.TIER_3
    assert T.is_deferred(mod["tier"], "quick") and not T.is_deferred(mod["tier"], "standard")
    assert ModuleMap(d).tier_of("x") == T.TIER_3


def test_without_trust_only_the_structure_decides():
    d = dag({"a": fn("a", trust=None), "add": fn("add", trust=None, cyclomatic=1, has_loops=False, const_ptr_params=0)})
    T.apply(d)
    assert d["functions"]["a"]["tier"] == T.TIER_1A and d["functions"]["a"]["untrusted_path"]
    assert d["functions"]["add"]["tier"] == T.TIER_3
    assert d["tiers"]["source"] == "structure"
    assert d["modules"]["libx_a"]["tier_counts"] == {"Tier 1A": 1, "Tier 3": 1}


def test_highest_and_rank():
    assert T.highest([T.TIER_3, T.TIER_2, T.TIER_1B]) == T.TIER_1B
    assert T.highest([]) is None
    assert T.tier_rank("unclassified") == 4


def _quick_run(run, profile: str) -> pm.Plan:
    write_json(run / "run-metadata.json", {"schema_version": 1, "repo": "x", "profile": profile})
    write_json(
        run / pm.DAG_JSON,
        {
            "modules": {
                "glue": {
                    "module": "glue",
                    "tier": T.TIER_3,
                    "run_eva": True,
                    "run_eacsl_fuzz": False,
                    "required_sources": [],
                    "functions": [],
                }
            }
        },
    )
    write_json(run / pm.HARNESS_DIR / "harness_glue.json", {"module": "glue", "sources": [], "cppflags": "-I."})
    (run / pm.HARNESS_DIR / "harness_glue.c").write_text("int harness;\n", encoding="utf-8")
    return pm.build_plan(run)


def test_pipeline_make_defers_a_harnessed_tier3_module_under_quick_only(tmp_path):
    quick = _quick_run(tmp_path / "q", "quick")
    assert "glue" not in quick.modules
    assert "deferred under the quick profile" in quick.excluded["glue"]
    assert quick.expected("eva") == {}
    standard = _quick_run(tmp_path / "s", "standard")
    assert "glue" in standard.modules and standard.modules["glue"].eva and not standard.modules["glue"].fuzz


def test_benchmark_reports_a_deferred_module_without_a_missing_report_problem(tmp_path):
    import benchmark as B

    _quick_run(tmp_path, "quick")
    metrics = B.collect_target_metrics(tmp_path, {"modules": [{"name": "glue"}], "scope": []})
    assert metrics["modules"]["glue"]["deferred"] == "Tier 3 deferred under the quick profile"
    assert not any("glue" in p for p in metrics["problems"])
