"""
Step R1 of docs/phase0-remediation-plan.md (Make, gates and resume): the Phase 0 checkpoint is
recorded by a passing build-check, a DAG rebuilt after the reach check fails the gate, both reach
gates match exemptions alike, build-check names the reach gate's reason, the fuzz budget warns,
the sweep list warns on a name-only callee match, and run_eva_slice.py refuses a gated module.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import harness_reach
import phase0_gates
import pipeline_make as pm
import run_eva_slice
from conftest import write_json
from module_map import ModuleMap
from test_harness_reach import _run_dir, _write_harness
from test_pipeline_make import ACSL, _make_run

pytestmark = pytest.mark.unit


def _reach(run: Path, hdir: Path, *extra: str) -> int:
    return harness_reach.main(
        ["check", "--harness-dir", str(hdir), "--out", str(run / harness_reach.DEFAULT_OUT), *extra]
    )


def _eacsl_reports(run: Path, *mods: str) -> None:
    for mod in mods:
        write_json(
            run / pm.BUILD_DIR / f"{mod}.build.json",
            {"mode": "build", "module": mod, "engine_used": "eacsl", "compile": {"returncode": 0}},
        )


def _no_build(targets: list[str], run_dir: Path) -> tuple[int, dict]:
    return 0, {}


# --- Phase 0 checkpoint ---------------------------------------------------------------------


def test_build_check_records_phase_0_only_once_every_gate_passed(tmp_path):
    run = _make_run(tmp_path)
    plan = pm.build_plan(run, templates_dir=ACSL)
    _eacsl_reports(run, *plan.fuzz_modules)
    progress = run / "state" / "progress.json"

    # No reach stamp yet: build-check passes, but Phase 0 is not done.
    out = pm.build_check(run, runner=_no_build, templates_dir=ACSL)
    assert out["ok"] is True
    assert out["phase0_checkpoint"]["saved"] is False
    assert any("reach has not run" in r for r in out["phase0_checkpoint"]["reasons"])
    assert not progress.exists()

    # Every module of the plan passed the reach gate: build-check initializes and records phase 0.
    phase0_gates.record_reach(run, {"modules": [{"module": m, "passed": True} for m in plan.modules]})
    out = pm.build_check(run, runner=_no_build, templates_dir=ACSL)
    assert out["phase0_checkpoint"] == {"saved": True, "phase_done": 0}
    state = json.loads(progress.read_text(encoding="utf-8"))
    assert state["phase_done"] == 0 and state["target_dir"] == pm.DEFAULT_TARGET_DIR
    assert json.loads((run / "state" / "phase0.json").read_text(encoding="utf-8"))["modules"]
    assert json.loads((run / pm.BUILD_CHECK_JSON).read_text(encoding="utf-8"))["phase0_checkpoint"]["saved"]


def test_a_failed_build_check_records_nothing(tmp_path):
    run = _make_run(tmp_path)
    plan = pm.build_plan(run, templates_dir=ACSL)
    phase0_gates.record_reach(run, {"modules": [{"module": m, "passed": True} for m in plan.modules]})
    calls: list[tuple[str, list[str]]] = []

    def script_runner(script: str, args: list[str]) -> tuple[int, str]:
        calls.append((script, args))
        return 0, "{}"

    out = pm.build_check(run, runner=_no_build, templates_dir=ACSL, script_runner=script_runner)
    assert out["ok"] is False and "phase0_checkpoint" not in out  # no build reports: not_built
    assert calls == []
    _eacsl_reports(run, *plan.fuzz_modules)
    out = pm.build_check(run, runner=_no_build, templates_dir=ACSL, script_runner=script_runner)
    assert out["phase0_checkpoint"]["saved"] is True
    assert [c[0] for c in calls] == ["checkpoint.py", "checkpoint.py"]
    assert calls[0][1][:2] == ["init", "state"]
    assert calls[1][1] == ["save-phase", "state", "--phase", "0", "--from-file", pm.DAG_JSON]


def test_a_module_the_reach_gate_stopped_is_not_built_with_the_gates_reason(tmp_path):
    run = _make_run(tmp_path)
    plan = pm.build_plan(run, templates_dir=ACSL)
    _eacsl_reports(run, *plan.fuzz_modules)  # snmp's is stale: the gate stopped its build-snmp
    rows = [{"module": m, "passed": m != "snmp", "gaps": ["snmp_walk"] if m == "snmp" else []} for m in plan.modules]
    phase0_gates.record_reach(run, {"modules": rows})
    out = pm.build_check(run, runner=_no_build, templates_dir=ACSL)
    snmp = out["modules"]["snmp"]
    assert out["ok"] is False and snmp["status"] == "not_built"
    assert snmp["reason"].startswith("reach gate: ") and "snmp_walk" in snmp["reason"]
    assert out["modules"]["cfg"]["status"] == "eacsl"
    assert "snmp_walk" in phase0_gates.load_gates(run)["build_check"]["modules"]["snmp"]["reason"]


# --- The reach gate and the DAG ---------------------------------------------------------------


def test_a_dag_rewritten_after_the_check_fails_the_gate(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 0); rec_print(0, 0);")
    harness_reach.record_exempt(hdir, "tools", None, "example programs")
    assert _reach(run, hdir) == 0
    stamp = phase0_gates.load_gates(run)["reach"]["modules"]["api"]
    assert stamp["dag_digest"] == phase0_gates.dag_digest(run)
    assert phase0_gates.check(run, "api", ("reach",)) == []
    assert phase0_gates.check(run, None, ("reach",), ["api"]) == []

    dag_path = run / "workspace" / "reports" / "callgraph_dag.json"
    dag = json.loads(dag_path.read_text(encoding="utf-8"))
    dag["modules"]["api"]["candidate_entry_points"].append("rec_ok")
    dag_path.write_text(json.dumps(dag), encoding="utf-8")
    [reason] = phase0_gates.check(run, "api", ("reach",))
    assert "call-graph DAG changed" in reason and "harness_reach.py check" in reason
    assert any("call-graph DAG changed" in r for r in phase0_gates.check(run, None, ("reach",)))
    assert phase0_gates.main(["check", "--run-dir", str(run), "--module", "api", "--need", "reach"]) == 1

    # The check runs again on the rebuilt DAG: the gate holds again.
    assert _reach(run, hdir) == 0
    assert phase0_gates.check(run, "api", ("reach",)) == []


def test_the_harness_digest_check_stays(tmp_path, monkeypatch):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len); rec_put(fuzz_buf, fuzz_len, 0); rec_print(0, 0);")
    assert _reach(run, hdir, "--module", "api") == 0
    (hdir / "harness_api.c").write_text("/* regenerated */\n", encoding="utf-8")
    assert "harness of api changed" in phase0_gates.check(run, "api", ("reach",))[0]


# --- Exemptions -----------------------------------------------------------------------------


def _collision_dag() -> dict:
    def fn(name: str, file: str) -> dict:
        return {"name": name, "file": file, "module": "m", "is_static": False, "internal_callees": []}

    functions = {
        "src/a.c#dup": fn("dup", "src/a.c"),
        "src/b.c#dup": fn("dup", "src/b.c"),
        "src/c.c#solo": fn("solo", "src/c.c"),  # keyed by file although its name is unique
        "uniq": fn("uniq", "src/c.c"),
    }
    entries = ["src/a.c#dup", "src/b.c#dup", "src/c.c#solo", "uniq"]
    return {
        "modules": {"m": {"module": "m", "functions": list(functions), "candidate_entry_points": entries}},
        "functions": functions,
    }


EXEMPT = {"dup": "ambiguous plain name", "src/b.c#dup": "by key", "solo": "unique plain name", "uniq": "by key"}


def test_the_exemption_matcher_takes_the_key_and_a_unique_plain_name():
    match = harness_reach.exemption_matcher(EXEMPT, _collision_dag()["functions"])
    assert match("src/b.c#dup") == "by key"
    assert match("uniq") == "by key"
    assert match("src/c.c#solo") == "unique plain name"
    assert match("src/a.c#dup") is None  # `dup` names two functions: it exempts neither
    assert match("absent") is None


def test_both_gates_exempt_the_same_entry_points(tmp_path):
    dag = _collision_dag()
    sidecar = {"module": "m", "reach_exempt": EXEMPT}
    static = harness_reach.check_module("m", dag, sidecar, "void drive(void) {}\n", [])
    assert static["gaps"] == ["src/a.c#dup"]
    assert set(static["exempt"]) == {"src/b.c#dup", "src/c.c#solo", "uniq"}

    mm = ModuleMap(dag, {"m": sidecar})
    dynamic = harness_reach.check_dynamic("m", dag, mm, {"status": "ok", "functions": []})
    assert dynamic["gaps"] == static["gaps"]

    # The static check keeps a dynamic gap failing through the same matcher.
    hdir = tmp_path / "workspace" / "harnesses"
    write_json(hdir / "harness_m.json", sidecar)
    dyn_path = tmp_path / "dynamic.json"
    entries = dag["modules"]["m"]["candidate_entry_points"]
    write_json(
        dyn_path,
        {"modules": {"m": {"gaps": entries, "harness_digest": phase0_gates.harness_digest(tmp_path, "m")}}},
    )
    report = {"modules": [{"module": "m", "passed": True}]}
    harness_reach.apply_dynamic(report, dyn_path, hdir, tmp_path, dag)
    assert report["modules"][0]["gaps"] == ["src/a.c#dup"] and report["passed"] is False


# --- Fuzz budget ----------------------------------------------------------------------------


def test_a_params_budget_above_the_unit_cap_is_kept_with_a_warning(tmp_path):
    run = _make_run(tmp_path, params={"version": 1, "modules": {"snmp": {"fuzz_budget": 5000}}})
    plan = pm.build_plan(run, templates_dir=ACSL)
    assert plan.modules["snmp"].params["fuzz_budget"] == 5000
    assert plan.modules["snmp"].params["fuzz_budget_source"] == "params"
    [warning] = [w for w in plan.warnings if "fuzz budget" in w]
    assert warning.startswith("snmp: ") and "5000" in warning and str(pm.FUZZ_UNIT_CAP_BY_PROFILE["quick"]) in warning
    assert any("fuzz budget" in w for w in pm.generate(run, templates_dir=ACSL)["warnings"])


def test_the_minimum_per_campaign_pushing_a_unit_over_its_cap_warns(tmp_path, monkeypatch):
    run = _make_run(tmp_path)
    plan = pm.build_plan(run, templates_dir=ACSL)
    assert not [w for w in plan.warnings if "fuzz budget" in w]
    # Three campaigns of one unit under a 50 s cap: each keeps the 30 s minimum, 90 s in all.
    monkeypatch.setitem(pm.FUZZ_UNIT_CAP_BY_PROFILE, "quick", 50)
    monkeypatch.setattr(plan.mm, "unit_of", lambda name: "u")
    plan.warnings.clear()
    pm.allocate_fuzz_budgets(plan)
    assert all(plan.modules[m].params["fuzz_budget"] == pm.MIN_FUZZ_BUDGET_S for m in plan.fuzz_modules)
    [warning] = plan.warnings
    assert "link unit u" in warning and "90" in warning and "50" in warning


# --- Sweep list -----------------------------------------------------------------------------


def _sweep_run(run: Path, dag_functions: dict) -> None:
    wp_unit = {
        "coverage_id": "c1",
        "file": "src/a.c",
        "function": "caller",
        "module": "m",
        "status": "covered",
        "evidence": [{"phase": "wp", "discharging": True}],
        "assumptions": [{"kind": "valid_under_hyp"}],
    }
    eva_unit = {"coverage_id": "c2", "file": "src/a.c", "function": "callee", "module": "m", "status": "covered"}
    write_json(run / pm.LEDGER_JSON, [wp_unit, eva_unit])
    write_json(run / pm.DAG_JSON, {"modules": {}, "functions": dag_functions})


def test_sweep_list_warns_when_a_stale_dag_matches_a_callee_by_name(tmp_path):
    caller = {"name": "caller", "file": "src/a.c", "internal_callees": ["callee"]}
    _sweep_run(tmp_path, {"caller": caller})
    warnings: list[str] = []
    entries, _ = pm.sweep_list(tmp_path, warnings)
    assert {e["function"] for e in entries} == {"caller", "callee"}
    [warning] = warnings
    assert "callee" in warning and "rebuild the DAG" in warning
    assert pm.sweep_list(tmp_path)[0] == entries  # the warnings list is optional

    _sweep_run(tmp_path, {"caller": caller, "callee": {"name": "callee", "file": "src/a.c"}})
    warnings.clear()
    pm.sweep_list(tmp_path, warnings)
    assert warnings == []


# --- run_eva_slice.py gate ------------------------------------------------------------------


def test_run_eva_slice_refuses_a_module_whose_gate_failed(tmp_path, monkeypatch, capsys):
    run = _run_dir(tmp_path, monkeypatch)
    hdir = _write_harness(run, "rec_parse(fuzz_buf, fuzz_len);")
    assert _reach(run, hdir) == 1  # api leaves rec_put and rec_print unreached
    capsys.readouterr()
    argv = ["--module", "api", "--sources", "x.c", "--main", "eva_main", "--out-dir", "eva", "--out-json", "r.json"]
    assert run_eva_slice.main(argv) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "gate_failed" and "rec_put" in out["reasons"][0]
    assert not (run / "r.json").exists()
    assert run_eva_slice.phase0_gate_reasons("") == []


def test_run_eva_slice_is_not_gated_without_a_stamp(tmp_path):
    assert run_eva_slice.phase0_gate_reasons("api", tmp_path) == []
    write_json(tmp_path / phase0_gates.GATES_JSON, {})
    assert "reach has not run" in run_eva_slice.phase0_gate_reasons("api", tmp_path)[0]
