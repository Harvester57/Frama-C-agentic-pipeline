"""The benchmark's `phase0` seeded-bug set (scripts/benchmark_seeded.py): harness policy and scoring, no Docker."""

import json
import shutil
from pathlib import Path

import pytest

import benchmark_seeded as bs
from conftest import PHASE0_FIXTURES

SEEDED = PHASE0_FIXTURES / "seeded"


def _truth(project: str) -> dict:
    return json.loads((SEEDED / project / "truth.json").read_text(encoding="utf-8"))


def _fn(file: str, name: str, lexer: str, static: bool = False) -> tuple[str, dict]:
    return f"{file}#{name}", {"name": name, "file": file, "is_static": static, "lexer_module": lexer}


def _unit_dag(entries: list[tuple[str, dict]], **unit: object) -> dict:
    fns = dict(entries)
    fns.update([_fn("tools/cli.c", "main", "cli")])
    rec = {
        "unit": "libkv.a",
        "required_sources": ["src/kv.c", "src/util.c", "include/kv.h", "tools/cli.c"],
        "cppflags": ["-I", "include", "-include", "config.h", "-DFAST"],
        "candidate_entry_points": [*fns],
        "run_eva": True,
        "run_eacsl_fuzz": True,
        **unit,
    }
    return {"module_kind": "link_unit", "functions": fns, "modules": {"libkv_a": rec}}


# ---------------------------------------------------------------------------
# Harness policy
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_harness_cppflags_moves_paths_under_the_overlay():
    flags = ["-I", "include", "-include", "config.h", "-DFAST", "-Iinclude", "-I/usr/include/x", "-DX=a b"]
    assert bs.harness_cppflags(flags) == (
        "-Iworkspace/work/include -include workspace/work/config.h -DFAST -I/usr/include/x '-DX=a b'"
    )
    assert bs.harness_cppflags("-I ./src -I") == "-Iworkspace/work/src"  # a dangling option is dropped
    assert bs.harness_cppflags([]) == "-I."


@pytest.mark.unit
def test_one_harness_per_unit_with_its_callable_entry_points():
    dag = _unit_dag(
        [
            _fn("src/kv.c", "kv_load", "kv"),
            _fn("src/kv.c", "find_slot", "kv", static=True),
            _fn("src/util.c", "kv_key_equals", "util"),
        ]
    )
    plans = bs.plan_harnesses(dag)
    assert list(plans) == ["libkv_a"]
    plan = plans["libkv_a"]
    assert plan["unit"] == "libkv_a" and plan["submodule"] is False
    assert plan["entries"] == ["src/kv.c#kv_load", "src/util.c#kv_key_equals"]
    assert plan["excluded"] == {
        "src/kv.c#find_slot": "static: not callable from the harness",
        "tools/cli.c#main": "main: the harness has its own entry",
    }
    # C files only, and not the file defining main; the unit's flags on the overlay.
    assert plan["sources"] == ["workspace/work/src/kv.c", "workspace/work/src/util.c"]
    assert plan["cppflags"] == "-Iworkspace/work/include -include workspace/work/config.h -DFAST"
    assert plan["run_flags"] == {"run_eva": True, "run_eacsl_fuzz": True}


@pytest.mark.unit
def test_a_large_unit_splits_into_lexer_sub_modules():
    dag = _unit_dag(
        [
            _fn("src/kv.c", "a1", "kv"),
            _fn("src/util.c", "b1", "util"),
            _fn("src/kv.c", "a2", "kv"),
            _fn("src/kv.c", "a3", "kv"),
            _fn("src/kv.c", "s", "kv", static=True),
        ]
    )
    plans = bs.plan_harnesses(dag, max_cases=2)
    assert sorted(plans) == ["kv", "util"]
    assert all(p["submodule"] and p["unit"] == "libkv_a" for p in plans.values())
    assert plans["kv"]["entries"] == ["src/kv.c#a1", "src/kv.c#a2"]
    assert plans["util"]["entries"] == ["src/util.c#b1"]
    # The overflow stays with its sub-module; main/static exclusions go to the unit's first sub-module.
    assert plans["kv"]["excluded"] == {
        "src/kv.c#a3": "beyond the policy's 2-case limit",
        "src/kv.c#s": "static: not callable from the harness",
        "tools/cli.c#main": "main: the harness has its own entry",
    }
    assert plans["util"]["excluded"] == {}
    # Every sub-module compiles the whole unit (it must link).
    assert plans["util"]["sources"] == plans["kv"]["sources"]
    assert bs.plan_harnesses(dag, max_cases=2) == plans  # deterministic


@pytest.mark.unit
def test_no_split_without_link_units_and_no_collision_with_a_unit_name():
    entries = [_fn("src/kv.c", f"f{i}", "kv") for i in range(3)]
    lexer = _unit_dag(entries)
    del lexer["module_kind"]
    plans = bs.plan_harnesses(lexer, max_cases=2)
    assert list(plans) == ["libkv_a"] and plans["libkv_a"]["entries"] == ["src/kv.c#f0", "src/kv.c#f1"]
    assert plans["libkv_a"]["excluded"]["src/kv.c#f2"].startswith("beyond")
    # A lexer module named as a DAG module would collide with it: its entries stay with the unit.
    colliding = _unit_dag([_fn("src/kv.c", f"f{i}", "libkv_a") for i in range(3)] + [_fn("src/util.c", "g", "util")])
    plans = bs.plan_harnesses(colliding, max_cases=2)
    assert sorted(plans) == ["libkv_a", "util"]
    assert plans["libkv_a"]["submodule"] is False and plans["util"]["submodule"] is True


@pytest.mark.unit
def test_synthesize_case_shapes():
    def p(t: str, fnp: bool = False) -> dict:
        return {"type": t, "is_fn_pointer": fnp}

    assert bs.synthesize_case("f", [p("void")]) == "(void)f();"
    assert bs.synthesize_case("f", [p("const uint8_t *"), p("size_t")]) == (
        "(void)f((const uint8_t *)fuzz_buf, (size_t)fuzz_len);"
    )
    out = bs.synthesize_case("f", [p("uint8_t *"), p("size_t"), p("const uint8_t *"), p("size_t")])
    assert (
        out is not None
        and "uint8_t o0[256]" in out
        and out.endswith("(void)f((uint8_t *)o0, (size_t)sizeof o0, (const uint8_t *)fuzz_buf, (size_t)fuzz_len);")
    )
    out = bs.synthesize_case("f", [p("struct reply *"), p("const uint8_t *"), p("size_t")])
    assert out is not None and "struct reply r0; memset(&r0" in out
    assert bs.synthesize_case("f", [p("void *")]) is None
    assert bs.synthesize_case("f", [p("int (*)(void)", fnp=True)]) is None


@pytest.mark.unit
def test_build_cases_on_the_api_internal_project(tmp_path, monkeypatch):
    project = SEEDED / "s05_api_internal"
    names = ["kv_load", "kv_find", "kv_key_equals", "kv_get", "kv_count"]
    fns = dict(_fn("src/kv.c", n, "kv") for n in names)
    plan = {
        "entries": list(fns),
        "sources": [str(project / "src" / "kv.c")],
        "cppflags": f"-I{(project / 'include').as_posix()}",
    }
    cases, excluded, headers = bs.build_cases(plan, fns, project)
    assert excluded == {}
    assert [n for _, n, _ in cases] == names
    assert headers["kv_key_equals"].endswith("include/kv.h")
    stmt = dict((n, c) for _, n, c in cases)["kv_key_equals"]
    assert stmt.startswith("unsigned a0 = 0;") and "kv_key_equals(a0, (const uint8_t *)fuzz_buf" in stmt
    argv = bs.generate_argv("libkv_a", {**plan, "submodule": False, "unit": "libkv_a"}, cases, headers)
    assert "--entry-style" in argv and argv[argv.index("--entry-style") + 1] == "dispatch"
    assert sum(a.startswith("--dispatch-case=") for a in argv) == 5
    assert not any(a.startswith("--unit") for a in argv)
    sub = bs.generate_argv("kv", {**plan, "submodule": True, "unit": "libkv_a"}, cases, headers)
    assert "--unit=libkv_a" in sub


@pytest.mark.unit
def test_apply_policy_generates_and_exempts(tmp_path, monkeypatch):
    shutil.copytree(SEEDED / "s05_api_internal", tmp_path / "workspace" / "work")
    monkeypatch.chdir(tmp_path)
    fns = dict(_fn("src/kv.c", n, "kv") for n in ("kv_load", "kv_key_equals"))
    fns.update([_fn("src/kv.c", "find_slot", "kv", static=True), _fn("src/none.c", "lonely", "none")])
    dag = {
        "module_kind": "link_unit",
        "functions": fns,
        "modules": {
            "libkv_a": {
                "required_sources": ["src/kv.c"],
                "cppflags": ["-I", "include"],
                "candidate_entry_points": list(fns)[:3],
            },
            "libnone_a": {"required_sources": [], "candidate_entry_points": ["src/none.c#lonely"]},
        },
    }
    Path("workspace/reports").mkdir(parents=True)
    Path("workspace/reports/callgraph_dag.json").write_bytes(json.dumps(dag).encode())
    calls: list[list[str]] = []

    def step(name: str, argv: list[str]) -> bool:
        calls.append(argv)
        module = argv[argv.index("--module") + 1]
        Path("workspace/harnesses").mkdir(parents=True, exist_ok=True)
        Path(f"workspace/harnesses/harness_{module}.json").write_bytes(json.dumps({"module": module}).encode())
        return True

    report = bs.apply_policy(dag, step)
    assert len(calls) == 1 and calls[0][calls[0].index("--module") + 1] == "libkv_a"
    assert report["libkv_a"]["harness"] is True and report["libkv_a"]["cases"] == ["kv_load", "kv_key_equals"]
    assert report["libnone_a"] == {**report["libnone_a"], "harness": False, "reason": "no sources"}
    sidecar = json.loads(Path("workspace/harnesses/harness_libkv_a.json").read_text(encoding="utf-8"))
    assert list(sidecar["reach_exempt"]) == ["src/kv.c#find_slot"]
    assert sidecar["reach_exempt"]["src/kv.c#find_slot"].startswith("seeded harness policy: static")
    modules = json.loads(Path("workspace/harnesses/reach_exempt_modules.json").read_text(encoding="utf-8"))
    assert modules == {"libnone_a": "seeded harness policy: no sources"}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _run_dir(tmp_path: Path, fuzz: dict | None = None, eva: dict | None = None, phase0: dict | None = None) -> Path:
    run = tmp_path / "runs" / "r" / "p" / "run-1"
    for kind, reports in (("fuzz", fuzz or {}), ("eva", eva or {})):
        d = run / "workspace" / "reports" / kind
        d.mkdir(parents=True, exist_ok=True)
        for module, rep in reports.items():
            (d / f"{module}.json").write_bytes(json.dumps(rep).encode())
    if phase0 is not None:
        (run / "bench").mkdir(parents=True, exist_ok=True)
        (run / "bench" / "phase0.json").write_bytes(json.dumps(phase0).encode())
    return run


def _artifact(file: str, function: str, line: int) -> dict:
    return {"failure": {"file": file, "function": function, "line": line, "kind": "mem_access"}}


@pytest.mark.unit
def test_bug_and_decoy_in_one_function_are_told_apart_by_line(tmp_path):
    truth = _truth("s03_config_body")
    run = _run_dir(
        tmp_path,
        fuzz={
            "libpkt_a": {"status": "ok", "artifacts": [_artifact("workspace/work/src/unescape.c", "pkt_unescape", 13)]}
        },
    )
    s = bs.score(run, truth)
    assert s["bugs"]["S03-1"]["found"] and s["bugs"]["S03-1"]["outcome"] == "fuzz"
    assert s["decoys"]["S03-D1"]["fired"] is False
    run2 = _run_dir(
        tmp_path / "2",
        eva={
            "libpkt_a": {
                "status": "ok",
                "invalid_alarms": [
                    {"directory": "workspace/work/src", "file": "unescape.c", "function": "pkt_unescape", "line": 33}
                ],
            }
        },
    )
    s2 = bs.score(run2, truth)
    assert s2["bugs"]["S03-1"]["outcome"] == "missed" and s2["decoys"]["S03-D1"]["fired"] is True
    assert s2["other_findings"] == []


@pytest.mark.unit
def test_eva_invalid_unknown_renamed_statics_and_other_findings(tmp_path):
    truth = _truth("s07_static_collision")
    eva = {
        "libframe_a": {
            "status": "ok",
            "invalid_alarms": [
                {"directory": "workspace/work/src", "file": "frame.c", "function": "at_1", "line": 10},
                {"directory": "workspace/work/src", "file": "stats.c", "function": "frame_stats", "line": 4},
            ],
        }
    }
    s = bs.score(_run_dir(tmp_path, eva=eva), truth)
    assert s["bugs"]["S07-1"]["outcome"] == "eva_invalid"
    assert s["other_findings"] == ["src/stats.c#frame_stats"]
    # The safe `at` of stats.c does not count for the bug in frame.c.
    eva["libframe_a"]["invalid_alarms"] = [{"file": "src/stats.c", "function": "at", "line": 10}]
    assert bs.score(_run_dir(tmp_path / "2", eva=eva), truth)["bugs"]["S07-1"]["found"] is False
    unknown = {
        "libframe_a": {"status": "ok", "unknown_obligations_by_function": {"at": [{"file": "src/frame.c", "line": 10}]}}
    }
    s3 = bs.score(_run_dir(tmp_path / "3", eva=unknown), truth)
    assert s3["bugs"]["S07-1"]["found"] is False and s3["bugs"]["S07-1"]["outcome"] == "eva_unknown"


@pytest.mark.unit
def test_score_records_phase0_and_policy(tmp_path):
    phase0 = {
        "ok": True,
        "module_kind": "link_unit",
        "policy": {
            "librec_a": {"harness": True, "cases": ["rec_parse", "rec_sum"], "excluded": {}},
            "main": {"harness": False, "reason": "no callable entry point", "excluded": {"x#main": "main"}},
        },
    }
    s = bs.score(_run_dir(tmp_path, phase0=phase0), _truth("s01_macro_fn"))
    assert s["module_kind"] == "link_unit" and s["phase0_ok"] is True
    assert s["harnesses"] == {"librec_a": ["rec_parse", "rec_sum"]}
    assert s["not_harnessed"] == {"main": "no callable entry point"}
    assert s["bugs"]["S01-1"]["outcome"] == "missed" and s["decoys"]["S01-D1"]["fired"] is False


@pytest.mark.unit
def test_totals_acceptance_and_render(tmp_path):
    found = {"found": True, "eva_unknown_at_line": False, "outcome": "fuzz", "function": "f", "mechanism": "m"}
    projects: dict[str, dict] = {
        "a": {
            "truth_bugs": ["A-1"],
            "score": {"bugs": {"A-1": found}, "decoys": {"A-D1": {"fired": False, "function": "g"}}},
        },
        "b": {"truth_bugs": ["B-1"], "score": {"bugs": {"B-1": found}, "decoys": {}}},
    }
    t = bs.totals(projects)
    assert (t["found"], t["bugs"], t["decoys_fired"], t["passed"]) == (2, 2, 0, True)
    projects["b"]["score"]["decoys"] = {"B-D1": {"fired": True, "function": "h"}}
    assert bs.totals(projects)["passed"] is False
    # A project that errored still counts its bugs: the set cannot pass without it.
    del projects["b"]["score"]
    projects["b"].update(status="error", error="boom")
    t = bs.totals(projects)
    assert (t["found"], t["bugs"], t["passed"]) == (1, 2, False)
    text = bs.render({"run_id": "seeded-x", "fuzz_budget": 30, "projects": projects})
    assert "Bugs found 1/2" in text and "**FAIL**" in text and "| `b` |" in text


@pytest.mark.unit
def test_rescore_resolves_run_dirs_against_the_work_dir(tmp_path):
    run = _run_dir(
        tmp_path,
        fuzz={"m": {"status": "ok", "artifacts": [_artifact("src/kv.c", "kv_key_equals", 50)]}},
    )
    results = tmp_path / "results" / "seeded-x.json"
    results.parent.mkdir()
    doc = {"run_id": "seeded-x", "projects": {"s05_api_internal": {"run_dir": run.relative_to(tmp_path).as_posix()}}}
    results.write_bytes(json.dumps(doc).encode())
    out = bs.rescore(results, tmp_path, SEEDED)
    assert out["totals"]["passed"] is True and out["totals"]["bugs"] == 1
    assert results.with_suffix(".md").is_file()


@pytest.mark.unit
def test_projects_and_specs_come_from_the_corpus():
    projects = bs.projects_in(SEEDED)
    assert [p.name for p in projects][:2] == ["s01_macro_fn", "s02_token_paste"] and len(projects) == 8
    with pytest.raises(bs.benchmark.BenchmarkError):
        bs.projects_in(SEEDED, ["s99_nope"])
    spec = bs.project_spec(projects[3], _truth("s04_force_include"))
    assert spec["build"] == {"command": "make", "test_command": None, "origin": "benchmark"}
    assert spec["repo"] == "s04-force-include"
    s08 = bs.project_spec(projects[7], _truth("s08_wellformed_input"))
    assert s08["build"]["test_command"] == "./sdf_test"
    assert bs.project_spec(projects[7], _truth("s08_wellformed_input"), seeds=False)["build"]["test_command"] is None
    plan = bs.stage_plan(projects[3], 45)
    assert [s[0] for s in plan] == ["phase0", "build", "fuzz", "eva", "ingest"]
    assert plan[0][1].endswith("benchmark_seeded.py inner --repo s04-force-include --fuzz-budget 45")
