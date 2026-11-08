"""
Remediation step R5 (docs/phase0-remediation-plan.md): contracts and validation. Each Phase 0 artifact
has a schema that accepts what its producer writes (generated here by calling the producers on recorded
inputs) and rejects a broken one; `validate_artifacts.py run-dir` checks them and fails on the schema
problems producers record as warnings; the sidecar's `scope_files` survives a regeneration (plain and
`--api`); `infer_unit` votes by DAG key; a harness's default reachability takes its entry function's own
trust when a same-named function elsewhere has another.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

import api_harness as ah
import build_callgraph_dag as bcd
import generate_harness as gh
import harness_reach
import phase0_gates
import pipeline_make as pm
import seed_harvest as sh
import validate_artifacts as va
from module_map import ModuleMap, infer_unit
from test_dag_model_view import _model as _view_model
from test_dag_model_view import target  # noqa: F401 - pytest fixture
from test_pipeline_make import ACSL, _make_run

pytestmark = pytest.mark.unit


def _write(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def test_every_schema_loads_with_the_minimal_interpreter():
    for name in (
        "callgraph_dag",
        "harness_sidecar",
        "build_check",
        "harness_reach_dynamic",
        "seed_harvest",
        "seed_trace",
    ):
        assert va.get_schema(name)["$comment"]


# ---------------------------------------------------------------------------------------------------
# The call-graph DAG
# ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("fallback", [False, True])
def test_the_dag_schema_accepts_the_producers_link_unit_dag(target: Path, fallback: bool):  # noqa: F811
    dag = bcd.build_dag(target, _view_model(fallback=fallback))
    assert dag["schema_version"] == bcd.DAG_SCHEMA_VERSION
    assert list(va.validate_dag(dag)) == []
    if fallback:
        assert dag["modules"]["libb"]["fuzz_engine"] == "sanitizers"


def test_the_dag_schema_accepts_a_split_unit_and_the_held_module_view(target: Path):  # noqa: F811
    split = bcd.build_dag(target, _view_model(), split_max_functions=2)
    assert split["submodules"], "the unit was split"
    assert list(va.validate_dag(split)) == []
    held = bcd.build_dag(target, _view_model(), units=False)
    assert "schema_version" not in held and list(va.validate_dag(held)) == []


def test_the_dag_schema_rejects_a_broken_dag(target: Path):  # noqa: F811
    dag = bcd.build_dag(target, _view_model(fallback=True))

    def problems(mutate) -> list[str]:
        broken = copy.deepcopy(dag)
        mutate(broken)
        return list(va.validate_dag(broken))

    assert any(
        "missing required property 'functions'" in e for e in problems(lambda d: d["modules"]["lib"].pop("functions"))
    )
    assert any(
        "expected type array" in e
        for e in problems(lambda d: d["functions"]["api_run"].update(internal_callees="helper"))
    )
    assert any("not a module" in e for e in problems(lambda d: d["functions"]["api_run"].update(module="nowhere")))
    assert any("not in $.functions" in e for e in problems(lambda d: d["modules"]["lib"]["functions"].append("ghost")))
    assert any("sanitizers" in e for e in problems(lambda d: d["modules"]["libb"].update(fuzz_engine="eacsl")))
    assert any("run_eva" in e for e in problems(lambda d: d["modules"]["libb"].update(run_eva=True)))
    assert any(
        "lack eva_wp_blocked" in e
        for e in problems(lambda d: d["functions"][d["modules"]["libb"]["functions"][0]].pop("eva_wp_blocked"))
    )


def test_a_link_unit_dag_without_schema_version_is_reported_not_crashed_on(target: Path):  # noqa: F811
    dag = bcd.build_dag(target, _view_model(fallback=True))
    dag.pop("schema_version")
    errors = list(va.validate_dag(dag))
    assert errors == [f"$: {va.DAG_NO_VERSION}"]


# ---------------------------------------------------------------------------------------------------
# Harness sidecars, scope_files, infer_unit
# ---------------------------------------------------------------------------------------------------


def _mini_tree(root: Path) -> None:
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "mod.c").write_text("int my_entry(const unsigned char *b, unsigned long n) { return (int)n; }\n")
    (root / "src" / "mod.h").write_text("int my_entry(const unsigned char *b, unsigned long n);\n")


def _gen_args(root: Path, *extra: str) -> list[str]:
    return [
        "--module",
        "mod",
        "--sources",
        str(root / "src" / "mod.c"),
        "--header",
        str(root / "src" / "mod.h"),
        "--entry-fn",
        "my_entry",
        f"--cppflags=-I{root / 'src'}",
        "--out-dir",
        str(root / "workspace" / "harnesses"),
        "--no-auto-prelude",
        *extra,
    ]


def _sidecar(root: Path, module: str = "mod") -> dict:
    return json.loads((root / "workspace" / "harnesses" / f"harness_{module}.json").read_text(encoding="utf-8"))


def test_the_sidecar_schema_accepts_generate_harness_output_and_scope_files_survive_regeneration(tmp_path):
    _mini_tree(tmp_path)
    assert gh.main(_gen_args(tmp_path, "--scope-file", "src/mod.c", "--scope-file", "./src/extra.c")) == 0
    side = _sidecar(tmp_path)
    assert side["scope_files"] == ["src/mod.c", "src/extra.c"] and "warnings" not in side
    assert list(va.validate_sidecar(side, "mod")) == []

    # A regeneration without --scope-file (a harness repair) keeps them; --record-repair too.
    assert gh.main(_gen_args(tmp_path, "--max-size", "99")) == 0
    side = _sidecar(tmp_path)
    assert side["scope_files"] == ["src/mod.c", "src/extra.c"] and side["max_input_size"] == 99
    path = tmp_path / "workspace" / "harnesses" / "harness_mod.json"
    assert gh.main(["--record-repair", str(path), "--reason", "retry"]) == 0
    assert _sidecar(tmp_path)["scope_files"] == ["src/mod.c", "src/extra.c"]
    # A new --scope-file replaces them.
    assert gh.main(_gen_args(tmp_path, "--scope-file", "src/mod.c")) == 0
    assert _sidecar(tmp_path)["scope_files"] == ["src/mod.c"]


def test_a_sidecar_without_scope_files_records_an_empty_list_and_module_map_falls_back_to_sources(tmp_path):
    _mini_tree(tmp_path)
    assert gh.main(_gen_args(tmp_path)) == 0
    side = _sidecar(tmp_path)
    assert side["scope_files"] == []
    dag = {
        "module_kind": "link_unit",
        "modules": {"lib": {"functions": ["my_entry", "other"]}},
        "functions": {
            "my_entry": {
                "name": "my_entry",
                "file": str(tmp_path / "src" / "mod.c").replace("\\", "/"),
                "module": "lib",
            },
            "other": {"name": "other", "file": "src/other.c", "module": "lib"},
        },
    }
    mm = ModuleMap(dag, {"mod": {**side, "unit": "lib"}})
    assert mm.scope_functions("mod") == ["my_entry"]
    mm = ModuleMap(dag, {"mod": {**side, "unit": "lib", "scope_files": ["src/other.c"]}})
    assert mm.scope_functions("mod") == ["other"]


def test_the_sidecar_schema_rejects_a_broken_sidecar(tmp_path):
    _mini_tree(tmp_path)
    assert gh.main(_gen_args(tmp_path)) == 0
    side = _sidecar(tmp_path)
    assert any("entry_style" in e for e in va.validate_sidecar({**side, "entry_style": "magic"}))
    assert any("scope_files" in e for e in va.validate_sidecar({**side, "scope_files": "src/mod.c"}))
    assert any("does not match the file name" in e for e in va.validate_sidecar(side, "other"))
    bad_case = {"selector": 0, "kind": "single", "calls": ["f"], "slots": [], "rest": None}  # no entry
    assert va.validate_sidecar({**side, "entry_style": "dispatch", "dispatch_cases": ["x"], "api_cases": [bad_case]})
    # The producer records the problem as a warning (the write is never stopped).
    path = tmp_path / "workspace" / "harnesses" / "harness_mod.json"
    written = gh.write_sidecar(path, {**side, "entry_style": "magic"})
    assert written["warnings"][0].startswith(va.SCHEMA_WARNING_PREFIX)
    assert any("recorded a schema problem" in e for e in va.validate_sidecar(_sidecar(tmp_path)))


def _api_inputs(root: Path) -> tuple[Path, Path, Path]:
    """A link unit `lib` with two files; a freely named sub-module scoped to one of them by scope_files."""
    (root / "lib.c").write_text("/* lib */\n")
    (root / "other.c").write_text("/* other */\n")
    sig = "int(unsigned char *,unsigned char *)"
    functions = {
        "keypair": {"name": "keypair", "file": "lib.c", "module": "lib", "is_static": False},
        "box": {"name": "box", "file": "lib.c", "module": "lib", "is_static": False},
        "elsewhere": {"name": "elsewhere", "file": "other.c", "module": "lib", "is_static": False},
    }
    for rec in functions.values():
        rec.update(internal_callees=[], internal_callers=[])
    dag = {
        "schema_version": 1,
        "module_kind": "link_unit",
        "callgraph_source": "frama_c",
        "warnings": [],
        "modules": {"lib": {"functions": sorted(functions), "candidate_entry_points": sorted(functions)}},
        "functions": functions,
    }
    formals = [{"name": "p0", "kind": "pointer"}, {"name": "p1", "kind": "pointer"}]
    model = {
        "status": "ok",
        "functions": {
            f"{rec['file']}#{name}": {"signature": sig, "formals": formals, "param_sizes": {"0": {"max": 32}}}
            for name, rec in functions.items()
        },
    }
    dag_path = _write(root / "workspace" / "reports" / "callgraph_dag.json", dag)
    model_path = _write(root / "workspace" / "reports" / "phase0_model.json", model)
    calls = root / "calls"
    calls.mkdir()
    (calls / "calls-7.txt").write_text("keypair 0a=0000 1a=0000 0x=100 1x=200\nbox 0a=00 1a=00 0x=300 1x=100\n")
    report: dict = {"status": "error"}
    sh._collect(report, calls, [], root / "tree", 0.0)
    return dag_path, model_path, root / "workspace" / "seed_records" / "traces.jsonl"


def _api(root: Path, paths: tuple[Path, Path, Path], **kw: Any) -> dict:
    dag_path, model_path, traces = paths
    return ah.generate(
        module="crypto",
        header=None,
        max_input_size=64,
        cppflags="-I.",
        out_dir=root / "workspace" / "harnesses",
        unit="lib",
        auto_prelude=False,
        probe=False,
        dag_path=dag_path,
        model_path=model_path,
        traces_path=traces,
        **kw,
    )


def test_api_sidecars_validate_and_keep_scope_files_through_api_regeneration(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    paths = _api_inputs(tmp_path)
    for line in paths[2].read_text(encoding="utf-8").splitlines():
        assert va.schema_problems("seed_trace", json.loads(line)) == []

    _api(tmp_path, paths, scope_files=["lib.c"])
    side = _sidecar(tmp_path, "crypto")
    assert side["scope_files"] == ["lib.c"] and side["api_harness"] is True
    # The scope decides the cases: `elsewhere` (other.c) is outside it.
    entries = sorted(c["entry"] for c in side["api_cases"] if c["kind"] == "single")
    assert entries == ["box", "keypair"]
    assert [c["kind"] for c in side["api_cases"]] == ["single", "single", "sequence"]
    assert list(va.validate_sidecar(side, "crypto")) == [] and "warnings" not in side

    # Regenerated through --api without --scope-file: kept, and still deciding the cases.
    _api(tmp_path, paths)
    side = _sidecar(tmp_path, "crypto")
    assert side["scope_files"] == ["lib.c"]
    assert sorted(c["entry"] for c in side["api_cases"] if c["kind"] == "single") == ["box", "keypair"]
    # A plain regeneration of the same module keeps them too (and drops the API fields).
    gh.generate_module_harness(
        module_name="crypto",
        sources=["lib.c"],
        header_include=None,
        entry_fn="keypair",
        max_input_size=64,
        cppflags="-I.",
        out_dir=tmp_path / "workspace" / "harnesses",
        auto_prelude=False,
    )
    side = _sidecar(tmp_path, "crypto")
    assert side["scope_files"] == ["lib.c"] and "api_cases" not in side

    # Broken API case layouts are rejected.
    _api(tmp_path, paths)
    side = _sidecar(tmp_path, "crypto")
    broken = copy.deepcopy(side)
    broken["api_cases"][0]["slots"].append({"call": 0, "param": 0, "size": 4, "kind": "blob"})
    assert any("slots" in e or "allowed shape" in e for e in va.validate_sidecar(broken))
    broken = copy.deepcopy(side)
    broken["api_cases"][2]["calls"] = ["keypair"]  # a sequence of one call
    assert va.validate_sidecar(broken)
    broken = copy.deepcopy(side)
    broken["api_cases"][1]["selector"] = 5
    assert any("selectors" in e for e in va.validate_sidecar(broken))


def test_api_cli_passes_scope_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    paths = _api_inputs(tmp_path)
    seen: dict = {}

    def fake_generate(**kw: Any) -> dict:
        seen.update(kw)
        return {"ok": True}

    monkeypatch.setattr(ah, "generate", fake_generate)
    assert gh.main(["--api", "--module", "crypto", "--scope-file", "lib.c"]) == 0
    assert seen["scope_files"] == ["lib.c"]
    assert gh.main(["--api", "--module", "crypto"]) == 0
    assert seen["scope_files"] is None  # kept from the previous sidecar by generate
    assert paths


def test_infer_unit_votes_by_dag_key_not_plain_name():
    # `helper` is a static defined in two units (keyed file#name); `run` is in liba only.
    functions = {
        "src/a.c#helper": {"name": "helper", "file": "src/a.c", "module": "liba"},
        "src/b.c#helper": {"name": "helper", "file": "src/b.c", "module": "libb"},
        "run": {"name": "run", "file": "src/a.c", "module": "liba"},
        "go": {"name": "go", "file": "src/b.c", "module": "libb"},
        "stop": {"name": "stop", "file": "src/b.c", "module": "libb"},
    }
    dag = {
        "module_kind": "link_unit",
        "modules": {"liba": {"functions": []}, "libb": {"functions": []}},
        "functions": functions,
    }
    # A plain name never matched a collided key before: `helper` voted for nothing, `run` won.
    assert infer_unit(dag, "harn", ["helper", "run"]) == "liba"
    # By key: `helper` resolves to both units (ambiguous, no vote) unless the sources narrow it.
    assert infer_unit(dag, "harn", ["helper", "helper", "go"]) == "libb"
    assert infer_unit(dag, "harn", ["helper", "go", "stop"], sources=["workspace/work/src/a.c"]) == "libb"
    assert infer_unit(dag, "harn", ["helper"], sources=["src/b.c"]) == "libb"
    assert infer_unit(dag, "harn", ["helper"], sources=["src/a.c"]) == "liba"
    assert infer_unit(dag, "harn", ["helper"]) is None
    # A DAG key is a reference too.
    assert infer_unit(dag, "harn", ["src/b.c#helper"]) == "libb"


def test_generate_harness_infers_the_unit_from_its_sources(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    dag = {
        "module_kind": "link_unit",
        "modules": {"liba": {"functions": ["src/a.c#parse"]}, "libb": {"functions": ["src/b.c#parse"]}},
        "functions": {
            "src/a.c#parse": {"name": "parse", "file": "src/a.c", "module": "liba"},
            "src/b.c#parse": {"name": "parse", "file": "src/b.c", "module": "libb"},
        },
    }
    _write(tmp_path / "workspace" / "reports" / "callgraph_dag.json", dag)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "b.c").write_text("int parse(const unsigned char *b, unsigned long n) { return 0; }\n")
    gh.generate_module_harness(
        module_name="parser",
        sources=["src/b.c"],
        header_include=None,
        entry_fn="parse",
        max_input_size=64,
        cppflags="-I.",
        out_dir=tmp_path / "workspace" / "harnesses",
        auto_prelude=False,
    )
    assert _sidecar(tmp_path, "parser")["unit"] == "libb"


def test_default_reachability_takes_the_entry_functions_own_trust(tmp_path, monkeypatch):
    """R3 follow-up: two same-named functions with different trust; the harness's source decides."""
    monkeypatch.chdir(tmp_path)
    untrusted = {"value": "untrusted", "boundary": True, "source": "reads_input"}
    trusted = {"value": "trusted", "boundary": False, "source": "no_untrusted_caller"}
    dag = {
        "module_kind": "link_unit",
        "modules": {"lib": {"functions": ["src/net.c#parse", "src/cfg.c#parse"]}},
        "functions": {
            "src/net.c#parse": {"name": "parse", "file": "src/net.c", "module": "lib", "trust": untrusted},
            "src/cfg.c#parse": {"name": "parse", "file": "src/cfg.c", "module": "lib", "trust": trusted},
        },
    }
    _write(tmp_path / "workspace" / "reports" / "callgraph_dag.json", dag)
    (tmp_path / "src").mkdir()
    for f in ("net", "cfg"):
        (tmp_path / "src" / f"{f}.c").write_text("int parse(const unsigned char *b, unsigned long n) { return 0; }\n")

    def gen(module: str, source: str) -> dict:
        return gh.generate_module_harness(
            module_name=module,
            sources=[source],
            header_include=None,
            entry_fn="parse",
            max_input_size=64,
            cppflags="-I.",
            out_dir=tmp_path / "workspace" / "harnesses",
            auto_prelude=False,
        )

    assert gen("cfg", "workspace/work/src/cfg.c")["reachability"] == "internal_api"
    assert gen("net", "src/net.c")["reachability"] == "untrusted_surface"
    # Without a source naming the file, same-named records merge (untrusted wins), as before.
    assert gen("both", "elsewhere.c")["reachability"] == "untrusted_surface"


# ---------------------------------------------------------------------------------------------------
# build_check.json, the dynamic reach report, seed_harvest.json
# ---------------------------------------------------------------------------------------------------


def test_the_build_check_schema_accepts_pipeline_make_output_and_rejects_a_broken_one(tmp_path):
    run = _make_run(tmp_path)
    plan = pm.build_plan(run, templates_dir=ACSL)
    out = pm.build_check(run, runner=lambda t, r: (0, {}), templates_dir=ACSL)  # no build reports: not_built
    assert out["ok"] is False and list(va.validate_build_check(out)) == []
    for mod in plan.fuzz_modules:
        _write(
            run / pm.BUILD_DIR / f"{mod}.build.json",
            {"mode": "build", "module": mod, "engine_used": "eacsl", "compile": {"returncode": 0}},
        )
    phase0_gates.record_reach(run, {"modules": [{"module": m, "passed": True} for m in plan.modules]})
    out = pm.build_check(run, runner=lambda t, r: (0, {}), templates_dir=ACSL)
    on_disk = json.loads((run / pm.BUILD_CHECK_JSON).read_text(encoding="utf-8"))
    assert on_disk["ok"] is True and "phase0_checkpoint" in on_disk
    assert list(va.validate_build_check(on_disk)) == []

    assert any("$.ok" in e for e in va.validate_build_check({**on_disk, "ok": False}))
    row = next(iter(on_disk["modules"]))
    broken = copy.deepcopy(on_disk)
    broken["modules"][row]["status"] = "fine"
    assert any("status" in e for e in va.validate_build_check(broken))
    assert any(
        "build_returncode" in e
        for e in va.validate_build_check({k: v for k, v in on_disk.items() if k != "build_returncode"})
    )


def test_the_dynamic_reach_schema_accepts_harness_reach_output_and_rejects_a_broken_one(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    dag = {
        "module_kind": "link_unit",
        "modules": {"lib": {"functions": ["a", "b"], "candidate_entry_points": ["a", "b"]}},
        "functions": {
            "a": {"name": "a", "file": "lib.c", "module": "lib"},
            "b": {"name": "b", "file": "lib.c", "module": "lib"},
        },
    }
    dag_path = _write(tmp_path / "workspace" / "reports" / "callgraph_dag.json", dag)
    hdir = tmp_path / "workspace" / "harnesses"
    _write(hdir / "harness_lib.json", {"module": "lib", "unit": "lib"})
    (hdir / "harness_lib.c").write_text("/* h */\n")
    cov_dir = tmp_path / "workspace" / "reports" / "coverage"
    _write(
        cov_dir / "lib.json",
        {"status": "ok", "inputs": {"replayed": 3}, "functions": [{"function": "a", "file": "lib.c", "executions": 4}]},
    )
    out = tmp_path / harness_reach.DEFAULT_DYNAMIC_OUT
    report = harness_reach.run_dynamic(dag_path, hdir, [], cov_dir)
    harness_reach.record_dynamic(tmp_path, report, out, dag_path=dag_path)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["modules"]["lib"]["gaps"] == ["b"]
    assert list(va.validate_dynamic_reach(data)) == []

    broken = copy.deepcopy(data)
    broken["modules"]["lib"]["passed"] = True
    assert any("passed" in e for e in va.validate_dynamic_reach(broken))
    broken = copy.deepcopy(data)
    del broken["modules"]["lib"]["harness_digest"]
    assert any("harness_digest" in e for e in va.validate_dynamic_reach(broken))


def test_the_seed_harvest_schema_accepts_the_recorders_reports_and_rejects_a_broken_one(tmp_path, monkeypatch):
    from test_seed_harvest import _record_fixture

    reports = tmp_path / "workspace" / "reports" / "seed_harvest.json"
    # No model at all.
    monkeypatch.chdir(tmp_path)
    assert sh.main(["record", "--scratch", str(tmp_path / "scratch")]) == 0
    assert list(va.validate_seed_harvest(json.loads(reports.read_text(encoding="utf-8")))) == []
    # Relinked and run, with and without a test command.
    for recipe in ({"command": "make"}, {"command": "make", "test_command": "make check"}):
        sub = tmp_path / ("t" if "test_command" in recipe else "e")
        sub.mkdir()
        units = {
            "demo": {"kind": "executable", "objects": []},
            "unit_test": {"kind": "executable", "test": True, "objects": []},
        }
        _record_fixture(sub, monkeypatch, units, recipe)
        monkeypatch.setattr(sh.shutil, "which", lambda name: None)
        assert sh.main(["record", "--scratch", str(sub / "scratch")]) == 0
        data = json.loads((sub / "workspace" / "reports" / "seed_harvest.json").read_text(encoding="utf-8"))
        assert data["source"] in ("executables", "test_command")
        assert list(va.validate_seed_harvest(data)) == []

    assert any("status" in e for e in va.validate_seed_harvest({**data, "status": "great"}))
    assert any("traces" in e for e in va.validate_seed_harvest({**data, "traces": "1"}))
    assert any("source" in e for e in va.validate_seed_harvest({**data, "source": "magic"}))


def test_the_trace_schema_accepts_recorded_traces_and_rejects_a_broken_line(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    calls = tmp_path / "calls"
    calls.mkdir()
    (calls / "calls-7.txt").write_text(
        "keypair 0a=0000 1a=0000 0x=100 1x=200\nbox 0a=00 1b=6869 3a=0000 0x=300 3x=100\n"
    )
    sh._collect({"status": "error"}, calls, [], tmp_path / "tree", 0.0)
    traces = tmp_path / va.TRACES_JSONL
    assert list(va.validate_traces(traces)) == []
    line = json.loads(traces.read_text(encoding="utf-8").splitlines()[0])
    line["calls"] = line["calls"][:1]
    traces.write_text(json.dumps(line) + "\n{not json\n", encoding="utf-8")
    errors = list(va.validate_traces(traces))
    assert any("line 1" in e and "fewer than 2" in e for e in errors) and any("line 2: not JSON" in e for e in errors)


# ---------------------------------------------------------------------------------------------------
# run-dir
# ---------------------------------------------------------------------------------------------------


def _phase0_run(root: Path, dag: dict) -> Path:
    run = root / "run"
    _write(run / "workspace" / "reports" / "callgraph_dag.json", dag)
    return run


def _phase0_errors(run: Path) -> list[str]:
    return [e for e in va.validate_run_dir(run) if e.startswith("workspace/")]


def test_run_dir_catches_a_dag_with_a_wrong_shape(tmp_path, target: Path):  # noqa: F811
    dag = bcd.build_dag(target, _view_model())
    run = _phase0_run(tmp_path, dag)
    assert _phase0_errors(run) == []
    dag["modules"] = [dag["modules"]]  # a list instead of the module map
    _write(run / "workspace" / "reports" / "callgraph_dag.json", dag)
    errors = _phase0_errors(run)
    assert errors and all(e.startswith("workspace/reports/callgraph_dag.json: ") for e in errors)
    assert any("$.modules: expected type object" in e for e in errors)
    # The CLI fails on it too.
    assert va.main(["run-dir", str(run)]) == 1
    assert va.main(["dag", str(run / "workspace" / "reports" / "callgraph_dag.json")]) == 1


def test_run_dir_fails_on_a_schema_problem_a_producer_recorded(tmp_path, target: Path):  # noqa: F811
    dag = bcd.build_dag(target, _view_model())
    dag["warnings"].append("schema: ['$.modules.lib: missing required property']")
    run = _phase0_run(tmp_path, dag)
    errors = _phase0_errors(run)
    assert any("callgraph_dag.json" in e and "recorded a schema problem" in e for e in errors)
    # build_capture.py's wording of the same policy counts too.
    assert va.recorded_schema_warnings({"warnings": ["report does not match its schema: $.x"]})


def test_run_dir_checks_each_phase0_artifact_when_present(tmp_path, target: Path):  # noqa: F811
    run = _phase0_run(tmp_path, bcd.build_dag(target, _view_model()))
    reports = run / "workspace" / "reports"
    _write(reports / "build_check.json", {"ok": True, "modules": {}})
    _write(reports / "seed_harvest.json", {"schema_version": 1, "generated_at": "t", "status": "nope", "warnings": []})
    _write(reports / "harness_reach_dynamic.json", {"generated_at": "t", "modules": {"m": {"module": "m"}}})
    _write(reports / "build_capture.json", {"status": "ok"})
    _write(reports / "security_props.json", {"schema_version": 1})
    _write(run / "workspace" / "harnesses" / "harness_m.json", {"module": "other"})
    (run / "workspace" / "seed_records").mkdir(parents=True)
    (run / va.TRACES_JSONL).write_text('{"pid": "1", "calls": []}\n', encoding="utf-8")
    errors = _phase0_errors(run)
    for rel in (
        "build_check.json",
        "seed_harvest.json",
        "harness_reach_dynamic.json",
        "build_capture.json",
        "security_props.json",
        "harness_m.json",
        "traces.jsonl",
    ):
        assert any(rel in e for e in errors), rel
    assert not any("callgraph_dag.json" in e for e in errors)
