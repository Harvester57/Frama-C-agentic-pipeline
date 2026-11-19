"""
Link repair on the coverage build (`run_eacsl_fuzz.py coverage`) and on the other module builds that
took no DAG (minimize, replay-candidates, minimize-candidates).

nginx 1.31.9 run-5: the fuzz builds of nginx__ngx_bpf and nginx__ngx_http_script linked only after link
repair added src/core/nginx.c and the generated objs/ngx_modules.c (ngx_core_module, ngx_modules,
ngx_module_names). The coverage build compiled the module's raw sources once, failed with the same
`undefined reference` errors, and the dynamic reach gate could not measure either module.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import crash_replay
import fuzz_build
import fuzz_coverage
import run_eacsl_fuzz as R
import sandbox_exec
from test_fuzz_coverage import CoverageSandbox

_NGX_MODULE = "nginx__ngx_bpf"
_NGX_UNIT = "objs/nginx"
_NGX_OWN = "workspace/work/src/core/ngx_bpf.c"
_NGX_MAIN_C = "workspace/work/src/core/nginx.c"
_NGX_GEN_C = "workspace/work/objs/ngx_modules.c"
_NGX_HARNESS = f"workspace/harnesses/harness_{_NGX_MODULE}.c"
# Defined in nginx.c (a function and a global) and in the generated objs/ngx_modules.c (two globals).
_NGX_DEFINED_IN = {
    "ngx_set_environment": "nginx.c",
    "ngx_core_module": "nginx.c",
    "ngx_modules": "ngx_modules.c",
    "ngx_module_names": "ngx_modules.c",
}


def _ngx_run(tmp_path: Path, *, generated: bool = True) -> Path:
    """
    A run directory shaped like nginx run-5: one link unit (objs/nginx) whose files hold nginx.c (with
    `main`) and the generated objs/ngx_modules.c, which exists only when `generated`. The harness
    module's sidecar names its unit. Returns the DAG at its default place.
    """
    work = tmp_path / "workspace" / "work"
    for rel in ("src/core/ngx_bpf.c", "src/core/nginx.c", *(("objs/ngx_modules.c",) if generated else ())):
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text("int x;\n", encoding="utf-8")
    harnesses = tmp_path / "workspace" / "harnesses"
    harnesses.mkdir(parents=True)
    (harnesses / f"harness_{_NGX_MODULE}.c").write_text("int y;\n", encoding="utf-8")
    (harnesses / f"harness_{_NGX_MODULE}.json").write_text(
        json.dumps({"module": _NGX_MODULE, "unit": "nginx"}), encoding="utf-8"
    )
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    files = ["src/core/ngx_bpf.c", "src/core/nginx.c", "objs/ngx_modules.c"]
    dag = {
        "module_kind": "link_unit",
        "modules": {"nginx": {"module": "nginx", "unit": _NGX_UNIT, "files": files, "required_sources": files}},
        "functions": {
            "ngx_bpf_compile": {"name": "ngx_bpf_compile", "file": "src/core/ngx_bpf.c", "module": "nginx"},
            "main": {"name": "main", "file": "src/core/nginx.c", "module": "nginx"},
            "ngx_set_environment": {"name": "ngx_set_environment", "file": "src/core/nginx.c", "module": "nginx"},
        },
    }
    (reports / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    globals_ = [
        ("src/core/nginx.c", "ngx_core_module", "ngx_module_t"),
        ("objs/ngx_modules.c", "ngx_modules", "ngx_module_t *[64]"),
        ("objs/ngx_modules.c", "ngx_module_names", "char *[64]"),
    ]
    model = {
        "global_variables": {
            f"{file}#{name}": {"name": name, "file": file, "static": False, "type": type_, "units": [_NGX_UNIT]}
            for file, name, type_ in globals_
        }
    }
    (reports / "phase0_model.json").write_text(json.dumps(model), encoding="utf-8")
    corpus = tmp_path / "workspace" / "corpus" / _NGX_MODULE
    corpus.mkdir(parents=True)
    (corpus / "input-000").write_bytes(b"a")
    return reports / "callgraph_dag.json"


def _ngx_linker(monkeypatch, root: Path) -> list[list[str]]:
    """
    The coverage build: `undefined reference` for each symbol whose defining file is not among the
    sources, as ld prints them. Every source it is given must exist (a compiler stops on one that does not).
    """
    calls: list[list[str]] = []

    def fake(sources, out_bin, cppflags="-I.", ldflags_extra="", runner=None, use_cache=True):
        calls.append(list(sources))
        assert all((root / s).is_file() for s in sources), sources
        names = {Path(s).name for s in sources}
        undefined = [sym for sym, file in _NGX_DEFINED_IN.items() if file not in names]
        if undefined:
            log = "".join(f"/usr/bin/ld: ngx_cycle.o: undefined reference to `{sym}'\n" for sym in undefined)
            return {"engine": "coverage", "returncode": 1, "binary": str(out_bin), "stdout": "", "stderr": log}
        return {"engine": "coverage", "returncode": 0, "binary": str(out_bin), "cache": {"hit": False, "key": None}}

    monkeypatch.setattr(fuzz_build, "compile_coverage_binary", fake)
    return calls


def _ngx_measured(monkeypatch) -> None:
    monkeypatch.setattr(sandbox_exec, "run_sandboxed", CoverageSandbox())
    export = {
        "data": [
            {
                "functions": [
                    {
                        "name": "ngx_bpf_compile",
                        "count": 1,
                        "filenames": ["/framac-run/workspace/work/src/core/ngx_bpf.c"],
                        "regions": [[1, 1, 2, 2, 1, 0, 0, 0]],
                    }
                ]
            }
        ]
    }
    monkeypatch.setattr(fuzz_coverage, "_export_coverage", lambda *a: (export, None))


def _ngx_coverage_cli(*extra: str) -> int:
    return R.main(
        [
            "coverage",
            "--module",
            _NGX_MODULE,
            "--sources",
            _NGX_OWN,
            _NGX_HARNESS,
            "--out-bin",
            f"workspace/harnesses/cov_{_NGX_MODULE}",
            "--corpus-dir",
            f"workspace/corpus/{_NGX_MODULE}",
            "--scratch-dir",
            f"workspace/coverage/{_NGX_MODULE}",
            "--out-json",
            f"workspace/reports/coverage/{_NGX_MODULE}.json",
            *extra,
        ]
    )


def _ngx_report(tmp_path: Path) -> dict:
    return json.loads((tmp_path / f"workspace/reports/coverage/{_NGX_MODULE}.json").read_text(encoding="utf-8"))


@pytest.mark.unit
def test_coverage_build_repairs_the_link_from_the_default_dag(tmp_path, monkeypatch, capsys):
    """nginx run-5: the coverage build links once the DAG's defining files are added, as the fuzz build did."""
    _ngx_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    calls = _ngx_linker(monkeypatch, tmp_path)
    _ngx_measured(monkeypatch)
    assert _ngx_coverage_cli() == 0  # no --dag: workspace/reports/callgraph_dag.json, as `make build` uses
    report = _ngx_report(tmp_path)
    assert report["status"] == "ok", report.get("reason")
    assert report["sources"] == [_NGX_OWN, _NGX_HARNESS, _NGX_MAIN_C, _NGX_GEN_C]
    assert calls == [[_NGX_OWN, _NGX_HARNESS], [_NGX_OWN, _NGX_HARNESS, _NGX_MAIN_C, _NGX_GEN_C]]
    repair = report["link_repair"]
    assert repair["added_sources"] == [_NGX_MAIN_C, _NGX_GEN_C]
    # A symbol whose file an earlier symbol of the round added is not listed again (run-5's build report
    # names ngx_core_module and ngx_modules, not ngx_module_names), as for the fuzz build.
    assert repair["symbols"] == ["ngx_set_environment", "ngx_modules"]
    assert len(repair["rounds"]) == 1
    assert "missing_sources" not in repair
    assert report["functions"][0]["function"] == "ngx_bpf_compile"


@pytest.mark.unit
def test_coverage_build_never_compiles_a_missing_generated_source(tmp_path, monkeypatch, capsys):
    """objs/ngx_modules.c not installed in workspace/work: recorded as missing, never handed to clang."""
    _ngx_run(tmp_path, generated=False)
    monkeypatch.chdir(tmp_path)
    calls = _ngx_linker(monkeypatch, tmp_path)
    _ngx_measured(monkeypatch)
    _ngx_coverage_cli()
    report = _ngx_report(tmp_path)
    assert report["status"] == "compile_error"
    assert calls == [[_NGX_OWN, _NGX_HARNESS], [_NGX_OWN, _NGX_HARNESS, _NGX_MAIN_C]]
    assert report["sources"] == [_NGX_OWN, _NGX_HARNESS, _NGX_MAIN_C]
    repair = report["link_repair"]
    assert repair["added_sources"] == [_NGX_MAIN_C]
    missing = repair["missing_sources"]
    assert [m["file"] for m in missing] == ["objs/ngx_modules.c"]
    assert set(missing[0]["symbols"]) == {"ngx_modules", "ngx_module_names"}


@pytest.mark.unit
def test_coverage_build_without_a_dag_compiles_once(tmp_path, monkeypatch, capsys):
    """No DAG (neither --dag nor the default file): one compile, the failure as before, no `link_repair`."""
    _ngx_run(tmp_path)
    (tmp_path / "workspace/reports/callgraph_dag.json").unlink()
    monkeypatch.chdir(tmp_path)
    calls = _ngx_linker(monkeypatch, tmp_path)
    _ngx_measured(monkeypatch)
    _ngx_coverage_cli()
    report = _ngx_report(tmp_path)
    assert report["status"] == "compile_error" and len(calls) == 1
    assert "link_repair" not in report
    assert report["sources"] == [_NGX_OWN, _NGX_HARNESS]


@pytest.mark.unit
def test_coverage_rebuild_with_pre_included_headers_starts_from_the_repaired_sources(tmp_path, monkeypatch):
    """The rebuild for an unreadable mapping (cryptolib) keeps the files link repair added: no failing link again."""
    dag = _ngx_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    calls = _ngx_linker(monkeypatch, tmp_path)
    monkeypatch.setattr(sandbox_exec, "run_sandboxed", CoverageSandbox())
    good = {
        "data": [
            {
                "functions": [
                    {
                        "name": "f",
                        "count": 1,
                        "filenames": ["/r/workspace/work/src/core/ngx_bpf.c"],
                        "regions": [[1, 1, 2, 2, 1, 0, 0, 0]],
                    }
                ]
            }
        ]
    }
    results = iter([(None, f"llvm-cov export failed (1): error: {R.COVERAGE_TRUNCATED_MAPPING}"), (good, None)])
    monkeypatch.setattr(fuzz_coverage, "_export_coverage", lambda *a: next(results))
    probed: list[list[str]] = []

    def includes(sources, cppflags=""):
        probed.append(list(sources))
        return ["m.h"]

    monkeypatch.setattr(fuzz_coverage, "in_function_includes", includes)
    report = R.coverage_report(
        _NGX_MODULE,
        [_NGX_OWN, _NGX_HARNESS],
        Path(f"workspace/harnesses/cov_{_NGX_MODULE}"),
        [Path(f"workspace/corpus/{_NGX_MODULE}")],
        Path("scratch"),
        dag_path=dag,
        link_module=_NGX_MODULE,
    )
    repaired = [_NGX_OWN, _NGX_HARNESS, _NGX_MAIN_C, _NGX_GEN_C]
    assert report["status"] == "ok" and report["pre_included"] == ["m.h"]
    assert calls == [[_NGX_OWN, _NGX_HARNESS], repaired, repaired]
    assert probed == [repaired]
    assert report["link_repair"]["added_sources"] == [_NGX_MAIN_C, _NGX_GEN_C]


# ------------------------------------------------------------------ the replay and minimize builds


@pytest.mark.unit
def test_candidate_replay_builds_repair_the_link_from_the_default_dag(tmp_path, monkeypatch):
    """replay-candidates / minimize-candidates build the module's binary like `make build`: same DAG repair."""
    dag = _ngx_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    seen: list[dict] = []

    def fake_prepare(module, sources, out_bin, **kwargs):
        seen.append({"module": module, **kwargs})
        return {"binary": None, "reason": "not built in this test"}

    monkeypatch.setattr(crash_replay, "prepare_replay_binary", fake_prepare)
    spec = {"sources": [_NGX_OWN, _NGX_HARNESS], "cppflags": "-I.", "ldflags": "", "harness_module": _NGX_MODULE}
    crash_replay._prepared_replay(
        "nginx",
        spec,
        "sanitizers",
        own_engine="sanitizers",
        bin_dir=Path("workspace/harnesses"),
        prepared_by_key={},
        attribution=False,
        selftest_json=None,
        machdep="gcc_x86_64",
    )
    crash_replay._cross_engine_replay(
        module="nginx",
        harness_module=_NGX_MODULE,
        spec=spec,
        reproducers=[],
        other="eacsl",
        bin_dir=None,
        scratch=Path("scratch"),
        per_input_timeout=1,
        prepared_cache={},
        attribution=False,
        selftest_json=None,
        machdep="gcc_x86_64",
    )
    assert [(s["module"], Path(s["dag_path"]), s["link_module"]) for s in seen] == [
        (_NGX_MODULE, Path("workspace/reports/callgraph_dag.json"), _NGX_MODULE)
    ] * 2
    assert Path(seen[0]["dag_path"]).resolve() == dag.resolve()


@pytest.mark.unit
def test_minimize_build_repairs_the_link_from_the_dag(tmp_path, monkeypatch, capsys):
    """`run_eacsl_fuzz.py minimize --sources ...` builds through prepare_replay_binary with the DAG."""
    _ngx_run(tmp_path)
    monkeypatch.chdir(tmp_path)
    seen: list[dict] = []

    def fake_prepare(module, sources, out_bin, **kwargs):
        seen.append(kwargs)
        return {"binary": None, "reason": "not built in this test"}

    monkeypatch.setattr(crash_replay, "prepare_replay_binary", fake_prepare)
    monkeypatch.setattr(crash_replay, "minimize_input", lambda *a, **k: {"status": "error"})
    crash = tmp_path / "crash-0"
    crash.write_bytes(b"x")
    R.main(
        [
            "minimize",
            "--module",
            _NGX_MODULE,
            "--sources",
            _NGX_OWN,
            _NGX_HARNESS,
            "--out-bin",
            f"workspace/harnesses/fuzz_{_NGX_MODULE}",
            "--inputs",
            str(crash),
            "--out-json",
            "min.json",
        ]
    )
    assert len(seen) == 1
    assert Path(seen[0]["dag_path"]) == Path("workspace/reports/callgraph_dag.json")
    assert seen[0]["link_module"] == _NGX_MODULE
