"""Link repair for an address-flow cluster (scripts/unit_split.py, scripts/fuzz_build.py): a
function or global its `build_sources` name and do not define is stubbed, not linked from its
file, which on nginx would pull the whole program back in. A function stub reports itself and
aborts when called."""

from __future__ import annotations

import json
from pathlib import Path

import fuzz_build
import run_eacsl_fuzz as R

FLOW_CLUSTER = "kvd__c1"
FLOW_STUB_DIR = Path("workspace/build/fuzz_kvd__c1_link_globals")


def _flow_run_dir(tmp_path: Path, reach: str = "address_flow") -> Path:
    """A daemon unit whose cluster compiles daemon/state.c only; returns the DAG path."""
    work = tmp_path / "workspace" / "work"
    for rel in ("daemon/main.c", "daemon/state.c", "daemon/conn.c", "lib/b.c"):
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text("int x;\n", encoding="utf-8")
    reports = tmp_path / "workspace" / "reports"
    reports.mkdir(parents=True)
    functions = {
        "main": {"name": "main", "file": "daemon/main.c", "module": "kvd"},
        "server_start": {"name": "server_start", "file": "daemon/state.c", "module": "kvd"},
        "conn_close": {"name": "conn_close", "file": "daemon/conn.c", "module": "kvd"},
        "kv_put": {"name": "kv_put", "file": "lib/b.c", "module": "kvd"},
    }
    files = ["daemon/main.c", "daemon/state.c", "daemon/conn.c", "lib/b.c"]
    dag = {
        "functions": functions,
        "module_kind": "link_unit",
        "modules": {
            "kvd": {
                "module": "kvd",
                "unit": "daemon/kvd",
                "files": files,
                "required_sources": files,
                "functions": sorted(functions),
            }
        },
        "submodules": {
            FLOW_CLUSTER: {
                "unit": "kvd",
                "functions": ["server_start"],
                "reach": reach,
                "build_sources": ["daemon/state.c"],
                "link_stubs": {"functions": ["conn_close", "kv_put"], "globals": ["G_Terminate"]},
            }
        },
    }
    (reports / "callgraph_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    records = [
        {"name": "G_Terminate", "file": "daemon/main.c", "static": False, "type": "int", "units": ["daemon/kvd"]},
        {"name": "G_Conn", "file": "daemon/state.c", "static": False, "type": "int", "units": ["daemon/kvd"]},
    ]
    model = {"global_variables": {f"{r['file']}#{r['name']}": r for r in records}}
    (reports / "phase0_model.json").write_text(json.dumps(model), encoding="utf-8")
    return reports / "callgraph_dag.json"


def _undefined_refs(*syms: str) -> str:
    return "".join(f"/usr/bin/ld: state.o: undefined reference to `{s}'\n" for s in syms)


def test_a_flow_cluster_stubs_what_its_files_name_outside_them(tmp_path: Path, monkeypatch) -> None:
    dag_path = _flow_run_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    sources = ["workspace/work/daemon/state.c"]
    repaired, info = R.repair_sources_for_link(
        sources,
        _undefined_refs("kv_put", "G_Terminate", "G_Conn"),
        dag_path,
        tmp_path,
        module=FLOW_CLUSTER,
        stub_dir=FLOW_STUB_DIR,
    )
    fn_file = (FLOW_STUB_DIR / fuzz_build.LINK_STUBS_FILE).as_posix()
    globals_file = (FLOW_STUB_DIR / R.LINK_GLOBALS_FILE).as_posix()
    # No file outside the cluster's build_sources is linked; G_Conn's file is one of them (already there).
    assert repaired == [*sources, globals_file, fn_file]
    assert info["stubbed_functions"] == [{"name": "kv_put", "file": "lib/b.c"}]
    assert [g["name"] for g in info["stubbed_globals"]] == ["G_Terminate"]
    assert sorted(info["symbols"]) == ["G_Terminate", "kv_put"]
    text = Path(fn_file).read_text(encoding="utf-8")
    assert b"\r" not in Path(fn_file).read_bytes()
    assert '".globl kv_put\\n"' in text and '"kv_put:\\n"' in text
    assert "jmp __framac_link_stub_called@PLT" in text
    assert fuzz_build.LINK_STUB_MARKER in text and "abort();" in text
    assert f"cluster {FLOW_CLUSTER}'s" in text


def test_a_call_graph_cluster_or_a_build_without_a_stub_dir_links_the_file(tmp_path: Path, monkeypatch) -> None:
    for reach in ("call_graph", "address_flow"):
        root = tmp_path / reach
        dag_path = _flow_run_dir(root, reach=reach)
        monkeypatch.chdir(root)
        stub_dir = FLOW_STUB_DIR if reach == "call_graph" else None
        repaired, info = R.repair_sources_for_link(
            [], _undefined_refs("kv_put"), dag_path, root, module=FLOW_CLUSTER, stub_dir=stub_dir
        )
        assert repaired == ["workspace/work/lib/b.c"] and "stubbed_functions" not in info


def test_build_module_binary_accumulates_the_function_stubs(tmp_path: Path, monkeypatch) -> None:
    """Two rounds: conn_close is named only once kv_put is stubbed; the file defines both."""
    dag_path = _flow_run_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    out_bin = Path("workspace/build/fuzz_kvd__c1")
    fn_file = (FLOW_STUB_DIR / fuzz_build.LINK_STUBS_FILE).as_posix()
    calls: list[list[str]] = []

    def fake_compile(srcs, out, *a, **k):
        calls.append(list(srcs))
        text = Path(fn_file).read_text(encoding="utf-8") if fn_file in srcs else ""
        missing = next((s for s in ("kv_put", "conn_close") if f'"{s}:\\n"' not in text), None)
        if missing:
            return {"engine": "sanitizers", "returncode": 1, "stderr": _undefined_refs(missing)}
        return {"engine": "sanitizers", "returncode": 0, "binary": str(out)}

    monkeypatch.setattr(fuzz_build, "compile_sanitizer_binary", fake_compile)
    out = R.build_module_binary(
        ["workspace/work/daemon/state.c"], out_bin, engine="sanitizers", dag_path=dag_path, link_module=FLOW_CLUSTER
    )
    assert out["compile"]["returncode"] == 0 and len(calls) == 3
    assert out["sources"] == ["workspace/work/daemon/state.c", fn_file]
    repair = out["link_repair"]
    assert [s["name"] for s in repair["stubbed_functions"]] == ["kv_put", "conn_close"]
    assert repair["functions_file"] == fn_file and "stubbed_globals" not in repair
    assert [r["added_sources"] for r in repair["rounds"]] == [[fn_file], []]
    text = Path(fn_file).read_text(encoding="utf-8")
    assert ".Lframac_link_stub_0" in text and ".Lframac_link_stub_1" in text
